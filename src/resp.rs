use bytes::BytesMut;
use std::cell::RefCell;

use crate::limits::{ByteBudget, ByteReservation};

struct OutputLimitState {
    limit: usize,
    exceeded: bool,
    capacity_exhausted: bool,
    reservation: Option<ByteReservation>,
}

thread_local! {
    static OUTPUT_LIMIT: RefCell<OutputLimitState> = const {
        RefCell::new(OutputLimitState {
            limit: usize::MAX,
            exceeded: false,
            capacity_exhausted: false,
            reservation: None,
        })
    };
}

/// Synchronous guard for response construction on the current runtime thread.
/// It must be dropped before the next `.await` so another task cannot inherit
/// this command's response budget.
#[must_use]
pub(crate) struct OutputLimitGuard {
    previous: OutputLimitState,
}

impl OutputLimitGuard {
    pub(crate) fn exceeded(&self) -> bool {
        OUTPUT_LIMIT.with(|state| state.borrow().exceeded)
    }

    pub(crate) fn capacity_exhausted(&self) -> bool {
        OUTPUT_LIMIT.with(|state| state.borrow().capacity_exhausted)
    }
}

impl Drop for OutputLimitGuard {
    fn drop(&mut self) {
        OUTPUT_LIMIT.with(|state| {
            *state.borrow_mut() = std::mem::replace(
                &mut self.previous,
                OutputLimitState {
                    limit: usize::MAX,
                    exceeded: false,
                    capacity_exhausted: false,
                    reservation: None,
                },
            );
        });
    }
}

pub(crate) fn limit_output(bytes: usize) -> OutputLimitGuard {
    limit_output_inner(bytes, 0, None)
}

pub(crate) fn limit_output_with_budget(
    bytes: usize,
    existing_bytes: usize,
    budget: ByteBudget,
) -> OutputLimitGuard {
    limit_output_inner(bytes, existing_bytes, Some(budget))
}

fn limit_output_inner(
    bytes: usize,
    existing_bytes: usize,
    budget: Option<ByteBudget>,
) -> OutputLimitGuard {
    let (reservation, capacity_exhausted) = match budget {
        Some(budget) => match budget.try_reserve(existing_bytes) {
            Some(reservation) => (Some(reservation), false),
            None => (None, true),
        },
        None => (None, false),
    };
    let previous = OUTPUT_LIMIT.with(|state| {
        std::mem::replace(
            &mut *state.borrow_mut(),
            OutputLimitState {
                limit: bytes,
                exceeded: existing_bytes > bytes || capacity_exhausted,
                capacity_exhausted,
                reservation,
            },
        )
    });
    OutputLimitGuard { previous }
}

fn extend(buf: &mut BytesMut, bytes: &[u8]) {
    OUTPUT_LIMIT.with(|state| {
        let mut current = state.borrow_mut();
        if current.exceeded {
            return;
        }
        if buf
            .len()
            .checked_add(bytes.len())
            .is_none_or(|next| next > current.limit)
        {
            current.exceeded = true;
            return;
        }
        if current
            .reservation
            .as_mut()
            .is_some_and(|reservation| !reservation.try_grow(bytes.len()))
        {
            current.exceeded = true;
            current.capacity_exhausted = true;
            return;
        }
        buf.extend_from_slice(bytes);
    });
}

/// Appends an already RESP-encoded fragment while preserving the active
/// response-construction limit.
pub(crate) fn write_encoded(buf: &mut BytesMut, encoded: &[u8]) {
    extend(buf, encoded);
}

// Pre-encoded RESP fragments reused across hot paths to avoid reformatting.
pub static OK: &[u8] = b"+OK\r\n";
pub static PONG: &[u8] = b"+PONG\r\n";
pub static NULL: &[u8] = b"$-1\r\n";
pub static ZERO: &[u8] = b":0\r\n";
pub static ONE: &[u8] = b":1\r\n";
pub static NEG_ONE: &[u8] = b":-1\r\n";
pub static NEG_TWO: &[u8] = b":-2\r\n";
pub static EMPTY_ARRAY: &[u8] = b"*0\r\n";
pub static QUEUED: &[u8] = b"+QUEUED\r\n";
pub static NULL_ARRAY: &[u8] = b"*-1\r\n";

/// Writes a pre-encoded `+OK` simple string.
pub fn write_ok(buf: &mut BytesMut) {
    extend(buf, OK);
}

/// Writes a pre-encoded `+PONG` simple string.
pub fn write_pong(buf: &mut BytesMut) {
    extend(buf, PONG);
}

/// Writes a RESP null bulk (`$-1`).
pub fn write_null(buf: &mut BytesMut) {
    extend(buf, NULL);
}

/// Writes the transaction `+QUEUED` marker.
pub fn write_queued(buf: &mut BytesMut) {
    extend(buf, QUEUED);
}

/// Writes a RESP null array (`*-1`).
pub fn write_null_array(buf: &mut BytesMut) {
    extend(buf, NULL_ARRAY);
}

/// Writes a RESP simple string (`+...`).
pub fn write_simple(buf: &mut BytesMut, s: &str) {
    extend(buf, b"+");
    extend(buf, s.as_bytes());
    extend(buf, b"\r\n");
}

/// Writes a RESP error (`-...`).
pub fn write_error(buf: &mut BytesMut, s: &str) {
    extend(buf, b"-");
    extend(buf, s.as_bytes());
    extend(buf, b"\r\n");
}

/// Writes a RESP integer (`:...`), using cached common values on hot paths.
pub fn write_integer(buf: &mut BytesMut, n: i64) {
    match n {
        0 => extend(buf, ZERO),
        1 => extend(buf, ONE),
        -1 => extend(buf, NEG_ONE),
        -2 => extend(buf, NEG_TWO),
        _ => {
            extend(buf, b":");
            let mut tmp = itoa::Buffer::new();
            extend(buf, tmp.format_i64(n).as_bytes());
            extend(buf, b"\r\n");
        }
    }
}

/// Writes a UTF-8 RESP bulk string.
pub fn write_bulk(buf: &mut BytesMut, s: &str) {
    write_bulk_raw(buf, s.as_bytes());
}

/// Writes a raw RESP bulk string payload.
pub fn write_bulk_raw(buf: &mut BytesMut, data: &[u8]) {
    extend(buf, b"$");
    let mut tmp = itoa::Buffer::new();
    extend(buf, tmp.format_usize(data.len()).as_bytes());
    extend(buf, b"\r\n");
    extend(buf, data);
    extend(buf, b"\r\n");
}

/// Writes a RESP array header (`*len`).
pub fn write_array_header(buf: &mut BytesMut, len: usize) {
    if len == 0 {
        extend(buf, EMPTY_ARRAY);
    } else {
        extend(buf, b"*");
        let mut tmp = itoa::Buffer::new();
        extend(buf, tmp.format_usize(len).as_bytes());
        extend(buf, b"\r\n");
    }
}

/// Writes an array of bulk strings from owned `String` values.
pub fn write_bulk_array(buf: &mut BytesMut, items: &[String]) {
    write_array_header(buf, items.len());
    for item in items {
        write_bulk(buf, item);
    }
}

/// Writes an array of bulk strings from byte buffers.
pub fn write_bulk_array_raw(buf: &mut BytesMut, items: &[bytes::Bytes]) {
    write_array_header(buf, items.len());
    for item in items {
        write_bulk_raw(buf, item);
    }
}

/// Writes an optional bulk value (`$-1` when absent).
pub fn write_optional_bulk_raw(buf: &mut BytesMut, val: &Option<bytes::Bytes>) {
    match val {
        Some(s) => write_bulk_raw(buf, s),
        None => write_null(buf),
    }
}

/// Incremental RESP parser over a borrowed read buffer.
pub struct Parser<'a> {
    buf: &'a [u8],
    pos: usize,
    max_bulk_len: usize,
    max_array_len: usize,
}

const INLINE_ARG_COUNT: usize = 8;

/// Small-vector command argument holder optimized for common tiny argv lists.
pub(crate) struct CommandArgs<'a> {
    inline: [&'a [u8]; INLINE_ARG_COUNT],
    len: usize,
    heap: Vec<&'a [u8]>,
}

impl<'a> CommandArgs<'a> {
    fn new(capacity: usize) -> Self {
        Self {
            inline: [b"" as &'a [u8]; INLINE_ARG_COUNT],
            len: 0,
            heap: if capacity > INLINE_ARG_COUNT {
                Vec::with_capacity(capacity)
            } else {
                Vec::new()
            },
        }
    }

    fn push(&mut self, arg: &'a [u8]) {
        // Stay stack-only for small commands, spill once to heap for larger ones.
        if !self.heap.is_empty() || self.heap.capacity() > 0 {
            self.heap.push(arg);
        } else if self.len < INLINE_ARG_COUNT {
            self.inline[self.len] = arg;
            self.len += 1;
        } else {
            self.heap = Vec::with_capacity(INLINE_ARG_COUNT * 2);
            self.heap.extend_from_slice(&self.inline[..self.len]);
            self.heap.push(arg);
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }

    pub(crate) fn as_slice(&self) -> &[&'a [u8]] {
        if self.heap.is_empty() {
            &self.inline[..self.len]
        } else {
            self.heap.as_slice()
        }
    }

    fn into_vec(self) -> Vec<&'a [u8]> {
        if self.heap.is_empty() {
            self.inline[..self.len].to_vec()
        } else {
            self.heap
        }
    }
}

impl<'a> Parser<'a> {
    #[allow(dead_code)]
    pub fn new(buf: &'a [u8]) -> Self {
        Self::with_max_bulk_len(buf, 64 * 1024 * 1024)
    }

    pub fn with_max_bulk_len(buf: &'a [u8], max_bulk_len: usize) -> Self {
        Self::with_limits(buf, max_bulk_len, 16_384)
    }

    pub fn with_limits(buf: &'a [u8], max_bulk_len: usize, max_array_len: usize) -> Self {
        Self {
            buf,
            pos: 0,
            max_bulk_len,
            max_array_len,
        }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn parse_command(&mut self) -> Result<Option<Vec<&'a [u8]>>, &'static str> {
        Ok(self.parse_command_args()?.map(CommandArgs::into_vec))
    }

    pub(crate) fn parse_command_args(&mut self) -> Result<Option<CommandArgs<'a>>, &'static str> {
        // Return None for "need more bytes", Err for protocol violations.
        if self.pos >= self.buf.len() {
            return Ok(None);
        }
        match self.buf[self.pos] {
            b'*' => self.parse_multibulk_args(),
            _ => self.parse_inline_args(),
        }
    }

    fn parse_inline_args(&mut self) -> Result<Option<CommandArgs<'a>>, &'static str> {
        let start = self.pos;
        while self.pos < self.buf.len() {
            if self.buf[self.pos] == b'\n' {
                let end = if self.pos > start && self.buf[self.pos - 1] == b'\r' {
                    self.pos - 1
                } else {
                    self.pos
                };
                self.pos += 1;
                let line = &self.buf[start..end];
                let mut args = CommandArgs::new(0);
                let mut count = 0usize;
                for part in line.split(|&b| b == b' ') {
                    if !part.is_empty() {
                        if count >= self.max_array_len {
                            return Err("ERR RESP argument count exceeds maximum");
                        }
                        args.push(part);
                        count += 1;
                    }
                }
                return Ok(Some(args));
            }
            self.pos += 1;
        }
        // Incomplete line: restore cursor so caller can retry with more input.
        self.pos = start;
        Ok(None)
    }

    fn parse_multibulk_args(&mut self) -> Result<Option<CommandArgs<'a>>, &'static str> {
        let saved = self.pos;
        self.pos += 1;
        let count = match self.read_line_int() {
            Some(n) => n,
            None => {
                self.pos = saved;
                return Ok(None);
            }
        };
        if count < 0 {
            return Ok(None);
        }
        if count as u64 > self.max_array_len as u64 {
            return Err("ERR RESP array count exceeds maximum");
        }
        let mut args = CommandArgs::new(count as usize);
        for _ in 0..count {
            match self.parse_bulk_string()? {
                Some(s) => args.push(s),
                None => {
                    // Roll back full frame on partial command for incremental parsing.
                    self.pos = saved;
                    return Ok(None);
                }
            }
        }
        Ok(Some(args))
    }

    fn parse_bulk_string(&mut self) -> Result<Option<&'a [u8]>, &'static str> {
        if self.pos >= self.buf.len() {
            return Ok(None);
        }
        if self.buf[self.pos] != b'$' {
            return Err("ERR expected bulk string");
        }
        self.pos += 1;
        let len = match self.read_line_int() {
            Some(len) => len,
            None => return Ok(None),
        };
        if len < 0 {
            // Redis uses `$-1` for null bulk; command parser normalizes to empty here.
            return Ok(Some(b""));
        }
        let len = len as usize;
        if len > self.max_bulk_len {
            return Err("ERR RESP bulk length exceeds maximum");
        }
        let Some(end) = self.pos.checked_add(len).and_then(|p| p.checked_add(2)) else {
            return Err("ERR RESP bulk length exceeds maximum");
        };
        if end > self.buf.len() {
            return Ok(None);
        }
        if self.buf[self.pos + len..end] != *b"\r\n" {
            return Err("ERR invalid bulk string terminator");
        }
        let data = &self.buf[self.pos..self.pos + len];
        self.pos = end;
        Ok(Some(data))
    }

    fn read_line_int(&mut self) -> Option<i64> {
        let start = self.pos;
        while self.pos < self.buf.len() {
            if self.buf[self.pos] == b'\r'
                && self.pos + 1 < self.buf.len()
                && self.buf[self.pos + 1] == b'\n'
            {
                let line = &self.buf[start..self.pos];
                self.pos += 2;
                return parse_i64_bytes(line);
            }
            self.pos += 1;
        }
        // Incomplete line: keep parser retry-safe by restoring cursor.
        self.pos = start;
        None
    }
}

fn parse_i64_bytes(line: &[u8]) -> Option<i64> {
    let (negative, digits) = match line.first().copied() {
        Some(b'-') => (true, &line[1..]),
        Some(b'+') => (false, &line[1..]),
        Some(_) => (false, line),
        None => return None,
    };
    if digits.is_empty() {
        return None;
    }

    let mut value: i64 = 0;
    for &byte in digits {
        if !byte.is_ascii_digit() {
            return None;
        }
        let digit = i64::from(byte - b'0');
        value = value.checked_mul(10)?.checked_add(digit)?;
    }
    if negative {
        value.checked_neg()
    } else {
        Some(value)
    }
}

pub mod itoa {
    /// Tiny integer formatter used to avoid pulling in std formatting in hot paths.
    pub struct Buffer {
        buf: [u8; 20],
        pos: usize,
    }

    impl Buffer {
        pub fn new() -> Self {
            Self {
                buf: [0u8; 20],
                pos: 20,
            }
        }

        pub fn format_i64(&mut self, n: i64) -> &str {
            self.pos = 20;
            let negative = n < 0;
            let mut n = if negative { -(n as i128) } else { n as i128 } as u64;
            if n == 0 {
                self.pos -= 1;
                self.buf[self.pos] = b'0';
            } else {
                while n > 0 {
                    self.pos -= 1;
                    self.buf[self.pos] = b'0' + (n % 10) as u8;
                    n /= 10;
                }
            }
            if negative {
                self.pos -= 1;
                self.buf[self.pos] = b'-';
            }
            std::str::from_utf8(&self.buf[self.pos..]).unwrap()
        }

        pub fn format_usize(&mut self, mut n: usize) -> &str {
            self.pos = 20;
            if n == 0 {
                self.pos -= 1;
                self.buf[self.pos] = b'0';
            } else {
                while n > 0 {
                    self.pos -= 1;
                    self.buf[self.pos] = b'0' + (n % 10) as u8;
                    n /= 10;
                }
            }
            std::str::from_utf8(&self.buf[self.pos..]).unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_set_command() {
        let input = b"*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n";
        let mut parser = Parser::new(input);
        let args = parser.parse_command().unwrap().unwrap();
        assert_eq!(args.len(), 3);
        assert_eq!(args[0], b"SET");
        assert_eq!(args[1], b"foo");
        assert_eq!(args[2], b"bar");
        assert_eq!(parser.pos(), input.len());
    }

    #[test]
    fn parse_get_command() {
        let input = b"*2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n";
        let mut parser = Parser::new(input);
        let args = parser.parse_command().unwrap().unwrap();
        assert_eq!(args.len(), 2);
        assert_eq!(args[0], b"GET");
        assert_eq!(args[1], b"foo");
    }

    #[test]
    fn parse_multi_bulk_array() {
        let input = b"*5\r\n$4\r\nMSET\r\n$1\r\na\r\n$1\r\n1\r\n$1\r\nb\r\n$1\r\n2\r\n";
        let mut parser = Parser::new(input);
        let args = parser.parse_command().unwrap().unwrap();
        assert_eq!(args.len(), 5);
        assert_eq!(args[0], b"MSET");
    }

    #[test]
    fn parse_null_bulk_string() {
        let input = b"*2\r\n$3\r\nGET\r\n$-1\r\n";
        let mut parser = Parser::new(input);
        let args = parser.parse_command().unwrap().unwrap();
        assert_eq!(args.len(), 2);
        assert_eq!(args[1], b"");
    }

    #[test]
    fn parse_integer_response() {
        let mut buf = BytesMut::new();
        write_integer(&mut buf, 42);
        assert_eq!(&buf[..], b":42\r\n");
    }

    #[test]
    fn parse_negative_integer() {
        let mut buf = BytesMut::new();
        write_integer(&mut buf, -100);
        assert_eq!(&buf[..], b":-100\r\n");
    }

    #[test]
    fn parse_special_integers() {
        let mut buf = BytesMut::new();
        write_integer(&mut buf, 0);
        assert_eq!(&buf[..], ZERO);
        buf.clear();
        write_integer(&mut buf, 1);
        assert_eq!(&buf[..], ONE);
        buf.clear();
        write_integer(&mut buf, -1);
        assert_eq!(&buf[..], NEG_ONE);
        buf.clear();
        write_integer(&mut buf, -2);
        assert_eq!(&buf[..], NEG_TWO);
    }

    #[test]
    fn response_limit_discards_payload_before_buffer_growth() {
        let mut buf = BytesMut::new();
        let payload = vec![b'x'; 1024 * 1024];
        let limit = limit_output(32);

        write_bulk_raw(&mut buf, &payload);

        assert!(limit.exceeded());
        assert!(buf.len() <= 32);
        drop(limit);
        write_error(&mut buf, "ERR response limit");
        assert!(buf.ends_with(b"\r\n"));
    }

    #[test]
    fn response_construction_reserves_and_releases_process_capacity() {
        let budget = ByteBudget::new(4);
        let mut buf = BytesMut::from(&b"ab"[..]);
        let limit = limit_output_with_budget(8, buf.len(), budget.clone());

        write_encoded(&mut buf, b"cd");
        assert!(!limit.exceeded());
        write_encoded(&mut buf, b"e");
        assert!(limit.exceeded());
        assert!(limit.capacity_exhausted());
        assert_eq!(&buf[..], b"abcd");
        drop(limit);

        let limit = limit_output_with_budget(8, 0, budget);
        let mut recovered = BytesMut::new();
        write_encoded(&mut recovered, b"wxyz");
        assert!(!limit.exceeded());
        assert_eq!(&recovered[..], b"wxyz");
    }

    #[test]
    fn incomplete_buffer_returns_none() {
        let input = b"*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n";
        let mut parser = Parser::new(input);
        let result = parser.parse_command().unwrap();
        assert!(result.is_none());
        assert_eq!(parser.pos(), 0);
    }

    #[test]
    fn parse_inline_command() {
        let input = b"PING\r\n";
        let mut parser = Parser::new(input);
        let args = parser.parse_command().unwrap().unwrap();
        assert_eq!(args.len(), 1);
        assert_eq!(args[0], b"PING");
    }

    #[test]
    fn parse_inline_with_args() {
        let input = b"SET foo bar\r\n";
        let mut parser = Parser::new(input);
        let args = parser.parse_command().unwrap().unwrap();
        assert_eq!(args.len(), 3);
        assert_eq!(args[0], b"SET");
        assert_eq!(args[1], b"foo");
        assert_eq!(args[2], b"bar");
    }

    #[test]
    fn inline_commands_obey_the_argument_limit() {
        let mut parser = Parser::with_limits(b"SET foo bar\r\n", 64, 2);
        assert_eq!(
            parser.parse_command().unwrap_err(),
            "ERR RESP argument count exceeds maximum"
        );
    }

    #[test]
    fn skips_blank_lines_before_a_command() {
        let input = b"\r\n\n*1\r\n$4\r\nPING\r\n";
        let mut parser = Parser::new(input);
        let mut args = parser.parse_command().unwrap().unwrap();
        while args.is_empty() {
            args = parser.parse_command().unwrap().unwrap();
        }
        assert_eq!(args, vec![b"PING".as_slice()]);
        assert_eq!(parser.pos(), input.len());
    }

    #[test]
    fn write_bulk_string() {
        let mut buf = BytesMut::new();
        write_bulk(&mut buf, "hello");
        assert_eq!(&buf[..], b"$5\r\nhello\r\n");
    }

    #[test]
    fn write_array() {
        let mut buf = BytesMut::new();
        write_array_header(&mut buf, 3);
        assert_eq!(&buf[..], b"*3\r\n");
    }

    #[test]
    fn write_empty_array() {
        let mut buf = BytesMut::new();
        write_array_header(&mut buf, 0);
        assert_eq!(&buf[..], EMPTY_ARRAY);
    }

    #[test]
    fn write_error_response() {
        let mut buf = BytesMut::new();
        write_error(&mut buf, "ERR test error");
        assert_eq!(&buf[..], b"-ERR test error\r\n");
    }

    #[test]
    fn write_simple_string() {
        let mut buf = BytesMut::new();
        write_simple(&mut buf, "OK");
        assert_eq!(&buf[..], b"+OK\r\n");
    }

    #[test]
    fn parse_two_commands_in_sequence() {
        let input = b"*2\r\n$3\r\nGET\r\n$1\r\na\r\n*2\r\n$3\r\nGET\r\n$1\r\nb\r\n";
        let mut parser = Parser::new(input);
        let args1 = parser.parse_command().unwrap().unwrap();
        assert_eq!(args1[1], b"a");
        let args2 = parser.parse_command().unwrap().unwrap();
        assert_eq!(args2[1], b"b");
        assert!(parser.parse_command().unwrap().is_none());
    }

    #[test]
    fn itoa_format_i64() {
        let mut buf = itoa::Buffer::new();
        assert_eq!(buf.format_i64(0), "0");
        assert_eq!(buf.format_i64(42), "42");
        assert_eq!(buf.format_i64(-42), "-42");
        assert_eq!(buf.format_i64(i64::MAX), "9223372036854775807");
        assert_eq!(buf.format_i64(i64::MIN), "-9223372036854775808");
    }

    #[test]
    fn itoa_format_usize() {
        let mut buf = itoa::Buffer::new();
        assert_eq!(buf.format_usize(0), "0");
        assert_eq!(buf.format_usize(12345), "12345");
    }

    // Fuzz: arbitrary client bytes through the RESP parser must never panic --
    // a malformed frame is a clean Err, never a crash. Drains the parser to EOF.
    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(4000))]

        #[test]
        fn fuzz_resp_parse_no_panic(
            data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2048)
        ) {
            let mut parser = Parser::new(&data);
            // Pull commands until the parser stops yielding (Ok(None)) or errors.
            for _ in 0..1024 {
                match parser.parse_command() {
                    Ok(Some(_)) => continue,
                    Ok(None) | Err(_) => break,
                }
            }
        }
    }
}
