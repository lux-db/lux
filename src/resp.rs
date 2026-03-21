use bytes::{BufMut, BytesMut};

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

pub fn write_ok(buf: &mut BytesMut) {
    buf.extend_from_slice(OK);
}

pub fn write_pong(buf: &mut BytesMut) {
    buf.extend_from_slice(PONG);
}

pub fn write_null(buf: &mut BytesMut) {
    buf.extend_from_slice(NULL);
}

pub fn write_queued(buf: &mut BytesMut) {
    buf.extend_from_slice(QUEUED);
}

pub fn write_null_array(buf: &mut BytesMut) {
    buf.extend_from_slice(NULL_ARRAY);
}

pub fn write_simple(buf: &mut BytesMut, s: &str) {
    buf.put_u8(b'+');
    buf.extend_from_slice(s.as_bytes());
    buf.extend_from_slice(b"\r\n");
}

pub fn write_error(buf: &mut BytesMut, s: &str) {
    buf.put_u8(b'-');
    buf.extend_from_slice(s.as_bytes());
    buf.extend_from_slice(b"\r\n");
}

pub fn write_integer(buf: &mut BytesMut, n: i64) {
    match n {
        0 => buf.extend_from_slice(ZERO),
        1 => buf.extend_from_slice(ONE),
        -1 => buf.extend_from_slice(NEG_ONE),
        -2 => buf.extend_from_slice(NEG_TWO),
        _ => {
            buf.put_u8(b':');
            let mut tmp = itoa::Buffer::new();
            buf.extend_from_slice(tmp.format_i64(n).as_bytes());
            buf.extend_from_slice(b"\r\n");
        }
    }
}

pub fn write_bulk(buf: &mut BytesMut, s: &str) {
    write_bulk_raw(buf, s.as_bytes());
}

pub fn write_bulk_raw(buf: &mut BytesMut, data: &[u8]) {
    buf.put_u8(b'$');
    let mut tmp = itoa::Buffer::new();
    buf.extend_from_slice(tmp.format_usize(data.len()).as_bytes());
    buf.extend_from_slice(b"\r\n");
    buf.extend_from_slice(data);
    buf.extend_from_slice(b"\r\n");
}

pub fn write_array_header(buf: &mut BytesMut, len: usize) {
    if len == 0 {
        buf.extend_from_slice(EMPTY_ARRAY);
    } else {
        buf.put_u8(b'*');
        let mut tmp = itoa::Buffer::new();
        buf.extend_from_slice(tmp.format_usize(len).as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
}

pub fn write_map_header(buf: &mut BytesMut, len: usize) {
    buf.put_u8(b'%');
    let mut tmp = itoa::Buffer::new();
    buf.extend_from_slice(tmp.format_usize(len).as_bytes());
    buf.extend_from_slice(b"\r\n");
}

pub fn write_bulk_array(buf: &mut BytesMut, items: &[String]) {
    write_array_header(buf, items.len());
    for item in items {
        write_bulk(buf, item);
    }
}

pub fn write_bulk_array_raw(buf: &mut BytesMut, items: &[bytes::Bytes]) {
    write_array_header(buf, items.len());
    for item in items {
        write_bulk_raw(buf, item);
    }
}

pub fn write_optional_bulk_raw(buf: &mut BytesMut, val: &Option<bytes::Bytes>) {
    match val {
        Some(s) => write_bulk_raw(buf, s),
        None => write_null(buf),
    }
}

pub struct Parser<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn parse_command(&mut self) -> Result<Option<Vec<&'a [u8]>>, &'static str> {
        if self.pos >= self.buf.len() {
            return Ok(None);
        }
        match self.buf[self.pos] {
            b'*' => self.parse_multibulk(),
            _ => self.parse_inline(),
        }
    }

    fn parse_inline(&mut self) -> Result<Option<Vec<&'a [u8]>>, &'static str> {
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
                let parts: Vec<&'a [u8]> = line
                    .split(|&b| b == b' ')
                    .filter(|s| !s.is_empty())
                    .collect();
                if parts.is_empty() {
                    return Ok(None);
                }
                return Ok(Some(parts));
            }
            self.pos += 1;
        }
        self.pos = start;
        Ok(None)
    }

    fn parse_multibulk(&mut self) -> Result<Option<Vec<&'a [u8]>>, &'static str> {
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
        let mut args = Vec::with_capacity(count as usize);
        for _ in 0..count {
            match self.parse_bulk_string() {
                Some(s) => args.push(s),
                None => {
                    self.pos = saved;
                    return Ok(None);
                }
            }
        }
        Ok(Some(args))
    }

    fn parse_bulk_string(&mut self) -> Option<&'a [u8]> {
        if self.pos >= self.buf.len() || self.buf[self.pos] != b'$' {
            return None;
        }
        self.pos += 1;
        let len = self.read_line_int()?;
        if len < 0 {
            return Some(b"");
        }
        let len = len as usize;
        if self.pos + len + 2 > self.buf.len() {
            return None;
        }
        let data = &self.buf[self.pos..self.pos + len];
        self.pos += len + 2;
        Some(data)
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
                let s = std::str::from_utf8(line).ok()?;
                return s.parse().ok();
            }
            self.pos += 1;
        }
        self.pos = start;
        None
    }
}

pub mod itoa {
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
}
