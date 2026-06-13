//! Binary JSON storage (a JSONB-style format) for the `JSON`/`ARRAY` column
//! types. JSON is parsed once at write time into a flat, length-prefixed binary
//! and stored as bytes. Reads walk the bytes with zero allocation to extract a
//! dot-path scalar — no `serde_json::Value` tree is rebuilt per row, which is
//! what makes path filtering fast at scale.
//!
//! Wire format (recursive, little-endian):
//!   NULL    0x00
//!   FALSE   0x01
//!   TRUE    0x02
//!   I64     0x03  i64
//!   F64     0x04  f64
//!   STR     0x05  u32 len, bytes
//!   ARRAY   0x06  u32 count, [value...]
//!   OBJECT  0x07  u32 count, [u32 keylen, key, value]...

use serde_json::Value;

const T_NULL: u8 = 0x00;
const T_FALSE: u8 = 0x01;
const T_TRUE: u8 = 0x02;
const T_I64: u8 = 0x03;
const T_F64: u8 = 0x04;
const T_STR: u8 = 0x05;
const T_ARRAY: u8 = 0x06;
const T_OBJECT: u8 = 0x07;

// ---------------------------------------------------------------------------
// Encode: serde_json::Value -> binary (write path, once per write)
// ---------------------------------------------------------------------------

pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    encode_into(value, &mut out);
    out
}

fn encode_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.push(T_NULL),
        Value::Bool(false) => out.push(T_FALSE),
        Value::Bool(true) => out.push(T_TRUE),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push(T_I64);
                out.extend_from_slice(&i.to_le_bytes());
            } else {
                out.push(T_F64);
                out.extend_from_slice(&n.as_f64().unwrap_or(0.0).to_le_bytes());
            }
        }
        Value::String(s) => {
            out.push(T_STR);
            out.extend_from_slice(&(s.len() as u32).to_le_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(arr) => {
            out.push(T_ARRAY);
            out.extend_from_slice(&(arr.len() as u32).to_le_bytes());
            for el in arr {
                encode_into(el, out);
            }
        }
        Value::Object(map) => {
            out.push(T_OBJECT);
            out.extend_from_slice(&(map.len() as u32).to_le_bytes());
            for (k, v) in map {
                out.extend_from_slice(&(k.len() as u32).to_le_bytes());
                out.extend_from_slice(k.as_bytes());
                encode_into(v, out);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Low-level cursor helpers (zero-alloc reads)
// ---------------------------------------------------------------------------

fn read_u32(b: &[u8], pos: usize) -> Option<(u32, usize)> {
    let end = pos.checked_add(4)?;
    let slice = b.get(pos..end)?;
    Some((u32::from_le_bytes(slice.try_into().ok()?), end))
}

fn read_i64(b: &[u8], pos: usize) -> Option<(i64, usize)> {
    let end = pos.checked_add(8)?;
    let slice = b.get(pos..end)?;
    Some((i64::from_le_bytes(slice.try_into().ok()?), end))
}

fn read_f64(b: &[u8], pos: usize) -> Option<(f64, usize)> {
    let end = pos.checked_add(8)?;
    let slice = b.get(pos..end)?;
    Some((f64::from_le_bytes(slice.try_into().ok()?), end))
}

/// Return the byte position just past the value starting at `pos`.
fn skip_value(b: &[u8], pos: usize) -> Option<usize> {
    let tag = *b.get(pos)?;
    let p = pos + 1;
    match tag {
        T_NULL | T_FALSE | T_TRUE => Some(p),
        T_I64 | T_F64 => Some(p + 8),
        T_STR => {
            let (len, p) = read_u32(b, p)?;
            Some(p + len as usize)
        }
        T_ARRAY => {
            let (count, mut p) = read_u32(b, p)?;
            for _ in 0..count {
                p = skip_value(b, p)?;
            }
            Some(p)
        }
        T_OBJECT => {
            let (count, mut p) = read_u32(b, p)?;
            for _ in 0..count {
                let (klen, kp) = read_u32(b, p)?;
                p = skip_value(b, kp + klen as usize)?;
            }
            Some(p)
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Path resolution (read path, hot)
// ---------------------------------------------------------------------------

/// A resolved JSON scalar (borrowed where possible), or a container marker.
pub enum JsonbRef<'a> {
    Null,
    Bool(bool),
    I64(i64),
    F64(f64),
    Str(&'a str),
    /// An array value; the slice is the bytes of the array value (tag included).
    Array(&'a [u8]),
    /// An object value (bytes not materialized — objects aren't directly compared).
    Object,
}

/// Outcome of walking a dot-path.
pub enum Resolve<'a> {
    /// Path resolved to a present value.
    Found(JsonbRef<'a>),
    /// A key/index along the path was missing.
    Absent,
    /// Tried to descend into a scalar/null.
    Invalid,
}

fn value_at(b: &[u8], pos: usize) -> Option<JsonbRef<'_>> {
    let tag = *b.get(pos)?;
    let p = pos + 1;
    Some(match tag {
        T_NULL => JsonbRef::Null,
        T_FALSE => JsonbRef::Bool(false),
        T_TRUE => JsonbRef::Bool(true),
        T_I64 => JsonbRef::I64(read_i64(b, p)?.0),
        T_F64 => JsonbRef::F64(read_f64(b, p)?.0),
        T_STR => {
            let (len, p) = read_u32(b, p)?;
            let s = std::str::from_utf8(b.get(p..p + len as usize)?).ok()?;
            JsonbRef::Str(s)
        }
        T_ARRAY => JsonbRef::Array(b.get(pos..skip_value(b, pos)?)?),
        T_OBJECT => JsonbRef::Object,
        _ => return None,
    })
}

/// Find the byte position of the child addressed by `seg` within the container
/// value at `pos`. Returns Ok(Some(child_pos)) / Ok(None)=absent / Err=invalid.
fn find_child(b: &[u8], pos: usize, seg: &str) -> Result<Option<usize>, ()> {
    let tag = *b.get(pos).ok_or(())?;
    let mut p = pos + 1;
    match tag {
        T_OBJECT => {
            let (count, np) = read_u32(b, p).ok_or(())?;
            p = np;
            for _ in 0..count {
                let (klen, kp) = read_u32(b, p).ok_or(())?;
                let key = b.get(kp..kp + klen as usize).ok_or(())?;
                let vpos = kp + klen as usize;
                if key == seg.as_bytes() {
                    return Ok(Some(vpos));
                }
                p = skip_value(b, vpos).ok_or(())?;
            }
            Ok(None)
        }
        T_ARRAY => {
            let idx: usize = match seg.parse() {
                Ok(i) => i,
                Err(_) => return Err(()), // non-numeric index into array
            };
            let (count, np) = read_u32(b, p).ok_or(())?;
            p = np;
            for i in 0..count {
                if i as usize == idx {
                    return Ok(Some(p));
                }
                p = skip_value(b, p).ok_or(())?;
            }
            Ok(None)
        }
        _ => Err(()), // descending into a scalar/null
    }
}

/// Walk a dotted path (`a.b.0.c`) into the binary, zero-alloc.
pub fn get_path<'a>(b: &'a [u8], path: &str) -> Resolve<'a> {
    let mut pos = 0usize;
    for seg in path.split('.') {
        match find_child(b, pos, seg) {
            Ok(Some(child)) => pos = child,
            Ok(None) => return Resolve::Absent,
            Err(()) => return Resolve::Invalid,
        }
    }
    match value_at(b, pos) {
        Some(v) => Resolve::Found(v),
        None => Resolve::Invalid,
    }
}

/// The top-level value is an array containing a scalar element equal (by string
/// form) to `needle`. Zero-alloc scan.
pub fn array_contains(b: &[u8], needle: &str) -> bool {
    array_contains_at(b, 0, needle)
}

fn array_contains_at(b: &[u8], pos: usize, needle: &str) -> bool {
    if b.get(pos) != Some(&T_ARRAY) {
        return false;
    }
    let Some((count, mut p)) = read_u32(b, pos + 1) else {
        return false;
    };
    for _ in 0..count {
        if let Some(v) = value_at(b, p) {
            if scalar_eq_str(&v, needle) {
                return true;
            }
        }
        match skip_value(b, p) {
            Some(np) => p = np,
            None => return false,
        }
    }
    false
}

/// Compare a resolved scalar to a string operand the way the query layer does.
pub fn scalar_eq_str(v: &JsonbRef, needle: &str) -> bool {
    match v {
        JsonbRef::Str(s) => *s == needle,
        JsonbRef::I64(i) => needle.parse::<i64>().map(|n| n == *i).unwrap_or(false),
        JsonbRef::F64(f) => needle
            .parse::<f64>()
            .map(|n| (n - *f).abs() < f64::EPSILON)
            .unwrap_or(false),
        JsonbRef::Bool(bl) => needle == if *bl { "true" } else { "false" },
        _ => false,
    }
}

impl JsonbRef<'_> {
    pub fn is_null(&self) -> bool {
        matches!(self, JsonbRef::Null)
    }
}

// ---------------------------------------------------------------------------
// Decode: binary -> JSON text (read path, only for returned columns)
// ---------------------------------------------------------------------------

pub fn to_json_string(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len());
    let _ = write_json(b, 0, &mut out);
    out
}

fn write_json(b: &[u8], pos: usize, out: &mut String) -> Option<usize> {
    use std::fmt::Write;
    let tag = *b.get(pos)?;
    let p = pos + 1;
    match tag {
        T_NULL => {
            out.push_str("null");
            Some(p)
        }
        T_FALSE => {
            out.push_str("false");
            Some(p)
        }
        T_TRUE => {
            out.push_str("true");
            Some(p)
        }
        T_I64 => {
            let (i, p) = read_i64(b, p)?;
            let _ = write!(out, "{i}");
            Some(p)
        }
        T_F64 => {
            let (f, p) = read_f64(b, p)?;
            // Reuse serde_json's number formatting for round-trip fidelity.
            let v = serde_json::Number::from_f64(f).map(serde_json::Value::Number);
            match v {
                Some(serde_json::Value::Number(n)) => {
                    let _ = write!(out, "{n}");
                }
                _ => out.push_str("null"),
            }
            Some(p)
        }
        T_STR => {
            let (len, p) = read_u32(b, p)?;
            let s = std::str::from_utf8(b.get(p..p + len as usize)?).ok()?;
            write_json_str(s, out);
            Some(p + len as usize)
        }
        T_ARRAY => {
            let (count, mut p) = read_u32(b, p)?;
            out.push('[');
            for i in 0..count {
                if i > 0 {
                    out.push(',');
                }
                p = write_json(b, p, out)?;
            }
            out.push(']');
            Some(p)
        }
        T_OBJECT => {
            let (count, mut p) = read_u32(b, p)?;
            out.push('{');
            for i in 0..count {
                if i > 0 {
                    out.push(',');
                }
                let (klen, kp) = read_u32(b, p)?;
                let key = std::str::from_utf8(b.get(kp..kp + klen as usize)?).ok()?;
                write_json_str(key, out);
                out.push(':');
                p = write_json(b, kp + klen as usize, out)?;
            }
            out.push('}');
            Some(p)
        }
        _ => None,
    }
}

fn write_json_str(s: &str, out: &mut String) {
    out.push('"');
    // Bulk-copy runs of safe characters; only break out at bytes needing escape.
    // Escapes are all single-byte ASCII, so slicing at those indices stays on
    // UTF-8 char boundaries (multi-byte bytes are >= 0x80 and never match).
    let bytes = s.as_bytes();
    let mut start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        let escape: &str = match b {
            b'"' => "\\\"",
            b'\\' => "\\\\",
            b'\n' => "\\n",
            b'\r' => "\\r",
            b'\t' => "\\t",
            0..=0x1f => {
                out.push_str(&s[start..i]);
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", b as u32);
                start = i + 1;
                continue;
            }
            _ => continue,
        };
        out.push_str(&s[start..i]);
        out.push_str(escape);
        start = i + 1;
    }
    out.push_str(&s[start..]);
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn roundtrip(v: serde_json::Value) {
        let b = encode(&v);
        let back: serde_json::Value = serde_json::from_str(&to_json_string(&b)).unwrap();
        assert_eq!(v, back, "roundtrip mismatch");
    }

    #[test]
    fn roundtrips_scalars_and_nesting() {
        roundtrip(json!(null));
        roundtrip(json!(true));
        roundtrip(json!(42));
        roundtrip(json!(-7));
        roundtrip(json!(3.5));
        roundtrip(json!("hi \"there\"\n"));
        roundtrip(json!([1, 2, 3]));
        roundtrip(json!({"a": 1, "b": {"c": [true, "x"]}}));
        roundtrip(json!({"reactions": {"count": 0}, "flagged": true}));
    }

    fn found_i64(b: &[u8], path: &str) -> Option<i64> {
        match get_path(b, path) {
            Resolve::Found(JsonbRef::I64(i)) => Some(i),
            _ => None,
        }
    }

    #[test]
    fn path_resolves_nested_and_arrays() {
        let b = encode(&json!({"reactions": {"count": 10}, "tags": ["red", "blue"]}));
        assert_eq!(found_i64(&b, "reactions.count"), Some(10));
        match get_path(&b, "tags.1") {
            Resolve::Found(JsonbRef::Str(s)) => assert_eq!(s, "blue"),
            _ => panic!("expected blue"),
        }
        assert!(matches!(get_path(&b, "tags.5"), Resolve::Absent));
        assert!(matches!(get_path(&b, "missing.x"), Resolve::Absent));
        // descend into a scalar => Invalid
        assert!(matches!(
            get_path(&b, "reactions.count.x"),
            Resolve::Invalid
        ));
    }

    #[test]
    fn zero_is_present_not_null() {
        let b = encode(&json!({"count": 0}));
        match get_path(&b, "count") {
            Resolve::Found(v) => assert!(!v.is_null()),
            _ => panic!("expected found"),
        }
    }

    #[test]
    fn array_contains_scalar() {
        let b = encode(&json!(["red", "green", "blue"]));
        assert!(array_contains(&b, "blue"));
        assert!(!array_contains(&b, "yellow"));
        let nums = encode(&json!([1, 2, 3]));
        assert!(array_contains(&nums, "2"));
    }
}
