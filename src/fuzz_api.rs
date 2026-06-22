//! Public, feature-gated entrypoints for the coverage-guided fuzz targets in
//! `fuzz/`. Each takes raw untrusted bytes and drives one decoder to its clean
//! contract (return Ok/Err, never panic/OOM/abort). Compiled only under
//! `--features fuzzing`; not part of the normal public API.
//!
//! The same decoders are also fuzzed in-crate with proptest (see the
//! `fuzz_*_no_panic` tests); this module exposes them to libfuzzer for
//! coverage-guided, OSS-Fuzz-style continuous fuzzing.

use std::io::Cursor;

/// Binary snapshot loader (`lux.dat`).
pub fn fuzz_snapshot(data: &[u8]) {
    let store =
        crate::store::Store::new_with_config(std::sync::Arc::new(crate::ServerConfig::default()));
    let _ = crate::snapshot::load_binary(&store, &mut Cursor::new(data), true, true);
}

/// RESP request parser.
pub fn fuzz_resp(data: &[u8]) {
    let mut parser = crate::resp::Parser::new(data);
    for _ in 0..4096 {
        match parser.parse_command() {
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => break,
        }
    }
}

/// Lua MessagePack decoder (`cmsgpack.unpack`).
pub fn fuzz_msgpack(data: &[u8]) {
    let lua = mlua::Lua::new();
    let owned = data.to_vec();
    let mut cursor = Cursor::new(&owned);
    let _ = crate::lua::msgpack_unpack_value(&lua, &mut cursor, 0);
}

/// TSELECT query / WHERE parser.
pub fn fuzz_table_query(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let tokens: Vec<&str> = text.split_whitespace().collect();
    let _ = crate::tables::select::parse_select(&tokens);
}

/// RESP parse -> command dispatch/lowering. Uses an in-memory store and skips
/// commands with side effects or that block, so the fuzzer can't write files or
/// hang.
pub fn fuzz_command(data: &[u8]) {
    let mut parser = crate::resp::Parser::new(data);
    let args = match parser.parse_command() {
        Ok(Some(a)) if !a.is_empty() => a,
        _ => return,
    };
    const SKIP: &[&[u8]] = &[
        b"SAVE",
        b"BGSAVE",
        b"BGREWRITEAOF",
        b"FLUSHALL",
        b"FLUSHDB",
        b"DEBUG",
        b"SHUTDOWN",
        b"BLPOP",
        b"BRPOP",
        b"BLMOVE",
        b"BRPOPLPUSH",
        b"BLMPOP",
        b"BZPOPMIN",
        b"BZPOPMAX",
        b"BZMPOP",
        b"WAIT",
        b"SUBSCRIBE",
        b"PSUBSCRIBE",
        b"MONITOR",
    ];
    let first_upper: Vec<u8> = args[0].iter().map(u8::to_ascii_uppercase).collect();
    if SKIP.contains(&first_upper.as_slice()) {
        return;
    }
    let store =
        crate::store::Store::new_with_config(std::sync::Arc::new(crate::ServerConfig::default()));
    let broker = crate::pubsub::Broker::new();
    let cache = std::sync::Arc::new(parking_lot::RwLock::new(crate::tables::SchemaCache::new()));
    let mut out = bytes::BytesMut::new();
    crate::cmd::execute(
        &store,
        &cache,
        &broker,
        &args,
        &mut out,
        std::time::Instant::now(),
    );
}
