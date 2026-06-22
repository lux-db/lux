use bytes::BytesMut;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io::Cursor;
use std::sync::Arc;
use std::time::Instant;

use crate::pubsub::Broker;
use crate::store::Store;

pub struct ScriptEngine {
    scripts: Mutex<HashMap<String, String>>,
}

impl ScriptEngine {
    pub fn new() -> Self {
        Self {
            scripts: Mutex::new(HashMap::new()),
        }
    }

    pub fn load(&self, script: &str) -> String {
        let sha = sha1_smol::Sha1::from(script).digest().to_string();
        self.scripts.lock().insert(sha.clone(), script.to_string());
        sha
    }

    pub fn get(&self, sha: &str) -> Option<String> {
        self.scripts.lock().get(sha).cloned()
    }

    pub fn exists(&self, sha: &str) -> bool {
        self.scripts.lock().contains_key(sha)
    }

    pub fn flush(&self) {
        self.scripts.lock().clear();
    }
}

fn resp_to_lua(lua: &mlua::Lua, data: &[u8]) -> mlua::Result<mlua::Value> {
    if data.is_empty() {
        return Ok(mlua::Value::Nil);
    }
    match data[0] {
        b'+' => {
            let end = data.iter().position(|&b| b == b'\r').unwrap_or(data.len());
            let s = std::str::from_utf8(&data[1..end]).unwrap_or("");
            let tbl = lua.create_table()?;
            tbl.set("ok", s)?;
            Ok(mlua::Value::Table(tbl))
        }
        b'-' => {
            let end = data.iter().position(|&b| b == b'\r').unwrap_or(data.len());
            let s = std::str::from_utf8(&data[1..end]).unwrap_or("");
            let tbl = lua.create_table()?;
            tbl.set("err", s)?;
            Ok(mlua::Value::Table(tbl))
        }
        b':' => {
            let end = data.iter().position(|&b| b == b'\r').unwrap_or(data.len());
            let s = std::str::from_utf8(&data[1..end]).unwrap_or("0");
            let n: i64 = s.parse().unwrap_or(0);
            Ok(mlua::Value::Integer(n))
        }
        b'$' => {
            let end = data.iter().position(|&b| b == b'\r').unwrap_or(data.len());
            let len_s = std::str::from_utf8(&data[1..end]).unwrap_or("-1");
            let len: i64 = len_s.parse().unwrap_or(-1);
            if len < 0 {
                return Ok(mlua::Value::Boolean(false));
            }
            let start = end + 2;
            let val_end = start + len as usize;
            if val_end <= data.len() {
                let s = lua.create_string(&data[start..val_end])?;
                Ok(mlua::Value::String(s))
            } else {
                Ok(mlua::Value::Nil)
            }
        }
        b'*' => {
            let end = data.iter().position(|&b| b == b'\r').unwrap_or(data.len());
            let count_s = std::str::from_utf8(&data[1..end]).unwrap_or("-1");
            let count: i64 = count_s.parse().unwrap_or(-1);
            if count < 0 {
                return Ok(mlua::Value::Boolean(false));
            }
            let tbl = lua.create_table()?;
            let mut pos = end + 2;
            for i in 0..count as usize {
                if pos >= data.len() {
                    break;
                }
                let (val, consumed) = resp_element_to_lua(lua, &data[pos..])?;
                tbl.set(i + 1, val)?;
                pos += consumed;
            }
            Ok(mlua::Value::Table(tbl))
        }
        _ => Ok(mlua::Value::Nil),
    }
}

fn resp_element_to_lua(lua: &mlua::Lua, data: &[u8]) -> mlua::Result<(mlua::Value, usize)> {
    if data.is_empty() {
        return Ok((mlua::Value::Nil, 0));
    }
    match data[0] {
        b'+' => {
            let end = data.iter().position(|&b| b == b'\r').unwrap_or(data.len());
            let s = std::str::from_utf8(&data[1..end]).unwrap_or("");
            let tbl = lua.create_table()?;
            tbl.set("ok", s)?;
            Ok((mlua::Value::Table(tbl), end + 2))
        }
        b'-' => {
            let end = data.iter().position(|&b| b == b'\r').unwrap_or(data.len());
            let s = std::str::from_utf8(&data[1..end]).unwrap_or("");
            let tbl = lua.create_table()?;
            tbl.set("err", s)?;
            Ok((mlua::Value::Table(tbl), end + 2))
        }
        b':' => {
            let end = data.iter().position(|&b| b == b'\r').unwrap_or(data.len());
            let s = std::str::from_utf8(&data[1..end]).unwrap_or("0");
            let n: i64 = s.parse().unwrap_or(0);
            Ok((mlua::Value::Integer(n), end + 2))
        }
        b'$' => {
            let end = data.iter().position(|&b| b == b'\r').unwrap_or(data.len());
            let len_s = std::str::from_utf8(&data[1..end]).unwrap_or("-1");
            let len: i64 = len_s.parse().unwrap_or(-1);
            if len < 0 {
                return Ok((mlua::Value::Boolean(false), end + 2));
            }
            let start = end + 2;
            let val_end = start + len as usize;
            let total = val_end + 2;
            if val_end <= data.len() {
                let s = lua.create_string(&data[start..val_end])?;
                Ok((mlua::Value::String(s), total))
            } else {
                Ok((mlua::Value::Nil, data.len()))
            }
        }
        b'*' => {
            let end = data.iter().position(|&b| b == b'\r').unwrap_or(data.len());
            let count_s = std::str::from_utf8(&data[1..end]).unwrap_or("-1");
            let count: i64 = count_s.parse().unwrap_or(-1);
            if count < 0 {
                return Ok((mlua::Value::Boolean(false), end + 2));
            }
            let tbl = lua.create_table()?;
            let mut pos = end + 2;
            for i in 0..count as usize {
                if pos >= data.len() {
                    break;
                }
                let (val, consumed) = resp_element_to_lua(lua, &data[pos..])?;
                tbl.set(i + 1, val)?;
                pos += consumed;
            }
            Ok((mlua::Value::Table(tbl), pos))
        }
        _ => {
            let end = data.iter().position(|&b| b == b'\r').unwrap_or(data.len());
            Ok((mlua::Value::Nil, end + 2))
        }
    }
}

fn lua_to_resp(val: &mlua::Value, out: &mut BytesMut) {
    match val {
        mlua::Value::Nil => {
            crate::resp::write_null(out);
        }
        mlua::Value::Boolean(false) => {
            crate::resp::write_null(out);
        }
        mlua::Value::Boolean(true) => {
            crate::resp::write_integer(out, 1);
        }
        mlua::Value::Integer(n) => {
            crate::resp::write_integer(out, *n);
        }
        mlua::Value::Number(n) => {
            crate::resp::write_integer(out, *n as i64);
        }
        mlua::Value::String(s) => {
            let b: Vec<u8> = s.as_bytes().to_vec();
            crate::resp::write_bulk_raw(out, &b);
        }
        mlua::Value::Table(tbl) => {
            if let Ok(mlua::Value::String(s)) = tbl.get::<mlua::Value>("ok") {
                let sv: String = s
                    .to_str()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|_| "OK".to_string());
                crate::resp::write_simple(out, &sv);
                return;
            }
            if let Ok(mlua::Value::String(s)) = tbl.get::<mlua::Value>("err") {
                let sv: String = s
                    .to_str()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|_| "ERR".to_string());
                crate::resp::write_error(out, &sv);
                return;
            }
            let len = tbl.len().unwrap_or(0) as usize;
            crate::resp::write_array_header(out, len);
            for i in 1..=len {
                if let Ok(v) = tbl.get::<mlua::Value>(i) {
                    lua_to_resp(&v, out);
                } else {
                    crate::resp::write_null(out);
                }
            }
        }
        _ => {
            crate::resp::write_null(out);
        }
    }
}

pub fn eval(
    script: &str,
    keys: &[Vec<u8>],
    argv: &[Vec<u8>],
    store: &Arc<Store>,
    broker: &Broker,
    now: Instant,
) -> Result<BytesMut, String> {
    let lua = mlua::Lua::new();
    install_lua_sandbox(&lua)?;

    let keys_table = lua
        .create_table()
        .map_err(|e| format!("ERR lua error: {}", e))?;
    for (i, k) in keys.iter().enumerate() {
        keys_table
            .set(
                i + 1,
                lua.create_string(k)
                    .map_err(|e| format!("ERR lua error: {}", e))?,
            )
            .map_err(|e| format!("ERR lua error: {}", e))?;
    }
    lua.globals()
        .set("KEYS", keys_table)
        .map_err(|e| format!("ERR lua error: {}", e))?;

    let argv_table = lua
        .create_table()
        .map_err(|e| format!("ERR lua error: {}", e))?;
    for (i, a) in argv.iter().enumerate() {
        argv_table
            .set(
                i + 1,
                lua.create_string(a)
                    .map_err(|e| format!("ERR lua error: {}", e))?,
            )
            .map_err(|e| format!("ERR lua error: {}", e))?;
    }
    lua.globals()
        .set("ARGV", argv_table)
        .map_err(|e| format!("ERR lua error: {}", e))?;

    // `redis.call` raises on a command error (aborting the script); `redis.pcall`
    // returns the error as a `{err=...}` table. They were the same function before,
    // so `pcall` wrongly aborted instead of returning the error table.
    let redis_call = create_redis_call(&lua, store.clone(), broker.clone(), now, true)
        .map_err(|e| format!("ERR lua error: {}", e))?;
    let redis_pcall = create_redis_call(&lua, store.clone(), broker.clone(), now, false)
        .map_err(|e| format!("ERR lua error: {}", e))?;

    let redis = lua
        .create_table()
        .map_err(|e| format!("ERR lua error: {}", e))?;
    redis
        .set("call", redis_call)
        .map_err(|e| format!("ERR lua error: {}", e))?;
    redis
        .set("pcall", redis_pcall)
        .map_err(|e| format!("ERR lua error: {}", e))?;
    lua.globals()
        .set("redis", redis)
        .map_err(|e| format!("ERR lua error: {}", e))?;

    let cmsgpack = lua
        .create_table()
        .map_err(|e| format!("ERR lua error: {}", e))?;
    let pack_fn = lua
        .create_function(|_lua, args: mlua::MultiValue| {
            let mut buf = Vec::new();
            if args.len() == 1 {
                msgpack_pack_value(&args[0], &mut buf).map_err(mlua::Error::external)?;
            } else {
                for val in &args {
                    msgpack_pack_value(val, &mut buf).map_err(mlua::Error::external)?;
                }
            }
            Ok(mlua::Value::String(_lua.create_string(&buf)?))
        })
        .map_err(|e| format!("ERR lua error: {}", e))?;
    let unpack_fn = lua
        .create_function(|lua_ctx, data: mlua::String| {
            let bytes = data.as_bytes().to_vec();
            let mut cursor = Cursor::new(&bytes);
            msgpack_unpack_value(lua_ctx, &mut cursor, 0).map_err(mlua::Error::external)
        })
        .map_err(|e| format!("ERR lua error: {}", e))?;
    cmsgpack
        .set("pack", pack_fn)
        .map_err(|e| format!("ERR lua error: {}", e))?;
    cmsgpack
        .set("unpack", unpack_fn)
        .map_err(|e| format!("ERR lua error: {}", e))?;
    lua.globals()
        .set("cmsgpack", cmsgpack)
        .map_err(|e| format!("ERR lua error: {}", e))?;

    let cjson = lua
        .create_table()
        .map_err(|e| format!("ERR lua error: {}", e))?;
    let cjson_encode = lua
        .create_function(|lua_ctx, val: mlua::Value| {
            let json = lua_value_to_json(&val);
            lua_ctx
                .create_string(json.as_bytes())
                .map(mlua::Value::String)
        })
        .map_err(|e| format!("ERR lua error: {}", e))?;
    let cjson_decode = lua
        .create_function(|lua_ctx, s: mlua::String| {
            let bytes = s.as_bytes().to_vec();
            let json_str = std::str::from_utf8(&bytes).unwrap_or("null");
            json_to_lua_value(lua_ctx, json_str).map_err(mlua::Error::external)
        })
        .map_err(|e| format!("ERR lua error: {}", e))?;
    cjson
        .set("encode", cjson_encode)
        .map_err(|e| format!("ERR lua error: {}", e))?;
    cjson
        .set("decode", cjson_decode)
        .map_err(|e| format!("ERR lua error: {}", e))?;
    lua.globals()
        .set("cjson", cjson)
        .map_err(|e| format!("ERR lua error: {}", e))?;

    lua.load("unpack = table.unpack")
        .exec()
        .map_err(|e| format!("ERR lua error: {}", e))?;

    // Limit execution to 1M VM instructions to prevent infinite loops,
    // infinite recursion, and CPU exhaustion from malicious scripts.
    lua.set_hook(mlua::HookTriggers::new().every_nth_instruction(10_000), {
        let count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        move |_lua, _debug| {
            let n = count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if n >= 100 {
                // 100 callbacks * 10,000 instructions = 1M instructions max
                Err(mlua::Error::RuntimeError(
                    "ERR script exceeded maximum execution limit (1000000 instructions)"
                        .to_string(),
                ))
            } else {
                Ok(mlua::VmState::Continue)
            }
        }
    });

    let result: mlua::Value = lua.load(script).eval().map_err(|e| format!("ERR {}", e))?;

    let mut out = BytesMut::new();
    lua_to_resp(&result, &mut out);
    Ok(out)
}

/// Build a `redis.call`/`redis.pcall` function. When `raise_errors` is true a
/// command error becomes a raised Lua error (aborts the script); when false the
/// error is returned as a `{err=...}` table (pcall semantics).
fn create_redis_call(
    lua: &mlua::Lua,
    store: Arc<Store>,
    broker: Broker,
    now: Instant,
    raise_errors: bool,
) -> mlua::Result<mlua::Function> {
    lua.create_function(move |lua_ctx, args: mlua::MultiValue| {
        let mut cmd_args: Vec<Vec<u8>> = Vec::new();
        for arg in args {
            match arg {
                mlua::Value::String(s) => cmd_args.push(s.as_bytes().to_vec()),
                mlua::Value::Integer(n) => cmd_args.push(n.to_string().into_bytes()),
                mlua::Value::Number(n) => cmd_args.push(n.to_string().into_bytes()),
                _ => cmd_args.push(b"".to_vec()),
            }
        }
        if cmd_args.is_empty() {
            return Err(mlua::Error::external(
                "ERR wrong number of arguments for redis.call",
            ));
        }
        // Scripts may not run admin/blocking/transaction/pubsub commands.
        if let Some(err) = lua_disallowed_command_error(&cmd_args[0]) {
            if raise_errors {
                return Err(mlua::Error::external(err));
            }
            let tbl = lua_ctx.create_table()?;
            tbl.set("err", err)?;
            return Ok(mlua::Value::Table(tbl));
        }
        let refs: Vec<&[u8]> = cmd_args.iter().map(|v| v.as_slice()).collect();
        let mut out = BytesMut::new();
        let lua_cache =
            std::sync::Arc::new(parking_lot::RwLock::new(crate::tables::SchemaCache::new()));
        // Route through execute_with_wal so a script's writes are durable:
        // KV writes get logged (raw args are already concrete -> deterministic
        // replay), table writes self-log their resolved command from the leaf,
        // and the reserved-key/table guards apply so a script can't bypass them.
        // We log effects, not the script, so replay never re-runs Lua and can't
        // diverge on a generated PK or now()-default.
        crate::cmd::execute_with_wal(&store, &lua_cache, &broker, &refs, &mut out, now);
        if raise_errors && out.first() == Some(&b'-') {
            return Err(mlua::Error::external(resp_error_message(&out)));
        }
        resp_to_lua(lua_ctx, &out).map_err(|e| mlua::Error::external(format!("{}", e)))
    })
}

/// Commands a script must not run: admin/persistence, blocking, transaction
/// control, and subscription commands.
fn lua_disallowed_command_error(cmd: &[u8]) -> Option<&'static str> {
    if crate::cmd::is_blocking_command(cmd)
        || cmd.eq_ignore_ascii_case(b"SAVE")
        || cmd.eq_ignore_ascii_case(b"BGSAVE")
        || cmd.eq_ignore_ascii_case(b"MULTI")
        || cmd.eq_ignore_ascii_case(b"EXEC")
        || cmd.eq_ignore_ascii_case(b"DISCARD")
        || cmd.eq_ignore_ascii_case(b"WATCH")
        || cmd.eq_ignore_ascii_case(b"UNWATCH")
        || cmd.eq_ignore_ascii_case(b"SUBSCRIBE")
        || cmd.eq_ignore_ascii_case(b"UNSUBSCRIBE")
        || cmd.eq_ignore_ascii_case(b"PSUBSCRIBE")
        || cmd.eq_ignore_ascii_case(b"PUNSUBSCRIBE")
        || cmd.eq_ignore_ascii_case(b"KSUB")
        || cmd.eq_ignore_ascii_case(b"KUNSUB")
    {
        Some("ERR This Redis command is not allowed from script")
    } else {
        None
    }
}

/// Extract the human message from a RESP error reply (`-MSG\r\n`).
fn resp_error_message(out: &[u8]) -> String {
    let end = out.iter().position(|&b| b == b'\r').unwrap_or(out.len());
    String::from_utf8_lossy(&out[1..end]).to_string()
}

/// Remove dangerous globals from the script environment: filesystem/process
/// (`os`, `io`), module loading (`package`, `require`, `dofile`, `loadfile`),
/// introspection (`debug`), GC control (`collectgarbage`), and dynamic code
/// loading (`load`, `loadstring`) -- the last of which can load crafted bytecode
/// and escape the VM. The engine's own helpers use the Rust `mlua` API, which is
/// unaffected by nil-ing these Lua globals.
fn install_lua_sandbox(lua: &mlua::Lua) -> Result<(), String> {
    let globals = lua.globals();
    for name in [
        "os",
        "io",
        "package",
        "require",
        "dofile",
        "loadfile",
        "load",
        "loadstring",
        "debug",
        "collectgarbage",
    ] {
        globals
            .set(name, mlua::Value::Nil)
            .map_err(|e| format!("ERR lua error: {}", e))?;
    }
    Ok(())
}

fn msgpack_pack_value(val: &mlua::Value, buf: &mut Vec<u8>) -> Result<(), String> {
    use rmp::encode;
    match val {
        mlua::Value::Nil => {
            encode::write_nil(buf).map_err(|e| e.to_string())?;
        }
        mlua::Value::Boolean(b) => {
            encode::write_bool(buf, *b).map_err(|e| e.to_string())?;
        }
        mlua::Value::Integer(n) => {
            encode::write_sint(buf, *n).map_err(|e| e.to_string())?;
        }
        mlua::Value::Number(n) => {
            encode::write_f64(buf, *n).map_err(|e| e.to_string())?;
        }
        mlua::Value::String(s) => {
            let b = s.as_bytes().to_vec();
            encode::write_str(buf, std::str::from_utf8(&b).unwrap_or(""))
                .map_err(|e| e.to_string())?;
        }
        mlua::Value::Table(tbl) => {
            let len = tbl.len().unwrap_or(0) as usize;
            if len > 0 {
                encode::write_array_len(buf, len as u32).map_err(|e| e.to_string())?;
                for i in 1..=len {
                    if let Ok(v) = tbl.get::<mlua::Value>(i) {
                        msgpack_pack_value(&v, buf)?;
                    } else {
                        encode::write_nil(buf).map_err(|e| e.to_string())?;
                    }
                }
            } else {
                let mut pairs: Vec<(mlua::Value, mlua::Value)> = Vec::new();
                let tbl_clone = tbl.clone();
                let iter = tbl_clone.pairs::<mlua::Value, mlua::Value>();
                for (k, v) in iter.flatten() {
                    pairs.push((k, v));
                }
                encode::write_map_len(buf, pairs.len() as u32).map_err(|e| e.to_string())?;
                for (k, v) in &pairs {
                    msgpack_pack_value(k, buf)?;
                    msgpack_pack_value(v, buf)?;
                }
            }
        }
        _ => {
            encode::write_nil(buf).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn read_raw_u8(cursor: &mut Cursor<&Vec<u8>>) -> Result<u8, String> {
    use std::io::Read;
    let mut buf = [0u8; 1];
    cursor.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf[0])
}

fn read_raw_u16(cursor: &mut Cursor<&Vec<u8>>) -> Result<u16, String> {
    use std::io::Read;
    let mut buf = [0u8; 2];
    cursor.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok(u16::from_be_bytes(buf))
}

fn read_raw_u32(cursor: &mut Cursor<&Vec<u8>>) -> Result<u32, String> {
    use std::io::Read;
    let mut buf = [0u8; 4];
    cursor.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok(u32::from_be_bytes(buf))
}

fn read_raw_u64(cursor: &mut Cursor<&Vec<u8>>) -> Result<u64, String> {
    use std::io::Read;
    let mut buf = [0u8; 8];
    cursor.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok(u64::from_be_bytes(buf))
}

/// Max items in a single decoded msgpack array/map -- bounds a hostile container
/// length prefix so cmsgpack.unpack can't be driven into runaway work.
const MAX_MSGPACK_CONTAINER_ITEMS: usize = 1_000_000;

/// Max msgpack nesting depth -- a hostile stream of nested array/map markers
/// must not be able to recurse the decoder into a stack overflow.
const MAX_MSGPACK_DEPTH: usize = 128;

fn check_msgpack_container_len(len: usize) -> Result<(), String> {
    if len > MAX_MSGPACK_CONTAINER_ITEMS {
        Err("msgpack container length exceeds maximum".to_string())
    } else {
        Ok(())
    }
}

fn read_raw_bytes(cursor: &mut Cursor<&Vec<u8>>, len: usize) -> Result<Vec<u8>, String> {
    use std::io::Read;
    // A msgpack length prefix is attacker-controlled: never pre-allocate beyond
    // the bytes actually remaining in the input.
    let remaining = cursor
        .get_ref()
        .len()
        .saturating_sub(cursor.position() as usize);
    if len > remaining {
        return Err("msgpack byte length exceeds input".to_string());
    }
    let mut buf = vec![0u8; len];
    cursor.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

pub(crate) fn msgpack_unpack_value(
    lua: &mlua::Lua,
    cursor: &mut Cursor<&Vec<u8>>,
    depth: usize,
) -> Result<mlua::Value, String> {
    if depth > MAX_MSGPACK_DEPTH {
        return Err("msgpack nesting too deep".to_string());
    }
    let pos = cursor.position() as usize;
    let buf = cursor.get_ref();
    if pos >= buf.len() {
        return Ok(mlua::Value::Nil);
    }

    let marker = rmp::decode::read_marker(cursor).map_err(|e| format!("{:?}", e))?;
    match marker {
        rmp::Marker::Null => Ok(mlua::Value::Nil),
        rmp::Marker::True => Ok(mlua::Value::Boolean(true)),
        rmp::Marker::False => Ok(mlua::Value::Boolean(false)),
        rmp::Marker::FixPos(n) => Ok(mlua::Value::Integer(n as i64)),
        rmp::Marker::FixNeg(n) => Ok(mlua::Value::Integer(n as i64)),
        rmp::Marker::U8 => Ok(mlua::Value::Integer(read_raw_u8(cursor)? as i64)),
        rmp::Marker::U16 => Ok(mlua::Value::Integer(read_raw_u16(cursor)? as i64)),
        rmp::Marker::U32 => Ok(mlua::Value::Integer(read_raw_u32(cursor)? as i64)),
        rmp::Marker::U64 => Ok(mlua::Value::Integer(read_raw_u64(cursor)? as i64)),
        rmp::Marker::I8 => Ok(mlua::Value::Integer(read_raw_u8(cursor)? as i8 as i64)),
        rmp::Marker::I16 => Ok(mlua::Value::Integer(read_raw_u16(cursor)? as i16 as i64)),
        rmp::Marker::I32 => Ok(mlua::Value::Integer(read_raw_u32(cursor)? as i32 as i64)),
        rmp::Marker::I64 => Ok(mlua::Value::Integer(read_raw_u64(cursor)? as i64)),
        rmp::Marker::F32 => {
            let bits = read_raw_u32(cursor)?;
            Ok(mlua::Value::Number(f32::from_bits(bits) as f64))
        }
        rmp::Marker::F64 => {
            let bits = read_raw_u64(cursor)?;
            Ok(mlua::Value::Number(f64::from_bits(bits)))
        }
        rmp::Marker::FixStr(len) => {
            let sbuf = read_raw_bytes(cursor, len as usize)?;
            let s = lua.create_string(&sbuf).map_err(|e| e.to_string())?;
            Ok(mlua::Value::String(s))
        }
        rmp::Marker::Str8 => {
            let len = read_raw_u8(cursor)? as usize;
            let sbuf = read_raw_bytes(cursor, len)?;
            let s = lua.create_string(&sbuf).map_err(|e| e.to_string())?;
            Ok(mlua::Value::String(s))
        }
        rmp::Marker::Str16 => {
            let len = read_raw_u16(cursor)? as usize;
            let sbuf = read_raw_bytes(cursor, len)?;
            let s = lua.create_string(&sbuf).map_err(|e| e.to_string())?;
            Ok(mlua::Value::String(s))
        }
        rmp::Marker::Str32 => {
            let len = read_raw_u32(cursor)? as usize;
            let sbuf = read_raw_bytes(cursor, len)?;
            let s = lua.create_string(&sbuf).map_err(|e| e.to_string())?;
            Ok(mlua::Value::String(s))
        }
        rmp::Marker::Bin8 => {
            let len = read_raw_u8(cursor)? as usize;
            let sbuf = read_raw_bytes(cursor, len)?;
            let s = lua.create_string(&sbuf).map_err(|e| e.to_string())?;
            Ok(mlua::Value::String(s))
        }
        rmp::Marker::Bin16 => {
            let len = read_raw_u16(cursor)? as usize;
            let sbuf = read_raw_bytes(cursor, len)?;
            let s = lua.create_string(&sbuf).map_err(|e| e.to_string())?;
            Ok(mlua::Value::String(s))
        }
        rmp::Marker::Bin32 => {
            let len = read_raw_u32(cursor)? as usize;
            let sbuf = read_raw_bytes(cursor, len)?;
            let s = lua.create_string(&sbuf).map_err(|e| e.to_string())?;
            Ok(mlua::Value::String(s))
        }
        rmp::Marker::FixArray(len) => {
            let tbl = lua.create_table().map_err(|e| e.to_string())?;
            for i in 0..len as usize {
                let v = msgpack_unpack_value(lua, cursor, depth + 1)?;
                tbl.set(i + 1, v).map_err(|e| e.to_string())?;
            }
            Ok(mlua::Value::Table(tbl))
        }
        rmp::Marker::Array16 => {
            let len = read_raw_u16(cursor)? as usize;
            check_msgpack_container_len(len)?;
            let tbl = lua.create_table().map_err(|e| e.to_string())?;
            for i in 0..len {
                let v = msgpack_unpack_value(lua, cursor, depth + 1)?;
                tbl.set(i + 1, v).map_err(|e| e.to_string())?;
            }
            Ok(mlua::Value::Table(tbl))
        }
        rmp::Marker::Array32 => {
            let len = read_raw_u32(cursor)? as usize;
            check_msgpack_container_len(len)?;
            let tbl = lua.create_table().map_err(|e| e.to_string())?;
            for i in 0..len {
                let v = msgpack_unpack_value(lua, cursor, depth + 1)?;
                tbl.set(i + 1, v).map_err(|e| e.to_string())?;
            }
            Ok(mlua::Value::Table(tbl))
        }
        rmp::Marker::FixMap(len) => {
            let tbl = lua.create_table().map_err(|e| e.to_string())?;
            for _ in 0..len {
                let k = msgpack_unpack_value(lua, cursor, depth + 1)?;
                let v = msgpack_unpack_value(lua, cursor, depth + 1)?;
                // A nil or NaN key is not a valid Lua table index. Real
                // msgpack never produces one, but corrupt/truncated input
                // can -- skip it rather than let Lua abort the process.
                let bad_key = matches!(k, mlua::Value::Nil)
                    || matches!(k, mlua::Value::Number(n) if n.is_nan());
                if !bad_key {
                    tbl.set(k, v).map_err(|e| e.to_string())?;
                }
            }
            Ok(mlua::Value::Table(tbl))
        }
        rmp::Marker::Map16 => {
            let len = read_raw_u16(cursor)? as usize;
            check_msgpack_container_len(len)?;
            let tbl = lua.create_table().map_err(|e| e.to_string())?;
            for _ in 0..len {
                let k = msgpack_unpack_value(lua, cursor, depth + 1)?;
                let v = msgpack_unpack_value(lua, cursor, depth + 1)?;
                // A nil or NaN key is not a valid Lua table index. Real
                // msgpack never produces one, but corrupt/truncated input
                // can -- skip it rather than let Lua abort the process.
                let bad_key = matches!(k, mlua::Value::Nil)
                    || matches!(k, mlua::Value::Number(n) if n.is_nan());
                if !bad_key {
                    tbl.set(k, v).map_err(|e| e.to_string())?;
                }
            }
            Ok(mlua::Value::Table(tbl))
        }
        rmp::Marker::Map32 => {
            let len = read_raw_u32(cursor)? as usize;
            check_msgpack_container_len(len)?;
            let tbl = lua.create_table().map_err(|e| e.to_string())?;
            for _ in 0..len {
                let k = msgpack_unpack_value(lua, cursor, depth + 1)?;
                let v = msgpack_unpack_value(lua, cursor, depth + 1)?;
                // A nil or NaN key is not a valid Lua table index. Real
                // msgpack never produces one, but corrupt/truncated input
                // can -- skip it rather than let Lua abort the process.
                let bad_key = matches!(k, mlua::Value::Nil)
                    || matches!(k, mlua::Value::Number(n) if n.is_nan());
                if !bad_key {
                    tbl.set(k, v).map_err(|e| e.to_string())?;
                }
            }
            Ok(mlua::Value::Table(tbl))
        }
        _ => Ok(mlua::Value::Nil),
    }
}

fn lua_value_to_json(val: &mlua::Value) -> String {
    match val {
        mlua::Value::Nil => "null".to_string(),
        mlua::Value::Boolean(b) => if *b { "true" } else { "false" }.to_string(),
        mlua::Value::Integer(n) => n.to_string(),
        mlua::Value::Number(n) => {
            if n.fract() == 0.0 && n.abs() < 1e15 {
                format!("{}", *n as i64)
            } else {
                format!("{}", n)
            }
        }
        mlua::Value::String(s) => {
            let bytes = s.as_bytes().to_vec();
            let st = String::from_utf8_lossy(&bytes);
            let escaped: String = st
                .chars()
                .map(|c| match c {
                    '"' => "\\\"".to_string(),
                    '\\' => "\\\\".to_string(),
                    '\n' => "\\n".to_string(),
                    '\r' => "\\r".to_string(),
                    '\t' => "\\t".to_string(),
                    c if (c as u32) < 0x20 => format!("\\u{:04x}", c as u32),
                    c => c.to_string(),
                })
                .collect();
            format!("\"{}\"", escaped)
        }
        mlua::Value::Table(tbl) => {
            let len = tbl.len().unwrap_or(0) as usize;
            if len > 0 {
                let items: Vec<String> = (1..=len)
                    .map(|i| {
                        if let Ok(v) = tbl.get::<mlua::Value>(i) {
                            lua_value_to_json(&v)
                        } else {
                            "null".to_string()
                        }
                    })
                    .collect();
                format!("[{}]", items.join(","))
            } else {
                let tbl_clone = tbl.clone();
                let mut pairs: Vec<String> = Vec::new();
                for (k, v) in tbl_clone.pairs::<mlua::Value, mlua::Value>().flatten() {
                    let key_str = match &k {
                        mlua::Value::String(s) => {
                            let bytes = s.as_bytes().to_vec();
                            String::from_utf8_lossy(&bytes).to_string()
                        }
                        mlua::Value::Integer(n) => n.to_string(),
                        _ => continue,
                    };
                    let escaped_key: String = key_str
                        .chars()
                        .map(|c| match c {
                            '"' => "\\\"".to_string(),
                            '\\' => "\\\\".to_string(),
                            c => c.to_string(),
                        })
                        .collect();
                    pairs.push(format!("\"{}\":{}", escaped_key, lua_value_to_json(&v)));
                }
                if pairs.is_empty() {
                    "{}".to_string()
                } else {
                    format!("{{{}}}", pairs.join(","))
                }
            }
        }
        _ => "null".to_string(),
    }
}

fn json_to_lua_value(lua: &mlua::Lua, s: &str) -> Result<mlua::Value, String> {
    let s = s.trim();
    if s.is_empty() || s == "null" {
        return Ok(mlua::Value::Nil);
    }
    if s == "true" {
        return Ok(mlua::Value::Boolean(true));
    }
    if s == "false" {
        return Ok(mlua::Value::Boolean(false));
    }
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        let inner = &s[1..s.len() - 1];
        let unescaped = json_unescape(inner);
        let ls = lua
            .create_string(unescaped.as_bytes())
            .map_err(|e| e.to_string())?;
        return Ok(mlua::Value::String(ls));
    }
    if s.starts_with('[') && s.ends_with(']') {
        let inner = s[1..s.len() - 1].trim();
        let tbl = lua.create_table().map_err(|e| e.to_string())?;
        if inner.is_empty() {
            return Ok(mlua::Value::Table(tbl));
        }
        let items = json_split_top_level(inner);
        for (i, item) in items.iter().enumerate() {
            let v = json_to_lua_value(lua, item)?;
            tbl.set(i + 1, v).map_err(|e| e.to_string())?;
        }
        return Ok(mlua::Value::Table(tbl));
    }
    if s.starts_with('{') && s.ends_with('}') {
        let inner = s[1..s.len() - 1].trim();
        let tbl = lua.create_table().map_err(|e| e.to_string())?;
        if inner.is_empty() {
            return Ok(mlua::Value::Table(tbl));
        }
        let pairs = json_split_top_level(inner);
        for pair in &pairs {
            if let Some(colon_pos) = json_find_colon(pair) {
                let key = pair[..colon_pos].trim();
                let val = pair[colon_pos + 1..].trim();
                let key_val = json_to_lua_value(lua, key)?;
                let val_val = json_to_lua_value(lua, val)?;
                tbl.set(key_val, val_val).map_err(|e| e.to_string())?;
            }
        }
        return Ok(mlua::Value::Table(tbl));
    }
    if let Ok(n) = s.parse::<i64>() {
        return Ok(mlua::Value::Integer(n));
    }
    if let Ok(n) = s.parse::<f64>() {
        return Ok(mlua::Value::Number(n));
    }
    Ok(mlua::Value::Nil)
}

fn json_unescape(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('"') => result.push('"'),
                Some('\\') => result.push('\\'),
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('t') => result.push('\t'),
                Some('/') => result.push('/'),
                Some('u') => {
                    let hex: String = chars.by_ref().take(4).collect();
                    if let Ok(n) = u32::from_str_radix(&hex, 16) {
                        if let Some(c) = char::from_u32(n) {
                            result.push(c);
                        }
                    }
                }
                Some(other) => {
                    result.push('\\');
                    result.push(other);
                }
                None => result.push('\\'),
            }
        } else {
            result.push(c);
        }
    }
    result
}

fn json_split_top_level(s: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape = false;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if c == '\\' && in_string {
            escape = true;
            continue;
        }
        if c == '"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        match c {
            '{' | '[' => depth += 1,
            '}' | ']' => depth -= 1,
            ',' if depth == 0 => {
                items.push(s[start..i].to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < s.len() {
        items.push(s[start..].to_string());
    }
    items
}

fn json_find_colon(s: &str) -> Option<usize> {
    let mut in_string = false;
    let mut escape = false;
    let mut depth = 0i32;
    for (i, c) in s.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if c == '\\' && in_string {
            escape = true;
            continue;
        }
        if c == '"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        match c {
            '{' | '[' => depth += 1,
            '}' | ']' => depth -= 1,
            ':' if depth == 0 => return Some(i),
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod fuzz_tests {
    use super::*;

    // A hostile stream of nested array markers must be rejected by the depth
    // guard, not stack-overflow the decoder.
    #[test]
    fn msgpack_deeply_nested_rejected_not_overflow() {
        // 0x91 = fixarray of length 1; a long run nests one level per byte.
        let data = vec![0x91u8; 100_000];
        let lua = mlua::Lua::new();
        let mut cursor = Cursor::new(&data);
        let result = msgpack_unpack_value(&lua, &mut cursor, 0);
        assert!(result.is_err(), "deeply nested msgpack must be rejected");
    }

    // A msgpack map whose key decodes to nil (e.g. truncated input) must not be
    // forwarded to Lua as `table[nil] = v`, which aborts the process. Found by
    // the fuzzer: 0x8c declares a 12-pair map but the stream runs out, so keys
    // read back as nil.
    #[test]
    fn msgpack_map_with_nil_key_does_not_abort() {
        let lua = mlua::Lua::new();
        let data = vec![
            0x8c_u8, 0x3e, 0x59, 0xe5, 0xc9, 0xfc, 0x9a, 0x7b, 0x05, 0x97, 0x9b, 0x5a,
        ];
        let mut cursor = Cursor::new(&data);
        let _ = msgpack_unpack_value(&lua, &mut cursor, 0);

        // Minimal explicit case: FixMap(1) with a nil key (0xc0) and value 1.
        let data = vec![0x81_u8, 0xc0, 0x01];
        let mut cursor = Cursor::new(&data);
        let result = msgpack_unpack_value(&lua, &mut cursor, 0);
        assert!(
            result.is_ok(),
            "nil-key map should decode with the key skipped: {result:?}"
        );
    }

    // Fuzz: arbitrary bytes through the msgpack decoder must never panic, OOM,
    // or overflow the stack -- only return Ok or a clean Err.
    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(2000))]

        #[test]
        fn fuzz_msgpack_unpack_no_panic(
            data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2048)
        ) {
            let lua = mlua::Lua::new();
            let mut cursor = Cursor::new(&data);
            let _ = msgpack_unpack_value(&lua, &mut cursor, 0);
        }
    }
}
