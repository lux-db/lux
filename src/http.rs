use bytes::BytesMut;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpSocket;
use tokio::sync::oneshot;

use crate::lua;
use crate::pubsub::Broker;
use crate::store::Store;
use crate::tables::SharedSchemaCache;
use crate::{CommandExecutor, CommandSession, LuxError};

/// Constant-time byte comparison to prevent timing attacks on auth tokens.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        let mut _acc = 0u8;
        for &byte in a {
            _acc |= byte;
        }
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Runtime options for the HTTP API listener.
///
/// `startup_ready` is used by `run_with_config` to include the HTTP bind in
/// the server readiness contract. `on_ready` remains the user-facing log hook.
pub struct HttpServerConfig {
    pub bind_host: String,
    pub http_port: u16,
    pub max_rows: Option<usize>,
    pub max_body: usize,
    pub on_ready: Option<Arc<dyn Fn(std::net::SocketAddr) + Send + Sync>>,
    pub startup_ready: Option<oneshot::Sender<std::io::Result<std::net::SocketAddr>>>,
}

/// Start the HTTP API listener and serve requests forever.
pub async fn start_http_server(
    config: HttpServerConfig,
    store: Arc<Store>,
    broker: Broker,
    cache: SharedSchemaCache,
    script_engine: Arc<lua::ScriptEngine>,
) -> std::io::Result<()> {
    let addr: std::net::SocketAddr = format!("{}:{}", config.bind_host, config.http_port)
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // Bind before notifying either readiness channel so callers never observe
    // a ready server with a missing HTTP listener.
    let listener = match bind_listener(addr) {
        Ok(listener) => listener,
        Err(e) => {
            if let Some(startup_ready) = config.startup_ready {
                let _ = startup_ready.send(Err(std::io::Error::new(e.kind(), e.to_string())));
            }
            return Err(e);
        }
    };
    let local_addr = listener.local_addr()?;
    if let Some(startup_ready) = config.startup_ready {
        let _ = startup_ready.send(Ok(local_addr));
    }
    if let Some(on_ready) = config.on_ready {
        on_ready(local_addr);
    }
    let max_rows = config.max_rows;
    let max_body = config.max_body;

    loop {
        let (socket, _) = listener.accept().await?;
        let store = store.clone();
        let broker = broker.clone();
        let cache = cache.clone();
        let script_engine = script_engine.clone();

        tokio::spawn(async move {
            let mut stream = socket;
            while let Ok(true) = handle_request(
                &mut stream,
                &store,
                &broker,
                &cache,
                &script_engine,
                max_rows,
                max_body,
            )
            .await
            {}
        });
    }
}

fn bind_listener(addr: std::net::SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    let socket = TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(1024)
}

async fn handle_request(
    socket: &mut tokio::net::TcpStream,
    store: &Arc<Store>,
    broker: &Broker,
    cache: &SharedSchemaCache,
    script_engine: &Arc<lua::ScriptEngine>,
    max_rows: Option<usize>,
    max_body: usize,
) -> std::io::Result<bool> {
    // Hard limits to prevent memory exhaustion DoS
    const MAX_HEADER_SIZE: usize = 64 * 1024; // 64 KB headers

    let mut buf = vec![0u8; 65536];
    let mut data = Vec::new();

    loop {
        let n = socket.read(&mut buf).await?;
        if n == 0 {
            return Ok(false);
        }
        data.extend_from_slice(&buf[..n]);

        if data.len() > MAX_HEADER_SIZE {
            let body = r#"{"error":"request headers too large"}"#;
            return send_json(socket, 431, "Request Header Fields Too Large", body).await;
        }

        if data.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let header_end = data.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let header_str = String::from_utf8_lossy(&data[..header_end]);

    let content_length: usize = header_str
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split_once(':'))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0);

    if content_length > max_body {
        let body = r#"{"error":"request body too large"}"#;
        return send_json(socket, 413, "Payload Too Large", body).await;
    }

    let total_needed = header_end + content_length;
    while data.len() < total_needed {
        let n = socket.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
    }

    let request = String::from_utf8_lossy(&data);

    let (method, full_path, headers, body) = parse_http_request(&request);

    if method == "OPTIONS" {
        let response = "HTTP/1.1 204 No Content\r\n\
             Access-Control-Allow-Origin: *\r\n\
             Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS\r\n\
             Access-Control-Allow-Headers: Authorization, Content-Type, Prefer\r\n\
             Content-Length: 0\r\n\r\n"
            .to_string();
        socket.write_all(response.as_bytes()).await?;
        return Ok(true);
    }

    let password = &store.config().password;
    if !password.is_empty() {
        let auth = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v.as_str())
            .unwrap_or("");

        let token = auth.strip_prefix("Bearer ").unwrap_or("");
        if !constant_time_eq(token.as_bytes(), password.as_bytes()) {
            let body = r#"{"error":"unauthorized"}"#;
            return send_json(socket, 401, "Unauthorized", body).await;
        }
    }

    let (path, query_string) = match full_path.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (full_path.clone(), String::new()),
    };
    let params = parse_query_string(&query_string);

    // Fast path: table GET queries stream JSON directly without building
    // the full response string in memory first.
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if method == "GET" {
        match segments.as_slice() {
            ["v1", "tables", table] => {
                let prefer = headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("prefer"))
                    .map(|(_, v)| v.as_str())
                    .unwrap_or("");
                return stream_table_query(socket, table, &params, prefer, store, cache, max_rows)
                    .await;
            }
            ["v1", "tables", table, "count"] => {
                let now = std::time::Instant::now();
                let body = match crate::tables::table_count(store, cache, table, now) {
                    Ok(n) => format!(r#"{{"result":{n}}}"#),
                    Err(e) => format!(r#"{{"error":"{}"}}"#, escape_json(&e)),
                };
                return send_json(socket, 200, "OK", &body).await;
            }
            ["v1", "tables", table, "schema"] => {
                let now = std::time::Instant::now();
                let body = match crate::tables::table_schema(store, cache, table, now) {
                    Ok(fields) => {
                        let items: Vec<String> = fields
                            .iter()
                            .map(|f| format!(r#""{}""#, escape_json(f)))
                            .collect();
                        format!(r#"{{"result":[{}]}}"#, items.join(","))
                    }
                    Err(e) => format!(r#"{{"error":"{}"}}"#, escape_json(&e)),
                };
                return send_json(socket, 200, "OK", &body).await;
            }
            ["v1", "tables", table, id] if *id != "count" && *id != "schema" => {
                let now = std::time::Instant::now();
                let body = match id.parse::<i64>() {
                    Ok(id_i64) => {
                        match crate::tables::table_get(store, cache, table, id_i64, now) {
                            Ok(row) => row_to_json_object(&row),
                            Err(e) => format!(r#"{{"error":"{}"}}"#, escape_json(&e)),
                        }
                    }
                    Err(_) => r#"{"error":"invalid row id"}"#.to_string(),
                };
                return send_json(socket, 200, "OK", &body).await;
            }
            _ => {}
        }
    }

    let deps = RouteDeps {
        store,
        broker,
        cache,
        script_engine,
    };
    let (status, status_text, result) = route_request(&method, &path, &body, &params, deps);

    send_json(socket, status, status_text, &result).await
}

/// Stream a table query response using chunked transfer encoding.
/// Writes rows directly to the socket as they come out of table_select,
/// without ever building the full JSON string in memory.
async fn stream_table_query(
    socket: &mut tokio::net::TcpStream,
    table: &str,
    params: &[(String, String)],
    prefer: &str,
    store: &Arc<Store>,
    cache: &SharedSchemaCache,
    max_rows: Option<usize>,
) -> std::io::Result<bool> {
    use tokio::io::AsyncWriteExt;

    let now = std::time::Instant::now();

    let (parsed, plan) = match parse_http_table_query(params, table, max_rows) {
        Ok(v) => v,
        Err(e) => {
            let body = format!(r#"{{"error":"{}"}}"#, escape_json(&e));
            return send_json(socket, 400, "Bad Request", &body).await;
        }
    };
    let has_where = parsed.has_where;
    let offset = parsed.offset;
    let count_exact = prefer.contains("count=exact");
    let result = crate::tables::table_select(store, cache, &plan, now);

    match result {
        Err(e) => {
            let body = format!(r#"{{"error":"{}"}}"#, escape_json(&e));
            return send_json(socket, 400, "Bad Request", &body).await;
        }
        Ok(crate::tables::SelectResult::Aggregate(row)) => {
            let body = {
                let mut out = String::with_capacity(128);
                out.push_str(r#"{"result":{"#);
                let mut first = true;
                for (k, v) in &row {
                    if !first {
                        out.push(',');
                    }
                    first = false;
                    out.push('"');
                    push_escaped(&mut out, k);
                    out.push_str(r#"":"#);
                    if looks_numeric(v) {
                        out.push_str(v);
                    } else {
                        out.push('"');
                        push_escaped(&mut out, v);
                        out.push('"');
                    }
                }
                out.push_str("}}");
                out
            };
            return send_json(socket, 200, "OK", &body).await;
        }
        Ok(crate::tables::SelectResult::Rows(rows)) => {
            let returned = rows.len();
            let range_end = if returned == 0 {
                offset
            } else {
                offset + returned - 1
            };

            // Compute Content-Range value:
            // - No WHERE: total is cheap (zcard), always exact
            // - WHERE + Prefer:count=exact: run a count query
            // - WHERE, no preference: total is unknown (*)
            let total_str = if !has_where {
                // Free - zcard on the ids sorted set
                let total =
                    crate::tables::table_count(store, cache, table, now).unwrap_or(returned as i64);
                total.to_string()
            } else if count_exact {
                // Run a count-only query with the same WHERE
                let mut count_tokens: Vec<String> = vec![
                    "COUNT(*)".to_string(),
                    "FROM".to_string(),
                    table.to_string(),
                ];
                if !parsed.where_tokens.is_empty() {
                    count_tokens.push("WHERE".to_string());
                    count_tokens.extend(parsed.where_tokens.iter().cloned());
                }
                let count_refs: Vec<&str> = count_tokens.iter().map(|s| s.as_str()).collect();
                let total = crate::tables::parse_select(&count_refs)
                    .ok()
                    .and_then(|plan| crate::tables::table_select(store, cache, &plan, now).ok())
                    .and_then(|res| match res {
                        crate::tables::SelectResult::Aggregate(row) => row
                            .into_iter()
                            .find(|(k, _)| k == "COUNT(*)")
                            .and_then(|(_, v)| v.parse::<i64>().ok()),
                        _ => None,
                    })
                    .unwrap_or(returned as i64);
                total.to_string()
            } else {
                "*".to_string()
            };

            let content_range = format!("{}-{}/{}", offset, range_end, total_str);

            const CHUNK_SIZE: usize = 65536;
            let header = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/json\r\n\
                 Transfer-Encoding: chunked\r\n\
                 Content-Range: {content_range}\r\n\
                 Access-Control-Allow-Origin: *\r\n\r\n"
            );
            socket.write_all(header.as_bytes()).await?;

            let mut buf = String::with_capacity(CHUNK_SIZE + 4096);
            buf.push_str(r#"{"result":["#);

            let mut first_row = true;
            for row in &rows {
                if !first_row {
                    buf.push(',');
                }
                first_row = false;
                buf.push('{');
                let mut first_col = true;
                for (k, v) in row {
                    if !first_col {
                        buf.push(',');
                    }
                    first_col = false;
                    buf.push('"');
                    push_escaped(&mut buf, k);
                    buf.push_str(r#"":"#);
                    if looks_numeric(v) || v == "true" || v == "false" {
                        buf.push_str(v);
                    } else {
                        buf.push('"');
                        push_escaped(&mut buf, v);
                        buf.push('"');
                    }
                }
                buf.push('}');

                if buf.len() >= CHUNK_SIZE {
                    write_chunk(socket, buf.as_bytes()).await?;
                    buf.clear();
                }
            }

            buf.push_str("]}");
            write_chunk(socket, buf.as_bytes()).await?;
            socket.write_all(b"0\r\n\r\n").await?;
            // Chunked response complete - keep connection alive for next request
            Ok(true)
        }
    }
}

/// Write a single HTTP chunk: `{hex_len}\r\n{data}\r\n`
async fn write_chunk(socket: &mut tokio::net::TcpStream, data: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    if data.is_empty() {
        return Ok(());
    }
    let header = format!("{:x}\r\n", data.len());
    socket.write_all(header.as_bytes()).await?;
    socket.write_all(data).await?;
    socket.write_all(b"\r\n").await?;
    Ok(())
}

async fn send_json(
    socket: &mut tokio::net::TcpStream,
    status: u16,
    status_text: &str,
    body: &str,
) -> std::io::Result<bool> {
    let response = format!(
        "HTTP/1.1 {status} {status_text}\r\n\
         Content-Type: application/json\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Content-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    socket.write_all(response.as_bytes()).await?;
    Ok(true)
}

fn parse_http_request(raw: &str) -> (String, String, Vec<(String, String)>, String) {
    let parts: Vec<&str> = raw.splitn(2, "\r\n\r\n").collect();
    let header_section = parts[0];
    let body = parts.get(1).unwrap_or(&"").to_string();

    let mut lines = header_section.lines();
    let request_line = lines.next().unwrap_or("");
    let mut tokens = request_line.split_whitespace();
    let method = tokens.next().unwrap_or("GET").to_string();
    let path = tokens.next().unwrap_or("/").to_string();

    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    (method, path, headers, body)
}

fn parse_query_string(qs: &str) -> Vec<(String, String)> {
    if qs.is_empty() {
        return Vec::new();
    }
    qs.split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let k = url_decode(k);
            let v = url_decode(v);
            if k.is_empty() {
                None
            } else {
                Some((k, v))
            }
        })
        .collect()
}

fn url_decode(s: &str) -> String {
    let mut result = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                result.push(byte);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            result.push(b' ');
            i += 1;
            continue;
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).to_string()
}

fn get_param<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

struct HttpTableQueryParams {
    has_where: bool,
    where_tokens: Vec<String>,
    offset: usize,
}

fn parse_http_where_tokens(where_clause: &str) -> Result<Vec<String>, String> {
    let tokens: Vec<String> = where_clause
        .split_whitespace()
        .map(ToString::to_string)
        .collect();
    if tokens.is_empty() {
        return Err("invalid where parameter".to_string());
    }
    Ok(tokens)
}

fn parse_http_table_query(
    params: &[(String, String)],
    table: &str,
    max_rows: Option<usize>,
) -> Result<(HttpTableQueryParams, crate::tables::SelectPlan), String> {
    let has_where = get_param(params, "where").is_some();
    let where_tokens = match get_param(params, "where") {
        Some(w) => parse_http_where_tokens(w)?,
        None => Vec::new(),
    };

    let order_tokens = match get_param(params, "order") {
        Some(o) => {
            let tokens: Vec<String> = o.split_whitespace().map(ToString::to_string).collect();
            if tokens.is_empty() {
                return Err("invalid order parameter".to_string());
            }
            tokens
        }
        None => Vec::new(),
    };

    let client_limit = match get_param(params, "limit") {
        Some(v) => Some(
            v.parse::<usize>()
                .map_err(|_| "invalid limit parameter".to_string())?,
        ),
        None => None,
    };
    let offset = match get_param(params, "offset") {
        Some(v) => v
            .parse::<usize>()
            .map_err(|_| "invalid offset parameter".to_string())?,
        None => 0,
    };
    let limit = match (client_limit, max_rows) {
        (Some(c), Some(m)) => Some(c.min(m)),
        (Some(c), None) => Some(c),
        (None, Some(m)) => Some(m),
        (None, None) => None,
    };

    let mut tokens: Vec<String> = vec!["*".to_string(), "FROM".to_string(), table.to_string()];
    if !where_tokens.is_empty() {
        tokens.push("WHERE".to_string());
        tokens.extend(where_tokens.iter().cloned());
    }
    if let Some(join) = get_param(params, "join") {
        tokens.push("JOIN".to_string());
        tokens.push(join.to_string());
    }
    if !order_tokens.is_empty() {
        tokens.push("ORDER".to_string());
        tokens.push("BY".to_string());
        tokens.extend(order_tokens.iter().cloned());
    }
    if let Some(lim) = limit {
        tokens.push("LIMIT".to_string());
        tokens.push(lim.to_string());
    }
    if offset > 0 {
        tokens.push("OFFSET".to_string());
        tokens.push(offset.to_string());
    }

    let refs: Vec<&str> = tokens.iter().map(|s| s.as_str()).collect();
    let plan = crate::tables::parse_select(&refs)?;
    Ok((
        HttpTableQueryParams {
            has_where,
            where_tokens,
            offset,
        },
        plan,
    ))
}

struct RouteDeps<'a> {
    store: &'a Arc<Store>,
    broker: &'a Broker,
    cache: &'a SharedSchemaCache,
    script_engine: &'a Arc<lua::ScriptEngine>,
}

fn route_request(
    method: &str,
    path: &str,
    body: &str,
    params: &[(String, String)],
    deps: RouteDeps<'_>,
) -> (u16, &'static str, String) {
    let RouteDeps {
        store,
        broker,
        cache,
        script_engine,
    } = deps;
    let path = path.trim_start_matches('/');
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    if segments.is_empty() || (segments.len() == 1 && segments[0] == "v1") {
        return (
            200,
            "OK",
            r#"{"lux":"ok","version":""#.to_string() + env!("CARGO_PKG_VERSION") + r#""}"#,
        );
    }

    let base = if segments[0] == "v1" {
        &segments[1..]
    } else {
        &segments[..]
    };

    match (method, base) {
        // ── exec (escape hatch) ──
        ("POST", ["exec"]) => ok(handle_exec(body, store, broker, cache, script_engine)),

        // ── KV routes ──
        ("GET", ["kv", key]) => ok(exec_json(
            store,
            broker,
            cache,
            script_engine,
            &["GET", key],
        )),
        ("PUT", ["kv", key]) => {
            let parsed: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
            let value = parsed["value"].as_str().unwrap_or("");
            if let Some(ex) = parsed["ex"].as_u64() {
                ok(exec_json(
                    store,
                    broker,
                    cache,
                    script_engine,
                    &["SET", key, value, "EX", &ex.to_string()],
                ))
            } else {
                ok(exec_json(
                    store,
                    broker,
                    cache,
                    script_engine,
                    &["SET", key, value],
                ))
            }
        }
        ("DELETE", ["kv", key]) => ok(exec_json(
            store,
            broker,
            cache,
            script_engine,
            &["DEL", key],
        )),
        ("POST", ["kv", key, "incr"]) => ok(exec_json(
            store,
            broker,
            cache,
            script_engine,
            &["INCR", key],
        )),
        ("POST", ["kv", key, "decr"]) => ok(exec_json(
            store,
            broker,
            cache,
            script_engine,
            &["DECR", key],
        )),
        ("GET", ["kv", key, "hash"]) => ok(exec_json(
            store,
            broker,
            cache,
            script_engine,
            &["HGETALL", key],
        )),
        ("GET", ["kv", key, "list"]) => {
            let start = get_param(params, "start").unwrap_or("0");
            let stop = get_param(params, "stop").unwrap_or("-1");
            ok(exec_json(
                store,
                broker,
                cache,
                script_engine,
                &["LRANGE", key, start, stop],
            ))
        }
        ("GET", ["kv", key, "set"]) => ok(exec_json(
            store,
            broker,
            cache,
            script_engine,
            &["SMEMBERS", key],
        )),
        ("GET", ["kv", key, "zset"]) => {
            let min = get_param(params, "min").unwrap_or("-inf");
            let max = get_param(params, "max").unwrap_or("+inf");
            ok(exec_json(
                store,
                broker,
                cache,
                script_engine,
                &["ZRANGEBYSCORE", key, min, max, "WITHSCORES"],
            ))
        }
        ("GET", ["keys"]) => {
            let pattern = get_param(params, "pattern").unwrap_or("*");
            ok(exec_json(
                store,
                broker,
                cache,
                script_engine,
                &["KEYS", pattern],
            ))
        }
        ("GET", ["dbsize"]) => ok(exec_json(store, broker, cache, script_engine, &["DBSIZE"])),
        ("GET", ["ping"]) => ok(exec_json(store, broker, cache, script_engine, &["PING"])),

        // ── Table routes (PostgREST-style) ──
        ("GET", ["tables"]) => ok(exec_json(store, broker, cache, script_engine, &["TLIST"])),
        ("POST", ["tables"]) => route_table_create(body, store, broker, cache, script_engine),
        ("GET", ["tables", table]) => route_table_query(table, params, store, broker, cache),
        ("GET", ["tables", table, "schema"]) => {
            let now = std::time::Instant::now();
            match crate::tables::table_schema(store, cache, table, now) {
                Ok(fields) => {
                    let items: Vec<String> = fields
                        .iter()
                        .map(|f| format!(r#""{}""#, escape_json(f)))
                        .collect();
                    ok(format!(r#"{{"result":[{}]}}"#, items.join(",")))
                }
                Err(e) => (
                    400,
                    "Bad Request",
                    format!(r#"{{"error":"{}"}}"#, escape_json(&e)),
                ),
            }
        }
        ("GET", ["tables", table, "count"]) => {
            let now = std::time::Instant::now();
            match crate::tables::table_count(store, cache, table, now) {
                Ok(n) => ok(format!(r#"{{"result":{n}}}"#)),
                Err(e) => (
                    400,
                    "Bad Request",
                    format!(r#"{{"error":"{}"}}"#, escape_json(&e)),
                ),
            }
        }
        ("POST", ["tables", table]) => route_table_insert(table, body, store, broker, cache),
        // Bulk update via PATCH (requires where parameter for safety)
        ("PATCH", ["tables", table]) => {
            route_table_update(table, params, body, store, broker, cache, script_engine)
        }
        // Bulk delete via DELETE with where parameter (TDROP is separate)
        ("DELETE", ["tables", table]) => {
            route_table_delete(table, params, store, broker, cache, script_engine)
        }

        // ── Time Series routes ──
        ("GET", ["ts"]) => {
            let filter = get_param(params, "filter").unwrap_or("");
            if filter.is_empty() {
                (
                    400,
                    "Bad Request",
                    r#"{"error":"filter parameter required"}"#.to_string(),
                )
            } else {
                let mut args = vec!["TSMRANGE", "-", "+", "FILTER", filter];
                if let Some(agg) = get_param(params, "agg") {
                    if let Some(bucket) = get_param(params, "bucket") {
                        args.push("AGGREGATION");
                        args.push(agg);
                        args.push(bucket);
                    }
                }
                ok(exec_json(store, broker, cache, script_engine, &args))
            }
        }
        ("GET", ["ts", key]) => route_ts_range(key, params, store, broker, cache, script_engine),
        ("POST", ["ts", key]) => route_ts_add(key, body, store, broker, cache, script_engine),
        ("GET", ["ts", key, "info"]) => ok(exec_json(
            store,
            broker,
            cache,
            script_engine,
            &["TSINFO", key],
        )),
        ("GET", ["ts", key, "latest"]) => ok(exec_json(
            store,
            broker,
            cache,
            script_engine,
            &["TSGET", key],
        )),

        // ── Vector routes ──
        ("POST", ["vectors", "search"]) => {
            route_vector_search(body, store, broker, cache, script_engine)
        }
        ("POST", ["vectors", key]) => {
            route_vector_set(key, body, store, broker, cache, script_engine)
        }
        ("GET", ["vectors", key]) => ok(exec_json(
            store,
            broker,
            cache,
            script_engine,
            &["VGET", key],
        )),
        ("DELETE", ["vectors", key]) => ok(exec_json(
            store,
            broker,
            cache,
            script_engine,
            &["DEL", key],
        )),
        ("GET", ["vectors"]) => ok(exec_json(store, broker, cache, script_engine, &["VCARD"])),

        // ── Legacy flat routes (backwards compat) ──
        ("GET", ["get", key]) => ok(exec_json(
            store,
            broker,
            cache,
            script_engine,
            &["GET", key],
        )),
        ("POST", ["set", key]) => {
            let parsed: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
            let value = parsed["value"].as_str().unwrap_or("");
            if let Some(ex) = parsed["ex"].as_u64() {
                ok(exec_json(
                    store,
                    broker,
                    cache,
                    script_engine,
                    &["SET", key, value, "EX", &ex.to_string()],
                ))
            } else {
                ok(exec_json(
                    store,
                    broker,
                    cache,
                    script_engine,
                    &["SET", key, value],
                ))
            }
        }
        ("POST", ["del", key]) => ok(exec_json(
            store,
            broker,
            cache,
            script_engine,
            &["DEL", key],
        )),
        ("POST", ["incr", key]) => ok(exec_json(
            store,
            broker,
            cache,
            script_engine,
            &["INCR", key],
        )),
        ("POST", ["decr", key]) => ok(exec_json(
            store,
            broker,
            cache,
            script_engine,
            &["DECR", key],
        )),
        ("GET", ["hgetall", key]) => ok(exec_json(
            store,
            broker,
            cache,
            script_engine,
            &["HGETALL", key],
        )),
        ("GET", ["keys", pattern]) => ok(exec_json(
            store,
            broker,
            cache,
            script_engine,
            &["KEYS", pattern],
        )),

        _ => (404, "Not Found", r#"{"error":"not found"}"#.to_string()),
    }
}

fn ok(result: String) -> (u16, &'static str, String) {
    (200, "OK", result)
}

// ── Table handlers ──

fn route_table_create(
    body: &str,
    store: &Arc<Store>,
    broker: &Broker,
    cache: &SharedSchemaCache,
    script_engine: &Arc<lua::ScriptEngine>,
) -> (u16, &'static str, String) {
    let parsed: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            return (
                400,
                "Bad Request",
                r#"{"error":"invalid json"}"#.to_string(),
            )
        }
    };

    let name = match parsed["name"].as_str() {
        Some(n) => n,
        None => {
            return (
                400,
                "Bad Request",
                r#"{"error":"missing name"}"#.to_string(),
            )
        }
    };

    let columns = match parsed["columns"].as_array() {
        Some(cols) => cols,
        None => {
            return (
                400,
                "Bad Request",
                r#"{"error":"missing columns array"}"#.to_string(),
            )
        }
    };

    // Build the column list as SQL-like specs joined by commas.
    // Accepts two formats per element:
    //   - plain string: "id UUID PRIMARY KEY" (passed through as-is)
    //   - object: {"name":"email","type":"STR","primaryKey":true,"unique":true,"notNull":true,
    //              "references":"users(id)","onDelete":"CASCADE"}
    let mut col_specs: Vec<String> = Vec::new();
    for col in columns {
        if let Some(s) = col.as_str() {
            col_specs.push(s.to_string());
        } else if let Some(obj) = col.as_object() {
            let col_name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let col_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("STR");
            let mut spec = format!("{} {}", col_name, col_type);
            if obj
                .get("primaryKey")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                spec.push_str(" PRIMARY KEY");
            } else if obj.get("unique").and_then(|v| v.as_bool()).unwrap_or(false) {
                spec.push_str(" UNIQUE");
            }
            if obj
                .get("notNull")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                spec.push_str(" NOT NULL");
            }
            if let Some(refs) = obj.get("references").and_then(|v| v.as_str()) {
                spec.push_str(&format!(" REFERENCES {}", refs));
                if let Some(on_delete) = obj.get("onDelete").and_then(|v| v.as_str()) {
                    spec.push_str(&format!(" ON DELETE {}", on_delete));
                }
            }
            col_specs.push(spec);
        }
    }

    // Join with commas and split back into tokens for parse_column_list
    let combined = col_specs.join(", ");
    let mut args: Vec<String> = vec!["TCREATE".to_string(), name.to_string()];
    args.extend(combined.split_whitespace().map(|s| s.to_string()));

    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    ok(exec_json(store, broker, cache, script_engine, &refs))
}

fn route_table_query(
    table: &str,
    params: &[(String, String)],
    store: &Arc<Store>,
    _broker: &Broker,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    let now = std::time::Instant::now();

    match parse_http_table_query(params, table, None) {
        Ok((_, plan)) => match crate::tables::table_select(store, cache, &plan, now) {
            Ok(result) => ok(select_result_to_json(result)),
            Err(e) => (
                400,
                "Bad Request",
                format!(r#"{{"error":"{}"}}"#, escape_json(&e)),
            ),
        },
        Err(e) => (
            400,
            "Bad Request",
            format!(r#"{{"error":"{}"}}"#, escape_json(&e)),
        ),
    }
}

fn route_table_insert(
    table: &str,
    body: &str,
    store: &Arc<Store>,
    _broker: &Broker,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    let parsed: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            return (
                400,
                "Bad Request",
                r#"{"error":"invalid json"}"#.to_string(),
            )
        }
    };

    let obj = match parsed.as_object() {
        Some(o) => o,
        None => {
            return (
                400,
                "Bad Request",
                r#"{"error":"expected json object"}"#.to_string(),
            )
        }
    };

    // Build field-value pairs directly - avoids RESP encode/decode round-trip through exec_simple
    let val_strings: Vec<(String, String)> = obj
        .iter()
        .map(|(k, v)| {
            let val = match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                serde_json::Value::Null => String::new(),
                _ => v.to_string(),
            };
            (k.clone(), val)
        })
        .collect();

    let field_values: Vec<(&str, &str)> = val_strings
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let now = Instant::now();
    match crate::tables::table_insert(store, cache, table, &field_values, now) {
        Ok(id) => ok(format!(r#"{{"result":{}}}"#, id)),
        Err(e) => (
            400,
            "Bad Request",
            format!(r#"{{"error":"{}"}}"#, escape_json(&e)),
        ),
    }
}

fn route_table_update(
    table: &str,
    params: &[(String, String)],
    body: &str,
    store: &Arc<Store>,
    broker: &Broker,
    cache: &SharedSchemaCache,
    script_engine: &Arc<lua::ScriptEngine>,
) -> (u16, &'static str, String) {
    // Require where parameter for safety (prevents accidental full table updates)
    let where_clause = match get_param(params, "where") {
        Some(w) => w,
        None => {
            return (
                400,
                "Bad Request",
                r#"{"error":"where parameter required for updates"}"#.to_string(),
            )
        }
    };

    let parsed: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            return (
                400,
                "Bad Request",
                r#"{"error":"invalid json"}"#.to_string(),
            )
        }
    };

    let obj = match parsed.as_object() {
        Some(o) => o,
        None => {
            return (
                400,
                "Bad Request",
                r#"{"error":"expected json object"}"#.to_string(),
            )
        }
    };

    // Build TUPDATE command: TUPDATE <table> SET <col> <val> ... WHERE <conditions>
    let mut args: Vec<String> = vec!["TUPDATE".to_string(), table.to_string(), "SET".to_string()];
    for (k, v) in obj {
        args.push(k.clone());
        match v {
            serde_json::Value::String(s) => args.push(s.clone()),
            serde_json::Value::Number(n) => args.push(n.to_string()),
            serde_json::Value::Bool(b) => args.push(b.to_string()),
            _ => args.push(v.to_string()),
        }
    }
    args.push("WHERE".to_string());
    let where_tokens = match parse_http_where_tokens(where_clause) {
        Ok(tokens) => tokens,
        Err(e) => {
            return (
                400,
                "Bad Request",
                format!(r#"{{"error":"{}"}}"#, escape_json(&e)),
            )
        }
    };
    args.extend(where_tokens);

    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    ok(exec_json(store, broker, cache, script_engine, &refs))
}

fn route_table_delete(
    table: &str,
    params: &[(String, String)],
    store: &Arc<Store>,
    broker: &Broker,
    cache: &SharedSchemaCache,
    script_engine: &Arc<lua::ScriptEngine>,
) -> (u16, &'static str, String) {
    // Check for drop=true parameter to distinguish from delete
    if let Some(val) = get_param(params, "drop") {
        if val == "true" {
            return ok(exec_json(
                store,
                broker,
                cache,
                script_engine,
                &["TDROP", table],
            ));
        }
    }

    // Require where parameter for safety (prevents accidental full table deletes)
    let where_clause =
        match get_param(params, "where") {
            Some(w) => w,
            None => return (
                400,
                "Bad Request",
                r#"{"error":"where parameter required for delete (use drop=true to drop table)"}"#
                    .to_string(),
            ),
        };

    // Build TDELETE command: TDELETE FROM <table> WHERE <conditions>
    let mut args: Vec<String> = vec!["TDELETE".to_string(), "FROM".to_string(), table.to_string()];
    args.push("WHERE".to_string());
    let where_tokens = match parse_http_where_tokens(where_clause) {
        Ok(tokens) => tokens,
        Err(e) => {
            return (
                400,
                "Bad Request",
                format!(r#"{{"error":"{}"}}"#, escape_json(&e)),
            )
        }
    };
    args.extend(where_tokens);

    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    ok(exec_json(store, broker, cache, script_engine, &refs))
}

// ── Time Series handlers ──

fn route_ts_range(
    key: &str,
    params: &[(String, String)],
    store: &Arc<Store>,
    broker: &Broker,
    cache: &SharedSchemaCache,
    script_engine: &Arc<lua::ScriptEngine>,
) -> (u16, &'static str, String) {
    let from = get_param(params, "from").unwrap_or("-");
    let to = get_param(params, "to").unwrap_or("+");

    let mut args: Vec<String> = vec![
        "TSRANGE".to_string(),
        key.to_string(),
        from.to_string(),
        to.to_string(),
    ];

    if let Some(agg) = get_param(params, "agg") {
        if let Some(bucket) = get_param(params, "bucket") {
            args.push("AGGREGATION".to_string());
            args.push(agg.to_string());
            args.push(bucket.to_string());
        }
    }

    if let Some(count) = get_param(params, "count") {
        args.push("COUNT".to_string());
        args.push(count.to_string());
    }

    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    ok(exec_json(store, broker, cache, script_engine, &refs))
}

fn route_ts_add(
    key: &str,
    body: &str,
    store: &Arc<Store>,
    broker: &Broker,
    cache: &SharedSchemaCache,
    script_engine: &Arc<lua::ScriptEngine>,
) -> (u16, &'static str, String) {
    let parsed: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            return (
                400,
                "Bad Request",
                r#"{"error":"invalid json"}"#.to_string(),
            )
        }
    };

    let timestamp = parsed["timestamp"].as_str().unwrap_or("*").to_string();
    let value = match parsed.get("value") {
        Some(serde_json::Value::Number(n)) => n.to_string(),
        Some(serde_json::Value::String(s)) => s.clone(),
        _ => {
            return (
                400,
                "Bad Request",
                r#"{"error":"missing value"}"#.to_string(),
            )
        }
    };

    let mut args: Vec<String> = vec!["TSADD".to_string(), key.to_string(), timestamp, value];

    if let Some(retention) = parsed.get("retention").and_then(|v| v.as_u64()) {
        args.push("RETENTION".to_string());
        args.push(retention.to_string());
    }

    if let Some(labels) = parsed.get("labels").and_then(|v| v.as_object()) {
        args.push("LABELS".to_string());
        for (k, v) in labels {
            args.push(k.clone());
            args.push(v.as_str().unwrap_or("").to_string());
        }
    }

    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    ok(exec_json(store, broker, cache, script_engine, &refs))
}

// ── Vector handlers ──

fn route_vector_set(
    key: &str,
    body: &str,
    store: &Arc<Store>,
    broker: &Broker,
    cache: &SharedSchemaCache,
    script_engine: &Arc<lua::ScriptEngine>,
) -> (u16, &'static str, String) {
    let parsed: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            return (
                400,
                "Bad Request",
                r#"{"error":"invalid json"}"#.to_string(),
            )
        }
    };

    let vector = match parsed.get("vector").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => {
            return (
                400,
                "Bad Request",
                r#"{"error":"missing vector array"}"#.to_string(),
            )
        }
    };

    let dim = vector.len().to_string();
    let mut args: Vec<String> = vec!["VSET".to_string(), key.to_string(), dim];
    for v in vector {
        args.push(v.as_f64().unwrap_or(0.0).to_string());
    }

    if let Some(meta) = parsed.get("metadata") {
        args.push("META".to_string());
        args.push(meta.to_string());
    }

    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    ok(exec_json(store, broker, cache, script_engine, &refs))
}

fn route_vector_search(
    body: &str,
    store: &Arc<Store>,
    broker: &Broker,
    cache: &SharedSchemaCache,
    script_engine: &Arc<lua::ScriptEngine>,
) -> (u16, &'static str, String) {
    let parsed: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            return (
                400,
                "Bad Request",
                r#"{"error":"invalid json"}"#.to_string(),
            )
        }
    };

    let vector = match parsed.get("vector").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => {
            return (
                400,
                "Bad Request",
                r#"{"error":"missing vector array"}"#.to_string(),
            )
        }
    };

    let k = parsed.get("k").and_then(|v| v.as_u64()).unwrap_or(10);
    let dim = vector.len().to_string();

    let mut args: Vec<String> = vec!["VSEARCH".to_string(), dim.clone()];
    for v in vector {
        args.push(v.as_f64().unwrap_or(0.0).to_string());
    }
    args.push("K".to_string());
    args.push(k.to_string());

    if let Some(filter_field) = parsed.get("filter").and_then(|v| v.as_str()) {
        if let Some(filter_val) = parsed.get("filter_value").and_then(|v| v.as_str()) {
            args.push("FILTER".to_string());
            args.push(filter_field.to_string());
            args.push(filter_val.to_string());
        }
    }

    args.push("META".to_string());

    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    ok(exec_json(store, broker, cache, script_engine, &refs))
}

// ── Command execution ──

fn handle_exec(
    body: &str,
    store: &Arc<Store>,
    broker: &Broker,
    cache: &SharedSchemaCache,
    script_engine: &Arc<lua::ScriptEngine>,
) -> String {
    let parsed: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return r#"{"error":"invalid json"}"#.to_string(),
    };

    let command = match parsed.get("command") {
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .map(|v| v.as_str().unwrap_or("").to_string())
            .collect::<Vec<_>>(),
        Some(serde_json::Value::String(s)) => s.split_whitespace().map(String::from).collect(),
        _ => return r#"{"error":"missing command"}"#.to_string(),
    };

    if command.is_empty() {
        return r#"{"error":"empty command"}"#.to_string();
    }

    exec_json(
        store,
        broker,
        cache,
        script_engine,
        &command.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
    )
}

// ---------------------------------------------------------------------------
// Direct JSON serialization - bypasses RESP entirely
// ---------------------------------------------------------------------------

/// Serialize a SelectResult straight to JSON without touching RESP.
fn select_result_to_json(result: crate::tables::SelectResult) -> String {
    match result {
        crate::tables::SelectResult::Rows(rows) => {
            // Estimate ~80 bytes per field, 4 fields avg per row - better than 64 flat
            let est_cols = rows.first().map(|r| r.len()).unwrap_or(4);
            let mut out = String::with_capacity(12 + rows.len() * est_cols * 24);
            out.push_str(r#"{"result":["#);
            let mut first_row = true;
            for row in rows {
                if !first_row {
                    out.push(',');
                }
                first_row = false;
                out.push('{');
                let mut first_col = true;
                for (k, v) in &row {
                    if !first_col {
                        out.push(',');
                    }
                    first_col = false;
                    out.push('"');
                    push_escaped(&mut out, k);
                    out.push_str(r#"":"#);
                    // Try to emit numbers unquoted, everything else quoted
                    if looks_numeric(v) || v == "true" || v == "false" {
                        out.push_str(v);
                    } else {
                        out.push('"');
                        push_escaped(&mut out, v);
                        out.push('"');
                    }
                }
                out.push('}');
            }
            out.push_str("]}");
            out
        }
        crate::tables::SelectResult::Aggregate(row) => {
            let mut out = String::with_capacity(128);
            out.push_str(r#"{"result":{"#);
            let mut first = true;
            for (k, v) in &row {
                if !first {
                    out.push(',');
                }
                first = false;
                out.push('"');
                push_escaped(&mut out, k);
                out.push_str(r#"":"#);
                if looks_numeric(v) {
                    out.push_str(v);
                } else {
                    out.push('"');
                    push_escaped(&mut out, v);
                    out.push('"');
                }
            }
            out.push_str("}}");
            out
        }
    }
}

/// Serialize a single row (from table_get) as a JSON object.
fn row_to_json_object(row: &[(String, String)]) -> String {
    let mut out = String::with_capacity(row.len() * 32);
    out.push_str(r#"{"result":{"#);
    let mut first = true;
    for (k, v) in row {
        if !first {
            out.push(',');
        }
        first = false;
        out.push('"');
        push_escaped(&mut out, k);
        out.push_str(r#"":"#);
        if looks_numeric(v) || v == "true" || v == "false" {
            out.push_str(v);
        } else {
            out.push('"');
            push_escaped(&mut out, v);
            out.push('"');
        }
    }
    out.push_str("}}");
    out
}

/// Push a string into out with JSON escaping, no allocations.
#[inline]
fn push_escaped(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.push_str(r#"\""#),
            '\\' => out.push_str(r#"\\"#),
            '\n' => out.push_str(r#"\n"#),
            '\r' => out.push_str(r#"\r"#),
            '\t' => out.push_str(r#"\t"#),
            c if (c as u32) < 32 => {
                out.push_str(&format!(r#"\u{:04x}"#, c as u32));
            }
            c => out.push(c),
        }
    }
}

/// Returns true if s looks like a JSON number (integer or float).
#[inline]
fn looks_numeric(s: &str) -> bool {
    // Only emit as a bare JSON number if it actually parses as one.
    // This prevents invalid JSON for strings like "-", "1.2.3", "1e", "1-2".
    s.parse::<i64>().is_ok() || s.parse::<f64>().is_ok()
}

fn exec_json(
    store: &Arc<Store>,
    broker: &Broker,
    cache: &SharedSchemaCache,
    script_engine: &Arc<lua::ScriptEngine>,
    args: &[&str],
) -> String {
    match exec_resp(store, broker, cache, script_engine, args) {
        Ok(resp) => resp_to_json(&resp),
        Err(e) => format!(r#"{{"error":"{}"}}"#, escape_json(&e.to_string())),
    }
}

fn exec_resp(
    store: &Arc<Store>,
    broker: &Broker,
    cache: &SharedSchemaCache,
    script_engine: &Arc<lua::ScriptEngine>,
    args: &[&str],
) -> Result<bytes::Bytes, LuxError> {
    if args.is_empty() {
        return Err(LuxError::Unsupported("empty command".to_string()));
    }
    let argv: Vec<Vec<u8>> = args.iter().map(|s| s.as_bytes().to_vec()).collect();
    let refs: Vec<&[u8]> = argv.iter().map(|a| a.as_slice()).collect();
    let mut out = BytesMut::with_capacity(1024);
    let now = Instant::now();
    let executor = CommandExecutor::new(
        store.clone(),
        broker.clone(),
        script_engine.clone(),
        cache.clone(),
    );
    let mut session = CommandSession::new(false);
    store.add_total_commands(1);
    if let Some(action) = executor.execute_command(&refs, &mut session, &mut out, now) {
        let kind = match action {
            crate::cmd::CmdResult::BlockPop { .. } => "BLPOP/BRPOP",
            crate::cmd::CmdResult::BlockMove { .. } => "BLMOVE",
            crate::cmd::CmdResult::BlockStreamRead { .. } => "XREAD/XREADGROUP",
            crate::cmd::CmdResult::BlockZPop { .. } => "BZPOP*",
            _ => "unsupported",
        };
        return Err(LuxError::Unsupported(format!(
            "blocking command not supported in HTTP execution: {kind}"
        )));
    }
    Ok(out.freeze())
}

// ── RESP to JSON translation ──

fn resp_to_json(buf: &[u8]) -> String {
    let s = std::str::from_utf8(buf).unwrap_or("");
    if s.is_empty() {
        return r#"{"result":null}"#.to_string();
    }

    match s.as_bytes()[0] {
        b'+' => {
            let val = s[1..].trim_end_matches("\r\n");
            format!(r#"{{"result":"{}"}}"#, escape_json(val))
        }
        b'-' => {
            let val = s[1..].trim_end_matches("\r\n");
            format!(r#"{{"error":"{}"}}"#, escape_json(val))
        }
        b':' => {
            let val = s[1..].trim_end_matches("\r\n");
            format!(r#"{{"result":{val}}}"#)
        }
        b'$' => {
            let nl = s.find("\r\n").unwrap_or(s.len());
            let len: i64 = s[1..nl].parse().unwrap_or(-1);
            if len < 0 {
                r#"{"result":null}"#.to_string()
            } else {
                let start = nl + 2;
                let end = start + len as usize;
                let val = &s[start..end.min(s.len())];
                format!(r#"{{"result":"{}"}}"#, escape_json(val))
            }
        }
        b'*' => {
            let parsed = parse_resp_array(s);
            format!(r#"{{"result":{}}}"#, parsed)
        }
        _ => {
            format!(r#"{{"result":"{}"}}"#, escape_json(s.trim()))
        }
    }
}

fn parse_resp_array(s: &str) -> String {
    let nl = match s.find("\r\n") {
        Some(i) => i,
        None => return "[]".to_string(),
    };
    let count: i64 = s[1..nl].parse().unwrap_or(-1);
    if count < 0 {
        return "null".to_string();
    }
    if count == 0 {
        return "[]".to_string();
    }

    let mut items = Vec::new();
    let mut pos = nl + 2;
    let bytes = s.as_bytes();

    for _ in 0..count {
        if pos >= bytes.len() {
            break;
        }
        match bytes[pos] {
            b'$' => {
                let end = find_crlf(s, pos);
                let len: i64 = s[pos + 1..end].parse().unwrap_or(-1);
                if len < 0 {
                    items.push("null".to_string());
                    pos = end + 2;
                } else {
                    let start = end + 2;
                    let val_end = start + len as usize;
                    let val = &s[start..val_end.min(s.len())];
                    items.push(format!(r#""{}""#, escape_json(val)));
                    pos = val_end + 2;
                }
            }
            b':' => {
                let end = find_crlf(s, pos);
                let val = &s[pos + 1..end];
                items.push(val.to_string());
                pos = end + 2;
            }
            b'+' => {
                let end = find_crlf(s, pos);
                let val = &s[pos + 1..end];
                items.push(format!(r#""{}""#, escape_json(val)));
                pos = end + 2;
            }
            b'-' => {
                let end = find_crlf(s, pos);
                let val = &s[pos + 1..end];
                items.push(format!(r#""{}""#, escape_json(val)));
                pos = end + 2;
            }
            b'*' => {
                let sub = &s[pos..];
                let parsed = parse_resp_array(sub);
                items.push(parsed);
                pos += skip_resp_element(sub);
            }
            _ => {
                let end = find_crlf(s, pos);
                let val = &s[pos..end];
                items.push(format!(r#""{}""#, escape_json(val)));
                pos = end + 2;
            }
        }
    }

    format!("[{}]", items.join(","))
}

fn find_crlf(s: &str, from: usize) -> usize {
    s[from..].find("\r\n").map(|i| from + i).unwrap_or(s.len())
}

fn skip_resp_element(s: &str) -> usize {
    if s.is_empty() {
        return 0;
    }
    match s.as_bytes()[0] {
        b'$' => {
            let nl = find_crlf(s, 0);
            let len: i64 = s[1..nl].parse().unwrap_or(-1);
            if len < 0 {
                nl + 2
            } else {
                nl + 2 + len as usize + 2
            }
        }
        b':' | b'+' | b'-' => {
            let nl = find_crlf(s, 0);
            nl + 2
        }
        b'*' => {
            let nl = find_crlf(s, 0);
            let count: i64 = s[1..nl].parse().unwrap_or(-1);
            let mut pos = nl + 2;
            for _ in 0..count.max(0) {
                pos += skip_resp_element(&s[pos..]);
            }
            pos
        }
        _ => {
            let nl = find_crlf(s, 0);
            nl + 2
        }
    }
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}
