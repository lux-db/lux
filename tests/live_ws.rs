mod common;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Child;
use std::time::Duration;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

type TestWs = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

struct LuxServer {
    child: Child,
    tmpdir: std::path::PathBuf,
}

impl Drop for LuxServer {
    fn drop(&mut self) {
        common::terminate_child(&mut self.child);
        let _ = std::fs::remove_dir_all(&self.tmpdir);
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start_lux(resp_port: u16, http_port: u16, password: Option<&str>) -> LuxServer {
    start_lux_with_env(resp_port, http_port, password, &[])
}

fn start_lux_with_env(
    resp_port: u16,
    http_port: u16,
    password: Option<&str>,
    extra_env: &[(&str, &str)],
) -> LuxServer {
    let bin = std::path::PathBuf::from(env!("CARGO_BIN_EXE_lux"));
    let tmpdir = std::env::temp_dir().join(format!(
        "lux_live_ws_test_{}_{}",
        std::process::id(),
        http_port
    ));
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();

    let mut cmd = common::lux_command(&bin);
    cmd.env("LUX_PORT", resp_port.to_string())
        .env("LUX_HTTP_PORT", http_port.to_string())
        .env("LUX_SHARDS", "4")
        .env("LUX_SAVE_INTERVAL", "0")
        .env("LUX_DATA_DIR", tmpdir.to_str().unwrap())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    if let Some(password) = password {
        cmd.env("LUX_PASSWORD", password);
    }
    for (key, value) in extra_env {
        cmd.env(key, value);
    }

    let child = cmd.spawn().expect("failed to start lux");
    let server = LuxServer { child, tmpdir };
    for _ in 0..80 {
        if TcpStream::connect(("127.0.0.1", http_port)).is_ok()
            && TcpStream::connect(("127.0.0.1", resp_port)).is_ok()
        {
            return server;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("lux did not start on resp={resp_port} http={http_port}");
}

fn http_json_request(
    port: u16,
    method: &str,
    path: &str,
    body: &str,
    auth: Option<&str>,
) -> (u16, Value) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n{}",
        auth.map(|token| format!("Authorization: Bearer {token}\r\n"))
            .unwrap_or_default(),
        body.len(),
        body
    );
    stream.write_all(request.as_bytes()).unwrap();

    let mut response = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&buf[..n]);
                if let Some(header_end) = response.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&response[..header_end]);
                    let Some(len) = headers
                        .lines()
                        .find(|line| line.to_ascii_lowercase().starts_with("content-length:"))
                        .and_then(|line| line.split(':').nth(1))
                        .and_then(|value| value.trim().parse::<usize>().ok())
                    else {
                        continue;
                    };
                    if response.len() >= header_end + 4 + len {
                        break;
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => panic!("HTTP read failed: {e}"),
        }
    }

    let text = String::from_utf8_lossy(&response);
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("");
    (
        status,
        serde_json::from_str(body).unwrap_or_else(|_| json!({})),
    )
}

async fn connect_live(http_port: u16, password: Option<&str>) -> TestWs {
    let mut request = format!("ws://127.0.0.1:{http_port}/live")
        .into_client_request()
        .unwrap();
    if let Some(password) = password {
        request.headers_mut().insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {password}")).unwrap(),
        );
    }
    let (ws, _) = connect_async(request).await.expect("websocket connect");
    ws
}

async fn send_json(ws: &mut TestWs, value: Value) {
    ws.send(Message::Text(value.to_string()))
        .await
        .expect("send websocket json");
}

async fn recv_json(ws: &mut TestWs) -> Value {
    let message = tokio::time::timeout(Duration::from_secs(3), ws.next())
        .await
        .expect("timed out waiting for websocket message")
        .expect("websocket closed")
        .expect("websocket error");
    match message {
        Message::Text(text) => serde_json::from_str(&text).expect("websocket text should be json"),
        other => panic!("expected websocket text, got {other:?}"),
    }
}

async fn recv_live_event(ws: &mut TestWs, id: &str) -> Value {
    loop {
        let message = recv_json(ws).await;
        if message.get("type").and_then(Value::as_str) == Some("live.event")
            && message.get("id").and_then(Value::as_str) == Some(id)
        {
            return message["event"].clone();
        }
    }
}

fn resp_command(port: u16, args: &[&str]) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut request = format!("*{}\r\n", args.len());
    for arg in args {
        request.push_str(&format!("${}\r\n{}\r\n", arg.len(), arg));
    }
    stream.write_all(request.as_bytes()).unwrap();

    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&buf[..n]);
                if n < buf.len() {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => panic!("RESP read failed: {e}"),
        }
    }
    String::from_utf8_lossy(&response).to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_websocket_requires_auth_when_password_is_set() {
    let resp_port = free_port();
    let http_port = free_port();
    let _server = start_lux(resp_port, http_port, Some("secret"));

    let err = connect_async(format!("ws://127.0.0.1:{http_port}/live"))
        .await
        .expect_err("unauthenticated websocket should be rejected");
    assert!(err.to_string().contains("401"), "unexpected error: {err}");

    let mut ws = connect_live(http_port, Some("secret")).await;
    send_json(
        &mut ws,
        json!({"type":"live.subscribe","id":"k","spec":{"kind":"key","pattern":"auth:*"}}),
    )
    .await;
    let subscribed = recv_json(&mut ws).await;
    assert_eq!(subscribed["type"], "live.subscribed");
    assert_eq!(subscribed["id"], "k");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_websocket_requires_lux_auth_token_when_auth_is_enabled() {
    let resp_port = free_port();
    let http_port = free_port();
    let _server = start_lux_with_env(
        resp_port,
        http_port,
        Some("rootsecret"),
        &[("LUX_AUTH_ENABLED", "true")],
    );

    let err = connect_async(format!("ws://127.0.0.1:{http_port}/live"))
        .await
        .expect_err("anonymous websocket should be rejected when auth is enabled");
    assert!(err.to_string().contains("401"), "unexpected error: {err}");

    let (status, signup) = http_json_request(
        http_port,
        "POST",
        "/auth/v1/signup",
        r#"{"email":"live-auth@example.com","password":"password123"}"#,
        None,
    );
    assert_eq!(status, 200, "signup: {signup}");
    let access_token = signup["access_token"]
        .as_str()
        .expect("signup should return access token");

    let mut ws = connect_live(http_port, Some(access_token)).await;
    send_json(
        &mut ws,
        json!({"type":"live.subscribe","id":"denied","spec":{"kind":"key","pattern":"authlive:*"}}),
    )
    .await;
    let denied = recv_json(&mut ws).await;
    assert_eq!(denied["type"], "live.error");
    // Token principals may only subscribe to table queries (gated by grants);
    // raw key subscriptions are operator-only and rejected at subscribe time.
    assert_eq!(denied["error"]["code"], "FORBIDDEN");

    let (status, logout) = http_json_request(
        http_port,
        "POST",
        "/auth/v1/logout",
        "{}",
        Some(access_token),
    );
    assert_eq!(status, 200, "logout: {logout}");

    let err = connect_async({
        let mut request = format!("ws://127.0.0.1:{http_port}/live")
            .into_client_request()
            .unwrap();
        request.headers_mut().insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {access_token}")).unwrap(),
        );
        request
    })
    .await
    .expect_err("revoked auth token should be rejected at websocket handshake");
    assert!(err.to_string().contains("401"), "unexpected error: {err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_websocket_delivers_key_and_pubsub_events() {
    let resp_port = free_port();
    let http_port = free_port();
    let _server = start_lux(resp_port, http_port, None);
    let mut ws = connect_live(http_port, None).await;

    send_json(
        &mut ws,
        json!({"type":"live.subscribe","id":"key-sub","spec":{"kind":"key","pattern":"bench:*"}}),
    )
    .await;
    assert_eq!(recv_json(&mut ws).await["type"], "live.subscribed");

    send_json(
        &mut ws,
        json!({"type":"live.subscribe","id":"pubsub-sub","spec":{"kind":"channel","channel":"room:1"}}),
    )
    .await;
    assert_eq!(recv_json(&mut ws).await["type"], "live.subscribed");

    assert!(resp_command(resp_port, &["SET", "bench:one", "1"]).contains("+OK"));
    let key_event = recv_live_event(&mut ws, "key-sub").await;
    assert_eq!(key_event["kind"], "key.set");
    assert_eq!(key_event["key"], "bench:one");

    assert!(resp_command(resp_port, &["PUBLISH", "room:1", "hello"]).contains(":1"));
    let pubsub_event = recv_live_event(&mut ws, "pubsub-sub").await;
    assert_eq!(pubsub_event["kind"], "pubsub.message");
    assert_eq!(pubsub_event["channel"], "room:1");
    assert_eq!(pubsub_event["message"], "hello");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_websocket_table_subscription_receives_http_insert() {
    let resp_port = free_port();
    let http_port = free_port();
    let _server = start_lux(resp_port, http_port, None);

    let (status, created) = http_json_request(
        http_port,
        "POST",
        "/v1/tables",
        r#"{"name":"live_messages","columns":[{"name":"id","type":"STR","primaryKey":true},{"name":"workspace_id","type":"STR","notNull":true},{"name":"body","type":"STR","notNull":true}]}"#,
        None,
    );
    assert_eq!(status, 200, "create table: {created}");

    let mut ws = connect_live(http_port, None).await;
    send_json(
        &mut ws,
        json!({
            "type":"live.subscribe",
            "id":"messages",
            "spec":{
                "kind":"table",
                "table":"live_messages",
                "where":{"workspace_id":"workspace-a"}
            }
        }),
    )
    .await;
    assert_eq!(recv_json(&mut ws).await["type"], "live.subscribed");
    let snapshot = recv_live_event(&mut ws, "messages").await;
    assert_eq!(snapshot["kind"], "snapshot");
    assert_eq!(snapshot["rows"].as_array().unwrap().len(), 0);

    let (status, inserted_other) = http_json_request(
        http_port,
        "POST",
        "/v1/tables/live_messages",
        r#"{"id":"msg-other","workspace_id":"workspace-b","body":"wrong workspace"}"#,
        None,
    );
    assert_eq!(status, 200, "insert other workspace: {inserted_other}");
    let no_event = tokio::time::timeout(Duration::from_millis(250), ws.next()).await;
    assert!(
        no_event.is_err(),
        "non-matching HTTP table insert should not produce a live event"
    );

    let (status, inserted) = http_json_request(
        http_port,
        "POST",
        "/v1/tables/live_messages",
        r#"{"id":"msg-1","workspace_id":"workspace-a","body":"hello live"}"#,
        None,
    );
    assert_eq!(status, 200, "insert matching row: {inserted}");

    let event = recv_live_event(&mut ws, "messages").await;
    assert_eq!(event["kind"], "insert");
    assert_eq!(event["pk"], "msg-1");
    assert_eq!(event["row"]["body"], "hello live");
    assert_eq!(event["cause"]["kind"], "table.insert");
    assert_eq!(event["cause"]["table"], "live_messages");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_encrypted_table_streams_plaintext_rows_without_key_event_value_leak() {
    let resp_port = free_port();
    let http_port = free_port();
    let _server = start_lux_with_env(resp_port, http_port, None, &[("LUX_ENC_AUTO_INIT", "1")]);

    let (status, created) = http_json_request(
        http_port,
        "POST",
        "/v1/tables",
        r#"{"name":"encrypted_messages","columns":[{"name":"id","type":"STR","primaryKey":true},{"name":"email","type":"STR","encrypted":true,"searchable":true},{"name":"token","type":"STR","encrypted":true}]}"#,
        None,
    );
    assert_eq!(status, 200, "create encrypted table: {created}");

    let mut table_ws = connect_live(http_port, None).await;
    send_json(
        &mut table_ws,
        json!({
            "type":"live.subscribe",
            "id":"messages",
            "spec":{
                "kind":"table",
                "table":"encrypted_messages",
                "where":{"email":"a@example.com"}
            }
        }),
    )
    .await;
    assert_eq!(recv_json(&mut table_ws).await["type"], "live.subscribed");
    let snapshot = recv_live_event(&mut table_ws, "messages").await;
    assert_eq!(snapshot["kind"], "snapshot");
    assert_eq!(snapshot["rows"].as_array().unwrap().len(), 0);

    let mut key_ws = connect_live(http_port, None).await;
    send_json(
        &mut key_ws,
        json!({"type":"live.subscribe","id":"keys","spec":{"kind":"key","pattern":"encrypted_messages"}}),
    )
    .await;
    assert_eq!(recv_json(&mut key_ws).await["type"], "live.subscribed");

    let (status, inserted) = http_json_request(
        http_port,
        "POST",
        "/v1/tables/encrypted_messages",
        r#"{"id":"msg-1","email":"a@example.com","token":"live-secret"}"#,
        None,
    );
    assert_eq!(status, 200, "insert encrypted row: {inserted}");
    assert_eq!(inserted["result"]["token"], "live-secret");

    let key_event = recv_live_event(&mut key_ws, "keys").await;
    assert_eq!(key_event["kind"], "key.update");
    assert_eq!(key_event["key"], "encrypted_messages");
    let key_json = key_event.to_string();
    assert!(
        !key_json.contains("live-secret") && !key_json.contains("a@example.com"),
        "key event leaked encrypted table values: {key_json}"
    );

    let insert = recv_live_event(&mut table_ws, "messages").await;
    assert_eq!(insert["kind"], "insert");
    assert_eq!(insert["pk"], "msg-1");
    assert_eq!(insert["row"]["email"], "a@example.com");
    assert_eq!(insert["row"]["token"], "live-secret");
    let insert_json = insert.to_string();
    assert!(
        !insert_json.contains("LUXENC2"),
        "table live event exposed encrypted envelope bytes: {insert_json}"
    );

    let (status, updated) = http_json_request(
        http_port,
        "PATCH",
        "/v1/tables/encrypted_messages?where=email=a@example.com",
        r#"{"token":"rotated-secret"}"#,
        None,
    );
    assert_eq!(status, 200, "update encrypted row: {updated}");
    let update = recv_live_event(&mut table_ws, "messages").await;
    assert_eq!(update["kind"], "update");
    assert_eq!(update["row"]["token"], "rotated-secret");
    assert_eq!(update["previous"]["token"], "live-secret");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_websocket_join_reacts_to_joined_table_insert() {
    let resp_port = free_port();
    let http_port = free_port();
    let _server = start_lux(resp_port, http_port, None);

    let (status, created) = http_json_request(
        http_port,
        "POST",
        "/v1/tables",
        r#"{"name":"live_teams","columns":[{"name":"id","type":"STR","primaryKey":true},{"name":"name","type":"STR","notNull":true}]}"#,
        None,
    );
    assert_eq!(status, 200, "create teams: {created}");
    let (status, created) = http_json_request(
        http_port,
        "POST",
        "/v1/tables",
        r#"{"name":"live_members","columns":[{"name":"id","type":"STR","primaryKey":true},{"name":"team_id","type":"STR","notNull":true},{"name":"user_id","type":"STR","notNull":true}]}"#,
        None,
    );
    assert_eq!(status, 200, "create members: {created}");

    let (status, inserted) = http_json_request(
        http_port,
        "POST",
        "/v1/tables/live_members",
        r#"{"id":"member-1","team_id":"team-1","user_id":"user-1"}"#,
        None,
    );
    assert_eq!(status, 200, "insert member: {inserted}");

    let mut ws = connect_live(http_port, None).await;
    send_json(
        &mut ws,
        json!({
            "type":"live.subscribe",
            "id":"teams",
            "spec":{
                "kind":"table",
                "table":"live_members",
                "select":"t.id AS id,t.name AS name",
                "where":[{"field":"user_id","op":"=","value":"user-1"}],
                "joins":[{
                    "type":"inner",
                    "table":"live_teams",
                    "alias":"t",
                    "onLeft":"team_id",
                    "onRight":"id"
                }]
            }
        }),
    )
    .await;
    assert_eq!(recv_json(&mut ws).await["type"], "live.subscribed");
    let snapshot = recv_live_event(&mut ws, "teams").await;
    assert_eq!(snapshot["kind"], "snapshot");
    assert_eq!(snapshot["rows"].as_array().unwrap().len(), 0);

    let (status, inserted) = http_json_request(
        http_port,
        "POST",
        "/v1/tables/live_teams",
        r#"{"id":"team-1","name":"Realtime Team"}"#,
        None,
    );
    assert_eq!(status, 200, "insert team: {inserted}");

    let event = recv_live_event(&mut ws, "teams").await;
    assert_eq!(event["kind"], "insert");
    assert_eq!(event["pk"], "team-1");
    assert_eq!(event["row"]["name"], "Realtime Team");
    assert_eq!(event["cause"]["table"], "live_teams");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_websocket_unsubscribe_stops_delivery() {
    let resp_port = free_port();
    let http_port = free_port();
    let _server = start_lux(resp_port, http_port, None);
    let mut ws = connect_live(http_port, None).await;

    send_json(
        &mut ws,
        json!({"type":"live.subscribe","id":"key-sub","spec":{"kind":"key","pattern":"gone:*"}}),
    )
    .await;
    assert_eq!(recv_json(&mut ws).await["type"], "live.subscribed");

    send_json(&mut ws, json!({"type":"live.unsubscribe","id":"key-sub"})).await;
    let unsubscribed = recv_json(&mut ws).await;
    assert_eq!(unsubscribed["type"], "live.unsubscribed");
    assert_eq!(unsubscribed["id"], "key-sub");

    assert!(resp_command(resp_port, &["SET", "gone:one", "1"]).contains("+OK"));
    let no_event = tokio::time::timeout(Duration::from_millis(250), ws.next()).await;
    assert!(
        no_event.is_err(),
        "unsubscribed websocket received an event"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_websocket_vector_near_receives_vector_changes() {
    let resp_port = free_port();
    let http_port = free_port();
    let _server = start_lux(resp_port, http_port, None);
    let mut ws = connect_live(http_port, None).await;

    send_json(
        &mut ws,
        json!({
            "type":"live.subscribe",
            "id":"near",
            "spec":{"kind":"vector.near","vector":[1.0,0.0],"k":3,"threshold":0.5}
        }),
    )
    .await;
    assert_eq!(recv_json(&mut ws).await["type"], "live.subscribed");
    let snapshot = recv_live_event(&mut ws, "near").await;
    assert_eq!(snapshot["kind"], "snapshot");
    assert_eq!(snapshot["rows"].as_array().unwrap().len(), 0);

    assert!(resp_command(resp_port, &["VSET", "doc:1", "2", "1.0", "0.0"]).contains("+OK"));
    let insert = recv_live_event(&mut ws, "near").await;
    assert_eq!(insert["kind"], "insert");
    assert_eq!(insert["cause"]["kind"], "vector.set");
    assert_eq!(insert["cause"]["key"], "doc:1");
}

// Regression: a table whose primary key is not literally `id` must still get
// live insert/update/delete events. The diff used to index rows by a hardcoded
// `id`/`key` field, so any custom PK (e.g. `user_id`) silently produced no
// change events even though the snapshot worked. Covers the `cursors` shape
// (custom PK + FLOAT column) used by realtime apps.
#[tokio::test]
async fn live_table_events_with_custom_pk() {
    let resp_port = free_port();
    let http_port = free_port();
    let pw = "secret-pw-live";
    let _server = start_lux_with_env(
        resp_port,
        http_port,
        Some(pw),
        &[("LUX_AUTH_ENABLED", "true")],
    );

    let (status, created) = http_json_request(
        http_port,
        "POST",
        "/v1/tables",
        r#"{"name":"cursors","columns":[{"name":"user_id","type":"STR","primaryKey":true},{"name":"x","type":"FLOAT"},{"name":"name","type":"STR"}]}"#,
        Some(pw),
    );
    assert_eq!(status, 200, "create: {created}");

    let mut ws = connect_live(http_port, Some(pw)).await;
    send_json(
        &mut ws,
        json!({"type":"live.subscribe","id":"c","spec":{"kind":"table","table":"cursors"}}),
    )
    .await;
    assert_eq!(recv_json(&mut ws).await["type"], "live.subscribed");
    assert_eq!(recv_live_event(&mut ws, "c").await["kind"], "snapshot");

    // insert
    let (status, _) = http_json_request(
        http_port,
        "POST",
        "/v1/tables/cursors",
        r#"{"user_id":"u1","x":0.5,"name":"otter"}"#,
        Some(pw),
    );
    assert_eq!(status, 200);
    let insert = recv_live_event(&mut ws, "c").await;
    assert_eq!(insert["kind"], "insert");
    assert_eq!(insert["pk"], "u1");
    assert_eq!(insert["row"]["name"], "otter");

    // update (PATCH keyed on the custom PK)
    let (status, _) = http_json_request(
        http_port,
        "PATCH",
        "/v1/tables/cursors?where=user_id=u1",
        r#"{"x":0.9}"#,
        Some(pw),
    );
    assert_eq!(status, 200);
    let update = recv_live_event(&mut ws, "c").await;
    assert_eq!(update["kind"], "update");
    assert_eq!(update["pk"], "u1");

    // delete
    let (status, _) = http_json_request(
        http_port,
        "DELETE",
        "/v1/tables/cursors?where=user_id=u1",
        "",
        Some(pw),
    );
    assert_eq!(status, 200);
    let delete = recv_live_event(&mut ws, "c").await;
    assert_eq!(delete["kind"], "delete");
    assert_eq!(delete["pk"], "u1");
}

// Row TTL: an expiring row must push a `.live()` delete to subscribers, the same
// way an explicit TDELETE does. Covers the realtime half of table-row TTL.
#[tokio::test]
async fn live_table_row_ttl_emits_delete() {
    let resp_port = free_port();
    let http_port = free_port();
    let _server = start_lux(resp_port, http_port, None);

    let (status, created) = http_json_request(
        http_port,
        "POST",
        "/v1/tables",
        r#"{"name":"pres","columns":[{"name":"user_id","type":"STR","primaryKey":true},{"name":"room","type":"STR"}]}"#,
        None,
    );
    assert_eq!(status, 200, "create: {created}");

    let mut ws = connect_live(http_port, None).await;
    send_json(
        &mut ws,
        json!({"type":"live.subscribe","id":"p","spec":{"kind":"table","table":"pres"}}),
    )
    .await;
    assert_eq!(recv_json(&mut ws).await["type"], "live.subscribed");
    assert_eq!(recv_live_event(&mut ws, "p").await["kind"], "snapshot");

    let (status, inserted) = http_json_request(
        http_port,
        "POST",
        "/v1/tables/pres?ttl=1",
        r#"{"user_id":"u1","room":"main"}"#,
        None,
    );
    assert_eq!(status, 200, "insert: {inserted}");
    let insert = recv_live_event(&mut ws, "p").await;
    assert_eq!(insert["kind"], "insert");
    assert_eq!(insert["pk"], "u1");

    // The TTL sweep should expire the row ~1s later and emit a delete.
    let delete = recv_live_event(&mut ws, "p").await;
    assert_eq!(
        delete["kind"], "delete",
        "expected expiry delete, got {delete}"
    );
    assert_eq!(delete["pk"], "u1");
}

// Multi-row insert (HTTP array body) with ?ttl applies the TTL to every row.
#[tokio::test]
async fn http_array_insert_applies_ttl_to_each() {
    let resp_port = free_port();
    let http_port = free_port();
    let _server = start_lux(resp_port, http_port, None);

    let (status, _) = http_json_request(
        http_port,
        "POST",
        "/v1/tables",
        r#"{"name":"pres","columns":[{"name":"user_id","type":"STR","primaryKey":true},{"name":"room","type":"STR"}]}"#,
        None,
    );
    assert_eq!(status, 200);

    // The insert response returns both rows -> the TTL applied to each.
    let (status, inserted) = http_json_request(
        http_port,
        "POST",
        "/v1/tables/pres?ttl=1",
        r#"[{"user_id":"a","room":"r"},{"user_id":"b","room":"r"}]"#,
        None,
    );
    assert_eq!(status, 200, "array insert: {inserted}");
    assert_eq!(
        inserted["result"].as_array().map(|a| a.len()).unwrap_or(0),
        2,
        "two rows inserted: {inserted}"
    );

    // After the TTL lapses, a fresh subscription's snapshot is empty.
    tokio::time::sleep(Duration::from_millis(1400)).await;
    let mut ws = connect_live(http_port, None).await;
    send_json(
        &mut ws,
        json!({"type":"live.subscribe","id":"p","spec":{"kind":"table","table":"pres"}}),
    )
    .await;
    assert_eq!(recv_json(&mut ws).await["type"], "live.subscribed");
    let snap = recv_live_event(&mut ws, "p").await;
    assert_eq!(snap["kind"], "snapshot");
    assert_eq!(
        snap["rows"].as_array().map(|a| a.len()).unwrap_or(99),
        0,
        "both rows should expire: {snap}"
    );
}

// The accountless-frontend path end to end: `signInAnonymously` yields a real
// User principal that (a) passes the auth-on `/live` handshake (anonymous
// sockets are 401'd) and (b) gets RLS-gated `.live()` rows via `auth.uid()`,
// exactly like the swarm/cursors use case but with no signup.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_anonymous_session_subscribes_granted_table() {
    let resp_port = free_port();
    let http_port = free_port();
    let _server = start_lux_with_env(
        resp_port,
        http_port,
        Some("rootsecret"),
        &[("LUX_AUTH_ENABLED", "true")],
    );

    let exec = |cmd: &str| {
        let (s, b) = http_json_request(http_port, "POST", "/v1/exec", cmd, Some("rootsecret"));
        assert_eq!(s, 200, "exec {cmd}: {b}");
    };
    exec(
        r#"{"command":["TCREATE","notes","id","STR","PRIMARY","KEY",",","owner_id","STR",",","body","STR"]}"#,
    );
    exec(r#"{"command":["GRANT","read","ON","notes","WHERE","owner_id","=","auth.uid()"]}"#);

    // Accountless sign-in: no email/password collected.
    let (status, session) =
        http_json_request(http_port, "POST", "/auth/v1/signin/anonymous", "{}", None);
    assert_eq!(status, 200, "anon signin: {session}");
    let access_token = session["access_token"].as_str().unwrap().to_string();
    let uid = session["user"]["id"].as_str().unwrap().to_string();
    assert_eq!(session["user"]["is_anonymous"], true);

    // The anon token passes the /live handshake that 401s anonymous sockets.
    let mut ws = connect_live(http_port, Some(&access_token)).await;
    send_json(
        &mut ws,
        json!({"type":"live.subscribe","id":"n","spec":{"kind":"table","table":"notes"}}),
    )
    .await;
    assert_eq!(recv_json(&mut ws).await["type"], "live.subscribed");
    assert_eq!(recv_live_event(&mut ws, "n").await["kind"], "snapshot");

    // A row owned by the anon principal arrives as a live insert (RLS via uid).
    exec(&format!(
        r#"{{"command":["TINSERT","notes","id","n1","owner_id","{uid}","body","hello"]}}"#
    ));
    let insert = recv_live_event(&mut ws, "n").await;
    assert_eq!(insert["kind"], "insert");
    assert_eq!(insert["pk"], "n1");
    assert_eq!(insert["row"]["body"], "hello");
}

// Incremental view maintenance: an UPDATE that moves a row across the WHERE
// predicate must emit exactly one insert (move-in) or delete (move-out), and an
// in-place change to a matching row must emit an update. This is the case the
// coarse re-query path handled but the delta path must reproduce precisely.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_table_where_predicate_transitions_emit_incremental_deltas() {
    let resp_port = free_port();
    let http_port = free_port();
    let _server = start_lux(resp_port, http_port, None);

    let (status, created) = http_json_request(
        http_port,
        "POST",
        "/v1/tables",
        r#"{"name":"tasks","columns":[{"name":"id","type":"STR","primaryKey":true},{"name":"status","type":"STR","notNull":true},{"name":"title","type":"STR"}]}"#,
        None,
    );
    assert_eq!(status, 200, "create table: {created}");

    let mut ws = connect_live(http_port, None).await;
    send_json(
        &mut ws,
        json!({
            "type":"live.subscribe",
            "id":"open",
            "spec":{"kind":"table","table":"tasks","where":{"status":"open"}}
        }),
    )
    .await;
    assert_eq!(recv_json(&mut ws).await["type"], "live.subscribed");
    assert_eq!(recv_live_event(&mut ws, "open").await["kind"], "snapshot");

    // Insert a matching row -> insert.
    let (status, _) = http_json_request(
        http_port,
        "POST",
        "/v1/tables/tasks",
        r#"{"id":"t1","status":"open","title":"first"}"#,
        None,
    );
    assert_eq!(status, 200);
    let e = recv_live_event(&mut ws, "open").await;
    assert_eq!(e["kind"], "insert");
    assert_eq!(e["pk"], "t1");
    assert_eq!(e["cause"]["kind"], "table.insert");

    // Insert a non-matching row -> no event.
    let (status, _) = http_json_request(
        http_port,
        "POST",
        "/v1/tables/tasks",
        r#"{"id":"t2","status":"closed","title":"second"}"#,
        None,
    );
    assert_eq!(status, 200);
    let none = tokio::time::timeout(Duration::from_millis(250), ws.next()).await;
    assert!(none.is_err(), "non-matching insert should not emit");

    // Move t2 into the predicate via UPDATE -> insert (not update).
    let (status, _) = http_json_request(
        http_port,
        "PATCH",
        "/v1/tables/tasks/t2",
        r#"{"status":"open"}"#,
        None,
    );
    assert_eq!(status, 200);
    let e = recv_live_event(&mut ws, "open").await;
    assert_eq!(e["kind"], "insert", "move-in should read as insert: {e}");
    assert_eq!(e["pk"], "t2");

    // In-place change to a matching row -> update.
    let (status, _) = http_json_request(
        http_port,
        "PATCH",
        "/v1/tables/tasks/t1",
        r#"{"title":"renamed"}"#,
        None,
    );
    assert_eq!(status, 200);
    let e = recv_live_event(&mut ws, "open").await;
    assert_eq!(e["kind"], "update", "in-place change should be update: {e}");
    assert_eq!(e["pk"], "t1");
    assert_eq!(e["row"]["title"], "renamed");
    assert_eq!(e["cause"]["kind"], "table.update");

    // Move t1 out of the predicate via UPDATE -> delete (not update).
    let (status, _) = http_json_request(
        http_port,
        "PATCH",
        "/v1/tables/tasks/t1",
        r#"{"status":"done"}"#,
        None,
    );
    assert_eq!(status, 200);
    let e = recv_live_event(&mut ws, "open").await;
    assert_eq!(e["kind"], "delete", "move-out should read as delete: {e}");
    assert_eq!(e["pk"], "t1");
    assert_eq!(e["cause"]["kind"], "table.delete");

    // An UPDATE to a row that is out of the set on both sides -> no event.
    let (status, _) = http_json_request(
        http_port,
        "PATCH",
        "/v1/tables/tasks/t1",
        r#"{"title":"still done"}"#,
        None,
    );
    assert_eq!(status, 200);
    let none = tokio::time::timeout(Duration::from_millis(250), ws.next()).await;
    assert!(none.is_err(), "out-of-set update should not emit");

    // Delete the remaining matching row -> delete.
    let reply = resp_command(
        resp_port,
        &["TDELETE", "FROM", "tasks", "WHERE", "id", "=", "t2"],
    );
    assert!(!reply.contains("ERR"), "tdelete: {reply}");
    let e = recv_live_event(&mut ws, "open").await;
    assert_eq!(e["kind"], "delete");
    assert_eq!(e["pk"], "t2");
}

// Parity: the incrementally-maintained result set must equal a fresh TSELECT of
// the same query after an arbitrary write sequence (IVM == ground truth).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_table_ivm_result_matches_fresh_select() {
    let resp_port = free_port();
    let http_port = free_port();
    let _server = start_lux(resp_port, http_port, None);

    let (status, created) = http_json_request(
        http_port,
        "POST",
        "/v1/tables",
        r#"{"name":"items","columns":[{"name":"id","type":"STR","primaryKey":true},{"name":"bucket","type":"STR","notNull":true},{"name":"v","type":"INT"}]}"#,
        None,
    );
    assert_eq!(status, 200, "create: {created}");

    let mut ws = connect_live(http_port, None).await;
    send_json(
        &mut ws,
        json!({
            "type":"live.subscribe",
            "id":"a",
            "spec":{"kind":"table","table":"items","where":{"bucket":"a"}}
        }),
    )
    .await;
    assert_eq!(recv_json(&mut ws).await["type"], "live.subscribed");
    assert_eq!(recv_live_event(&mut ws, "a").await["kind"], "snapshot");

    // A mixed write sequence: inserts, in/out moves, in-place updates, deletes.
    let writes: &[(&str, &str, &str)] = &[
        (
            "POST",
            "/v1/tables/items",
            r#"{"id":"i1","bucket":"a","v":1}"#,
        ),
        (
            "POST",
            "/v1/tables/items",
            r#"{"id":"i2","bucket":"b","v":2}"#,
        ),
        (
            "POST",
            "/v1/tables/items",
            r#"{"id":"i3","bucket":"a","v":3}"#,
        ),
        ("PATCH", "/v1/tables/items/i2", r#"{"bucket":"a"}"#), // move in
        ("PATCH", "/v1/tables/items/i1", r#"{"v":10}"#),       // in-place
        ("PATCH", "/v1/tables/items/i3", r#"{"bucket":"c"}"#), // move out
        (
            "POST",
            "/v1/tables/items",
            r#"{"id":"i4","bucket":"a","v":4}"#,
        ),
    ];
    for (method, path, body) in writes {
        let (status, resp) = http_json_request(http_port, method, path, body, None);
        assert_eq!(status, 200, "{method} {path}: {resp}");
    }
    // Delete i2 (RESP, since HTTP delete-by-id is a where-filtered bulk route).
    let reply = resp_command(
        resp_port,
        &["TDELETE", "FROM", "items", "WHERE", "id", "=", "i2"],
    );
    assert!(!reply.contains("ERR"), "tdelete: {reply}");

    // Reconstruct the client's maintained result set purely from the delta
    // stream, applying each event the way a real client would.
    let mut client: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
    while let Ok(event) =
        tokio::time::timeout(Duration::from_millis(300), recv_live_event(&mut ws, "a")).await
    {
        let pk = event["pk"].as_str().unwrap().to_string();
        match event["kind"].as_str().unwrap() {
            "insert" | "update" => {
                client.insert(pk, event["row"].clone());
            }
            "delete" => {
                client.remove(&pk);
            }
            other => panic!("unexpected event kind {other}: {event}"),
        }
    }

    // Ground truth after the sequence, restricted to bucket == "a":
    //   i1: inserted (a,1) then v->10           => present, v=10
    //   i2: (b,2) -> moved to a -> deleted        => absent
    //   i3: (a,3) -> moved to c                    => absent
    //   i4: inserted (a,4)                         => present, v=4
    let mut client_ids: Vec<&String> = client.keys().collect();
    client_ids.sort();
    assert_eq!(
        client_ids,
        vec![&"i1".to_string(), &"i4".to_string()],
        "IVM-maintained set must converge to ground truth: {client:?}"
    );
    assert_eq!(
        client["i1"]["v"],
        json!(10),
        "i1 reflects the in-place update"
    );
    assert_eq!(client["i4"]["v"], json!(4));
}

// After a live socket disconnects, its row-delta subscription must be torn down
// so the broker's per-table channel and subscriber gate are reclaimed. A fresh
// connection re-subscribing to the same table must still receive deltas, proving
// the teardown left the broker in a clean, reusable state.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_table_ivm_survives_reconnect_after_disconnect() {
    let resp_port = free_port();
    let http_port = free_port();
    let _server = start_lux(resp_port, http_port, None);

    let (status, _) = http_json_request(
        http_port,
        "POST",
        "/v1/tables",
        r#"{"name":"beats","columns":[{"name":"id","type":"STR","primaryKey":true},{"name":"room","type":"STR"}]}"#,
        None,
    );
    assert_eq!(status, 200);

    // First subscriber connects, gets its snapshot, then drops the socket.
    {
        let mut ws = connect_live(http_port, None).await;
        send_json(
            &mut ws,
            json!({"type":"live.subscribe","id":"b","spec":{"kind":"table","table":"beats"}}),
        )
        .await;
        assert_eq!(recv_json(&mut ws).await["type"], "live.subscribed");
        assert_eq!(recv_live_event(&mut ws, "b").await["kind"], "snapshot");
        // ws dropped here -> server-side teardown should reclaim the channel.
    }

    // Give the server a moment to observe the close and run teardown.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // A brand-new connection re-subscribes to the same table and must still get
    // incremental deltas (the reclaimed channel is transparently recreated).
    let mut ws2 = connect_live(http_port, None).await;
    send_json(
        &mut ws2,
        json!({"type":"live.subscribe","id":"b2","spec":{"kind":"table","table":"beats"}}),
    )
    .await;
    assert_eq!(recv_json(&mut ws2).await["type"], "live.subscribed");
    assert_eq!(recv_live_event(&mut ws2, "b2").await["kind"], "snapshot");

    let (status, _) = http_json_request(
        http_port,
        "POST",
        "/v1/tables/beats",
        r#"{"id":"k1","room":"main"}"#,
        None,
    );
    assert_eq!(status, 200);

    let e = recv_live_event(&mut ws2, "b2").await;
    assert_eq!(e["kind"], "insert");
    assert_eq!(e["pk"], "k1");
}
