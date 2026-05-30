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
