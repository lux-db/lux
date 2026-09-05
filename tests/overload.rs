use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;

fn resp_command(args: &[&[u8]]) -> Vec<u8> {
    let mut request = format!("*{}\r\n", args.len()).into_bytes();
    for arg in args {
        request.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
        request.extend_from_slice(arg);
        request.extend_from_slice(b"\r\n");
    }
    request
}

async fn read_quiet(socket: &mut TcpStream) -> Vec<u8> {
    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match tokio::time::timeout(Duration::from_millis(100), socket.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(count)) => response.extend_from_slice(&buf[..count]),
            Ok(Err(error)) => panic!("socket read failed: {error}"),
            Err(_) => break,
        }
    }
    response
}

async fn send_resp(address: SocketAddr, args: &[&[u8]]) -> Vec<u8> {
    let mut socket = TcpStream::connect(address).await.unwrap();
    socket.write_all(&resp_command(args)).await.unwrap();
    read_quiet(&mut socket).await
}

async fn read_http_response(socket: &mut TcpStream) -> Vec<u8> {
    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    let mut total_needed = None;
    loop {
        let count = tokio::time::timeout(Duration::from_secs(3), socket.read(&mut buf))
            .await
            .expect("HTTP response timed out")
            .expect("HTTP response read failed");
        if count == 0 {
            break;
        }
        response.extend_from_slice(&buf[..count]);
        if total_needed.is_none() {
            if let Some(header_end) = response.windows(4).position(|window| window == b"\r\n\r\n") {
                let header_end = header_end + 4;
                let headers = String::from_utf8_lossy(&response[..header_end]);
                let body_length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                total_needed = Some(header_end + body_length);
            }
        }
        if total_needed.is_some_and(|needed| response.len() >= needed) {
            break;
        }
    }
    response
}

async fn send_http(address: SocketAddr, request: Vec<u8>) -> Vec<u8> {
    let mut socket = TcpStream::connect(address).await.unwrap();
    socket.write_all(&request).await.unwrap();
    read_http_response(&mut socket).await
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.local_addr().unwrap().port()
}

async fn start_server(
    mut config: lux::ServerConfig,
) -> (lux::ServerHandle, SocketAddr, Option<SocketAddr>) {
    let http_address = Arc::new(Mutex::new(None));
    let ready = http_address.clone();
    config.on_info = Some(Arc::new(move |event| {
        if let lux::ServerInfoEvent::HttpReady { addr } = event {
            *ready.lock().unwrap() = Some(addr);
        }
    }));
    let handle = lux::run_with_config(config).await.unwrap();
    let resp_address = handle.local_addr().expect("RESP listener address");
    let http_address = *http_address.lock().unwrap();
    (handle, resp_address, http_address)
}

fn test_config(root: &std::path::Path) -> lux::ServerConfig {
    lux::ServerConfig {
        port: 0,
        data_dir: root.display().to_string(),
        save_interval: Duration::ZERO,
        ..lux::ServerConfig::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connection_ceilings_shed_and_recover() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.http_port = free_port();
    config.limits.max_resp_connections = 1;
    config.limits.max_http_connections = 1;
    config.limits.http_header_timeout = Duration::from_secs(5);
    let (handle, resp_address, http_address) = start_server(config).await;
    let http_address = http_address.unwrap();

    let resp_held = TcpStream::connect(resp_address).await.unwrap();
    tokio::time::sleep(Duration::from_millis(25)).await;
    let mut rejected = TcpStream::connect(resp_address).await.unwrap();
    let response = read_quiet(&mut rejected).await;
    assert!(
        response.starts_with(b"-ERR max number of clients reached"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    drop(resp_held);
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(send_resp(resp_address, &[b"PING"]).await, b"+PONG\r\n");

    let http_held = TcpStream::connect(http_address).await.unwrap();
    tokio::time::sleep(Duration::from_millis(25)).await;
    let mut rejected = TcpStream::connect(http_address).await.unwrap();
    let response = read_http_response(&mut rejected).await;
    assert!(response.starts_with(b"HTTP/1.1 503 Service Unavailable"));
    assert!(response.ends_with(b"{\"error\":\"server connection limit reached\"}"));
    drop(http_held);
    tokio::time::sleep(Duration::from_millis(25)).await;
    let response = send_http(
        http_address,
        b"GET /health/live HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
    )
    .await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    let info = send_resp(resp_address, &[b"INFO"]).await;
    let info = String::from_utf8_lossy(&info);
    assert!(info.contains("rejected_resp_connections:1"), "{info}");
    assert!(info.contains("rejected_http_connections:1"), "{info}");

    drop(rejected);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn partial_request_deadlines_close_connections_and_recover() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.http_port = free_port();
    config.limits.resp_request_timeout = Duration::from_millis(150);
    config.limits.http_header_timeout = Duration::from_millis(150);
    config.limits.http_body_timeout = Duration::from_millis(150);
    let (handle, resp_address, http_address) = start_server(config).await;
    let http_address = http_address.unwrap();

    let mut resp = TcpStream::connect(resp_address).await.unwrap();
    resp.write_all(b"*2\r\n$4\r\nPING\r\n$5\r\nhe")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    resp.write_all(b"l").await.unwrap();
    tokio::time::sleep(Duration::from_millis(95)).await;
    let response = read_quiet(&mut resp).await;
    assert!(String::from_utf8_lossy(&response).contains("RESP request timeout"));

    let mut header = TcpStream::connect(http_address).await.unwrap();
    header
        .write_all(b"GET /health/live HTTP/1.1\r\nHost:")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    header.write_all(b" ").await.unwrap();
    let response = read_http_response(&mut header).await;
    assert!(response.starts_with(b"HTTP/1.1 408 Request Timeout"));

    let mut body = TcpStream::connect(http_address).await.unwrap();
    body.write_all(b"POST /v1/exec HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\nx")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    body.write_all(b"y").await.unwrap();
    let response = read_http_response(&mut body).await;
    assert!(response.starts_with(b"HTTP/1.1 408 Request Timeout"));

    assert_eq!(send_resp(resp_address, &[b"PING"]).await, b"+PONG\r\n");
    let response = send_http(
        http_address,
        b"GET /health/live HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
    )
    .await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    let info = String::from_utf8_lossy(&send_resp(resp_address, &[b"INFO"]).await).into_owned();
    assert!(info.contains("connection_timeouts:3"), "{info}");

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_keep_alive_and_framing_fail_closed_then_recover() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.http_port = free_port();
    config.limits.http_keep_alive_timeout = Duration::from_millis(100);
    let (handle, _, http_address) = start_server(config).await;
    let address = http_address.unwrap();

    let mut idle = TcpStream::connect(address).await.unwrap();
    idle.write_all(b"GET /health/live HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    assert!(read_http_response(&mut idle)
        .await
        .starts_with(b"HTTP/1.1 200 OK"));
    tokio::time::sleep(Duration::from_millis(125)).await;
    let mut byte = [0u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), idle.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );

    for request in [
        b"POST /v1/exec HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".as_slice(),
        b"POST /v1/exec HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n".as_slice(),
        b"POST /v1/exec HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx".as_slice(),
        b"POST /v1/exec HTTP/1.1\r\nHost: localhost\r\nContent-Length: nope\r\n\r\n".as_slice(),
    ] {
        let response = send_http(address, request.to_vec()).await;
        assert!(
            response.starts_with(b"HTTP/1.1 400")
                || response.starts_with(b"HTTP/1.1 501"),
            "{}",
            String::from_utf8_lossy(&response)
        );
    }

    let pipelined = [
        b"GET /health/live HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(),
        b"GET /health/live HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(),
    ]
    .concat();
    let response = send_http(address, pipelined).await;
    assert!(response.starts_with(b"HTTP/1.1 400 Bad Request"));
    assert!(String::from_utf8_lossy(&response).contains("pipelining is not supported"));

    let response = send_http(
        address,
        b"GET /health/live HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
    )
    .await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK"));

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_header_body_and_duplicate_length_boundaries_are_exact() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.http_port = free_port();
    config.max_body = 8;
    let (handle, _, http_address) = start_server(config).await;
    let address = http_address.unwrap();

    let exact_body =
        b"GET /health/live HTTP/1.1\r\nHost: localhost\r\nContent-Length: 8\r\n\r\n12345678";
    assert!(send_http(address, exact_body.to_vec())
        .await
        .starts_with(b"HTTP/1.1 200 OK"));

    let duplicate = b"GET /health/live HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx";
    assert!(send_http(address, duplicate.to_vec())
        .await
        .starts_with(b"HTTP/1.1 200 OK"));

    let oversized_body =
        b"GET /health/live HTTP/1.1\r\nHost: localhost\r\nContent-Length: 9\r\n\r\n123456789";
    assert!(send_http(address, oversized_body.to_vec())
        .await
        .starts_with(b"HTTP/1.1 413 Payload Too Large"));

    let prefix = b"GET /health/live HTTP/1.1\r\nHost: localhost\r\nX-Fill: ";
    let suffix = b"\r\n\r\n";
    let fill = vec![b'a'; 64 * 1024 - prefix.len() - suffix.len()];
    let exact_header = [prefix.as_slice(), fill.as_slice(), suffix.as_slice()].concat();
    assert_eq!(exact_header.len(), 64 * 1024);
    assert!(send_http(address, exact_header)
        .await
        .starts_with(b"HTTP/1.1 200 OK"));

    let fill = vec![b'a'; 64 * 1024 + 1 - prefix.len() - suffix.len()];
    let oversized_header = [prefix.as_slice(), fill.as_slice(), suffix.as_slice()].concat();
    assert!(send_http(address, oversized_header)
        .await
        .starts_with(b"HTTP/1.1 431 Request Header Fields Too Large"));

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_resp_connection_closes_and_releases_capacity() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.limits.max_resp_connections = 1;
    config.limits.resp_idle_timeout = Duration::from_millis(100);
    let (handle, address, _) = start_server(config).await;

    let mut idle = TcpStream::connect(address).await.unwrap();
    let mut byte = [0u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), idle.read(&mut byte))
            .await
            .expect("idle RESP connection did not close")
            .unwrap(),
        0
    );
    assert_eq!(send_resp(address, &[b"PING"]).await, b"+PONG\r\n");

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_shape_and_shared_memory_limits_are_deterministic() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.max_resp_request = 64;
    config.max_body = 64;
    config.http_port = free_port();
    config.limits.max_request_buffer_bytes = 64;
    config.limits.max_resp_pipeline_commands = 2;
    config.limits.max_resp_command_args = 2;
    config.limits.max_resp_subscriptions = 1;
    config.limits.max_subscription_name_bytes = 3;
    let (handle, address, http_address) = start_server(config).await;
    let http_address = http_address.unwrap();

    let pipeline = [
        resp_command(&[b"PING"]),
        resp_command(&[b"PING"]),
        resp_command(&[b"PING"]),
    ]
    .concat();
    let mut socket = TcpStream::connect(address).await.unwrap();
    socket.write_all(&pipeline).await.unwrap();
    let response = read_quiet(&mut socket).await;
    assert!(String::from_utf8_lossy(&response).contains("pipeline command limit exceeded"));

    let response = send_resp(address, &[b"SET", b"key", b"value"]).await;
    assert!(String::from_utf8_lossy(&response).contains("array count exceeds maximum"));

    let mut inline = TcpStream::connect(address).await.unwrap();
    inline.write_all(b"SET key value\r\n").await.unwrap();
    let response = read_quiet(&mut inline).await;
    assert!(String::from_utf8_lossy(&response).contains("argument count exceeds maximum"));

    let mut subscriber = TcpStream::connect(address).await.unwrap();
    subscriber
        .write_all(&resp_command(&[b"SUBSCRIBE", b"four"]))
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&read_quiet(&mut subscriber).await)
        .contains("subscription name exceeds maximum"));
    subscriber
        .write_all(&resp_command(&[b"SUBSCRIBE", b"one"]))
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&read_quiet(&mut subscriber).await).contains("subscribe"));
    subscriber
        .write_all(&resp_command(&[b"SUBSCRIBE", b"one"]))
        .await
        .unwrap();
    let duplicate = String::from_utf8_lossy(&read_quiet(&mut subscriber).await).into_owned();
    assert!(duplicate.contains("subscribe"), "{duplicate}");
    assert!(duplicate.contains(":1\r\n"), "{duplicate}");
    subscriber
        .write_all(&resp_command(&[b"SUBSCRIBE", b"two"]))
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&read_quiet(&mut subscriber).await)
        .contains("maximum subscriptions reached"));
    drop(subscriber);
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(
        send_resp(address, &[b"PUBSUB", b"CHANNELS"]).await,
        b"*0\r\n"
    );

    let mut held = TcpStream::connect(address).await.unwrap();
    held.write_all(b"*2\r\n$3\r\nGET\r\n$50\r\npartial-buffer-data")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(25)).await;
    let mut rejected = TcpStream::connect(address).await.unwrap();
    rejected
        .write_all(b"*2\r\n$3\r\nGET\r\n$50\r\nsecond-partial-data")
        .await
        .unwrap();
    let response = read_quiet(&mut rejected).await;
    assert!(String::from_utf8_lossy(&response).contains("buffer capacity exhausted"));
    let response = send_http(
        http_address,
        b"GET /health/live HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
    )
    .await;
    assert!(response.starts_with(b"HTTP/1.1 503 Service Unavailable"));
    drop(held);
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(send_resp(address, &[b"PING"]).await, b"+PONG\r\n");
    let response = send_http(
        http_address,
        b"GET /health/live HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
    )
    .await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    let info = String::from_utf8_lossy(&send_resp(address, &[b"INFO"]).await).into_owned();
    assert!(info.contains("rejected_request_buffers:2"), "{info}");

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retained_session_state_is_bounded() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.max_resp_request = 96;
    config.max_body = 96;
    config.limits.max_request_buffer_bytes = 192;
    let (handle, address, _) = start_server(config).await;

    let mut transaction = TcpStream::connect(address).await.unwrap();
    transaction
        .write_all(&resp_command(&[b"MULTI"]))
        .await
        .unwrap();
    assert_eq!(read_quiet(&mut transaction).await, b"+OK\r\n");
    for key in [b"first".as_slice(), b"second".as_slice()] {
        transaction
            .write_all(&resp_command(&[b"SET", key, &[b'y'; 35]]))
            .await
            .unwrap();
        assert_eq!(read_quiet(&mut transaction).await, b"+QUEUED\r\n");
    }
    transaction
        .write_all(&resp_command(&[b"SET", b"third", &[b'y'; 35]]))
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&read_quiet(&mut transaction).await)
        .contains("transaction queued bytes limit exceeded"));
    transaction
        .write_all(&resp_command(&[b"EXEC"]))
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&read_quiet(&mut transaction).await).contains("EXECABORT"));

    let first_key = [b'a'; 60];
    let second_key = [b'b'; 60];
    let mut watcher = TcpStream::connect(address).await.unwrap();
    watcher
        .write_all(&resp_command(&[b"WATCH", &first_key]))
        .await
        .unwrap();
    assert_eq!(read_quiet(&mut watcher).await, b"+OK\r\n");
    watcher
        .write_all(&resp_command(&[b"WATCH", &second_key]))
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&read_quiet(&mut watcher).await)
        .contains("watched key bytes limit exceeded"));
    watcher
        .write_all(&resp_command(&[b"UNWATCH"]))
        .await
        .unwrap();
    assert_eq!(read_quiet(&mut watcher).await, b"+OK\r\n");

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retained_session_state_shares_and_releases_process_capacity() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.max_resp_request = 96;
    config.max_body = 96;
    config.limits.max_request_buffer_bytes = 120;
    let (handle, address, _) = start_server(config).await;

    let key = [b'k'; 40];
    let mut first = TcpStream::connect(address).await.unwrap();
    first
        .write_all(&resp_command(&[b"WATCH", &key]))
        .await
        .unwrap();
    assert_eq!(read_quiet(&mut first).await, b"+OK\r\n");

    let mut second = TcpStream::connect(address).await.unwrap();
    second
        .write_all(&resp_command(&[b"WATCH", &key]))
        .await
        .unwrap();
    let response = read_quiet(&mut second).await;
    assert!(
        String::from_utf8_lossy(&response).contains("process request capacity exhausted"),
        "{}",
        String::from_utf8_lossy(&response)
    );

    first.write_all(&resp_command(&[b"UNWATCH"])).await.unwrap();
    assert_eq!(read_quiet(&mut first).await, b"+OK\r\n");
    second
        .write_all(&resp_command(&[b"WATCH", &key]))
        .await
        .unwrap();
    assert_eq!(read_quiet(&mut second).await, b"+OK\r\n");

    drop(first);
    drop(second);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resp_response_size_is_bounded_and_capacity_recovers() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.http_port = free_port();
    config.limits.max_resp_response = 36;
    let (handle, address, http_address) = start_server(config).await;
    let http_address = http_address.unwrap();

    assert_eq!(
        send_resp(address, &[b"SET", b"large", &[b'x'; 40]]).await,
        b"+OK\r\n"
    );
    let response = send_resp(address, &[b"GET", b"large"]).await;
    assert!(String::from_utf8_lossy(&response).contains("response exceeds maximum"));

    let body = br#"{"command":["GET","large"]}"#;
    let request = format!(
        "POST /v1/exec HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let response = send_http(http_address, [request.as_bytes(), body].concat()).await;
    assert!(
        String::from_utf8_lossy(&response).contains("command response exceeds maximum"),
        "HTTP command execution materialized an oversized response: {}",
        String::from_utf8_lossy(&response)
    );

    let mut pipelined = TcpStream::connect(address).await.unwrap();
    let request = [
        resp_command(&[b"PING"]),
        resp_command(&[b"EVAL", b"return string.rep('x', 25)", b"0"]),
    ]
    .concat();
    pipelined.write_all(&request).await.unwrap();
    let response = read_quiet(&mut pipelined).await;
    assert!(
        String::from_utf8_lossy(&response).contains("response exceeds maximum"),
        "combined pipeline response escaped its ceiling: {}",
        String::from_utf8_lossy(&response)
    );

    let mut blocked = TcpStream::connect(address).await.unwrap();
    blocked
        .write_all(&resp_command(&[b"BLPOP", b"large-list", b"1"]))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(
        send_resp(address, &[b"LPUSH", b"large-list", &[b'y'; 40]]).await,
        b":1\r\n"
    );
    let blocked_response = read_quiet(&mut blocked).await;
    assert!(String::from_utf8_lossy(&blocked_response).contains("response exceeds maximum"));

    assert_eq!(send_resp(address, &[b"PING"]).await, b"+PONG\r\n");

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn table_queries_reject_excess_candidates_but_allow_limit_pushdown() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.limits.max_query_candidates = 2;
    let (handle, address, _) = start_server(config).await;

    assert_eq!(
        send_resp(address, &[b"TCREATE", b"items", b"name STR,", b"score INT"]).await,
        b"+OK\r\n"
    );
    for (name, score) in [
        (b"one".as_slice(), b"1".as_slice()),
        (b"two".as_slice(), b"2".as_slice()),
        (b"three".as_slice(), b"3".as_slice()),
    ] {
        let response = send_resp(
            address,
            &[b"TINSERT", b"items", b"name", name, b"score", score],
        )
        .await;
        assert!(
            response.starts_with(b":"),
            "{}",
            String::from_utf8_lossy(&response)
        );
    }

    let response = send_resp(address, &[b"TSELECT", b"*", b"FROM", b"items"]).await;
    assert!(String::from_utf8_lossy(&response).contains("query candidate limit exceeded (2)"));

    for query in [
        [
            b"TSELECT".as_slice(),
            b"*",
            b"FROM",
            b"items",
            b"WHERE",
            b"score",
            b">",
            b"0",
        ]
        .as_slice(),
        [
            b"TSELECT".as_slice(),
            b"*",
            b"FROM",
            b"items",
            b"ORDER",
            b"BY",
            b"score",
        ]
        .as_slice(),
        [b"TSELECT".as_slice(), b"SUM(score)", b"FROM", b"items"].as_slice(),
        [
            b"TSELECT".as_slice(),
            b"*",
            b"FROM",
            b"items",
            b"ORDER",
            b"BY",
            b"score",
            b"LIMIT",
            b"1",
            b"OFFSET",
            b"3",
        ]
        .as_slice(),
    ] {
        let response = send_resp(address, query).await;
        assert!(
            String::from_utf8_lossy(&response).contains("query candidate limit exceeded (2)"),
            "{}",
            String::from_utf8_lossy(&response)
        );
    }

    let response = send_resp(address, &[b"TSELECT", b"COUNT(*)", b"FROM", b"items"]).await;
    assert!(response.contains(&b'3'));
    assert!(!String::from_utf8_lossy(&response).contains("candidate limit"));

    let response = send_resp(
        address,
        &[b"TSELECT", b"*", b"FROM", b"items", b"LIMIT", b"1"],
    )
    .await;
    assert!(response.starts_with(b"*1\r\n"));
    assert!(!String::from_utf8_lossy(&response).contains("candidate limit"));

    assert_eq!(
        send_resp(address, &[b"TCREATE", b"left_rows", b"id INT PRIMARY KEY"]).await,
        b"+OK\r\n"
    );
    assert_eq!(
        send_resp(address, &[b"TINSERT", b"left_rows", b"id", b"1"]).await,
        b":1\r\n"
    );
    assert_eq!(
        send_resp(
            address,
            &[
                b"TCREATE",
                b"right_rows",
                b"id INT PRIMARY KEY,",
                b"left_id INT"
            ]
        )
        .await,
        b"+OK\r\n"
    );
    for id in [b"1".as_slice(), b"2".as_slice(), b"3".as_slice()] {
        assert!(send_resp(
            address,
            &[b"TINSERT", b"right_rows", b"id", id, b"left_id", b"1"]
        )
        .await
        .starts_with(b":"));
    }
    let response = send_resp(
        address,
        &[
            b"TSELECT",
            b"*",
            b"FROM",
            b"left_rows",
            b"JOIN",
            b"right_rows",
            b"r",
            b"ON",
            b"id",
            b"=",
            b"r.left_id",
        ],
    )
    .await;
    assert!(String::from_utf8_lossy(&response).contains("query candidate limit exceeded (2)"));

    assert_eq!(
        send_resp(
            address,
            &[
                b"TCREATE",
                b"docs",
                b"id STR PRIMARY KEY,",
                b"emb VECTOR(2)"
            ]
        )
        .await,
        b"+OK\r\n"
    );
    for (id, vector) in [
        (b"a".as_slice(), b"[1,0]".as_slice()),
        (b"b".as_slice(), b"[0.9,0.1]".as_slice()),
        (b"c".as_slice(), b"[0,1]".as_slice()),
    ] {
        let response = send_resp(address, &[b"TINSERT", b"docs", b"id", id, b"emb", vector]).await;
        assert!(!response.starts_with(b"-"));
    }
    let response = send_resp(
        address,
        &[
            b"TSELECT", b"*", b"FROM", b"docs", b"NEAR", b"emb", b"[1,0]", b"K", b"3",
        ],
    )
    .await;
    assert!(String::from_utf8_lossy(&response).contains("query candidate limit exceeded (2)"));

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn table_limits_are_applied_after_filters_select_matching_rows() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.limits.max_query_candidates = 16;
    let (handle, address, _) = start_server(config).await;

    assert_eq!(
        send_resp(
            address,
            &[b"TCREATE", b"filtered", b"name STR,", b"score INT"]
        )
        .await,
        b"+OK\r\n"
    );
    for (name, score) in [
        (b"first".as_slice(), b"1".as_slice()),
        (b"second".as_slice(), b"2".as_slice()),
        (b"match".as_slice(), b"3".as_slice()),
    ] {
        assert!(send_resp(
            address,
            &[b"TINSERT", b"filtered", b"name", name, b"score", score],
        )
        .await
        .starts_with(b":"));
    }

    for query in [
        [
            b"TSELECT".as_slice(),
            b"*",
            b"FROM",
            b"filtered",
            b"WHERE",
            b"name",
            b"LIKE",
            b"mat%",
            b"LIMIT",
            b"1",
        ]
        .as_slice(),
        [
            b"TSELECT".as_slice(),
            b"*",
            b"FROM",
            b"filtered",
            b"WHERE",
            b"name",
            b"=",
            b"match",
            b"ORDER",
            b"BY",
            b"score",
            b"LIMIT",
            b"1",
        ]
        .as_slice(),
        [
            b"TSELECT".as_slice(),
            b"*",
            b"FROM",
            b"filtered",
            b"WHERE",
            b"name",
            b"=",
            b"missing",
            b"OR",
            b"name",
            b"=",
            b"match",
            b"LIMIT",
            b"1",
        ]
        .as_slice(),
    ] {
        let response = send_resp(address, query).await;
        let rendered = String::from_utf8_lossy(&response);
        assert!(response.starts_with(b"*1\r\n"), "{rendered}");
        assert!(rendered.contains("match"), "{rendered}");
    }

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocked_client_limit_releases_after_completion() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.limits.max_blocked_clients = 1;
    config.limits.max_blocking_keys = 1;
    let (handle, address, _) = start_server(config).await;

    let response = send_resp(address, &[b"BLPOP", b"one", b"two", b"1"]).await;
    assert!(String::from_utf8_lossy(&response).contains("blocking key limit exceeded"));

    let mut first = TcpStream::connect(address).await.unwrap();
    first
        .write_all(&resp_command(&[b"BLPOP", b"first", b"0.15"]))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(25)).await;
    let response = send_resp(address, &[b"BLPOP", b"second", b"1"]).await;
    assert!(String::from_utf8_lossy(&response).contains("maximum blocked clients reached"));
    assert_eq!(read_quiet(&mut first).await, b"*-1\r\n");

    let mut recovered = TcpStream::connect(address).await.unwrap();
    recovered
        .write_all(&resp_command(&[b"BLPOP", b"third", b"0.05"]))
        .await
        .unwrap();
    assert_eq!(read_quiet(&mut recovered).await, b"*-1\r\n");

    let mut abandoned = TcpStream::connect(address).await.unwrap();
    abandoned
        .write_all(&resp_command(&[b"BLPOP", b"abandoned", b"30"]))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(25)).await;
    let info = String::from_utf8_lossy(&send_resp(address, &[b"INFO"]).await).into_owned();
    assert!(info.contains("blocked_list_waiters:1"), "{info}");
    drop(abandoned);

    let mut released = false;
    for _ in 0..20 {
        let info = String::from_utf8_lossy(&send_resp(address, &[b"INFO"]).await).into_owned();
        if info.contains("blocked_list_waiters:0") {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(released, "disconnected blocking client leaked its waiter");

    let mut after_disconnect = TcpStream::connect(address).await.unwrap();
    after_disconnect
        .write_all(&resp_command(&[b"BLPOP", b"after-disconnect", b"0.05"]))
        .await
        .unwrap();
    assert_eq!(read_quiet(&mut after_disconnect).await, b"*-1\r\n");

    for args in [
        [b"BLPOP".as_slice(), b"key", b"nan"].as_slice(),
        [b"BLPOP".as_slice(), b"key", b"1e300"].as_slice(),
        [b"BZPOPMIN".as_slice(), b"key", b"inf"].as_slice(),
        [b"BZPOPMIN".as_slice(), b"key", b"1e300"].as_slice(),
        [b"BZMPOP".as_slice(), b"NaN", b"1", b"key", b"MIN"].as_slice(),
    ] {
        let response = send_resp(address, args).await;
        assert!(
            String::from_utf8_lossy(&response).contains("timeout is not a float or out of range"),
            "{}",
            String::from_utf8_lossy(&response)
        );
    }
    assert_eq!(send_resp(address, &[b"PING"]).await, b"+PONG\r\n");

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_auth_work_is_bounded_with_uniform_login_errors() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.http_port = free_port();
    config.durability.policy = lux::DurabilityPolicy::Ephemeral;
    config.auth.enabled = true;
    config.limits.max_auth_workers = 1;
    config.limits.max_http_connections = 32;
    let (handle, _, http_address) = start_server(config).await;
    let address = http_address.unwrap();

    let signup_body = br#"{"email":"known@example.com","password":"password123"}"#;
    let request = format!(
        "POST /auth/v1/signup HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        signup_body.len()
    );
    let response = send_http(address, [request.as_bytes(), signup_body].concat()).await;
    assert!(
        response.starts_with(b"HTTP/1.1 200 OK"),
        "{}",
        String::from_utf8_lossy(&response)
    );

    let barrier = Arc::new(tokio::sync::Barrier::new(13));
    let mut attempts = Vec::new();
    for index in 0..12 {
        let barrier = barrier.clone();
        attempts.push(tokio::spawn(async move {
            barrier.wait().await;
            let body = format!(
                r#"{{"grant_type":"password","email":"storm-{index}@example.com","password":"incorrect-password"}}"#
            );
            let head = format!(
                "POST /auth/v1/token HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            send_http(address, [head.as_bytes(), body.as_bytes()].concat()).await
        }));
    }
    barrier.wait().await;
    let health = tokio::time::timeout(
        Duration::from_secs(1),
        send_http(
            address,
            b"GET /health/live HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
        ),
    )
    .await
    .expect("health endpoint stalled behind password verification");
    assert!(health.starts_with(b"HTTP/1.1 200 OK"));
    let mut shed = 0;
    for attempt in attempts {
        let response = attempt.await.unwrap();
        if response.starts_with(b"HTTP/1.1 429 Too Many Requests") {
            shed += 1;
        }
    }
    assert!(shed > 0, "concurrent login work was not bounded");
    let info = String::from_utf8_lossy(&send_resp(handle.local_addr().unwrap(), &[b"INFO"]).await)
        .into_owned();
    assert!(
        info.contains(&format!("rejected_auth_requests:{shed}")),
        "{info}"
    );

    async fn invalid_login(address: SocketAddr, email: &str) -> Vec<u8> {
        let body = format!(
            r#"{{"grant_type":"password","email":"{email}","password":"incorrect-password"}}"#
        );
        let head = format!(
            "POST /auth/v1/token HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        send_http(address, [head.as_bytes(), body.as_bytes()].concat()).await
    }
    let known = invalid_login(address, "known@example.com").await;
    let unknown = invalid_login(address, "unknown@example.com").await;
    assert_eq!(known, unknown);
    let known_body = known.split(|byte| *byte == b'\n').next_back().unwrap();
    let unknown_body = unknown.split(|byte| *byte == b'\n').next_back().unwrap();
    assert_eq!(known_body, unknown_body);
    assert_eq!(known_body, br#"{"error":"invalid login credentials"}"#);

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_subscription_limit_is_enforced_per_socket() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.http_port = free_port();
    config.limits.max_live_subscriptions = 1;
    config.limits.max_subscription_name_bytes = 3;
    let (handle, _, http_address) = start_server(config).await;
    let address = http_address.unwrap();
    let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{address}/live"))
        .await
        .unwrap();

    socket
        .send(Message::Text(
            r#"{"type":"live.subscribe","id":"large","spec":{"kind":"key","pattern":"four"}}"#
                .to_string(),
        ))
        .await
        .unwrap();
    let oversized = socket.next().await.unwrap().unwrap().into_text().unwrap();
    assert!(
        oversized.contains("subscription name exceeds maximum"),
        "{oversized}"
    );

    socket
        .send(Message::Text(
            r#"{"type":"live.subscribe","id":"one","spec":{"kind":"key","pattern":"one"}}"#
                .to_string(),
        ))
        .await
        .unwrap();
    let first = socket.next().await.unwrap().unwrap().into_text().unwrap();
    assert!(first.contains("live.subscribed"), "{first}");

    socket
        .send(Message::Text(
            r#"{"type":"live.subscribe","id":"two","spec":{"kind":"key","pattern":"two"}}"#
                .to_string(),
        ))
        .await
        .unwrap();
    let second = socket.next().await.unwrap().unwrap().into_text().unwrap();
    assert!(second.contains("LIMIT_EXCEEDED"), "{second}");
    drop(socket);

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_live_socket_is_closed_and_capacity_recovers() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.http_port = free_port();
    config.limits.max_http_connections = 1;
    config.limits.live_idle_timeout = Duration::from_millis(100);
    let (handle, _, http_address) = start_server(config).await;
    let address = http_address.unwrap();
    let (mut idle, _) = tokio_tungstenite::connect_async(format!("ws://{address}/live"))
        .await
        .unwrap();

    let closed = tokio::time::timeout(Duration::from_secs(1), idle.next())
        .await
        .expect("idle live socket was not closed");
    assert!(
        closed.is_none()
            || matches!(closed, Some(Ok(Message::Close(_))))
            || matches!(closed, Some(Err(_)))
    );

    let (recovered, _) = tokio_tungstenite::connect_async(format!("ws://{address}/live"))
        .await
        .unwrap();
    drop(recovered);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_live_message_closes_socket_and_releases_capacity() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.http_port = free_port();
    config.max_body = 128;
    config.limits.max_http_connections = 1;
    let (handle, _, http_address) = start_server(config).await;
    let address = http_address.unwrap();
    let (mut oversized, _) = tokio_tungstenite::connect_async(format!("ws://{address}/live"))
        .await
        .unwrap();

    oversized
        .send(Message::Text("x".repeat(129)))
        .await
        .unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(1), oversized.next())
        .await
        .expect("oversized live message did not close the socket");
    assert!(
        closed.is_none()
            || matches!(closed, Some(Err(_)))
            || matches!(closed, Some(Ok(Message::Close(_))))
    );
    drop(oversized);

    let mut recovered = false;
    for _ in 0..20 {
        if let Ok((socket, _)) =
            tokio_tungstenite::connect_async(format!("ws://{address}/live")).await
        {
            drop(socket);
            recovered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(recovered, "oversized live frame leaked HTTP capacity");

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn overload_does_not_lose_acknowledged_writes() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.limits.max_resp_connections = 2;
    let restart_config = config.clone();
    let (handle, address, _) = start_server(config).await;

    assert_eq!(
        send_resp(address, &[b"SET", b"before-overload", b"safe"]).await,
        b"+OK\r\n"
    );
    let held_one = TcpStream::connect(address).await.unwrap();
    let held_two = TcpStream::connect(address).await.unwrap();
    tokio::time::sleep(Duration::from_millis(25)).await;
    for _ in 0..16 {
        let mut rejected = TcpStream::connect(address).await.unwrap();
        assert!(read_quiet(&mut rejected)
            .await
            .starts_with(b"-ERR max number of clients reached"));
    }
    drop(held_one);
    drop(held_two);
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(
        send_resp(address, &[b"SET", b"after-overload", b"safe"]).await,
        b"+OK\r\n"
    );
    handle.shutdown_and_wait().await.unwrap();

    let (restarted, address, _) = start_server(restart_config).await;
    assert_eq!(
        send_resp(address, &[b"GET", b"before-overload"]).await,
        b"$4\r\nsafe\r\n"
    );
    assert_eq!(
        send_resp(address, &[b"GET", b"after-overload"]).await,
        b"$4\r\nsafe\r\n"
    );
    restarted.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn header_and_body_in_one_large_read_is_not_misclassified() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.http_port = free_port();
    let (handle, _, http_address) = start_server(config).await;
    let address = http_address.unwrap();

    let body = vec![b'x'; 70 * 1024];
    let head = format!(
        "GET /health/live HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let response = send_http(address, [head.as_bytes(), &body].concat()).await;
    assert!(
        response.starts_with(b"HTTP/1.1 200 OK"),
        "{}",
        String::from_utf8_lossy(&response)
    );

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejected_pipelines_never_apply_a_valid_prefix() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.limits.max_resp_pipeline_commands = 1;
    let (handle, address, _) = start_server(config).await;

    let over_limit = [
        resp_command(&[b"SET", b"pipeline-prefix", b"must-not-exist"]),
        resp_command(&[b"PING"]),
    ]
    .concat();
    let mut socket = TcpStream::connect(address).await.unwrap();
    socket.write_all(&over_limit).await.unwrap();
    assert!(String::from_utf8_lossy(&read_quiet(&mut socket).await)
        .contains("pipeline command limit exceeded"));
    assert_eq!(
        send_resp(address, &[b"GET", b"pipeline-prefix"]).await,
        b"$-1\r\n"
    );

    let malformed = [
        resp_command(&[b"SET", b"malformed-prefix", b"must-not-exist"]),
        b"*2\r\n$4\r\nPING\r\n!1\r\nx\r\n".to_vec(),
    ]
    .concat();
    let mut socket = TcpStream::connect(address).await.unwrap();
    socket.write_all(&malformed).await.unwrap();
    assert!(String::from_utf8_lossy(&read_quiet(&mut socket).await).contains("expected bulk"));
    assert_eq!(
        send_resp(address, &[b"GET", b"malformed-prefix"]).await,
        b"$-1\r\n"
    );
    assert_eq!(send_resp(address, &[b"PING"]).await, b"+PONG\r\n");

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transaction_and_watch_limits_leave_the_session_reusable() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.max_resp_request = 80;
    config.max_body = 80;
    config.limits.max_request_buffer_bytes = 80;
    config.limits.max_resp_pipeline_commands = 2;
    config.limits.max_blocking_keys = 1;
    let (handle, address, _) = start_server(config).await;

    let mut socket = TcpStream::connect(address).await.unwrap();
    for args in [
        vec![b"MULTI".as_slice()],
        vec![b"SET".as_slice(), b"one", b"1"],
        vec![b"SET".as_slice(), b"two", b"2"],
        vec![b"SET".as_slice(), b"three", b"3"],
    ] {
        socket.write_all(&resp_command(&args)).await.unwrap();
        let _ = read_quiet(&mut socket).await;
    }
    socket.write_all(&resp_command(&[b"EXEC"])).await.unwrap();
    assert!(String::from_utf8_lossy(&read_quiet(&mut socket).await).contains("EXECABORT"));
    for key in [b"one".as_slice(), b"two", b"three"] {
        assert_eq!(send_resp(address, &[b"GET", key]).await, b"$-1\r\n");
    }

    socket.write_all(&resp_command(&[b"MULTI"])).await.unwrap();
    assert_eq!(read_quiet(&mut socket).await, b"+OK\r\n");
    socket
        .write_all(&resp_command(&[b"SET", b"after-abort", b"safe"]))
        .await
        .unwrap();
    assert_eq!(read_quiet(&mut socket).await, b"+QUEUED\r\n");
    socket.write_all(&resp_command(&[b"EXEC"])).await.unwrap();
    assert!(read_quiet(&mut socket).await.starts_with(b"*1\r\n+OK\r\n"));
    assert_eq!(
        send_resp(address, &[b"GET", b"after-abort"]).await,
        b"$4\r\nsafe\r\n"
    );

    socket
        .write_all(&resp_command(&[b"WATCH", b"one"]))
        .await
        .unwrap();
    assert_eq!(read_quiet(&mut socket).await, b"+OK\r\n");
    socket
        .write_all(&resp_command(&[b"WATCH", b"two"]))
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&read_quiet(&mut socket).await)
        .contains("watched key limit exceeded"));
    socket
        .write_all(&resp_command(&[b"UNWATCH"]))
        .await
        .unwrap();
    assert_eq!(read_quiet(&mut socket).await, b"+OK\r\n");
    socket
        .write_all(&resp_command(&[b"WATCH", b"two"]))
        .await
        .unwrap();
    assert_eq!(read_quiet(&mut socket).await, b"+OK\r\n");

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn query_limit_is_exact_and_rejected_mutations_are_atomic() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.limits.max_query_candidates = 2;
    let (handle, address, _) = start_server(config).await;

    assert_eq!(
        send_resp(
            address,
            &[b"TCREATE", b"bounded", b"id INT PRIMARY KEY,", b"state STR"]
        )
        .await,
        b"+OK\r\n"
    );
    for id in [b"1".as_slice(), b"2"] {
        assert!(send_resp(
            address,
            &[b"TINSERT", b"bounded", b"id", id, b"state", b"old"]
        )
        .await
        .starts_with(b":"));
    }
    let exact = send_resp(address, &[b"TSELECT", b"*", b"FROM", b"bounded"]).await;
    assert!(
        exact.starts_with(b"*2\r\n"),
        "{}",
        String::from_utf8_lossy(&exact)
    );
    assert_eq!(
        send_resp(
            address,
            &[b"TUPDATE", b"bounded", b"SET", b"state", b"safe", b"WHERE", b"id", b">", b"0"]
        )
        .await,
        b":2\r\n"
    );
    assert!(send_resp(
        address,
        &[b"TINSERT", b"bounded", b"id", b"3", b"state", b"old"]
    )
    .await
    .starts_with(b":"));
    let rejected = send_resp(
        address,
        &[
            b"TUPDATE", b"bounded", b"SET", b"state", b"bad", b"WHERE", b"id", b">", b"0",
        ],
    )
    .await;
    assert!(String::from_utf8_lossy(&rejected).contains("query candidate limit exceeded (2)"));

    let rejected_delete = send_resp(
        address,
        &[b"TDELETE", b"FROM", b"bounded", b"WHERE", b"id", b">", b"0"],
    )
    .await;
    assert!(
        String::from_utf8_lossy(&rejected_delete).contains("query candidate limit exceeded (2)"),
        "{}",
        String::from_utf8_lossy(&rejected_delete)
    );

    let max_offset = usize::MAX.to_string();
    let rejected_offset = send_resp(
        address,
        &[
            b"TSELECT",
            b"*",
            b"FROM",
            b"bounded",
            b"LIMIT",
            b"1",
            b"OFFSET",
            max_offset.as_bytes(),
        ],
    )
    .await;
    assert!(
        String::from_utf8_lossy(&rejected_offset).contains("query candidate limit exceeded (2)"),
        "{}",
        String::from_utf8_lossy(&rejected_offset)
    );

    for (id, expected) in [
        (b"1".as_slice(), b"safe".as_slice()),
        (b"2", b"safe"),
        (b"3", b"old"),
    ] {
        let row = send_resp(
            address,
            &[
                b"TSELECT", b"state", b"FROM", b"bounded", b"WHERE", b"id", b"=", id,
            ],
        )
        .await;
        assert!(row.windows(expected.len()).any(|value| value == expected));
        assert!(!row.windows(3).any(|value| value == b"bad"));
    }

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_response_writer_is_evicted_and_connection_capacity_recovers() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.durability.policy = lux::DurabilityPolicy::Ephemeral;
    config.max_resp_request = 32 * 1024 * 1024;
    config.max_body = 32 * 1024 * 1024;
    config.limits.max_request_buffer_bytes = 32 * 1024 * 1024;
    config.limits.max_resp_response = 32 * 1024 * 1024;
    config.limits.max_resp_connections = 1;
    config.limits.write_timeout = Duration::from_millis(100);
    let (handle, address, _) = start_server(config).await;

    let value = vec![b'x'; 24 * 1024 * 1024];
    assert_eq!(
        send_resp(address, &[b"SET", b"large", &value]).await,
        b"+OK\r\n"
    );

    let mut stalled = TcpStream::connect(address).await.unwrap();
    stalled
        .write_all(&resp_command(&[b"GET", b"large"]))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(750)).await;

    let mut recovered = false;
    for _ in 0..20 {
        if send_resp(address, &[b"PING"]).await == b"+PONG\r\n" {
            recovered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        recovered,
        "write timeout did not release connection capacity"
    );
    let info = String::from_utf8_lossy(&send_resp(address, &[b"INFO"]).await).into_owned();
    assert!(info.contains("connection_timeouts:1"), "{info}");
    drop(stalled);

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stalled_responses_share_a_process_budget_and_recover() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.durability.policy = lux::DurabilityPolicy::Ephemeral;
    config.max_resp_request = 16 * 1024 * 1024;
    config.max_body = 16 * 1024 * 1024;
    config.limits.max_request_buffer_bytes = 16 * 1024 * 1024;
    config.limits.max_resp_response = 16 * 1024 * 1024;
    config.limits.max_response_buffer_bytes = 16 * 1024 * 1024;
    config.limits.max_resp_connections = 3;
    config.limits.write_timeout = Duration::from_millis(500);
    let (handle, address, _) = start_server(config).await;

    let value = vec![b'x'; 12 * 1024 * 1024];
    assert_eq!(
        send_resp(address, &[b"SET", b"large", &value]).await,
        b"+OK\r\n"
    );

    let mut first = TcpStream::connect(address).await.unwrap();
    first
        .write_all(&resp_command(&[b"GET", b"large"]))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut second = TcpStream::connect(address).await.unwrap();
    second
        .write_all(&resp_command(&[b"GET", b"large"]))
        .await
        .unwrap();
    let second_response = read_quiet(&mut second).await;
    assert!(
        second_response.is_empty()
            || String::from_utf8_lossy(&second_response).contains("response exceeds maximum"),
        "a second retained response escaped the shared process budget: {}",
        String::from_utf8_lossy(&second_response)
    );
    let info = String::from_utf8_lossy(&send_resp(address, &[b"INFO"]).await).into_owned();
    assert!(info.contains("rejected_response_buffers:1"), "{info}");

    drop(first);
    drop(second);
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(send_resp(address, &[b"PING"]).await, b"+PONG\r\n");

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replacing_and_removing_live_subscriptions_recovers_capacity() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.http_port = free_port();
    config.limits.max_live_subscriptions = 1;
    let (handle, resp_address, http_address) = start_server(config).await;
    let address = http_address.unwrap();
    let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{address}/live"))
        .await
        .unwrap();

    for pattern in ["one", "two"] {
        socket
            .send(Message::Text(format!(
                r#"{{"type":"live.subscribe","id":"same","spec":{{"kind":"key","pattern":"{pattern}"}}}}"#
            )))
            .await
            .unwrap();
        let response = socket.next().await.unwrap().unwrap().into_text().unwrap();
        assert!(response.contains("live.subscribed"), "{response}");
    }
    socket
        .send(Message::Text(
            r#"{"type":"live.subscribe","id":"same","spec":{"kind":"unsupported"}}"#.to_string(),
        ))
        .await
        .unwrap();
    let response = socket.next().await.unwrap().unwrap().into_text().unwrap();
    assert!(response.contains("INVALID_SPEC"), "{response}");
    assert_eq!(
        send_resp(resp_address, &[b"SET", b"two", b"value"]).await,
        b"+OK\r\n"
    );
    let response = socket.next().await.unwrap().unwrap().into_text().unwrap();
    assert!(response.contains("\"key\":\"two\""), "{response}");

    socket
        .send(Message::Text(
            r#"{"type":"live.subscribe","id":"other","spec":{"kind":"key","pattern":"three"}}"#
                .to_string(),
        ))
        .await
        .unwrap();
    let response = socket.next().await.unwrap().unwrap().into_text().unwrap();
    assert!(response.contains("LIMIT_EXCEEDED"), "{response}");

    socket
        .send(Message::Text(
            r#"{"type":"live.unsubscribe","id":"same"}"#.to_string(),
        ))
        .await
        .unwrap();
    let response = socket.next().await.unwrap().unwrap().into_text().unwrap();
    assert!(response.contains("live.unsubscribed"), "{response}");
    socket
        .send(Message::Text(
            r#"{"type":"live.subscribe","id":"other","spec":{"kind":"key","pattern":"three"}}"#
                .to_string(),
        ))
        .await
        .unwrap();
    let response = socket.next().await.unwrap().unwrap().into_text().unwrap();
    assert!(response.contains("live.subscribed"), "{response}");

    drop(socket);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_fanout_delivers_once_per_subscription_without_quadratic_duplicates() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.http_port = free_port();
    let (handle, resp_address, http_address) = start_server(config).await;
    let address = http_address.unwrap();
    let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{address}/live"))
        .await
        .unwrap();

    for id in ["first", "second"] {
        socket
            .send(Message::Text(format!(
                r#"{{"type":"live.subscribe","id":"{id}","spec":{{"kind":"key","pattern":"shared"}}}}"#
            )))
            .await
            .unwrap();
        let response = socket.next().await.unwrap().unwrap().into_text().unwrap();
        assert!(response.contains("live.subscribed"), "{response}");
    }

    assert_eq!(
        send_resp(resp_address, &[b"SET", b"shared", b"value"]).await,
        b"+OK\r\n"
    );
    let mut delivered = std::collections::HashSet::new();
    for _ in 0..2 {
        let response = socket.next().await.unwrap().unwrap().into_text().unwrap();
        let response: serde_json::Value = serde_json::from_str(&response).unwrap();
        delivered.insert(response["id"].as_str().unwrap().to_string());
    }
    assert_eq!(
        delivered,
        ["first".to_string(), "second".to_string()].into()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), socket.next())
            .await
            .is_err(),
        "one broker event was delivered more than once per subscription"
    );

    drop(socket);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retained_subscription_bytes_are_bounded_and_released() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.max_resp_request = 80;
    config.max_body = 320;
    config.http_port = free_port();
    // The incoming frame and retained definition coexist while subscription
    // ownership transfers; this test targets the per-socket retained ceiling.
    config.limits.max_request_buffer_bytes = 640;
    config.limits.max_resp_subscriptions = 10;
    config.limits.max_live_subscriptions = 10;
    let (handle, address, http_address) = start_server(config).await;

    let first = "a".repeat(50);
    let second = "b".repeat(50);
    let mut resp = TcpStream::connect(address).await.unwrap();
    resp.write_all(&resp_command(&[b"SUBSCRIBE", first.as_bytes()]))
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&read_quiet(&mut resp).await).contains("subscribe"));
    resp.write_all(&resp_command(&[b"SUBSCRIBE", second.as_bytes()]))
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&read_quiet(&mut resp).await)
        .contains("subscription bytes limit exceeded"));
    resp.write_all(&resp_command(&[b"UNSUBSCRIBE", first.as_bytes()]))
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&read_quiet(&mut resp).await).contains("unsubscribe"));
    resp.write_all(&resp_command(&[b"SUBSCRIBE", second.as_bytes()]))
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&read_quiet(&mut resp).await).contains("subscribe"));

    let http_address = http_address.unwrap();
    let (mut live, _) = tokio_tungstenite::connect_async(format!("ws://{http_address}/live"))
        .await
        .unwrap();
    let first_pattern = "c".repeat(120);
    let second_pattern = "d".repeat(120);
    for (id, pattern, expected) in [
        ("first", &first_pattern, "live.subscribed"),
        ("second", &second_pattern, "definitions exceed maximum"),
    ] {
        live.send(Message::Text(format!(
            r#"{{"type":"live.subscribe","id":"{id}","spec":{{"kind":"key","pattern":"{pattern}"}}}}"#
        )))
        .await
        .unwrap();
        let response = live.next().await.unwrap().unwrap().into_text().unwrap();
        assert!(response.contains(expected), "{response}");
    }
    live.send(Message::Text(
        r#"{"type":"live.unsubscribe","id":"first"}"#.to_string(),
    ))
    .await
    .unwrap();
    let _ = live.next().await.unwrap().unwrap();
    live.send(Message::Text(format!(
        r#"{{"type":"live.subscribe","id":"second","spec":{{"kind":"key","pattern":"{second_pattern}"}}}}"#
    )))
    .await
    .unwrap();
    let response = live.next().await.unwrap().unwrap().into_text().unwrap();
    assert!(response.contains("live.subscribed"), "{response}");

    drop(resp);
    drop(live);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn process_subscription_count_and_bytes_are_shared_and_recover() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.max_resp_request = 80;
    config.max_body = 80;
    config.limits.max_request_buffer_bytes = 120;
    config.limits.max_resp_subscriptions = 10;
    config.limits.max_subscriptions = 10;
    let (handle, address, _) = start_server(config).await;

    let name = "x".repeat(30);
    let mut first = TcpStream::connect(address).await.unwrap();
    first
        .write_all(&resp_command(&[b"SUBSCRIBE", name.as_bytes()]))
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&read_quiet(&mut first).await).contains("subscribe"));

    let second_name = "y".repeat(30);
    let mut second = TcpStream::connect(address).await.unwrap();
    second
        .write_all(&resp_command(&[b"SUBSCRIBE", second_name.as_bytes()]))
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&read_quiet(&mut second).await).contains("subscribe"));

    let third_name = "z".repeat(30);
    let mut third = TcpStream::connect(address).await.unwrap();
    third
        .write_all(&resp_command(&[b"SUBSCRIBE", third_name.as_bytes()]))
        .await
        .unwrap();
    let rejected = String::from_utf8_lossy(&read_quiet(&mut third).await).into_owned();
    assert!(
        rejected.contains("process subscription capacity exhausted"),
        "{rejected}"
    );

    drop(first);
    tokio::time::sleep(Duration::from_millis(25)).await;
    third
        .write_all(&resp_command(&[b"SUBSCRIBE", third_name.as_bytes()]))
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&read_quiet(&mut third).await).contains("subscribe"));

    drop(second);
    drop(third);
    tokio::time::sleep(Duration::from_millis(25)).await;
    let info = String::from_utf8_lossy(&send_resp(address, &[b"INFO"]).await).into_owned();
    assert!(info.contains("network_subscriptions:0"), "{info}");
    assert!(info.contains("max_subscriptions:10"), "{info}");

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn process_subscription_count_is_shared_by_resp_and_live() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.http_port = free_port();
    config.limits.max_subscriptions = 2;
    let (handle, address, http_address) = start_server(config).await;

    let mut resp = TcpStream::connect(address).await.unwrap();
    resp.write_all(&resp_command(&[b"SUBSCRIBE", b"events"]))
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&read_quiet(&mut resp).await).contains("subscribe"));

    let (mut live, _) =
        tokio_tungstenite::connect_async(format!("ws://{}/live", http_address.unwrap()))
            .await
            .unwrap();
    live.send(Message::Text(
        r#"{"type":"live.subscribe","id":"first","spec":{"kind":"key","pattern":"one"}}"#
            .to_string(),
    ))
    .await
    .unwrap();
    assert!(live
        .next()
        .await
        .unwrap()
        .unwrap()
        .into_text()
        .unwrap()
        .contains("live.subscribed"));

    live.send(Message::Text(
        r#"{"type":"live.subscribe","id":"second","spec":{"kind":"key","pattern":"two"}}"#
            .to_string(),
    ))
    .await
    .unwrap();
    let rejected = live.next().await.unwrap().unwrap().into_text().unwrap();
    assert!(
        rejected.contains("process subscription capacity exhausted"),
        "{rejected}"
    );

    live.send(Message::Text(
        r#"{"type":"live.unsubscribe","id":"first"}"#.to_string(),
    ))
    .await
    .unwrap();
    let _ = live.next().await.unwrap().unwrap();
    live.send(Message::Text(
        r#"{"type":"live.subscribe","id":"second","spec":{"kind":"key","pattern":"two"}}"#
            .to_string(),
    ))
    .await
    .unwrap();
    assert!(live
        .next()
        .await
        .unwrap()
        .unwrap()
        .into_text()
        .unwrap()
        .contains("live.subscribed"));

    drop(resp);
    drop(live);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_exec_subscription_session_is_reclaimed_after_response() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.http_port = free_port();
    let (handle, resp_address, http_address) = start_server(config).await;
    let http_address = http_address.unwrap();

    let body = br#"{"command":["KSUB","orphan:*"]}"#;
    let mut request = format!(
        "POST /v1/exec HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    let response = send_http(http_address, request).await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    assert!(String::from_utf8_lossy(&response).contains("ksub"));

    assert_eq!(
        send_resp(resp_address, &[b"SET", b"orphan:key", b"value"]).await,
        b"+OK\r\n"
    );
    let info = send_resp(resp_address, &[b"INFO"]).await;
    let info = String::from_utf8_lossy(&info);
    assert!(info.contains("key_events_enqueued:0\r\n"), "{info}");

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_table_snapshots_inherit_the_http_row_ceiling() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.http_port = free_port();
    config.max_rows = Some(2);
    config.limits.max_query_candidates = 10;
    let (handle, address, http_address) = start_server(config).await;

    assert_eq!(
        send_resp(address, &[b"TCREATE", b"live_rows", b"id INT PRIMARY KEY"]).await,
        b"+OK\r\n"
    );
    for id in [b"1".as_slice(), b"2", b"3"] {
        assert!(send_resp(address, &[b"TINSERT", b"live_rows", b"id", id])
            .await
            .starts_with(b":"));
    }

    let address = http_address.unwrap();
    let (mut live, _) = tokio_tungstenite::connect_async(format!("ws://{address}/live"))
        .await
        .unwrap();
    live.send(Message::Text(
        r#"{"type":"live.subscribe","id":"rows","spec":{"kind":"table","table":"live_rows"}}"#
            .to_string(),
    ))
    .await
    .unwrap();
    let subscribed = live.next().await.unwrap().unwrap().into_text().unwrap();
    assert!(subscribed.contains("live.subscribed"), "{subscribed}");
    let snapshot = live.next().await.unwrap().unwrap().into_text().unwrap();
    let snapshot: serde_json::Value = serde_json::from_str(&snapshot).unwrap();
    assert_eq!(snapshot["event"]["rows"].as_array().map(Vec::len), Some(2));

    drop(live);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_query_state_is_process_bounded_and_failed_setup_recovers_capacity() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.http_port = free_port();
    config.max_resp_request = 1_024;
    config.max_body = 1_024;
    config.limits.max_request_buffer_bytes = 2_048;
    let (handle, address, http_address) = start_server(config).await;

    assert_eq!(
        send_resp(
            address,
            &[b"TCREATE", b"bounded_live", b"id INT PRIMARY KEY, body STR"]
        )
        .await,
        b"+OK\r\n"
    );
    let body = vec![b'x'; 700];
    for id in [b"1".as_slice(), b"2"] {
        assert!(send_resp(
            address,
            &[b"TINSERT", b"bounded_live", b"id", id, b"body", &body]
        )
        .await
        .starts_with(b":"));
    }

    let http_address = http_address.unwrap();
    let (mut live, _) = tokio_tungstenite::connect_async(format!("ws://{http_address}/live"))
        .await
        .unwrap();
    live.send(Message::Text(
        r#"{"type":"live.subscribe","id":"too-large","spec":{"kind":"table","table":"bounded_live"}}"#
            .to_string(),
    ))
    .await
    .unwrap();
    let rejected = live.next().await.unwrap().unwrap().into_text().unwrap();
    assert!(
        rejected.contains("process live query state capacity exhausted"),
        "{rejected}"
    );
    let info = String::from_utf8_lossy(&send_resp(address, &[b"INFO"]).await).into_owned();
    assert!(info.contains("network_subscriptions:0"), "{info}");

    assert!(send_resp(
        address,
        &[
            b"TDELETE",
            b"FROM",
            b"bounded_live",
            b"WHERE",
            b"id",
            b"=",
            b"2"
        ]
    )
    .await
    .starts_with(b":"));
    live.send(Message::Text(
        r#"{"type":"live.subscribe","id":"fits","spec":{"kind":"table","table":"bounded_live"}}"#
            .to_string(),
    ))
    .await
    .unwrap();
    let subscribed = live.next().await.unwrap().unwrap().into_text().unwrap();
    assert!(subscribed.contains("live.subscribed"), "{subscribed}");
    let snapshot = live.next().await.unwrap().unwrap().into_text().unwrap();
    assert!(snapshot.contains("\"kind\":\"snapshot\""), "{snapshot}");

    assert!(send_resp(
        address,
        &[b"TINSERT", b"bounded_live", b"id", b"2", b"body", &body]
    )
    .await
    .starts_with(b":"));
    let terminal = tokio::time::timeout(Duration::from_secs(2), live.next())
        .await
        .expect("live state growth beyond the process budget did not terminate the socket");
    assert!(
        terminal.is_none()
            || matches!(terminal, Some(Ok(Message::Close(_))))
            || matches!(terminal, Some(Err(_))),
        "oversized state growth emitted a data event instead of failing closed"
    );
    for _ in 0..20 {
        let info = String::from_utf8_lossy(&send_resp(address, &[b"INFO"]).await).into_owned();
        if info.contains("network_subscriptions:0") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let info = String::from_utf8_lossy(&send_resp(address, &[b"INFO"]).await).into_owned();
    assert!(info.contains("network_subscriptions:0"), "{info}");

    assert!(send_resp(
        address,
        &[
            b"TDELETE",
            b"FROM",
            b"bounded_live",
            b"WHERE",
            b"id",
            b"=",
            b"2"
        ]
    )
    .await
    .starts_with(b":"));
    let (mut recovered, _) = tokio_tungstenite::connect_async(format!("ws://{http_address}/live"))
        .await
        .unwrap();
    recovered
        .send(Message::Text(
            r#"{"type":"live.subscribe","id":"recovered","spec":{"kind":"table","table":"bounded_live"}}"#
                .to_string(),
        ))
        .await
        .unwrap();
    let subscribed = recovered
        .next()
        .await
        .unwrap()
        .unwrap()
        .into_text()
        .unwrap();
    assert!(subscribed.contains("live.subscribed"), "{subscribed}");

    drop(recovered);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_messages_obey_the_shared_request_budget_and_recover() {
    let root = tempfile::tempdir().unwrap();
    let mut config = test_config(root.path());
    config.http_port = free_port();
    config.max_resp_request = 2_048;
    config.max_body = 2_048;
    config.limits.max_request_buffer_bytes = 2_048;
    let (handle, _, http_address) = start_server(config).await;
    let http_address = http_address.unwrap();

    let mut held = TcpStream::connect(http_address).await.unwrap();
    let head = b"POST /v1/exec HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1800\r\n\r\n";
    held.write_all(head).await.unwrap();
    held.write_all(&vec![b'x'; 1_600]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(25)).await;

    let (mut live, _) = tokio_tungstenite::connect_async(format!("ws://{http_address}/live"))
        .await
        .unwrap();
    live.send(Message::Text(
        serde_json::json!({
            "type":"live.subscribe",
            "id":"pressure",
            "spec":{"kind":"key","pattern":"key"},
            "padding":"x".repeat(600),
        })
        .to_string(),
    ))
    .await
    .unwrap();
    let rejected = live.next().await.unwrap().unwrap().into_text().unwrap();
    assert!(
        rejected.contains("request buffer capacity exhausted"),
        "{rejected}"
    );
    drop(live);
    drop(held);

    let (mut recovered, _) = tokio_tungstenite::connect_async(format!("ws://{http_address}/live"))
        .await
        .unwrap();
    recovered
        .send(Message::Text(
            r#"{"type":"live.subscribe","id":"recovered","spec":{"kind":"key","pattern":"key"}}"#
                .to_string(),
        ))
        .await
        .unwrap();
    let subscribed = recovered
        .next()
        .await
        .unwrap()
        .unwrap()
        .into_text()
        .unwrap();
    assert!(subscribed.contains("live.subscribed"), "{subscribed}");

    handle.shutdown_and_wait().await.unwrap();
}
