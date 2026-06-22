use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[path = "support/universal_client.rs"]
mod universal_client;

use universal_client::UniversalClient;

fn resp_cmd(args: &[&str]) -> Vec<u8> {
    let mut buf = format!("*{}\r\n", args.len());
    for arg in args {
        buf.push_str(&format!("${}\r\n{}\r\n", arg.len(), arg));
    }
    buf.into_bytes()
}

fn connect(addr: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect(addr).unwrap();
    stream.set_nodelay(true).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    stream
}

fn send_and_read(stream: &mut TcpStream, args: &[&str]) -> String {
    stream.write_all(&resp_cmd(args)).unwrap();
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                data.extend_from_slice(&buf[..n]);
                if data.ends_with(b"\r\n") {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => panic!("failed reading RESP response: {e}"),
        }
    }
    String::from_utf8_lossy(&data).to_string()
}

fn assert_resp_simple_ok(resp: &[u8]) {
    assert_eq!(resp, b"+OK\r\n", "expected +OK, got {resp:?}");
}

fn assert_resp_int_eq(resp: &[u8], expected: i64) {
    assert_eq!(
        universal_client::parse_resp_int_frame(resp),
        expected,
        "unexpected int: {resp:?}"
    );
}

fn assert_resp_bulk_eq(resp: &[u8], expected: &[u8]) {
    assert_eq!(
        universal_client::parse_resp_bulk(resp),
        Some(expected.to_vec())
    );
}

fn send_only(stream: &mut TcpStream, args: &[&str]) {
    stream.write_all(&resp_cmd(args)).unwrap();
}

fn read_with_timeout(stream: &mut TcpStream, timeout_ms: u64) -> String {
    stream
        .set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .unwrap();
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                data.extend_from_slice(&buf[..n]);
                if data.ends_with(b"\r\n") {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => panic!("failed reading RESP response: {e}"),
        }
    }
    String::from_utf8_lossy(&data).to_string()
}

fn read_exact_responses(stream: &mut TcpStream, expected: usize) -> Vec<u8> {
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    let mut responses = 0usize;
    while responses < expected {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                data.extend_from_slice(&buf[..n]);
                responses = data.windows(2).filter(|w| *w == b"\r\n").count();
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => panic!("failed reading RESP pipeline response: {e}"),
        }
    }
    data
}

fn info_usize(info: &str, field: &str) -> usize {
    let prefix = format!("{field}:");
    info.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or_else(|| panic!("missing numeric INFO field {field}: {info:?}"))
}

fn append_corrupt_wal_frames(storage_dir: &std::path::Path) {
    // Append a full-length frame with a bad checksum so startup can skip it
    // and still report the corruption through the public callback.
    for entry in std::fs::read_dir(storage_dir).unwrap() {
        let entry = entry.unwrap();
        if !entry.file_type().unwrap().is_dir() {
            continue;
        }
        let wal_path = entry.path().join("wal.lux");
        if !wal_path.exists() {
            continue;
        }
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(wal_path)
            .unwrap();
        file.write_all(&50u32.to_le_bytes()).unwrap();
        file.write_all(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        file.write_all(&[0xFF; 46]).unwrap();
        file.flush().unwrap();
    }
}

#[tokio::test]
async fn run_with_config_rejects_unauthenticated_non_loopback_listener() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        bind_host: "0.0.0.0".to_string(),
        port: 0,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };

    let err = match lux::run_with_config(cfg).await {
        Ok(handle) => {
            handle.shutdown_and_wait().await.unwrap();
            panic!("run_with_config should reject unauthenticated non-loopback listeners");
        }
        Err(err) => err,
    };
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
}

#[tokio::test]
async fn run_with_config_rejects_invalid_shard_counts() {
    for shards in [0, 65_537] {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = lux::ServerConfig {
            enable_resp: false,
            shards,
            data_dir: tmp.path().display().to_string(),
            ..Default::default()
        };

        let err = match lux::run_with_config(cfg).await {
            Ok(handle) => {
                handle.shutdown_and_wait().await.unwrap();
                panic!("run_with_config should reject shard count {shards}");
            }
            Err(err) => err,
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}

#[tokio::test]
async fn embedded_client_rejects_invalid_utf8_key_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        enable_resp: false,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg).await.unwrap();
    let client = handle.client();

    let invalid_key = [0xff];
    let err = client
        .execute_bytes(&[b"GET", &invalid_key])
        .await
        .unwrap_err();
    assert!(err.to_string().contains("invalid UTF-8"));

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn universal_client_runs_strings_on_resp_and_embedded() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        port: 0,
        shards: 4,
        password: String::new(),
        require_auth: false,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg).await.unwrap();
    let embedded = UniversalClient::embedded(handle.client());
    let addr = handle.local_addr().unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let resp = UniversalClient::resp(addr);

    for (client, prefix) in [(&embedded, "uni:embedded"), (&resp, "uni:resp")] {
        let key = format!("{prefix}:k");
        let counter = format!("{prefix}:counter");
        assert!(client.set(&key, "v1").await);
        assert_eq!(client.get(&key).await, Some(b"v1".to_vec()));
        assert!(!client.setnx(&key, "ignored").await);
        assert!(client.setnx(&counter, "10").await);
        assert_eq!(client.incrby(&counter, 5).await, 15);
        assert_eq!(client.append(&key, ":tail").await, 7);
        assert_eq!(client.strlen(&key).await, 7);
        assert_eq!(client.get(&key).await, Some(b"v1:tail".to_vec()));
    }

    drop(resp);
    drop(embedded);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn universal_client_runs_core_surface_on_resp_and_embedded() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        port: 0,
        shards: 4,
        password: String::new(),
        require_auth: false,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg).await.unwrap();
    let embedded = UniversalClient::embedded(handle.client());
    let addr = handle.local_addr().unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let resp = UniversalClient::resp(addr);

    for (client, prefix) in [(&embedded, "u2:embedded"), (&resp, "u2:resp")] {
        let skey = format!("{prefix}:str");
        let lkey = format!("{prefix}:list");
        let hkey = format!("{prefix}:hash");
        let setkey = format!("{prefix}:set");
        let zkey = format!("{prefix}:zset");
        let xkey = format!("{prefix}:stream");

        assert_resp_simple_ok(
            &client
                .execute_bytes(&[b"SET", skey.as_bytes(), b"hello"])
                .await,
        );
        assert_resp_bulk_eq(
            &client.execute_bytes(&[b"GET", skey.as_bytes()]).await,
            b"hello",
        );
        assert_resp_int_eq(
            &client
                .execute_bytes(&[b"APPEND", skey.as_bytes(), b":tail"])
                .await,
            10,
        );
        assert_resp_int_eq(
            &client.execute_bytes(&[b"STRLEN", skey.as_bytes()]).await,
            10,
        );
        assert_resp_int_eq(
            &client.execute_bytes(&[b"EXISTS", skey.as_bytes()]).await,
            1,
        );

        assert_resp_int_eq(
            &client
                .execute_bytes(&[b"LPUSH", lkey.as_bytes(), b"v1", b"v2"])
                .await,
            2,
        );
        assert_resp_int_eq(&client.execute_bytes(&[b"LLEN", lkey.as_bytes()]).await, 2);
        assert_resp_bulk_eq(
            &client.execute_bytes(&[b"LPOP", lkey.as_bytes()]).await,
            b"v2",
        );

        assert_resp_int_eq(
            &client
                .execute_bytes(&[b"HSET", hkey.as_bytes(), b"f1", b"one"])
                .await,
            1,
        );
        assert_resp_bulk_eq(
            &client
                .execute_bytes(&[b"HGET", hkey.as_bytes(), b"f1"])
                .await,
            b"one",
        );

        assert_resp_int_eq(
            &client
                .execute_bytes(&[b"SADD", setkey.as_bytes(), b"m1", b"m2"])
                .await,
            2,
        );
        assert_resp_int_eq(
            &client
                .execute_bytes(&[b"SISMEMBER", setkey.as_bytes(), b"m1"])
                .await,
            1,
        );

        assert_resp_int_eq(
            &client
                .execute_bytes(&[b"ZADD", zkey.as_bytes(), b"1", b"a"])
                .await,
            1,
        );
        assert_resp_bulk_eq(
            &client
                .execute_bytes(&[b"ZSCORE", zkey.as_bytes(), b"a"])
                .await,
            b"1",
        );

        let xadd_resp = client
            .execute_bytes(&[b"XADD", xkey.as_bytes(), b"*", b"f", b"v"])
            .await;
        assert!(
            universal_client::parse_resp_bulk(&xadd_resp).is_some(),
            "XADD should return entry id, got {xadd_resp:?}"
        );
        assert_resp_int_eq(&client.execute_bytes(&[b"XLEN", xkey.as_bytes()]).await, 1);

        assert_resp_int_eq(
            &client
                .execute_bytes(&[b"EXPIRE", skey.as_bytes(), b"60"])
                .await,
            1,
        );
        let ttl = universal_client::parse_resp_int_frame(
            &client.execute_bytes(&[b"TTL", skey.as_bytes()]).await,
        );
        assert!(ttl > 0, "TTL should be positive, got {ttl}");

        assert_resp_int_eq(
            &client
                .execute_bytes(&[b"DEL", skey.as_bytes(), lkey.as_bytes()])
                .await,
            2,
        );
    }

    drop(resp);
    drop(embedded);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn embedded_client_executes_commands_without_resp_listener() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        enable_resp: false,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg).await.unwrap();
    assert!(handle.local_addr().is_none());
    let client = handle.client();

    let set = client.set("embedded:key", "value").await.unwrap();
    assert!(set);

    let get = client.get("embedded:key").await.unwrap();
    assert_eq!(get, Some(bytes::Bytes::from_static(b"value")));

    drop(client);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn resp_pipelined_hget_returns_all_responses() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        port: 0,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg).await.unwrap();
    let addr = handle.local_addr().unwrap();
    tokio::task::spawn_blocking(move || {
        let mut conn = connect(addr);

        assert_eq!(
            send_and_read(&mut conn, &["HSET", "bench:hash", "field:1", "value"]),
            ":1\r\n"
        );

        let mut pipeline = Vec::new();
        for _ in 0..50 {
            pipeline.extend_from_slice(&resp_cmd(&["HGET", "bench:hash", "field:1"]));
        }
        conn.write_all(&pipeline).unwrap();
        let data = read_exact_responses(&mut conn, 50);
        let text = String::from_utf8_lossy(&data);
        assert_eq!(
            text.matches("$5\r\nvalue\r\n").count(),
            50,
            "pipelined HGET returned incomplete data: {text:?}"
        );
    })
    .await
    .unwrap();

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn embedded_client_rejects_empty_and_subscription_control_execute() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        enable_resp: false,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg).await.unwrap();
    let client = handle.client();

    assert!(matches!(
        client.execute_bytes(&[]).await,
        Err(lux::LuxError::InvalidCommand(_))
    ));
    assert!(matches!(
        client.execute("SUBSCRIBE", &["events"]).await,
        Err(lux::LuxError::Unsupported(_))
    ));

    drop(client);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn embedded_pubsub_receives_published_messages() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        enable_resp: false,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg).await.unwrap();
    let client = handle.client();
    let mut sub = client.subscribe("events");

    let published = client
        .execute("PUBLISH", &["events", "hello"])
        .await
        .unwrap();
    assert_eq!(&published[..], b":1\r\n");

    let message = tokio::time::timeout(Duration::from_secs(1), sub.recv())
        .await
        .expect("pubsub message should arrive")
        .unwrap();
    assert_eq!(message.kind, lux::EmbeddedMessageKind::PubSub);
    assert_eq!(message.channel, "events");
    assert_eq!(&message.payload[..], b"hello");
    assert_eq!(message.pattern, None);

    drop(sub);
    drop(client);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn embedded_write_resp_read_and_inverse() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        port: 0,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };
    let handle = lux::run_with_config(cfg).await.unwrap();
    let client = handle.client();
    let addr = handle.local_addr().unwrap();

    client.set("cross:key:a", "from-embedded").await.unwrap();

    tokio::task::spawn_blocking(move || {
        let mut conn = connect(addr);
        let resp = send_and_read(&mut conn, &["GET", "cross:key:a"]);
        assert_eq!(resp, "$13\r\nfrom-embedded\r\n");
        let set_resp = send_and_read(&mut conn, &["SET", "cross:key:b", "from-resp"]);
        assert_eq!(set_resp, "+OK\r\n");
    })
    .await
    .unwrap();

    let val = client.get("cross:key:b").await.unwrap();
    assert_eq!(val, Some(bytes::Bytes::from_static(b"from-resp")));

    drop(client);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn embedded_expire_resp_ttl_and_inverse() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        port: 0,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };
    let handle = lux::run_with_config(cfg).await.unwrap();
    let client = handle.client();
    let addr = handle.local_addr().unwrap();

    client.set("cross:ttl:a", "v").await.unwrap();
    client
        .expire("cross:ttl:a", Duration::from_secs(10))
        .await
        .unwrap();

    tokio::task::spawn_blocking(move || {
        let mut conn = connect(addr);
        let ttl = send_and_read(&mut conn, &["TTL", "cross:ttl:a"]);
        assert!(ttl.starts_with(':'), "unexpected TTL response: {ttl:?}");
        let pexpire = send_and_read(&mut conn, &["PEXPIRE", "cross:ttl:a", "2000"]);
        assert_eq!(pexpire, ":1\r\n");
    })
    .await
    .unwrap();

    let pttl = client.pttl("cross:ttl:a").await.unwrap();
    assert!(
        (1..=2000).contains(&pttl),
        "unexpected PTTL after PEXPIRE: {pttl}"
    );

    drop(client);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn embedded_publish_resp_subscribe() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        port: 0,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };
    let handle = lux::run_with_config(cfg).await.unwrap();
    let client = handle.client();
    let addr = handle.local_addr().unwrap();

    let resp_side = tokio::task::spawn_blocking(move || {
        let mut sub = connect(addr);
        send_only(&mut sub, &["SUBSCRIBE", "cross:events"]);
        let _confirm = read_with_timeout(&mut sub, 500);
        read_with_timeout(&mut sub, 1500)
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    let published = client
        .execute("PUBLISH", &["cross:events", "hello-from-embedded"])
        .await
        .unwrap();
    assert_eq!(&published[..], b":1\r\n");

    let pushed = resp_side.await.unwrap();
    assert!(
        pushed.contains("hello-from-embedded"),
        "RESP subscriber did not receive embedded publish: {pushed:?}"
    );

    drop(client);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn resp_publish_embedded_subscribe() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        port: 0,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };
    let handle = lux::run_with_config(cfg).await.unwrap();
    let client = handle.client();
    let mut sub = client.subscribe("cross:events2");
    let addr = handle.local_addr().unwrap();

    let published = tokio::task::spawn_blocking(move || {
        let mut conn = connect(addr);
        send_and_read(&mut conn, &["PUBLISH", "cross:events2", "hello-from-resp"])
    })
    .await
    .unwrap();
    assert_eq!(published, ":1\r\n");

    let message = tokio::time::timeout(Duration::from_secs(1), sub.recv())
        .await
        .expect("embedded subscriber should receive RESP publish")
        .unwrap();
    assert_eq!(message.channel, "cross:events2");
    assert_eq!(&message.payload[..], b"hello-from-resp");

    drop(sub);
    drop(client);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn embedded_stream_write_resp_read() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        port: 0,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };
    let handle = lux::run_with_config(cfg).await.unwrap();
    let client = handle.client();
    let addr = handle.local_addr().unwrap();

    let add = client
        .execute(
            "XADD",
            &["cross:stream", "*", "field", "value-from-embedded"],
        )
        .await
        .unwrap();
    assert!(add.starts_with(b"$"), "unexpected XADD response: {add:?}");

    tokio::task::spawn_blocking(move || {
        let mut conn = connect(addr);
        let xrange = send_and_read(&mut conn, &["XRANGE", "cross:stream", "-", "+"]);
        assert!(
            xrange.contains("value-from-embedded"),
            "RESP XRANGE missing embedded entry: {xrange:?}"
        );
    })
    .await
    .unwrap();

    drop(client);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn resp_shard_batch_executes_increment_and_stream_writes() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        port: 0,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg).await.unwrap();
    let addr = handle.local_addr().unwrap();
    tokio::task::spawn_blocking(move || {
        let mut conn = connect(addr);

        let mut pipeline = Vec::new();
        for _ in 0..10 {
            pipeline.extend_from_slice(&resp_cmd(&["HINCRBY", "bench:hash", "counter", "1"]));
            pipeline.extend_from_slice(&resp_cmd(&["ZINCRBY", "bench:zset", "1", "member"]));
            pipeline.extend_from_slice(&resp_cmd(&["XADD", "bench:stream", "*", "field", "value"]));
        }
        conn.write_all(&pipeline).unwrap();
        let data = read_exact_responses(&mut conn, 50);
        let text = String::from_utf8_lossy(&data);
        assert!(
            !text.contains("unoptimized command in shard batch"),
            "shard batch fell through to the unoptimized error path: {text:?}"
        );
        assert!(
            text.contains(":10\r\n"),
            "batched HINCRBY replies should include the final counter: {text:?}"
        );
        assert!(
            text.contains("$2\r\n10\r\n"),
            "batched ZINCRBY replies should include the final score: {text:?}"
        );
    })
    .await
    .unwrap();

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn embedded_client_can_parse_typed_values() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        enable_resp: false,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg).await.unwrap();
    let client = handle.client();

    let set = client
        .execute_value("SET", &["typed:key", "typed-value"])
        .await
        .unwrap();
    assert_eq!(set, lux::EmbeddedValue::Simple("OK".to_string()));

    let get = client.execute_value("GET", &["typed:key"]).await.unwrap();
    assert_eq!(
        get,
        lux::EmbeddedValue::Bulk(bytes::Bytes::from_static(b"typed-value"))
    );

    let missing = client
        .execute_value("GET", &["typed:missing"])
        .await
        .unwrap();
    assert_eq!(missing, lux::EmbeddedValue::Nil);

    assert!(matches!(
        client.execute_value("NO_SUCH_COMMAND", &[]).await,
        Err(lux::LuxError::Command(_))
    ));

    drop(client);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn embedded_client_has_typed_convenience_methods() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        enable_resp: false,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg).await.unwrap();
    let client = handle.client();

    assert_eq!(
        client.set_value("typed:convenience", "1").await.unwrap(),
        lux::EmbeddedValue::Simple("OK".to_string())
    );
    assert_eq!(
        client.get_value("typed:convenience").await.unwrap(),
        lux::EmbeddedValue::Bulk(bytes::Bytes::from_static(b"1"))
    );
    assert_eq!(
        client.incr_value("typed:convenience").await.unwrap(),
        lux::EmbeddedValue::Int(2)
    );
    assert_eq!(
        client.del_value("typed:convenience").await.unwrap(),
        lux::EmbeddedValue::Int(1)
    );

    drop(client);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn embedded_client_exposes_typed_redis_command_facade() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        enable_resp: false,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg).await.unwrap();
    let client = handle.client();

    assert_eq!(client.ping().await.unwrap(), "PONG");
    assert!(client.set("native:string", b"hello").await.unwrap());
    assert_eq!(
        client.get("native:string").await.unwrap(),
        Some(bytes::Bytes::from_static(b"hello"))
    );
    let mut pipeline = lux::EmbeddedPipeline::new();
    pipeline
        .set(b"native:pipeline", b"queued")
        .get(b"native:pipeline")
        .setnx(b"native:pipeline", b"ignored");
    assert_eq!(
        client.execute_embedded_pipeline(&pipeline).await.unwrap(),
        vec![
            lux::EmbeddedValue::Simple("OK".to_string()),
            lux::EmbeddedValue::Bulk(bytes::Bytes::from_static(b"queued")),
            lux::EmbeddedValue::Int(0)
        ]
    );
    let mut discard_pipeline = lux::EmbeddedPipeline::new();
    discard_pipeline
        .set(b"native:pipeline:discard", b"queued")
        .get(b"native:pipeline:discard");
    client
        .execute_embedded_pipeline_discard(&discard_pipeline)
        .await
        .unwrap();
    assert_eq!(
        client.get("native:pipeline:discard").await.unwrap(),
        Some(bytes::Bytes::from_static(b"queued"))
    );
    let mut fast_pipeline = lux::EmbeddedPipeline::new();
    fast_pipeline
        .set(b"native:pipeline:ops", b"1")
        .incrby(b"native:pipeline:ops", 4)
        .strlen(b"native:pipeline:ops")
        .hset(b"native:pipeline:hash", b"field", b"value")
        .hget(b"native:pipeline:hash", b"field")
        .sadd(
            b"native:pipeline:set",
            vec![b"a".as_slice(), b"b".as_slice()],
        )
        .zadd(b"native:pipeline:zset", 1.5, b"member")
        .del(vec![b"native:pipeline:ops"]);
    assert_eq!(
        client
            .execute_embedded_pipeline(&fast_pipeline)
            .await
            .unwrap(),
        vec![
            lux::EmbeddedValue::Simple("OK".to_string()),
            lux::EmbeddedValue::Int(5),
            lux::EmbeddedValue::Int(1),
            lux::EmbeddedValue::Int(1),
            lux::EmbeddedValue::Bulk(bytes::Bytes::from_static(b"value")),
            lux::EmbeddedValue::Int(2),
            lux::EmbeddedValue::Int(1),
            lux::EmbeddedValue::Int(1),
        ]
    );
    let mut mset_pipeline = lux::EmbeddedPipeline::new();
    mset_pipeline
        .mset(vec![
            (b"native:pipeline:mset:a".as_slice(), b"one".as_slice()),
            (b"native:pipeline:mset:b".as_slice(), b"two".as_slice()),
            (b"native:pipeline:mset:c".as_slice(), b"three".as_slice()),
        ])
        .mset(vec![(
            b"native:pipeline:mset:b".as_slice(),
            b"overwritten".as_slice(),
        )]);
    assert_eq!(
        client
            .execute_embedded_pipeline(&mset_pipeline)
            .await
            .unwrap(),
        vec![
            lux::EmbeddedValue::Simple("OK".to_string()),
            lux::EmbeddedValue::Simple("OK".to_string()),
        ]
    );
    assert_eq!(
        client
            .mget(&[
                "native:pipeline:mset:a",
                "native:pipeline:mset:b",
                "native:pipeline:mset:c",
            ])
            .await
            .unwrap(),
        vec![
            Some(bytes::Bytes::from_static(b"one")),
            Some(bytes::Bytes::from_static(b"overwritten")),
            Some(bytes::Bytes::from_static(b"three")),
        ]
    );
    let mut mset_discard_pipeline = lux::EmbeddedPipeline::new();
    mset_discard_pipeline.mset(vec![
        (
            b"native:pipeline:mset:discard:a".as_slice(),
            b"one".as_slice(),
        ),
        (
            b"native:pipeline:mset:discard:b".as_slice(),
            b"two".as_slice(),
        ),
    ]);
    client
        .execute_embedded_pipeline_discard(&mset_discard_pipeline)
        .await
        .unwrap();
    assert_eq!(
        client
            .mget(&[
                "native:pipeline:mset:discard:a",
                "native:pipeline:mset:discard:b",
            ])
            .await
            .unwrap(),
        vec![
            Some(bytes::Bytes::from_static(b"one")),
            Some(bytes::Bytes::from_static(b"two")),
        ]
    );
    assert_eq!(client.append("native:string", " world").await.unwrap(), 11);
    assert_eq!(client.strlen("native:string").await.unwrap(), 11);
    assert_eq!(client.incr("native:counter").await.unwrap(), 1);
    assert_eq!(client.incrby("native:counter", 4).await.unwrap(), 5);
    assert!(client
        .set_options("native:nx", "first", lux::SetOptions::default().nx())
        .await
        .unwrap());
    assert!(!client
        .set_options("native:nx", "second", lux::SetOptions::default().nx())
        .await
        .unwrap());
    client
        .mset(&[("native:m1", "one"), ("native:m2", "two")])
        .await
        .unwrap();
    assert_eq!(
        client
            .mget(&["native:m1", "native:m2", "missing"])
            .await
            .unwrap(),
        vec![
            Some(bytes::Bytes::from_static(b"one")),
            Some(bytes::Bytes::from_static(b"two")),
            None
        ]
    );
    assert_eq!(client.del(&["native:string"]).await.unwrap(), 1);
    assert_eq!(
        client.key_type("native:m1").await.unwrap(),
        lux::RedisKeyType::String
    );

    assert_eq!(client.rpush("native:list", &["a", "b"]).await.unwrap(), 2);
    assert_eq!(
        client.lrange("native:list", 0, -1).await.unwrap(),
        vec![
            bytes::Bytes::from_static(b"a"),
            bytes::Bytes::from_static(b"b")
        ]
    );
    assert_eq!(
        client.lpop("native:list").await.unwrap(),
        Some(bytes::Bytes::from_static(b"a"))
    );

    assert_eq!(
        client.hset("native:hash", "field", "value").await.unwrap(),
        1
    );
    assert_eq!(
        client.hincrby("native:hash", "counter", 3).await.unwrap(),
        3
    );
    assert!(client.hexists("native:hash", "field").await.unwrap());
    assert_eq!(
        client.hget("native:hash", "field").await.unwrap(),
        Some(bytes::Bytes::from_static(b"value"))
    );

    assert_eq!(client.sadd("native:set", &["a", "b"]).await.unwrap(), 2);
    assert!(client.sismember("native:set", "a").await.unwrap());
    let mut members = client.smembers("native:set").await.unwrap();
    members.sort();
    assert_eq!(
        members,
        vec![
            bytes::Bytes::from_static(b"a"),
            bytes::Bytes::from_static(b"b")
        ]
    );

    assert_eq!(client.zadd("native:zset", 1.5, "a").await.unwrap(), 1);
    assert_eq!(client.zadd("native:zset", 2.5, "b").await.unwrap(), 1);
    assert_eq!(client.zcard("native:zset").await.unwrap(), 2);
    assert_eq!(client.zscore("native:zset", "b").await.unwrap(), Some(2.5));
    assert_eq!(
        client.zrange("native:zset", 0, -1).await.unwrap(),
        vec![
            bytes::Bytes::from_static(b"a"),
            bytes::Bytes::from_static(b"b")
        ]
    );
    assert_eq!(
        client
            .zrange_withscores("native:zset", 0, -1)
            .await
            .unwrap(),
        vec![
            lux::ScoredMember {
                member: bytes::Bytes::from_static(b"a"),
                score: 1.5,
            },
            lux::ScoredMember {
                member: bytes::Bytes::from_static(b"b"),
                score: 2.5,
            }
        ]
    );

    assert_eq!(
        client
            .geoadd(
                "native:geo",
                &[
                    lux::GeoMember {
                        longitude: 13.361389,
                        latitude: 38.115556,
                        member: "Palermo",
                    },
                    lux::GeoMember {
                        longitude: 15.087269,
                        latitude: 37.502669,
                        member: "Catania",
                    },
                ],
            )
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        client.geopos("native:geo", &["missing"]).await.unwrap(),
        vec![None]
    );
    assert!(client
        .geodist("native:geo", "Palermo", "Catania", lux::GeoUnit::Km)
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        client
            .xadd("native:stream", "1-0", &[("field", "value")])
            .await
            .unwrap(),
        "1-0"
    );

    drop(client);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn embedded_native_pipeline_matches_raw_pipeline_outputs_and_state() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        enable_resp: false,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg).await.unwrap();
    let native = handle.client();
    let raw = handle.client();

    let mut native_pipeline = lux::EmbeddedPipeline::new();
    native_pipeline
        .set(b"native:eq:string", b"1")
        .incrby(b"native:eq:string", 4)
        .get(b"native:eq:string")
        .hset(b"native:eq:hash", b"field", b"value")
        .hget(b"native:eq:hash", b"field")
        .sadd(b"native:eq:set", vec![b"a".as_slice(), b"b".as_slice()])
        .spop(b"native:eq:set")
        .zadd(b"native:eq:zset", 2.5, b"member")
        .lpush(b"native:eq:list", vec![b"a".as_slice()])
        .rpush(b"native:eq:list", vec![b"b".as_slice()])
        .lpop(b"native:eq:list")
        .rpop(b"native:eq:list")
        .del(vec![b"native:eq:string"]);
    let native_output = native
        .execute_embedded_pipeline(&native_pipeline)
        .await
        .unwrap();

    let raw_commands = vec![
        vec![b"SET".to_vec(), b"raw:eq:string".to_vec(), b"1".to_vec()],
        vec![b"INCRBY".to_vec(), b"raw:eq:string".to_vec(), b"4".to_vec()],
        vec![b"GET".to_vec(), b"raw:eq:string".to_vec()],
        vec![
            b"HSET".to_vec(),
            b"raw:eq:hash".to_vec(),
            b"field".to_vec(),
            b"value".to_vec(),
        ],
        vec![b"HGET".to_vec(), b"raw:eq:hash".to_vec(), b"field".to_vec()],
        vec![
            b"SADD".to_vec(),
            b"raw:eq:set".to_vec(),
            b"a".to_vec(),
            b"b".to_vec(),
        ],
        vec![b"SPOP".to_vec(), b"raw:eq:set".to_vec()],
        vec![
            b"ZADD".to_vec(),
            b"raw:eq:zset".to_vec(),
            b"2.5".to_vec(),
            b"member".to_vec(),
        ],
        vec![b"LPUSH".to_vec(), b"raw:eq:list".to_vec(), b"a".to_vec()],
        vec![b"RPUSH".to_vec(), b"raw:eq:list".to_vec(), b"b".to_vec()],
        vec![b"LPOP".to_vec(), b"raw:eq:list".to_vec()],
        vec![b"RPOP".to_vec(), b"raw:eq:list".to_vec()],
        vec![b"DEL".to_vec(), b"raw:eq:string".to_vec()],
    ];
    let raw_output = raw.pipeline_values(&raw_commands).await.unwrap();

    assert_eq!(native_output, raw_output);
    assert_eq!(
        native.hget("native:eq:hash", "field").await.unwrap(),
        raw.hget("raw:eq:hash", "field").await.unwrap()
    );
    assert_eq!(
        native.zscore("native:eq:zset", "member").await.unwrap(),
        raw.zscore("raw:eq:zset", "member").await.unwrap()
    );
    assert_eq!(
        native.exists(&["native:eq:string"]).await.unwrap(),
        raw.exists(&["raw:eq:string"]).await.unwrap()
    );

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn embedded_native_pipeline_matches_raw_for_modeled_command_groups() {
    let native_tmp = tempfile::tempdir().unwrap();
    let raw_tmp = tempfile::tempdir().unwrap();
    let native_handle = lux::run_with_config(lux::ServerConfig {
        enable_resp: false,
        shards: 4,
        data_dir: native_tmp.path().display().to_string(),
        ..Default::default()
    })
    .await
    .unwrap();
    let raw_handle = lux::run_with_config(lux::ServerConfig {
        enable_resp: false,
        shards: 4,
        data_dir: raw_tmp.path().display().to_string(),
        ..Default::default()
    })
    .await
    .unwrap();

    let native = native_handle.client();
    let raw = raw_handle.client();

    let mut native_pipeline = lux::EmbeddedPipeline::new();
    native_pipeline
        .ping()
        .publish(b"parity:events", b"payload")
        .set(b"parity:string", b"1")
        .getset(b"parity:string", b"2")
        .get(b"parity:string")
        .setnx(b"parity:string", b"ignored")
        .setex(b"parity:setex", 60, b"setex")
        .psetex(b"parity:psetex", 60_000, b"psetex")
        .mset(vec![
            (b"parity:mset:a".as_slice(), b"a".as_slice()),
            (b"parity:mset:b".as_slice(), b"b".as_slice()),
        ])
        .mget(vec![
            b"parity:mset:a".as_slice(),
            b"parity:mset:b".as_slice(),
            b"parity:mset:missing".as_slice(),
        ])
        .append(b"parity:string", b":tail")
        .strlen(b"parity:string")
        .incr(b"parity:counter")
        .incrby(b"parity:counter", 4)
        .decr(b"parity:counter")
        .decrby(b"parity:counter", 2)
        .exists(vec![b"parity:string".as_slice()])
        .expire(b"parity:string", 60)
        .persist(b"parity:string")
        .key_type(b"parity:string")
        .lpush(b"parity:list", vec![b"a".as_slice(), b"b".as_slice()])
        .rpush(b"parity:list", vec![b"c".as_slice()])
        .llen(b"parity:list")
        .lindex(b"parity:list", 1)
        .lrange(b"parity:list", 0, -1)
        .lpop(b"parity:list")
        .rpop(b"parity:list")
        .hset(b"parity:hash", b"f1", b"v1")
        .hset(b"parity:hash", b"f2", b"v2")
        .hincrby(b"parity:hash", b"counter", 3)
        .hmget(
            b"parity:hash",
            vec![b"f1".as_slice(), b"f2".as_slice(), b"missing".as_slice()],
        )
        .hexists(b"parity:hash", b"f1")
        .hlen(b"parity:hash")
        .hdel(b"parity:hash", vec![b"f2".as_slice()])
        .sadd(b"parity:set", vec![b"a".as_slice(), b"b".as_slice()])
        .sismember(b"parity:set", b"a")
        .scard(b"parity:set")
        .srem(b"parity:set", vec![b"b".as_slice()])
        .zadd(b"parity:zset", 1.5, b"a")
        .zadd(b"parity:zset", 2.5, b"b")
        .zscore(b"parity:zset", b"b")
        .zcard(b"parity:zset")
        .zcount(b"parity:zset", b"0", b"+inf")
        .zrange(b"parity:zset", 0, -1, false)
        .zrange(b"parity:zset", 0, -1, true)
        .zincrby(b"parity:zset", 1.0, b"a")
        .zrem(b"parity:zset", vec![b"b".as_slice()])
        .geoadd(
            b"parity:geo",
            vec![
                lux::GeoMember {
                    longitude: 13.361389,
                    latitude: 38.115556,
                    member: "Palermo",
                },
                lux::GeoMember {
                    longitude: 15.087269,
                    latitude: 37.502669,
                    member: "Catania",
                },
            ],
        )
        .geopos(b"parity:geo", vec![b"Palermo".as_slice()])
        .geodist(b"parity:geo", b"Palermo", b"Catania", lux::GeoUnit::Km)
        .xadd(
            b"parity:stream",
            b"1-0",
            vec![(b"field".as_slice(), b"value".as_slice())],
        );

    let raw_commands = vec![
        vec![b"PING".to_vec()],
        vec![
            b"PUBLISH".to_vec(),
            b"parity:events".to_vec(),
            b"payload".to_vec(),
        ],
        vec![b"SET".to_vec(), b"parity:string".to_vec(), b"1".to_vec()],
        vec![b"GETSET".to_vec(), b"parity:string".to_vec(), b"2".to_vec()],
        vec![b"GET".to_vec(), b"parity:string".to_vec()],
        vec![
            b"SETNX".to_vec(),
            b"parity:string".to_vec(),
            b"ignored".to_vec(),
        ],
        vec![
            b"SETEX".to_vec(),
            b"parity:setex".to_vec(),
            b"60".to_vec(),
            b"setex".to_vec(),
        ],
        vec![
            b"PSETEX".to_vec(),
            b"parity:psetex".to_vec(),
            b"60000".to_vec(),
            b"psetex".to_vec(),
        ],
        vec![
            b"MSET".to_vec(),
            b"parity:mset:a".to_vec(),
            b"a".to_vec(),
            b"parity:mset:b".to_vec(),
            b"b".to_vec(),
        ],
        vec![
            b"MGET".to_vec(),
            b"parity:mset:a".to_vec(),
            b"parity:mset:b".to_vec(),
            b"parity:mset:missing".to_vec(),
        ],
        vec![
            b"APPEND".to_vec(),
            b"parity:string".to_vec(),
            b":tail".to_vec(),
        ],
        vec![b"STRLEN".to_vec(), b"parity:string".to_vec()],
        vec![b"INCR".to_vec(), b"parity:counter".to_vec()],
        vec![
            b"INCRBY".to_vec(),
            b"parity:counter".to_vec(),
            b"4".to_vec(),
        ],
        vec![b"DECR".to_vec(), b"parity:counter".to_vec()],
        vec![
            b"DECRBY".to_vec(),
            b"parity:counter".to_vec(),
            b"2".to_vec(),
        ],
        vec![b"EXISTS".to_vec(), b"parity:string".to_vec()],
        vec![
            b"EXPIRE".to_vec(),
            b"parity:string".to_vec(),
            b"60".to_vec(),
        ],
        vec![b"PERSIST".to_vec(), b"parity:string".to_vec()],
        vec![b"TYPE".to_vec(), b"parity:string".to_vec()],
        vec![
            b"LPUSH".to_vec(),
            b"parity:list".to_vec(),
            b"a".to_vec(),
            b"b".to_vec(),
        ],
        vec![b"RPUSH".to_vec(), b"parity:list".to_vec(), b"c".to_vec()],
        vec![b"LLEN".to_vec(), b"parity:list".to_vec()],
        vec![b"LINDEX".to_vec(), b"parity:list".to_vec(), b"1".to_vec()],
        vec![
            b"LRANGE".to_vec(),
            b"parity:list".to_vec(),
            b"0".to_vec(),
            b"-1".to_vec(),
        ],
        vec![b"LPOP".to_vec(), b"parity:list".to_vec()],
        vec![b"RPOP".to_vec(), b"parity:list".to_vec()],
        vec![
            b"HSET".to_vec(),
            b"parity:hash".to_vec(),
            b"f1".to_vec(),
            b"v1".to_vec(),
        ],
        vec![
            b"HSET".to_vec(),
            b"parity:hash".to_vec(),
            b"f2".to_vec(),
            b"v2".to_vec(),
        ],
        vec![
            b"HINCRBY".to_vec(),
            b"parity:hash".to_vec(),
            b"counter".to_vec(),
            b"3".to_vec(),
        ],
        vec![
            b"HMGET".to_vec(),
            b"parity:hash".to_vec(),
            b"f1".to_vec(),
            b"f2".to_vec(),
            b"missing".to_vec(),
        ],
        vec![b"HEXISTS".to_vec(), b"parity:hash".to_vec(), b"f1".to_vec()],
        vec![b"HLEN".to_vec(), b"parity:hash".to_vec()],
        vec![b"HDEL".to_vec(), b"parity:hash".to_vec(), b"f2".to_vec()],
        vec![
            b"SADD".to_vec(),
            b"parity:set".to_vec(),
            b"a".to_vec(),
            b"b".to_vec(),
        ],
        vec![b"SISMEMBER".to_vec(), b"parity:set".to_vec(), b"a".to_vec()],
        vec![b"SCARD".to_vec(), b"parity:set".to_vec()],
        vec![b"SREM".to_vec(), b"parity:set".to_vec(), b"b".to_vec()],
        vec![
            b"ZADD".to_vec(),
            b"parity:zset".to_vec(),
            b"1.5".to_vec(),
            b"a".to_vec(),
        ],
        vec![
            b"ZADD".to_vec(),
            b"parity:zset".to_vec(),
            b"2.5".to_vec(),
            b"b".to_vec(),
        ],
        vec![b"ZSCORE".to_vec(), b"parity:zset".to_vec(), b"b".to_vec()],
        vec![b"ZCARD".to_vec(), b"parity:zset".to_vec()],
        vec![
            b"ZCOUNT".to_vec(),
            b"parity:zset".to_vec(),
            b"0".to_vec(),
            b"+inf".to_vec(),
        ],
        vec![
            b"ZRANGE".to_vec(),
            b"parity:zset".to_vec(),
            b"0".to_vec(),
            b"-1".to_vec(),
        ],
        vec![
            b"ZRANGE".to_vec(),
            b"parity:zset".to_vec(),
            b"0".to_vec(),
            b"-1".to_vec(),
            b"WITHSCORES".to_vec(),
        ],
        vec![
            b"ZINCRBY".to_vec(),
            b"parity:zset".to_vec(),
            b"1".to_vec(),
            b"a".to_vec(),
        ],
        vec![b"ZREM".to_vec(), b"parity:zset".to_vec(), b"b".to_vec()],
        vec![
            b"GEOADD".to_vec(),
            b"parity:geo".to_vec(),
            b"13.361389".to_vec(),
            b"38.115556".to_vec(),
            b"Palermo".to_vec(),
            b"15.087269".to_vec(),
            b"37.502669".to_vec(),
            b"Catania".to_vec(),
        ],
        vec![
            b"GEOPOS".to_vec(),
            b"parity:geo".to_vec(),
            b"Palermo".to_vec(),
        ],
        vec![
            b"GEODIST".to_vec(),
            b"parity:geo".to_vec(),
            b"Palermo".to_vec(),
            b"Catania".to_vec(),
            b"KM".to_vec(),
        ],
        vec![
            b"XADD".to_vec(),
            b"parity:stream".to_vec(),
            b"1-0".to_vec(),
            b"field".to_vec(),
            b"value".to_vec(),
        ],
    ];

    let native_output = native
        .execute_embedded_pipeline(&native_pipeline)
        .await
        .unwrap();
    let raw_output = raw.pipeline_values(&raw_commands).await.unwrap();
    assert_eq!(native_output, raw_output);

    native_handle.shutdown_and_wait().await.unwrap();
    raw_handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn embedded_prepared_pipeline_can_be_reused_without_reparsing_argv() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        enable_resp: false,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg).await.unwrap();
    let client = handle.client();

    let mut typed = lux::PreparedPipeline::new();
    typed
        .set("prepared:string", "one")
        .get("prepared:string")
        .append("prepared:string", ":two");
    assert_eq!(
        client.execute_prepared_pipeline(&typed).await.unwrap(),
        vec![
            lux::EmbeddedValue::Simple("OK".to_string()),
            lux::EmbeddedValue::Bulk(bytes::Bytes::from_static(b"one")),
            lux::EmbeddedValue::Int(7),
        ]
    );
    assert_eq!(
        client.get("prepared:string").await.unwrap(),
        Some(bytes::Bytes::from_static(b"one:two"))
    );

    let mut parsed = lux::PreparedPipeline::new();
    parsed
        .push_argv([
            b"MSET".as_slice(),
            b"prepared:mset:a".as_slice(),
            b"a".as_slice(),
            b"prepared:mset:b".as_slice(),
            b"b".as_slice(),
        ])
        .unwrap();
    assert!(parsed.is_write_only());
    client
        .execute_prepared_pipeline_discard(&parsed)
        .await
        .unwrap();
    client
        .execute_prepared_pipeline_discard(&parsed)
        .await
        .unwrap();
    assert_eq!(
        client
            .mget(&["prepared:mset:a", "prepared:mset:b"])
            .await
            .unwrap(),
        vec![
            Some(bytes::Bytes::from_static(b"a")),
            Some(bytes::Bytes::from_static(b"b")),
        ]
    );

    let mut parsed_write = lux::PreparedPipeline::new();
    parsed_write
        .push_argv([
            b"HINCRBY".as_slice(),
            b"prepared:raw:hash".as_slice(),
            b"counter".as_slice(),
            b"2".as_slice(),
        ])
        .unwrap()
        .push_argv([
            b"ZINCRBY".as_slice(),
            b"prepared:raw:zset".as_slice(),
            b"1".as_slice(),
            b"member".as_slice(),
        ])
        .unwrap()
        .push_argv([
            b"XADD".as_slice(),
            b"prepared:raw:stream".as_slice(),
            b"1-*".as_slice(),
            b"field".as_slice(),
            b"value".as_slice(),
        ])
        .unwrap();
    assert!(parsed_write.is_write_only());
    assert_eq!(
        client
            .execute_prepared_pipeline(&parsed_write)
            .await
            .unwrap(),
        vec![
            lux::EmbeddedValue::Int(2),
            lux::EmbeddedValue::Bulk(bytes::Bytes::from_static(b"1")),
            lux::EmbeddedValue::Bulk(bytes::Bytes::from_static(b"1-0")),
        ]
    );
    client
        .execute_prepared_pipeline_discard(&parsed_write)
        .await
        .unwrap();
    assert_eq!(
        client.hget("prepared:raw:hash", "counter").await.unwrap(),
        Some(bytes::Bytes::from_static(b"4"))
    );
    assert_eq!(
        client.zscore("prepared:raw:zset", "member").await.unwrap(),
        Some(2.0)
    );

    let mut get =
        lux::PreparedPipeline::from_argv([b"GET".as_slice(), b"prepared:mset:a".as_slice()])
            .unwrap();
    assert!(!get.is_write_only());
    get.extend(&typed);
    assert_eq!(get.len(), typed.len() + 1);

    drop(client);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn prepared_pipeline_classifies_and_falls_back_without_changing_semantics() {
    let empty = lux::PreparedPipeline::new();
    assert!(!empty.is_read_only());
    assert!(!empty.is_write_only());

    let mut read_only = lux::PreparedPipeline::new();
    read_only
        .push_argv([b"PING".as_slice()])
        .unwrap()
        .push_argv([b"GET".as_slice(), b"classify:key".as_slice()])
        .unwrap();
    assert!(read_only.is_read_only());
    assert!(!read_only.is_write_only());

    let mut write_only = lux::PreparedPipeline::new();
    write_only
        .push_argv([
            b"SET".as_slice(),
            b"classify:key".as_slice(),
            b"value".as_slice(),
        ])
        .unwrap()
        .push_argv([
            b"MSET".as_slice(),
            b"classify:a".as_slice(),
            b"a".as_slice(),
            b"classify:b".as_slice(),
            b"b".as_slice(),
        ])
        .unwrap()
        .push_argv([
            b"HINCRBY".as_slice(),
            b"classify:hash".as_slice(),
            b"counter".as_slice(),
            b"1".as_slice(),
        ])
        .unwrap()
        .push_argv([
            b"ZINCRBY".as_slice(),
            b"classify:zset".as_slice(),
            b"1".as_slice(),
            b"member".as_slice(),
        ])
        .unwrap()
        .push_argv([
            b"XADD".as_slice(),
            b"classify:stream".as_slice(),
            b"1-0".as_slice(),
            b"field".as_slice(),
            b"value".as_slice(),
        ])
        .unwrap();
    assert!(write_only.is_write_only());
    assert!(!write_only.is_read_only());

    let mut mixed = write_only.clone();
    mixed.extend(&read_only);
    assert!(!mixed.is_read_only());
    assert!(!mixed.is_write_only());

    let mut raw_only = lux::PreparedPipeline::new();
    raw_only
        .push_argv([
            b"XADD".as_slice(),
            b"classify:raw:stream".as_slice(),
            b"MAXLEN".as_slice(),
            b"10".as_slice(),
            b"*".as_slice(),
            b"field".as_slice(),
            b"value".as_slice(),
        ])
        .unwrap();
    assert!(!raw_only.is_read_only());
    assert!(!raw_only.is_write_only());

    let tmp = tempfile::tempdir().unwrap();
    let handle = lux::run_with_config(lux::ServerConfig {
        enable_resp: false,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    })
    .await
    .unwrap();
    let client = handle.client();

    let mut hset_multi_field = lux::PreparedPipeline::new();
    hset_multi_field
        .push_argv([
            b"HSET".as_slice(),
            b"fallback:hash".as_slice(),
            b"a".as_slice(),
            b"1".as_slice(),
            b"b".as_slice(),
            b"2".as_slice(),
        ])
        .unwrap();
    assert_eq!(
        client
            .execute_prepared_pipeline(&hset_multi_field)
            .await
            .unwrap(),
        vec![lux::EmbeddedValue::Int(2)]
    );
    assert_eq!(
        client.hmget("fallback:hash", &["a", "b"]).await.unwrap(),
        vec![
            Some(bytes::Bytes::from_static(b"1")),
            Some(bytes::Bytes::from_static(b"2")),
        ]
    );

    let mut invalid_set_option = lux::PreparedPipeline::new();
    invalid_set_option
        .push_argv([
            b"SET".as_slice(),
            b"fallback:set".as_slice(),
            b"value".as_slice(),
            b"BOGUS".as_slice(),
        ])
        .unwrap();
    let output = client
        .execute_prepared_pipeline(&invalid_set_option)
        .await
        .unwrap();
    let [lux::EmbeddedValue::Error(err)] = output.as_slice() else {
        panic!("invalid SET option should stay on raw path and return an error: {output:?}");
    };
    assert!(
        err.contains("syntax") || err.contains("unsupported") || err.contains("ERR"),
        "unexpected SET option error: {err}"
    );
    assert_eq!(client.get("fallback:set").await.unwrap(), None);

    client
        .geoadd(
            "fallback:geo",
            &[
                lux::GeoMember {
                    longitude: 13.361389,
                    latitude: 38.115556,
                    member: "Palermo",
                },
                lux::GeoMember {
                    longitude: 15.087269,
                    latitude: 37.502669,
                    member: "Catania",
                },
            ],
        )
        .await
        .unwrap();
    let mut invalid_geodist_unit = lux::PreparedPipeline::new();
    invalid_geodist_unit
        .push_argv([
            b"GEODIST".as_slice(),
            b"fallback:geo".as_slice(),
            b"Palermo".as_slice(),
            b"Catania".as_slice(),
            b"PARSEC".as_slice(),
        ])
        .unwrap();
    let output = client
        .execute_prepared_pipeline(&invalid_geodist_unit)
        .await
        .unwrap();
    let [lux::EmbeddedValue::Error(err)] = output.as_slice() else {
        panic!("invalid GEODIST unit should stay on raw path and return an error: {output:?}");
    };
    assert!(
        err.contains("unsupported unit"),
        "unexpected GEODIST unit error: {err}"
    );

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn embedded_discard_pipeline_propagates_command_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        enable_resp: false,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg).await.unwrap();
    let client = handle.client();
    client.lpush("discard:wrongtype", &["value"]).await.unwrap();

    let mut pipeline = lux::EmbeddedPipeline::new();
    pipeline.incr(b"discard:wrongtype");
    let err = client
        .execute_embedded_pipeline_discard(&pipeline)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("WRONGTYPE"),
        "unexpected discard error: {err}"
    );

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn embedded_pipeline_works_in_tiered_mode_via_generic_path() {
    let tmp = tempfile::tempdir().unwrap();
    let storage_dir = tmp.path().join("storage");
    let cfg = lux::ServerConfig {
        enable_resp: false,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        save_interval: Duration::ZERO,
        storage: lux::StorageConfig {
            mode: lux::StorageMode::Tiered,
            dir: storage_dir.display().to_string(),
        },
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg).await.unwrap();
    let client = handle.client();

    let mut pipeline = lux::EmbeddedPipeline::new();
    pipeline
        .set(b"tiered:pipeline", b"value")
        .get(b"tiered:pipeline")
        .incr(b"tiered:counter");
    assert_eq!(
        client.execute_embedded_pipeline(&pipeline).await.unwrap(),
        vec![
            lux::EmbeddedValue::Simple("OK".to_string()),
            lux::EmbeddedValue::Bulk(bytes::Bytes::from_static(b"value")),
            lux::EmbeddedValue::Int(1),
        ]
    );

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn embedded_typed_writes_replay_from_tiered_wal() {
    let tmp = tempfile::tempdir().unwrap();
    let storage_dir = tmp.path().join("storage");
    let cfg = lux::ServerConfig {
        enable_resp: false,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        save_interval: Duration::ZERO,
        storage: lux::StorageConfig {
            mode: lux::StorageMode::Tiered,
            dir: storage_dir.display().to_string(),
        },
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg.clone()).await.unwrap();
    let client = handle.client();
    assert!(client.set("wal:string", "a").await.unwrap());
    assert_eq!(client.append("wal:string", ":b").await.unwrap(), 3);
    assert_eq!(client.incrby("wal:counter", 5).await.unwrap(), 5);
    assert_eq!(client.lpush("wal:list", &["left"]).await.unwrap(), 1);
    assert_eq!(client.rpush("wal:list", &["right"]).await.unwrap(), 2);
    assert_eq!(client.hset("wal:hash", "field", "value").await.unwrap(), 1);
    assert_eq!(client.hincrby("wal:hash", "counter", 7).await.unwrap(), 7);
    assert_eq!(client.sadd("wal:set", &["member"]).await.unwrap(), 1);
    assert_eq!(client.zadd("wal:zset", 2.5, "member").await.unwrap(), 1);
    assert_eq!(
        client.zincrby("wal:zset", 1.5, "member").await.unwrap(),
        4.0
    );
    assert_eq!(
        client
            .xadd("wal:stream", "1-0", &[("field", "value")])
            .await
            .unwrap(),
        "1-0"
    );
    client
        .mset(&[("wal:mset:a", "a"), ("wal:mset:b", "b")])
        .await
        .unwrap();
    handle.shutdown_and_wait().await.unwrap();

    let handle = lux::run_with_config(cfg).await.unwrap();
    let client = handle.client();
    assert_eq!(
        client.get("wal:string").await.unwrap(),
        Some(bytes::Bytes::from_static(b"a:b"))
    );
    assert_eq!(
        client.get("wal:counter").await.unwrap(),
        Some(bytes::Bytes::from_static(b"5"))
    );
    assert_eq!(
        client.lrange("wal:list", 0, -1).await.unwrap(),
        vec![
            bytes::Bytes::from_static(b"left"),
            bytes::Bytes::from_static(b"right"),
        ]
    );
    assert_eq!(
        client.hget("wal:hash", "field").await.unwrap(),
        Some(bytes::Bytes::from_static(b"value"))
    );
    assert_eq!(
        client.hget("wal:hash", "counter").await.unwrap(),
        Some(bytes::Bytes::from_static(b"7"))
    );
    assert!(client.sismember("wal:set", "member").await.unwrap());
    assert_eq!(
        client.zscore("wal:zset", "member").await.unwrap(),
        Some(4.0)
    );
    assert_eq!(
        client.mget(&["wal:mset:a", "wal:mset:b"]).await.unwrap(),
        vec![
            Some(bytes::Bytes::from_static(b"a")),
            Some(bytes::Bytes::from_static(b"b")),
        ]
    );

    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn embedded_blocking_pop_wakes_when_value_is_pushed() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        enable_resp: false,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg).await.unwrap();
    let blocked = handle.client();
    let producer = handle.client();

    let waiter = tokio::spawn(async move {
        blocked
            .blpop(&["blocking:list"], Duration::from_secs(1))
            .await
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut pipeline = lux::EmbeddedPipeline::new();
    pipeline.rpush(b"blocking:list", vec![b"ready".as_slice()]);
    producer.execute_embedded_pipeline(&pipeline).await.unwrap();

    let result = waiter.await.unwrap().unwrap().expect("BLPOP should wake");
    assert_eq!(result.0, "blocking:list");
    assert_eq!(&result.1[..], b"ready");

    drop(producer);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn embedded_blocking_pop_times_out() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        enable_resp: false,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg).await.unwrap();
    let client = handle.client();

    let result = client
        .brpop(&["blocking:missing"], Duration::from_millis(25))
        .await
        .unwrap();
    assert_eq!(result, None);

    drop(client);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn embedded_pattern_pubsub_receives_matching_messages() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        enable_resp: false,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg).await.unwrap();
    let client = handle.client();
    let mut sub = client.psubscribe("events:*");
    assert_eq!(sub.try_recv().unwrap(), None);

    let published = client
        .execute_value("PUBLISH", &["events:created", "payload"])
        .await
        .unwrap();
    assert_eq!(published, lux::EmbeddedValue::Int(1));

    let message = tokio::time::timeout(Duration::from_secs(1), sub.recv())
        .await
        .expect("pattern pubsub message should arrive")
        .unwrap();
    assert_eq!(message.kind, lux::EmbeddedMessageKind::PubSub);
    assert_eq!(message.channel, "events:created");
    assert_eq!(message.pattern.as_deref(), Some("events:*"));
    assert_eq!(&message.payload[..], b"payload");

    drop(sub);
    drop(client);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn embedded_subscription_close_stops_delivery() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        enable_resp: false,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg).await.unwrap();
    let client = handle.client();
    let sub = client.subscribe("close:events");
    sub.close();

    let published = client
        .execute_value("PUBLISH", &["close:events", "payload"])
        .await
        .unwrap();
    assert_eq!(published, lux::EmbeddedValue::Int(0));

    drop(client);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn embedded_key_subscription_receives_key_events() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        enable_resp: false,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg).await.unwrap();
    let client = handle.client();
    let mut sub = client.ksubscribe("key:*");

    assert!(client.set("key:one", "1").await.unwrap());

    let message = tokio::time::timeout(Duration::from_secs(1), sub.recv())
        .await
        .expect("key event should arrive")
        .unwrap();
    assert_eq!(message.kind, lux::EmbeddedMessageKind::KeyEvent);
    assert_eq!(message.channel, "key:one");
    assert_eq!(message.pattern.as_deref(), Some("key:*"));
    assert_eq!(&message.payload[..], b"set");

    sub.close();
    drop(client);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn embedded_key_subscription_lazy_worker_handles_multiple_subscribers() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        enable_resp: false,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg).await.unwrap();
    let client = handle.client();
    let mut glob = client.ksubscribe("lazy:*");
    let mut exact = client.ksubscribe("lazy:one");

    assert!(client.set("lazy:one", "1").await.unwrap());

    let glob_msg = tokio::time::timeout(Duration::from_secs(1), glob.recv())
        .await
        .expect("glob key event should arrive")
        .unwrap();
    let exact_msg = tokio::time::timeout(Duration::from_secs(1), exact.recv())
        .await
        .expect("exact key event should arrive")
        .unwrap();
    for message in [glob_msg, exact_msg] {
        assert_eq!(message.kind, lux::EmbeddedMessageKind::KeyEvent);
        assert_eq!(message.channel, "lazy:one");
        assert_eq!(&message.payload[..], b"set");
    }

    glob.close();
    exact.close();
    drop(client);
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_with_config_instances_keep_runtime_state_isolated() {
    let tmp_a = tempfile::tempdir().unwrap();
    let tmp_b = tempfile::tempdir().unwrap();

    let cfg_a = lux::ServerConfig {
        port: 0,
        shards: 4,
        data_dir: tmp_a.path().display().to_string(),
        ..Default::default()
    };

    let cfg_b = lux::ServerConfig {
        port: 0,
        shards: 4,
        data_dir: tmp_b.path().display().to_string(),
        ..Default::default()
    };

    let handle_a = lux::run_with_config(cfg_a).await.unwrap();
    let handle_b = lux::run_with_config(cfg_b).await.unwrap();
    let mut conn_a = connect(handle_a.local_addr().unwrap());
    let mut conn_b = connect(handle_b.local_addr().unwrap());

    // Exercise only instance A before reading INFO from both servers. Global
    // counters would make instance B report A's commands and memory.
    assert!(send_and_read(&mut conn_a, &["SET", "shared", "one"]).contains("+OK"));
    assert!(send_and_read(&mut conn_a, &["GET", "shared"]).contains("one"));
    assert!(send_and_read(&mut conn_b, &["GET", "shared"]).contains("$-1"));

    let info_a = send_and_read(&mut conn_a, &["INFO"]);
    let info_b = send_and_read(&mut conn_b, &["INFO"]);

    assert_eq!(info_usize(&info_a, "connected_clients"), 1);
    assert_eq!(info_usize(&info_b, "connected_clients"), 1);
    assert!(
        info_usize(&info_a, "total_commands_processed")
            > info_usize(&info_b, "total_commands_processed"),
        "instance A should not share command counters with instance B"
    );
    assert!(
        info_usize(&info_a, "used_memory_bytes") > info_usize(&info_b, "used_memory_bytes"),
        "instance B should not inherit instance A's memory counter"
    );

    drop(conn_a);
    drop(conn_b);
    handle_a.shutdown_and_wait().await.unwrap();
    handle_b.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn run_with_config_port_zero_assigns_ephemeral_port() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        port: 0,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg).await.unwrap();
    let addr = handle
        .local_addr()
        .expect("RESP should be enabled by default");
    assert_ne!(addr.port(), 0, "port=0 should bind an ephemeral port");
    let _ = std::net::TcpStream::connect(addr).expect("RESP listener should accept connections");
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn run_with_config_can_disable_resp_explicitly() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = lux::ServerConfig {
        enable_resp: false,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg).await.unwrap();
    assert!(
        handle.local_addr().is_none(),
        "RESP local addr should be absent when disabled"
    );
    handle.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn run_with_config_emits_startup_events_when_callback_set() {
    let tmp = tempfile::tempdir().unwrap();
    let events = Arc::new(Mutex::new(Vec::<lux::ServerInfoEvent>::new()));
    let sink = events.clone();

    let cfg = lux::ServerConfig {
        enable_resp: false,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        on_info: Some(Arc::new(move |event| {
            sink.lock().unwrap().push(event);
        })),
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg).await.unwrap();
    handle.shutdown_and_wait().await.unwrap();

    let captured = events.lock().unwrap();
    assert!(
        captured
            .iter()
            .any(|e| matches!(e, lux::ServerInfoEvent::NoSnapshotFound)),
        "expected NoSnapshotFound event, got: {captured:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_with_config_returns_after_snapshot_and_wal_replay() {
    let tmp = tempfile::tempdir().unwrap();
    let storage_dir = tmp.path().join("storage");

    let cfg = lux::ServerConfig {
        port: 0,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        save_interval: Duration::ZERO,
        storage: lux::StorageConfig {
            mode: lux::StorageMode::Tiered,
            dir: storage_dir.display().to_string(),
        },
        ..Default::default()
    };

    let handle = lux::run_with_config(cfg.clone()).await.unwrap();
    let addr = handle.local_addr().unwrap();
    let writer = UniversalClient::resp(addr);
    assert!(writer.set("snapshot_key", "snapshot_value").await);
    writer.save().await;
    assert!(writer.set("wal_key", "wal_value").await);
    drop(writer);
    handle.shutdown_and_wait().await.unwrap();

    append_corrupt_wal_frames(&storage_dir);
    let events = Arc::new(Mutex::new(Vec::<lux::ServerWarnEvent>::new()));
    let sink = events.clone();
    let cfg = lux::ServerConfig {
        on_warn: Some(Arc::new(move |event| {
            sink.lock().unwrap().push(event);
        })),
        ..cfg
    };

    let handle = lux::run_with_config(cfg).await.unwrap();
    let addr = handle.local_addr().unwrap();
    let reader = UniversalClient::resp(addr);
    let snapshot_resp = reader.get("snapshot_key").await;
    assert!(
        snapshot_resp
            .as_ref()
            .is_some_and(|v| String::from_utf8_lossy(v).contains("snapshot_value")),
        "snapshot value should be loaded before readiness: {snapshot_resp:?}"
    );
    let wal_resp = reader.get("wal_key").await;
    assert!(
        wal_resp
            .as_ref()
            .is_some_and(|v| String::from_utf8_lossy(v).contains("wal_value")),
        "WAL value should be replayed before readiness: {wal_resp:?}"
    );
    drop(reader);
    handle.shutdown_and_wait().await.unwrap();

    let captured = events.lock().unwrap();
    assert!(
        captured.iter().any(|e| {
            matches!(
                e,
                lux::ServerWarnEvent::WalCorruptedFramesSkipped { frames, .. } if *frames > 0
            )
        }),
        "expected WAL corruption event, got: {captured:?}"
    );
}

#[tokio::test]
async fn run_with_config_reports_http_bind_errors_before_ready() {
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = occupied.local_addr().unwrap().port();
    let tmp = tempfile::tempdir().unwrap();

    let cfg = lux::ServerConfig {
        enable_resp: false,
        http_port: port,
        shards: 4,
        data_dir: tmp.path().display().to_string(),
        ..Default::default()
    };

    match lux::run_with_config(cfg).await {
        Ok(handle) => {
            handle.shutdown_and_wait().await.unwrap();
            panic!("run_with_config should fail when the HTTP port is unavailable");
        }
        Err(e) => {
            assert_eq!(e.kind(), std::io::ErrorKind::AddrInUse);
        }
    }
}
