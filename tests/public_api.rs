use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_with_config_instances_keep_runtime_state_isolated() {
    let tmp_a = tempfile::tempdir().unwrap();
    let tmp_b = tempfile::tempdir().unwrap();

    let mut cfg_a = lux::ServerConfig::default();
    cfg_a.port = 0;
    cfg_a.shards = 4;
    cfg_a.data_dir = tmp_a.path().display().to_string();

    let mut cfg_b = lux::ServerConfig::default();
    cfg_b.port = 0;
    cfg_b.shards = 4;
    cfg_b.data_dir = tmp_b.path().display().to_string();

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
    let mut cfg = lux::ServerConfig::default();
    cfg.port = 0;
    cfg.shards = 4;
    cfg.data_dir = tmp.path().display().to_string();

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
    let mut cfg = lux::ServerConfig::default();
    cfg.enable_resp = false;
    cfg.shards = 4;
    cfg.data_dir = tmp.path().display().to_string();

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

    let mut cfg = lux::ServerConfig::default();
    cfg.enable_resp = false;
    cfg.shards = 4;
    cfg.data_dir = tmp.path().display().to_string();
    cfg.on_info = Some(Arc::new(move |event| {
        sink.lock().unwrap().push(event);
    }));

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

    let mut cfg = lux::ServerConfig::default();
    cfg.port = 0;
    cfg.shards = 4;
    cfg.data_dir = tmp.path().display().to_string();
    cfg.save_interval = Duration::ZERO;
    cfg.storage = lux::StorageConfig {
        mode: lux::StorageMode::Tiered,
        dir: storage_dir.display().to_string(),
    };

    let handle = lux::run_with_config(cfg.clone()).await.unwrap();
    let addr = handle.local_addr().unwrap();
    let mut conn = connect(addr);
    let set_snapshot = send_and_read(&mut conn, &["SET", "snapshot_key", "snapshot_value"]);
    assert!(
        set_snapshot.contains("+OK"),
        "initial SET should succeed: {set_snapshot:?}"
    );
    let save = send_and_read(&mut conn, &["SAVE"]);
    assert!(save.contains("+OK"), "SAVE should succeed: {save:?}");
    let set_wal = send_and_read(&mut conn, &["SET", "wal_key", "wal_value"]);
    assert!(
        set_wal.contains("+OK"),
        "WAL SET should succeed: {set_wal:?}"
    );
    drop(conn);
    handle.shutdown_and_wait().await.unwrap();

    append_corrupt_wal_frames(&storage_dir);
    let events = Arc::new(Mutex::new(Vec::<lux::ServerWarnEvent>::new()));
    let sink = events.clone();
    cfg.on_warn = Some(Arc::new(move |event| {
        sink.lock().unwrap().push(event);
    }));

    let handle = lux::run_with_config(cfg).await.unwrap();
    let addr = handle.local_addr().unwrap();
    let mut conn = connect(addr);
    let snapshot_resp = send_and_read(&mut conn, &["GET", "snapshot_key"]);
    assert!(
        snapshot_resp.contains("snapshot_value"),
        "snapshot value should be loaded before readiness: {snapshot_resp:?}"
    );
    let wal_resp = send_and_read(&mut conn, &["GET", "wal_key"]);
    assert!(
        wal_resp.contains("wal_value"),
        "WAL value should be replayed before readiness: {wal_resp:?}"
    );
    drop(conn);
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
    let occupied = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    let port = occupied.local_addr().unwrap().port();
    let tmp = tempfile::tempdir().unwrap();

    let mut cfg = lux::ServerConfig::default();
    cfg.enable_resp = false;
    cfg.http_port = port;
    cfg.shards = 4;
    cfg.data_dir = tmp.path().display().to_string();

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
