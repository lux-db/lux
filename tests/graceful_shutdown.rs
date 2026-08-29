#![cfg(unix)]

mod common;

use common::{connect, free_port, resp_cmd, send};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn spawn(data_dir: &Path, port: u16, shutdown_timeout_ms: u64) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lux"));
    command
        .env("LUX_BIND_HOST", "127.0.0.1")
        .env("LUX_PORT", port.to_string())
        .env("LUX_HTTP_PORT", "0")
        .env("LUX_DATA_DIR", data_dir)
        .env("LUX_DURABILITY", "every_second")
        .env("LUX_DURABILITY_SYNC_INTERVAL_MS", "1000")
        .env("LUX_SAVE_INTERVAL", "0")
        .env("LUX_SHUTDOWN_TIMEOUT_MS", shutdown_timeout_ms.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    common::spawn_lux(&mut command).expect("spawn lux")
}

fn signal(child: &Child, name: &str) {
    let status = Command::new("kill")
        .arg(name)
        .arg(child.id().to_string())
        .status()
        .expect("send process signal");
    assert!(status.success(), "kill {name} failed: {status}");
}

fn sigterm(child: &Child) {
    signal(child, "-TERM");
}

fn wait_bounded(child: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().expect("wait for lux") {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("lux did not exit within five seconds after SIGTERM");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn set_fast(connection: &mut BufReader<std::net::TcpStream>, key: &str) -> std::io::Result<bool> {
    connection
        .get_mut()
        .write_all(&resp_cmd(&["SET", key, "value"]))?;
    let mut response = String::new();
    connection.read_line(&mut response)?;
    Ok(response == "+OK\r\n")
}

fn get_fast(connection: &mut BufReader<std::net::TcpStream>, key: &str) -> std::io::Result<bool> {
    connection.get_mut().write_all(&resp_cmd(&["GET", key]))?;
    let mut header = String::new();
    connection.read_line(&mut header)?;
    let Some(length) = header
        .strip_prefix('$')
        .and_then(|line| line.trim_end().parse::<usize>().ok())
    else {
        return Ok(false);
    };
    let mut value = vec![0; length + 2];
    std::io::Read::read_exact(connection, &mut value)?;
    Ok(&value[..length] == b"value" && &value[length..] == b"\r\n")
}

#[test]
fn sigterm_exits_clean_and_preserves_acknowledged_write() {
    let root = tempfile::tempdir().unwrap();
    let port = free_port();
    let mut child = spawn(root.path(), port, 2_000);
    let mut connection = connect(port);
    assert!(send(&mut connection, &["SET", "signal:key", "value"]).contains("+OK"));

    sigterm(&child);
    let status = wait_bounded(&mut child);
    assert_eq!(status.code(), Some(0), "unexpected clean exit: {status}");

    let mut restarted = spawn(root.path(), port, 2_000);
    let mut connection = connect(port);
    assert!(
        send(&mut connection, &["GET", "signal:key"]).contains("value"),
        "graceful shutdown did not preserve the acknowledged write"
    );
    sigterm(&restarted);
    assert_eq!(wait_bounded(&mut restarted).code(), Some(0));
}

#[test]
fn drain_deadline_exits_with_forced_status() {
    let root = tempfile::tempdir().unwrap();
    let port = free_port();
    let mut child = spawn(root.path(), port, 50);
    let mut connection = connect(port);
    connection
        .write_all(&resp_cmd(&["BLPOP", "never", "10"]))
        .unwrap();
    thread::sleep(Duration::from_millis(25));

    sigterm(&child);
    let status = wait_bounded(&mut child);
    assert_eq!(status.code(), Some(2), "unexpected forced exit: {status}");
}

#[test]
fn sigint_uses_the_same_clean_shutdown_barrier() {
    let root = tempfile::tempdir().unwrap();
    let port = free_port();
    let mut child = spawn(root.path(), port, 2_000);
    let mut connection = connect(port);
    assert!(send(&mut connection, &["SET", "interrupt:key", "value"]).contains("+OK"));

    signal(&child, "-INT");
    assert_eq!(wait_bounded(&mut child).code(), Some(0));

    let mut restarted = spawn(root.path(), port, 2_000);
    let mut connection = connect(port);
    assert!(send(&mut connection, &["GET", "interrupt:key"]).contains("value"));
    sigterm(&restarted);
    assert_eq!(wait_bounded(&mut restarted).code(), Some(0));
}

#[test]
fn every_write_acknowledged_while_sigterm_lands_recovers() {
    let root = tempfile::tempdir().unwrap();
    let port = free_port();
    let mut child = spawn(root.path(), port, 2_000);
    let connection = connect(port);
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let writer = thread::spawn(move || {
        let mut connection = BufReader::new(connection);
        let mut acknowledged = Vec::new();
        for index in 0..10_000 {
            let key = format!("signal-race:{index}");
            match set_fast(&mut connection, &key) {
                Ok(true) => {
                    acknowledged.push(key);
                    if acknowledged.len() == 10 {
                        ready_tx.send(()).unwrap();
                    }
                }
                Ok(false) | Err(_) => break,
            }
        }
        acknowledged
    });

    ready_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("writer did not receive ten acknowledgements");
    sigterm(&child);
    let acknowledged = writer.join().unwrap();
    assert_eq!(wait_bounded(&mut child).code(), Some(0));
    assert!(acknowledged.len() >= 10);

    let mut restarted = spawn(root.path(), port, 2_000);
    let mut connection = BufReader::new(connect(port));
    for key in &acknowledged {
        assert!(
            get_fast(&mut connection, key).unwrap(),
            "acknowledged key did not recover: {key}"
        );
    }
    sigterm(&restarted);
    assert_eq!(wait_bounded(&mut restarted).code(), Some(0));
}
