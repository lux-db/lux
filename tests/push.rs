//! Integration tests for lux push (engine PR1): device registry, reserved-table
//! guards, durable outbox delivery through a mock APNs server, dead-token
//! pruning, and WAL-replay durability.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Child;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

// ── engine harness ─────────────────────────────────────────────────────────

struct PushServer {
    child: Child,
    dir: std::path::PathBuf,
    keep_dir: bool,
}

impl Drop for PushServer {
    fn drop(&mut self) {
        common::terminate_child(&mut self.child);
        if !self.keep_dir {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

fn free_port_pair() -> (u16, u16) {
    let ports = common::free_ports(2);
    (ports[0], ports[1])
}

fn start(dir: &std::path::Path, resp_port: u16, http_port: u16, keep_dir: bool) -> PushServer {
    let bin = common::find_lux_binary();
    std::fs::create_dir_all(dir).unwrap();
    let mut cmd = common::lux_command(&bin);
    cmd.env("LUX_PORT", resp_port.to_string())
        .env("LUX_HTTP_PORT", http_port.to_string())
        .env("LUX_SHARDS", "4")
        .env("LUX_SAVE_INTERVAL", "0")
        .env("LUX_DATA_DIR", dir.to_str().unwrap())
        // Persistent durability enables the WAL, so the registry survives restart.
        .env("LUX_STORAGE_MODE", "tiered")
        .env("LUX_STORAGE_DIR", dir.join("storage").to_str().unwrap())
        .env("LUX_PASSWORD", "rootsecret")
        .env("LUX_AUTH_ENABLED", "true")
        // Provider private keys are accepted only when the engine can persist
        // them in ENCRYPTED columns. Keep this stable across restart tests.
        .env("LUX_ENCRYPTION_KEY_ID", "push-integration")
        .env("LUX_ENCRYPTION_KEY", "push-integration-secret")
        // Integration delivery uses a loopback mock push service. Production
        // defaults reject private and non-HTTPS Web Push endpoints.
        .env("LUX_PUSH_ALLOW_PRIVATE_ENDPOINTS", "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let child = cmd.spawn().expect("spawn lux");
    let server = PushServer {
        child,
        dir: dir.to_path_buf(),
        keep_dir,
    };
    for _ in 0..160 {
        if TcpStream::connect(("127.0.0.1", http_port)).is_ok()
            && TcpStream::connect(("127.0.0.1", resp_port)).is_ok()
        {
            std::thread::sleep(Duration::from_millis(150));
            return server;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("lux did not start");
}

fn http(port: u16, method: &str, path: &str, body: &str, auth: Option<&str>) -> (u16, Value) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let auth_header = auth
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n{auth_header}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).unwrap();
    let mut resp = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                resp.extend_from_slice(&buf[..n]);
                if let Some(he) = resp.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&resp[..he]);
                    if let Some(len) = headers
                        .lines()
                        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                        .and_then(|l| l.split(':').nth(1))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                    {
                        if resp.len() >= he + 4 + len {
                            break;
                        }
                    }
                }
            }
            Err(error) => panic!(
                "failed reading push HTTP response: {error}; partial response: {}",
                String::from_utf8_lossy(&resp)
            ),
        }
    }
    let text = String::from_utf8_lossy(&resp);
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    (
        status,
        serde_json::from_str(body).unwrap_or_else(|_| json!({})),
    )
}

fn resp_cmd(port: u16, args: &[&str]) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    // The push-test engine sets a password; authenticate on the same connection
    // (pipelined) before the command.
    let mut req = String::from("*2\r\n$4\r\nAUTH\r\n$10\r\nrootsecret\r\n");
    req.push_str(&format!("*{}\r\n", args.len()));
    for a in args {
        req.push_str(&format!("${}\r\n{}\r\n", a.len(), a));
    }
    stream.write_all(req.as_bytes()).unwrap();
    let mut resp = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                resp.extend_from_slice(&buf[..n]);
                if n < buf.len() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&resp).to_string()
}

fn exec(port: u16, command: Value) -> (u16, Value) {
    http(
        port,
        "POST",
        "/v1/exec",
        &json!({ "command": command }).to_string(),
        Some("rootsecret"),
    )
}

// ── mock APNs server (HTTP/1.1; reqwest talks cleartext h1 to localhost) ─────

#[derive(Clone, Default)]
struct Captured {
    path: String,
    authorization: String,
    apns_topic: String,
    apns_push_type: String,
    apns_priority: String,
    apns_expiration: String,
    apns_collapse_id: String,
    apns_id: String,
    content_encoding: String,
    body: String,
}

struct MockApns {
    port: u16,
    requests: Arc<Mutex<Vec<Captured>>>,
}

impl MockApns {
    fn start(status: u16) -> Self {
        let reason = if status == 200 {
            "{}"
        } else {
            "{\"reason\":\"Unregistered\"}"
        };
        Self::start_with_reason(status, reason)
    }

    fn start_with_reason(status: u16, reason: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let reqs = requests.clone();
        let reason = reason.to_string();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut stream) = conn else { continue };
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                // Read headers.
                let header_end = loop {
                    match stream.read(&mut tmp) {
                        Ok(0) => break None,
                        Ok(n) => {
                            buf.extend_from_slice(&tmp[..n]);
                            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                break Some(p);
                            }
                        }
                        Err(_) => break None,
                    }
                };
                let Some(he) = header_end else { continue };
                let head = String::from_utf8_lossy(&buf[..he]).to_string();
                let mut cap = Captured::default();
                for (i, line) in head.lines().enumerate() {
                    if i == 0 {
                        cap.path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                    } else if let Some((k, v)) = line.split_once(':') {
                        match k.trim().to_ascii_lowercase().as_str() {
                            "authorization" => cap.authorization = v.trim().to_string(),
                            "apns-topic" => cap.apns_topic = v.trim().to_string(),
                            "apns-push-type" => cap.apns_push_type = v.trim().to_string(),
                            "apns-priority" => cap.apns_priority = v.trim().to_string(),
                            "apns-expiration" => cap.apns_expiration = v.trim().to_string(),
                            "apns-collapse-id" => cap.apns_collapse_id = v.trim().to_string(),
                            "apns-id" => cap.apns_id = v.trim().to_string(),
                            "content-encoding" => cap.content_encoding = v.trim().to_string(),
                            _ => {}
                        }
                    }
                }
                let content_len = head
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                    .and_then(|l| l.split(':').nth(1))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                let mut body = buf[he + 4..].to_vec();
                while body.len() < content_len {
                    match stream.read(&mut tmp) {
                        Ok(0) => break,
                        Ok(n) => body.extend_from_slice(&tmp[..n]),
                        Err(_) => break,
                    }
                }
                cap.body = String::from_utf8_lossy(&body).to_string();
                reqs.lock().unwrap().push(cap);
                let response = format!(
                    "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reason}",
                    reason.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        MockApns { port, requests }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn wait_for_request(&self, timeout: Duration) -> Option<Captured> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(c) = self.requests.lock().unwrap().first().cloned() {
                return Some(c);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }
}

fn test_p8() -> String {
    use p256::pkcs8::{EncodePrivateKey, LineEnding};
    use p256::SecretKey;
    SecretKey::random(&mut rand_core::OsRng)
        .to_pkcs8_pem(LineEnding::LF)
        .unwrap()
        .to_string()
}

fn set_creds(http_port: u16, environment: &str) {
    let (s, b) = http(
        http_port,
        "POST",
        "/v1/push/credentials",
        &json!({
            "app_id": "default",
            "team_id": "TEAM123456",
            "key_id": "KEY7890AB",
            "p8_pem": test_p8(),
            "topic": "com.example.app",
            "environment": environment,
        })
        .to_string(),
        Some("rootsecret"),
    );
    assert_eq!(s, 200, "set creds: {b}");
}

fn set_creds_topic(http_port: u16, environment: &str, topic: &str) {
    set_creds_material(http_port, environment, topic, &test_p8());
}

fn set_creds_material(http_port: u16, environment: &str, topic: &str, p8_pem: &str) {
    let (s, b) = http(
        http_port,
        "POST",
        "/v1/push/credentials",
        &json!({
            "app_id": "default",
            "team_id": "TEAM123456",
            "key_id": "KEY7890AB",
            "p8_pem": p8_pem,
            "topic": topic,
            "environment": environment,
        })
        .to_string(),
        Some("rootsecret"),
    );
    assert_eq!(s, 200, "set creds: {b}");
}

#[test]
fn private_key_rotation_rebuilds_cached_apns_sink() {
    let mock = MockApns::start(200);
    let dir = tempfile::tempdir().unwrap();
    let (resp_port, http_port) = free_port_pair();
    let _server = start(dir.path(), resp_port, http_port, false);
    let first_private_key = test_p8();
    let second_private_key = test_p8();

    set_creds_material(
        http_port,
        &mock.url(),
        "com.example.unchanged",
        &first_private_key,
    );
    let (token, uid) = anon_login(http_port);
    let (status, body) = http(
        http_port,
        "POST",
        "/v1/push/devices",
        &json!({"token":"private-rotation-token","platform":"ios","app_id":"default"}).to_string(),
        Some(&token),
    );
    assert_eq!(status, 200, "register: {body}");

    let send = |body: &str| {
        let (status, response) = http(
            http_port,
            "POST",
            "/v1/push/send",
            &json!({"subject_id":uid,"notification":{"title":"rotation","body":body}}).to_string(),
            Some("rootsecret"),
        );
        assert_eq!(status, 200, "send: {response}");
    };
    send("before");
    let first = mock
        .wait_for_request(Duration::from_secs(5))
        .expect("first delivery");

    // Rotate only private signing material. Every non-secret sink field stays
    // fixed, so a stale cache fingerprint would reuse the first provider token.
    set_creds_material(
        http_port,
        &mock.url(),
        "com.example.unchanged",
        &second_private_key,
    );
    send("after");

    let deadline = Instant::now() + Duration::from_secs(5);
    let second_authorization = loop {
        {
            let requests = mock.requests.lock().unwrap();
            if requests.len() >= 2 {
                break requests[1].authorization.clone();
            }
        }
        assert!(Instant::now() < deadline, "second delivery not received");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_ne!(
        first.authorization, second_authorization,
        "private-key-only rotation must rebuild the cached APNs signer"
    );
}

// A credentials edit (here the APNs topic) must invalidate the worker's cached
// sink so the next delivery uses the new value. Previously the sink was cached
// for the worker's lifetime, so changes only took effect after an engine restart.
#[test]
fn credential_change_rebuilds_cached_sink() {
    let mock = MockApns::start(200);
    let dir = tempfile::tempdir().unwrap();
    let (resp_port, http_port) = free_port_pair();
    let _server = start(dir.path(), resp_port, http_port, false);

    set_creds_topic(http_port, &mock.url(), "com.example.first");
    let (token, uid) = anon_login(http_port);
    let (s, b) = http(
        http_port,
        "POST",
        "/v1/push/devices",
        &json!({"token":"devtoken-abc","platform":"ios","app_id":"default"}).to_string(),
        Some(&token),
    );
    assert_eq!(s, 200, "register: {b}");

    let (s, _) = http(
        http_port,
        "POST",
        "/v1/push/send",
        &json!({"subject_id": uid, "notification": {"title":"Hi","body":"1"}}).to_string(),
        Some("rootsecret"),
    );
    assert_eq!(s, 200);
    let first = mock
        .wait_for_request(Duration::from_secs(5))
        .expect("first delivery");
    assert_eq!(first.apns_topic, "com.example.first");

    // Change the topic, then send again.
    set_creds_topic(http_port, &mock.url(), "com.example.second");
    let (s, _) = http(
        http_port,
        "POST",
        "/v1/push/send",
        &json!({"subject_id": uid, "notification": {"title":"Hi","body":"2"}}).to_string(),
        Some("rootsecret"),
    );
    assert_eq!(s, 200);

    // The second delivery must carry the NEW topic, not the cached one.
    let deadline = Instant::now() + Duration::from_secs(5);
    let second_topic = loop {
        {
            let reqs = mock.requests.lock().unwrap();
            if reqs.len() >= 2 {
                break reqs[1].apns_topic.clone();
            }
        }
        assert!(Instant::now() < deadline, "second delivery not received");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(
        second_topic, "com.example.second",
        "a credential change must invalidate the cached sink"
    );
}

#[test]
fn unregister_by_token_and_admin_stats() {
    let mock = MockApns::start(200);
    let dir = tempfile::tempdir().unwrap();
    let (resp_port, http_port) = free_port_pair();
    let _server = start(dir.path(), resp_port, http_port, false);

    set_creds(http_port, &mock.url());
    let (token, uid) = anon_login(http_port);
    let (s, b) = http(
        http_port,
        "POST",
        "/v1/push/devices",
        &json!({"token":"tok-xyz","platform":"ios","app_id":"default"}).to_string(),
        Some(&token),
    );
    assert_eq!(s, 200, "register: {b}");

    // Admin stats endpoint (operator) reports the live device count.
    let (s, stats) = http(
        http_port,
        "GET",
        "/v1/push/admin/stats",
        "",
        Some("rootsecret"),
    );
    assert_eq!(s, 200, "stats: {stats}");
    assert!(
        stats["devices"].as_i64().unwrap_or(0) >= 1,
        "stats: {stats}"
    );

    // Unregister by token (operator) removes the device.
    let (s, b) = http(
        http_port,
        "DELETE",
        "/v1/push/devices",
        &json!({"token":"tok-xyz"}).to_string(),
        Some("rootsecret"),
    );
    assert_eq!(s, 200, "delete: {b}");
    assert_eq!(b["deleted"], true);

    // The subject now has no devices, so a send enqueues to zero.
    let (s, b) = http(
        http_port,
        "POST",
        "/v1/push/send",
        &json!({"subject_id": uid, "notification": {"title":"x","body":"y"}}).to_string(),
        Some("rootsecret"),
    );
    assert_eq!(s, 200, "send: {b}");
    assert_eq!(b["enqueued"], 0);
}

#[test]
fn delete_by_token_edge_cases() {
    let mock = MockApns::start(200);
    let dir = tempfile::tempdir().unwrap();
    let (resp_port, http_port) = free_port_pair();
    let _server = start(dir.path(), resp_port, http_port, false);

    set_creds(http_port, &mock.url());
    let (token, uid) = anon_login(http_port);
    for t in ["keep-tok", "drop-tok"] {
        let (s, b) = http(
            http_port,
            "POST",
            "/v1/push/devices",
            &json!({"token": t, "platform":"ios", "app_id":"default"}).to_string(),
            Some(&token),
        );
        assert_eq!(s, 200, "register {t}: {b}");
    }

    // Missing token -> 400.
    let (s, _) = http(
        http_port,
        "DELETE",
        "/v1/push/devices",
        "{}",
        Some("rootsecret"),
    );
    assert_eq!(s, 400);

    // Unknown token -> 200 with deleted:false (idempotent, not an error).
    let (s, b) = http(
        http_port,
        "DELETE",
        "/v1/push/devices",
        &json!({"token":"never-registered"}).to_string(),
        Some("rootsecret"),
    );
    assert_eq!(s, 200, "{b}");
    assert_eq!(b["deleted"], false);

    // Deleting one token leaves the other device intact (scoped to the token).
    let (s, b) = http(
        http_port,
        "DELETE",
        "/v1/push/devices",
        &json!({"token":"drop-tok"}).to_string(),
        Some("rootsecret"),
    );
    assert_eq!(s, 200, "{b}");
    assert_eq!(b["deleted"], true);

    let (s, list) = http(
        http_port,
        "GET",
        &format!("/v1/push/devices?subject_id={uid}"),
        "",
        Some("rootsecret"),
    );
    assert_eq!(s, 200, "{list}");
    let devices = list["devices"].as_array().expect("devices array");
    assert_eq!(
        devices.len(),
        1,
        "only the un-deleted device remains: {list}"
    );
}

#[test]
fn push_admin_routes_require_operator_and_token_cleanup_requires_auth() {
    let mock = MockApns::start(200);
    let dir = tempfile::tempdir().unwrap();
    let (resp_port, http_port) = free_port_pair();
    let _server = start(dir.path(), resp_port, http_port, false);
    set_creds(http_port, &mock.url());
    let (token, _uid) = anon_login(http_port);

    // A signed-in user can reach the cleanup route, but a token it does not
    // own is indistinguishable from a missing token. Admin stats remain
    // operator-only.
    let (s, deleted) = http(
        http_port,
        "DELETE",
        "/v1/push/devices",
        &json!({"token":"x"}).to_string(),
        Some(&token),
    );
    assert_eq!(s, 200, "authenticated cleanup: {deleted}");
    assert_eq!(deleted["deleted"], false);
    let (s, _) = http(http_port, "GET", "/v1/push/admin/stats", "", Some(&token));
    assert!(s == 401 || s == 403, "user stats read denied, got {s}");

    // No auth at all is denied too.
    let (s, _) = http(
        http_port,
        "DELETE",
        "/v1/push/devices",
        &json!({"token":"x"}).to_string(),
        None,
    );
    assert!(
        s == 401 || s == 403,
        "unauth delete-by-token denied, got {s}"
    );
}

fn anon_login(http_port: u16) -> (String, String) {
    let (s, sess) = http(http_port, "POST", "/auth/v1/signin/anonymous", "{}", None);
    assert_eq!(s, 200, "anon signin: {sess}");
    (
        sess["access_token"].as_str().unwrap().to_string(),
        sess["user"]["id"].as_str().unwrap().to_string(),
    )
}

fn info_field(port: u16, field: &str) -> i64 {
    let info = resp_cmd(port, &["INFO", "push"]);
    for line in info.lines() {
        if let Some(rest) = line.trim().strip_prefix(&format!("{field}:")) {
            return rest.trim().parse().unwrap_or(-1);
        }
    }
    -1
}

// ── tests ───────────────────────────────────────────────────────────────────

#[test]
fn push_end_to_end_delivers_to_apns_mock() {
    let mock = MockApns::start(200);
    let dir = tempfile::tempdir().unwrap();
    let (resp_port, http_port) = free_port_pair();
    let server = start(dir.path(), resp_port, http_port, false);

    set_creds(http_port, &mock.url());
    let (token, uid) = anon_login(http_port);

    // Register a device as the current user (user_id derived from the JWT).
    let (s, b) = http(
        http_port,
        "POST",
        "/v1/push/devices",
        &json!({"token":"devtoken-abc","platform":"ios","app_id":"default"}).to_string(),
        Some(&token),
    );
    assert_eq!(s, 200, "register: {b}");

    // Operator send fans out to the user's devices.
    let (s, b) = http(
        http_port,
        "POST",
        "/v1/push/send",
        &json!({
            "subject_id": uid,
            "notification": {
                "title": "Hi",
                "body": "There",
                "interruption_level": "time-sensitive",
                "target_content_id": "question-window",
                "relevance_score": 0.8,
                "filter_criteria": "work",
                "apns": {
                    "priority": 5,
                    "expiration": 1_900_000_000,
                    "collapse_id": "question-user"
                }
            }
        })
        .to_string(),
        Some("rootsecret"),
    );
    assert_eq!(s, 200, "send: {b}");
    assert_eq!(b["enqueued"], 1);

    let got = mock
        .wait_for_request(Duration::from_secs(5))
        .expect("APNs mock should receive a delivery");
    assert_eq!(got.path, "/3/device/devtoken-abc");
    assert!(
        got.authorization.starts_with("bearer "),
        "auth header: {}",
        got.authorization
    );
    assert_eq!(got.apns_topic, "com.example.app");
    assert_eq!(got.apns_push_type, "alert");
    assert_eq!(got.apns_priority, "5");
    assert_eq!(got.apns_expiration, "1900000000");
    assert_eq!(got.apns_collapse_id, "question-user");
    assert_eq!(got.apns_id.len(), 36);
    assert_eq!(
        got.apns_id
            .chars()
            .filter(|character| *character == '-')
            .count(),
        4
    );
    let body: Value = serde_json::from_str(&got.body).unwrap();
    assert_eq!(body["aps"]["alert"]["title"], "Hi");
    assert_eq!(body["aps"]["alert"]["body"], "There");
    assert_eq!(body["aps"]["interruption-level"], "time-sensitive");
    assert_eq!(body["aps"]["target-content-id"], "question-window");
    assert_eq!(body["aps"]["relevance-score"], 0.8);
    assert_eq!(body["aps"]["filter-criteria"], "work");

    // Delivered: the outbox drains and the counter increments.
    let deadline = Instant::now() + Duration::from_secs(3);
    while info_field(resp_port, "push_delivered_total") < 1 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(info_field(resp_port, "push_delivered_total") >= 1);
    drop(server);
}

#[test]
fn push_send_rejects_invalid_interruption_level() {
    let dir = tempfile::tempdir().unwrap();
    let (resp_port, http_port) = free_port_pair();
    let server = start(dir.path(), resp_port, http_port, false);

    let (s, b) = http(
        http_port,
        "POST",
        "/v1/push/send",
        &json!({
            "subject_id": "user-1",
            "notification": {"title": "Hi", "interruption_level": "urgent"}
        })
        .to_string(),
        Some("rootsecret"),
    );
    assert_eq!(s, 400, "invalid interruption level: {b}");
    assert!(
        b.to_string()
            .contains("interruption_level must be passive, active, time-sensitive, or critical"),
        "error response: {b}"
    );
    drop(server);
}

#[test]
fn push_unregistered_token_disables_device() {
    let mock = MockApns::start(410);
    let dir = tempfile::tempdir().unwrap();
    let (resp_port, http_port) = free_port_pair();
    let server = start(dir.path(), resp_port, http_port, false);

    set_creds(http_port, &mock.url());
    let (token, uid) = anon_login(http_port);
    let (s, _) = http(
        http_port,
        "POST",
        "/v1/push/devices",
        &json!({"token":"dead-token","platform":"ios","app_id":"default"}).to_string(),
        Some(&token),
    );
    assert_eq!(s, 200);

    let (s, _) = http(
        http_port,
        "POST",
        "/v1/push/send",
        &json!({"subject_id": uid, "notification": {"title":"x","body":"y"}}).to_string(),
        Some("rootsecret"),
    );
    assert_eq!(s, 200);

    assert!(
        mock.wait_for_request(Duration::from_secs(5)).is_some(),
        "mock should receive the attempt"
    );

    // 410 Unregistered prunes the token: the device disappears from the list.
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let (_, list) = http(http_port, "GET", "/v1/push/devices", "", Some(&token));
        let n = list["devices"].as_array().map(|a| a.len()).unwrap_or(0);
        if n == 0 || Instant::now() >= deadline {
            assert_eq!(n, 0, "unregistered device should be disabled: {list}");
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(server);
}

#[test]
fn push_bad_request_dead_letters_without_disabling_device() {
    let mock = MockApns::start_with_reason(400, r#"{"reason":"BadCollapseId"}"#);
    let dir = tempfile::tempdir().unwrap();
    let (resp_port, http_port) = free_port_pair();
    let server = start(dir.path(), resp_port, http_port, false);

    set_creds(http_port, &mock.url());
    let (token, uid) = anon_login(http_port);
    let (s, b) = http(
        http_port,
        "POST",
        "/v1/push/devices",
        &json!({"token":"healthy-token","platform":"ios","app_id":"default"}).to_string(),
        Some(&token),
    );
    assert_eq!(s, 200, "register: {b}");

    let (s, b) = http(
        http_port,
        "POST",
        "/v1/push/send",
        &json!({"subject_id": uid, "notification": {"title":"Hi"}}).to_string(),
        Some("rootsecret"),
    );
    assert_eq!(s, 200, "send: {b}");
    assert!(
        mock.wait_for_request(Duration::from_secs(5)).is_some(),
        "mock should receive the attempt"
    );

    let deadline = Instant::now() + Duration::from_secs(3);
    let dead = loop {
        let (s, body) = http(
            http_port,
            "GET",
            "/v1/push/admin/outbox",
            "",
            Some("rootsecret"),
        );
        assert_eq!(s, 200, "dead letters: {body}");
        if body["dead_letters"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty())
        {
            break body;
        }
        assert!(
            Instant::now() < deadline,
            "delivery was not dead-lettered: {body}"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        dead["dead_letters"][0]["last_error"]
            .as_str()
            .is_some_and(|error| error.contains("BadCollapseId") && error.contains("apns-id")),
        "dead letter should retain APNs diagnostics: {dead}"
    );

    let (s, devices) = http(http_port, "GET", "/v1/push/devices", "", Some(&token));
    assert_eq!(s, 200, "devices: {devices}");
    assert_eq!(
        devices["devices"].as_array().map(Vec::len),
        Some(1),
        "request errors must not disable a healthy device: {devices}"
    );
    drop(server);
}

#[test]
fn push_devices_scoped_and_reserved_guarded() {
    let dir = tempfile::tempdir().unwrap();
    let (resp_port, http_port) = free_port_pair();
    let server = start(dir.path(), resp_port, http_port, false);

    let (token_a, _uid_a) = anon_login(http_port);
    let (token_b, _uid_b) = anon_login(http_port);

    // User A registers a device; user B cannot see it.
    let (s, _) = http(
        http_port,
        "POST",
        "/v1/push/devices",
        &json!({"token":"a-token","platform":"ios","app_id":"default"}).to_string(),
        Some(&token_a),
    );
    assert_eq!(s, 200);
    let (_, list_a) = http(http_port, "GET", "/v1/push/devices", "", Some(&token_a));
    assert_eq!(list_a["devices"].as_array().unwrap().len(), 1);
    let (_, list_b) = http(http_port, "GET", "/v1/push/devices", "", Some(&token_b));
    assert_eq!(list_b["devices"].as_array().unwrap().len(), 0);

    // The stable token cleanup route is user-scoped: B cannot delete A's
    // device, while A can remove it without knowing the internal device id.
    let (s, deleted) = http(
        http_port,
        "DELETE",
        "/v1/push/devices",
        &json!({"token":"a-token"}).to_string(),
        Some(&token_b),
    );
    assert_eq!(s, 200, "other-user cleanup: {deleted}");
    assert_eq!(deleted["deleted"], false);
    let (_, list_a) = http(http_port, "GET", "/v1/push/devices", "", Some(&token_a));
    assert_eq!(list_a["devices"].as_array().unwrap().len(), 1);

    let (s, deleted) = http(
        http_port,
        "DELETE",
        "/v1/push/devices",
        &json!({"token":"a-token"}).to_string(),
        Some(&token_a),
    );
    assert_eq!(s, 200, "own-token cleanup: {deleted}");
    assert_eq!(deleted["deleted"], true);
    let (_, list_a) = http(http_port, "GET", "/v1/push/devices", "", Some(&token_a));
    assert_eq!(list_a["devices"].as_array().unwrap().len(), 0);

    // Anonymous (no JWT) registration is rejected.
    let (s, _) = http(
        http_port,
        "POST",
        "/v1/push/devices",
        &json!({"token":"x"}).to_string(),
        None,
    );
    assert_eq!(s, 401);

    // Reserved-table guard: clients cannot touch push.devices directly.
    let (_, ins) = exec(
        http_port,
        json!([
            "TINSERT",
            "push.devices",
            "id",
            "hax",
            "subject_id",
            "evil",
            "token",
            "t"
        ]),
    );
    assert!(
        ins["error"].as_str().unwrap_or("").contains("Lux Push"),
        "direct insert should be blocked: {ins}"
    );
    let (_, sel) = exec(http_port, json!(["TSELECT", "*", "FROM", "push.devices"]));
    assert!(
        sel["error"].as_str().unwrap_or("").contains("Lux Push"),
        "direct select should be blocked: {sel}"
    );
    drop(server);
}

#[test]
fn push_registry_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (resp_port, http_port) = free_port_pair();

    // Register via the RESP operator form, then hard-restart on the same dir.
    {
        let server = start(dir.path(), resp_port, http_port, true);
        let reply = resp_cmd(
            resp_port,
            &[
                "LUX",
                "PUSH",
                "REGISTER",
                "11111111-1111-1111-1111-111111111111",
                "persist-token",
                "ios",
                "default",
            ],
        );
        assert!(reply.contains("dev_"), "register reply: {reply}");
        drop(server);
    }

    let (resp_port2, http_port2) = free_port_pair();
    let server = start(dir.path(), resp_port2, http_port2, false);
    let reply = resp_cmd(
        resp_port2,
        &[
            "LUX",
            "PUSH",
            "DEVICES",
            "11111111-1111-1111-1111-111111111111",
        ],
    );
    assert!(
        reply.contains("persist-token") || reply.contains("dev_"),
        "device should survive restart: {reply}"
    );
    drop(server);
}

/// Same as `start` but WITHOUT Lux auth — push is a standalone scope and must
/// work with `LUX_AUTH_ENABLED` unset.
fn start_no_auth(dir: &std::path::Path, resp_port: u16, http_port: u16) -> PushServer {
    let bin = common::find_lux_binary();
    std::fs::create_dir_all(dir).unwrap();
    let mut cmd = common::lux_command(&bin);
    cmd.env("LUX_PORT", resp_port.to_string())
        .env("LUX_HTTP_PORT", http_port.to_string())
        .env("LUX_SHARDS", "4")
        .env("LUX_SAVE_INTERVAL", "0")
        .env("LUX_DATA_DIR", dir.to_str().unwrap())
        .env("LUX_STORAGE_MODE", "tiered")
        .env("LUX_STORAGE_DIR", dir.join("storage").to_str().unwrap())
        .env("LUX_PASSWORD", "rootsecret")
        .env("LUX_ENCRYPTION_KEY_ID", "push-integration")
        .env("LUX_ENCRYPTION_KEY", "push-integration-secret")
        .env("LUX_PUSH_ALLOW_PRIVATE_ENDPOINTS", "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let child = cmd.spawn().expect("spawn lux");
    let server = PushServer {
        child,
        dir: dir.to_path_buf(),
        keep_dir: false,
    };
    for _ in 0..160 {
        if TcpStream::connect(("127.0.0.1", http_port)).is_ok()
            && TcpStream::connect(("127.0.0.1", resp_port)).is_ok()
        {
            std::thread::sleep(Duration::from_millis(150));
            return server;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("lux did not start");
}

/// The Pompeii case: Lux auth OFF, a trusted secret-key caller registers a token
/// under an arbitrary external subject id and sends by it. No Lux users exist.
#[test]
fn push_works_with_auth_disabled_via_secret_key() {
    let mock = MockApns::start(200);
    let dir = tempfile::tempdir().unwrap();
    let (resp_port, http_port) = free_port_pair();
    let server = start_no_auth(dir.path(), resp_port, http_port);

    set_creds(http_port, &mock.url());

    // Operator (secret key) registers a device under an opaque external subject.
    let (s, b) = http(
        http_port,
        "POST",
        "/v1/push/devices",
        &json!({"subject_id":"ext-user-123","token":"tok-ext","platform":"ios","app_id":"default"})
            .to_string(),
        Some("rootsecret"),
    );
    assert_eq!(s, 200, "secret-key register: {b}");

    // A user JWT is NOT available (auth off); anonymous register is rejected.
    let (s, _) = http(
        http_port,
        "POST",
        "/v1/push/devices",
        &json!({"token":"x"}).to_string(),
        None,
    );
    assert_eq!(s, 401);

    // Send by the external subject id.
    let (s, b) = http(
        http_port,
        "POST",
        "/v1/push/send",
        &json!({"subject_id":"ext-user-123","notification":{"title":"Hi","body":"no lux auth"}})
            .to_string(),
        Some("rootsecret"),
    );
    assert_eq!(s, 200, "send: {b}");
    assert_eq!(b["enqueued"], 1);

    let got = mock
        .wait_for_request(Duration::from_secs(5))
        .expect("APNs mock should receive a delivery");
    assert_eq!(got.path, "/3/device/tok-ext");
    drop(server);
}

/// Batch: one send to many subjects enqueues + delivers to each.
#[test]
fn push_batch_send_to_many_subjects() {
    let mock = MockApns::start(200);
    let dir = tempfile::tempdir().unwrap();
    let (resp_port, http_port) = free_port_pair();
    let server = start_no_auth(dir.path(), resp_port, http_port);
    set_creds(http_port, &mock.url());

    for (subj, tok) in [("s1", "tok1"), ("s2", "tok2")] {
        let (s, _) = http(
            http_port,
            "POST",
            "/v1/push/devices",
            &json!({"subject_id":subj,"token":tok,"platform":"ios"}).to_string(),
            Some("rootsecret"),
        );
        assert_eq!(s, 200);
    }

    let (s, b) = http(
        http_port,
        "POST",
        "/v1/push/send",
        &json!({"subject_ids":["s1","s2"],"notification":{"title":"batch","body":"x"}}).to_string(),
        Some("rootsecret"),
    );
    assert_eq!(s, 200, "batch send: {b}");
    assert_eq!(b["enqueued"], 2);

    let deadline = Instant::now() + Duration::from_secs(6);
    while mock.requests.lock().unwrap().len() < 2 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        mock.requests.lock().unwrap().len(),
        2,
        "both subjects should deliver"
    );
    drop(server);
}

/// Web Push: register a browser subscription (platform=web), configure VAPID,
/// send, and assert the mock push service got an aes128gcm + VAPID-authenticated
/// encrypted POST.
#[test]
fn push_web_push_delivers_encrypted() {
    let mock = MockApns::start(201);
    let dir = tempfile::tempdir().unwrap();
    let (resp_port, http_port) = free_port_pair();
    let server = start_no_auth(dir.path(), resp_port, http_port);

    // Configure VAPID. The private key is any valid P-256 PKCS8 PEM (used to
    // sign the JWT); the public key is passed through as the `k=` param.
    let (s, b) = http(
        http_port,
        "POST",
        "/v1/push/credentials",
        &json!({
            "app_id":"default",
            "vapid_public":"BExamplePublicKeyForTestingOnly_notvalidated_1234567890abcdefgh",
            "vapid_private": test_p8(),
            "vapid_subject":"mailto:test@luxdb.dev"
        })
        .to_string(),
        Some("rootsecret"),
    );
    assert_eq!(s, 200, "set vapid: {b}");

    // Public VAPID key endpoint is readable.
    let (s, vk) = http(http_port, "GET", "/v1/push/vapid", "", Some("rootsecret"));
    assert_eq!(s, 200, "get vapid: {vk}");
    assert!(vk["public_key"]
        .as_str()
        .unwrap_or("")
        .starts_with("BExample"));

    // Register a browser subscription as the device token (P-256 keys from the
    // RFC 8291 vector — any valid point works, the mock doesn't decrypt).
    let subscription = json!({
        "endpoint": format!("{}/wp/device-1", mock.url()),
        "keys": {
            "p256dh":"BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
            "auth":"BTBZMqHH6r4Tts7J_aSIgg"
        }
    })
    .to_string();
    let (s, b) = http(
        http_port,
        "POST",
        "/v1/push/devices",
        &json!({"subject_id":"web-user","token":subscription,"platform":"web","app_id":"default"})
            .to_string(),
        Some("rootsecret"),
    );
    assert_eq!(s, 200, "register web device: {b}");

    let (s, b) = http(
        http_port,
        "POST",
        "/v1/push/send",
        &json!({"subject_id":"web-user","notification":{"title":"web","body":"hello browser"}})
            .to_string(),
        Some("rootsecret"),
    );
    assert_eq!(s, 200, "send: {b}");

    let got = mock
        .wait_for_request(Duration::from_secs(5))
        .expect("push service should receive a delivery");
    assert_eq!(got.path, "/wp/device-1");
    assert_eq!(got.content_encoding, "aes128gcm");
    assert!(
        got.authorization.starts_with("vapid t="),
        "VAPID auth header: {}",
        got.authorization
    );
    assert!(got.authorization.contains("k="), "VAPID k= param missing");
    assert!(!got.body.is_empty(), "encrypted body should be non-empty");
    drop(server);
}

/// Item 12: a project has one APNs key but its devices live on two hosts. Apple
/// issues sandbox tokens to development builds and production tokens to
/// TestFlight, both at once while a team is still developing, and a token is
/// only valid against the host that minted it. Before this, a project held a
/// single environment and every send went to that one host, so half the fleet
/// failed with BadDeviceToken depending on which way the toggle was set.
#[test]
fn push_routes_each_device_to_its_own_apns_host() {
    // Two mocks stand in for the two APNs hosts.
    let testflight = MockApns::start(200);
    let development = MockApns::start(200);
    let dir = tempfile::tempdir().unwrap();
    let (resp_port, http_port) = free_port_pair();
    let server = start_no_auth(dir.path(), resp_port, http_port);

    // One credential, pointed at the "production" host. The same .p8 signs for
    // both, so nothing about the credentials forces a single environment.
    set_creds(http_port, &testflight.url());

    // The TestFlight build registers without naming an environment, which is
    // every client written before this existed: it falls back to the credential.
    let (s, b) = http(
        http_port,
        "POST",
        "/v1/push/devices",
        &json!({"subject_id":"dual-env-user","token":"testflight-token",
                "platform":"ios","app_id":"default"})
        .to_string(),
        Some("rootsecret"),
    );
    assert_eq!(s, 200, "register testflight device: {b}");

    // The development build names its own host and must not follow the
    // credential.
    let (s, b) = http(
        http_port,
        "POST",
        "/v1/push/devices",
        &json!({"subject_id":"dual-env-user","token":"development-token",
                "platform":"ios","app_id":"default","environment":development.url()})
        .to_string(),
        Some("rootsecret"),
    );
    assert_eq!(s, 200, "register development device: {b}");

    // One send fans out to both devices.
    let (s, b) = http(
        http_port,
        "POST",
        "/v1/push/send",
        &json!({"subject_id":"dual-env-user","notification":{"title":"both"}}).to_string(),
        Some("rootsecret"),
    );
    assert_eq!(s, 200, "send: {b}");
    assert_eq!(b["enqueued"], 2);

    let to_testflight = testflight
        .wait_for_request(Duration::from_secs(5))
        .expect("the credential host should receive the unlabelled device");
    let to_development = development
        .wait_for_request(Duration::from_secs(5))
        .expect("the device's own host should receive the labelled device");

    // Each token reached its own host, off one set of credentials.
    assert_eq!(to_testflight.path, "/3/device/testflight-token");
    assert_eq!(to_development.path, "/3/device/development-token");
    drop(server);
}

/// The environment is recorded on the device and readable back, and a
/// re-register that omits it does not erase it. A token cannot change hosts, so
/// silence has to mean "unchanged" rather than "reset to the credential".
#[test]
fn push_device_environment_is_recorded_and_sticky() {
    let dir = tempfile::tempdir().unwrap();
    let (resp_port, http_port) = free_port_pair();
    let server = start_no_auth(dir.path(), resp_port, http_port);

    let register = |body: Value| {
        let (s, b) = http(
            http_port,
            "POST",
            "/v1/push/devices",
            &body.to_string(),
            Some("rootsecret"),
        );
        assert_eq!(s, 200, "register: {b}");
    };

    register(
        json!({"subject_id":"env-user","token":"sticky-token","platform":"ios",
                    "app_id":"default","environment":"development"}),
    );

    let environment_of = |token: &str| -> String {
        let (s, b) = http(
            http_port,
            "GET",
            "/v1/push/admin/devices",
            "",
            Some("rootsecret"),
        );
        assert_eq!(s, 200, "admin devices: {b}");
        b["devices"]
            .as_array()
            .expect("devices array")
            .iter()
            .find(|d| d["id"].is_string() && d["subject_id"] == "env-user")
            .map(|d| d["environment"].as_str().unwrap_or("").to_string())
            .unwrap_or_else(|| panic!("no device row for {token}"))
    };

    // "development" is Apple's spelling for the sandbox host.
    assert_eq!(environment_of("sticky-token"), "sandbox");

    // A refresh that omits it keeps the stored value.
    register(
        json!({"subject_id":"env-user","token":"sticky-token","platform":"ios",
                    "app_id":"default"}),
    );
    assert_eq!(environment_of("sticky-token"), "sandbox");

    // An explicit value still updates it.
    register(
        json!({"subject_id":"env-user","token":"sticky-token","platform":"ios",
                    "app_id":"default","environment":"production"}),
    );
    assert_eq!(environment_of("sticky-token"), "production");
    drop(server);
}

/// The delivery worker sends the APNs provider JWT as a bearer token to
/// whichever host the environment resolves to, and that JWT is signed with the
/// team's `.p8` and is good for the whole app. `POST /v1/push/devices` accepts
/// an end user's own session, so a user-supplied host would hand any signed-in
/// user a way to collect it.
#[test]
fn user_session_cannot_redirect_delivery_to_its_own_host() {
    let real = MockApns::start(200);
    let attacker = MockApns::start(200);
    let dir = tempfile::tempdir().unwrap();
    let (resp_port, http_port) = free_port_pair();
    let server = start(dir.path(), resp_port, http_port, false);

    set_creds(http_port, &real.url());
    let (token, uid) = anon_login(http_port);

    // A signed-in user self-registers and tries to name the delivery host.
    let (s, b) = http(
        http_port,
        "POST",
        "/v1/push/devices",
        &json!({"token":"victim-token","platform":"ios","app_id":"default",
                "environment": attacker.url()})
        .to_string(),
        Some(&token),
    );
    assert_eq!(s, 200, "register: {b}");

    let (s, b) = http(
        http_port,
        "POST",
        "/v1/push/send",
        &json!({"subject_id": uid, "notification":{"title":"secret"}}).to_string(),
        Some("rootsecret"),
    );
    assert_eq!(s, 200, "send: {b}");

    // Delivery goes to the project's own credential host, not the one the user
    // named, so no provider token reaches it.
    let got = real
        .wait_for_request(Duration::from_secs(5))
        .expect("the credential host should receive the delivery");
    assert_eq!(got.path, "/3/device/victim-token");
    assert!(
        attacker
            .wait_for_request(Duration::from_millis(750))
            .is_none(),
        "a user-named host received a delivery, leaking the APNs provider token"
    );
    drop(server);
}
