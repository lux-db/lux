use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

mod common;

fn find_lux_binary() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let target_dir = exe.parent()?.parent()?.parent()?;
    let debug = target_dir.join("debug").join("lux");
    if debug.exists() {
        return Some(debug);
    }
    let release = target_dir.join("release").join("lux");
    if release.exists() {
        return Some(release);
    }
    None
}

struct LuxServer {
    child: std::process::Child,
    tmpdir: std::path::PathBuf,
}

impl Drop for LuxServer {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
        let _ = std::fs::remove_dir_all(&self.tmpdir);
    }
}

fn start_lux(resp_port: u16, http_port: u16, password: &str) -> LuxServer {
    start_lux_with_env(resp_port, http_port, password, &[])
}

fn start_lux_with_env(
    resp_port: u16,
    http_port: u16,
    password: &str,
    extra_env: &[(&str, &str)],
) -> LuxServer {
    let tmpdir = std::env::temp_dir().join(format!(
        "lux_http_test_{}_{}",
        std::process::id(),
        http_port
    ));
    std::fs::create_dir_all(&tmpdir).unwrap();
    let child = spawn_lux_with_data_dir(resp_port, http_port, password, extra_env, &tmpdir);
    LuxServer { child, tmpdir }
}

fn spawn_lux_with_data_dir(
    resp_port: u16,
    http_port: u16,
    password: &str,
    extra_env: &[(&str, &str)],
    data_dir: &std::path::Path,
) -> std::process::Child {
    let bin = find_lux_binary().expect("no lux binary found");

    // Wait for the port to be free before starting (previous test may still be releasing it)
    for _ in 0..40 {
        if TcpStream::connect(format!("127.0.0.1:{http_port}")).is_err() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    let mut cmd = common::lux_command(&bin);
    cmd.env("LUX_PORT", resp_port.to_string())
        .env("LUX_HTTP_PORT", http_port.to_string())
        .env("LUX_SHARDS", "4")
        .env("LUX_SAVE_INTERVAL", "0")
        .env("LUX_DATA_DIR", data_dir.to_str().unwrap())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    if !password.is_empty() {
        cmd.env("LUX_PASSWORD", password);
    }
    for (key, value) in extra_env {
        cmd.env(key, value);
    }

    let mut child = cmd.spawn().expect("failed to start lux");

    for _ in 0..60 {
        if TcpStream::connect(format!("127.0.0.1:{http_port}")).is_ok() {
            return child;
        }
        thread::sleep(Duration::from_millis(50));
    }
    common::terminate_child(&mut child);
    panic!("lux http did not start on port {http_port}");
}

fn http_request(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&str>,
    auth: Option<&str>,
) -> (u16, String) {
    http_request_with_headers(port, method, path, body, auth, &[])
}

fn http_request_with_headers(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&str>,
    auth: Option<&str>,
    extra_headers: &[&str],
) -> (u16, String) {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    let body_str = body.unwrap_or("");
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        body_str.len()
    );
    if let Some(token) = auth {
        req.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    for h in extra_headers {
        req.push_str(h);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    req.push_str(body_str);

    stream.write_all(req.as_bytes()).unwrap();

    let mut response = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&buf[..n]);
                if let Some(header_end) = response.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&response[..header_end]);
                    // Content-Length: stop once we have full body
                    if let Some(cl_line) = headers
                        .lines()
                        .find(|l| l.to_lowercase().starts_with("content-length:"))
                    {
                        if let Some(cl) = cl_line
                            .split(':')
                            .nth(1)
                            .and_then(|v| v.trim().parse::<usize>().ok())
                        {
                            if response.len() >= header_end + 4 + cl {
                                break;
                            }
                        }
                    }
                    // Chunked: stop when we see the terminal chunk "0\r\n\r\n"
                    if headers
                        .to_lowercase()
                        .contains("transfer-encoding: chunked")
                        && response.windows(5).any(|w| w == b"0\r\n\r\n")
                    {
                        break;
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(_) => break,
        }
    }

    let resp = String::from_utf8_lossy(&response).to_string();
    let status = resp
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let body = resp
        .split_once("\r\n\r\n")
        .map(|x| x.1)
        .unwrap_or("")
        .to_string();
    (status, body)
}

fn get(port: u16, path: &str, auth: &str) -> String {
    http_request(port, "GET", path, None, Some(auth)).1
}

fn post(port: u16, path: &str, body: &str, auth: &str) -> String {
    http_request(port, "POST", path, Some(body), Some(auth)).1
}

fn put(port: u16, path: &str, body: &str, auth: &str) -> String {
    http_request(port, "PUT", path, Some(body), Some(auth)).1
}

fn patch(port: u16, path: &str, body: &str, auth: &str) -> String {
    http_request(port, "PATCH", path, Some(body), Some(auth)).1
}

fn delete(port: u16, path: &str, auth: &str) -> (u16, String) {
    http_request(port, "DELETE", path, None, Some(auth))
}

#[test]
fn http_health_check() {
    let _server = start_lux(17600, 17601, "");
    let resp = get(17601, "/v1", "");
    assert!(resp.contains("\"lux\""), "health: {resp}");
    assert!(resp.contains("\"version\""), "version: {resp}");
}

#[test]
fn http_auth_required() {
    let _server = start_lux(17602, 17603, "secret");

    let (status, body) = http_request(17603, "GET", "/v1/ping", None, None);
    assert_eq!(status, 401, "no auth: {body}");

    let (status, body) = http_request(17603, "GET", "/v1/ping", None, Some("wrong"));
    assert_eq!(status, 401, "wrong auth: {body}");

    let resp = get(17603, "/v1/ping", "secret");
    assert!(resp.contains("PONG"), "correct auth: {resp}");
}

#[test]
fn http_auth_routes_are_disabled_unless_enabled() {
    let _server = start_lux(17700, 17701, "");

    let (status, body) = http_request(17701, "GET", "/auth/v1/health", None, None);
    assert_eq!(status, 404, "auth should be disabled by default: {body}");
    assert!(body.contains("auth is not enabled"), "{body}");
}

#[test]
fn http_auth_signup_login_user_logout_and_admin_routes() {
    let _server = start_lux_with_env(17702, 17703, "rootsecret", &[("LUX_AUTH_ENABLED", "true")]);

    let (status, health) = http_request(17703, "GET", "/auth/v1/health", None, None);
    assert_eq!(status, 200, "health: {health}");

    let (status, signup_body) = http_request(
        17703,
        "POST",
        "/auth/v1/signup",
        Some(r#"{"email":"http-auth@example.com","password":"password123"}"#),
        None,
    );
    assert_eq!(status, 200, "signup: {signup_body}");
    let signup_json: serde_json::Value = serde_json::from_str(&signup_body).unwrap();
    let signup_access = signup_json["access_token"]
        .as_str()
        .expect("signup should return access token");
    assert_eq!(signup_json["user"]["email"], "http-auth@example.com");

    let (status, user_body) =
        http_request(17703, "GET", "/auth/v1/user", None, Some(signup_access));
    assert_eq!(status, 200, "user: {user_body}");
    assert!(user_body.contains("http-auth@example.com"), "{user_body}");

    let (status, login_body) = http_request(
        17703,
        "POST",
        "/auth/v1/token",
        Some(
            r#"{"grant_type":"password","email":"http-auth@example.com","password":"password123"}"#,
        ),
        None,
    );
    assert_eq!(status, 200, "login: {login_body}");
    let login_json: serde_json::Value = serde_json::from_str(&login_body).unwrap();
    let login_access = login_json["access_token"]
        .as_str()
        .expect("login should return access token");
    let refresh_token = login_json["refresh_token"]
        .as_str()
        .expect("login should return refresh token");

    let (status, refresh_body) = http_request(
        17703,
        "POST",
        "/auth/v1/token",
        Some(&format!(
            r#"{{"grant_type":"refresh_token","refresh_token":"{}"}}"#,
            refresh_token
        )),
        None,
    );
    assert_eq!(status, 200, "refresh: {refresh_body}");

    let (status, admin_body) = http_request(
        17703,
        "GET",
        "/auth/v1/admin/users",
        None,
        Some("rootsecret"),
    );
    assert_eq!(status, 200, "admin users: {admin_body}");
    assert!(admin_body.contains("http-auth@example.com"), "{admin_body}");
    let admin_json: serde_json::Value = serde_json::from_str(&admin_body).unwrap();
    let user_id = admin_json["users"][0]["id"]
        .as_str()
        .expect("admin users should include id");

    let (status, grant_body) = http_request(
        17703,
        "POST",
        "/auth/v1/admin/grants",
        Some(&format!(
            r#"{{"user_id":"{}","capability":"live.channel.room:*"}}"#,
            user_id
        )),
        Some("rootsecret"),
    );
    assert_eq!(status, 200, "grant: {grant_body}");
    let grant_json: serde_json::Value = serde_json::from_str(&grant_body).unwrap();
    let grant_id = grant_json["grant"]["id"]
        .as_str()
        .expect("grant should include id");

    let (status, grants_body) = http_request(
        17703,
        "GET",
        &format!("/auth/v1/admin/users/{user_id}/grants"),
        None,
        Some("rootsecret"),
    );
    assert_eq!(status, 200, "list grants: {grants_body}");
    assert!(grants_body.contains("live.channel.room:*"), "{grants_body}");

    let (status, revoke_body) = http_request(
        17703,
        "DELETE",
        &format!("/auth/v1/admin/grants/{grant_id}"),
        None,
        Some("rootsecret"),
    );
    assert_eq!(status, 200, "revoke grant: {revoke_body}");

    let (status, grants_body) = http_request(
        17703,
        "GET",
        &format!("/auth/v1/admin/users/{user_id}/grants"),
        None,
        Some("rootsecret"),
    );
    assert_eq!(status, 200, "list grants after revoke: {grants_body}");
    assert!(
        !grants_body.contains("live.channel.room:*"),
        "revoked grant should not be active: {grants_body}"
    );

    let (status, table_body) = http_request(
        17703,
        "GET",
        "/v1/tables/auth.users",
        None,
        Some("rootsecret"),
    );
    assert_eq!(status, 403, "auth tables should be hidden: {table_body}");
    assert!(table_body.contains("managed by Lux Auth"), "{table_body}");

    let (status, logout_body) = http_request(
        17703,
        "POST",
        "/auth/v1/logout",
        Some(&format!(r#"{{"refresh_token":"{}"}}"#, refresh_token)),
        None,
    );
    assert_eq!(status, 200, "logout: {logout_body}");

    let (status, user_body) = http_request(17703, "GET", "/auth/v1/user", None, Some(login_access));
    assert_eq!(
        status, 401,
        "revoked login access token should not authenticate: {user_body}"
    );

    let (status, refresh_body) = http_request(
        17703,
        "POST",
        "/auth/v1/token",
        Some(&format!(
            r#"{{"grant_type":"refresh_token","refresh_token":"{}"}}"#,
            refresh_token
        )),
        None,
    );
    assert_eq!(
        status, 401,
        "revoked refresh token should not refresh: {refresh_body}"
    );
}

#[test]
fn http_auth_grants_gate_data_apis() {
    let _server = start_lux_with_env(17704, 17705, "rootsecret", &[("LUX_AUTH_ENABLED", "true")]);

    let (status, signup_body) = http_request(
        17705,
        "POST",
        "/auth/v1/signup",
        Some(r#"{"email":"http-data@example.com","password":"password123"}"#),
        None,
    );
    assert_eq!(status, 200, "signup: {signup_body}");
    let signup_json: serde_json::Value = serde_json::from_str(&signup_body).unwrap();
    let access_token = signup_json["access_token"]
        .as_str()
        .expect("signup should return access token");
    let user_id = signup_json["user"]["id"]
        .as_str()
        .expect("signup should return user id");

    let (status, body) = http_request(17705, "GET", "/v1/kv/doc:1", None, None);
    assert_eq!(status, 401, "anonymous data read should be denied: {body}");

    let (status, body) = http_request(17705, "GET", "/v1/kv/doc:1", None, Some(access_token));
    assert_eq!(status, 403, "ungranted kv read should be denied: {body}");
    assert!(body.contains("kv.doc:1.read"), "{body}");

    let (status, body) = http_request(
        17705,
        "PUT",
        "/v1/kv/doc:1",
        Some(r#"{"value":"hello"}"#),
        Some(access_token),
    );
    assert_eq!(status, 403, "ungranted kv write should be denied: {body}");

    for capability in [
        "kv.doc:1.write",
        "kv.doc:1.read",
        "table.messages.write",
        "table.messages.read",
        "ts.cpu:host1.write",
        "ts.cpu:host1.read",
        "vector.write",
        "vector.read",
        "vector.search",
    ] {
        let (status, body) = http_request(
            17705,
            "POST",
            "/auth/v1/admin/grants",
            Some(&format!(
                r#"{{"user_id":"{}","capability":"{}"}}"#,
                user_id, capability
            )),
            Some("rootsecret"),
        );
        assert_eq!(status, 200, "grant {capability}: {body}");
    }

    let (status, body) = http_request(
        17705,
        "PUT",
        "/v1/kv/doc:1",
        Some(r#"{"value":"hello"}"#),
        Some(access_token),
    );
    assert_eq!(status, 200, "granted kv write: {body}");
    assert!(body.contains("\"OK\""), "{body}");

    let (status, body) = http_request(17705, "GET", "/v1/kv/doc:1", None, Some(access_token));
    assert_eq!(status, 200, "granted kv read: {body}");
    assert!(body.contains("\"hello\""), "{body}");

    let (status, body) = http_request(
        17705,
        "POST",
        "/v1/tables",
        Some(r#"{"name":"messages","columns":["body STR","channel STR"]}"#),
        Some("rootsecret"),
    );
    assert_eq!(status, 200, "operator table create: {body}");

    let (status, body) = http_request(
        17705,
        "POST",
        "/v1/tables/messages",
        Some(r#"{"body":"hello","channel":"general"}"#),
        Some(access_token),
    );
    assert_eq!(status, 200, "granted table write: {body}");

    let (status, body) = http_request(
        17705,
        "GET",
        "/v1/tables/messages",
        None,
        Some(access_token),
    );
    assert_eq!(status, 200, "granted table read: {body}");
    assert!(body.contains("hello"), "{body}");

    let (status, body) = http_request(
        17705,
        "POST",
        "/v1/ts/cpu:host1",
        Some(r#"{"timestamp":"1000","value":72.5,"labels":{"host":"server1"}}"#),
        Some(access_token),
    );
    assert_eq!(status, 200, "granted timeseries write: {body}");

    let (status, body) = http_request(
        17705,
        "GET",
        "/v1/ts/cpu:host1/latest",
        None,
        Some(access_token),
    );
    assert_eq!(status, 200, "granted timeseries read: {body}");
    assert!(body.contains("72.5"), "{body}");

    let (status, body) = http_request(
        17705,
        "POST",
        "/v1/vectors/doc:1",
        Some(r#"{"vector":[0.1,0.2,0.3],"metadata":{"title":"hello"}}"#),
        Some(access_token),
    );
    assert_eq!(status, 200, "granted vector write: {body}");

    let (status, body) = http_request(
        17705,
        "POST",
        "/v1/vectors/search",
        Some(r#"{"vector":[0.1,0.2,0.3],"k":1}"#),
        Some(access_token),
    );
    assert_eq!(status, 200, "granted vector search: {body}");
    assert!(body.contains("doc:1"), "{body}");

    let (status, body) = http_request(17705, "GET", "/v1/vectors/doc:1", None, Some(access_token));
    assert_eq!(status, 200, "granted vector read: {body}");
    assert!(body.contains("0.1"), "{body}");

    let (status, body) = http_request(
        17705,
        "POST",
        "/auth/v1/logout",
        Some("{}"),
        Some(access_token),
    );
    assert_eq!(status, 200, "logout: {body}");

    let (status, body) = http_request(17705, "GET", "/v1/kv/doc:1", None, Some(access_token));
    assert_eq!(
        status, 401,
        "revoked access token should not reach granted data API: {body}"
    );
}

#[test]
fn http_auth_sessions_grants_keys_and_revocation_survive_restart() {
    let data_dir = tempfile::tempdir().unwrap();
    let first_env = [
        ("LUX_AUTH_ENABLED", "true"),
        ("LUX_STORAGE_MODE", "tiered"),
        ("LUX_AUTH_PUBLISHABLE_KEY", "lux_pub_persist"),
        ("LUX_AUTH_SECRET_KEY", "lux_sec_persist"),
    ];
    let auth_only_env = [("LUX_AUTH_ENABLED", "true"), ("LUX_STORAGE_MODE", "tiered")];

    let mut child =
        spawn_lux_with_data_dir(17706, 17707, "rootsecret", &first_env, data_dir.path());

    let (status, signup_body) = http_request_with_headers(
        17707,
        "POST",
        "/auth/v1/signup",
        Some(r#"{"email":"persist-auth@example.com","password":"password123"}"#),
        None,
        &["apikey: lux_pub_persist"],
    );
    assert_eq!(status, 200, "signup: {signup_body}");
    let signup_json: serde_json::Value = serde_json::from_str(&signup_body).unwrap();
    let access_token = signup_json["access_token"]
        .as_str()
        .expect("signup should return access token")
        .to_string();
    let refresh_token = signup_json["refresh_token"]
        .as_str()
        .expect("signup should return refresh token")
        .to_string();
    let user_id = signup_json["user"]["id"]
        .as_str()
        .expect("signup should return user id")
        .to_string();

    for capability in ["kv.persist.write", "kv.persist.read"] {
        let (status, body) = http_request(
            17707,
            "POST",
            "/auth/v1/admin/grants",
            Some(&format!(
                r#"{{"user_id":"{}","capability":"{}"}}"#,
                user_id, capability
            )),
            Some("lux_sec_persist"),
        );
        assert_eq!(status, 200, "grant {capability}: {body}");
    }

    let (status, body) = http_request(
        17707,
        "PUT",
        "/v1/kv/persist",
        Some(r#"{"value":"survived"}"#),
        Some(&access_token),
    );
    assert_eq!(status, 200, "granted write before restart: {body}");

    common::terminate_child(&mut child);

    let mut child =
        spawn_lux_with_data_dir(17706, 17707, "rootsecret", &auth_only_env, data_dir.path());

    let (status, body) = http_request(17707, "GET", "/auth/v1/user", None, Some(&access_token));
    assert_eq!(
        status, 200,
        "access token should validate after restart via persisted signing key/session: {body}"
    );
    assert!(body.contains("persist-auth@example.com"), "{body}");

    let (status, body) = http_request(17707, "GET", "/v1/kv/persist", None, Some(&access_token));
    assert_eq!(
        status, 200,
        "persisted grants should authorize data API after restart: {body}"
    );
    assert!(body.contains("survived"), "{body}");

    let (status, body) = http_request(
        17707,
        "GET",
        "/auth/v1/admin/users",
        None,
        Some("lux_sec_persist"),
    );
    assert_eq!(
        status, 200,
        "persisted secret api key should authorize admin route without config reseed: {body}"
    );

    let (status, body) = http_request_with_headers(
        17707,
        "POST",
        "/auth/v1/token",
        Some(&format!(
            r#"{{"grant_type":"refresh_token","refresh_token":"{}"}}"#,
            refresh_token
        )),
        None,
        &["apikey: lux_pub_persist"],
    );
    assert_eq!(
        status, 200,
        "persisted publishable api key and refresh session should work after restart: {body}"
    );

    let (status, body) = http_request(
        17707,
        "POST",
        "/auth/v1/logout",
        Some("{}"),
        Some(&access_token),
    );
    assert_eq!(status, 200, "logout after restart: {body}");

    common::terminate_child(&mut child);

    let mut child =
        spawn_lux_with_data_dir(17706, 17707, "rootsecret", &auth_only_env, data_dir.path());

    let (status, body) = http_request(17707, "GET", "/auth/v1/user", None, Some(&access_token));
    assert_eq!(
        status, 401,
        "revoked access token should stay revoked after restart: {body}"
    );

    let (status, body) = http_request_with_headers(
        17707,
        "POST",
        "/auth/v1/token",
        Some(&format!(
            r#"{{"grant_type":"refresh_token","refresh_token":"{}"}}"#,
            refresh_token
        )),
        None,
        &["apikey: lux_pub_persist"],
    );
    assert_eq!(
        status, 401,
        "revoked refresh session should stay revoked after restart: {body}"
    );

    common::terminate_child(&mut child);
}

#[test]
fn http_set_get_del() {
    let _server = start_lux(17604, 17605, "");

    let resp = post(17605, "/v1/set/mykey", r#"{"value":"hello"}"#, "");
    assert!(resp.contains("\"OK\""), "set: {resp}");

    let resp = get(17605, "/v1/get/mykey", "");
    assert!(resp.contains("\"hello\""), "get: {resp}");

    let resp = post(17605, "/v1/del/mykey", "", "");
    assert!(resp.contains("1"), "del: {resp}");

    let resp = get(17605, "/v1/get/mykey", "");
    assert!(resp.contains("null"), "get after del: {resp}");
}

#[test]
fn http_incr_decr() {
    let _server = start_lux(17606, 17607, "");

    let resp = post(17607, "/v1/incr/counter", "", "");
    assert!(resp.contains("1"), "incr: {resp}");

    let resp = post(17607, "/v1/incr/counter", "", "");
    assert!(resp.contains("2"), "incr2: {resp}");

    let resp = post(17607, "/v1/decr/counter", "", "");
    assert!(resp.contains("1"), "decr: {resp}");
}

#[test]
fn http_exec_arbitrary() {
    let _server = start_lux(17608, 17609, "");

    let resp = post(17609, "/v1/exec", r#"{"command":["SET","foo","bar"]}"#, "");
    assert!(resp.contains("\"OK\""), "exec set: {resp}");

    let resp = post(17609, "/v1/exec", r#"{"command":"GET foo"}"#, "");
    assert!(resp.contains("\"bar\""), "exec get: {resp}");

    let resp = post(
        17609,
        "/v1/exec",
        r#"{"command":["HSET","h1","f1","v1","f2","v2"]}"#,
        "",
    );
    assert!(resp.contains("2"), "exec hset: {resp}");

    let resp = post(17609, "/v1/exec", r#"{"command":["HGETALL","h1"]}"#, "");
    assert!(resp.contains("f1"), "exec hgetall: {resp}");
    assert!(resp.contains("v1"), "exec hgetall val: {resp}");
}

#[test]
fn http_exec_tables() {
    let _server = start_lux(17610, 17611, "");

    let resp = post(
        17611,
        "/v1/exec",
        r#"{"command":["TCREATE","users","name","STR,","age","INT"]}"#,
        "",
    );
    assert!(resp.contains("\"OK\""), "tcreate: {resp}");

    let resp = post(
        17611,
        "/v1/exec",
        r#"{"command":["TINSERT","users","name","Alice","age","28"]}"#,
        "",
    );
    assert!(resp.contains("1"), "tinsert: {resp}");

    let resp = post(
        17611,
        "/v1/exec",
        r#"{"command":["TSELECT","*","FROM","users"]}"#,
        "",
    );
    assert!(resp.contains("Alice"), "tselect: {resp}");
}

#[test]
fn http_cors_options() {
    let _server = start_lux(17612, 17613, "secret");
    let (status, _) = http_request(17613, "OPTIONS", "/v1/exec", None, None);
    assert_eq!(status, 204, "options should return 204");
}

#[test]
fn http_tables_content_range() {
    let _server = start_lux(17630, 17631, "");

    post(
        17631,
        "/v1/tables",
        r#"{"name":"items","columns":["name STR","score INT"]}"#,
        "",
    );
    for i in 1..=10 {
        post(
            17631,
            "/v1/tables/items",
            &format!(r#"{{"name":"item{}","score":"{}"}}"#, i, i * 10),
            "",
        );
    }

    // Read full raw HTTP response including headers using a longer timeout
    let read_raw = |path: &str, extra: &[&str]| -> String {
        use std::io::{Read, Write};
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", 17631)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n");
        for h in extra {
            req.push_str(h);
            req.push_str("\r\n");
        }
        req.push_str("\r\n");
        stream.write_all(req.as_bytes()).unwrap();
        let mut data = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => data.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&data).to_string()
    };

    let extract_headers =
        |raw: &str| -> String { raw.split("\r\n\r\n").next().unwrap_or("").to_string() };

    // No WHERE - total should be exact (free via zcard)
    let raw = read_raw("/v1/tables/items", &[]);
    let hdrs = extract_headers(&raw);
    assert!(
        hdrs.contains("Content-Range: 0-9/10"),
        "no-where should have exact total: {hdrs}"
    );

    // With LIMIT - range end should match limit
    let raw = read_raw("/v1/tables/items?limit=3", &[]);
    let hdrs = extract_headers(&raw);
    assert!(
        hdrs.contains("Content-Range: 0-2/10"),
        "limit=3 should have Content-Range 0-2/10: {hdrs}"
    );

    // With OFFSET+LIMIT - range should reflect offset
    let raw = read_raw("/v1/tables/items?limit=3&offset=5", &[]);
    let hdrs = extract_headers(&raw);
    assert!(
        hdrs.contains("Content-Range: 5-7/10"),
        "offset=5 limit=3 should have 5-7/10: {hdrs}"
    );

    // With WHERE no Prefer - total should be *
    let raw = read_raw("/v1/tables/items?where=score+>+50", &[]);
    let hdrs = extract_headers(&raw);
    assert!(
        hdrs.contains("Content-Range:") && hdrs.contains("/*"),
        "where without prefer should have *: {hdrs}"
    );

    // With WHERE and Prefer: count=exact - total should be exact (not *)
    let raw = read_raw(
        "/v1/tables/items?where=score+>+50",
        &["Prefer: count=exact"],
    );
    let hdrs = extract_headers(&raw);
    assert!(
        hdrs.contains("Content-Range:") && !hdrs.contains("/*"),
        "where with count=exact should have exact total: {hdrs}"
    );
}

#[test]
fn http_kv_crud() {
    let _server = start_lux(17616, 17617, "");

    let resp = put(17617, "/v1/kv/mykey", r#"{"value":"hello"}"#, "");
    assert!(resp.contains("\"OK\""), "put: {resp}");

    let resp = get(17617, "/v1/kv/mykey", "");
    assert!(resp.contains("\"hello\""), "get: {resp}");

    let resp = post(17617, "/v1/kv/mykey/incr", "", "");
    assert!(
        resp.contains("error"),
        "incr on string should error: {resp}"
    );

    let (status, body) = delete(17617, "/v1/kv/mykey", "");
    assert_eq!(status, 200, "delete status");
    assert!(body.contains("1"), "delete: {body}");

    let resp = get(17617, "/v1/kv/mykey", "");
    assert!(resp.contains("null"), "get after delete: {resp}");
}

#[test]
fn http_kv_incr_decr() {
    let _server = start_lux(17618, 17619, "");

    let resp = post(17619, "/v1/kv/counter/incr", "", "");
    assert!(resp.contains("1"), "incr: {resp}");
    let resp = post(17619, "/v1/kv/counter/incr", "", "");
    assert!(resp.contains("2"), "incr2: {resp}");
    let resp = post(17619, "/v1/kv/counter/decr", "", "");
    assert!(resp.contains("1"), "decr: {resp}");
}

#[test]
fn http_tables_rest() {
    let _server = start_lux(17620, 17621, "");

    let resp = post(
        17621,
        "/v1/tables",
        r#"{"name":"users","columns":["name STR","age INT"]}"#,
        "",
    );
    assert!(resp.contains("\"OK\""), "create table: {resp}");

    let resp = get(17621, "/v1/tables", "");
    assert!(resp.contains("users"), "list tables: {resp}");

    let resp = post(
        17621,
        "/v1/tables/users",
        r#"{"name":"Alice","age":"28"}"#,
        "",
    );
    assert!(resp.contains("1"), "insert: {resp}");

    let resp = post(
        17621,
        "/v1/tables/users",
        r#"{"name":"Bob","age":"35"}"#,
        "",
    );
    assert!(resp.contains("2"), "insert2: {resp}");

    let resp = get(17621, "/v1/tables/users", "");
    assert!(resp.contains("Alice"), "query all: {resp}");
    assert!(resp.contains("Bob"), "query all bob: {resp}");

    let resp = get(17621, "/v1/tables/users?where=id+%3D+1", "");
    assert!(resp.contains("Alice"), "get by id: {resp}");

    let resp = patch(
        17621,
        "/v1/tables/users?where=id+%3D+1",
        r#"{"name":"Alicia"}"#,
        "",
    );
    assert!(resp.contains("1"), "update: {resp}");

    let resp = get(17621, "/v1/tables/users?where=id+%3D+1", "");
    assert!(resp.contains("Alicia"), "get after update: {resp}");

    let resp = get(17621, "/v1/tables/users?where=age+>+30", "");
    assert!(resp.contains("Bob"), "query where: {resp}");
    assert!(!resp.contains("Alicia"), "query where excludes: {resp}");

    let resp = get(17621, "/v1/tables/users/count", "");
    assert!(resp.contains("2"), "count: {resp}");

    let resp = get(17621, "/v1/tables/users/schema", "");
    assert!(resp.contains("name"), "schema: {resp}");
    assert!(resp.contains("age"), "schema age: {resp}");

    let (status, _) = delete(17621, "/v1/tables/users?where=id+%3D+1", "");
    assert_eq!(status, 200, "delete row");

    let resp = get(17621, "/v1/tables/users/count", "");
    assert!(resp.contains("1"), "count after delete: {resp}");
}

#[test]
fn http_timeseries_rest() {
    let _server = start_lux(17622, 17623, "");

    let resp = post(
        17623,
        "/v1/ts/cpu:host1",
        r#"{"timestamp":"1000","value":72.5,"labels":{"host":"server1","metric":"cpu"}}"#,
        "",
    );
    assert!(resp.contains("result"), "tsadd: {resp}");

    let resp = post(
        17623,
        "/v1/ts/cpu:host1",
        r#"{"timestamp":"2000","value":75.0}"#,
        "",
    );
    assert!(resp.contains("result"), "tsadd2: {resp}");

    let resp = post(
        17623,
        "/v1/ts/cpu:host1",
        r#"{"timestamp":"3000","value":68.2}"#,
        "",
    );
    assert!(resp.contains("result"), "tsadd3: {resp}");

    let resp = get(17623, "/v1/ts/cpu:host1/latest", "");
    assert!(resp.contains("68.2"), "tsget latest: {resp}");

    let resp = get(17623, "/v1/ts/cpu:host1", "");
    assert!(resp.contains("72.5"), "tsrange: {resp}");
    assert!(resp.contains("75"), "tsrange2: {resp}");

    let resp = get(17623, "/v1/ts/cpu:host1?from=1000&to=2000", "");
    assert!(resp.contains("72.5"), "tsrange from/to: {resp}");

    let resp = get(17623, "/v1/ts/cpu:host1/info", "");
    assert!(resp.contains("result"), "tsinfo: {resp}");
}

#[test]
fn http_vectors_rest() {
    let _server = start_lux(17624, 17625, "");

    let resp = post(
        17625,
        "/v1/vectors/doc:1",
        r#"{"vector":[0.1,0.2,0.3],"metadata":{"title":"hello"}}"#,
        "",
    );
    assert!(resp.contains("result"), "vset: {resp}");

    let resp = post(
        17625,
        "/v1/vectors/doc:2",
        r#"{"vector":[0.9,0.1,0.0],"metadata":{"title":"other"}}"#,
        "",
    );
    assert!(resp.contains("result"), "vset2: {resp}");

    let resp = get(17625, "/v1/vectors/doc:1", "");
    assert!(resp.contains("0.1"), "vget: {resp}");

    let resp = get(17625, "/v1/vectors", "");
    assert!(resp.contains("2"), "vcard: {resp}");

    let resp = post(
        17625,
        "/v1/vectors/search",
        r#"{"vector":[0.1,0.2,0.3],"k":2}"#,
        "",
    );
    assert!(resp.contains("doc:1"), "vsearch: {resp}");

    let (status, _) = delete(17625, "/v1/vectors/doc:2", "");
    assert_eq!(status, 200, "delete vector");

    let resp = get(17625, "/v1/vectors", "");
    assert!(resp.contains("1"), "vcard after delete: {resp}");
}

#[test]
fn http_kv_data_types() {
    let _server = start_lux(17626, 17627, "");

    post(
        17627,
        "/v1/exec",
        r#"{"command":["HSET","myhash","f1","v1","f2","v2"]}"#,
        "",
    );
    let resp = get(17627, "/v1/kv/myhash/hash", "");
    assert!(resp.contains("f1"), "hash: {resp}");
    assert!(resp.contains("v1"), "hash val: {resp}");

    post(
        17627,
        "/v1/exec",
        r#"{"command":["RPUSH","mylist","a","b","c"]}"#,
        "",
    );
    let resp = get(17627, "/v1/kv/mylist/list", "");
    assert!(resp.contains("\"a\""), "list: {resp}");
    assert!(resp.contains("\"c\""), "list c: {resp}");

    post(
        17627,
        "/v1/exec",
        r#"{"command":["SADD","myset","x","y","z"]}"#,
        "",
    );
    let resp = get(17627, "/v1/kv/myset/set", "");
    assert!(resp.contains("\"x\""), "set: {resp}");

    post(
        17627,
        "/v1/exec",
        r#"{"command":["ZADD","myzset","1","a","2","b","3","c"]}"#,
        "",
    );
    let resp = get(17627, "/v1/kv/myzset/zset", "");
    assert!(resp.contains("\"a\""), "zset: {resp}");
    assert!(resp.contains("\"b\""), "zset b: {resp}");
}

#[test]
fn http_tables_constraint_errors() {
    let _server = start_lux(17628, 17629, "");

    // Create table with unique constraint
    post(
        17629,
        "/v1/tables",
        r#"{"name":"users","columns":["email STR UNIQUE","name STR"]}"#,
        "",
    );

    // Insert first row
    let resp = post(
        17629,
        "/v1/tables/users",
        r#"{"email":"alice@test.com","name":"alice"}"#,
        "",
    );
    assert!(resp.contains("1"), "first insert: {resp}");

    // Insert duplicate unique value - should return error body, not 500
    let resp = post(
        17629,
        "/v1/tables/users",
        r#"{"email":"alice@test.com","name":"alice2"}"#,
        "",
    );
    assert!(
        resp.contains("error"),
        "duplicate unique should return error body: {resp}"
    );
    assert!(
        !resp.contains("\"result\":2"),
        "duplicate should not succeed: {resp}"
    );

    // PATCH update to duplicate unique value - should error
    let resp = patch(
        17629,
        "/v1/tables/users?where=name+%3D+alice2",
        r#"{"email":"alice@test.com"}"#,
        "",
    );
    assert!(
        resp.contains("error") || resp.contains("0"),
        "patch to duplicate unique should error or return 0: {resp}"
    );

    // Insert with invalid type - should return error body
    post(
        17629,
        "/v1/tables",
        r#"{"name":"scores","columns":["val INT"]}"#,
        "",
    );
    let resp = post(17629, "/v1/tables/scores", r#"{"val":"notanumber"}"#, "");
    assert!(
        resp.contains("error"),
        "type error should return error body: {resp}"
    );

    // PATCH with where that matches nothing - should return result:0 not error
    post(
        17629,
        "/v1/tables",
        r#"{"name":"items","columns":["name STR"]}"#,
        "",
    );
    post(17629, "/v1/tables/items", r#"{"name":"widget"}"#, "");
    let resp = patch(
        17629,
        "/v1/tables/items?where=name+%3D+nobody",
        r#"{"name":"new"}"#,
        "",
    );
    assert!(
        resp.contains("0") || resp.contains("result"),
        "patch no match should return 0: {resp}"
    );

    // DELETE with where that matches nothing - should return result:0 not error
    let (status, resp) = delete(17629, "/v1/tables/items?where=name+%3D+nobody", "");
    assert_eq!(status, 200, "delete no match should be 200: {resp}");
    assert!(
        resp.contains("0") || resp.contains("result"),
        "delete no match should return 0: {resp}"
    );
}
