mod common;
use common::{send_and_read, LuxServer};
use std::io::Write;

// Raw-KV access to the internal `_t:` namespace (where auth rows live --
// password hashes, the JWT signing key, OAuth secrets) is reserved, for reads
// as well as writes, and on the batched pipeline path as well as the generic
// dispatch. Regression coverage for that guard, which was previously untested
// on the read/pipeline path. A bypass would return row data / empty arrays
// instead of the reserved-namespace error.
#[test]
fn pipelined_raw_kv_read_of_auth_keys_is_blocked() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let mut batch = common::resp_cmd(&["HGETALL", "_t:auth.users:row:x"]);
    batch.extend_from_slice(&common::resp_cmd(&[
        "HGET",
        "_t:auth.signing_keys:row:1",
        "private_key_encrypted",
    ]));
    conn.write_all(&batch).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(100));
    let resp = common::read_all(&mut conn);

    let blocked = resp.matches("reserved internal namespace").count();
    assert!(
        blocked >= 2,
        "both pipelined auth-key reads must be blocked, got: {resp:?}"
    );
}

// Same protection on a single (non-pipelined) read.
#[test]
fn raw_kv_read_of_auth_key_is_blocked() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    let resp = send_and_read(&mut conn, &["HGETALL", "_t:auth.users:row:x"]);
    assert!(
        resp.contains("reserved internal namespace"),
        "auth-key read must be refused, got: {resp:?}"
    );
}

#[test]
fn commands_rejected_without_auth() {
    let server = LuxServer::builder().password("secret123").start();
    let mut conn = server.conn();

    let resp = send_and_read(&mut conn, &["SET", "k", "v"]);
    assert!(resp.contains("NOAUTH"), "should reject: {resp}");

    let resp = send_and_read(&mut conn, &["GET", "k"]);
    assert!(resp.contains("NOAUTH"), "still rejected: {resp}");
}

#[test]
fn ping_allowed_without_auth() {
    let server = LuxServer::builder().password("secret123").start();
    let mut conn = server.conn();

    let resp = send_and_read(&mut conn, &["PING"]);
    assert!(resp.contains("PONG"), "PING allowed: {resp}");
}

#[test]
fn auth_wrong_password_rejected() {
    let server = LuxServer::builder().password("secret123").start();
    let mut conn = server.conn();

    let resp = send_and_read(&mut conn, &["AUTH", "wrongpass"]);
    assert!(resp.contains("WRONGPASS"), "bad password: {resp}");

    let resp = send_and_read(&mut conn, &["SET", "k", "v"]);
    assert!(resp.contains("NOAUTH"), "still locked out: {resp}");
}

#[test]
fn auth_correct_password_allows_commands() {
    let server = LuxServer::builder().password("secret123").start();
    let mut conn = server.conn();

    let resp = send_and_read(&mut conn, &["AUTH", "secret123"]);
    assert!(resp.contains("+OK"), "auth success: {resp}");

    let resp = send_and_read(&mut conn, &["SET", "k", "v"]);
    assert!(resp.contains("+OK"), "command works after auth: {resp}");

    let resp = send_and_read(&mut conn, &["GET", "k"]);
    assert!(resp.contains("v"), "value readable: {resp}");
}

#[test]
fn auth_is_per_connection() {
    let server = LuxServer::builder().password("secret123").start();
    let mut conn1 = server.conn();
    let mut conn2 = server.conn();

    send_and_read(&mut conn1, &["AUTH", "secret123"]);
    send_and_read(&mut conn1, &["SET", "k", "fromconn1"]);

    let resp = send_and_read(&mut conn2, &["GET", "k"]);
    assert!(resp.contains("NOAUTH"), "conn2 not authenticated: {resp}");

    send_and_read(&mut conn2, &["AUTH", "secret123"]);
    let resp = send_and_read(&mut conn2, &["GET", "k"]);
    assert!(
        resp.contains("fromconn1"),
        "conn2 can read after auth: {resp}"
    );
}

#[test]
fn auth_missing_args() {
    let server = LuxServer::builder().password("secret123").start();
    let mut conn = server.conn();

    let resp = send_and_read(&mut conn, &["AUTH"]);
    assert!(
        resp.contains("ERR wrong number"),
        "AUTH needs password arg: {resp}"
    );
}

#[test]
fn hello_allowed_without_auth() {
    let server = LuxServer::builder().password("secret123").start();
    let mut conn = server.conn();

    let resp = send_and_read(&mut conn, &["HELLO"]);
    assert!(resp.contains("lux"), "HELLO allowed pre-auth: {resp}");
}

#[test]
fn hello_with_auth_authenticates() {
    let server = LuxServer::builder().password("secret123").start();
    let mut conn = server.conn();

    let resp = send_and_read(&mut conn, &["HELLO", "2", "AUTH", "default", "secret123"]);
    assert!(resp.contains("lux"), "HELLO returns server info: {resp}");

    let resp = send_and_read(&mut conn, &["SET", "k", "v"]);
    assert!(resp.contains("+OK"), "authenticated via HELLO: {resp}");
}

#[test]
fn hello_with_wrong_password_rejected() {
    let server = LuxServer::builder().password("secret123").start();
    let mut conn = server.conn();

    let resp = send_and_read(&mut conn, &["HELLO", "2", "AUTH", "default", "wrongpass"]);
    assert!(resp.contains("WRONGPASS"), "bad password in HELLO: {resp}");

    let resp = send_and_read(&mut conn, &["SET", "k", "v"]);
    assert!(resp.contains("NOAUTH"), "still locked out: {resp}");
}

#[test]
fn hello_refuses_resp3_instead_of_emitting_a_mixed_protocol_reply() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let resp = send_and_read(&mut conn, &["HELLO", "3"]);
    assert!(
        resp.starts_with("-NOPROTO") && resp.contains("unsupported protocol"),
        "RESP3 must fail explicitly: {resp}"
    );
}

// --- Unified credential model -------------------------------------------------
//
// One `lux_sec_*` is meant to reach every surface: auth, data, native commands,
// vectors, pubsub, lua. A `lux_pub_*` is browser-embedded, so it identifies the
// project and nothing more: it reaches `/auth/v1/*` (that is how you obtain a
// person) and is refused everywhere else until an end-user token makes it a
// principal. The operator password stays valid as break-glass.
//
// The matrix is spelled out per surface because the failure mode for this kind
// of change is one entry point disagreeing with the others.

const SECRET: &str = "lux_sec_matrixtest";
const PUBLISHABLE: &str = "lux_pub_matrixtest";

fn keyed_server() -> LuxServer {
    LuxServer::builder()
        .http()
        .env("LUX_AUTH_ENABLED", "1")
        .env("LUX_AUTH_SECRET_KEY", SECRET)
        .env("LUX_AUTH_PUBLISHABLE_KEY", PUBLISHABLE)
        .start()
}

#[test]
fn resp_auth_accepts_secret_key_and_refuses_publishable() {
    let server = keyed_server();

    let mut conn = server.conn();
    let resp = send_and_read(&mut conn, &["AUTH", SECRET]);
    assert!(
        resp.starts_with("+OK"),
        "secret key should authenticate: {resp}"
    );
    let pong = send_and_read(&mut conn, &["PING"]);
    assert!(pong.contains("PONG"), "session usable after AUTH: {pong}");

    // A publishable key is public by construction; RESP exposes lua, FLUSHALL
    // and raw KV, which no grant can contain.
    let mut conn = server.conn();
    let resp = send_and_read(&mut conn, &["AUTH", PUBLISHABLE]);
    assert!(
        resp.starts_with("-WRONGPASS") && resp.contains("RESP"),
        "publishable must be refused on RESP with a reason: {resp}"
    );

    let mut conn = server.conn();
    let resp = send_and_read(&mut conn, &["AUTH", "lux_sec_not_a_real_key"]);
    assert!(resp.starts_with("-WRONGPASS"), "unknown key: {resp}");

    let mut conn = server.conn();
    let resp = send_and_read(&mut conn, &["HELLO", "2", "AUTH", "default", SECRET]);
    assert!(
        resp.contains("lux"),
        "HELLO should accept a secret key: {resp}"
    );
    assert!(
        send_and_read(&mut conn, &["PING"]).contains("PONG"),
        "HELLO-authenticated session should be usable"
    );
}

#[test]
fn resp_refuses_commands_until_authenticated() {
    let server = keyed_server();
    let mut conn = server.conn();
    let resp = send_and_read(&mut conn, &["DBSIZE"]);
    assert!(resp.contains("NOAUTH"), "unauthenticated RESP: {resp}");
}

#[test]
fn secret_key_reaches_every_http_surface() {
    let server = keyed_server();
    let port = server.http_port();

    // Native commands, raw KV, tables and vectors were all operator-only. One
    // secret key is the whole point of the model.
    for (method, path, body) in [
        ("POST", "/v1/exec", Some(r#"{"command":["PING"]}"#)),
        ("GET", "/v1/dbsize", None),
        ("PUT", "/v1/kv/matrix", Some(r#"{"value":"v"}"#)),
        ("GET", "/v1/kv/matrix", None),
        ("GET", "/v1/tables", None),
    ] {
        let (status, resp) = common::http_request(port, method, path, body, Some(SECRET));
        assert!(
            status < 400,
            "{method} {path} with a secret key: {status} {resp}"
        );
    }
}

#[test]
fn publishable_key_alone_reaches_auth_and_nothing_else() {
    let server = keyed_server();
    let port = server.http_port();

    // Auth is reachable: it is how a publishable client obtains a principal.
    let (status, resp) = common::http_request_with_headers(
        port,
        "POST",
        "/auth/v1/signup",
        Some(r#"{"email":"matrix@example.com","password":"hunter2hunter2"}"#),
        None,
        &[&format!("apikey: {PUBLISHABLE}")],
    );
    assert!(
        status < 400,
        "publishable must reach /auth/v1/signup: {status} {resp}"
    );

    // Data is not, on any shape of route.
    for (method, path, body) in [
        ("POST", "/v1/exec", Some(r#"{"command":["PING"]}"#)),
        ("GET", "/v1/dbsize", None),
        ("GET", "/v1/kv/matrix", None),
        ("GET", "/v1/tables", None),
    ] {
        let (status, resp) = common::http_request_with_headers(
            port,
            method,
            path,
            body,
            None,
            &[&format!("apikey: {PUBLISHABLE}")],
        );
        assert_eq!(
            status, 401,
            "publishable must not reach {method} {path}: {status} {resp}"
        );
    }
}

#[test]
fn operator_password_still_works_as_break_glass() {
    let server = LuxServer::builder()
        .http()
        .password("breakglass")
        .env("LUX_AUTH_ENABLED", "1")
        .env("LUX_AUTH_SECRET_KEY", SECRET)
        .start();

    // Both credentials are live during and after the migration.
    for credential in ["breakglass", SECRET] {
        let (status, resp) = common::http_request(
            server.http_port(),
            "GET",
            "/v1/dbsize",
            None,
            Some(credential),
        );
        assert!(status < 400, "{credential} on /v1/dbsize: {status} {resp}");
    }

    let mut conn = server.conn();
    let resp = send_and_read(&mut conn, &["AUTH", "breakglass"]);
    assert!(resp.starts_with("+OK"), "password on RESP: {resp}");
}

#[test]
fn unknown_and_revoked_credentials_are_refused() {
    let server = keyed_server();
    let port = server.http_port();

    for credential in ["lux_sec_wrong", "lux_pub_wrong", "not-a-key", ""] {
        let (status, _) = common::http_request(port, "GET", "/v1/dbsize", None, Some(credential));
        assert_eq!(status, 401, "credential {credential:?} must be refused");
    }
}

#[test]
fn revoking_a_key_takes_effect_immediately() {
    let server = keyed_server();
    let port = server.http_port();

    // Mint a second secret key using the bootstrap one.
    let (status, created) = common::http_request(
        port,
        "POST",
        "/auth/v1/admin/keys",
        Some(r#"{"kind":"secret","name":"revoke-me"}"#),
        Some(SECRET),
    );
    assert!(status < 400, "create key: {status} {created}");
    let minted = created
        .split("\"plain_key\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("minted key in response")
        .to_string();
    let key_id = created
        .split("\"id\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("key id in response")
        .to_string();

    // It works, which also warms the resolution cache.
    for _ in 0..3 {
        let (status, _) = common::http_request(port, "GET", "/v1/dbsize", None, Some(&minted));
        assert_eq!(status, 200, "minted key should work");
    }

    let (status, body) = common::http_request(
        port,
        "DELETE",
        &format!("/auth/v1/admin/keys/{key_id}"),
        None,
        Some(SECRET),
    );
    assert!(status < 400, "revoke: {status} {body}");

    // Immediately, not after the cache TTL expires.
    let (status, _) = common::http_request(port, "GET", "/v1/dbsize", None, Some(&minted));
    assert_eq!(status, 401, "revoked key must stop working at once");

    let mut conn = server.conn();
    let resp = send_and_read(&mut conn, &["AUTH", &minted]);
    assert!(
        resp.starts_with("-WRONGPASS"),
        "revoked key must not authenticate RESP: {resp}"
    );
}

// The browser shape, and the reason publishable is not capped at read: a live
// cursors app signs in anonymously (or as a user) and writes its own row
// directly from the browser. `apikey: lux_pub_*` + `Authorization: Bearer <jwt>`
// must read AND write exactly what the grant allows, and nothing else.
#[test]
fn publishable_with_end_user_token_reads_and_writes_per_grants() {
    let server = keyed_server();
    let port = server.http_port();

    let exec = |cmd: &str| {
        common::http_request(
            port,
            "POST",
            "/v1/exec",
            Some(&format!(r#"{{"command":{cmd}}}"#)),
            Some(SECRET),
        )
    };
    let (status, out) =
        exec(r#"["TCREATE","cursors","id STR PRIMARY KEY,","owner_id STR,","x STR"]"#);
    assert!(status < 400, "create table: {status} {out}");
    let (status, out) =
        exec(r#"["GRANT","read","write","ON","cursors","WHERE","owner_id","=","auth.uid()"]"#);
    assert!(
        status < 400 && !out.contains("error"),
        "grant: {status} {out}"
    );

    let (status, signup) = common::http_request_with_headers(
        port,
        "POST",
        "/auth/v1/signup",
        Some(r#"{"email":"cursor@example.com","password":"hunter2hunter2"}"#),
        None,
        &[&format!("apikey: {PUBLISHABLE}")],
    );
    assert!(status < 400, "signup: {status} {signup}");
    let field = |body: &str, key: &str| -> String {
        body.split(&format!("\"{key}\":\""))
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or_default()
            .to_string()
    };
    let jwt = field(&signup, "access_token");
    let uid = field(&signup, "id");
    assert!(
        !jwt.is_empty() && !uid.is_empty(),
        "signup payload: {signup}"
    );

    let browser = [
        format!("apikey: {PUBLISHABLE}"),
        format!("Authorization: Bearer {jwt}"),
    ];
    let browser: Vec<&str> = browser.iter().map(String::as_str).collect();

    // Writes its own row.
    let (status, body) = common::http_request_with_headers(
        port,
        "POST",
        "/v1/tables/cursors",
        Some(&format!(r#"{{"id":"c1","owner_id":"{uid}","x":"10"}}"#)),
        None,
        &browser,
    );
    assert!(
        status < 400,
        "publishable+jwt must write its own row: {status} {body}"
    );

    // Reads it back.
    let (status, body) =
        common::http_request_with_headers(port, "GET", "/v1/tables/cursors", None, None, &browser);
    assert!(
        status < 400 && body.contains("c1"),
        "publishable+jwt must read its own row: {status} {body}"
    );

    // The grant predicate still binds: someone else's row is refused.
    let (status, body) = common::http_request_with_headers(
        port,
        "POST",
        "/v1/tables/cursors",
        Some(r#"{"id":"c2","owner_id":"someone-else","x":"99"}"#),
        None,
        &browser,
    );
    assert!(
        status >= 400,
        "grant predicate must block another user's row: {status} {body}"
    );

    // And a principal never reaches the secret-key routes.
    let (status, body) =
        common::http_request_with_headers(port, "GET", "/v1/dbsize", None, None, &browser);
    assert!(
        status >= 400,
        "end-user principal must not reach secret-key routes: {status} {body}"
    );
}
