mod common;
use common::{send_and_read, LuxServer};

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

    let resp = send_and_read(&mut conn, &["HELLO", "3", "AUTH", "default", "secret123"]);
    assert!(resp.contains("lux"), "HELLO returns server info: {resp}");

    let resp = send_and_read(&mut conn, &["SET", "k", "v"]);
    assert!(resp.contains("+OK"), "authenticated via HELLO: {resp}");
}

#[test]
fn hello_with_wrong_password_rejected() {
    let server = LuxServer::builder().password("secret123").start();
    let mut conn = server.conn();

    let resp = send_and_read(&mut conn, &["HELLO", "3", "AUTH", "default", "wrongpass"]);
    assert!(resp.contains("WRONGPASS"), "bad password in HELLO: {resp}");

    let resp = send_and_read(&mut conn, &["SET", "k", "v"]);
    assert!(resp.contains("NOAUTH"), "still locked out: {resp}");
}
