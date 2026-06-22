mod common;
use common::{send_and_read, LuxServer};

fn pos(resp: &str, value: &str) -> usize {
    resp.find(&format!("\r\n{value}\r\n"))
        .unwrap_or_else(|| panic!("missing bulk payload {value:?}: {resp}"))
}

#[test]
fn sort_numeric_desc_and_limit() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["RPUSH", "nums", "3", "1", "2", "10"]);
    let resp = send_and_read(&mut conn, &["SORT", "nums", "DESC", "LIMIT", "1", "2"]);
    assert!(
        resp.contains("*2"),
        "LIMIT should return two elements: {resp}"
    );
    assert!(
        pos(&resp, "3") < pos(&resp, "2"),
        "DESC numeric order: {resp}"
    );
}

#[test]
fn sort_alpha_set_members() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["SADD", "words", "pear", "apple", "banana"]);
    let resp = send_and_read(&mut conn, &["SORT", "words", "ALPHA"]);
    assert!(
        pos(&resp, "apple") < pos(&resp, "banana"),
        "ALPHA should sort lexically: {resp}"
    );
    assert!(
        pos(&resp, "banana") < pos(&resp, "pear"),
        "ALPHA should sort lexically: {resp}"
    );
}

#[test]
fn sort_by_external_weights_and_get_hash_fields() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["RPUSH", "ids", "1", "2", "3"]);
    send_and_read(&mut conn, &["SET", "weight:1", "30"]);
    send_and_read(&mut conn, &["SET", "weight:2", "10"]);
    send_and_read(&mut conn, &["SET", "weight:3", "20"]);
    send_and_read(&mut conn, &["HSET", "user:1", "name", "Ada"]);
    send_and_read(&mut conn, &["HSET", "user:2", "name", "Linus"]);
    send_and_read(&mut conn, &["HSET", "user:3", "name", "Grace"]);

    let resp = send_and_read(
        &mut conn,
        &[
            "SORT",
            "ids",
            "BY",
            "weight:*",
            "GET",
            "#",
            "GET",
            "user:*->name",
        ],
    );
    assert!(
        pos(&resp, "2") < pos(&resp, "Linus"),
        "GET # and hash field should be paired for id 2 first: {resp}"
    );
    assert!(
        pos(&resp, "Linus") < pos(&resp, "3"),
        "weight order: {resp}"
    );
    assert!(
        pos(&resp, "Grace") < pos(&resp, "1"),
        "weight order: {resp}"
    );
}

#[test]
fn sort_store_writes_list_and_sort_ro_rejects_store() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["RPUSH", "nums", "4", "2", "3"]);
    let stored = send_and_read(&mut conn, &["SORT", "nums", "STORE", "sorted:nums"]);
    assert!(
        stored.contains(":3"),
        "STORE should write three elements: {stored}"
    );

    let range = send_and_read(&mut conn, &["LRANGE", "sorted:nums", "0", "-1"]);
    assert!(
        pos(&range, "2") < pos(&range, "3"),
        "stored list should be sorted: {range}"
    );

    let readonly = send_and_read(&mut conn, &["SORT_RO", "nums", "STORE", "bad"]);
    assert!(
        readonly.contains("ERR syntax error"),
        "SORT_RO STORE must be rejected: {readonly}"
    );
}

#[test]
fn sort_rejects_invalid_limit_without_writing_store_destination() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["RPUSH", "nums", "4", "2", "3"]);
    send_and_read(&mut conn, &["RPUSH", "dest", "original"]);

    for cmd in [
        vec!["SORT", "nums", "LIMIT", "nope", "1", "STORE", "dest"],
        vec!["SORT", "nums", "LIMIT", "0", "nope", "STORE", "dest"],
        vec!["SORT", "nums", "LIMIT", "-1", "1", "STORE", "dest"],
        vec!["SORT", "nums", "LIMIT", "0", "-1", "STORE", "dest"],
    ] {
        let resp = send_and_read(&mut conn, &cmd);
        assert!(
            resp.starts_with("-ERR"),
            "expected error for {cmd:?}, got: {resp}"
        );
    }

    let range = send_and_read(&mut conn, &["LRANGE", "dest", "0", "-1"]);
    assert!(
        range.contains("original"),
        "invalid SORT STORE should not replace destination: {range}"
    );
}

#[test]
fn sort_reports_wrongtype_and_numeric_conversion_errors() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["SET", "plain", "value"]);
    let wrongtype = send_and_read(&mut conn, &["SORT", "plain"]);
    assert!(wrongtype.contains("WRONGTYPE"), "wrong type: {wrongtype}");

    send_and_read(&mut conn, &["RPUSH", "badnums", "a", "b"]);
    let numeric = send_and_read(&mut conn, &["SORT", "badnums"]);
    assert!(
        numeric.contains("can't be converted into double"),
        "non-numeric sort should fail without ALPHA: {numeric}"
    );
}
