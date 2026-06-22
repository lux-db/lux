mod common;
use common::{send_and_read, LuxServer};

fn parse_integer(resp: &str) -> i64 {
    for line in resp.lines() {
        if let Some(rest) = line.strip_prefix(':') {
            return rest.trim().parse().unwrap_or(-999);
        }
    }
    panic!("no integer in response: {resp}");
}

#[test]
fn test_pfadd_basic() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let resp = send_and_read(&mut conn, &["PFADD", "hll", "a", "b", "c"]);
    assert!(resp.contains(":1"), "PFADD should return 1: {resp}");

    let resp = send_and_read(&mut conn, &["PFADD", "hll", "a", "b", "c"]);
    assert!(
        resp.contains(":0"),
        "PFADD duplicates should return 0: {resp}"
    );

    let resp = send_and_read(&mut conn, &["PFADD", "hll", "d"]);
    assert!(
        resp.contains(":1"),
        "PFADD new element should return 1: {resp}"
    );
}

#[test]
fn test_pfadd_creates_empty() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let resp = send_and_read(&mut conn, &["PFADD", "hll"]);
    assert!(
        resp.contains(":0") || resp.contains(":1"),
        "PFADD empty should work: {resp}"
    );

    let resp = send_and_read(&mut conn, &["PFCOUNT", "hll"]);
    assert!(resp.contains(":0"), "empty HLL should count 0: {resp}");
}

#[test]
fn test_pfcount_accuracy() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let n = 1000;
    let elements: Vec<String> = (0..n).map(|i| format!("element:{}", i)).collect();
    let mut args: Vec<&str> = vec!["PFADD", "hll"];
    args.extend(elements.iter().map(|s| s.as_str()));
    send_and_read(&mut conn, &args);

    let resp = send_and_read(&mut conn, &["PFCOUNT", "hll"]);
    let count = parse_integer(&resp);
    let error = (count as f64 - n as f64).abs() / n as f64;
    assert!(
        error < 0.05,
        "PFCOUNT {count} too far from {n}, error={error}"
    );
}

#[test]
fn test_pfcount_multiple_keys() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let elems1: Vec<String> = (0..500).map(|i| format!("a:{}", i)).collect();
    let mut args1: Vec<&str> = vec!["PFADD", "hll1"];
    args1.extend(elems1.iter().map(|s| s.as_str()));
    send_and_read(&mut conn, &args1);

    let elems2: Vec<String> = (0..500).map(|i| format!("b:{}", i)).collect();
    let mut args2: Vec<&str> = vec!["PFADD", "hll2"];
    args2.extend(elems2.iter().map(|s| s.as_str()));
    send_and_read(&mut conn, &args2);

    let resp = send_and_read(&mut conn, &["PFCOUNT", "hll1", "hll2"]);
    let count = parse_integer(&resp);
    let error = (count as f64 - 1000.0).abs() / 1000.0;
    assert!(
        error < 0.05,
        "PFCOUNT multi {count} too far from 1000, error={error}"
    );
}

#[test]
fn test_pfmerge_disjoint() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let elems1: Vec<String> = (0..500).map(|i| format!("a:{}", i)).collect();
    let mut args1: Vec<&str> = vec!["PFADD", "src1"];
    args1.extend(elems1.iter().map(|s| s.as_str()));
    send_and_read(&mut conn, &args1);

    let elems2: Vec<String> = (0..500).map(|i| format!("b:{}", i)).collect();
    let mut args2: Vec<&str> = vec!["PFADD", "src2"];
    args2.extend(elems2.iter().map(|s| s.as_str()));
    send_and_read(&mut conn, &args2);

    let resp = send_and_read(&mut conn, &["PFMERGE", "dest", "src1", "src2"]);
    assert!(resp.contains("+OK"), "PFMERGE should return OK: {resp}");

    let resp = send_and_read(&mut conn, &["PFCOUNT", "dest"]);
    let count = parse_integer(&resp);
    let error = (count as f64 - 1000.0).abs() / 1000.0;
    assert!(
        error < 0.05,
        "merged count {count} too far from 1000, error={error}"
    );
}

#[test]
fn test_pfmerge_overlapping() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let elems1: Vec<String> = (0..500).map(|i| format!("item:{}", i)).collect();
    let mut args1: Vec<&str> = vec!["PFADD", "src1"];
    args1.extend(elems1.iter().map(|s| s.as_str()));
    send_and_read(&mut conn, &args1);

    let elems2: Vec<String> = (250..750).map(|i| format!("item:{}", i)).collect();
    let mut args2: Vec<&str> = vec!["PFADD", "src2"];
    args2.extend(elems2.iter().map(|s| s.as_str()));
    send_and_read(&mut conn, &args2);

    send_and_read(&mut conn, &["PFMERGE", "dest", "src1", "src2"]);
    let resp = send_and_read(&mut conn, &["PFCOUNT", "dest"]);
    let count = parse_integer(&resp);
    let error = (count as f64 - 750.0).abs() / 750.0;
    assert!(
        error < 0.05,
        "overlapping merge count {count} too far from 750, error={error}"
    );
}

#[test]
fn test_pfcount_empty_key() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let resp = send_and_read(&mut conn, &["PFCOUNT", "nonexistent"]);
    assert!(
        resp.contains(":0"),
        "nonexistent key should return 0: {resp}"
    );
}

#[test]
fn test_wrongtype_on_non_hll() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["SET", "mystr", "hello"]);

    let resp = send_and_read(&mut conn, &["PFADD", "mystr", "element"]);
    assert!(
        resp.contains("WRONGTYPE"),
        "PFADD on string should return WRONGTYPE: {resp}"
    );

    let resp = send_and_read(&mut conn, &["PFCOUNT", "mystr"]);
    assert!(
        resp.contains("WRONGTYPE"),
        "PFCOUNT on string should return WRONGTYPE: {resp}"
    );
}

#[test]
fn test_type_returns_string() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["PFADD", "hll", "a"]);
    let resp = send_and_read(&mut conn, &["TYPE", "hll"]);
    assert!(
        resp.contains("string"),
        "TYPE should return string for HLL: {resp}"
    );
}
