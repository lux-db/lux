mod common;
use common::{send_and_read, LuxServer};

#[test]
fn test_tsadd_and_tsget() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let resp = send_and_read(&mut conn, &["TSADD", "cpu", "1000", "72.5"]);
    assert!(
        resp.contains(":1000"),
        "TSADD should return timestamp: {resp}"
    );

    let resp = send_and_read(&mut conn, &["TSADD", "cpu", "2000", "75.0"]);
    assert!(resp.contains(":2000"), "TSADD second: {resp}");

    let resp = send_and_read(&mut conn, &["TSGET", "cpu"]);
    assert!(
        resp.contains(":2000"),
        "TSGET should return last timestamp: {resp}"
    );
    assert!(
        resp.contains("75"),
        "TSGET should return last value: {resp}"
    );
}

#[test]
fn test_tsadd_auto_timestamp() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let resp = send_and_read(&mut conn, &["TSADD", "cpu", "*", "72.5"]);
    assert!(
        resp.contains(":"),
        "TSADD * should return a timestamp: {resp}"
    );
    assert!(!resp.contains("-"), "should not be an error: {resp}");
}

#[test]
fn test_tsrange_basic() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["TSADD", "cpu", "1000", "10.0"]);
    send_and_read(&mut conn, &["TSADD", "cpu", "2000", "20.0"]);
    send_and_read(&mut conn, &["TSADD", "cpu", "3000", "30.0"]);
    send_and_read(&mut conn, &["TSADD", "cpu", "4000", "40.0"]);

    let resp = send_and_read(&mut conn, &["TSRANGE", "cpu", "-", "+"]);
    assert!(resp.contains("10"), "should contain first value: {resp}");
    assert!(resp.contains("40"), "should contain last value: {resp}");
    assert!(resp.contains(":1000"), "should contain first ts: {resp}");
    assert!(resp.contains(":4000"), "should contain last ts: {resp}");
}

#[test]
fn test_tsrange_with_bounds() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["TSADD", "cpu", "1000", "10.0"]);
    send_and_read(&mut conn, &["TSADD", "cpu", "2000", "20.0"]);
    send_and_read(&mut conn, &["TSADD", "cpu", "3000", "30.0"]);
    send_and_read(&mut conn, &["TSADD", "cpu", "4000", "40.0"]);

    let resp = send_and_read(&mut conn, &["TSRANGE", "cpu", "2000", "3000"]);
    assert!(resp.contains("20"), "should contain 20: {resp}");
    assert!(resp.contains("30"), "should contain 30: {resp}");
    assert!(!resp.contains("10\r\n"), "should not contain 10: {resp}");
}

#[test]
fn test_tsrange_aggregation_avg() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["TSADD", "cpu", "1000", "10.0"]);
    send_and_read(&mut conn, &["TSADD", "cpu", "1500", "20.0"]);
    send_and_read(&mut conn, &["TSADD", "cpu", "2000", "30.0"]);
    send_and_read(&mut conn, &["TSADD", "cpu", "2500", "40.0"]);

    let resp = send_and_read(
        &mut conn,
        &["TSRANGE", "cpu", "-", "+", "AGGREGATION", "avg", "2000"],
    );
    assert!(resp.contains("15"), "avg of 10,20 = 15: {resp}");
    assert!(resp.contains("35"), "avg of 30,40 = 35: {resp}");
}

#[test]
fn test_tsrange_aggregation_sum() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["TSADD", "cpu", "1000", "10.0"]);
    send_and_read(&mut conn, &["TSADD", "cpu", "1500", "20.0"]);
    send_and_read(&mut conn, &["TSADD", "cpu", "2000", "30.0"]);

    let resp = send_and_read(
        &mut conn,
        &["TSRANGE", "cpu", "-", "+", "AGGREGATION", "sum", "2000"],
    );
    assert!(resp.contains("30"), "sum of 10,20 = 30: {resp}");
}

#[test]
fn test_tsrange_count() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    for i in 0..10 {
        send_and_read(
            &mut conn,
            &["TSADD", "cpu", &format!("{}", i * 1000), &format!("{}", i)],
        );
    }

    let resp = send_and_read(&mut conn, &["TSRANGE", "cpu", "-", "+", "COUNT", "3"]);
    assert!(resp.starts_with("*3\r\n"), "should return 3 items: {resp}");
}

#[test]
fn test_tsget_nonexistent() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let resp = send_and_read(&mut conn, &["TSGET", "nonexistent"]);
    assert!(
        resp.contains("*-1"),
        "TSGET nonexistent should return null array: {resp}"
    );
}

#[test]
fn test_tsadd_with_labels() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(
        &mut conn,
        &[
            "TSADD", "cpu:h1", "1000", "72.5", "LABELS", "host", "server1", "metric", "cpu",
        ],
    );

    let resp = send_and_read(&mut conn, &["TSINFO", "cpu:h1"]);
    assert!(resp.contains("totalSamples"), "should have info: {resp}");
    assert!(resp.contains("server1"), "should have label value: {resp}");
}

#[test]
fn test_tsadd_with_retention() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(
        &mut conn,
        &["TSADD", "cpu", "1000", "10.0", "RETENTION", "5000"],
    );
    send_and_read(&mut conn, &["TSADD", "cpu", "2000", "20.0"]);
    send_and_read(&mut conn, &["TSADD", "cpu", "8000", "80.0"]);

    let resp = send_and_read(&mut conn, &["TSRANGE", "cpu", "-", "+"]);
    assert!(
        !resp.contains(":1000"),
        "sample at 1000 should be expired by retention: {resp}"
    );
    assert!(resp.contains(":8000"), "latest sample should exist: {resp}");
}

#[test]
fn test_tsmadd() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let resp = send_and_read(
        &mut conn,
        &[
            "TSMADD", "cpu:h1", "1000", "72.5", "cpu:h2", "1000", "65.0", "mem:h1", "1000", "45.0",
        ],
    );
    assert!(
        resp.contains(":1000"),
        "TSMADD should return timestamps: {resp}"
    );

    let resp = send_and_read(&mut conn, &["TSGET", "cpu:h2"]);
    assert!(resp.contains("65"), "cpu:h2 should have value: {resp}");
}

#[test]
fn test_tsmrange_filter() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(
        &mut conn,
        &[
            "TSADD", "cpu:h1", "1000", "72.5", "LABELS", "host", "s1", "metric", "cpu",
        ],
    );
    send_and_read(
        &mut conn,
        &[
            "TSADD", "mem:h1", "1000", "45.0", "LABELS", "host", "s1", "metric", "mem",
        ],
    );
    send_and_read(
        &mut conn,
        &[
            "TSADD", "cpu:h2", "1000", "68.0", "LABELS", "host", "s2", "metric", "cpu",
        ],
    );

    let resp = send_and_read(&mut conn, &["TSMRANGE", "-", "+", "FILTER", "host=s1"]);
    assert!(resp.contains("72.5"), "should find cpu:h1: {resp}");
    assert!(resp.contains("45"), "should find mem:h1: {resp}");
    assert!(
        !resp.contains("68"),
        "should not find cpu:h2 (host=s2): {resp}"
    );

    let resp = send_and_read(&mut conn, &["TSMRANGE", "-", "+", "FILTER", "metric=cpu"]);
    assert!(resp.contains("72.5"), "should find cpu:h1: {resp}");
    assert!(resp.contains("68"), "should find cpu:h2: {resp}");
    assert!(!resp.contains("45"), "should not find mem:h1: {resp}");
}

#[test]
fn test_tsinfo_nonexistent() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let resp = send_and_read(&mut conn, &["TSINFO", "nonexistent"]);
    assert!(
        resp.contains("ERR"),
        "TSINFO nonexistent should error: {resp}"
    );
}

#[test]
fn test_type_returns_timeseries() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["TSADD", "cpu", "1000", "72.5"]);
    let resp = send_and_read(&mut conn, &["TYPE", "cpu"]);
    assert!(
        resp.contains("timeseries"),
        "TYPE should return timeseries: {resp}"
    );
}

#[test]
fn test_wrongtype_on_non_ts() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["SET", "mystr", "hello"]);
    let resp = send_and_read(&mut conn, &["TSADD", "mystr", "1000", "42.5"]);
    assert!(
        resp.contains("WRONGTYPE"),
        "TSADD on string should WRONGTYPE: {resp}"
    );
}

#[test]
fn test_tsadd_duplicate_timestamp() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["TSADD", "cpu", "1000", "10.0"]);
    send_and_read(&mut conn, &["TSADD", "cpu", "1000", "99.0"]);

    let resp = send_and_read(&mut conn, &["TSGET", "cpu"]);
    assert!(
        resp.contains("99"),
        "duplicate timestamp should overwrite: {resp}"
    );
}

#[test]
fn test_tsrange_empty() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let resp = send_and_read(&mut conn, &["TSRANGE", "nonexistent", "-", "+"]);
    assert!(
        resp.contains("*0"),
        "TSRANGE nonexistent should return empty: {resp}"
    );
}

#[test]
fn test_tsmrange_with_aggregation() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(
        &mut conn,
        &["TSADD", "cpu:h1", "1000", "10.0", "LABELS", "metric", "cpu"],
    );
    send_and_read(&mut conn, &["TSADD", "cpu:h1", "2000", "20.0"]);
    send_and_read(&mut conn, &["TSADD", "cpu:h1", "3000", "30.0"]);

    let resp = send_and_read(
        &mut conn,
        &[
            "TSMRANGE",
            "-",
            "+",
            "FILTER",
            "metric=cpu",
            "AGGREGATION",
            "max",
            "2000",
        ],
    );
    assert!(resp.contains("20"), "max of first bucket: {resp}");
    assert!(resp.contains("30"), "max of second bucket: {resp}");
}
