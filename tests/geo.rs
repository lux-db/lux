mod common;
use common::{send_and_read, LuxServer};

#[test]
fn test_geoadd_basic() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let resp = send_and_read(
        &mut conn,
        &[
            "GEOADD",
            "Sicily",
            "13.361389",
            "38.115556",
            "Palermo",
            "15.087269",
            "37.502669",
            "Catania",
        ],
    );
    assert!(resp.contains(":2"), "GEOADD should return 2: {resp}");
}

#[test]
fn test_geoadd_nx_xx_ch() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(
        &mut conn,
        &["GEOADD", "key", "13.361389", "38.115556", "Palermo"],
    );

    let resp = send_and_read(
        &mut conn,
        &["GEOADD", "key", "NX", "15.0", "37.0", "Palermo"],
    );
    assert!(resp.contains(":0"), "NX should not update existing: {resp}");

    let resp = send_and_read(
        &mut conn,
        &["GEOADD", "key", "NX", "15.0", "37.0", "Catania"],
    );
    assert!(resp.contains(":1"), "NX should add new: {resp}");

    let resp = send_and_read(
        &mut conn,
        &["GEOADD", "key", "XX", "15.0", "37.0", "Missing"],
    );
    assert!(resp.contains(":0"), "XX should not add missing: {resp}");

    let resp = send_and_read(
        &mut conn,
        &["GEOADD", "key", "XX", "CH", "14.0", "37.5", "Palermo"],
    );
    assert!(resp.contains(":1"), "XX CH should count changed: {resp}");
}

#[test]
fn test_geodist_basic() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(
        &mut conn,
        &[
            "GEOADD",
            "Sicily",
            "13.361389",
            "38.115556",
            "Palermo",
            "15.087269",
            "37.502669",
            "Catania",
        ],
    );

    let resp = send_and_read(&mut conn, &["GEODIST", "Sicily", "Palermo", "Catania"]);
    assert!(
        resp.contains("166"),
        "distance should be ~166km in meters: {resp}"
    );

    let resp = send_and_read(
        &mut conn,
        &["GEODIST", "Sicily", "Palermo", "Catania", "km"],
    );
    assert!(resp.contains("166."), "distance should be ~166 km: {resp}");

    let resp = send_and_read(
        &mut conn,
        &["GEODIST", "Sicily", "Palermo", "Catania", "mi"],
    );
    assert!(resp.contains("103."), "distance in miles: {resp}");

    let resp = send_and_read(&mut conn, &["GEODIST", "Sicily", "Palermo", "Missing"]);
    assert!(resp.contains("$-1"), "missing member returns null: {resp}");
}

#[test]
fn test_geopos_basic() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(
        &mut conn,
        &[
            "GEOADD",
            "Sicily",
            "13.361389",
            "38.115556",
            "Palermo",
            "15.087269",
            "37.502669",
            "Catania",
        ],
    );

    let resp = send_and_read(&mut conn, &["GEOPOS", "Sicily", "Palermo", "Catania"]);
    assert!(resp.contains("13.36"), "should contain Palermo lon: {resp}");
    assert!(resp.contains("38.11"), "should contain Palermo lat: {resp}");
    assert!(resp.contains("15.08"), "should contain Catania lon: {resp}");
    assert!(resp.contains("37.50"), "should contain Catania lat: {resp}");

    let resp = send_and_read(
        &mut conn,
        &["GEOPOS", "Sicily", "Palermo", "Missing", "Catania"],
    );
    assert!(
        resp.contains("*-1"),
        "missing member should be null array: {resp}"
    );
}

#[test]
fn test_geohash_basic() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(
        &mut conn,
        &[
            "GEOADD",
            "Sicily",
            "13.361389",
            "38.115556",
            "Palermo",
            "15.087269",
            "37.502669",
            "Catania",
        ],
    );

    let resp = send_and_read(&mut conn, &["GEOHASH", "Sicily", "Palermo", "Catania"]);
    assert!(
        resp.contains("sqc8b49rny"),
        "Palermo geohash should start with sqc8b49rny: {resp}"
    );
    assert!(
        resp.contains("sqdtr74hyu"),
        "Catania geohash should start with sqdtr74hyu: {resp}"
    );

    let resp = send_and_read(&mut conn, &["GEOHASH", "Sicily", "Missing"]);
    assert!(resp.contains("$-1"), "missing member returns null: {resp}");
}

#[test]
fn test_geosearch_byradius() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(
        &mut conn,
        &[
            "GEOADD",
            "Sicily",
            "13.361389",
            "38.115556",
            "Palermo",
            "15.087269",
            "37.502669",
            "Catania",
            "13.5833",
            "37.3167",
            "Agrigento",
        ],
    );

    let resp = send_and_read(
        &mut conn,
        &[
            "GEOSEARCH",
            "Sicily",
            "FROMLONLAT",
            "15",
            "37",
            "BYRADIUS",
            "100",
            "km",
            "ASC",
        ],
    );
    assert!(resp.contains("Catania"), "Catania within 100km: {resp}");

    let resp = send_and_read(
        &mut conn,
        &[
            "GEOSEARCH",
            "Sicily",
            "FROMLONLAT",
            "15",
            "37",
            "BYRADIUS",
            "200",
            "km",
            "ASC",
            "COUNT",
            "2",
        ],
    );
    assert!(resp.contains("Catania"), "should include Catania: {resp}");

    let resp = send_and_read(
        &mut conn,
        &[
            "GEOSEARCH",
            "Sicily",
            "FROMLONLAT",
            "15",
            "37",
            "BYRADIUS",
            "200",
            "km",
            "ASC",
            "WITHCOORD",
            "WITHDIST",
        ],
    );
    assert!(
        resp.contains("Catania"),
        "should include Catania with extras: {resp}"
    );
}

#[test]
fn test_geosearch_bybox() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(
        &mut conn,
        &[
            "GEOADD",
            "Sicily",
            "13.361389",
            "38.115556",
            "Palermo",
            "15.087269",
            "37.502669",
            "Catania",
        ],
    );

    let resp = send_and_read(
        &mut conn,
        &[
            "GEOSEARCH",
            "Sicily",
            "FROMLONLAT",
            "15",
            "37",
            "BYBOX",
            "400",
            "400",
            "km",
            "ASC",
        ],
    );
    assert!(resp.contains("Catania"), "Catania in box: {resp}");
    assert!(resp.contains("Palermo"), "Palermo in box: {resp}");
}

#[test]
fn test_geosearch_frommember() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(
        &mut conn,
        &[
            "GEOADD",
            "Sicily",
            "13.361389",
            "38.115556",
            "Palermo",
            "15.087269",
            "37.502669",
            "Catania",
        ],
    );

    let resp = send_and_read(
        &mut conn,
        &[
            "GEOSEARCH",
            "Sicily",
            "FROMMEMBER",
            "Palermo",
            "BYRADIUS",
            "200",
            "km",
            "ASC",
        ],
    );
    assert!(resp.contains("Palermo"), "should include self: {resp}");
    assert!(resp.contains("Catania"), "should include Catania: {resp}");
}

#[test]
fn test_geosearchstore() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(
        &mut conn,
        &[
            "GEOADD",
            "Sicily",
            "13.361389",
            "38.115556",
            "Palermo",
            "15.087269",
            "37.502669",
            "Catania",
        ],
    );

    let resp = send_and_read(
        &mut conn,
        &[
            "GEOSEARCHSTORE",
            "dest",
            "Sicily",
            "FROMLONLAT",
            "15",
            "37",
            "BYRADIUS",
            "200",
            "km",
            "ASC",
        ],
    );
    assert!(resp.contains(":2"), "should store 2 results: {resp}");

    let resp = send_and_read(&mut conn, &["ZCARD", "dest"]);
    assert!(resp.contains(":2"), "dest should have 2 members: {resp}");

    let resp = send_and_read(
        &mut conn,
        &[
            "GEOSEARCHSTORE",
            "dest2",
            "Sicily",
            "FROMLONLAT",
            "15",
            "37",
            "BYRADIUS",
            "200",
            "km",
            "ASC",
            "STOREDIST",
        ],
    );
    assert!(resp.contains(":2"), "STOREDIST should store 2: {resp}");

    let resp = send_and_read(&mut conn, &["ZSCORE", "dest2", "Catania"]);
    assert!(
        !resp.contains("$-1"),
        "Catania should have a distance score: {resp}"
    );
}

#[test]
fn test_georadius_legacy() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(
        &mut conn,
        &[
            "GEOADD",
            "Sicily",
            "13.361389",
            "38.115556",
            "Palermo",
            "15.087269",
            "37.502669",
            "Catania",
        ],
    );

    let resp = send_and_read(
        &mut conn,
        &["GEORADIUS", "Sicily", "15", "37", "200", "km", "ASC"],
    );
    assert!(resp.contains("Catania"), "should include Catania: {resp}");
    assert!(resp.contains("Palermo"), "should include Palermo: {resp}");
}

#[test]
fn test_georadiusbymember_legacy() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(
        &mut conn,
        &[
            "GEOADD",
            "Sicily",
            "13.361389",
            "38.115556",
            "Palermo",
            "15.087269",
            "37.502669",
            "Catania",
        ],
    );

    let resp = send_and_read(
        &mut conn,
        &["GEORADIUSBYMEMBER", "Sicily", "Palermo", "200", "km", "ASC"],
    );
    assert!(resp.contains("Palermo"), "should include self: {resp}");
    assert!(resp.contains("Catania"), "should include Catania: {resp}");
}

#[test]
fn test_geoadd_invalid_coords() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let resp = send_and_read(&mut conn, &["GEOADD", "key", "181", "38", "member"]);
    assert!(resp.contains("ERR"), "longitude > 180 should error: {resp}");

    let resp = send_and_read(&mut conn, &["GEOADD", "key", "13", "86", "member"]);
    assert!(
        resp.contains("ERR"),
        "latitude > 85.05 should error: {resp}"
    );
}

#[test]
fn test_geo_empty_key() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let resp = send_and_read(&mut conn, &["GEODIST", "nokey", "a", "b"]);
    assert!(resp.contains("$-1"), "empty key returns null: {resp}");

    let resp = send_and_read(&mut conn, &["GEOPOS", "nokey", "a"]);
    assert!(resp.contains("*-1"), "empty key returns null array: {resp}");

    let resp = send_and_read(
        &mut conn,
        &[
            "GEOSEARCH",
            "nokey",
            "FROMLONLAT",
            "0",
            "0",
            "BYRADIUS",
            "100",
            "km",
        ],
    );
    assert!(resp.contains("*0"), "empty key returns empty array: {resp}");
}

#[test]
fn test_geosearch_desc_order() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(
        &mut conn,
        &[
            "GEOADD",
            "places",
            "13.361389",
            "38.115556",
            "Palermo",
            "15.087269",
            "37.502669",
            "Catania",
            "2.349014",
            "48.864716",
            "Paris",
        ],
    );

    let resp = send_and_read(
        &mut conn,
        &[
            "GEOSEARCH",
            "places",
            "FROMLONLAT",
            "14",
            "38",
            "BYRADIUS",
            "200",
            "km",
            "DESC",
        ],
    );
    let catania_pos = resp.find("Catania").unwrap_or(0);
    let palermo_pos = resp.find("Palermo").unwrap_or(0);
    assert!(
        catania_pos < palermo_pos,
        "DESC: Catania (farther) should come before Palermo: {resp}"
    );
}
