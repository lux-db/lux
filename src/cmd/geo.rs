use bytes::BytesMut;
use std::time::Instant;

use crate::geo::{self, DistUnit};
use crate::resp;
use crate::store::Store;

use super::{arg_str, cmd_eq, CmdResult};

fn format_geo_coord(v: f64) -> String {
    if v == 0.0 {
        return "0".to_string();
    }
    let magnitude = v.abs().log10().floor() as usize + 1;
    let decimals = 17usize.saturating_sub(magnitude);
    let s = format!("{:.prec$}", v, prec = decimals);
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

enum MemberLookup {
    Found(f64, f64),
    KeyMissing,
    MemberMissing,
}

fn lookup_member_coords(
    store: &Store,
    key: &[u8],
    member: &[u8],
    now: Instant,
) -> Result<MemberLookup, String> {
    match store.zscore_with_key_state(key, member, now) {
        Ok((Some(s), _)) => {
            let (lon, lat) = geo::geohash_decode(s as u64);
            Ok(MemberLookup::Found(lon, lat))
        }
        Ok((None, key_exists)) => {
            if !key_exists {
                Ok(MemberLookup::KeyMissing)
            } else {
                Ok(MemberLookup::MemberMissing)
            }
        }
        Err(e) => Err(e),
    }
}

pub fn cmd_geoadd(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 5 {
        resp::write_error(out, "ERR wrong number of arguments for 'geoadd' command");
        return CmdResult::Written;
    }
    let key = args[1];
    let mut nx = false;
    let mut xx = false;
    let mut ch = false;
    let mut i = 2;
    while i < args.len() {
        if cmd_eq(args[i], b"NX") {
            nx = true;
            i += 1;
        } else if cmd_eq(args[i], b"XX") {
            xx = true;
            i += 1;
        } else if cmd_eq(args[i], b"CH") {
            ch = true;
            i += 1;
        } else {
            break;
        }
    }
    if nx && xx {
        resp::write_error(out, "ERR syntax error");
        return CmdResult::Written;
    }
    let remaining = args.len() - i;
    if remaining < 3 || !remaining.is_multiple_of(3) {
        resp::write_error(out, "ERR syntax error");
        return CmdResult::Written;
    }
    let mut members: Vec<(&[u8], f64)> = Vec::new();
    while i + 2 < args.len() {
        let lon: f64 = match arg_str(args[i]).parse() {
            Ok(v) => v,
            Err(_) => {
                resp::write_error(out, "ERR value is not a valid float");
                return CmdResult::Written;
            }
        };
        let lat: f64 = match arg_str(args[i + 1]).parse() {
            Ok(v) => v,
            Err(_) => {
                resp::write_error(out, "ERR value is not a valid float");
                return CmdResult::Written;
            }
        };
        if let Err(e) = geo::validate_coords(lon, lat) {
            resp::write_error(out, &e);
            return CmdResult::Written;
        }
        members.push((args[i + 2], geo::geohash_encode(lon, lat) as f64));
        i += 3;
    }
    match store.zadd(key, &members, nx, xx, false, false, ch, now) {
        Ok(n) => resp::write_integer(out, n),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_geodist(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 || args.len() > 5 {
        resp::write_error(out, "ERR wrong number of arguments for 'geodist' command");
        return CmdResult::Written;
    }
    let unit = if args.len() == 5 {
        match DistUnit::parse(arg_str(args[4])) {
            Some(u) => u,
            None => {
                resp::write_error(
                    out,
                    "ERR unsupported unit provided. please use M, KM, FT, MI",
                );
                return CmdResult::Written;
            }
        }
    } else {
        DistUnit::M
    };
    let s1 = match store.zscore(args[1], args[2], now) {
        Ok(Some(s)) => s,
        Ok(None) => {
            resp::write_null(out);
            return CmdResult::Written;
        }
        Err(e) => {
            resp::write_error(out, &e);
            return CmdResult::Written;
        }
    };
    let s2 = match store.zscore(args[1], args[3], now) {
        Ok(Some(s)) => s,
        Ok(None) => {
            resp::write_null(out);
            return CmdResult::Written;
        }
        Err(e) => {
            resp::write_error(out, &e);
            return CmdResult::Written;
        }
    };
    let (lon1, lat1) = geo::geohash_decode(s1 as u64);
    let (lon2, lat2) = geo::geohash_decode(s2 as u64);
    let dist = unit.from_meters(geo::haversine(lon1, lat1, lon2, lat2));
    resp::write_bulk(out, &format!("{:.4}", dist));
    CmdResult::Written
}

pub fn cmd_geopos(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'geopos' command");
        return CmdResult::Written;
    }
    let members = args.get(2..).unwrap_or(&[]);
    let scores = match store.zscores(args[1], members, now) {
        Ok(scores) => scores,
        Err(e) => {
            resp::write_error(out, &e);
            return CmdResult::Written;
        }
    };
    resp::write_array_header(out, members.len());
    for score in scores {
        if let Some(s) = score {
            let (lon, lat) = geo::geohash_decode(s as u64);
            resp::write_array_header(out, 2);
            resp::write_bulk(out, &format_geo_coord(lon));
            resp::write_bulk(out, &format_geo_coord(lat));
        } else {
            resp::write_null_array(out);
        }
    }
    CmdResult::Written
}

pub fn cmd_geohash(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'geohash' command");
        return CmdResult::Written;
    }
    resp::write_array_header(out, args.len().saturating_sub(2));
    for member in args.get(2..).unwrap_or(&[]) {
        match store.zscore(args[1], member, now) {
            Ok(Some(s)) => resp::write_bulk(out, &geo::geohash_to_base32(s as u64)),
            Ok(None) => resp::write_null(out),
            Err(e) => {
                resp::write_error(out, &e);
                return CmdResult::Written;
            }
        }
    }
    CmdResult::Written
}

struct GeoSearchParams {
    center_lon: f64,
    center_lat: f64,
    radius_m: Option<f64>,
    box_width_m: Option<f64>,
    box_height_m: Option<f64>,
    sort: Option<bool>,
    count: Option<usize>,
    count_any: bool,
    with_coord: bool,
    with_dist: bool,
    with_hash: bool,
    unit: DistUnit,
    store_key: Option<Vec<u8>>,
    store_dist: bool,
}

struct GeoResult {
    member: String,
    dist: f64,
    hash: u64,
    lon: f64,
    lat: f64,
}

fn execute_geosearch(
    store: &Store,
    key: &[u8],
    params: &GeoSearchParams,
    now: Instant,
) -> Result<Vec<GeoResult>, String> {
    let radius_bounds = params.radius_m.map(|radius| {
        let lat_delta = (radius / 6372797.560856).to_degrees();
        let lon_delta = if params.center_lat.abs() < 89.0 {
            (radius / (6372797.560856 * params.center_lat.to_radians().cos())).to_degrees()
        } else {
            360.0
        };
        (
            (params.center_lon - lon_delta).max(-180.0),
            (params.center_lon + lon_delta).min(180.0),
            (params.center_lat - lat_delta).max(-85.05112878),
            (params.center_lat + lat_delta).min(85.05112878),
        )
    });
    let mut results: Vec<GeoResult> = Vec::new();
    let topk_asc_radius = params.radius_m.is_some()
        && params.sort == Some(true)
        && params.count.is_some()
        && !params.count_any;
    let topk_limit = params.count.unwrap_or(0);
    let mut process = |member: &str, score: f64| {
        let hash = score as u64;
        let (lon, lat) = geo::geohash_decode(hash);
        if let Some((min_lon, max_lon, min_lat, max_lat)) = radius_bounds {
            if lon < min_lon || lon > max_lon || lat < min_lat || lat > max_lat {
                return;
            }
        }
        let dist = geo::haversine(params.center_lon, params.center_lat, lon, lat);

        let in_area = if let Some(radius) = params.radius_m {
            dist <= radius
        } else if let (Some(w), Some(h)) = (params.box_width_m, params.box_height_m) {
            geo::in_box(params.center_lon, params.center_lat, w, h, lon, lat)
        } else {
            false
        };

        if in_area {
            let candidate = GeoResult {
                member: member.to_string(),
                dist,
                hash,
                lon,
                lat,
            };
            if topk_asc_radius && topk_limit > 0 {
                if results.len() < topk_limit {
                    results.push(candidate);
                } else {
                    let mut worst_idx = 0usize;
                    let mut worst_dist = results[0].dist;
                    for (i, r) in results.iter().enumerate().skip(1) {
                        if r.dist > worst_dist {
                            worst_dist = r.dist;
                            worst_idx = i;
                        }
                    }
                    if candidate.dist < worst_dist {
                        results[worst_idx] = candidate;
                    }
                }
            } else {
                results.push(candidate);
            }
        }
    };

    if let Some(radius) = params.radius_m {
        let padded = radius * 2.0;
        let lat_delta = (padded / 6372797.560856).to_degrees();
        let lon_delta = if params.center_lat.abs() < 89.0 {
            (padded / (6372797.560856 * params.center_lat.to_radians().cos())).to_degrees()
        } else {
            360.0
        };
        if lon_delta < 180.0 && lat_delta < 80.0 {
            let min_lon = (params.center_lon - lon_delta).max(-180.0);
            let min_lat = (params.center_lat - lat_delta).max(-85.05112878);
            let max_lon = (params.center_lon + lon_delta).min(180.0);
            let max_lat = (params.center_lat + lat_delta).min(85.05112878);
            let hashes = [
                geo::geohash_encode(min_lon, min_lat),
                geo::geohash_encode(max_lon, max_lat),
                geo::geohash_encode(min_lon, max_lat),
                geo::geohash_encode(max_lon, min_lat),
            ];
            let lo = *hashes.iter().min().unwrap() as f64;
            let hi = *hashes.iter().max().unwrap() as f64;
            store.zvisit_scores_inclusive(key, lo, hi, now, &mut process)?;
        } else {
            store.zvisit_all_scores(key, now, &mut process)?;
        }
    } else {
        store.zvisit_all_scores(key, now, &mut process)?;
    }

    if params.count_any {
        if let Some(count) = params.count {
            results.truncate(count);
        }
        if let Some(asc) = params.sort {
            if asc {
                results.sort_by(|a, b| {
                    a.dist
                        .partial_cmp(&b.dist)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
            } else {
                results.sort_by(|a, b| {
                    b.dist
                        .partial_cmp(&a.dist)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
            }
        }
    } else {
        if params.sort.is_some() || params.count.is_some() {
            match params.sort {
                Some(false) => results.sort_by(|a, b| {
                    b.dist
                        .partial_cmp(&a.dist)
                        .unwrap_or(std::cmp::Ordering::Equal)
                }),
                _ => results.sort_by(|a, b| {
                    a.dist
                        .partial_cmp(&b.dist)
                        .unwrap_or(std::cmp::Ordering::Equal)
                }),
            }
        }
        if let Some(count) = params.count {
            results.truncate(count);
        }
    }
    Ok(results)
}

fn write_results(
    store: &Store,
    out: &mut BytesMut,
    results: &[GeoResult],
    params: &GeoSearchParams,
    now: Instant,
) {
    if let Some(dest) = &params.store_key {
        store.del(&[dest]);
        let members: Vec<(&[u8], f64)> = results
            .iter()
            .map(|r| {
                let score = if params.store_dist {
                    params.unit.from_meters(r.dist)
                } else {
                    r.hash as f64
                };
                (r.member.as_bytes(), score)
            })
            .collect();
        if members.is_empty() {
            resp::write_integer(out, 0);
        } else {
            match store.zadd(dest, &members, false, false, false, false, false, now) {
                Ok(n) => resp::write_integer(out, n),
                Err(e) => resp::write_error(out, &e),
            }
        }
        return;
    }

    let extras = params.with_coord as usize + params.with_dist as usize + params.with_hash as usize;
    if extras == 0 {
        resp::write_array_header(out, results.len());
        for r in results {
            resp::write_bulk(out, &r.member);
        }
    } else {
        resp::write_array_header(out, results.len());
        for r in results {
            resp::write_array_header(out, 1 + extras);
            resp::write_bulk(out, &r.member);
            if params.with_dist {
                resp::write_bulk(out, &format!("{:.4}", params.unit.from_meters(r.dist)));
            }
            if params.with_hash {
                resp::write_integer(out, r.hash as i64);
            }
            if params.with_coord {
                resp::write_array_header(out, 2);
                resp::write_bulk(out, &format_geo_coord(r.lon));
                resp::write_bulk(out, &format_geo_coord(r.lat));
            }
        }
    }
}

pub fn cmd_geosearch(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'geosearch' command");
        return CmdResult::Written;
    }
    let key = args[1];
    match parse_geosearch_params(args, 2, store, key, now, false) {
        Ok(params) => match execute_geosearch(store, key, &params, now) {
            Ok(results) => write_results(store, out, &results, &params, now),
            Err(e) => resp::write_error(out, &e),
        },
        Err(GeoParseError::KeyMissing) => resp::write_array_header(out, 0),
        Err(GeoParseError::Err(e)) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_geosearchstore(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() < 5 {
        resp::write_error(
            out,
            "ERR wrong number of arguments for 'geosearchstore' command",
        );
        return CmdResult::Written;
    }
    let dest = args[1];
    let src = args[2];
    let mut store_dist = false;
    for arg in &args[3..] {
        if cmd_eq(arg, b"STOREDIST") {
            store_dist = true;
        }
    }
    match parse_geosearch_params(args, 3, store, src, now, true) {
        Ok(mut params) => {
            params.store_key = Some(dest.to_vec());
            params.store_dist = store_dist;
            match execute_geosearch(store, src, &params, now) {
                Ok(results) => write_results(store, out, &results, &params, now),
                Err(e) => resp::write_error(out, &e),
            }
        }
        Err(GeoParseError::KeyMissing) => resp::write_integer(out, 0),
        Err(GeoParseError::Err(e)) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_georadius(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 6 {
        resp::write_error(out, "ERR wrong number of arguments for 'georadius' command");
        return CmdResult::Written;
    }
    let key = args[1];
    let lon: f64 = match arg_str(args[2]).parse() {
        Ok(v) => v,
        Err(_) => {
            resp::write_error(out, "ERR value is not a valid float");
            return CmdResult::Written;
        }
    };
    let lat: f64 = match arg_str(args[3]).parse() {
        Ok(v) => v,
        Err(_) => {
            resp::write_error(out, "ERR value is not a valid float");
            return CmdResult::Written;
        }
    };
    let radius: f64 = match arg_str(args[4]).parse() {
        Ok(v) => v,
        Err(_) => {
            resp::write_error(out, "ERR value is not a valid float");
            return CmdResult::Written;
        }
    };
    let unit = match DistUnit::parse(arg_str(args[5])) {
        Some(u) => u,
        None => {
            resp::write_error(
                out,
                "ERR unsupported unit provided. please use M, KM, FT, MI",
            );
            return CmdResult::Written;
        }
    };

    let mut params = GeoSearchParams {
        center_lon: lon,
        center_lat: lat,
        radius_m: Some(unit.to_meters(radius)),
        box_width_m: None,
        box_height_m: None,
        sort: None,
        count: None,
        count_any: false,
        with_coord: false,
        with_dist: false,
        with_hash: false,
        unit,
        store_key: None,
        store_dist: false,
    };

    if let Err(true) = parse_legacy_options(args, 6, &mut params, out) {
        return CmdResult::Written;
    }

    match execute_geosearch(store, key, &params, now) {
        Ok(results) => write_results(store, out, &results, &params, now),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_georadiusbymember(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() < 5 {
        resp::write_error(
            out,
            "ERR wrong number of arguments for 'georadiusbymember' command",
        );
        return CmdResult::Written;
    }
    let key = args[1];
    let radius: f64 = match arg_str(args[3]).parse() {
        Ok(v) => v,
        Err(_) => {
            resp::write_error(out, "ERR value is not a valid float");
            return CmdResult::Written;
        }
    };
    let unit = match DistUnit::parse(arg_str(args[4])) {
        Some(u) => u,
        None => {
            resp::write_error(
                out,
                "ERR unsupported unit provided. please use M, KM, FT, MI",
            );
            return CmdResult::Written;
        }
    };

    let mut params = GeoSearchParams {
        center_lon: 0.0,
        center_lat: 0.0,
        radius_m: Some(unit.to_meters(radius)),
        box_width_m: None,
        box_height_m: None,
        sort: None,
        count: None,
        count_any: false,
        with_coord: false,
        with_dist: false,
        with_hash: false,
        unit,
        store_key: None,
        store_dist: false,
    };

    if let Err(true) = parse_legacy_options(args, 5, &mut params, out) {
        return CmdResult::Written;
    }

    let (lon, lat) = match lookup_member_coords(store, key, args[2], now) {
        Ok(MemberLookup::Found(lon, lat)) => (lon, lat),
        Ok(MemberLookup::KeyMissing) => {
            if params.store_key.is_some() {
                resp::write_integer(out, 0);
            } else {
                resp::write_array_header(out, 0);
            }
            return CmdResult::Written;
        }
        Ok(MemberLookup::MemberMissing) => {
            resp::write_error(out, "ERR could not decode requested zset member");
            return CmdResult::Written;
        }
        Err(e) => {
            resp::write_error(out, &e);
            return CmdResult::Written;
        }
    };
    params.center_lon = lon;
    params.center_lat = lat;

    match execute_geosearch(store, key, &params, now) {
        Ok(results) => write_results(store, out, &results, &params, now),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

fn parse_legacy_options(
    args: &[&[u8]],
    start: usize,
    params: &mut GeoSearchParams,
    out: &mut BytesMut,
) -> Result<(), bool> {
    let mut i = start;
    while i < args.len() {
        if cmd_eq(args[i], b"WITHCOORD") || cmd_eq(args[i], b"WITHCOORDS") {
            params.with_coord = true;
        } else if cmd_eq(args[i], b"WITHDIST") {
            params.with_dist = true;
        } else if cmd_eq(args[i], b"WITHHASH") {
            params.with_hash = true;
        } else if cmd_eq(args[i], b"ASC") {
            params.sort = Some(true);
        } else if cmd_eq(args[i], b"DESC") {
            params.sort = Some(false);
        } else if cmd_eq(args[i], b"COUNT") {
            if i + 1 >= args.len() {
                resp::write_error(out, "ERR syntax error");
                return Err(true);
            }
            match arg_str(args[i + 1]).parse::<usize>() {
                Ok(n) => params.count = Some(n),
                Err(_) => {
                    resp::write_error(out, "ERR syntax error");
                    return Err(true);
                }
            }
            i += 1;
            if i + 1 < args.len() && cmd_eq(args[i + 1], b"ANY") {
                params.count_any = true;
                i += 1;
            }
        } else if cmd_eq(args[i], b"ANY") {
            params.count_any = true;
        } else if cmd_eq(args[i], b"STORE") {
            if i + 1 >= args.len() {
                resp::write_error(out, "ERR syntax error");
                return Err(true);
            }
            params.store_key = Some(args[i + 1].to_vec());
            i += 1;
        } else if cmd_eq(args[i], b"STOREDIST") {
            if i + 1 >= args.len() {
                resp::write_error(out, "ERR syntax error");
                return Err(true);
            }
            params.store_key = Some(args[i + 1].to_vec());
            params.store_dist = true;
            i += 1;
        }
        i += 1;
    }
    if params.count_any && params.count.is_none() {
        resp::write_error(out, "ERR syntax error. ANY requires COUNT option");
        return Err(true);
    }
    if params.store_key.is_some() && (params.with_coord || params.with_dist || params.with_hash) {
        resp::write_error(out, "ERR STORE option in GEORADIUS is not compatible with WITHDIST, WITHHASH and WITHCOORD options");
        return Err(true);
    }
    Ok(())
}

enum GeoParseError {
    KeyMissing,
    Err(String),
}

#[allow(clippy::too_many_arguments)]
fn parse_geosearch_params(
    args: &[&[u8]],
    start: usize,
    store: &Store,
    key: &[u8],
    now: Instant,
    is_store: bool,
) -> Result<GeoSearchParams, GeoParseError> {
    let mut center_lon = None;
    let mut center_lat = None;
    let mut radius_m = None;
    let mut box_width_m = None;
    let mut box_height_m = None;
    let mut sort = None;
    let mut count = None;
    let mut count_any = false;
    let mut with_coord = false;
    let mut with_dist = false;
    let mut with_hash = false;
    let mut unit = DistUnit::M;
    let mut has_from = false;
    let mut has_by = false;

    let mut i = start;
    while i < args.len() {
        if cmd_eq(args[i], b"FROMMEMBER") && i + 1 < args.len() {
            if has_from {
                return Err(GeoParseError::Err("ERR syntax error".into()));
            }
            has_from = true;
            match lookup_member_coords(store, key, args[i + 1], now) {
                Ok(MemberLookup::Found(lon, lat)) => {
                    center_lon = Some(lon);
                    center_lat = Some(lat);
                }
                Ok(MemberLookup::KeyMissing) => return Err(GeoParseError::KeyMissing),
                Ok(MemberLookup::MemberMissing) => {
                    return Err(GeoParseError::Err(
                        "ERR could not decode requested zset member".into(),
                    ))
                }
                Err(e) => return Err(GeoParseError::Err(e)),
            }
            i += 2;
        } else if cmd_eq(args[i], b"FROMLONLAT") && i + 2 < args.len() {
            if has_from {
                return Err(GeoParseError::Err("ERR syntax error".into()));
            }
            has_from = true;
            let lon: f64 = arg_str(args[i + 1])
                .parse()
                .map_err(|_| GeoParseError::Err("ERR value is not a valid float".into()))?;
            let lat: f64 = arg_str(args[i + 2])
                .parse()
                .map_err(|_| GeoParseError::Err("ERR value is not a valid float".into()))?;
            geo::validate_coords(lon, lat).map_err(GeoParseError::Err)?;
            center_lon = Some(lon);
            center_lat = Some(lat);
            i += 3;
        } else if cmd_eq(args[i], b"BYRADIUS") && i + 2 < args.len() {
            if has_by {
                return Err(GeoParseError::Err("ERR syntax error".into()));
            }
            has_by = true;
            let r: f64 = arg_str(args[i + 1])
                .parse()
                .map_err(|_| GeoParseError::Err("ERR value is not a valid float".into()))?;
            let u = DistUnit::parse(arg_str(args[i + 2])).ok_or_else(|| {
                GeoParseError::Err("ERR unsupported unit provided. please use M, KM, FT, MI".into())
            })?;
            unit = u;
            radius_m = Some(u.to_meters(r));
            i += 3;
        } else if cmd_eq(args[i], b"BYBOX") && i + 3 < args.len() {
            if has_by {
                return Err(GeoParseError::Err("ERR syntax error".into()));
            }
            has_by = true;
            let w: f64 = arg_str(args[i + 1])
                .parse()
                .map_err(|_| GeoParseError::Err("ERR value is not a valid float".into()))?;
            let h: f64 = arg_str(args[i + 2])
                .parse()
                .map_err(|_| GeoParseError::Err("ERR value is not a valid float".into()))?;
            let u = DistUnit::parse(arg_str(args[i + 3])).ok_or_else(|| {
                GeoParseError::Err("ERR unsupported unit provided. please use M, KM, FT, MI".into())
            })?;
            unit = u;
            box_width_m = Some(u.to_meters(w));
            box_height_m = Some(u.to_meters(h));
            i += 4;
        } else if cmd_eq(args[i], b"ASC") {
            sort = Some(true);
            i += 1;
        } else if cmd_eq(args[i], b"DESC") {
            sort = Some(false);
            i += 1;
        } else if cmd_eq(args[i], b"COUNT") && i + 1 < args.len() {
            count = arg_str(args[i + 1]).parse().ok();
            if count.is_none() {
                return Err(GeoParseError::Err("ERR syntax error".into()));
            }
            i += 2;
            if i < args.len() && cmd_eq(args[i], b"ANY") {
                count_any = true;
                i += 1;
            }
        } else if cmd_eq(args[i], b"WITHCOORD") {
            with_coord = true;
            i += 1;
        } else if cmd_eq(args[i], b"WITHDIST") {
            with_dist = true;
            i += 1;
        } else if cmd_eq(args[i], b"WITHHASH") {
            with_hash = true;
            i += 1;
        } else if cmd_eq(args[i], b"STOREDIST") {
            if !is_store {
                return Err(GeoParseError::Err("ERR syntax error".into()));
            }
            i += 1;
        } else if cmd_eq(args[i], b"STORE") {
            if !is_store {
                return Err(GeoParseError::Err("ERR syntax error".into()));
            }
            return Err(GeoParseError::Err("ERR syntax error".into()));
        } else {
            i += 1;
        }
    }

    if !has_from {
        return Err(GeoParseError::Err(
            "ERR exactly one of FROMMEMBER or FROMLONLAT must be provided".into(),
        ));
    }
    if !has_by {
        return Err(GeoParseError::Err(
            "ERR exactly one of BYRADIUS and BYBOX must be provided".into(),
        ));
    }
    if count_any && count.is_none() {
        return Err(GeoParseError::Err("ERR syntax error".into()));
    }

    Ok(GeoSearchParams {
        center_lon: center_lon.unwrap(),
        center_lat: center_lat.unwrap(),
        radius_m,
        box_width_m,
        box_height_m,
        sort,
        count,
        count_any,
        with_coord,
        with_dist,
        with_hash,
        unit,
        store_key: None,
        store_dist: false,
    })
}
