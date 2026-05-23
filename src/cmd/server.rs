use bytes::BytesMut;
use std::sync::atomic::Ordering;
use std::time::Instant;

use crate::resp;
use crate::store::Store;
use crate::{CONNECTED_CLIENTS, START_TIME, TOTAL_COMMANDS};

use super::{arg_str, cmd_eq, is_restricted, CmdResult};

pub fn cmd_ping(args: &[&[u8]], _store: &Store, out: &mut BytesMut, _now: Instant) -> CmdResult {
    if args.len() > 1 {
        resp::write_bulk_raw(out, args[1]);
    } else {
        resp::write_pong(out);
    }
    CmdResult::Written
}

pub fn cmd_echo(args: &[&[u8]], _store: &Store, out: &mut BytesMut, _now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'echo' command");
    } else {
        resp::write_bulk_raw(out, args[1]);
    }
    CmdResult::Written
}

pub fn cmd_quit(_args: &[&[u8]], _store: &Store, out: &mut BytesMut, _now: Instant) -> CmdResult {
    resp::write_ok(out);
    CmdResult::Written
}

pub fn cmd_hello(args: &[&[u8]], store: &Store, out: &mut BytesMut, _now: Instant) -> CmdResult {
    let mut authenticated = false;
    let mut auth_failed = false;
    let mut i = 2;
    while i < args.len() {
        if cmd_eq(args[i], b"AUTH") {
            if i + 2 >= args.len() {
                resp::write_error(
                    out,
                    "ERR wrong number of arguments for 'hello' AUTH section",
                );
                return CmdResult::Written;
            }
            let password = arg_str(args[i + 2]);
            let expected = &store.config().password;
            if expected.is_empty() {
                resp::write_error(out, "ERR Client sent AUTH, but no password is set");
                return CmdResult::Written;
            } else if constant_time_eq(password.as_bytes(), expected.as_bytes()) {
                authenticated = true;
            } else {
                auth_failed = true;
            }
            i += 3;
        } else if cmd_eq(args[i], b"SETNAME") {
            i += 2;
        } else {
            i += 1;
        }
    }

    if auth_failed {
        resp::write_error(out, "WRONGPASS invalid password");
        return CmdResult::Written;
    }

    let requested_proto = if args.len() >= 2 {
        arg_str(args[1]).parse::<i64>().unwrap_or(2)
    } else {
        2
    };

    if requested_proto == 3 {
        resp::write_map_header(out, 7);
    } else {
        resp::write_array_header(out, 14);
    }
    resp::write_bulk(out, "server");
    resp::write_bulk(out, "lux");
    resp::write_bulk(out, "version");
    resp::write_bulk(out, env!("CARGO_PKG_VERSION"));
    resp::write_bulk(out, "proto");
    resp::write_integer(out, 2);
    resp::write_bulk(out, "id");
    resp::write_integer(out, 1);
    resp::write_bulk(out, "mode");
    resp::write_bulk(out, "standalone");
    resp::write_bulk(out, "role");
    resp::write_bulk(out, "master");
    resp::write_bulk(out, "modules");
    resp::write_array_header(out, 0);

    if authenticated {
        return CmdResult::Authenticated;
    }
    CmdResult::Written
}

pub fn cmd_info(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    let section = if args.len() > 1 {
        arg_str(args[1]).to_lowercase()
    } else {
        "all".to_string()
    };
    let info = build_info(store, &section, now);
    resp::write_bulk(out, &info);
    CmdResult::Written
}

pub fn cmd_time(_args: &[&[u8]], _store: &Store, out: &mut BytesMut, _now: Instant) -> CmdResult {
    let now_sys = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    resp::write_array_header(out, 2);
    resp::write_bulk(out, &now_sys.as_secs().to_string());
    resp::write_bulk(out, &(now_sys.subsec_micros()).to_string());
    CmdResult::Written
}

pub fn cmd_save(_args: &[&[u8]], store: &Store, out: &mut BytesMut, _now: Instant) -> CmdResult {
    match crate::snapshot::save(store) {
        Ok(n) => resp::write_simple(out, &format!("OK ({n} keys saved)")),
        Err(e) => resp::write_error(out, &format!("ERR snapshot failed: {e}")),
    }
    CmdResult::Written
}

pub fn cmd_bgsave(_args: &[&[u8]], store: &Store, out: &mut BytesMut, _now: Instant) -> CmdResult {
    match crate::snapshot::save(store) {
        Ok(_) => resp::write_simple(out, "Background saving started"),
        Err(e) => resp::write_error(out, &format!("ERR snapshot failed: {e}")),
    }
    CmdResult::Written
}

pub fn cmd_lastsave(
    _args: &[&[u8]],
    _store: &Store,
    out: &mut BytesMut,
    _now: Instant,
) -> CmdResult {
    resp::write_integer(
        out,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64,
    );
    CmdResult::Written
}

/// Constant-time byte comparison to prevent timing attacks on password auth.
/// Always compares all bytes regardless of where the first mismatch is.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // Still do a dummy comparison to avoid leaking length via timing.
        let mut _acc = 0u8;
        for &byte in a {
            _acc |= byte;
        }
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn cmd_auth(args: &[&[u8]], store: &Store, out: &mut BytesMut, _now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'auth' command");
        return CmdResult::Written;
    }
    let expected = &store.config().password;
    if expected.is_empty() {
        resp::write_error(out, "ERR Client sent AUTH, but no password is set");
    } else if constant_time_eq(arg_str(args[1]).as_bytes(), expected.as_bytes()) {
        resp::write_ok(out);
        return CmdResult::Authenticated;
    } else {
        resp::write_error(out, "WRONGPASS invalid password");
    }
    CmdResult::Written
}

pub fn cmd_config(args: &[&[u8]], _store: &Store, out: &mut BytesMut, _now: Instant) -> CmdResult {
    if args.len() > 1 && cmd_eq(args[1], b"GET") {
        resp::write_array_header(out, 0);
    } else {
        resp::write_ok(out);
    }
    CmdResult::Written
}

pub fn cmd_client(_args: &[&[u8]], _store: &Store, out: &mut BytesMut, _now: Instant) -> CmdResult {
    resp::write_ok(out);
    CmdResult::Written
}

pub fn cmd_select(_args: &[&[u8]], _store: &Store, out: &mut BytesMut, _now: Instant) -> CmdResult {
    resp::write_ok(out);
    CmdResult::Written
}

pub fn cmd_command(args: &[&[u8]], _store: &Store, out: &mut BytesMut, _now: Instant) -> CmdResult {
    if args.len() > 1 && cmd_eq(args[1], b"DOCS") {
        resp::write_array_header(out, 0);
    } else {
        resp::write_ok(out);
    }
    CmdResult::Written
}

pub fn cmd_noop_ok(
    _args: &[&[u8]],
    _store: &Store,
    out: &mut BytesMut,
    _now: Instant,
) -> CmdResult {
    resp::write_ok(out);
    CmdResult::Written
}

fn build_info(store: &Store, _section: &str, now: Instant) -> String {
    let uptime = START_TIME.get().map(|t| t.elapsed().as_secs()).unwrap_or(0);
    let restricted = is_restricted(store);
    let powered_by = if restricted {
        "\r\npowered_by:LuxDB Cloud (luxdb.dev)"
    } else {
        ""
    };
    format!(
        "# Server\r\n\
         redis_version:7.2.0\r\n\
         lux_version:{}\r\n\
         shards:{}\r\n\
         uptime_in_seconds:{}\r\n\
         {powered_by}\
         \r\n\
         # Clients\r\n\
         connected_clients:{}\r\n\
         \r\n\
         # Stats\r\n\
         total_commands_processed:{}\r\n\
         key_events_enqueued:{}\r\n\
         key_events_dropped:{}\r\n\
         key_events_emitted:{}\r\n\
         key_events_coalesced:{}\r\n\
         \r\n\
         # Memory\r\n\
         used_memory_bytes:{}\r\n\
         \r\n\
         # Storage\r\n\
         storage_mode:{}\r\n\
         used_disk_bytes:{}\r\n\
         disk_keys:{}\r\n\
         \r\n\
         # Persistence\r\n\
         persistence_err_wal_append:{}\r\n\
         persistence_err_wal_fsync:{}\r\n\
         persistence_err_disk_write:{}\r\n\
         \r\n\
         # Keyspace\r\n\
         db0:keys={},expires=0,avg_ttl=0\r\n\
         keys:{}\r\n\
         vector_keys:{}\r\n",
        env!("CARGO_PKG_VERSION"),
        store.shard_count(),
        uptime,
        CONNECTED_CLIENTS.load(Ordering::Relaxed),
        TOTAL_COMMANDS.load(Ordering::Relaxed),
        crate::pubsub::KEY_EVENTS_ENQUEUED.load(Ordering::Relaxed),
        crate::pubsub::KEY_EVENTS_DROPPED.load(Ordering::Relaxed),
        crate::pubsub::KEY_EVENTS_EMITTED.load(Ordering::Relaxed),
        crate::pubsub::KEY_EVENTS_COALESCED.load(Ordering::Relaxed),
        store.approximate_memory(),
        if store.config().storage.mode == crate::disk::StorageMode::Tiered {
            "tiered"
        } else {
            "memory"
        },
        store.disk_usage_bytes(),
        store.disk_key_count(),
        crate::store::PERSISTENCE_ERR_WAL_APPEND.load(Ordering::Relaxed),
        crate::store::PERSISTENCE_ERR_WAL_FSYNC.load(Ordering::Relaxed),
        crate::store::PERSISTENCE_ERR_DISK_WRITE.load(Ordering::Relaxed),
        store.dbsize(now),
        store.dbsize(now),
        store.vcard(now)
    )
}
