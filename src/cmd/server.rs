use bytes::BytesMut;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use crate::pubsub::Broker;
use crate::resp;
use crate::store::Store;

use super::{arg_str, cmd_eq, is_restricted, CmdResult};

static ZSET_MAX_ZIPLIST_ENTRIES: AtomicUsize = AtomicUsize::new(128);

pub(crate) fn zset_max_ziplist_entries() -> usize {
    ZSET_MAX_ZIPLIST_ENTRIES.load(Ordering::Relaxed)
}

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

pub fn cmd_info(
    args: &[&[u8]],
    store: &Store,
    broker: &Broker,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    let section = if args.len() > 1 {
        arg_str(args[1]).to_lowercase()
    } else {
        "all".to_string()
    };
    let mut info = build_info(store, broker, &section, now);
    if section == "all" || section == "push" {
        info.push_str("\r\n");
        crate::push::append_info(&mut info);
    }
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
    match crate::snapshot::save_and_truncate_wal_consistent(store) {
        Ok(n) => resp::write_simple(out, &format!("OK ({n} keys saved)")),
        Err(e) => resp::write_error(out, &format!("ERR snapshot failed: {e}")),
    }
    CmdResult::Written
}

pub fn cmd_bgsave(_args: &[&[u8]], store: &Store, out: &mut BytesMut, _now: Instant) -> CmdResult {
    match crate::snapshot::save_and_truncate_wal_consistent(store) {
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
    if args.len() > 2 && cmd_eq(args[1], b"GET") {
        if cmd_eq(args[2], b"zset-max-ziplist-entries")
            || cmd_eq(args[2], b"zset-max-listpack-entries")
        {
            resp::write_array_header(out, 2);
            resp::write_bulk(out, arg_str(args[2]));
            resp::write_bulk(out, &zset_max_ziplist_entries().to_string());
        } else {
            resp::write_array_header(out, 0);
        }
    } else if args.len() > 3 && cmd_eq(args[1], b"SET") {
        if cmd_eq(args[2], b"zset-max-ziplist-entries")
            || cmd_eq(args[2], b"zset-max-listpack-entries")
        {
            match arg_str(args[3]).parse::<usize>() {
                Ok(value) => {
                    ZSET_MAX_ZIPLIST_ENTRIES.store(value, Ordering::Relaxed);
                    resp::write_ok(out);
                }
                Err(_) => resp::write_error(out, "ERR invalid argument"),
            }
        } else {
            resp::write_ok(out);
        }
    } else {
        resp::write_ok(out);
    }
    CmdResult::Written
}

pub fn cmd_client(_args: &[&[u8]], _store: &Store, out: &mut BytesMut, _now: Instant) -> CmdResult {
    resp::write_ok(out);
    CmdResult::Written
}

pub fn cmd_select(args: &[&[u8]], _store: &Store, out: &mut BytesMut, _now: Instant) -> CmdResult {
    // Lux is single-database. SELECT 0 is a no-op OK; any other index is an
    // honest out-of-range error instead of a silent fake OK.
    let Some(idx) = args.get(1) else {
        resp::write_error(out, "ERR wrong number of arguments for 'select' command");
        return CmdResult::Written;
    };
    match arg_str(idx).parse::<i64>() {
        Ok(0) => resp::write_ok(out),
        Ok(_) => resp::write_error(out, "ERR DB index is out of range"),
        Err(_) => resp::write_error(out, "ERR value is not an integer or out of range"),
    }
    CmdResult::Written
}

pub fn cmd_command(args: &[&[u8]], _store: &Store, out: &mut BytesMut, _now: Instant) -> CmdResult {
    if args.len() > 1 && cmd_eq(args[1], b"COUNT") {
        // Real count of registered commands, not a fake +OK.
        resp::write_integer(out, super::command_count() as i64);
    } else if args.len() > 1 && (cmd_eq(args[1], b"GETKEYS") || cmd_eq(args[1], b"GETKEYSANDFLAGS"))
    {
        resp::write_error(out, "ERR COMMAND GETKEYS is not supported");
    } else {
        // COMMAND / COMMAND INFO / COMMAND DOCS / COMMAND LIST: per-command
        // metadata is not implemented yet, so return an empty array of the
        // correct shape rather than a fake +OK.
        resp::write_array_header(out, 0);
    }
    CmdResult::Written
}

/// WAIT reports how many replicas acknowledged. Lux has no replication, so the
/// honest answer is the integer 0 (Redis WAIT returns an integer, not +OK).
pub fn cmd_wait(_args: &[&[u8]], _store: &Store, out: &mut BytesMut, _now: Instant) -> CmdResult {
    resp::write_integer(out, 0);
    CmdResult::Written
}

/// SWAPDB requires multiple databases, which Lux does not have.
pub fn cmd_swapdb(_args: &[&[u8]], _store: &Store, out: &mut BytesMut, _now: Instant) -> CmdResult {
    resp::write_error(out, "ERR SWAPDB is not supported: Lux is a single database");
    CmdResult::Written
}

/// LATENCY: no latency monitoring is kept. RESET clears 0 events; the reporting
/// forms return an empty array of the right shape instead of a fake +OK.
pub fn cmd_latency(args: &[&[u8]], _store: &Store, out: &mut BytesMut, _now: Instant) -> CmdResult {
    if args.len() > 1 && cmd_eq(args[1], b"RESET") {
        resp::write_integer(out, 0);
    } else {
        resp::write_array_header(out, 0);
    }
    CmdResult::Written
}

/// RESET replies with the +RESET status line (Redis-correct), not +OK.
pub fn cmd_reset(_args: &[&[u8]], _store: &Store, out: &mut BytesMut, _now: Instant) -> CmdResult {
    resp::write_simple(out, "RESET");
    CmdResult::Written
}

/// Redis Functions are not implemented. LIST honestly reports no libraries; any
/// other subcommand returns a clear unsupported error instead of a fake +OK.
pub fn cmd_function(
    args: &[&[u8]],
    _store: &Store,
    out: &mut BytesMut,
    _now: Instant,
) -> CmdResult {
    if args.len() > 1 && cmd_eq(args[1], b"LIST") {
        resp::write_array_header(out, 0);
    } else {
        resp::write_error(out, "ERR FUNCTION is not supported");
    }
    CmdResult::Written
}

/// DUMP has no serialization format in Lux; a fake +OK would hand clients a
/// bogus payload, so return a clear unsupported error.
pub fn cmd_dump(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() != 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'dump' command");
        return CmdResult::Written;
    }
    match store.dump_key(args[1], now) {
        Ok(Some(blob)) => resp::write_bulk_raw(out, &blob),
        Ok(None) => resp::write_null(out),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

/// RESTORE key ttl serialized-value [REPLACE] [ABSTTL] [IDLETIME n] [FREQ n].
/// The serialized value must come from Lux DUMP (not RDB-compatible).
pub fn cmd_restore(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'restore' command");
        return CmdResult::Written;
    }
    let Ok(ttl_ms) = arg_str(args[2]).parse::<i64>() else {
        resp::write_error(out, "ERR value is not an integer or out of range");
        return CmdResult::Written;
    };
    let mut replace = false;
    let mut absttl = false;
    let mut i = 4;
    while i < args.len() {
        if cmd_eq(args[i], b"REPLACE") {
            replace = true;
            i += 1;
        } else if cmd_eq(args[i], b"ABSTTL") {
            absttl = true;
            i += 1;
        } else if (cmd_eq(args[i], b"IDLETIME") || cmd_eq(args[i], b"FREQ")) && i + 1 < args.len() {
            // Accepted for compatibility; Lux does not use LRU/LFU restore hints.
            i += 2;
        } else {
            resp::write_error(out, "ERR syntax error");
            return CmdResult::Written;
        }
    }
    match store.restore_key(args[1], ttl_ms, args[3], replace, absttl, now) {
        Ok(()) => resp::write_ok(out),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

/// TOUCH key [key ...]: returns the number of keys that exist (Lux does not
/// track access recency for eviction the way Redis LRU/LFU does).
pub fn cmd_touch(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'touch' command");
        return CmdResult::Written;
    }
    let keys: Vec<&[u8]> = args[1..].to_vec();
    resp::write_integer(out, store.exists(&keys, now));
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

fn build_info(store: &Store, broker: &Broker, _section: &str, now: Instant) -> String {
    let key_event_stats = broker.key_event_stats();
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
         blocked_list_waiters:{}\r\n\
         blocked_stream_waiters:{}\r\n\
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
         tracked_key_count:{}\r\n\
         tracked_total_key_count:{}\r\n\
         vector_keys:{}\r\n",
        env!("CARGO_PKG_VERSION"),
        store.shard_count(),
        store.uptime_seconds(),
        store.connected_clients(),
        broker.list_waiter_count(),
        broker.stream_waiter_count(),
        store.total_commands(),
        key_event_stats.enqueued,
        key_event_stats.dropped,
        key_event_stats.emitted,
        key_event_stats.coalesced,
        store.approximate_memory(),
        if store.config().storage.mode == crate::disk::StorageMode::Tiered {
            "tiered"
        } else {
            "memory"
        },
        store.disk_usage_bytes(),
        store.disk_key_count(),
        store.persistence_wal_append_errors(),
        store.persistence_wal_fsync_errors(),
        store.persistence_disk_write_errors(),
        store.dbsize(now),
        store.dbsize(now),
        store.tracked_key_count(),
        store.tracked_key_count() + store.disk_key_count(),
        store.vcard(now)
    )
}
