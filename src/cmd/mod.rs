mod bitops;
mod geo;
mod hashes;
mod hll;
mod keys;
mod lists;
mod pubsub;
mod scripting;
mod server;
mod sets;
mod sort;
mod sorted_sets;
mod streams;
mod strings;
mod tables;
mod timeseries;
mod vectors;

use bytes::{Bytes, BytesMut};
use std::collections::VecDeque;
use std::time::Instant;

use crate::pubsub::Broker;
use crate::resp;
use crate::store::{Entry, Store, StoreValue};

pub enum CmdResult {
    Written,
    Authenticated,
    Subscribe {
        channels: Vec<String>,
    },
    PSubscribe {
        patterns: Vec<String>,
    },
    Publish {
        channel: String,
        message: String,
    },
    BlockPop {
        keys: Vec<String>,
        timeout: std::time::Duration,
        pop_left: bool,
    },
    BlockZPop {
        keys: Vec<String>,
        timeout: std::time::Duration,
        pop_min: bool,
    },
    BlockMove {
        src: String,
        dst: String,
        src_left: bool,
        dst_left: bool,
        timeout: std::time::Duration,
    },
    BlockStreamRead {
        keys: Vec<String>,
        ids: Vec<String>,
        group: Option<(String, String)>,
        count: Option<usize>,
        noack: bool,
        timeout: std::time::Duration,
    },
    KSubscribe {
        patterns: Vec<String>,
    },
    KUnsubscribe {
        patterns: Vec<String>,
    },
    Eval {
        script: String,
        keys: Vec<Vec<u8>>,
        argv: Vec<Vec<u8>>,
    },
    ScriptOp,
}

fn is_restricted() -> bool {
    std::env::var("LUX_RESTRICTED").is_ok_and(|v| v == "1" || v == "true")
}

#[inline(always)]
fn cmd_eq(input: &[u8], expected: &[u8]) -> bool {
    input.len() == expected.len()
        && input
            .iter()
            .zip(expected)
            .all(|(a, b)| a.to_ascii_uppercase() == *b)
}

#[inline(always)]
fn arg_str(arg: &[u8]) -> &str {
    std::str::from_utf8(arg).unwrap_or("")
}

fn parse_u64(arg: &[u8]) -> Result<u64, ()> {
    arg_str(arg).parse::<u64>().map_err(|_| ())
}

fn parse_i64(arg: &[u8]) -> Result<i64, ()> {
    arg_str(arg).parse::<i64>().map_err(|_| ())
}

fn format_float(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{}", v)
    }
}

pub fn execute(
    store: &Store,
    _broker: &Broker,
    args: &[&[u8]],
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.is_empty() {
        resp::write_error(out, "ERR no command");
        return CmdResult::Written;
    }

    let cmd = args[0];

    if cmd_eq(cmd, b"AUTH") {
        return server::cmd_auth(args, store, out, now);
    }

    if (cmd_eq(cmd, b"KEYS")
        || cmd_eq(cmd, b"FLUSHALL")
        || cmd_eq(cmd, b"FLUSHDB")
        || cmd_eq(cmd, b"DEBUG"))
        && is_restricted()
    {
        resp::write_error(out, "ERR command disabled in restricted mode");
        return CmdResult::Written;
    }

    if crate::eviction::is_write_command(cmd) {
        if let Err(e) = crate::eviction::evict_if_needed(store) {
            resp::write_error(out, e);
            return CmdResult::Written;
        }
    }

    if cmd.is_empty() {
        resp::write_error(out, "ERR no command");
        return CmdResult::Written;
    }

    match cmd[0].to_ascii_uppercase() {
        b'A' => {
            if cmd_eq(cmd, b"APPEND") {
                return strings::cmd_append(args, store, out, now);
            }
        }
        b'B' => {
            if cmd_eq(cmd, b"BLPOP") || cmd_eq(cmd, b"BRPOP") {
                return lists::cmd_blpop(args, store, out, now);
            }
            if cmd_eq(cmd, b"BLMOVE") {
                return lists::cmd_blmove(args, store, out, now);
            }
            if cmd_eq(cmd, b"BGSAVE") {
                return server::cmd_bgsave(args, store, out, now);
            }
            if cmd_eq(cmd, b"BZPOPMIN") || cmd_eq(cmd, b"BZPOPMAX") {
                return sorted_sets::cmd_bzpopmin(args, store, out, now);
            }
            if cmd_eq(cmd, b"BITCOUNT") {
                return bitops::cmd_bitcount(args, store, out, now);
            }
            if cmd_eq(cmd, b"BITPOS") {
                return bitops::cmd_bitpos(args, store, out, now);
            }
            if cmd_eq(cmd, b"BITOP") {
                return bitops::cmd_bitop(args, store, out, now);
            }
        }
        b'C' => {
            if cmd_eq(cmd, b"CONFIG") {
                return server::cmd_config(args, store, out, now);
            }
            if cmd_eq(cmd, b"CLIENT") {
                return server::cmd_client(args, store, out, now);
            }
            if cmd_eq(cmd, b"COMMAND") {
                return server::cmd_command(args, store, out, now);
            }
            if cmd_eq(cmd, b"COPY") {
                return keys::cmd_copy(args, store, out, now);
            }
        }
        b'D' => {
            if cmd_eq(cmd, b"DEL") {
                return keys::cmd_del(args, store, out, now);
            }
            if cmd_eq(cmd, b"DBSIZE") {
                return keys::cmd_dbsize(args, store, out, now);
            }
            if cmd_eq(cmd, b"DECR") {
                return strings::cmd_decr(args, store, out, now);
            }
            if cmd_eq(cmd, b"DECRBY") {
                return strings::cmd_decrby(args, store, out, now);
            }
            if cmd_eq(cmd, b"DEBUG") || cmd_eq(cmd, b"DUMP") {
                return server::cmd_noop_ok(args, store, out, now);
            }
            if cmd_eq(cmd, b"DISCARD") {
                resp::write_error(out, &format!("ERR unknown command '{}'", arg_str(cmd)));
                return CmdResult::Written;
            }
        }
        b'E' => {
            if cmd_eq(cmd, b"ECHO") {
                return server::cmd_echo(args, store, out, now);
            }
            if cmd_eq(cmd, b"EXISTS") {
                return keys::cmd_exists(args, store, out, now);
            }
            if cmd_eq(cmd, b"EXPIRE") {
                return keys::cmd_expire(args, store, out, now);
            }
            if cmd_eq(cmd, b"EXPIREAT") {
                return keys::cmd_expireat(args, store, out, now);
            }
            if cmd_eq(cmd, b"EXPIRETIME") {
                return keys::cmd_expiretime(args, store, out, now);
            }
            if cmd_eq(cmd, b"EVAL") {
                return scripting::cmd_eval(args, store, out, now);
            }
            if cmd_eq(cmd, b"EVALSHA") {
                return scripting::cmd_evalsha(args, store, out, now);
            }
            if cmd_eq(cmd, b"EXEC") {
                resp::write_error(out, &format!("ERR unknown command '{}'", arg_str(cmd)));
                return CmdResult::Written;
            }
        }
        b'F' => {
            if cmd_eq(cmd, b"FLUSHDB") || cmd_eq(cmd, b"FLUSHALL") {
                return keys::cmd_flushdb(args, store, out, now);
            }
            if cmd_eq(cmd, b"FUNCTION") {
                return server::cmd_noop_ok(args, store, out, now);
            }
        }
        b'G' => {
            if cmd_eq(cmd, b"GET") {
                return strings::cmd_get(args, store, out, now);
            }
            if cmd_eq(cmd, b"GETBIT") {
                return bitops::cmd_getbit(args, store, out, now);
            }
            if cmd_eq(cmd, b"GETSET") {
                return strings::cmd_getset(args, store, out, now);
            }
            if cmd_eq(cmd, b"GETDEL") {
                return strings::cmd_getdel(args, store, out, now);
            }
            if cmd_eq(cmd, b"GETEX") {
                return strings::cmd_getex(args, store, out, now);
            }
            if cmd_eq(cmd, b"GETRANGE") {
                return strings::cmd_getrange(args, store, out, now);
            }
            if cmd_eq(cmd, b"GEOADD") {
                return geo::cmd_geoadd(args, store, out, now);
            }
            if cmd_eq(cmd, b"GEODIST") {
                return geo::cmd_geodist(args, store, out, now);
            }
            if cmd_eq(cmd, b"GEOPOS") {
                return geo::cmd_geopos(args, store, out, now);
            }
            if cmd_eq(cmd, b"GEOHASH") {
                return geo::cmd_geohash(args, store, out, now);
            }
            if cmd_eq(cmd, b"GEOSEARCH") {
                return geo::cmd_geosearch(args, store, out, now);
            }
            if cmd_eq(cmd, b"GEOSEARCHSTORE") {
                return geo::cmd_geosearchstore(args, store, out, now);
            }
            if cmd_eq(cmd, b"GEORADIUS") {
                return geo::cmd_georadius(args, store, out, now);
            }
            if cmd_eq(cmd, b"GEORADIUSBYMEMBER") || cmd_eq(cmd, b"GEORADIUSBYMEMBER_RO") {
                return geo::cmd_georadiusbymember(args, store, out, now);
            }
            if cmd_eq(cmd, b"GEORADIUS_RO") {
                return geo::cmd_georadius(args, store, out, now);
            }
            if cmd_eq(cmd, b"GEOSEARCH_RO") {
                return geo::cmd_geosearch(args, store, out, now);
            }
        }
        b'H' => {
            if cmd_eq(cmd, b"HSET") || cmd_eq(cmd, b"HMSET") {
                return hashes::cmd_hset(args, store, out, now);
            }
            if cmd_eq(cmd, b"HSETNX") {
                return hashes::cmd_hsetnx(args, store, out, now);
            }
            if cmd_eq(cmd, b"HGET") {
                return hashes::cmd_hget(args, store, out, now);
            }
            if cmd_eq(cmd, b"HMGET") {
                return hashes::cmd_hmget(args, store, out, now);
            }
            if cmd_eq(cmd, b"HDEL") {
                return hashes::cmd_hdel(args, store, out, now);
            }
            if cmd_eq(cmd, b"HGETALL") {
                return hashes::cmd_hgetall(args, store, out, now);
            }
            if cmd_eq(cmd, b"HKEYS") {
                return hashes::cmd_hkeys(args, store, out, now);
            }
            if cmd_eq(cmd, b"HVALS") {
                return hashes::cmd_hvals(args, store, out, now);
            }
            if cmd_eq(cmd, b"HLEN") {
                return hashes::cmd_hlen(args, store, out, now);
            }
            if cmd_eq(cmd, b"HEXISTS") {
                return hashes::cmd_hexists(args, store, out, now);
            }
            if cmd_eq(cmd, b"HINCRBY") {
                return hashes::cmd_hincrby(args, store, out, now);
            }
            if cmd_eq(cmd, b"HINCRBYFLOAT") {
                return hashes::cmd_hincrbyfloat(args, store, out, now);
            }
            if cmd_eq(cmd, b"HSTRLEN") {
                return hashes::cmd_hstrlen(args, store, out, now);
            }
            if cmd_eq(cmd, b"HRANDFIELD") {
                return hashes::cmd_hrandfield(args, store, out, now);
            }
            if cmd_eq(cmd, b"HSCAN") {
                return hashes::cmd_hscan(args, store, out, now);
            }
            if cmd_eq(cmd, b"HELLO") {
                return server::cmd_hello(args, store, out, now);
            }
        }
        b'I' => {
            if cmd_eq(cmd, b"INCR") {
                return strings::cmd_incr(args, store, out, now);
            }
            if cmd_eq(cmd, b"INCRBY") {
                return strings::cmd_incrby(args, store, out, now);
            }
            if cmd_eq(cmd, b"INCRBYFLOAT") {
                return strings::cmd_incrbyfloat(args, store, out, now);
            }
            if cmd_eq(cmd, b"INFO") {
                return server::cmd_info(args, store, out, now);
            }
        }
        b'K' => {
            if cmd_eq(cmd, b"KEYS") {
                return keys::cmd_keys(args, store, out, now);
            }
            if cmd_eq(cmd, b"KSUB") {
                return pubsub::cmd_ksub(args, store, out, now);
            }
            if cmd_eq(cmd, b"KUNSUB") {
                return pubsub::cmd_kunsub(args, store, out, now);
            }
        }
        b'L' => {
            if cmd_eq(cmd, b"LPUSH") {
                return lists::cmd_lpush(args, store, _broker, out, now);
            }
            if cmd_eq(cmd, b"LPOP") {
                return lists::cmd_lpop(args, store, out, now);
            }
            if cmd_eq(cmd, b"LLEN") {
                return lists::cmd_llen(args, store, out, now);
            }
            if cmd_eq(cmd, b"LRANGE") {
                return lists::cmd_lrange(args, store, out, now);
            }
            if cmd_eq(cmd, b"LINDEX") {
                return lists::cmd_lindex(args, store, out, now);
            }
            if cmd_eq(cmd, b"LSET") {
                return lists::cmd_lset(args, store, out, now);
            }
            if cmd_eq(cmd, b"LINSERT") {
                return lists::cmd_linsert(args, store, out, now);
            }
            if cmd_eq(cmd, b"LREM") {
                return lists::cmd_lrem(args, store, out, now);
            }
            if cmd_eq(cmd, b"LTRIM") {
                return lists::cmd_ltrim(args, store, out, now);
            }
            if cmd_eq(cmd, b"LPUSHX") {
                return lists::cmd_lpushx(args, store, out, now);
            }
            if cmd_eq(cmd, b"LPOS") {
                return lists::cmd_lpos(args, store, out, now);
            }
            if cmd_eq(cmd, b"LMOVE") {
                return lists::cmd_lmove(args, store, out, now);
            }
            if cmd_eq(cmd, b"LASTSAVE") {
                return server::cmd_lastsave(args, store, out, now);
            }
            if cmd_eq(cmd, b"LATENCY") {
                return server::cmd_noop_ok(args, store, out, now);
            }
        }
        b'M' => {
            if cmd_eq(cmd, b"MGET") {
                return strings::cmd_mget(args, store, out, now);
            }
            if cmd_eq(cmd, b"MSET") {
                return strings::cmd_mset(args, store, out, now);
            }
            if cmd_eq(cmd, b"MSETNX") {
                return strings::cmd_msetnx(args, store, out, now);
            }
            if cmd_eq(cmd, b"MEMORY") {
                return keys::cmd_memory(args, store, out, now);
            }
            if cmd_eq(cmd, b"MULTI") {
                resp::write_error(out, &format!("ERR unknown command '{}'", arg_str(cmd)));
                return CmdResult::Written;
            }
        }
        b'O' => {
            if cmd_eq(cmd, b"OBJECT") {
                return keys::cmd_object(args, store, out, now);
            }
        }
        b'P' => {
            if cmd_eq(cmd, b"PING") {
                return server::cmd_ping(args, store, out, now);
            }
            if cmd_eq(cmd, b"PSETEX") {
                return strings::cmd_psetex(args, store, out, now);
            }
            if cmd_eq(cmd, b"PTTL") {
                return keys::cmd_pttl(args, store, out, now);
            }
            if cmd_eq(cmd, b"PEXPIRE") {
                return keys::cmd_pexpire(args, store, out, now);
            }
            if cmd_eq(cmd, b"PEXPIREAT") {
                return keys::cmd_pexpireat(args, store, out, now);
            }
            if cmd_eq(cmd, b"PEXPIRETIME") {
                return keys::cmd_pexpiretime(args, store, out, now);
            }
            if cmd_eq(cmd, b"PERSIST") {
                return keys::cmd_persist(args, store, out, now);
            }
            if cmd_eq(cmd, b"PUBLISH") {
                return pubsub::cmd_publish(args, store, out, now);
            }
            if cmd_eq(cmd, b"PFADD") {
                return hll::cmd_pfadd(args, store, out, now);
            }
            if cmd_eq(cmd, b"PFCOUNT") {
                return hll::cmd_pfcount(args, store, out, now);
            }
            if cmd_eq(cmd, b"PFMERGE") {
                return hll::cmd_pfmerge(args, store, out, now);
            }
            if cmd_eq(cmd, b"PFDEBUG") {
                resp::write_ok(out);
                return CmdResult::Written;
            }
            if cmd_eq(cmd, b"PSUBSCRIBE") {
                return pubsub::cmd_psubscribe(args, store, out, now);
            }
            if cmd_eq(cmd, b"PUNSUBSCRIBE") {
                return pubsub::cmd_punsubscribe(args, store, out, now);
            }
        }
        b'Q' => {
            if cmd_eq(cmd, b"QUIT") {
                return server::cmd_quit(args, store, out, now);
            }
        }
        b'R' => {
            if cmd_eq(cmd, b"RPUSH") {
                return lists::cmd_rpush(args, store, _broker, out, now);
            }
            if cmd_eq(cmd, b"RPOP") {
                return lists::cmd_rpop(args, store, out, now);
            }
            if cmd_eq(cmd, b"RPUSHX") {
                return lists::cmd_rpushx(args, store, out, now);
            }
            if cmd_eq(cmd, b"RPOPLPUSH") {
                return lists::cmd_rpoplpush(args, store, out, now);
            }
            if cmd_eq(cmd, b"RENAME") {
                return keys::cmd_rename(args, store, out, now);
            }
            if cmd_eq(cmd, b"RENAMENX") {
                return keys::cmd_renamenx(args, store, out, now);
            }
            if cmd_eq(cmd, b"RANDOMKEY") {
                return keys::cmd_randomkey(args, store, out, now);
            }
            if cmd_eq(cmd, b"RESET") {
                return server::cmd_noop_ok(args, store, out, now);
            }
        }
        b'S' => {
            if cmd_eq(cmd, b"SET") {
                return strings::cmd_set(args, store, out, now);
            }
            if cmd_eq(cmd, b"SETBIT") {
                return bitops::cmd_setbit(args, store, out, now);
            }
            if cmd_eq(cmd, b"SETNX") {
                return strings::cmd_setnx(args, store, out, now);
            }
            if cmd_eq(cmd, b"SETEX") {
                return strings::cmd_setex(args, store, out, now);
            }
            if cmd_eq(cmd, b"SETRANGE") {
                return strings::cmd_setrange(args, store, out, now);
            }
            if cmd_eq(cmd, b"STRLEN") {
                return strings::cmd_strlen(args, store, out, now);
            }
            if cmd_eq(cmd, b"SADD") {
                return sets::cmd_sadd(args, store, out, now);
            }
            if cmd_eq(cmd, b"SREM") {
                return sets::cmd_srem(args, store, out, now);
            }
            if cmd_eq(cmd, b"SMEMBERS") {
                return sets::cmd_smembers(args, store, out, now);
            }
            if cmd_eq(cmd, b"SISMEMBER") {
                return sets::cmd_sismember(args, store, out, now);
            }
            if cmd_eq(cmd, b"SMISMEMBER") {
                return sets::cmd_smismember(args, store, out, now);
            }
            if cmd_eq(cmd, b"SCARD") {
                return sets::cmd_scard(args, store, out, now);
            }
            if cmd_eq(cmd, b"SPOP") {
                return sets::cmd_spop(args, store, out, now);
            }
            if cmd_eq(cmd, b"SRANDMEMBER") {
                return sets::cmd_srandmember(args, store, out, now);
            }
            if cmd_eq(cmd, b"SMOVE") {
                return sets::cmd_smove(args, store, out, now);
            }
            if cmd_eq(cmd, b"SUNION") {
                return sets::cmd_sunion(args, store, out, now);
            }
            if cmd_eq(cmd, b"SINTER") {
                return sets::cmd_sinter(args, store, out, now);
            }
            if cmd_eq(cmd, b"SDIFF") {
                return sets::cmd_sdiff(args, store, out, now);
            }
            if cmd_eq(cmd, b"SUNIONSTORE") {
                return sets::cmd_sunionstore(args, store, out, now);
            }
            if cmd_eq(cmd, b"SINTERSTORE") {
                return sets::cmd_sinterstore(args, store, out, now);
            }
            if cmd_eq(cmd, b"SDIFFSTORE") {
                return sets::cmd_sdiffstore(args, store, out, now);
            }
            if cmd_eq(cmd, b"SINTERCARD") {
                return sets::cmd_sintercard(args, store, out, now);
            }
            if cmd_eq(cmd, b"SSCAN") {
                return hashes::cmd_hscan(args, store, out, now);
            }
            if cmd_eq(cmd, b"SCAN") {
                return keys::cmd_scan(args, store, out, now);
            }
            if cmd_eq(cmd, b"SAVE") {
                return server::cmd_save(args, store, out, now);
            }
            if cmd_eq(cmd, b"SELECT") {
                return server::cmd_select(args, store, out, now);
            }
            if cmd_eq(cmd, b"SUBSCRIBE") {
                return pubsub::cmd_subscribe(args, store, out, now);
            }
            if cmd_eq(cmd, b"SCRIPT") {
                return scripting::cmd_script(args, store, out, now);
            }
            if cmd_eq(cmd, b"SUBSTR") {
                return strings::cmd_getrange(args, store, out, now);
            }
            if cmd_eq(cmd, b"SORT") || cmd_eq(cmd, b"SORT_RO") {
                return sort::cmd_sort(args, store, out, now);
            }
            if cmd_eq(cmd, b"SWAPDB") {
                return server::cmd_noop_ok(args, store, out, now);
            }
        }
        b'T' => {
            if cmd_eq(cmd, b"TTL") {
                return keys::cmd_ttl(args, store, out, now);
            }
            if cmd_eq(cmd, b"TYPE") {
                return keys::cmd_type(args, store, out, now);
            }
            if cmd_eq(cmd, b"TIME") {
                return server::cmd_time(args, store, out, now);
            }
            if cmd_eq(cmd, b"TSADD") {
                return timeseries::cmd_tsadd(args, store, out, now);
            }
            if cmd_eq(cmd, b"TSMADD") {
                return timeseries::cmd_tsmadd(args, store, out, now);
            }
            if cmd_eq(cmd, b"TSGET") {
                return timeseries::cmd_tsget(args, store, out, now);
            }
            if cmd_eq(cmd, b"TSRANGE") {
                return timeseries::cmd_tsrange(args, store, out, now);
            }
            if cmd_eq(cmd, b"TSMRANGE") {
                return timeseries::cmd_tsmrange(args, store, out, now);
            }
            if cmd_eq(cmd, b"TSINFO") {
                return timeseries::cmd_tsinfo(args, store, out, now);
            }
            if cmd_eq(cmd, b"TCREATE") {
                return tables::cmd_tcreate(args, store, out, now);
            }
            if cmd_eq(cmd, b"TINSERT") {
                return tables::cmd_tinsert(args, store, out, now);
            }
            if cmd_eq(cmd, b"TGET") {
                return tables::cmd_tget(args, store, out, now);
            }
            if cmd_eq(cmd, b"TQUERY") {
                return tables::cmd_tquery(args, store, out, now);
            }
            if cmd_eq(cmd, b"TUPDATE") {
                return tables::cmd_tupdate(args, store, out, now);
            }
            if cmd_eq(cmd, b"TDEL") {
                return tables::cmd_tdel(args, store, out, now);
            }
            if cmd_eq(cmd, b"TDROP") {
                return tables::cmd_tdrop(args, store, out, now);
            }
            if cmd_eq(cmd, b"TCOUNT") {
                return tables::cmd_tcount(args, store, out, now);
            }
            if cmd_eq(cmd, b"TSCHEMA") {
                return tables::cmd_tschema(args, store, out, now);
            }
            if cmd_eq(cmd, b"TLIST") {
                return tables::cmd_tlist(args, store, out, now);
            }
        }
        b'U' => {
            if cmd_eq(cmd, b"UNLINK") {
                return keys::cmd_unlink(args, store, out, now);
            }
            if cmd_eq(cmd, b"UNSUBSCRIBE") {
                return pubsub::cmd_unsubscribe(args, store, out, now);
            }
            if cmd_eq(cmd, b"UNWATCH") {
                resp::write_error(out, &format!("ERR unknown command '{}'", arg_str(cmd)));
                return CmdResult::Written;
            }
        }
        b'V' => {
            if cmd_eq(cmd, b"VSET") {
                return vectors::cmd_vset(args, store, out, now);
            }
            if cmd_eq(cmd, b"VGET") {
                return vectors::cmd_vget(args, store, out, now);
            }
            if cmd_eq(cmd, b"VSEARCH") {
                return vectors::cmd_vsearch(args, store, out, now);
            }
            if cmd_eq(cmd, b"VCARD") {
                return vectors::cmd_vcard(args, store, out, now);
            }
        }
        b'W' => {
            if cmd_eq(cmd, b"WAIT") {
                return server::cmd_noop_ok(args, store, out, now);
            }
            if cmd_eq(cmd, b"WATCH") {
                resp::write_error(out, &format!("ERR unknown command '{}'", arg_str(cmd)));
                return CmdResult::Written;
            }
        }
        b'X' => {
            if cmd_eq(cmd, b"XADD") {
                return streams::cmd_xadd(args, store, _broker, out, now);
            }
            if cmd_eq(cmd, b"XLEN") {
                return streams::cmd_xlen(args, store, out, now);
            }
            if cmd_eq(cmd, b"XRANGE") {
                return streams::cmd_xrange(args, store, out, now);
            }
            if cmd_eq(cmd, b"XREVRANGE") {
                return streams::cmd_xrevrange(args, store, out, now);
            }
            if cmd_eq(cmd, b"XREAD") {
                return streams::cmd_xread(args, store, out, now);
            }
            if cmd_eq(cmd, b"XREADGROUP") {
                return streams::cmd_xreadgroup(args, store, out, now);
            }
            if cmd_eq(cmd, b"XGROUP") {
                return streams::cmd_xgroup(args, store, out, now);
            }
            if cmd_eq(cmd, b"XACK") {
                return streams::cmd_xack(args, store, out, now);
            }
            if cmd_eq(cmd, b"XPENDING") {
                return streams::cmd_xpending(args, store, out, now);
            }
            if cmd_eq(cmd, b"XCLAIM") {
                return streams::cmd_xclaim(args, store, out, now);
            }
            if cmd_eq(cmd, b"XAUTOCLAIM") {
                return streams::cmd_xautoclaim(args, store, out, now);
            }
            if cmd_eq(cmd, b"XDEL") {
                return streams::cmd_xdel(args, store, out, now);
            }
            if cmd_eq(cmd, b"XTRIM") {
                return streams::cmd_xtrim(args, store, out, now);
            }
            if cmd_eq(cmd, b"XINFO") {
                return streams::cmd_xinfo(args, store, out, now);
            }
        }
        b'Z' => {
            if cmd_eq(cmd, b"ZADD") {
                return sorted_sets::cmd_zadd(args, store, out, now);
            }
            if cmd_eq(cmd, b"ZSCORE") {
                return sorted_sets::cmd_zscore(args, store, out, now);
            }
            if cmd_eq(cmd, b"ZMSCORE") {
                return sorted_sets::cmd_zmscore(args, store, out, now);
            }
            if cmd_eq(cmd, b"ZRANK") {
                return sorted_sets::cmd_zrank(args, store, out, now);
            }
            if cmd_eq(cmd, b"ZREVRANK") {
                return sorted_sets::cmd_zrevrank(args, store, out, now);
            }
            if cmd_eq(cmd, b"ZREM") {
                return sorted_sets::cmd_zrem(args, store, out, now);
            }
            if cmd_eq(cmd, b"ZCARD") {
                return sorted_sets::cmd_zcard(args, store, out, now);
            }
            if cmd_eq(cmd, b"ZCOUNT") {
                return sorted_sets::cmd_zcount(args, store, out, now);
            }
            if cmd_eq(cmd, b"ZLEXCOUNT") {
                return sorted_sets::cmd_zlexcount(args, store, out, now);
            }
            if cmd_eq(cmd, b"ZINCRBY") {
                return sorted_sets::cmd_zincrby(args, store, out, now);
            }
            if cmd_eq(cmd, b"ZRANGE") {
                return sorted_sets::cmd_zrange(args, store, out, now);
            }
            if cmd_eq(cmd, b"ZREVRANGE") {
                return sorted_sets::cmd_zrevrange(args, store, out, now);
            }
            if cmd_eq(cmd, b"ZRANGEBYSCORE") {
                return sorted_sets::cmd_zrangebyscore(args, store, out, now);
            }
            if cmd_eq(cmd, b"ZREVRANGEBYSCORE") {
                return sorted_sets::cmd_zrevrangebyscore(args, store, out, now);
            }
            if cmd_eq(cmd, b"ZRANGEBYLEX") {
                return sorted_sets::cmd_zrangebylex(args, store, out, now);
            }
            if cmd_eq(cmd, b"ZREVRANGEBYLEX") {
                return sorted_sets::cmd_zrevrangebylex(args, store, out, now);
            }
            if cmd_eq(cmd, b"ZPOPMIN") {
                return sorted_sets::cmd_zpopmin(args, store, out, now);
            }
            if cmd_eq(cmd, b"ZPOPMAX") {
                return sorted_sets::cmd_zpopmax(args, store, out, now);
            }
            if cmd_eq(cmd, b"ZUNIONSTORE") {
                return sorted_sets::cmd_zunionstore(args, store, out, now);
            }
            if cmd_eq(cmd, b"ZINTERSTORE") {
                return sorted_sets::cmd_zinterstore(args, store, out, now);
            }
            if cmd_eq(cmd, b"ZDIFFSTORE") {
                return sorted_sets::cmd_zdiffstore(args, store, out, now);
            }
            if cmd_eq(cmd, b"ZREMRANGEBYRANK") {
                return sorted_sets::cmd_zremrangebyrank(args, store, out, now);
            }
            if cmd_eq(cmd, b"ZREMRANGEBYSCORE") {
                return sorted_sets::cmd_zremrangebyscore(args, store, out, now);
            }
            if cmd_eq(cmd, b"ZREMRANGEBYLEX") {
                return sorted_sets::cmd_zremrangebylex(args, store, out, now);
            }
            if cmd_eq(cmd, b"ZSCAN") {
                return sorted_sets::cmd_zscan(args, store, out, now);
            }
        }
        _ => {}
    }

    resp::write_error(out, &format!("ERR unknown command '{}'", arg_str(cmd)));
    CmdResult::Written
}

pub type ShardData = hashbrown::HashMap<String, Entry, crate::store::FxBuildHasher>;

pub fn execute_on_shard(
    data: &mut ShardData,
    _store: &Store,
    _broker: &Broker,
    args: &[&[u8]],
    out: &mut BytesMut,
    now: Instant,
) {
    if args.is_empty() {
        resp::write_error(out, "ERR no command");
        return;
    }
    let cmd = args[0];
    let key = args[1];

    if cmd_eq(cmd, b"SET") && args.len() >= 3 {
        let mut ttl = None;
        let mut nx = false;
        let mut xx = false;
        let mut parse_err = false;
        let mut i = 3;
        while i < args.len() {
            if cmd_eq(args[i], b"EX") {
                if i + 1 >= args.len() {
                    resp::write_error(out, "ERR syntax error");
                    parse_err = true;
                    break;
                }
                match parse_u64(args[i + 1]) {
                    Ok(s) => ttl = Some(std::time::Duration::from_secs(s)),
                    Err(_) => {
                        resp::write_error(out, "ERR value is not an integer or out of range");
                        parse_err = true;
                        break;
                    }
                }
                i += 2;
            } else if cmd_eq(args[i], b"PX") {
                if i + 1 >= args.len() {
                    resp::write_error(out, "ERR syntax error");
                    parse_err = true;
                    break;
                }
                match parse_u64(args[i + 1]) {
                    Ok(ms) => ttl = Some(std::time::Duration::from_millis(ms)),
                    Err(_) => {
                        resp::write_error(out, "ERR value is not an integer or out of range");
                        parse_err = true;
                        break;
                    }
                }
                i += 2;
            } else if cmd_eq(args[i], b"NX") {
                nx = true;
                i += 1;
            } else if cmd_eq(args[i], b"XX") {
                xx = true;
                i += 1;
            } else {
                resp::write_error(out, "ERR syntax error");
                parse_err = true;
                break;
            }
        }
        if !parse_err {
            if nx {
                let exists = Store::get_from_shard(data, key, now).is_some();
                if !exists {
                    Store::set_on_shard(data, key, args[2], None, now);
                    resp::write_ok(out);
                } else {
                    resp::write_null(out);
                }
            } else if xx {
                let exists = Store::get_from_shard(data, key, now).is_some();
                if exists {
                    Store::set_on_shard(data, key, args[2], ttl, now);
                    resp::write_ok(out);
                } else {
                    resp::write_null(out);
                }
            } else {
                Store::set_on_shard(data, key, args[2], ttl, now);
                resp::write_ok(out);
            }
        }
    } else if cmd_eq(cmd, b"GET") {
        Store::get_and_write(data, key, now, out);
    } else if cmd_eq(cmd, b"INCR") {
        shard_incr(data, key, 1, now, out);
    } else if cmd_eq(cmd, b"DECR") {
        shard_incr(data, key, -1, now, out);
    } else if cmd_eq(cmd, b"INCRBY") && args.len() >= 3 {
        match parse_i64(args[2]) {
            Ok(delta) => shard_incr(data, key, delta, now, out),
            Err(_) => resp::write_error(out, "ERR value is not an integer or out of range"),
        }
    } else if cmd_eq(cmd, b"DECRBY") && args.len() >= 3 {
        match parse_i64(args[2]) {
            Ok(delta) => shard_incr(data, key, -delta, now, out),
            Err(_) => resp::write_error(out, "ERR value is not an integer or out of range"),
        }
    } else if cmd_eq(cmd, b"LPUSH") && args.len() >= 3 {
        shard_list_push(data, key, &args[2..], true, now, out);
    } else if cmd_eq(cmd, b"RPUSH") && args.len() >= 3 {
        shard_list_push(data, key, &args[2..], false, now, out);
    } else if cmd_eq(cmd, b"LPOP") && args.len() == 2 {
        shard_list_pop(data, key, true, now, out);
    } else if cmd_eq(cmd, b"RPOP") && args.len() == 2 {
        shard_list_pop(data, key, false, now, out);
    } else if cmd_eq(cmd, b"SADD") && args.len() >= 3 {
        shard_sadd(data, key, &args[2..], now, out);
    } else if cmd_eq(cmd, b"HSET") && args.len() >= 4 {
        shard_hset(data, key, &args[2..], now, out);
    } else if cmd_eq(cmd, b"SREM") && args.len() >= 3 {
        shard_srem(data, key, &args[2..], now, out);
    } else if cmd_eq(cmd, b"SPOP") {
        shard_spop(
            data,
            key,
            if args.len() > 2 {
                parse_u64(args[2]).unwrap_or(1) as usize
            } else {
                1
            },
            now,
            out,
            args.len() > 2,
        );
    } else if cmd_eq(cmd, b"HDEL") && args.len() >= 3 {
        shard_hdel(data, key, &args[2..], now, out);
    } else if cmd_eq(cmd, b"ZADD") && args.len() >= 4 {
        shard_zadd(data, key, &args[2..], now, out);
    } else if cmd_eq(cmd, b"ZREM") && args.len() >= 3 {
        shard_zrem(data, key, &args[2..], now, out);
    } else if cmd_eq(cmd, b"ZPOPMIN") {
        let count = if args.len() > 2 {
            parse_u64(args[2]).unwrap_or(1) as usize
        } else {
            1
        };
        shard_zpop(data, key, count, true, now, out);
    } else if cmd_eq(cmd, b"ZPOPMAX") {
        let count = if args.len() > 2 {
            parse_u64(args[2]).unwrap_or(1) as usize
        } else {
            1
        };
        shard_zpop(data, key, count, false, now, out);
    } else {
        resp::write_error(
            out,
            &format!("ERR unoptimized command in shard batch '{}'", arg_str(cmd)),
        );
    }
}

pub fn execute_on_shard_read(data: &ShardData, args: &[&[u8]], out: &mut BytesMut, now: Instant) {
    if args.is_empty() || args.len() < 2 {
        resp::write_error(out, "ERR no command");
        return;
    }
    let cmd = args[0];
    let key = args[1];
    let ks = arg_str(key);

    if cmd_eq(cmd, b"GET") {
        Store::get_and_write(data, key, now, out);
    } else if cmd_eq(cmd, b"STRLEN") {
        match data.get(ks) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Str(s) => resp::write_integer(out, s.len() as i64),
                _ => resp::write_integer(out, 0),
            },
            _ => resp::write_integer(out, 0),
        }
    } else if cmd_eq(cmd, b"LLEN") {
        match data.get(ks) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::List(l) => resp::write_integer(out, l.len() as i64),
                _ => resp::write_error(
                    out,
                    "WRONGTYPE Operation against a key holding the wrong kind of value",
                ),
            },
            _ => resp::write_integer(out, 0),
        }
    } else if cmd_eq(cmd, b"SCARD") {
        match data.get(ks) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Set(s) => resp::write_integer(out, s.len() as i64),
                _ => resp::write_error(
                    out,
                    "WRONGTYPE Operation against a key holding the wrong kind of value",
                ),
            },
            _ => resp::write_integer(out, 0),
        }
    } else if cmd_eq(cmd, b"HLEN") {
        match data.get(ks) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Hash(h) => resp::write_integer(out, h.len() as i64),
                _ => resp::write_error(
                    out,
                    "WRONGTYPE Operation against a key holding the wrong kind of value",
                ),
            },
            _ => resp::write_integer(out, 0),
        }
    } else if cmd_eq(cmd, b"HGET") && args.len() >= 3 {
        match data.get(ks) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Hash(map) => {
                    resp::write_optional_bulk_raw(out, &map.get(arg_str(args[2])).cloned())
                }
                _ => resp::write_null(out),
            },
            _ => resp::write_null(out),
        }
    } else if cmd_eq(cmd, b"ZCARD") {
        match data.get(ks) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::SortedSet(_, scores) => resp::write_integer(out, scores.len() as i64),
                _ => resp::write_error(
                    out,
                    "WRONGTYPE Operation against a key holding the wrong kind of value",
                ),
            },
            _ => resp::write_integer(out, 0),
        }
    } else if cmd_eq(cmd, b"ZSCORE") && args.len() >= 3 {
        match data.get(ks) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::SortedSet(_, scores) => match scores.get(arg_str(args[2])) {
                    Some(s) => resp::write_bulk(out, &format_float(*s)),
                    None => resp::write_null(out),
                },
                _ => resp::write_error(
                    out,
                    "WRONGTYPE Operation against a key holding the wrong kind of value",
                ),
            },
            _ => resp::write_null(out),
        }
    } else if cmd_eq(cmd, b"TYPE") {
        match data.get(ks) {
            Some(entry) if !entry.is_expired_at(now) => {
                resp::write_simple(out, entry.value.type_name())
            }
            _ => resp::write_simple(out, "none"),
        }
    } else if cmd_eq(cmd, b"TTL") || cmd_eq(cmd, b"PTTL") {
        let is_pttl = cmd_eq(cmd, b"PTTL");
        match data.get(ks) {
            None => resp::write_integer(out, -2),
            Some(entry) => match entry.expires_at {
                None => {
                    if entry.is_expired_at(now) {
                        resp::write_integer(out, -2);
                    } else {
                        resp::write_integer(out, -1);
                    }
                }
                Some(exp) => {
                    if now > exp {
                        resp::write_integer(out, -2);
                    } else if is_pttl {
                        resp::write_integer(out, exp.duration_since(now).as_millis() as i64);
                    } else {
                        resp::write_integer(out, exp.duration_since(now).as_secs() as i64);
                    }
                }
            },
        }
    } else {
        resp::write_error(out, &format!("ERR unknown command '{}'", arg_str(cmd)));
    }
}

fn shard_incr(data: &mut ShardData, key: &[u8], delta: i64, now: Instant, out: &mut BytesMut) {
    let ks = arg_str(key);
    let (current, expires_at) = match data.get(ks) {
        Some(e) if !e.is_expired_at(now) => match &e.value {
            StoreValue::Str(s) => {
                match std::str::from_utf8(s)
                    .ok()
                    .and_then(|s| s.parse::<i64>().ok())
                {
                    Some(n) => (n, e.expires_at),
                    None => {
                        resp::write_error(out, "ERR value is not an integer or out of range");
                        return;
                    }
                }
            }
            _ => {
                resp::write_error(
                    out,
                    "WRONGTYPE Operation against a key holding the wrong kind of value",
                );
                return;
            }
        },
        _ => (0, None),
    };
    match current.checked_add(delta) {
        Some(new_val) => {
            data.insert(
                key_string(key),
                Entry {
                    value: StoreValue::Str(Bytes::from(new_val.to_string())),
                    expires_at,
                    lru_clock: crate::store::LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
                },
            );
            resp::write_integer(out, new_val);
        }
        None => resp::write_error(out, "ERR increment or decrement would overflow"),
    }
}

fn shard_list_push(
    data: &mut ShardData,
    key: &[u8],
    values: &[&[u8]],
    left: bool,
    now: Instant,
    out: &mut BytesMut,
) {
    let ks = key_string(key);
    let entry = data.entry(ks).or_insert_with(|| Entry {
        value: StoreValue::List(VecDeque::new()),
        expires_at: None,
        lru_clock: crate::store::LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
    });
    if entry.is_expired_at(now) {
        entry.value = StoreValue::List(VecDeque::new());
        entry.expires_at = None;
    }
    match &mut entry.value {
        StoreValue::List(list) => {
            for v in values {
                if left {
                    list.push_front(Bytes::copy_from_slice(v));
                } else {
                    list.push_back(Bytes::copy_from_slice(v));
                }
            }
            resp::write_integer(out, list.len() as i64);
        }
        _ => resp::write_error(
            out,
            "WRONGTYPE Operation against a key holding the wrong kind of value",
        ),
    }
}

fn shard_list_pop(data: &mut ShardData, key: &[u8], left: bool, now: Instant, out: &mut BytesMut) {
    let ks = arg_str(key);
    match data.get_mut(ks) {
        Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
            StoreValue::List(list) => {
                let val = if left {
                    list.pop_front()
                } else {
                    list.pop_back()
                };
                resp::write_optional_bulk_raw(out, &val);
            }
            _ => resp::write_null(out),
        },
        _ => resp::write_null(out),
    }
}

fn shard_sadd(
    data: &mut ShardData,
    key: &[u8],
    members: &[&[u8]],
    now: Instant,
    out: &mut BytesMut,
) {
    let ks = key_string(key);
    let entry = data.entry(ks).or_insert_with(|| Entry {
        value: StoreValue::Set(std::collections::HashSet::new()),
        expires_at: None,
        lru_clock: crate::store::LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
    });
    if entry.is_expired_at(now) {
        entry.value = StoreValue::Set(std::collections::HashSet::new());
        entry.expires_at = None;
    }
    match &mut entry.value {
        StoreValue::Set(set) => {
            let mut added = 0i64;
            for m in members {
                if set.insert(key_string(m)) {
                    added += 1;
                }
            }
            resp::write_integer(out, added);
        }
        _ => resp::write_error(
            out,
            "WRONGTYPE Operation against a key holding the wrong kind of value",
        ),
    }
}

fn shard_hset(
    data: &mut ShardData,
    key: &[u8],
    field_vals: &[&[u8]],
    now: Instant,
    out: &mut BytesMut,
) {
    if !field_vals.len().is_multiple_of(2) {
        resp::write_error(out, "ERR wrong number of arguments for 'hset' command");
        return;
    }
    let ks = key_string(key);
    let entry = data.entry(ks).or_insert_with(|| Entry {
        value: StoreValue::Hash(hashbrown::HashMap::new()),
        expires_at: None,
        lru_clock: crate::store::LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
    });
    if entry.is_expired_at(now) {
        entry.value = StoreValue::Hash(hashbrown::HashMap::new());
        entry.expires_at = None;
    }
    match &mut entry.value {
        StoreValue::Hash(map) => {
            let mut added = 0i64;
            for pair in field_vals.chunks(2) {
                if map
                    .insert(key_string(pair[0]), Bytes::copy_from_slice(pair[1]))
                    .is_none()
                {
                    added += 1;
                }
            }
            resp::write_integer(out, added);
        }
        _ => resp::write_error(
            out,
            "WRONGTYPE Operation against a key holding the wrong kind of value",
        ),
    }
}

fn shard_srem(
    data: &mut ShardData,
    key: &[u8],
    members: &[&[u8]],
    now: Instant,
    out: &mut BytesMut,
) {
    let ks = arg_str(key);
    match data.get_mut(ks) {
        Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
            StoreValue::Set(set) => {
                let mut removed = 0i64;
                for m in members {
                    if set.remove(arg_str(m)) {
                        removed += 1;
                    }
                }
                resp::write_integer(out, removed);
            }
            _ => resp::write_error(
                out,
                "WRONGTYPE Operation against a key holding the wrong kind of value",
            ),
        },
        _ => resp::write_integer(out, 0),
    }
}

fn shard_spop(
    data: &mut ShardData,
    key: &[u8],
    count: usize,
    now: Instant,
    out: &mut BytesMut,
    has_count: bool,
) {
    let ks = arg_str(key);
    match data.get_mut(ks) {
        Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
            StoreValue::Set(set) => {
                let mut result = Vec::new();
                for _ in 0..count {
                    if set.is_empty() {
                        break;
                    }
                    let member = set.iter().next().unwrap().clone();
                    set.remove(&member);
                    result.push(member);
                }
                if has_count {
                    resp::write_array_header(out, result.len());
                    for m in &result {
                        resp::write_bulk(out, m);
                    }
                } else if result.is_empty() {
                    resp::write_null(out);
                } else {
                    resp::write_bulk(out, &result[0]);
                }
            }
            _ => resp::write_error(
                out,
                "WRONGTYPE Operation against a key holding the wrong kind of value",
            ),
        },
        _ => {
            if has_count {
                resp::write_array_header(out, 0);
            } else {
                resp::write_null(out);
            }
        }
    }
}

fn shard_hdel(
    data: &mut ShardData,
    key: &[u8],
    fields: &[&[u8]],
    now: Instant,
    out: &mut BytesMut,
) {
    let ks = arg_str(key);
    match data.get_mut(ks) {
        Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
            StoreValue::Hash(map) => {
                let mut removed = 0i64;
                for f in fields {
                    if map.remove(arg_str(f)).is_some() {
                        removed += 1;
                    }
                }
                resp::write_integer(out, removed);
            }
            _ => resp::write_error(
                out,
                "WRONGTYPE Operation against a key holding the wrong kind of value",
            ),
        },
        _ => resp::write_integer(out, 0),
    }
}

fn shard_zadd(data: &mut ShardData, key: &[u8], rest: &[&[u8]], now: Instant, out: &mut BytesMut) {
    let mut nx = false;
    let mut xx = false;
    let mut gt = false;
    let mut lt = false;
    let mut ch = false;
    let mut i = 0;
    while i < rest.len() {
        if cmd_eq(rest[i], b"NX") {
            nx = true;
            i += 1;
        } else if cmd_eq(rest[i], b"XX") {
            xx = true;
            i += 1;
        } else if cmd_eq(rest[i], b"GT") {
            gt = true;
            i += 1;
        } else if cmd_eq(rest[i], b"LT") {
            lt = true;
            i += 1;
        } else if cmd_eq(rest[i], b"CH") {
            ch = true;
            i += 1;
        } else {
            break;
        }
    }
    if i >= rest.len() || !((rest.len() - i).is_multiple_of(2)) {
        resp::write_error(out, "ERR syntax error");
        return;
    }
    let mut members = Vec::new();
    while i + 1 < rest.len() {
        match arg_str(rest[i]).parse::<f64>() {
            Ok(s) => members.push((rest[i + 1], s)),
            Err(_) => {
                resp::write_error(out, "ERR value is not a valid float");
                return;
            }
        }
        i += 2;
    }

    let ks = key_string(key);
    let entry = data.entry(ks).or_insert_with(|| Entry {
        value: StoreValue::SortedSet(std::collections::BTreeMap::new(), hashbrown::HashMap::new()),
        expires_at: None,
        lru_clock: crate::store::LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
    });
    if entry.is_expired_at(now) {
        entry.value =
            StoreValue::SortedSet(std::collections::BTreeMap::new(), hashbrown::HashMap::new());
        entry.expires_at = None;
    }
    match &mut entry.value {
        StoreValue::SortedSet(tree, scores) => {
            let mut added = 0i64;
            let mut changed = 0i64;
            for (member_bytes, score) in &members {
                let member = arg_str(member_bytes).to_string();
                if let Some(&old_score) = scores.get(&member) {
                    if nx {
                        continue;
                    }
                    let new_score = *score;
                    if gt && new_score <= old_score {
                        continue;
                    }
                    if lt && new_score >= old_score {
                        continue;
                    }
                    if new_score != old_score {
                        tree.remove(&(ordered_float::OrderedFloat(old_score), member.clone()));
                        tree.insert((ordered_float::OrderedFloat(new_score), member.clone()), ());
                        scores.insert(member, new_score);
                        changed += 1;
                    }
                } else {
                    if xx {
                        continue;
                    }
                    tree.insert((ordered_float::OrderedFloat(*score), member.clone()), ());
                    scores.insert(member, *score);
                    added += 1;
                }
            }
            resp::write_integer(out, if ch { added + changed } else { added });
        }
        _ => resp::write_error(
            out,
            "WRONGTYPE Operation against a key holding the wrong kind of value",
        ),
    }
}

fn shard_zrem(
    data: &mut ShardData,
    key: &[u8],
    members: &[&[u8]],
    now: Instant,
    out: &mut BytesMut,
) {
    let ks = arg_str(key);
    match data.get_mut(ks) {
        Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
            StoreValue::SortedSet(tree, scores) => {
                let mut removed = 0i64;
                for m in members {
                    let ms = arg_str(m);
                    if let Some(score) = scores.remove(ms) {
                        tree.remove(&(ordered_float::OrderedFloat(score), ms.to_string()));
                        removed += 1;
                    }
                }
                resp::write_integer(out, removed);
            }
            _ => resp::write_error(
                out,
                "WRONGTYPE Operation against a key holding the wrong kind of value",
            ),
        },
        _ => resp::write_integer(out, 0),
    }
}

fn shard_zpop(
    data: &mut ShardData,
    key: &[u8],
    count: usize,
    is_min: bool,
    now: Instant,
    out: &mut BytesMut,
) {
    let ks = arg_str(key);
    match data.get_mut(ks) {
        Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
            StoreValue::SortedSet(tree, scores) => {
                let mut result = Vec::new();
                for _ in 0..count {
                    let popped = if is_min {
                        tree.pop_first()
                    } else {
                        tree.pop_last()
                    };
                    if let Some(((score, member), _)) = popped {
                        scores.remove(&member);
                        result.push((member, score.0));
                    } else {
                        break;
                    }
                }
                resp::write_array_header(out, result.len() * 2);
                for (m, s) in &result {
                    resp::write_bulk(out, m);
                    resp::write_bulk(out, &format_float(*s));
                }
            }
            _ => resp::write_error(
                out,
                "WRONGTYPE Operation against a key holding the wrong kind of value",
            ),
        },
        _ => resp::write_array_header(out, 0),
    }
}

fn key_string(key: &[u8]) -> String {
    String::from_utf8_lossy(key).into_owned()
}

pub fn is_known_command(cmd: &[u8]) -> bool {
    cmd_eq(cmd, b"SET")
        || cmd_eq(cmd, b"GET")
        || cmd_eq(cmd, b"DEL")
        || cmd_eq(cmd, b"PING")
        || cmd_eq(cmd, b"ECHO")
        || cmd_eq(cmd, b"QUIT")
        || cmd_eq(cmd, b"SETNX")
        || cmd_eq(cmd, b"SETEX")
        || cmd_eq(cmd, b"PSETEX")
        || cmd_eq(cmd, b"GETSET")
        || cmd_eq(cmd, b"MGET")
        || cmd_eq(cmd, b"MSET")
        || cmd_eq(cmd, b"STRLEN")
        || cmd_eq(cmd, b"EXISTS")
        || cmd_eq(cmd, b"INCR")
        || cmd_eq(cmd, b"DECR")
        || cmd_eq(cmd, b"INCRBY")
        || cmd_eq(cmd, b"DECRBY")
        || cmd_eq(cmd, b"APPEND")
        || cmd_eq(cmd, b"KEYS")
        || cmd_eq(cmd, b"SCAN")
        || cmd_eq(cmd, b"TTL")
        || cmd_eq(cmd, b"PTTL")
        || cmd_eq(cmd, b"EXPIRE")
        || cmd_eq(cmd, b"PEXPIRE")
        || cmd_eq(cmd, b"PERSIST")
        || cmd_eq(cmd, b"TYPE")
        || cmd_eq(cmd, b"RENAME")
        || cmd_eq(cmd, b"DBSIZE")
        || cmd_eq(cmd, b"FLUSHDB")
        || cmd_eq(cmd, b"FLUSHALL")
        || cmd_eq(cmd, b"LPUSH")
        || cmd_eq(cmd, b"RPUSH")
        || cmd_eq(cmd, b"LPOP")
        || cmd_eq(cmd, b"RPOP")
        || cmd_eq(cmd, b"LLEN")
        || cmd_eq(cmd, b"LRANGE")
        || cmd_eq(cmd, b"LINDEX")
        || cmd_eq(cmd, b"HSET")
        || cmd_eq(cmd, b"HMSET")
        || cmd_eq(cmd, b"HGET")
        || cmd_eq(cmd, b"HMGET")
        || cmd_eq(cmd, b"HDEL")
        || cmd_eq(cmd, b"HGETALL")
        || cmd_eq(cmd, b"HKEYS")
        || cmd_eq(cmd, b"HVALS")
        || cmd_eq(cmd, b"HLEN")
        || cmd_eq(cmd, b"HEXISTS")
        || cmd_eq(cmd, b"HINCRBY")
        || cmd_eq(cmd, b"SADD")
        || cmd_eq(cmd, b"SREM")
        || cmd_eq(cmd, b"SMEMBERS")
        || cmd_eq(cmd, b"SISMEMBER")
        || cmd_eq(cmd, b"SCARD")
        || cmd_eq(cmd, b"SUNION")
        || cmd_eq(cmd, b"SINTER")
        || cmd_eq(cmd, b"SDIFF")
        || cmd_eq(cmd, b"SAVE")
        || cmd_eq(cmd, b"INFO")
        || cmd_eq(cmd, b"CONFIG")
        || cmd_eq(cmd, b"CLIENT")
        || cmd_eq(cmd, b"SELECT")
        || cmd_eq(cmd, b"COMMAND")
        || cmd_eq(cmd, b"GETDEL")
        || cmd_eq(cmd, b"GETEX")
        || cmd_eq(cmd, b"GETRANGE")
        || cmd_eq(cmd, b"SUBSTR")
        || cmd_eq(cmd, b"SETRANGE")
        || cmd_eq(cmd, b"MSETNX")
        || cmd_eq(cmd, b"UNLINK")
        || cmd_eq(cmd, b"EXPIREAT")
        || cmd_eq(cmd, b"PEXPIREAT")
        || cmd_eq(cmd, b"EXPIRETIME")
        || cmd_eq(cmd, b"PEXPIRETIME")
        || cmd_eq(cmd, b"LSET")
        || cmd_eq(cmd, b"LINSERT")
        || cmd_eq(cmd, b"LREM")
        || cmd_eq(cmd, b"LTRIM")
        || cmd_eq(cmd, b"LPUSHX")
        || cmd_eq(cmd, b"RPUSHX")
        || cmd_eq(cmd, b"LPOS")
        || cmd_eq(cmd, b"LMOVE")
        || cmd_eq(cmd, b"RPOPLPUSH")
        || cmd_eq(cmd, b"HSETNX")
        || cmd_eq(cmd, b"HINCRBYFLOAT")
        || cmd_eq(cmd, b"HSTRLEN")
        || cmd_eq(cmd, b"SPOP")
        || cmd_eq(cmd, b"SRANDMEMBER")
        || cmd_eq(cmd, b"SMOVE")
        || cmd_eq(cmd, b"SMISMEMBER")
        || cmd_eq(cmd, b"SDIFFSTORE")
        || cmd_eq(cmd, b"SINTERSTORE")
        || cmd_eq(cmd, b"SUNIONSTORE")
        || cmd_eq(cmd, b"SINTERCARD")
        || cmd_eq(cmd, b"HRANDFIELD")
        || cmd_eq(cmd, b"HSCAN")
        || cmd_eq(cmd, b"SSCAN")
        || cmd_eq(cmd, b"INCRBYFLOAT")
        || cmd_eq(cmd, b"TIME")
        || cmd_eq(cmd, b"RENAMENX")
        || cmd_eq(cmd, b"RANDOMKEY")
        || cmd_eq(cmd, b"HELLO")
        || cmd_eq(cmd, b"PSUBSCRIBE")
        || cmd_eq(cmd, b"PUNSUBSCRIBE")
        || cmd_eq(cmd, b"COPY")
        || cmd_eq(cmd, b"FUNCTION")
        || cmd_eq(cmd, b"DEBUG")
        || cmd_eq(cmd, b"WAIT")
        || cmd_eq(cmd, b"RESET")
        || cmd_eq(cmd, b"LATENCY")
        || cmd_eq(cmd, b"SWAPDB")
        || cmd_eq(cmd, b"OBJECT")
        || cmd_eq(cmd, b"MEMORY")
        || cmd_eq(cmd, b"BGSAVE")
        || cmd_eq(cmd, b"LASTSAVE")
        || cmd_eq(cmd, b"PUBLISH")
        || cmd_eq(cmd, b"SUBSCRIBE")
        || cmd_eq(cmd, b"ZADD")
        || cmd_eq(cmd, b"ZSCORE")
        || cmd_eq(cmd, b"ZRANK")
        || cmd_eq(cmd, b"ZREVRANK")
        || cmd_eq(cmd, b"ZREM")
        || cmd_eq(cmd, b"ZCARD")
        || cmd_eq(cmd, b"ZRANGE")
        || cmd_eq(cmd, b"ZINCRBY")
        || cmd_eq(cmd, b"ZCOUNT")
        || cmd_eq(cmd, b"ZPOPMIN")
        || cmd_eq(cmd, b"ZPOPMAX")
        || cmd_eq(cmd, b"ZUNIONSTORE")
        || cmd_eq(cmd, b"ZINTERSTORE")
        || cmd_eq(cmd, b"ZDIFFSTORE")
        || cmd_eq(cmd, b"ZSCAN")
        || cmd_eq(cmd, b"ZMSCORE")
        || cmd_eq(cmd, b"ZLEXCOUNT")
        || cmd_eq(cmd, b"ZRANGEBYSCORE")
        || cmd_eq(cmd, b"ZREVRANGEBYSCORE")
        || cmd_eq(cmd, b"ZRANGEBYLEX")
        || cmd_eq(cmd, b"ZREVRANGEBYLEX")
        || cmd_eq(cmd, b"ZREMRANGEBYRANK")
        || cmd_eq(cmd, b"ZREMRANGEBYSCORE")
        || cmd_eq(cmd, b"ZREMRANGEBYLEX")
        || cmd_eq(cmd, b"AUTH")
        || cmd_eq(cmd, b"BLPOP")
        || cmd_eq(cmd, b"BRPOP")
        || cmd_eq(cmd, b"BLMOVE")
        || cmd_eq(cmd, b"BZPOPMIN")
        || cmd_eq(cmd, b"BZPOPMAX")
        || cmd_eq(cmd, b"XADD")
        || cmd_eq(cmd, b"XLEN")
        || cmd_eq(cmd, b"XRANGE")
        || cmd_eq(cmd, b"XREVRANGE")
        || cmd_eq(cmd, b"XREAD")
        || cmd_eq(cmd, b"XREADGROUP")
        || cmd_eq(cmd, b"XGROUP")
        || cmd_eq(cmd, b"XACK")
        || cmd_eq(cmd, b"XPENDING")
        || cmd_eq(cmd, b"XCLAIM")
        || cmd_eq(cmd, b"XAUTOCLAIM")
        || cmd_eq(cmd, b"XDEL")
        || cmd_eq(cmd, b"XTRIM")
        || cmd_eq(cmd, b"XINFO")
        || cmd_eq(cmd, b"EVAL")
        || cmd_eq(cmd, b"EVALSHA")
        || cmd_eq(cmd, b"SCRIPT")
        || cmd_eq(cmd, b"VSET")
        || cmd_eq(cmd, b"VGET")
        || cmd_eq(cmd, b"VSEARCH")
        || cmd_eq(cmd, b"VCARD")
        || cmd_eq(cmd, b"PFADD")
        || cmd_eq(cmd, b"PFCOUNT")
        || cmd_eq(cmd, b"PFMERGE")
        || cmd_eq(cmd, b"PFDEBUG")
        || cmd_eq(cmd, b"SORT")
        || cmd_eq(cmd, b"SORT_RO")
        || cmd_eq(cmd, b"TSADD")
        || cmd_eq(cmd, b"TSMADD")
        || cmd_eq(cmd, b"TSGET")
        || cmd_eq(cmd, b"TSRANGE")
        || cmd_eq(cmd, b"TSMRANGE")
        || cmd_eq(cmd, b"TSINFO")
        || cmd_eq(cmd, b"SETBIT")
        || cmd_eq(cmd, b"GETBIT")
        || cmd_eq(cmd, b"BITCOUNT")
        || cmd_eq(cmd, b"BITPOS")
        || cmd_eq(cmd, b"BITOP")
        || cmd_eq(cmd, b"KSUB")
        || cmd_eq(cmd, b"KUNSUB")
        || cmd_eq(cmd, b"TCREATE")
        || cmd_eq(cmd, b"TINSERT")
        || cmd_eq(cmd, b"TGET")
        || cmd_eq(cmd, b"TQUERY")
        || cmd_eq(cmd, b"TUPDATE")
        || cmd_eq(cmd, b"TDEL")
        || cmd_eq(cmd, b"TDROP")
        || cmd_eq(cmd, b"TCOUNT")
        || cmd_eq(cmd, b"TSCHEMA")
        || cmd_eq(cmd, b"TLIST")
}

pub fn validate_args(args: &[&[u8]]) -> Result<(), String> {
    if args.is_empty() {
        return Err("ERR no command".to_string());
    }
    let cmd = args[0];
    let min = if cmd_eq(cmd, b"SET")
        || cmd_eq(cmd, b"GETSET")
        || cmd_eq(cmd, b"SETNX")
        || cmd_eq(cmd, b"APPEND")
        || cmd_eq(cmd, b"EXPIRE")
        || cmd_eq(cmd, b"PEXPIRE")
        || cmd_eq(cmd, b"HGET")
        || cmd_eq(cmd, b"HEXISTS")
        || cmd_eq(cmd, b"SISMEMBER")
        || cmd_eq(cmd, b"LINDEX")
        || cmd_eq(cmd, b"GETRANGE")
        || cmd_eq(cmd, b"SUBSTR")
        || cmd_eq(cmd, b"GETBIT")
    {
        3
    } else if cmd_eq(cmd, b"GET")
        || cmd_eq(cmd, b"DEL")
        || cmd_eq(cmd, b"EXISTS")
        || cmd_eq(cmd, b"INCR")
        || cmd_eq(cmd, b"DECR")
        || cmd_eq(cmd, b"STRLEN")
        || cmd_eq(cmd, b"TTL")
        || cmd_eq(cmd, b"PTTL")
        || cmd_eq(cmd, b"TYPE")
        || cmd_eq(cmd, b"PERSIST")
        || cmd_eq(cmd, b"KEYS")
        || cmd_eq(cmd, b"LLEN")
        || cmd_eq(cmd, b"LPOP")
        || cmd_eq(cmd, b"RPOP")
        || cmd_eq(cmd, b"HGETALL")
        || cmd_eq(cmd, b"HKEYS")
        || cmd_eq(cmd, b"HVALS")
        || cmd_eq(cmd, b"HLEN")
        || cmd_eq(cmd, b"SMEMBERS")
        || cmd_eq(cmd, b"SCARD")
        || cmd_eq(cmd, b"ZCARD")
        || cmd_eq(cmd, b"SCAN")
        || cmd_eq(cmd, b"ECHO")
        || cmd_eq(cmd, b"GETDEL")
        || cmd_eq(cmd, b"GETEX")
    {
        2
    } else if cmd_eq(cmd, b"LPUSH")
        || cmd_eq(cmd, b"RPUSH")
        || cmd_eq(cmd, b"SADD")
        || cmd_eq(cmd, b"SREM")
        || cmd_eq(cmd, b"INCRBY")
        || cmd_eq(cmd, b"DECRBY")
        || cmd_eq(cmd, b"MSET")
        || cmd_eq(cmd, b"MGET")
        || cmd_eq(cmd, b"RENAME")
        || cmd_eq(cmd, b"INCRBYFLOAT")
        || cmd_eq(cmd, b"HDEL")
        || cmd_eq(cmd, b"HMGET")
        || cmd_eq(cmd, b"COPY")
        || cmd_eq(cmd, b"LRANGE")
        || cmd_eq(cmd, b"SUNION")
        || cmd_eq(cmd, b"SINTER")
        || cmd_eq(cmd, b"SDIFF")
    {
        3
    } else if cmd_eq(cmd, b"SETEX")
        || cmd_eq(cmd, b"PSETEX")
        || cmd_eq(cmd, b"HSET")
        || cmd_eq(cmd, b"HMSET")
        || cmd_eq(cmd, b"HINCRBY")
        || cmd_eq(cmd, b"HSETNX")
        || cmd_eq(cmd, b"HINCRBYFLOAT")
        || cmd_eq(cmd, b"ZADD")
        || cmd_eq(cmd, b"LSET")
        || cmd_eq(cmd, b"SETRANGE")
        || cmd_eq(cmd, b"LINSERT")
        || cmd_eq(cmd, b"LREM")
        || cmd_eq(cmd, b"LTRIM")
        || cmd_eq(cmd, b"ZUNIONSTORE")
        || cmd_eq(cmd, b"ZINTERSTORE")
        || cmd_eq(cmd, b"ZDIFFSTORE")
        || cmd_eq(cmd, b"ZSCORE")
        || cmd_eq(cmd, b"ZRANK")
        || cmd_eq(cmd, b"ZREVRANK")
        || cmd_eq(cmd, b"ZREM")
        || cmd_eq(cmd, b"ZINCRBY")
        || cmd_eq(cmd, b"SMOVE")
        || cmd_eq(cmd, b"HSTRLEN")
        || cmd_eq(cmd, b"SETBIT")
        || cmd_eq(cmd, b"BITOP")
    {
        4
    } else if cmd_eq(cmd, b"XADD") || cmd_eq(cmd, b"XREADGROUP") {
        5
    } else if cmd_eq(cmd, b"BLPOP")
        || cmd_eq(cmd, b"BRPOP")
        || cmd_eq(cmd, b"BZPOPMIN")
        || cmd_eq(cmd, b"BZPOPMAX")
        || cmd_eq(cmd, b"XRANGE")
        || cmd_eq(cmd, b"XREVRANGE")
        || cmd_eq(cmd, b"EVAL")
        || cmd_eq(cmd, b"EVALSHA")
        || cmd_eq(cmd, b"XACK")
        || cmd_eq(cmd, b"XPENDING")
    {
        3
    } else if cmd_eq(cmd, b"XLEN")
        || cmd_eq(cmd, b"XREAD")
        || cmd_eq(cmd, b"XGROUP")
        || cmd_eq(cmd, b"XDEL")
        || cmd_eq(cmd, b"XINFO")
        || cmd_eq(cmd, b"XTRIM")
        || cmd_eq(cmd, b"SCRIPT")
        || cmd_eq(cmd, b"PFADD")
        || cmd_eq(cmd, b"PFCOUNT")
        || cmd_eq(cmd, b"PFMERGE")
        || cmd_eq(cmd, b"BITCOUNT")
        || cmd_eq(cmd, b"BITPOS")
        || cmd_eq(cmd, b"SORT")
        || cmd_eq(cmd, b"SORT_RO")
    {
        2
    } else if cmd_eq(cmd, b"BLMOVE") || cmd_eq(cmd, b"XCLAIM") || cmd_eq(cmd, b"XAUTOCLAIM") {
        6
    } else if cmd_eq(cmd, b"PING")
        || cmd_eq(cmd, b"DBSIZE")
        || cmd_eq(cmd, b"FLUSHDB")
        || cmd_eq(cmd, b"FLUSHALL")
        || cmd_eq(cmd, b"SAVE")
        || cmd_eq(cmd, b"INFO")
        || cmd_eq(cmd, b"TIME")
        || cmd_eq(cmd, b"RANDOMKEY")
        || cmd_eq(cmd, b"BGSAVE")
        || cmd_eq(cmd, b"LASTSAVE")
        || cmd_eq(cmd, b"HELLO")
        || cmd_eq(cmd, b"QUIT")
        || cmd_eq(cmd, b"COMMAND")
        || cmd_eq(cmd, b"CONFIG")
        || cmd_eq(cmd, b"CLIENT")
        || cmd_eq(cmd, b"SELECT")
        || cmd_eq(cmd, b"VCARD")
    {
        1
    } else if cmd_eq(cmd, b"VGET") {
        2
    } else if cmd_eq(cmd, b"VSET") || cmd_eq(cmd, b"VSEARCH") {
        4
    } else {
        return Ok(());
    };
    if args.len() < min {
        let cmd_name = std::str::from_utf8(cmd).unwrap_or("unknown").to_lowercase();
        return Err(format!(
            "ERR wrong number of arguments for '{}' command",
            cmd_name
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pubsub::Broker;
    use crate::store::Store;
    use std::time::Instant;

    fn exec(store: &Store, args: &[&[u8]]) -> BytesMut {
        let broker = Broker::new();
        let mut out = BytesMut::new();
        let now = Instant::now();
        execute(store, &broker, args, &mut out, now);
        out
    }

    fn exec_str(store: &Store, args: &[&[u8]]) -> String {
        String::from_utf8_lossy(&exec(store, args)).to_string()
    }

    #[test]
    fn set_wrong_arg_count() {
        let store = Store::new();
        let out = exec_str(&store, &[b"SET", b"key"]);
        assert!(out.contains("ERR wrong number of arguments"));
    }

    #[test]
    fn setex_negative_time() {
        let store = Store::new();
        let out = exec_str(&store, &[b"SETEX", b"key", b"-1", b"val"]);
        assert!(out.contains("ERR invalid expire time"));
    }

    #[test]
    fn incrbyfloat_nan_error() {
        let store = Store::new();
        let out = exec_str(&store, &[b"INCRBYFLOAT", b"key", b"nan"]);
        assert!(out.contains("NaN or Infinity") || out.contains("not a valid float"));
    }

    #[test]
    fn incrbyfloat_with_spaces() {
        let store = Store::new();
        let out = exec_str(&store, &[b"INCRBYFLOAT", b"key", b"1 2"]);
        assert!(out.contains("not a valid float"));
    }

    #[test]
    fn unknown_command_returns_error() {
        let store = Store::new();
        let out = exec_str(&store, &[b"NOTACMD"]);
        assert!(out.contains("ERR unknown command"));
    }

    #[test]
    fn auth_wrong_password() {
        std::env::set_var("LUX_PASSWORD", "secret123");
        let store = Store::new();
        let out = exec_str(&store, &[b"AUTH", b"wrong"]);
        assert!(out.contains("WRONGPASS"));
        std::env::remove_var("LUX_PASSWORD");
    }

    #[test]
    fn getex_syntax_error() {
        let store = Store::new();
        let out = exec_str(&store, &[b"GETEX", b"key", b"BADOPT"]);
        assert!(out.contains("ERR syntax error"));
    }

    #[test]
    fn ping_returns_pong() {
        let store = Store::new();
        let out = exec(&store, &[b"PING"]);
        assert_eq!(&out[..], b"+PONG\r\n");
    }

    #[test]
    fn ping_with_message() {
        let store = Store::new();
        let out = exec_str(&store, &[b"PING", b"hello"]);
        assert!(out.contains("hello"));
    }

    #[test]
    fn echo_returns_argument() {
        let store = Store::new();
        let out = exec_str(&store, &[b"ECHO", b"test"]);
        assert!(out.contains("test"));
    }

    #[test]
    fn set_then_get() {
        let store = Store::new();
        exec(&store, &[b"SET", b"mykey", b"myval"]);
        let out = exec_str(&store, &[b"GET", b"mykey"]);
        assert!(out.contains("myval"));
    }

    #[test]
    fn del_returns_count() {
        let store = Store::new();
        exec(&store, &[b"SET", b"a", b"1"]);
        exec(&store, &[b"SET", b"b", b"2"]);
        let out = exec(&store, &[b"DEL", b"a", b"b", b"c"]);
        assert!(out.starts_with(b":2\r\n"));
    }

    #[test]
    fn zadd_and_zscore() {
        let store = Store::new();
        exec(&store, &[b"ZADD", b"zs", b"1.5", b"alice"]);
        let out = exec_str(&store, &[b"ZSCORE", b"zs", b"alice"]);
        assert!(out.contains("1") || out.contains("1.5"));
    }

    #[test]
    fn zadd_nx_flag() {
        let store = Store::new();
        exec(&store, &[b"ZADD", b"zs", b"1", b"a"]);
        exec(&store, &[b"ZADD", b"zs", b"NX", b"2", b"a"]);
        let score = store.zscore(b"zs", b"a", Instant::now()).unwrap().unwrap();
        assert!((score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn type_returns_correct_type() {
        let store = Store::new();
        exec(&store, &[b"SET", b"s", b"val"]);
        exec(&store, &[b"LPUSH", b"l", b"val"]);
        exec(&store, &[b"SADD", b"set", b"val"]);
        exec(&store, &[b"ZADD", b"zs", b"1", b"val"]);
        assert!(exec_str(&store, &[b"TYPE", b"s"]).contains("string"));
        assert!(exec_str(&store, &[b"TYPE", b"l"]).contains("list"));
        assert!(exec_str(&store, &[b"TYPE", b"set"]).contains("set"));
        assert!(exec_str(&store, &[b"TYPE", b"zs"]).contains("zset"));
        assert!(exec_str(&store, &[b"TYPE", b"missing"]).contains("none"));
    }

    #[test]
    fn exec_without_multi_returns_error() {
        let store = Store::new();
        let out = exec_str(&store, &[b"EXEC"]);
        assert!(out.contains("ERR unknown command"));
    }

    #[test]
    fn discard_without_multi_returns_error() {
        let store = Store::new();
        let out = exec_str(&store, &[b"DISCARD"]);
        assert!(out.contains("ERR unknown command"));
    }

    #[test]
    fn validate_args_rejects_missing_args() {
        assert!(validate_args(&[b"SET" as &[u8], b"key"]).is_err());
        assert!(validate_args(&[b"GET" as &[u8]]).is_err());
        assert!(validate_args(&[b"HSET" as &[u8], b"k", b"f"]).is_err());
    }

    #[test]
    fn validate_args_accepts_valid_commands() {
        assert!(validate_args(&[b"SET" as &[u8], b"key", b"val"]).is_ok());
        assert!(validate_args(&[b"GET" as &[u8], b"key"]).is_ok());
        assert!(validate_args(&[b"PING" as &[u8]]).is_ok());
        assert!(validate_args(&[b"DEL" as &[u8], b"key"]).is_ok());
    }

    #[test]
    fn validate_args_passes_unknown_commands() {
        assert!(validate_args(&[b"FOOBAR" as &[u8]]).is_ok());
    }

    #[test]
    fn set_xx_only_if_exists() {
        let store = Store::new();
        let out = exec_str(&store, &[b"SET", b"k", b"v", b"XX"]);
        assert!(out.contains("$-1"), "XX on missing key returns null: {out}");
        exec(&store, &[b"SET", b"k", b"orig"]);
        let out = exec_str(&store, &[b"SET", b"k", b"new", b"XX"]);
        assert!(out.contains("+OK"), "XX on existing key succeeds: {out}");
        let out = exec_str(&store, &[b"GET", b"k"]);
        assert!(out.contains("new"));
    }

    #[test]
    fn set_px_millisecond_ttl() {
        let store = Store::new();
        exec(&store, &[b"SET", b"k", b"v", b"PX", b"100000"]);
        let ttl = store.pttl(b"k", Instant::now());
        assert!(ttl > 0 && ttl <= 100000, "PX TTL: {ttl}");
    }

    #[test]
    fn psetex_sets_with_ms_ttl() {
        let store = Store::new();
        exec(&store, &[b"PSETEX", b"k", b"50000", b"val"]);
        let out = exec_str(&store, &[b"GET", b"k"]);
        assert!(out.contains("val"));
        let ttl = store.pttl(b"k", Instant::now());
        assert!(ttl > 0 && ttl <= 50000, "PSETEX TTL: {ttl}");
    }

    #[test]
    fn copy_basic_and_replace() {
        let store = Store::new();
        exec(&store, &[b"SET", b"src", b"hello"]);
        let out = exec_str(&store, &[b"COPY", b"src", b"dst"]);
        assert!(out.contains(":1"));
        let out = exec_str(&store, &[b"GET", b"dst"]);
        assert!(out.contains("hello"));

        exec(&store, &[b"SET", b"dst", b"existing"]);
        let out = exec_str(&store, &[b"COPY", b"src", b"dst"]);
        assert!(out.contains(":0"), "no REPLACE, dest exists: {out}");

        let out = exec_str(&store, &[b"COPY", b"src", b"dst", b"REPLACE"]);
        assert!(out.contains(":1"), "with REPLACE: {out}");
        let out = exec_str(&store, &[b"GET", b"dst"]);
        assert!(out.contains("hello"));
    }

    #[test]
    fn copy_nonexistent_source() {
        let store = Store::new();
        let out = exec_str(&store, &[b"COPY", b"nosrc", b"dst"]);
        assert!(out.contains(":0"));
    }

    #[test]
    fn renamenx_only_if_dest_missing() {
        let store = Store::new();
        exec(&store, &[b"SET", b"a", b"1"]);
        exec(&store, &[b"SET", b"b", b"2"]);
        let out = exec_str(&store, &[b"RENAMENX", b"a", b"b"]);
        assert!(out.contains(":0"), "dest exists: {out}");
        let out = exec_str(&store, &[b"RENAMENX", b"a", b"c"]);
        assert!(out.contains(":1"), "dest missing: {out}");
        let out = exec_str(&store, &[b"GET", b"c"]);
        assert!(out.contains("1"));
    }

    #[test]
    fn time_returns_two_element_array() {
        let store = Store::new();
        let out = exec_str(&store, &[b"TIME"]);
        assert!(out.starts_with("*2\r\n"), "TIME array: {out}");
    }

    #[test]
    fn object_encoding_types() {
        let store = Store::new();
        exec(&store, &[b"SET", b"num", b"42"]);
        let out = exec_str(&store, &[b"OBJECT", b"ENCODING", b"num"]);
        assert!(out.contains("int"), "integer encoding: {out}");

        exec(&store, &[b"SET", b"str", b"hello"]);
        let out = exec_str(&store, &[b"OBJECT", b"ENCODING", b"str"]);
        assert!(out.contains("embstr"), "short string encoding: {out}");

        exec(&store, &[b"LPUSH", b"list", b"a"]);
        let out = exec_str(&store, &[b"OBJECT", b"ENCODING", b"list"]);
        assert!(out.contains("listpack"), "list encoding: {out}");
    }

    #[test]
    fn object_encoding_missing_key() {
        let store = Store::new();
        let out = exec_str(&store, &[b"OBJECT", b"ENCODING", b"nope"]);
        assert!(out.contains("ERR no such key"));
    }

    #[test]
    fn memory_usage_returns_integer() {
        let store = Store::new();
        exec(&store, &[b"SET", b"k", b"hello"]);
        let out = exec_str(&store, &[b"MEMORY", b"USAGE", b"k"]);
        assert!(out.starts_with(":"), "should be integer: {out}");
        let n: i64 = out
            .trim()
            .trim_start_matches(':')
            .trim_end_matches("\r\n")
            .parse()
            .unwrap_or(0);
        assert!(n > 0, "should be positive: {n}");
    }

    #[test]
    fn memory_usage_missing_key() {
        let store = Store::new();
        let out = exec_str(&store, &[b"MEMORY", b"USAGE", b"nope"]);
        assert!(out.contains("$-1"), "null for missing key: {out}");
    }

    #[test]
    fn lpos_basic() {
        let store = Store::new();
        exec(&store, &[b"RPUSH", b"list", b"a", b"b", b"c", b"b", b"d"]);
        let out = exec_str(&store, &[b"LPOS", b"list", b"b"]);
        assert!(out.contains(":1"), "first occurrence at index 1: {out}");
    }

    #[test]
    fn lpos_count() {
        let store = Store::new();
        exec(&store, &[b"RPUSH", b"list", b"a", b"b", b"c", b"b", b"d"]);
        let out = exec_str(&store, &[b"LPOS", b"list", b"b", b"COUNT", b"0"]);
        assert!(out.contains("*2"), "two occurrences: {out}");
        assert!(out.contains(":1"));
        assert!(out.contains(":3"));
    }

    #[test]
    fn lpos_rank_negative() {
        let store = Store::new();
        exec(&store, &[b"RPUSH", b"list", b"a", b"b", b"c", b"b", b"d"]);
        let out = exec_str(&store, &[b"LPOS", b"list", b"b", b"RANK", b"-1"]);
        assert!(out.contains(":3"), "last occurrence from end: {out}");
    }

    #[test]
    fn lpos_not_found() {
        let store = Store::new();
        exec(&store, &[b"RPUSH", b"list", b"a", b"b"]);
        let out = exec_str(&store, &[b"LPOS", b"list", b"z"]);
        assert!(out.contains("$-1"), "not found returns null: {out}");
    }

    #[test]
    fn hincrbyfloat_basic() {
        let store = Store::new();
        exec(&store, &[b"HSET", b"h", b"f", b"10.5"]);
        let out = exec_str(&store, &[b"HINCRBYFLOAT", b"h", b"f", b"0.1"]);
        assert!(out.contains("10.6"), "float increment: {out}");
    }

    #[test]
    fn hincrbyfloat_creates_field() {
        let store = Store::new();
        let out = exec_str(&store, &[b"HINCRBYFLOAT", b"h", b"newf", b"3.14"]);
        assert!(out.contains("3.14"), "creates field: {out}");
    }

    #[test]
    fn hstrlen_returns_length() {
        let store = Store::new();
        exec(&store, &[b"HSET", b"h", b"f", b"hello"]);
        let out = exec_str(&store, &[b"HSTRLEN", b"h", b"f"]);
        assert!(out.contains(":5"), "length of 'hello': {out}");
        let out = exec_str(&store, &[b"HSTRLEN", b"h", b"missing"]);
        assert!(out.contains(":0"), "missing field: {out}");
    }

    #[test]
    fn hscan_basic() {
        let store = Store::new();
        exec(&store, &[b"HSET", b"h", b"f1", b"v1", b"f2", b"v2"]);
        let out = exec_str(&store, &[b"HSCAN", b"h", b"0"]);
        assert!(out.contains("f1"), "contains field: {out}");
        assert!(out.contains("v1"), "contains value: {out}");
    }

    #[test]
    fn sscan_basic() {
        let store = Store::new();
        exec(&store, &[b"SADD", b"s", b"a", b"b", b"c"]);
        let out = exec_str(&store, &[b"SSCAN", b"s", b"0"]);
        assert!(
            out.starts_with("*2"),
            "two-element array (cursor + items): {out}"
        );
    }

    #[test]
    fn zscan_basic() {
        let store = Store::new();
        exec(&store, &[b"ZADD", b"z", b"1", b"a", b"2", b"b"]);
        let out = exec_str(&store, &[b"ZSCAN", b"z", b"0"]);
        assert!(out.starts_with("*2"), "two-element array: {out}");
        assert!(out.contains("a"));
    }

    #[test]
    fn spop_single_and_count() {
        let store = Store::new();
        exec(&store, &[b"SADD", b"s", b"a", b"b", b"c"]);
        let out = exec_str(&store, &[b"SPOP", b"s"]);
        assert!(out.contains("$1"), "single element: {out}");

        let out = exec_str(&store, &[b"SPOP", b"s", b"10"]);
        assert!(out.starts_with("*"), "array for count variant: {out}");
    }

    #[test]
    fn srandmember_does_not_remove() {
        let store = Store::new();
        exec(&store, &[b"SADD", b"s", b"a", b"b", b"c"]);
        exec_str(&store, &[b"SRANDMEMBER", b"s"]);
        let out = exec_str(&store, &[b"SCARD", b"s"]);
        assert!(out.contains(":3"), "no removal: {out}");
    }

    #[test]
    fn srandmember_count() {
        let store = Store::new();
        exec(&store, &[b"SADD", b"s", b"a", b"b", b"c"]);
        let out = exec_str(&store, &[b"SRANDMEMBER", b"s", b"2"]);
        assert!(out.starts_with("*"), "array response: {out}");
    }

    #[test]
    fn sintercard_basic() {
        let store = Store::new();
        exec(&store, &[b"SADD", b"s1", b"a", b"b", b"c"]);
        exec(&store, &[b"SADD", b"s2", b"b", b"c", b"d"]);
        let out = exec_str(&store, &[b"SINTERCARD", b"2", b"s1", b"s2"]);
        assert!(out.contains(":2"), "intersection cardinality: {out}");
    }

    #[test]
    fn hrandfield_basic() {
        let store = Store::new();
        exec(&store, &[b"HSET", b"h", b"f1", b"v1", b"f2", b"v2"]);
        let out = exec_str(&store, &[b"HRANDFIELD", b"h"]);
        assert!(
            out.contains("f1") || out.contains("f2"),
            "returns a field: {out}"
        );
    }

    #[test]
    fn hrandfield_count_withvalues() {
        let store = Store::new();
        exec(&store, &[b"HSET", b"h", b"f1", b"v1", b"f2", b"v2"]);
        let out = exec_str(&store, &[b"HRANDFIELD", b"h", b"2", b"WITHVALUES"]);
        assert!(out.starts_with("*4"), "2 fields * 2 = 4 elements: {out}");
    }

    #[test]
    fn zremrangebyrank_basic() {
        let store = Store::new();
        exec(&store, &[b"ZADD", b"z", b"1", b"a", b"2", b"b", b"3", b"c"]);
        let out = exec_str(&store, &[b"ZREMRANGEBYRANK", b"z", b"0", b"1"]);
        assert!(out.contains(":2"), "removed 2: {out}");
        let out = exec_str(&store, &[b"ZCARD", b"z"]);
        assert!(out.contains(":1"), "1 remaining: {out}");
    }

    #[test]
    fn zremrangebyscore_basic() {
        let store = Store::new();
        exec(&store, &[b"ZADD", b"z", b"1", b"a", b"2", b"b", b"3", b"c"]);
        let out = exec_str(&store, &[b"ZREMRANGEBYSCORE", b"z", b"-inf", b"2"]);
        assert!(out.contains(":2"), "removed 2: {out}");
        let out = exec_str(&store, &[b"ZCARD", b"z"]);
        assert!(out.contains(":1"), "1 remaining: {out}");
    }

    #[test]
    fn zremrangebylex_basic() {
        let store = Store::new();
        exec(
            &store,
            &[
                b"ZADD", b"z", b"0", b"a", b"0", b"b", b"0", b"c", b"0", b"d",
            ],
        );
        let out = exec_str(&store, &[b"ZREMRANGEBYLEX", b"z", b"[a", b"[c"]);
        assert!(out.contains(":3"), "removed a,b,c: {out}");
        let out = exec_str(&store, &[b"ZCARD", b"z"]);
        assert!(out.contains(":1"), "d remaining: {out}");
    }

    #[test]
    fn zlexcount_basic() {
        let store = Store::new();
        exec(&store, &[b"ZADD", b"z", b"0", b"a", b"0", b"b", b"0", b"c"]);
        let out = exec_str(&store, &[b"ZLEXCOUNT", b"z", b"-", b"+"]);
        assert!(out.contains(":3"), "all members: {out}");
        let out = exec_str(&store, &[b"ZLEXCOUNT", b"z", b"[a", b"[b"]);
        assert!(out.contains(":2"), "a and b: {out}");
    }

    #[test]
    fn zrevrange_basic() {
        let store = Store::new();
        exec(&store, &[b"ZADD", b"z", b"1", b"a", b"2", b"b", b"3", b"c"]);
        let out = exec_str(&store, &[b"ZRANGE", b"z", b"0", b"-1", b"REV"]);
        let a_pos = out.find("a").unwrap_or(0);
        let c_pos = out.find("c").unwrap_or(usize::MAX);
        assert!(c_pos < a_pos, "c before a in reverse: {out}");
    }

    #[test]
    fn zrevrangebyscore_basic() {
        let store = Store::new();
        exec(&store, &[b"ZADD", b"z", b"1", b"a", b"2", b"b", b"3", b"c"]);
        let out = exec_str(&store, &[b"ZREVRANGEBYSCORE", b"z", b"3", b"1"]);
        assert!(
            out.contains("a") && out.contains("c"),
            "contains both: {out}"
        );
    }

    #[test]
    fn unlink_same_as_del() {
        let store = Store::new();
        exec(&store, &[b"SET", b"a", b"1"]);
        exec(&store, &[b"SET", b"b", b"2"]);
        let out = exec_str(&store, &[b"UNLINK", b"a", b"b"]);
        assert!(out.contains(":2"), "removed 2: {out}");
        assert!(store.get(b"a", Instant::now()).is_none());
    }

    #[test]
    fn randomkey_returns_key_or_null() {
        let store = Store::new();
        let out = exec_str(&store, &[b"RANDOMKEY"]);
        assert!(out.contains("$-1"), "empty db returns null: {out}");

        exec(&store, &[b"SET", b"mykey", b"val"]);
        let out = exec_str(&store, &[b"RANDOMKEY"]);
        assert!(out.contains("mykey"), "returns existing key: {out}");
    }

    #[test]
    fn hello_returns_server_info() {
        let store = Store::new();
        let out = exec_str(&store, &[b"HELLO"]);
        assert!(out.contains("lux"), "contains server name: {out}");
        assert!(out.contains("proto"), "contains proto: {out}");
    }

    #[test]
    fn info_returns_bulk_string() {
        let store = Store::new();
        let out = exec_str(&store, &[b"INFO"]);
        assert!(out.contains("lux_version"), "contains version: {out}");
        assert!(out.contains("connected_clients"), "contains clients: {out}");
    }

    #[test]
    fn config_get_returns_empty_array() {
        let store = Store::new();
        let out = exec_str(&store, &[b"CONFIG", b"GET", b"maxmemory"]);
        assert!(out.contains("*0"), "empty array: {out}");
    }

    #[test]
    fn select_returns_ok() {
        let store = Store::new();
        let out = exec_str(&store, &[b"SELECT", b"0"]);
        assert!(out.contains("+OK"));
    }

    #[test]
    fn substr_alias_for_getrange() {
        let store = Store::new();
        exec(&store, &[b"SET", b"k", b"Hello World"]);
        let out = exec_str(&store, &[b"SUBSTR", b"k", b"0", b"4"]);
        assert!(out.contains("Hello"), "substr works like getrange: {out}");
    }

    #[test]
    fn multi_exec_discard_watch_unwatch_not_handled_by_cmd() {
        let store = Store::new();
        for cmd in &[
            vec![b"MULTI" as &[u8]],
            vec![b"WATCH", b"key"],
            vec![b"UNWATCH"],
        ] {
            let out = exec_str(&store, cmd);
            assert!(
                out.contains("ERR unknown command"),
                "cmd {:?} should be unknown: {out}",
                std::str::from_utf8(cmd[0])
            );
        }
    }
}
