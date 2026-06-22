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
use std::time::Instant;

use crate::pubsub::Broker;
use crate::resp;
use crate::store::{Entry, Store, StoreValue, StreamId};
use crate::tables::SharedSchemaCache;

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
        message: Bytes,
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

fn is_restricted(store: &Store) -> bool {
    // Restricted mode is per-runtime so embedded servers in one process do not
    // share command policy through global environment variables.
    store.config().restricted
}

#[inline(always)]
fn cmd_eq(input: &[u8], expected: &[u8]) -> bool {
    if input == expected {
        return true;
    }
    if input.len() != expected.len() {
        return false;
    }
    for i in 0..input.len() {
        let b = input[i];
        let upper = if b.is_ascii_lowercase() { b - 32 } else { b };
        if upper != expected[i] {
            return false;
        }
    }
    true
}

#[inline(always)]
pub(crate) fn cmd_eq_ci(input: &[u8], expected: &[u8]) -> bool {
    cmd_eq(input, expected)
}

struct CommandSpec {
    name: &'static [u8],
    min_arity: usize,
}

const COMMAND_SPECS: &[CommandSpec] = &[
    CommandSpec {
        name: b"SET",
        min_arity: 3,
    },
    CommandSpec {
        name: b"GET",
        min_arity: 2,
    },
    CommandSpec {
        name: b"DEL",
        min_arity: 2,
    },
    CommandSpec {
        name: b"PING",
        min_arity: 1,
    },
    CommandSpec {
        name: b"ECHO",
        min_arity: 2,
    },
    CommandSpec {
        name: b"QUIT",
        min_arity: 1,
    },
    CommandSpec {
        name: b"SETNX",
        min_arity: 3,
    },
    CommandSpec {
        name: b"SETEX",
        min_arity: 4,
    },
    CommandSpec {
        name: b"PSETEX",
        min_arity: 4,
    },
    CommandSpec {
        name: b"GETSET",
        min_arity: 3,
    },
    CommandSpec {
        name: b"MGET",
        min_arity: 2,
    },
    CommandSpec {
        name: b"MSET",
        min_arity: 3,
    },
    CommandSpec {
        name: b"STRLEN",
        min_arity: 2,
    },
    CommandSpec {
        name: b"EXISTS",
        min_arity: 2,
    },
    CommandSpec {
        name: b"INCR",
        min_arity: 2,
    },
    CommandSpec {
        name: b"DECR",
        min_arity: 2,
    },
    CommandSpec {
        name: b"INCRBY",
        min_arity: 3,
    },
    CommandSpec {
        name: b"DECRBY",
        min_arity: 3,
    },
    CommandSpec {
        name: b"APPEND",
        min_arity: 3,
    },
    CommandSpec {
        name: b"KEYS",
        min_arity: 2,
    },
    CommandSpec {
        name: b"SCAN",
        min_arity: 2,
    },
    CommandSpec {
        name: b"TTL",
        min_arity: 2,
    },
    CommandSpec {
        name: b"PTTL",
        min_arity: 2,
    },
    CommandSpec {
        name: b"EXPIRE",
        min_arity: 3,
    },
    CommandSpec {
        name: b"PEXPIRE",
        min_arity: 3,
    },
    CommandSpec {
        name: b"PERSIST",
        min_arity: 2,
    },
    CommandSpec {
        name: b"TYPE",
        min_arity: 2,
    },
    CommandSpec {
        name: b"RENAME",
        min_arity: 3,
    },
    CommandSpec {
        name: b"DBSIZE",
        min_arity: 1,
    },
    CommandSpec {
        name: b"FLUSHDB",
        min_arity: 1,
    },
    CommandSpec {
        name: b"FLUSHALL",
        min_arity: 1,
    },
    CommandSpec {
        name: b"LPUSH",
        min_arity: 3,
    },
    CommandSpec {
        name: b"RPUSH",
        min_arity: 3,
    },
    CommandSpec {
        name: b"LPOP",
        min_arity: 2,
    },
    CommandSpec {
        name: b"RPOP",
        min_arity: 2,
    },
    CommandSpec {
        name: b"LLEN",
        min_arity: 2,
    },
    CommandSpec {
        name: b"LRANGE",
        min_arity: 3,
    },
    CommandSpec {
        name: b"LINDEX",
        min_arity: 3,
    },
    CommandSpec {
        name: b"HSET",
        min_arity: 4,
    },
    CommandSpec {
        name: b"HMSET",
        min_arity: 4,
    },
    CommandSpec {
        name: b"HGET",
        min_arity: 3,
    },
    CommandSpec {
        name: b"HMGET",
        min_arity: 3,
    },
    CommandSpec {
        name: b"HDEL",
        min_arity: 3,
    },
    CommandSpec {
        name: b"HGETALL",
        min_arity: 2,
    },
    CommandSpec {
        name: b"HKEYS",
        min_arity: 2,
    },
    CommandSpec {
        name: b"HVALS",
        min_arity: 2,
    },
    CommandSpec {
        name: b"HLEN",
        min_arity: 2,
    },
    CommandSpec {
        name: b"HEXISTS",
        min_arity: 3,
    },
    CommandSpec {
        name: b"HINCRBY",
        min_arity: 4,
    },
    CommandSpec {
        name: b"SADD",
        min_arity: 3,
    },
    CommandSpec {
        name: b"SREM",
        min_arity: 3,
    },
    CommandSpec {
        name: b"SMEMBERS",
        min_arity: 2,
    },
    CommandSpec {
        name: b"SISMEMBER",
        min_arity: 3,
    },
    CommandSpec {
        name: b"SCARD",
        min_arity: 2,
    },
    CommandSpec {
        name: b"SUNION",
        min_arity: 2,
    },
    CommandSpec {
        name: b"SINTER",
        min_arity: 2,
    },
    CommandSpec {
        name: b"SDIFF",
        min_arity: 2,
    },
    CommandSpec {
        name: b"SAVE",
        min_arity: 1,
    },
    CommandSpec {
        name: b"INFO",
        min_arity: 1,
    },
    CommandSpec {
        name: b"CONFIG",
        min_arity: 1,
    },
    CommandSpec {
        name: b"CLIENT",
        min_arity: 2,
    },
    CommandSpec {
        name: b"SELECT",
        min_arity: 2,
    },
    CommandSpec {
        name: b"COMMAND",
        min_arity: 1,
    },
    CommandSpec {
        name: b"MULTI",
        min_arity: 1,
    },
    CommandSpec {
        name: b"EXEC",
        min_arity: 1,
    },
    CommandSpec {
        name: b"DISCARD",
        min_arity: 1,
    },
    CommandSpec {
        name: b"WATCH",
        min_arity: 2,
    },
    CommandSpec {
        name: b"UNWATCH",
        min_arity: 1,
    },
    CommandSpec {
        name: b"GETDEL",
        min_arity: 2,
    },
    CommandSpec {
        name: b"GETEX",
        min_arity: 2,
    },
    CommandSpec {
        name: b"GETRANGE",
        min_arity: 4,
    },
    CommandSpec {
        name: b"GEOADD",
        min_arity: 5,
    },
    CommandSpec {
        name: b"GEODIST",
        min_arity: 4,
    },
    CommandSpec {
        name: b"GEOPOS",
        min_arity: 3,
    },
    CommandSpec {
        name: b"GEOHASH",
        min_arity: 3,
    },
    CommandSpec {
        name: b"GEOSEARCH",
        min_arity: 4,
    },
    CommandSpec {
        name: b"GEOSEARCH_RO",
        min_arity: 4,
    },
    CommandSpec {
        name: b"GEOSEARCHSTORE",
        min_arity: 5,
    },
    CommandSpec {
        name: b"GEORADIUS",
        min_arity: 6,
    },
    CommandSpec {
        name: b"GEORADIUS_RO",
        min_arity: 6,
    },
    CommandSpec {
        name: b"GEORADIUSBYMEMBER",
        min_arity: 5,
    },
    CommandSpec {
        name: b"GEORADIUSBYMEMBER_RO",
        min_arity: 5,
    },
    CommandSpec {
        name: b"SUBSTR",
        min_arity: 4,
    },
    CommandSpec {
        name: b"SETRANGE",
        min_arity: 4,
    },
    CommandSpec {
        name: b"MSETNX",
        min_arity: 3,
    },
    CommandSpec {
        name: b"UNLINK",
        min_arity: 2,
    },
    CommandSpec {
        name: b"EXPIREAT",
        min_arity: 3,
    },
    CommandSpec {
        name: b"PEXPIREAT",
        min_arity: 3,
    },
    CommandSpec {
        name: b"EXPIRETIME",
        min_arity: 2,
    },
    CommandSpec {
        name: b"PEXPIRETIME",
        min_arity: 2,
    },
    CommandSpec {
        name: b"LSET",
        min_arity: 4,
    },
    CommandSpec {
        name: b"LINSERT",
        min_arity: 5,
    },
    CommandSpec {
        name: b"LREM",
        min_arity: 4,
    },
    CommandSpec {
        name: b"LTRIM",
        min_arity: 4,
    },
    CommandSpec {
        name: b"LPUSHX",
        min_arity: 3,
    },
    CommandSpec {
        name: b"RPUSHX",
        min_arity: 3,
    },
    CommandSpec {
        name: b"LPOS",
        min_arity: 3,
    },
    CommandSpec {
        name: b"LMOVE",
        min_arity: 5,
    },
    CommandSpec {
        name: b"RPOPLPUSH",
        min_arity: 3,
    },
    CommandSpec {
        name: b"HSETNX",
        min_arity: 4,
    },
    CommandSpec {
        name: b"HINCRBYFLOAT",
        min_arity: 4,
    },
    CommandSpec {
        name: b"HSTRLEN",
        min_arity: 3,
    },
    CommandSpec {
        name: b"SPOP",
        min_arity: 2,
    },
    CommandSpec {
        name: b"SRANDMEMBER",
        min_arity: 2,
    },
    CommandSpec {
        name: b"SMOVE",
        min_arity: 4,
    },
    CommandSpec {
        name: b"SMISMEMBER",
        min_arity: 3,
    },
    CommandSpec {
        name: b"SDIFFSTORE",
        min_arity: 3,
    },
    CommandSpec {
        name: b"SINTERSTORE",
        min_arity: 3,
    },
    CommandSpec {
        name: b"SUNIONSTORE",
        min_arity: 3,
    },
    CommandSpec {
        name: b"SINTERCARD",
        min_arity: 3,
    },
    CommandSpec {
        name: b"HRANDFIELD",
        min_arity: 2,
    },
    CommandSpec {
        name: b"HSCAN",
        min_arity: 3,
    },
    CommandSpec {
        name: b"SSCAN",
        min_arity: 3,
    },
    CommandSpec {
        name: b"INCRBYFLOAT",
        min_arity: 3,
    },
    CommandSpec {
        name: b"TIME",
        min_arity: 1,
    },
    CommandSpec {
        name: b"RENAMENX",
        min_arity: 3,
    },
    CommandSpec {
        name: b"RANDOMKEY",
        min_arity: 1,
    },
    CommandSpec {
        name: b"HELLO",
        min_arity: 1,
    },
    CommandSpec {
        name: b"PSUBSCRIBE",
        min_arity: 2,
    },
    CommandSpec {
        name: b"PUNSUBSCRIBE",
        min_arity: 1,
    },
    CommandSpec {
        name: b"COPY",
        min_arity: 3,
    },
    CommandSpec {
        name: b"FUNCTION",
        min_arity: 1,
    },
    CommandSpec {
        name: b"DEBUG",
        min_arity: 1,
    },
    CommandSpec {
        name: b"DUMP",
        min_arity: 1,
    },
    CommandSpec {
        name: b"WAIT",
        min_arity: 1,
    },
    CommandSpec {
        name: b"RESET",
        min_arity: 1,
    },
    CommandSpec {
        name: b"LATENCY",
        min_arity: 1,
    },
    CommandSpec {
        name: b"SWAPDB",
        min_arity: 1,
    },
    CommandSpec {
        name: b"OBJECT",
        min_arity: 1,
    },
    CommandSpec {
        name: b"MEMORY",
        min_arity: 1,
    },
    CommandSpec {
        name: b"BGSAVE",
        min_arity: 1,
    },
    CommandSpec {
        name: b"LASTSAVE",
        min_arity: 1,
    },
    CommandSpec {
        name: b"PUBLISH",
        min_arity: 3,
    },
    CommandSpec {
        name: b"SUBSCRIBE",
        min_arity: 2,
    },
    CommandSpec {
        name: b"UNSUBSCRIBE",
        min_arity: 1,
    },
    CommandSpec {
        name: b"ZADD",
        min_arity: 4,
    },
    CommandSpec {
        name: b"ZSCORE",
        min_arity: 3,
    },
    CommandSpec {
        name: b"ZRANK",
        min_arity: 3,
    },
    CommandSpec {
        name: b"ZREVRANK",
        min_arity: 3,
    },
    CommandSpec {
        name: b"ZREVRANGE",
        min_arity: 4,
    },
    CommandSpec {
        name: b"ZREM",
        min_arity: 3,
    },
    CommandSpec {
        name: b"ZCARD",
        min_arity: 2,
    },
    CommandSpec {
        name: b"ZRANGE",
        min_arity: 4,
    },
    CommandSpec {
        name: b"ZINCRBY",
        min_arity: 4,
    },
    CommandSpec {
        name: b"ZCOUNT",
        min_arity: 4,
    },
    CommandSpec {
        name: b"ZPOPMIN",
        min_arity: 2,
    },
    CommandSpec {
        name: b"ZPOPMAX",
        min_arity: 2,
    },
    CommandSpec {
        name: b"ZUNIONSTORE",
        min_arity: 4,
    },
    CommandSpec {
        name: b"ZINTERSTORE",
        min_arity: 4,
    },
    CommandSpec {
        name: b"ZDIFFSTORE",
        min_arity: 4,
    },
    CommandSpec {
        name: b"ZSCAN",
        min_arity: 3,
    },
    CommandSpec {
        name: b"ZMSCORE",
        min_arity: 3,
    },
    CommandSpec {
        name: b"ZLEXCOUNT",
        min_arity: 4,
    },
    CommandSpec {
        name: b"ZRANGEBYSCORE",
        min_arity: 4,
    },
    CommandSpec {
        name: b"ZREVRANGEBYSCORE",
        min_arity: 4,
    },
    CommandSpec {
        name: b"ZRANGEBYLEX",
        min_arity: 4,
    },
    CommandSpec {
        name: b"ZREVRANGEBYLEX",
        min_arity: 4,
    },
    CommandSpec {
        name: b"ZREMRANGEBYRANK",
        min_arity: 4,
    },
    CommandSpec {
        name: b"ZREMRANGEBYSCORE",
        min_arity: 4,
    },
    CommandSpec {
        name: b"ZREMRANGEBYLEX",
        min_arity: 4,
    },
    CommandSpec {
        name: b"AUTH",
        min_arity: 2,
    },
    CommandSpec {
        name: b"BLPOP",
        min_arity: 3,
    },
    CommandSpec {
        name: b"BRPOP",
        min_arity: 3,
    },
    CommandSpec {
        name: b"BLMOVE",
        min_arity: 6,
    },
    CommandSpec {
        name: b"BZPOPMIN",
        min_arity: 3,
    },
    CommandSpec {
        name: b"BZPOPMAX",
        min_arity: 3,
    },
    CommandSpec {
        name: b"XADD",
        min_arity: 5,
    },
    CommandSpec {
        name: b"XLEN",
        min_arity: 2,
    },
    CommandSpec {
        name: b"XRANGE",
        min_arity: 4,
    },
    CommandSpec {
        name: b"XREVRANGE",
        min_arity: 4,
    },
    CommandSpec {
        name: b"XREAD",
        min_arity: 2,
    },
    CommandSpec {
        name: b"XREADGROUP",
        min_arity: 5,
    },
    CommandSpec {
        name: b"XGROUP",
        min_arity: 2,
    },
    CommandSpec {
        name: b"XACK",
        min_arity: 3,
    },
    CommandSpec {
        name: b"XPENDING",
        min_arity: 3,
    },
    CommandSpec {
        name: b"XCLAIM",
        min_arity: 6,
    },
    CommandSpec {
        name: b"XAUTOCLAIM",
        min_arity: 6,
    },
    CommandSpec {
        name: b"XDEL",
        min_arity: 3,
    },
    CommandSpec {
        name: b"XTRIM",
        min_arity: 2,
    },
    CommandSpec {
        name: b"XINFO",
        min_arity: 2,
    },
    CommandSpec {
        name: b"EVAL",
        min_arity: 3,
    },
    CommandSpec {
        name: b"EVALSHA",
        min_arity: 3,
    },
    CommandSpec {
        name: b"SCRIPT",
        min_arity: 2,
    },
    CommandSpec {
        name: b"VSET",
        min_arity: 4,
    },
    CommandSpec {
        name: b"VGET",
        min_arity: 2,
    },
    CommandSpec {
        name: b"VSEARCH",
        min_arity: 4,
    },
    CommandSpec {
        name: b"VCARD",
        min_arity: 2,
    },
    CommandSpec {
        name: b"PFADD",
        min_arity: 2,
    },
    CommandSpec {
        name: b"PFCOUNT",
        min_arity: 2,
    },
    CommandSpec {
        name: b"PFMERGE",
        min_arity: 2,
    },
    CommandSpec {
        name: b"PFDEBUG",
        min_arity: 2,
    },
    CommandSpec {
        name: b"SORT",
        min_arity: 2,
    },
    CommandSpec {
        name: b"SORT_RO",
        min_arity: 2,
    },
    CommandSpec {
        name: b"TSADD",
        min_arity: 4,
    },
    CommandSpec {
        name: b"TSMADD",
        min_arity: 4,
    },
    CommandSpec {
        name: b"TSGET",
        min_arity: 2,
    },
    CommandSpec {
        name: b"TSRANGE",
        min_arity: 4,
    },
    CommandSpec {
        name: b"TSMRANGE",
        min_arity: 5,
    },
    CommandSpec {
        name: b"TSINFO",
        min_arity: 2,
    },
    CommandSpec {
        name: b"SETBIT",
        min_arity: 4,
    },
    CommandSpec {
        name: b"GETBIT",
        min_arity: 3,
    },
    CommandSpec {
        name: b"BITCOUNT",
        min_arity: 2,
    },
    CommandSpec {
        name: b"BITPOS",
        min_arity: 2,
    },
    CommandSpec {
        name: b"BITOP",
        min_arity: 4,
    },
    CommandSpec {
        name: b"KSUB",
        min_arity: 2,
    },
    CommandSpec {
        name: b"KUNSUB",
        min_arity: 1,
    },
    CommandSpec {
        name: b"TCREATE",
        min_arity: 3,
    },
    CommandSpec {
        name: b"TINSERT",
        min_arity: 2,
    },
    CommandSpec {
        name: b"TUPSERT",
        min_arity: 2,
    },
    CommandSpec {
        name: b"TUPDATE",
        min_arity: 7,
    },
    CommandSpec {
        name: b"TDELETE",
        min_arity: 6,
    },
    CommandSpec {
        name: b"TDROP",
        min_arity: 2,
    },
    CommandSpec {
        name: b"TINDEX",
        min_arity: 4,
    },
    CommandSpec {
        name: b"TDROPINDEX",
        min_arity: 3,
    },
    CommandSpec {
        name: b"GRANT",
        min_arity: 4,
    },
    CommandSpec {
        name: b"REVOKE",
        min_arity: 4,
    },
    CommandSpec {
        name: b"TCOUNT",
        min_arity: 2,
    },
    CommandSpec {
        name: b"TSCHEMA",
        min_arity: 2,
    },
    CommandSpec {
        name: b"TLIST",
        min_arity: 1,
    },
    CommandSpec {
        name: b"TALTER",
        min_arity: 4,
    },
    CommandSpec {
        name: b"TSELECT",
        min_arity: 4,
    },
];

fn command_spec(cmd: &[u8]) -> Option<&'static CommandSpec> {
    COMMAND_SPECS.iter().find(|spec| cmd_eq(cmd, spec.name))
}

#[inline(always)]
pub(crate) fn is_public_without_auth_command(cmd: &[u8]) -> bool {
    command_spec(cmd).is_some()
        && (cmd_eq(cmd, b"AUTH")
            || cmd_eq(cmd, b"HELLO")
            || cmd_eq(cmd, b"PING")
            || cmd_eq(cmd, b"QUIT"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PipelineAccess {
    General,
    Read,
    Write,
}

#[inline(always)]
pub(crate) fn is_blocking_command(cmd: &[u8]) -> bool {
    cmd_eq(cmd, b"BLPOP")
        || cmd_eq(cmd, b"BRPOP")
        || cmd_eq(cmd, b"BLMOVE")
        || cmd_eq(cmd, b"BZPOPMIN")
        || cmd_eq(cmd, b"BZPOPMAX")
        || cmd_eq(cmd, b"EVAL")
        || cmd_eq(cmd, b"EVALSHA")
        || cmd_eq(cmd, b"SCRIPT")
}

#[inline(always)]
pub(crate) fn is_pipeline_special_command(cmd: &[u8]) -> bool {
    cmd_eq(cmd, b"SUBSCRIBE")
        || cmd_eq(cmd, b"UNSUBSCRIBE")
        || cmd_eq(cmd, b"PSUBSCRIBE")
        || cmd_eq(cmd, b"PUNSUBSCRIBE")
        || cmd_eq(cmd, b"KSUB")
        || cmd_eq(cmd, b"KUNSUB")
        || cmd_eq(cmd, b"PUBLISH")
        || cmd_eq(cmd, b"AUTH")
        || cmd_eq(cmd, b"MULTI")
        || cmd_eq(cmd, b"EXEC")
        || cmd_eq(cmd, b"DISCARD")
        || cmd_eq(cmd, b"WATCH")
        || cmd_eq(cmd, b"UNWATCH")
        || is_blocking_command(cmd)
        || cmd_eq(cmd, b"XREAD")
        || cmd_eq(cmd, b"XREADGROUP")
}

#[inline(always)]
pub(crate) fn pipeline_access(cmd: &[u8]) -> PipelineAccess {
    if cmd.is_empty() {
        return PipelineAccess::General;
    }
    match cmd[0].to_ascii_uppercase() {
        b'A' => {
            if cmd_eq(cmd, b"APPEND") {
                return PipelineAccess::Write;
            }
        }
        b'D' => {
            if cmd_eq(cmd, b"DECR") || cmd_eq(cmd, b"DECRBY") {
                return PipelineAccess::Write;
            }
        }
        b'E' => {
            if cmd_eq(cmd, b"EXISTS") {
                return PipelineAccess::Read;
            }
            if cmd_eq(cmd, b"EXPIRE") {
                return PipelineAccess::Write;
            }
        }
        b'G' => {
            if cmd_eq(cmd, b"GET") || cmd_eq(cmd, b"GEODIST") || cmd_eq(cmd, b"GEOPOS") {
                return PipelineAccess::Read;
            }
            if cmd_eq(cmd, b"GETSET") || cmd_eq(cmd, b"GEOADD") {
                return PipelineAccess::Write;
            }
        }
        b'H' => {
            if cmd_eq(cmd, b"HGET")
                || cmd_eq(cmd, b"HLEN")
                || cmd_eq(cmd, b"HMGET")
                || cmd_eq(cmd, b"HEXISTS")
                || cmd_eq(cmd, b"HGETALL")
            {
                return PipelineAccess::Read;
            }
            if cmd_eq(cmd, b"HSET") || cmd_eq(cmd, b"HINCRBY") || cmd_eq(cmd, b"HDEL") {
                return PipelineAccess::Write;
            }
        }
        b'I' => {
            if cmd_eq(cmd, b"INCR") || cmd_eq(cmd, b"INCRBY") {
                return PipelineAccess::Write;
            }
        }
        b'L' => {
            if cmd_eq(cmd, b"LLEN") || cmd_eq(cmd, b"LINDEX") || cmd_eq(cmd, b"LRANGE") {
                return PipelineAccess::Read;
            }
            if cmd_eq(cmd, b"LPUSH") || cmd_eq(cmd, b"LPOP") {
                return PipelineAccess::Write;
            }
        }
        b'P' => {
            if cmd_eq(cmd, b"PTTL") {
                return PipelineAccess::Read;
            }
            if cmd_eq(cmd, b"PERSIST") {
                return PipelineAccess::Write;
            }
        }
        b'R' => {
            if cmd_eq(cmd, b"RPOP") || cmd_eq(cmd, b"RPUSH") {
                return PipelineAccess::Write;
            }
        }
        b'S' => {
            if cmd_eq(cmd, b"STRLEN")
                || cmd_eq(cmd, b"SCARD")
                || cmd_eq(cmd, b"SMEMBERS")
                || cmd_eq(cmd, b"SISMEMBER")
                || cmd_eq(cmd, b"SRANDMEMBER")
            {
                return PipelineAccess::Read;
            }
            if cmd_eq(cmd, b"SET")
                || cmd_eq(cmd, b"SETNX")
                || cmd_eq(cmd, b"SETEX")
                || cmd_eq(cmd, b"SADD")
                || cmd_eq(cmd, b"SREM")
                || cmd_eq(cmd, b"SPOP")
            {
                return PipelineAccess::Write;
            }
        }
        b'T' => {
            if cmd_eq(cmd, b"TTL") || cmd_eq(cmd, b"TYPE") {
                return PipelineAccess::Read;
            }
        }
        b'X' => {
            if cmd_eq(cmd, b"XLEN") || cmd_eq(cmd, b"XRANGE") {
                return PipelineAccess::Read;
            }
            if cmd_eq(cmd, b"XADD") {
                return PipelineAccess::Write;
            }
        }
        b'Z' => {
            if cmd_eq(cmd, b"ZCARD") || cmd_eq(cmd, b"ZSCORE") || cmd_eq(cmd, b"ZCOUNT") {
                return PipelineAccess::Read;
            }
            if cmd_eq(cmd, b"ZADD")
                || cmd_eq(cmd, b"ZINCRBY")
                || cmd_eq(cmd, b"ZREM")
                || cmd_eq(cmd, b"ZPOPMIN")
                || cmd_eq(cmd, b"ZPOPMAX")
            {
                return PipelineAccess::Write;
            }
        }
        _ => {}
    }
    PipelineAccess::General
}

pub(crate) fn pipeline_access_for_args(args: &[&[u8]]) -> PipelineAccess {
    if args.is_empty() || args[0].is_empty() {
        return PipelineAccess::General;
    }

    let cmd = args[0];
    if args.len() == 2 && cmd_eq(cmd, b"GET") {
        return PipelineAccess::Read;
    }
    if args.len() == 3 && cmd_eq(cmd, b"SET") {
        return PipelineAccess::Write;
    }

    if cmd[0].eq_ignore_ascii_case(&b'Z') {
        if cmd_eq(cmd, b"ZCARD") {
            return if args.len() == 2 {
                PipelineAccess::Read
            } else {
                PipelineAccess::General
            };
        }
        if cmd_eq(cmd, b"ZSCORE") {
            return if args.len() == 3 {
                PipelineAccess::Read
            } else {
                PipelineAccess::General
            };
        }
        if cmd_eq(cmd, b"ZCOUNT") {
            return if args.len() == 4 {
                PipelineAccess::Read
            } else {
                PipelineAccess::General
            };
        }
        if cmd_eq(cmd, b"ZADD")
            || cmd_eq(cmd, b"ZINCRBY")
            || cmd_eq(cmd, b"ZREM")
            || cmd_eq(cmd, b"ZPOPMIN")
            || cmd_eq(cmd, b"ZPOPMAX")
        {
            return if pipeline_fast_path_arity(args) {
                PipelineAccess::Write
            } else {
                PipelineAccess::General
            };
        }
    }

    if !pipeline_fast_path_arity(args) {
        return PipelineAccess::General;
    }
    pipeline_access(cmd)
}

fn pipeline_fast_path_arity(args: &[&[u8]]) -> bool {
    let cmd = args[0];
    match cmd[0].to_ascii_uppercase() {
        b'A' => cmd_eq(cmd, b"APPEND") && args.len() == 3,
        b'D' => {
            (cmd_eq(cmd, b"DECR") && args.len() == 2) || (cmd_eq(cmd, b"DECRBY") && args.len() == 3)
        }
        b'E' => {
            (cmd_eq(cmd, b"EXISTS") && args.len() == 2)
                || (cmd_eq(cmd, b"EXPIRE") && args.len() == 3)
        }
        b'G' => {
            (cmd_eq(cmd, b"GET") && args.len() == 2)
                || (cmd_eq(cmd, b"GEODIST") && (args.len() == 4 || args.len() == 5))
                || (cmd_eq(cmd, b"GEOPOS") && args.len() >= 3)
                || (cmd_eq(cmd, b"GETSET") && args.len() == 3)
                || (cmd_eq(cmd, b"GEOADD") && args.len() >= 5)
        }
        b'H' => {
            (cmd_eq(cmd, b"HGET") && args.len() == 3)
                || (cmd_eq(cmd, b"HLEN") && args.len() == 2)
                || (cmd_eq(cmd, b"HMGET") && args.len() >= 3)
                || (cmd_eq(cmd, b"HEXISTS") && args.len() == 3)
                || (cmd_eq(cmd, b"HGETALL") && args.len() == 2)
                || (cmd_eq(cmd, b"HSET") && args.len() >= 4)
                || (cmd_eq(cmd, b"HINCRBY") && args.len() == 4)
                || (cmd_eq(cmd, b"HDEL") && args.len() >= 3)
        }
        b'I' => {
            (cmd_eq(cmd, b"INCR") && args.len() == 2) || (cmd_eq(cmd, b"INCRBY") && args.len() == 3)
        }
        b'L' => {
            (cmd_eq(cmd, b"LLEN") && args.len() == 2)
                || (cmd_eq(cmd, b"LINDEX") && args.len() == 3)
                || (cmd_eq(cmd, b"LRANGE") && args.len() == 4)
                || (cmd_eq(cmd, b"LPUSH") && args.len() >= 3)
                || (cmd_eq(cmd, b"LPOP") && args.len() == 2)
        }
        b'P' => {
            (cmd_eq(cmd, b"PTTL") && args.len() == 2)
                || (cmd_eq(cmd, b"PERSIST") && args.len() == 2)
        }
        b'R' => {
            (cmd_eq(cmd, b"RPOP") && args.len() == 2) || (cmd_eq(cmd, b"RPUSH") && args.len() >= 3)
        }
        b'S' => {
            (cmd_eq(cmd, b"STRLEN") && args.len() == 2)
                || (cmd_eq(cmd, b"SCARD") && args.len() == 2)
                || (cmd_eq(cmd, b"SMEMBERS") && args.len() == 2)
                || (cmd_eq(cmd, b"SISMEMBER") && args.len() == 3)
                || (cmd_eq(cmd, b"SRANDMEMBER") && args.len() == 2)
                || (cmd_eq(cmd, b"SET") && set_pipeline_fast_path_arity(args))
                || (cmd_eq(cmd, b"SETNX") && args.len() == 3)
                || (cmd_eq(cmd, b"SADD") && args.len() >= 3)
                || (cmd_eq(cmd, b"SREM") && args.len() >= 3)
                || (cmd_eq(cmd, b"SPOP") && args.len() == 2)
        }
        b'T' => (cmd_eq(cmd, b"TTL") || cmd_eq(cmd, b"TYPE")) && args.len() == 2,
        b'X' => {
            (cmd_eq(cmd, b"XLEN") && args.len() == 2)
                || (cmd_eq(cmd, b"XRANGE")
                    && (args.len() == 4 || (args.len() == 6 && cmd_eq(args[4], b"COUNT"))))
                || (cmd_eq(cmd, b"XADD") && args.len() >= 5)
        }
        b'Z' => {
            (cmd_eq(cmd, b"ZCARD") && args.len() == 2)
                || (cmd_eq(cmd, b"ZSCORE") && args.len() == 3)
                || (cmd_eq(cmd, b"ZCOUNT") && args.len() == 4)
                || (cmd_eq(cmd, b"ZADD") && args.len() >= 4)
                || (cmd_eq(cmd, b"ZINCRBY") && args.len() == 4)
                || (cmd_eq(cmd, b"ZREM") && args.len() >= 3)
                || (cmd_eq(cmd, b"ZPOPMIN") && args.len() == 2)
                || (cmd_eq(cmd, b"ZPOPMAX") && args.len() == 2)
        }
        _ => false,
    }
}

fn set_pipeline_fast_path_arity(args: &[&[u8]]) -> bool {
    if args.len() == 3 {
        return true;
    }
    if args.len() < 4 {
        return false;
    }
    args[3..]
        .iter()
        .all(|arg| cmd_eq(arg, b"NX") || cmd_eq(arg, b"XX"))
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

#[inline(always)]
fn parse_score_bound_fast(s: &str, is_max: bool) -> (f64, bool) {
    if s == "-inf" || s == "-" {
        (f64::NEG_INFINITY, false)
    } else if s == "+inf" || s == "+" {
        (f64::INFINITY, false)
    } else if let Some(rest) = s.strip_prefix('(') {
        (
            rest.parse::<f64>().unwrap_or(if is_max {
                f64::INFINITY
            } else {
                f64::NEG_INFINITY
            }),
            true,
        )
    } else {
        (
            s.parse::<f64>().unwrap_or(if is_max {
                f64::INFINITY
            } else {
                f64::NEG_INFINITY
            }),
            false,
        )
    }
}

fn write_stream_entries_fast(
    out: &mut BytesMut,
    entries: &std::collections::BTreeMap<StreamId, Vec<(String, Bytes)>>,
    start: StreamId,
    end: StreamId,
    count: Option<usize>,
) {
    let take_n = count.unwrap_or(usize::MAX);
    let items = entries
        .range(start..=end)
        .take(take_n)
        .collect::<Vec<(&StreamId, &Vec<(String, Bytes)>)>>();
    resp::write_array_header(out, items.len());
    for (id, fields) in items {
        resp::write_array_header(out, 2);
        resp::write_bulk(out, &id.to_string());
        resp::write_array_header(out, fields.len() * 2);
        for (k, v) in fields {
            resp::write_bulk(out, k);
            resp::write_bulk_raw(out, v);
        }
    }
}

#[allow(dead_code)]
fn format_geo_coord(v: f64) -> String {
    if v == 0.0 {
        return "0".to_string();
    }
    let magnitude = v.abs().log10().floor() as usize + 1;
    let decimals = 17usize.saturating_sub(magnitude);
    let s = format!("{:.prec$}", v, prec = decimals);
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

/// Table data/DDL commands that tolerate a trailing `;` statement terminator.
fn is_table_terminator_command(cmd: &[u8]) -> bool {
    const TABLE_CMDS: &[&[u8]] = &[
        b"TSELECT",
        b"TINSERT",
        b"TUPSERT",
        b"TUPDATE",
        b"TDELETE",
        b"TCREATE",
        b"TDROP",
        b"TINDEX",
        b"TDROPINDEX",
        b"TCOUNT",
        b"TSCHEMA",
        b"TALTER",
        b"TLIST",
        b"GRANT",
        b"REVOKE",
    ];
    TABLE_CMDS.iter().any(|c| cmd_eq(cmd, c))
}

/// Drop a trailing `;` statement terminator from a table-command argv: either a
/// standalone `;` token or a `;` suffix on the final token. Borrows the original
/// bytes (no copy of token contents). Quoted values are unaffected because their
/// final byte is the closing quote, not `;`.
fn strip_trailing_terminator<'a>(args: &[&'a [u8]]) -> Vec<&'a [u8]> {
    match args.split_last() {
        Some((last, head)) if **last == *b";" => head.to_vec(),
        Some((last, head)) if last.last() == Some(&b';') => {
            let mut v = head.to_vec();
            let trimmed: &'a [u8] = &last[..last.len() - 1];
            if !trimmed.is_empty() {
                v.push(trimmed);
            }
            v
        }
        _ => args.to_vec(),
    }
}

pub fn execute(
    store: &Store,
    cache: &SharedSchemaCache,
    broker: &Broker,
    args: &[&[u8]],
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.is_empty() {
        resp::write_error(out, "ERR no command");
        return CmdResult::Written;
    }

    let cmd = args[0];

    // Tolerate a trailing `;` statement terminator on table commands, so SQL-style
    // statements pasted into the console or written across lines in a migration
    // file work (`TSELECT ... FROM t;`). RESP/argv clients never include one; this
    // only normalizes the text frontends that tokenize a raw line. Scoped to table
    // commands so KV value semantics (`SET k v;`) are untouched. Only allocates
    // when a terminator is actually present.
    let stripped_args;
    let args: &[&[u8]] = if is_table_terminator_command(cmd)
        && args.last().is_some_and(|t| t.last() == Some(&b';'))
    {
        stripped_args = strip_trailing_terminator(args);
        &stripped_args
    } else {
        args
    };

    if cmd_eq(cmd, b"AUTH") {
        return server::cmd_auth(args, store, out, now);
    }

    // Reserve the internal table-storage namespace ("_t:") from direct command
    // access. Table + Lux Auth data lives under `_t:<table>:...` keys; the table
    // API and internal ops reach them through the store directly, never through
    // command dispatch, so rejecting `_t:` args here closes the raw-KV bypass of
    // the reserved-table guard without touching tables/auth. (KEYS/SCAN take a
    // pattern and are filtered in their handlers instead.) Tradeoff: user values
    // cannot start with the 3-char reserved prefix `_t:`.
    if !cmd_eq(cmd, b"KEYS") && !cmd_eq(cmd, b"SCAN") {
        for arg in &args[1..] {
            if arg.starts_with(b"_t:") {
                resp::write_error(out, "ERR '_t:' is a reserved internal namespace");
                return CmdResult::Written;
            }
        }
    }

    if (cmd_eq(cmd, b"KEYS")
        || cmd_eq(cmd, b"FLUSHALL")
        || cmd_eq(cmd, b"FLUSHDB")
        || cmd_eq(cmd, b"DEBUG"))
        && is_restricted(store)
    {
        resp::write_error(out, "ERR command disabled in restricted mode");
        return CmdResult::Written;
    }

    if args.len() > 1 {
        store.try_promote(args[1], now);
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
        b'A' if cmd_eq(cmd, b"APPEND") => {
            return strings::cmd_append(args, store, out, now);
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
            if cmd_eq(cmd, b"GRANT") {
                return tables::cmd_grant(args, store, cache, out, now);
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
                return server::cmd_info(args, store, broker, out, now);
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
                return lists::cmd_lpush(args, store, broker, out, now);
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
        b'O' if cmd_eq(cmd, b"OBJECT") => {
            return keys::cmd_object(args, store, out, now);
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
        b'Q' if cmd_eq(cmd, b"QUIT") => {
            return server::cmd_quit(args, store, out, now);
        }
        b'R' => {
            if cmd_eq(cmd, b"RPUSH") {
                return lists::cmd_rpush(args, store, broker, out, now);
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
            if cmd_eq(cmd, b"REVOKE") {
                return tables::cmd_revoke(args, store, cache, out, now);
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
                return tables::cmd_tcreate(args, store, cache, out, now);
            }
            if cmd_eq(cmd, b"TINSERT") {
                return tables::cmd_tinsert(args, store, cache, out, now);
            }
            if cmd_eq(cmd, b"TUPSERT") {
                return tables::cmd_tupsert(args, store, cache, out, now);
            }
            if cmd_eq(cmd, b"TUPDATE") {
                return tables::cmd_tupdate(args, store, cache, out, now);
            }
            if cmd_eq(cmd, b"TDELETE") {
                return tables::cmd_tdelete(args, store, cache, out, now);
            }
            if cmd_eq(cmd, b"TDROP") {
                return tables::cmd_tdrop(args, store, cache, out, now);
            }
            if cmd_eq(cmd, b"TINDEX") {
                return tables::cmd_tindex(args, store, cache, out, now);
            }
            if cmd_eq(cmd, b"TDROPINDEX") {
                return tables::cmd_tdropindex(args, store, cache, out, now);
            }
            if cmd_eq(cmd, b"TCOUNT") {
                return tables::cmd_tcount(args, store, cache, out, now);
            }
            if cmd_eq(cmd, b"TSCHEMA") {
                return tables::cmd_tschema(args, store, cache, out, now);
            }
            if cmd_eq(cmd, b"TALTER") {
                return tables::cmd_talter(args, store, cache, out, now);
            }
            if cmd_eq(cmd, b"TLIST") {
                return tables::cmd_tlist(args, store, out, now);
            }
            if cmd_eq(cmd, b"TSELECT") {
                return tables::cmd_tselect(args, store, cache, out, now);
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
                return streams::cmd_xadd(args, store, broker, out, now);
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

pub fn execute_with_wal(
    store: &Store,
    cache: &SharedSchemaCache,
    broker: &Broker,
    args: &[&[u8]],
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if !args.is_empty() && crate::eviction::is_write_command(args[0]) {
        if let Some(err) = crate::auth::reserved_table_mutation_error(args, store) {
            resp::write_error(out, &err);
            return CmdResult::Written;
        }
        if let Some(err) = crate::auth::reserved_key_mutation_error(args, store) {
            resp::write_error(out, &err);
            return CmdResult::Written;
        }
        if let Err(e) = store.wal_log_command(args) {
            resp::write_error(out, &format!("ERR WAL append failed: {e}"));
            return CmdResult::Written;
        }
    }
    execute(store, cache, broker, args, out, now)
}

#[allow(dead_code)]
pub(crate) type ShardData = crate::store::ShardData;

#[allow(dead_code)]
pub(crate) fn execute_on_shard(
    shard: &mut crate::store::Shard,
    store: &Store,
    broker: &Broker,
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
    let ks = key;

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
                let exists = Store::get_from_shard(&shard.data, key, now).is_some();
                if !exists {
                    store.set_on_shard(&mut shard.data, key, args[2], None, now);
                    resp::write_ok(out);
                } else {
                    resp::write_null(out);
                }
            } else if xx {
                let exists = Store::get_from_shard(&shard.data, key, now).is_some();
                if exists {
                    store.set_on_shard(&mut shard.data, key, args[2], ttl, now);
                    resp::write_ok(out);
                } else {
                    resp::write_null(out);
                }
            } else {
                store.set_on_shard(&mut shard.data, key, args[2], ttl, now);
                resp::write_ok(out);
            }
        }
    } else if cmd_eq(cmd, b"GET") {
        Store::get_and_write(&shard.data, key, now, out);
    } else if cmd_eq(cmd, b"GETSET") && args.len() >= 3 {
        let old = store.get_set_on_shard(&mut shard.data, key, args[2], now);
        resp::write_optional_bulk_raw(out, &old);
    } else if cmd_eq(cmd, b"SETNX") && args.len() >= 3 {
        let changed = store.set_nx_on_shard(&mut shard.data, key, args[2], now);
        resp::write_integer(out, i64::from(changed));
    } else if cmd_eq(cmd, b"SETEX") && args.len() >= 4 {
        match parse_i64(args[2]) {
            Ok(secs) if secs <= 0 => {
                resp::write_error(out, "ERR invalid expire time in 'setex' command")
            }
            Ok(secs) => {
                store.set_on_shard(
                    &mut shard.data,
                    key,
                    args[3],
                    Some(std::time::Duration::from_secs(secs as u64)),
                    now,
                );
                resp::write_ok(out);
            }
            Err(_) => resp::write_error(out, "ERR value is not an integer or out of range"),
        }
    } else if cmd_eq(cmd, b"PSETEX") && args.len() >= 4 {
        match parse_u64(args[2]) {
            Ok(ms) => {
                store.set_on_shard(
                    &mut shard.data,
                    key,
                    args[3],
                    Some(std::time::Duration::from_millis(ms)),
                    now,
                );
                resp::write_ok(out);
            }
            Err(_) => resp::write_error(out, "ERR value is not an integer or out of range"),
        }
    } else if cmd_eq(cmd, b"APPEND") && args.len() >= 3 {
        resp::write_integer(out, store.append_on_shard(shard, key, args[2], now));
    } else if cmd_eq(cmd, b"EXPIRE") && args.len() >= 3 {
        match parse_u64(args[2]) {
            Ok(secs) => match shard.data.get_mut(ks) {
                Some(entry) if !entry.is_expired_at(now) => {
                    entry.expires_at = Some(now + std::time::Duration::from_secs(secs));
                    resp::write_integer(out, 1);
                }
                _ => resp::write_integer(out, 0),
            },
            Err(_) => resp::write_error(out, "ERR value is not an integer or out of range"),
        }
    } else if cmd_eq(cmd, b"PERSIST") {
        match shard.data.get_mut(ks) {
            Some(entry) if !entry.is_expired_at(now) && entry.expires_at.is_some() => {
                entry.expires_at = None;
                resp::write_integer(out, 1);
            }
            _ => resp::write_integer(out, 0),
        }
    } else if cmd_eq(cmd, b"INCR") {
        shard_incr_fast(&mut shard.data, key, 1, store.lru_clock(), now, out);
    } else if cmd_eq(cmd, b"DECR") {
        shard_incr_fast(&mut shard.data, key, -1, store.lru_clock(), now, out);
    } else if cmd_eq(cmd, b"INCRBY") && args.len() >= 3 {
        match parse_i64(args[2]) {
            Ok(delta) => shard_incr_fast(&mut shard.data, key, delta, store.lru_clock(), now, out),
            Err(_) => resp::write_error(out, "ERR value is not an integer or out of range"),
        }
    } else if cmd_eq(cmd, b"DECRBY") && args.len() >= 3 {
        match parse_i64(args[2]) {
            Ok(delta) => shard_incr_fast(&mut shard.data, key, -delta, store.lru_clock(), now, out),
            Err(_) => resp::write_error(out, "ERR value is not an integer or out of range"),
        }
    } else if cmd_eq(cmd, b"LPUSH") && args.len() >= 3 {
        shard_list_push_fast(
            &mut shard.data,
            key,
            &args[2..],
            true,
            store.lru_clock(),
            now,
            out,
        );
    } else if cmd_eq(cmd, b"RPUSH") && args.len() >= 3 {
        shard_list_push_fast(
            &mut shard.data,
            key,
            &args[2..],
            false,
            store.lru_clock(),
            now,
            out,
        );
    } else if cmd_eq(cmd, b"LPOP") && args.len() == 2 {
        let value = store.lpop_on_shard(shard, key, now);
        resp::write_optional_bulk_raw(out, &value);
    } else if cmd_eq(cmd, b"RPOP") && args.len() == 2 {
        let value = store.rpop_on_shard(shard, key, now);
        resp::write_optional_bulk_raw(out, &value);
    } else if cmd_eq(cmd, b"SADD") && args.len() >= 3 {
        shard_sadd_fast(
            &mut shard.data,
            key,
            &args[2..],
            store.lru_clock(),
            now,
            out,
        );
    } else if cmd_eq(cmd, b"HSET") && args.len() >= 4 {
        if !args[2..].len().is_multiple_of(2) {
            resp::write_error(out, "ERR wrong number of arguments for 'hset' command");
        } else if args.len() == 4 {
            shard_hset_one_fast(shard, store, key, args[2], args[3], now, out);
        } else {
            let pairs = args[2..]
                .chunks_exact(2)
                .map(|pair| (pair[0], pair[1]))
                .collect::<Vec<_>>();
            write_int_result(out, store.hset_on_shard(shard, key, &pairs, now));
        }
    } else if cmd_eq(cmd, b"HINCRBY") && args.len() >= 4 {
        match parse_i64(args[3]) {
            Ok(delta) => {
                write_int_result(out, store.hincrby_on_shard(shard, key, args[2], delta, now))
            }
            Err(_) => resp::write_error(out, "ERR value is not an integer or out of range"),
        }
    } else if cmd_eq(cmd, b"SREM") && args.len() >= 3 {
        shard_srem(&mut shard.data, key, &args[2..], now, out);
    } else if cmd_eq(cmd, b"SPOP") {
        let count = if args.len() > 2 {
            parse_u64(args[2]).unwrap_or(1) as usize
        } else {
            1
        };
        match store.spop_on_shard(shard, key, count, now) {
            Ok(result) if args.len() > 2 => {
                resp::write_array_header(out, result.len());
                for member in result {
                    resp::write_bulk(out, &member);
                }
            }
            Ok(mut result) => match result.pop() {
                Some(member) => resp::write_bulk(out, &member),
                None => resp::write_null(out),
            },
            Err(e) => resp::write_error(out, &e),
        }
    } else if cmd_eq(cmd, b"HDEL") && args.len() >= 3 {
        shard_hdel(&mut shard.data, key, &args[2..], now, out);
    } else if cmd_eq(cmd, b"ZADD") && args.len() >= 4 {
        shard_zadd(shard, store, key, &args[2..], now, out);
    } else if cmd_eq(cmd, b"ZINCRBY") && args.len() == 4 {
        match arg_str(args[2]).parse::<f64>() {
            Ok(increment) if !increment.is_nan() => {
                match store.zincrby_on_shard(shard, key, args[3], increment, now) {
                    Ok(score) => resp::write_bulk(out, &format_float(score)),
                    Err(e) => resp::write_error(out, &e),
                }
            }
            _ => resp::write_error(out, "ERR value is not a valid float"),
        }
    } else if cmd_eq(cmd, b"ZREM") && args.len() >= 3 {
        shard_zrem(&mut shard.data, key, &args[2..], now, out);
    } else if cmd_eq(cmd, b"ZPOPMIN") {
        let count = if args.len() > 2 {
            parse_u64(args[2]).unwrap_or(1) as usize
        } else {
            1
        };
        shard_zpop(&mut shard.data, key, count, true, now, out);
    } else if cmd_eq(cmd, b"ZPOPMAX") {
        let count = if args.len() > 2 {
            parse_u64(args[2]).unwrap_or(1) as usize
        } else {
            1
        };
        shard_zpop(&mut shard.data, key, count, false, now, out);
    } else if cmd_eq(cmd, b"XADD") {
        shard_xadd(shard, store, broker, key, &args[2..], now, out);
    } else if cmd_eq(cmd, b"GEOADD") {
        if args.len() < 5 {
            resp::write_error(out, "ERR wrong number of arguments for 'geoadd' command");
            return;
        }
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
            return;
        }
        let remaining = args.len() - i;
        if remaining < 3 || !remaining.is_multiple_of(3) {
            resp::write_error(out, "ERR syntax error");
            return;
        }
        if remaining == 3 {
            let lon: f64 = match arg_str(args[i]).parse() {
                Ok(v) => v,
                Err(_) => {
                    resp::write_error(out, "ERR value is not a valid float");
                    return;
                }
            };
            let lat: f64 = match arg_str(args[i + 1]).parse() {
                Ok(v) => v,
                Err(_) => {
                    resp::write_error(out, "ERR value is not a valid float");
                    return;
                }
            };
            if let Err(e) = crate::geo::validate_coords(lon, lat) {
                resp::write_error(out, &e);
                return;
            }
            let single = [(args[i + 2], crate::geo::geohash_encode(lon, lat) as f64)];
            match store.zadd_on_shard(shard, key, &single, nx, xx, false, false, ch, now) {
                Ok(n) => resp::write_integer(out, n),
                Err(e) => resp::write_error(out, &e),
            }
        } else {
            let mut members: Vec<(&[u8], f64)> = Vec::new();
            while i + 2 < args.len() {
                let lon: f64 = match arg_str(args[i]).parse() {
                    Ok(v) => v,
                    Err(_) => {
                        resp::write_error(out, "ERR value is not a valid float");
                        return;
                    }
                };
                let lat: f64 = match arg_str(args[i + 1]).parse() {
                    Ok(v) => v,
                    Err(_) => {
                        resp::write_error(out, "ERR value is not a valid float");
                        return;
                    }
                };
                if let Err(e) = crate::geo::validate_coords(lon, lat) {
                    resp::write_error(out, &e);
                    return;
                }
                members.push((args[i + 2], crate::geo::geohash_encode(lon, lat) as f64));
                i += 3;
            }
            match store.zadd_on_shard(shard, key, &members, nx, xx, false, false, ch, now) {
                Ok(n) => resp::write_integer(out, n),
                Err(e) => resp::write_error(out, &e),
            }
        }
    } else {
        resp::write_error(
            out,
            &format!("ERR unoptimized command in shard batch '{}'", arg_str(cmd)),
        );
    }
}

#[allow(dead_code)]
pub(crate) fn execute_on_shard_read(
    data: &ShardData,
    args: &[&[u8]],
    out: &mut BytesMut,
    now: Instant,
) {
    if args.is_empty() || args.len() < 2 {
        resp::write_error(out, "ERR no command");
        return;
    }
    let cmd = args[0];
    let key = args[1];
    let ks = key;

    if cmd[0].eq_ignore_ascii_case(&b'Z') {
        if cmd_eq(cmd, b"ZCARD") {
            match data.get(ks) {
                Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                    StoreValue::SortedSet(_, scores) => {
                        resp::write_integer(out, scores.len() as i64)
                    }
                    _ => resp::write_error(
                        out,
                        "WRONGTYPE Operation against a key holding the wrong kind of value",
                    ),
                },
                _ => resp::write_integer(out, 0),
            }
            return;
        }
        if cmd_eq(cmd, b"ZCOUNT") && args.len() >= 4 {
            let (min, min_ex) = parse_score_bound_fast(arg_str(args[2]), false);
            let (max, max_ex) = parse_score_bound_fast(arg_str(args[3]), true);
            match data.get(ks) {
                Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                    StoreValue::SortedSet(_, scores) => {
                        let mut count = 0i64;
                        for score in scores.values() {
                            let ge_min = if min_ex { *score > min } else { *score >= min };
                            let le_max = if max_ex { *score < max } else { *score <= max };
                            if ge_min && le_max {
                                count += 1;
                            }
                        }
                        resp::write_integer(out, count);
                    }
                    _ => resp::write_error(
                        out,
                        "WRONGTYPE Operation against a key holding the wrong kind of value",
                    ),
                },
                _ => resp::write_integer(out, 0),
            }
            return;
        }
        if cmd_eq(cmd, b"ZSCORE") && args.len() >= 3 {
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
            return;
        }
    }

    if cmd_eq(cmd, b"GET") {
        Store::get_and_write(data, key, now, out);
    } else if cmd_eq(cmd, b"EXISTS") {
        resp::write_integer(out, i64::from(Store::exists_on_shard(data, key, now)));
    } else if cmd_eq(cmd, b"STRLEN") {
        match data.get(ks) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Str(s) => resp::write_integer(out, s.len() as i64),
                StoreValue::StrBuf(s) => resp::write_integer(out, s.len() as i64),
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
    } else if cmd_eq(cmd, b"LINDEX") && args.len() >= 3 {
        match parse_i64(args[2]) {
            Ok(index) => match data.get(ks) {
                Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                    StoreValue::List(list) => {
                        let i = if index < 0 {
                            (list.len() as i64 + index) as usize
                        } else {
                            index as usize
                        };
                        resp::write_optional_bulk_raw(out, &list.get(i).cloned());
                    }
                    _ => resp::write_null(out),
                },
                _ => resp::write_null(out),
            },
            Err(_) => resp::write_error(out, "ERR value is not an integer or out of range"),
        }
    } else if cmd_eq(cmd, b"LRANGE") && args.len() >= 4 {
        let start = match parse_i64(args[2]) {
            Ok(v) => v,
            Err(_) => {
                resp::write_error(out, "ERR value is not an integer or out of range");
                return;
            }
        };
        let stop = match parse_i64(args[3]) {
            Ok(v) => v,
            Err(_) => {
                resp::write_error(out, "ERR value is not an integer or out of range");
                return;
            }
        };
        match data.get(ks) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::List(list) => {
                    let len = list.len() as i64;
                    let s = if start < 0 {
                        (len + start).max(0) as usize
                    } else {
                        start.min(len) as usize
                    };
                    let e = if stop < 0 {
                        (len + stop + 1).max(0) as usize
                    } else {
                        (stop + 1).min(len) as usize
                    };
                    if s >= e {
                        resp::write_array_header(out, 0);
                    } else {
                        resp::write_array_header(out, e - s);
                        for idx in s..e {
                            if let Some(value) = list.get(idx) {
                                resp::write_bulk_raw(out, value);
                            }
                        }
                    }
                }
                _ => resp::write_error(
                    out,
                    "WRONGTYPE Operation against a key holding the wrong kind of value",
                ),
            },
            _ => resp::write_array_header(out, 0),
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
    } else if cmd_eq(cmd, b"SMEMBERS") {
        match data.get(ks) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Set(set) => {
                    resp::write_array_header(out, set.len());
                    for member in set.iter() {
                        resp::write_bulk(out, member);
                    }
                }
                _ => resp::write_error(
                    out,
                    "WRONGTYPE Operation against a key holding the wrong kind of value",
                ),
            },
            _ => resp::write_array_header(out, 0),
        }
    } else if cmd_eq(cmd, b"HGET") && args.len() >= 3 {
        match data.get(ks) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Hash(map) => match map.get(arg_str(args[2])) {
                    Some(value) => resp::write_bulk_raw(out, value),
                    None => resp::write_null(out),
                },
                _ => resp::write_null(out),
            },
            _ => resp::write_null(out),
        }
    } else if cmd_eq(cmd, b"HMGET") && args.len() >= 3 {
        resp::write_array_header(out, args.len() - 2);
        match data.get(ks) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Hash(map) => {
                    for field in &args[2..] {
                        resp::write_optional_bulk_raw(out, &map.get(arg_str(field)).cloned());
                    }
                }
                _ => {
                    for _ in &args[2..] {
                        resp::write_null(out);
                    }
                }
            },
            _ => {
                for _ in &args[2..] {
                    resp::write_null(out);
                }
            }
        }
    } else if cmd_eq(cmd, b"HEXISTS") && args.len() >= 3 {
        match data.get(ks) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Hash(map) => resp::write_integer(
                    out,
                    if map.contains_key(arg_str(args[2])) {
                        1
                    } else {
                        0
                    },
                ),
                _ => resp::write_error(
                    out,
                    "WRONGTYPE Operation against a key holding the wrong kind of value",
                ),
            },
            _ => resp::write_integer(out, 0),
        }
    } else if cmd_eq(cmd, b"HGETALL") {
        match data.get(ks) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Hash(map) => {
                    resp::write_array_header(out, map.len() * 2);
                    for (field, value) in map {
                        resp::write_bulk(out, field);
                        resp::write_bulk_raw(out, value);
                    }
                }
                _ => resp::write_error(
                    out,
                    "WRONGTYPE Operation against a key holding the wrong kind of value",
                ),
            },
            _ => resp::write_array_header(out, 0),
        }
    } else if cmd_eq(cmd, b"SISMEMBER") && args.len() >= 3 {
        match data.get(ks) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Set(set) => {
                    resp::write_integer(out, if set.contains(arg_str(args[2])) { 1 } else { 0 })
                }
                _ => resp::write_error(
                    out,
                    "WRONGTYPE Operation against a key holding the wrong kind of value",
                ),
            },
            _ => resp::write_integer(out, 0),
        }
    } else if cmd_eq(cmd, b"SRANDMEMBER") {
        match data.get(ks) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Set(set) => match set.iter().next() {
                    Some(member) => resp::write_bulk(out, member),
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
    } else if cmd_eq(cmd, b"GEODIST") && (args.len() == 4 || args.len() == 5) {
        let unit = if args.len() == 5 {
            match crate::geo::DistUnit::parse(arg_str(args[4])) {
                Some(u) => u,
                None => {
                    resp::write_error(
                        out,
                        "ERR unsupported unit provided. please use M, KM, FT, MI",
                    );
                    return;
                }
            }
        } else {
            crate::geo::DistUnit::M
        };
        match data.get(ks) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::SortedSet(_, scores) => {
                    let s1 = match scores.get(arg_str(args[2])) {
                        Some(s) => *s,
                        None => {
                            resp::write_null(out);
                            return;
                        }
                    };
                    let s2 = match scores.get(arg_str(args[3])) {
                        Some(s) => *s,
                        None => {
                            resp::write_null(out);
                            return;
                        }
                    };
                    let (lon1, lat1) = crate::geo::geohash_decode(s1 as u64);
                    let (lon2, lat2) = crate::geo::geohash_decode(s2 as u64);
                    let dist = unit.from_meters(crate::geo::haversine(lon1, lat1, lon2, lat2));
                    resp::write_bulk(out, &format!("{:.4}", dist));
                }
                _ => resp::write_error(
                    out,
                    "WRONGTYPE Operation against a key holding the wrong kind of value",
                ),
            },
            _ => resp::write_null(out),
        }
    } else if cmd_eq(cmd, b"GEOPOS") && args.len() >= 2 {
        let members = args.get(2..).unwrap_or(&[]);
        resp::write_array_header(out, members.len());
        match data.get(ks) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::SortedSet(_, scores) => {
                    for member in members {
                        match scores.get(arg_str(member)) {
                            Some(score) => {
                                let (lon, lat) = crate::geo::geohash_decode(*score as u64);
                                resp::write_array_header(out, 2);
                                resp::write_bulk(out, &format_geo_coord(lon));
                                resp::write_bulk(out, &format_geo_coord(lat));
                            }
                            None => resp::write_null_array(out),
                        }
                    }
                }
                _ => resp::write_error(
                    out,
                    "WRONGTYPE Operation against a key holding the wrong kind of value",
                ),
            },
            _ => {
                for _ in members {
                    resp::write_null_array(out);
                }
            }
        }
    } else if cmd_eq(cmd, b"XLEN") {
        match data.get(ks) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Stream(stream) => resp::write_integer(out, stream.entries.len() as i64),
                _ => resp::write_error(
                    out,
                    "WRONGTYPE Operation against a key holding the wrong kind of value",
                ),
            },
            _ => resp::write_integer(out, 0),
        }
    } else if cmd_eq(cmd, b"XRANGE") && args.len() >= 4 {
        let start = if arg_str(args[2]) == "-" {
            StreamId { ms: 0, seq: 0 }
        } else {
            StreamId::parse(arg_str(args[2])).unwrap_or(StreamId { ms: 0, seq: 0 })
        };
        let end = if arg_str(args[3]) == "+" {
            StreamId {
                ms: u64::MAX,
                seq: u64::MAX,
            }
        } else {
            StreamId::parse(arg_str(args[3])).unwrap_or(StreamId {
                ms: u64::MAX,
                seq: u64::MAX,
            })
        };
        let count = if args.len() > 5 && cmd_eq(args[4], b"COUNT") {
            parse_u64(args[5]).ok().map(|n| n as usize)
        } else {
            None
        };
        match data.get(ks) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Stream(stream) => {
                    write_stream_entries_fast(out, &stream.entries, start, end, count)
                }
                _ => resp::write_error(
                    out,
                    "WRONGTYPE Operation against a key holding the wrong kind of value",
                ),
            },
            _ => resp::write_array_header(out, 0),
        }
    } else {
        resp::write_error(out, &format!("ERR unknown command '{}'", arg_str(cmd)));
    }
}

#[allow(dead_code)]
fn write_int_result(out: &mut BytesMut, result: Result<i64, String>) {
    match result {
        Ok(value) => resp::write_integer(out, value),
        Err(error) => resp::write_error(out, &error),
    }
}

fn shard_incr_fast(
    data: &mut ShardData,
    key: &[u8],
    delta: i64,
    lru_clock: u32,
    now: Instant,
    out: &mut BytesMut,
) {
    let ks = key;
    if let Some(entry) = data.get_mut(ks) {
        if entry.is_expired_at(now) {
            match 0i64.checked_add(delta) {
                Some(new_val) => {
                    entry.value = StoreValue::Str(Bytes::from(new_val.to_string()));
                    entry.expires_at = None;
                    entry.lru_clock = lru_clock;
                    resp::write_integer(out, new_val);
                }
                None => resp::write_error(out, "ERR increment or decrement would overflow"),
            }
            return;
        }
        let current = match entry.value.string_bytes() {
            Some(bytes) => match std::str::from_utf8(bytes)
                .ok()
                .and_then(|s| s.parse::<i64>().ok())
            {
                Some(n) => n,
                None => {
                    resp::write_error(out, "ERR value is not an integer or out of range");
                    return;
                }
            },
            None => {
                resp::write_error(
                    out,
                    "WRONGTYPE Operation against a key holding the wrong kind of value",
                );
                return;
            }
        };
        match current.checked_add(delta) {
            Some(new_val) => {
                let expires_at = entry.expires_at;
                entry.value = StoreValue::Str(Bytes::from(new_val.to_string()));
                entry.expires_at = expires_at;
                entry.lru_clock = lru_clock;
                resp::write_integer(out, new_val);
            }
            None => resp::write_error(out, "ERR increment or decrement would overflow"),
        }
        return;
    }

    match 0i64.checked_add(delta) {
        Some(new_val) => {
            data.insert(
                ks.to_vec(),
                Entry {
                    value: StoreValue::Str(Bytes::from(new_val.to_string())),
                    expires_at: None,
                    lru_clock,
                },
            );
            resp::write_integer(out, new_val);
        }
        None => resp::write_error(out, "ERR increment or decrement would overflow"),
    }
}

fn shard_list_push_fast(
    data: &mut ShardData,
    key: &[u8],
    values: &[&[u8]],
    left: bool,
    lru_clock: u32,
    now: Instant,
    out: &mut BytesMut,
) {
    let ks = crate::store::key_bytes(key);
    let entry = data.entry(ks).or_insert_with(|| Entry {
        value: StoreValue::List(std::collections::VecDeque::new()),
        expires_at: None,
        lru_clock,
    });
    if entry.is_expired_at(now) {
        entry.value = StoreValue::List(std::collections::VecDeque::new());
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

fn shard_sadd_fast(
    data: &mut ShardData,
    key: &[u8],
    members: &[&[u8]],
    lru_clock: u32,
    now: Instant,
    out: &mut BytesMut,
) {
    let ks = crate::store::key_bytes(key);
    let entry = data.entry(ks).or_insert_with(|| Entry {
        value: StoreValue::Set(crate::store::SetData::new()),
        expires_at: None,
        lru_clock,
    });
    if entry.is_expired_at(now) {
        entry.value = StoreValue::Set(crate::store::SetData::new());
        entry.expires_at = None;
    }
    match &mut entry.value {
        StoreValue::Set(set) => {
            let mut added = 0i64;
            for m in members {
                if set.insert(arg_str(m).to_string()) {
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

fn shard_hset_one_fast(
    shard: &mut crate::store::Shard,
    store: &Store,
    key: &[u8],
    field: &[u8],
    value: &[u8],
    now: Instant,
    out: &mut BytesMut,
) {
    let pairs = [(field, value)];
    write_int_result(out, store.hset_on_shard(shard, key, &pairs, now));
}

#[allow(dead_code)]
fn shard_srem(
    data: &mut ShardData,
    key: &[u8],
    members: &[&[u8]],
    now: Instant,
    out: &mut BytesMut,
) {
    let ks = key;
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

#[allow(dead_code)]
fn shard_hdel(
    data: &mut ShardData,
    key: &[u8],
    fields: &[&[u8]],
    now: Instant,
    out: &mut BytesMut,
) {
    let ks = key;
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

#[allow(dead_code)]
fn shard_zadd(
    shard: &mut crate::store::Shard,
    store: &Store,
    key: &[u8],
    rest: &[&[u8]],
    now: Instant,
    out: &mut BytesMut,
) {
    if rest.len() == 2 {
        match arg_str(rest[0]).parse::<f64>() {
            Ok(score) if !score.is_nan() => {
                match store.zadd_single_default_on_shard(shard, key, rest[1], score, now) {
                    Ok(count) => resp::write_integer(out, count),
                    Err(error) => resp::write_error(out, &error),
                }
            }
            _ => resp::write_error(out, "ERR value is not a valid float"),
        }
        return;
    }

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
    if rest.len() - i == 2 {
        match arg_str(rest[i]).parse::<f64>() {
            Ok(score) => {
                let single = [(rest[i + 1], score)];
                match store.zadd_on_shard(shard, key, &single, nx, xx, gt, lt, ch, now) {
                    Ok(count) => resp::write_integer(out, count),
                    Err(error) => resp::write_error(out, &error),
                }
            }
            Err(_) => resp::write_error(out, "ERR value is not a valid float"),
        }
        return;
    }

    let mut members = Vec::with_capacity((rest.len() - i) / 2);
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

    match store.zadd_on_shard(shard, key, &members, nx, xx, gt, lt, ch, now) {
        Ok(count) => resp::write_integer(out, count),
        Err(error) => resp::write_error(out, &error),
    }
}

#[allow(dead_code)]
fn shard_zrem(
    data: &mut ShardData,
    key: &[u8],
    members: &[&[u8]],
    now: Instant,
    out: &mut BytesMut,
) {
    let ks = key;
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

#[allow(dead_code)]
fn shard_xadd(
    shard: &mut crate::store::Shard,
    store: &Store,
    broker: &Broker,
    key: &[u8],
    rest: &[&[u8]],
    now: Instant,
    out: &mut BytesMut,
) {
    let mut i = 0;
    let mut maxlen = None;
    while i < rest.len() {
        if cmd_eq(rest[i], b"MAXLEN") {
            i += 1;
            if i < rest.len() && rest[i] == b"~" {
                i += 1;
            }
            if i < rest.len() {
                maxlen = parse_u64(rest[i]).ok().map(|n| n as usize);
            }
            i += 1;
        } else if cmd_eq(rest[i], b"NOMKSTREAM") {
            i += 1;
        } else {
            break;
        }
    }
    if i >= rest.len() {
        resp::write_error(out, "ERR wrong number of arguments for 'xadd' command");
        return;
    }
    let id_input = arg_str(rest[i]);
    i += 1;
    if (rest.len() - i) < 2 || !(rest.len() - i).is_multiple_of(2) {
        resp::write_error(out, "ERR wrong number of arguments for 'xadd' command");
        return;
    }

    let mut fields = Vec::with_capacity((rest.len() - i) / 2);
    while i + 1 < rest.len() {
        fields.push((
            arg_str(rest[i]).to_string(),
            Bytes::copy_from_slice(rest[i + 1]),
        ));
        i += 2;
    }

    match store.xadd_on_shard(shard, key, id_input, fields, maxlen, now) {
        Ok(id) => {
            resp::write_bulk(out, &id.to_string());
            broker.wake_stream_waiters(arg_str(key));
        }
        Err(error) => resp::write_error(out, &error),
    }
}

#[allow(dead_code)]
fn shard_zpop(
    data: &mut ShardData,
    key: &[u8],
    count: usize,
    is_min: bool,
    now: Instant,
    out: &mut BytesMut,
) {
    let ks = key;
    match data.get_mut(ks) {
        Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
            StoreValue::SortedSet(tree, scores) => {
                if count == 1 {
                    let popped = if is_min {
                        tree.pop_first()
                    } else {
                        tree.pop_last()
                    };
                    if let Some(((score, member), _)) = popped {
                        scores.remove(&member);
                        resp::write_array_header(out, 2);
                        resp::write_bulk(out, &member);
                        resp::write_bulk(out, &format_float(score.0));
                    } else {
                        resp::write_array_header(out, 0);
                    }
                    return;
                }

                let mut result = Vec::with_capacity(count.min(tree.len()));
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

pub fn is_known_command(cmd: &[u8]) -> bool {
    command_spec(cmd).is_some()
}

pub fn validate_args(args: &[&[u8]]) -> Result<(), String> {
    if args.is_empty() {
        return Err("ERR no command".to_string());
    }
    let cmd = args[0];
    let Some(spec) = command_spec(cmd) else {
        return Ok(());
    };
    let min = spec.min_arity;
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
        let cache =
            std::sync::Arc::new(parking_lot::RwLock::new(crate::tables::SchemaCache::new()));
        let mut out = BytesMut::new();
        let now = Instant::now();
        execute(store, &cache, &broker, args, &mut out, now);
        out
    }

    fn exec_str(store: &Store, args: &[&[u8]]) -> String {
        String::from_utf8_lossy(&exec(store, args)).to_string()
    }

    #[test]
    fn strip_terminator_suffix_on_last_token() {
        let stripped = strip_trailing_terminator(&[b"TSELECT", b"*", b"FROM", b"workspaces;"]);
        assert_eq!(stripped.len(), 4);
        assert_eq!(stripped[3], b"workspaces".as_slice());
    }

    #[test]
    fn strip_terminator_standalone_token() {
        let stripped = strip_trailing_terminator(&[b"TSELECT", b"*", b"FROM", b"t", b";"]);
        assert_eq!(stripped.len(), 4);
        assert_eq!(stripped[3], b"t".as_slice());
    }

    #[test]
    fn strip_terminator_noop_without_terminator() {
        let stripped = strip_trailing_terminator(&[b"TSELECT", b"*", b"FROM", b"t"]);
        assert_eq!(stripped.len(), 4);
        assert_eq!(stripped[3], b"t".as_slice());
    }

    #[test]
    fn tselect_trailing_semicolon_not_in_table_name() {
        let store = Store::new();
        // The terminator must not leak into the table name lookup.
        let out = exec_str(&store, &[b"TSELECT", b"*", b"FROM", b"ghost;"]);
        assert!(out.contains("ghost"), "got: {out}");
        assert!(
            !out.contains("ghost;"),
            "terminator leaked into name: {out}"
        );
    }

    #[test]
    fn tselect_trailing_semicolon_succeeds_on_real_table() {
        let store = Store::new();
        exec(&store, &[b"TCREATE", b"widgets", b"id", b"int"]);
        let out = exec_str(&store, &[b"TSELECT", b"*", b"FROM", b"widgets;"]);
        assert!(!out.contains("does not exist"), "got: {out}");
        assert!(!out.to_lowercase().contains("err"), "got: {out}");
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
        let cfg = crate::ServerConfig {
            password: "secret123".to_string(),
            require_auth: true,
            ..Default::default()
        };
        let store = Store::new_with_config(std::sync::Arc::new(cfg));
        let out = exec_str(&store, &[b"AUTH", b"wrong"]);
        assert!(out.contains("WRONGPASS"));
    }

    #[test]
    fn getex_syntax_error() {
        let store = Store::new();
        let out = exec_str(&store, &[b"GETEX", b"key", b"BADOPT"]);
        assert!(out.contains("ERR syntax error"));
    }

    #[test]
    fn command_specs_cover_dispatched_commands() {
        for cmd in [
            b"GEOADD" as &[u8],
            b"GEODIST",
            b"GEOPOS",
            b"GEOHASH",
            b"GEOSEARCH",
            b"GEOSEARCHSTORE",
            b"GEORADIUS",
            b"GEORADIUSBYMEMBER",
            b"TSELECT",
            b"UNSUBSCRIBE",
            b"ZREVRANGE",
        ] {
            assert!(is_known_command(cmd), "missing command spec for {cmd:?}");
        }
    }

    #[test]
    fn validate_args_matches_supported_minimums() {
        assert!(validate_args(&[b"SUNION" as &[u8], b"key"]).is_ok());
        assert!(validate_args(&[b"SINTER" as &[u8], b"key"]).is_ok());
        assert!(validate_args(&[b"SDIFF" as &[u8], b"key"]).is_ok());
        assert!(validate_args(&[b"GETRANGE" as &[u8], b"key", b"0"]).is_err());
        assert!(validate_args(&[b"XRANGE" as &[u8], b"s", b"-"]).is_err());
        assert!(validate_args(&[b"XDEL" as &[u8], b"s"]).is_err());
        assert!(validate_args(&[b"GEOPOS" as &[u8], b"geo"]).is_err());
    }

    #[test]
    fn pipeline_access_requires_fast_path_safe_arity() {
        assert_eq!(
            pipeline_access_for_args(&[b"GET" as &[u8], b"k"]),
            PipelineAccess::Read
        );
        assert_eq!(
            pipeline_access_for_args(&[b"GET" as &[u8], b"k", b"extra"]),
            PipelineAccess::General
        );
        assert_eq!(
            pipeline_access_for_args(&[b"LRANGE" as &[u8], b"k"]),
            PipelineAccess::General
        );
        assert_eq!(
            pipeline_access_for_args(&[b"EXISTS" as &[u8], b"a", b"b"]),
            PipelineAccess::General
        );
        assert_eq!(
            pipeline_access_for_args(&[b"EXISTS" as &[u8], b"a"]),
            PipelineAccess::Read
        );
        assert_eq!(
            pipeline_access_for_args(&[b"SET" as &[u8], b"k", b"v"]),
            PipelineAccess::Write
        );
        assert_eq!(
            pipeline_access_for_args(&[b"SET" as &[u8], b"k", b"v", b"NX"]),
            PipelineAccess::Write
        );
        assert_eq!(
            pipeline_access_for_args(&[b"SET" as &[u8], b"k", b"v", b"BAD"]),
            PipelineAccess::General
        );
        assert_eq!(
            pipeline_access_for_args(&[b"SET" as &[u8], b"k", b"v", b"EX", b"10"]),
            PipelineAccess::General
        );
        assert_eq!(
            pipeline_access_for_args(&[b"SETEX" as &[u8], b"k", b"10", b"v"]),
            PipelineAccess::General
        );
        assert_eq!(
            pipeline_access_for_args(&[b"PSETEX" as &[u8], b"k", b"10", b"v"]),
            PipelineAccess::General
        );
        assert_eq!(
            pipeline_access_for_args(&[b"SPOP" as &[u8], b"k"]),
            PipelineAccess::Write
        );
        assert_eq!(
            pipeline_access_for_args(&[b"SPOP" as &[u8], b"k", b"2"]),
            PipelineAccess::General
        );
        assert_eq!(
            pipeline_access_for_args(&[b"ZPOPMIN" as &[u8], b"k"]),
            PipelineAccess::Write
        );
        assert_eq!(
            pipeline_access_for_args(&[b"ZPOPMIN" as &[u8], b"k", b"2"]),
            PipelineAccess::General
        );
    }

    #[test]
    fn geo_member_commands_require_a_member() {
        let store = Store::new();
        let geopos = exec_str(&store, &[b"GEOPOS", b"geo"]);
        assert!(geopos.contains("ERR wrong number of arguments"));
        let geohash = exec_str(&store, &[b"GEOHASH", b"geo"]);
        assert!(geohash.contains("ERR wrong number of arguments"));
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
        assert!(
            out.contains("tracked_key_count:"),
            "contains tracked key count: {out}"
        );
        assert!(
            out.contains("tracked_total_key_count:"),
            "contains tracked total key count: {out}"
        );
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
