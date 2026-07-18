use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Status {
    Supported,
    Partial,
    Missing,
    Excluded,
    LuxNative,
}

#[derive(Debug, Clone, Copy)]
struct CommandInventory {
    command: &'static str,
    status: Status,
    note: &'static str,
}

const INVENTORY: &[CommandInventory] = &[
    supported("APPEND"),
    missing("ACL", "Lux auth/grants are not Redis ACLs"),
    excluded("ASKING", "cluster mode is out of scope"),
    supported("AUTH"),
    missing("BGREWRITEAOF", "Lux uses snapshot + WAL, not Redis AOF"),
    supported("BGSAVE"),
    supported("BITFIELD"),
    supported("BITFIELD_RO"),
    supported("BITCOUNT"),
    supported("BITOP"),
    supported("BITPOS"),
    supported("BLMOVE"),
    supported("BLPOP"),
    supported("BLMPOP"),
    supported("BRPOP"),
    supported("BRPOPLPUSH"),
    supported("BZPOPMAX"),
    supported("BZPOPMIN"),
    supported("BZMPOP"),
    partial("CLIENT", "compatibility gap"),
    excluded("CLUSTER", "cluster mode is out of scope"),
    partial("COMMAND", "compatibility gap"),
    partial("CONFIG", "compatibility gap"),
    supported("COPY"),
    supported("DBSIZE"),
    partial("DEBUG", "compatibility stub needing audit"),
    supported("DECR"),
    supported("DECRBY"),
    supported("DEL"),
    supported("DISCARD"),
    partial(
        "DUMP",
        "Lux-internal serialization; not RDB-compatible, round-trips within Lux",
    ),
    supported("ECHO"),
    supported("EVAL"),
    missing("EVAL_RO", "compatibility gap"),
    supported("EVALSHA"),
    missing("EVALSHA_RO", "compatibility gap"),
    supported("EXEC"),
    supported("EXISTS"),
    supported("EXPIRE"),
    supported("EXPIREAT"),
    supported("EXPIRETIME"),
    excluded("FAILOVER", "replication/failover is out of scope"),
    missing("FCALL", "compatibility gap"),
    missing("FCALL_RO", "compatibility gap"),
    supported("FLUSHALL"),
    supported("FLUSHDB"),
    partial("FUNCTION", "compatibility gap"),
    supported("GEOADD"),
    supported("GEODIST"),
    supported("GEOHASH"),
    supported("GEOPOS"),
    supported("GEORADIUS"),
    supported("GEORADIUS_RO"),
    supported("GEORADIUSBYMEMBER"),
    supported("GEORADIUSBYMEMBER_RO"),
    supported("GEOSEARCH"),
    supported("GEOSEARCH_RO"),
    supported("GEOSEARCHSTORE"),
    supported("GET"),
    supported("GETBIT"),
    supported("GETDEL"),
    supported("GETEX"),
    supported("GETRANGE"),
    supported("GETSET"),
    supported("HDEL"),
    partial("HELLO", "RESP3 negotiation decision pending"),
    supported("HEXISTS"),
    supported("HEXPIRE"),
    supported("HEXPIREAT"),
    supported("HEXPIRETIME"),
    supported("HGET"),
    supported("HGETDEL"),
    supported("HGETEX"),
    supported("HGETALL"),
    supported("HINCRBY"),
    supported("HINCRBYFLOAT"),
    supported("HKEYS"),
    supported("HLEN"),
    supported("HMGET"),
    supported("HMSET"),
    supported("HPERSIST"),
    supported("HPEXPIRE"),
    supported("HPEXPIREAT"),
    supported("HPEXPIRETIME"),
    supported("HPTTL"),
    supported("HRANDFIELD"),
    supported("HSCAN"),
    supported("HSET"),
    supported("HSETNX"),
    supported("HSTRLEN"),
    supported("HTTL"),
    supported("HVALS"),
    supported("INCR"),
    supported("INCRBY"),
    supported("INCRBYFLOAT"),
    partial("INFO", "compatibility gap"),
    supported("KEYS"),
    partial("LATENCY", "compatibility gap"),
    supported("LASTSAVE"),
    supported("LCS"),
    supported("LINDEX"),
    supported("LINSERT"),
    supported("LLEN"),
    supported("LMOVE"),
    supported("LMPOP"),
    missing("LOLWUT", "not implemented; low-value diagnostics command"),
    supported("LPOP"),
    supported("LPOS"),
    supported("LPUSH"),
    supported("LPUSHX"),
    supported("LRANGE"),
    supported("LREM"),
    supported("LSET"),
    supported("LTRIM"),
    partial("MEMORY", "compatibility gap"),
    supported("MGET"),
    partial(
        "MIGRATE",
        "explicit unsupported error; no Redis inter-node key migration",
    ),
    excluded("MODULE", "Redis modules are out of scope"),
    missing("MONITOR", "compatibility gap"),
    missing("MOVE", "compatibility gap"),
    supported("MSET"),
    supported("MSETNX"),
    supported("MULTI"),
    partial("OBJECT", "compatibility gap"),
    supported("PERSIST"),
    supported("PEXPIRE"),
    supported("PEXPIREAT"),
    supported("PEXPIRETIME"),
    supported("PFADD"),
    supported("PFCOUNT"),
    supported("PFMERGE"),
    supported("PING"),
    supported("PSETEX"),
    supported("PSUBSCRIBE"),
    supported("PTTL"),
    supported("PUBSUB"),
    supported("PUBLISH"),
    supported("PUNSUBSCRIBE"),
    supported("QUIT"),
    supported("RANDOMKEY"),
    excluded("READONLY", "cluster mode is out of scope"),
    excluded("READWRITE", "cluster mode is out of scope"),
    supported("RENAME"),
    supported("RENAMENX"),
    excluded("REPLICAOF", "replication is out of scope"),
    partial("RESTORE", "accepts Lux DUMP format; not RDB-compatible"),
    partial("RESET", "compatibility gap"),
    missing("ROLE", "compatibility gap"),
    supported("RPOP"),
    supported("RPOPLPUSH"),
    supported("RPUSH"),
    supported("RPUSHX"),
    supported("SADD"),
    supported("SAVE"),
    supported("SCAN"),
    supported("SCARD"),
    supported("SCRIPT"),
    supported("SDIFF"),
    supported("SDIFFSTORE"),
    partial("SELECT", "multi-DB behavior decision pending"),
    supported("SET"),
    supported("SETBIT"),
    supported("SETEX"),
    supported("SETNX"),
    supported("SETRANGE"),
    excluded("SHUTDOWN", "process lifecycle command is out of scope"),
    supported("SINTER"),
    supported("SINTERCARD"),
    supported("SINTERSTORE"),
    supported("SISMEMBER"),
    excluded("SLAVEOF", "replication is out of scope"),
    missing("SLOWLOG", "compatibility gap"),
    supported("SMEMBERS"),
    supported("SMISMEMBER"),
    supported("SMOVE"),
    supported("SORT"),
    supported("SORT_RO"),
    supported("SPOP"),
    partial(
        "SPUBLISH",
        "explicit unsupported error; sharded pub/sub needs Redis Cluster",
    ),
    supported("SRANDMEMBER"),
    supported("SREM"),
    supported("SSCAN"),
    partial(
        "SSUBSCRIBE",
        "explicit unsupported error; sharded pub/sub needs Redis Cluster",
    ),
    supported("STRLEN"),
    supported("SUBSCRIBE"),
    supported("SUBSTR"),
    supported("SUNION"),
    supported("SUNIONSTORE"),
    partial(
        "SUNSUBSCRIBE",
        "explicit unsupported error; sharded pub/sub needs Redis Cluster",
    ),
    partial("SWAPDB", "compatibility gap"),
    supported("TIME"),
    partial(
        "TOUCH",
        "returns key count; does not update access recency/eviction",
    ),
    supported("TTL"),
    supported("TYPE"),
    supported("UNLINK"),
    supported("UNSUBSCRIBE"),
    supported("UNWATCH"),
    partial("WAIT", "compatibility gap"),
    partial(
        "WAITAOF",
        "explicit unsupported error; Lux uses WAL, not AOF",
    ),
    supported("WATCH"),
    supported("XACK"),
    supported("XADD"),
    supported("XAUTOCLAIM"),
    supported("XCLAIM"),
    supported("XDEL"),
    supported("XGROUP"),
    supported("XINFO"),
    supported("XLEN"),
    supported("XPENDING"),
    supported("XRANGE"),
    supported("XREAD"),
    supported("XREADGROUP"),
    supported("XREVRANGE"),
    missing("XSETID", "compatibility gap"),
    supported("XTRIM"),
    supported("ZADD"),
    supported("ZCARD"),
    supported("ZCOUNT"),
    supported("ZDIFF"),
    supported("ZDIFFSTORE"),
    supported("ZINCRBY"),
    supported("ZINTER"),
    supported("ZINTERCARD"),
    supported("ZINTERSTORE"),
    supported("ZLEXCOUNT"),
    supported("ZMPOP"),
    supported("ZMSCORE"),
    supported("ZPOPMAX"),
    supported("ZPOPMIN"),
    supported("ZRANDMEMBER"),
    supported("ZRANGE"),
    supported("ZRANGESTORE"),
    supported("ZRANGEBYLEX"),
    supported("ZRANGEBYSCORE"),
    supported("ZRANK"),
    supported("ZREM"),
    supported("ZREMRANGEBYLEX"),
    supported("ZREMRANGEBYRANK"),
    supported("ZREMRANGEBYSCORE"),
    supported("ZREVRANGE"),
    supported("ZREVRANGEBYLEX"),
    supported("ZREVRANGEBYSCORE"),
    supported("ZREVRANK"),
    supported("ZSCAN"),
    supported("ZSCORE"),
    supported("ZUNION"),
    supported("ZUNIONSTORE"),
    lux_native("DELIFEQ"),
    lux_native("ENC"),
    lux_native("GRANT"),
    lux_native("KSUB"),
    lux_native("KUNSUB"),
    lux_native("LUX"),
    lux_native("PFDEBUG"),
    lux_native("TALTER"),
    lux_native("TCOUNT"),
    lux_native("TCREATE"),
    lux_native("TDELETE"),
    lux_native("TDROP"),
    lux_native("TDROPINDEX"),
    lux_native("TGET"),
    lux_native("TINDEX"),
    lux_native("TINSERT"),
    lux_native("TLIST"),
    lux_native("TSCHEMA"),
    lux_native("TSELECT"),
    lux_native("TSET"),
    lux_native("TSADD"),
    lux_native("TSGET"),
    lux_native("TSINFO"),
    lux_native("TSMADD"),
    lux_native("TSMRANGE"),
    lux_native("TSRANGE"),
    lux_native("TUPDATE"),
    lux_native("TUPSERT"),
    lux_native("VCARD"),
    lux_native("VGET"),
    lux_native("VSEARCH"),
    lux_native("VSET"),
    lux_native("REVOKE"),
];

const fn supported(command: &'static str) -> CommandInventory {
    CommandInventory {
        command,
        status: Status::Supported,
        note: "",
    }
}

const fn partial(command: &'static str, note: &'static str) -> CommandInventory {
    CommandInventory {
        command,
        status: Status::Partial,
        note,
    }
}

const fn missing(command: &'static str, note: &'static str) -> CommandInventory {
    CommandInventory {
        command,
        status: Status::Missing,
        note,
    }
}

const fn excluded(command: &'static str, note: &'static str) -> CommandInventory {
    CommandInventory {
        command,
        status: Status::Excluded,
        note,
    }
}

const fn lux_native(command: &'static str) -> CommandInventory {
    CommandInventory {
        command,
        status: Status::LuxNative,
        note: "Lux-native command, not Redis OSS/core",
    }
}

fn registry_commands() -> BTreeSet<String> {
    let source = include_str!("../src/cmd/mod.rs");
    let mut commands = BTreeSet::new();
    for line in source.lines() {
        let Some(start) = line.find("name: b\"") else {
            continue;
        };
        let rest = &line[start + "name: b\"".len()..];
        let Some(end) = rest.find('"') else {
            continue;
        };
        commands.insert(rest[..end].to_string());
    }
    commands
}

fn inventory_by_command() -> BTreeMap<&'static str, CommandInventory> {
    let mut by_command = BTreeMap::new();
    for item in INVENTORY {
        assert!(
            by_command.insert(item.command, *item).is_none(),
            "duplicate inventory entry for {}",
            item.command
        );
    }
    by_command
}

#[test]
fn redis_core_inventory_covers_lux_registry() {
    let registry = registry_commands();
    let inventory = inventory_by_command();

    let unclassified: Vec<_> = registry
        .iter()
        .filter(|command| !inventory.contains_key(command.as_str()))
        .collect();
    assert!(
        unclassified.is_empty(),
        "registry commands missing inventory status: {unclassified:?}"
    );
}

#[test]
fn supported_and_partial_inventory_entries_exist_in_lux_registry() {
    let registry = registry_commands();
    let inventory = inventory_by_command();

    let stale: Vec<_> = inventory
        .values()
        .filter(|item| {
            matches!(
                item.status,
                Status::Supported | Status::Partial | Status::LuxNative
            )
        })
        .filter(|item| !registry.contains(item.command))
        .collect();
    assert!(
        stale.is_empty(),
        "inventory marks commands present but they are absent from registry: {stale:?}"
    );
}

#[test]
fn missing_or_excluded_inventory_entries_are_not_registered() {
    let registry = registry_commands();
    let inventory = inventory_by_command();

    let misleading: Vec<_> = inventory
        .values()
        .filter(|item| matches!(item.status, Status::Missing | Status::Excluded))
        .filter(|item| registry.contains(item.command))
        .collect();
    assert!(
        misleading.is_empty(),
        "inventory marks registered commands missing/excluded: {misleading:?}"
    );
}

#[test]
fn missing_and_partial_entries_have_context() {
    let inventory = inventory_by_command();
    let missing_context: Vec<_> = inventory
        .values()
        .filter(|item| {
            matches!(
                item.status,
                Status::Missing | Status::Partial | Status::Excluded
            )
        })
        .filter(|item| item.note.is_empty())
        .collect();
    assert!(
        missing_context.is_empty(),
        "non-supported inventory entries need context: {missing_context:?}"
    );
}
