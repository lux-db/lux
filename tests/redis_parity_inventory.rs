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
    missing("BITFIELD", "compatibility gap"),
    missing("BITFIELD_RO", "compatibility gap"),
    supported("BITCOUNT"),
    supported("BITOP"),
    supported("BITPOS"),
    supported("BLMOVE"),
    supported("BLPOP"),
    missing("BLMPOP", "compatibility gap"),
    supported("BRPOP"),
    missing("BRPOPLPUSH", "compatibility gap"),
    supported("BZPOPMAX"),
    supported("BZPOPMIN"),
    missing("BZMPOP", "compatibility gap"),
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
    partial("DUMP", "compatibility gap"),
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
    missing("HEXPIRE", "compatibility gap"),
    missing("HEXPIREAT", "compatibility gap"),
    missing("HEXPIRETIME", "compatibility gap"),
    supported("HGET"),
    missing("HGETDEL", "compatibility gap"),
    missing("HGETEX", "compatibility gap"),
    supported("HGETALL"),
    supported("HINCRBY"),
    supported("HINCRBYFLOAT"),
    supported("HKEYS"),
    supported("HLEN"),
    supported("HMGET"),
    supported("HMSET"),
    missing("HPERSIST", "compatibility gap"),
    missing("HPEXPIRE", "compatibility gap"),
    missing("HPEXPIREAT", "compatibility gap"),
    missing("HPEXPIRETIME", "compatibility gap"),
    missing("HPTTL", "compatibility gap"),
    supported("HRANDFIELD"),
    supported("HSCAN"),
    supported("HSET"),
    supported("HSETNX"),
    supported("HSTRLEN"),
    missing("HTTL", "compatibility gap"),
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
    missing("LMPOP", "compatibility gap"),
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
    missing("MIGRATE", "compatibility gap"),
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
    missing("PUBSUB", "compatibility gap"),
    supported("PUBLISH"),
    supported("PUNSUBSCRIBE"),
    supported("QUIT"),
    supported("RANDOMKEY"),
    excluded("READONLY", "cluster mode is out of scope"),
    excluded("READWRITE", "cluster mode is out of scope"),
    supported("RENAME"),
    supported("RENAMENX"),
    excluded("REPLICAOF", "replication is out of scope"),
    missing("RESTORE", "compatibility gap"),
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
    missing("SPUBLISH", "compatibility gap"),
    supported("SRANDMEMBER"),
    supported("SREM"),
    supported("SSCAN"),
    missing("SSUBSCRIBE", "compatibility gap"),
    supported("STRLEN"),
    supported("SUBSCRIBE"),
    supported("SUBSTR"),
    supported("SUNION"),
    supported("SUNIONSTORE"),
    missing("SUNSUBSCRIBE", "compatibility gap"),
    partial("SWAPDB", "compatibility gap"),
    supported("TIME"),
    missing("TOUCH", "compatibility gap"),
    supported("TTL"),
    supported("TYPE"),
    supported("UNLINK"),
    supported("UNSUBSCRIBE"),
    supported("UNWATCH"),
    partial("WAIT", "compatibility gap"),
    missing("WAITAOF", "compatibility gap"),
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
    missing("ZDIFF", "compatibility gap"),
    supported("ZDIFFSTORE"),
    supported("ZINCRBY"),
    missing("ZINTER", "compatibility gap"),
    missing("ZINTERCARD", "compatibility gap"),
    supported("ZINTERSTORE"),
    supported("ZLEXCOUNT"),
    missing("ZMPOP", "compatibility gap"),
    supported("ZMSCORE"),
    supported("ZPOPMAX"),
    supported("ZPOPMIN"),
    missing("ZRANDMEMBER", "compatibility gap"),
    supported("ZRANGE"),
    missing("ZRANGESTORE", "compatibility gap"),
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
    missing("ZUNION", "compatibility gap"),
    supported("ZUNIONSTORE"),
    lux_native("DELIFEQ"),
    lux_native("GRANT"),
    lux_native("KSUB"),
    lux_native("KUNSUB"),
    lux_native("PFDEBUG"),
    lux_native("TALTER"),
    lux_native("TCOUNT"),
    lux_native("TCREATE"),
    lux_native("TDELETE"),
    lux_native("TDROP"),
    lux_native("TDROPINDEX"),
    lux_native("TINDEX"),
    lux_native("TINSERT"),
    lux_native("TLIST"),
    lux_native("TSCHEMA"),
    lux_native("TSELECT"),
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
