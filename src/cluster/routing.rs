use super::{slot_for_key, slot_for_table_row};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CommandRoute {
    /// Connection state and node diagnostics execute on the ingress node.
    Local,
    /// Catalog/system state executes only on the signed system node.
    System { read_only: bool },
    /// Data state executes on the node owning this slot.
    Slot { slot: u16, read_only: bool },
    /// The command has defined semantics but is not safe in the current Cluster slice.
    Unsupported(String),
}

pub(crate) fn classify_command(argv: &[&[u8]]) -> CommandRoute {
    let Some(command) = argv.first() else {
        return CommandRoute::Local;
    };
    if command.is_empty() {
        return CommandRoute::Local;
    }

    if local_command(command) {
        return CommandRoute::Local;
    }
    if table_row_command(command) {
        let (Some(table), Some(primary_key)) = (argv.get(1), argv.get(2)) else {
            // Preserve the ordinary command's exact arity response on the
            // system node instead of inventing a router-level error.
            return CommandRoute::System {
                read_only: eq(command, b"TGET"),
            };
        };
        if reserved_system_table(table) {
            return CommandRoute::System {
                read_only: eq(command, b"TGET"),
            };
        }
        return CommandRoute::Slot {
            slot: slot_for_table_row(table, primary_key),
            read_only: eq(command, b"TGET"),
        };
    }
    if system_command(command) {
        return CommandRoute::System {
            read_only: !system_command_is_write(argv),
        };
    }
    if global_scan_command(command) {
        return CommandRoute::System { read_only: true };
    }
    if unsupported_distributed_command(command) {
        return unsupported(command, "requires a distributed coordinator");
    }

    let keys = match route_keys(argv) {
        Ok(Some(keys)) => keys,
        Ok(None) if crate::cmd::is_known_command(command) => {
            return unsupported(command, "has no declared Cluster routing domain")
        }
        Ok(None) => return CommandRoute::Local,
        Err(message) => return CommandRoute::Unsupported(message),
    };
    let Some(first) = keys.first() else {
        return unsupported(command, "has no safe routing key");
    };
    let slot = slot_for_key(first);
    if keys.iter().skip(1).any(|key| slot_for_key(key) != slot) {
        return CommandRoute::Unsupported(format!(
            "CROSSSLOT command '{}' touches keys in different Cluster slots; use a shared Redis hash tag",
            String::from_utf8_lossy(command).to_ascii_uppercase()
        ));
    }
    CommandRoute::Slot {
        slot,
        read_only: !crate::eviction::is_write_command(command),
    }
}

fn route_keys<'a>(argv: &[&'a [u8]]) -> Result<Option<Vec<&'a [u8]>>, String> {
    let command = argv[0];
    if single_key_at_one(command) {
        return Ok(argv.get(1).copied().map(|key| vec![key]));
    }
    if eq(command, b"OBJECT") || eq(command, b"XINFO") || eq(command, b"XGROUP") {
        return Ok(argv.get(2).copied().map(|key| vec![key]));
    }
    if eq(command, b"MEMORY") && argv.get(1).is_some_and(|arg| eq(arg, b"USAGE")) {
        return Ok(argv.get(2).copied().map(|key| vec![key]));
    }
    if eq(command, b"MSET") || eq(command, b"MSETNX") {
        return Ok(Some(argv.iter().skip(1).step_by(2).copied().collect()));
    }
    if matches_all_keys(command) {
        return Ok(Some(argv.iter().skip(1).copied().collect()));
    }
    if two_key_command(command) {
        return Ok(Some(argv.iter().skip(1).take(2).copied().collect()));
    }
    if eq(command, b"BITOP") {
        return Ok(Some(argv.iter().skip(2).copied().collect()));
    }
    if eq(command, b"TSMADD") {
        return Ok(Some(argv.iter().skip(1).step_by(3).copied().collect()));
    }
    if eq(command, b"LMPOP") || eq(command, b"ZMPOP") {
        return counted_keys(argv, 1, 2);
    }
    if eq(command, b"BLMPOP") || eq(command, b"BZMPOP") {
        return counted_keys(argv, 2, 3);
    }
    if destination_counted_keys(command) {
        let mut keys = argv.get(1).copied().into_iter().collect::<Vec<_>>();
        keys.extend(counted_keys(argv, 2, 3)?.unwrap_or_default());
        return Ok(Some(keys));
    }
    if counted_read_keys(command) {
        return counted_keys(argv, 1, 2);
    }
    if eq(command, b"XREAD") || eq(command, b"XREADGROUP") {
        let Some(streams) = argv.iter().position(|arg| eq(arg, b"STREAMS")) else {
            return Err("Cluster cannot route XREAD without a STREAMS clause".to_string());
        };
        let tail = &argv[streams + 1..];
        return Ok(Some(tail.iter().take(tail.len() / 2).copied().collect()));
    }
    if eq(command, b"GEORADIUS") || eq(command, b"GEORADIUSBYMEMBER") {
        let mut keys = argv.get(1).copied().into_iter().collect::<Vec<_>>();
        for index in 2..argv.len() {
            if (eq(argv[index], b"STORE") || eq(argv[index], b"STOREDIST"))
                && argv.get(index + 1).is_some()
            {
                keys.push(argv[index + 1]);
            }
        }
        return Ok(Some(keys));
    }

    // Unknown commands stay on the normal executor so Lux preserves its exact
    // unknown-command and arity responses. Registered commands must be added to
    // one of the explicit families above before they can touch distributed data.
    Ok(None)
}

fn counted_keys<'a>(
    argv: &[&'a [u8]],
    count_index: usize,
    first_key_index: usize,
) -> Result<Option<Vec<&'a [u8]>>, String> {
    let Some(count) = argv
        .get(count_index)
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(|value| value.parse::<usize>().ok())
    else {
        return Err(format!(
            "Cluster could not parse the key count for '{}'",
            String::from_utf8_lossy(argv[0])
        ));
    };
    let end = first_key_index.saturating_add(count);
    if count == 0 || end > argv.len() {
        return Err(format!(
            "Cluster found an invalid key count for '{}'",
            String::from_utf8_lossy(argv[0])
        ));
    }
    Ok(Some(argv[first_key_index..end].to_vec()))
}

fn local_command(command: &[u8]) -> bool {
    const COMMANDS: &[&[u8]] = &[
        b"AUTH", b"CLIENT", b"CLUSTER", b"COMMAND", b"CONFIG", b"ECHO", b"HELLO", b"INFO",
        b"LATENCY", b"PING", b"QUIT", b"RESET", b"SELECT", b"TIME",
    ];
    COMMANDS.iter().any(|candidate| eq(command, candidate))
}

fn system_command(command: &[u8]) -> bool {
    const COMMANDS: &[&[u8]] = &[
        b"GRANT",
        b"LUX",
        b"REVOKE",
        b"TALTER",
        b"TCOUNT",
        b"TCREATE",
        b"TDELETE",
        b"TDROP",
        b"TDROPINDEX",
        b"TINDEX",
        b"TINSERT",
        b"TLIST",
        b"TSCHEMA",
        b"TSELECT",
        b"TUPDATE",
        b"TUPSERT",
    ];
    COMMANDS.iter().any(|candidate| eq(command, candidate))
}

fn table_row_command(command: &[u8]) -> bool {
    eq(command, b"TGET") || eq(command, b"TSET")
}

fn global_scan_command(command: &[u8]) -> bool {
    [
        b"KEYS".as_slice(),
        b"TSMRANGE".as_slice(),
        b"VCARD".as_slice(),
        b"VSEARCH".as_slice(),
    ]
    .iter()
    .any(|candidate| eq(command, candidate))
}

fn reserved_system_table(table: &[u8]) -> bool {
    let Ok(table) = std::str::from_utf8(table) else {
        return true;
    };
    table.starts_with("auth.") || table.starts_with("push.")
}

pub(crate) fn routed_table<'a>(argv: &'a [&'a [u8]]) -> Option<&'a str> {
    let command = argv.first()?;
    if !table_row_command(command) {
        return None;
    }
    argv.get(2)?;
    let table = std::str::from_utf8(argv.get(1)?).ok()?;
    (!crate::auth::is_reserved_system_table(table)).then_some(table)
}

fn system_command_is_write(argv: &[&[u8]]) -> bool {
    let command = argv[0];
    if eq(command, b"GRANT") || eq(command, b"REVOKE") {
        return true;
    }
    if eq(command, b"LUX") {
        return !argv
            .get(1)
            .is_some_and(|subcommand| eq(subcommand, b"VERSION"));
    }
    ![
        b"TCOUNT".as_slice(),
        b"TGET".as_slice(),
        b"TLIST".as_slice(),
        b"TSCHEMA".as_slice(),
        b"TSELECT".as_slice(),
    ]
    .iter()
    .any(|candidate| eq(command, candidate))
}

fn unsupported_distributed_command(command: &[u8]) -> bool {
    const COMMANDS: &[&[u8]] = &[
        b"BGSAVE",
        b"BLMOVE",
        b"BLMPOP",
        b"BLPOP",
        b"BRPOP",
        b"BRPOPLPUSH",
        b"BZMPOP",
        b"BZPOPMAX",
        b"BZPOPMIN",
        b"DBSIZE",
        b"DEBUG",
        b"DISCARD",
        b"ENC",
        b"EVAL",
        b"EVALSHA",
        b"EXEC",
        b"FLUSHALL",
        b"FLUSHDB",
        b"FUNCTION",
        b"KSUB",
        b"KUNSUB",
        b"LASTSAVE",
        b"MIGRATE",
        b"MULTI",
        b"PFDEBUG",
        b"PSUBSCRIBE",
        b"PUBLISH",
        b"PUBSUB",
        b"PUNSUBSCRIBE",
        b"RANDOMKEY",
        b"SAVE",
        b"SCAN",
        b"SCRIPT",
        b"SORT",
        b"SORT_RO",
        b"SPUBLISH",
        b"SSUBSCRIBE",
        b"SUBSCRIBE",
        b"SUNSUBSCRIBE",
        b"SWAPDB",
        b"UNSUBSCRIBE",
        b"UNWATCH",
        b"WAIT",
        b"WAITAOF",
        b"WATCH",
        b"XREAD",
        b"XREADGROUP",
    ];
    COMMANDS.iter().any(|candidate| eq(command, candidate))
}

fn single_key_at_one(command: &[u8]) -> bool {
    const COMMANDS: &[&[u8]] = &[
        b"APPEND",
        b"BITCOUNT",
        b"BITFIELD",
        b"BITFIELD_RO",
        b"BITPOS",
        b"DECR",
        b"DECRBY",
        b"DELIFEQ",
        b"DUMP",
        b"EXPIRE",
        b"EXPIREAT",
        b"EXPIRETIME",
        b"GEOADD",
        b"GEODIST",
        b"GEOHASH",
        b"GEOPOS",
        b"GEORADIUSBYMEMBER_RO",
        b"GEORADIUS_RO",
        b"GEOSEARCH",
        b"GEOSEARCH_RO",
        b"GET",
        b"GETBIT",
        b"GETDEL",
        b"GETEX",
        b"GETRANGE",
        b"GETSET",
        b"HDEL",
        b"HEXISTS",
        b"HEXPIRE",
        b"HEXPIREAT",
        b"HEXPIRETIME",
        b"HGET",
        b"HGETALL",
        b"HGETDEL",
        b"HGETEX",
        b"HINCRBY",
        b"HINCRBYFLOAT",
        b"HKEYS",
        b"HLEN",
        b"HMGET",
        b"HMSET",
        b"HPERSIST",
        b"HPEXPIRE",
        b"HPEXPIREAT",
        b"HPEXPIRETIME",
        b"HPTTL",
        b"HRANDFIELD",
        b"HSCAN",
        b"HSET",
        b"HSETNX",
        b"HSTRLEN",
        b"HTTL",
        b"HVALS",
        b"INCR",
        b"INCRBY",
        b"INCRBYFLOAT",
        b"LINDEX",
        b"LINSERT",
        b"LLEN",
        b"LPOP",
        b"LPOS",
        b"LPUSH",
        b"LPUSHX",
        b"LRANGE",
        b"LREM",
        b"LSET",
        b"LTRIM",
        b"PERSIST",
        b"PEXPIRE",
        b"PEXPIREAT",
        b"PEXPIRETIME",
        b"PFADD",
        b"PSETEX",
        b"PTTL",
        b"RESTORE",
        b"RPOP",
        b"RPUSH",
        b"RPUSHX",
        b"SADD",
        b"SCARD",
        b"SET",
        b"SETBIT",
        b"SETEX",
        b"SETNX",
        b"SETRANGE",
        b"SISMEMBER",
        b"SMEMBERS",
        b"SMISMEMBER",
        b"SPOP",
        b"SRANDMEMBER",
        b"SREM",
        b"SSCAN",
        b"STRLEN",
        b"SUBSTR",
        b"TSADD",
        b"TSGET",
        b"TSINFO",
        b"TSRANGE",
        b"TTL",
        b"TYPE",
        b"VGET",
        b"VSET",
        b"XACK",
        b"XADD",
        b"XAUTOCLAIM",
        b"XCLAIM",
        b"XDEL",
        b"XLEN",
        b"XPENDING",
        b"XRANGE",
        b"XREVRANGE",
        b"XTRIM",
        b"ZADD",
        b"ZCARD",
        b"ZCOUNT",
        b"ZINCRBY",
        b"ZLEXCOUNT",
        b"ZMSCORE",
        b"ZPOPMAX",
        b"ZPOPMIN",
        b"ZRANDMEMBER",
        b"ZRANGE",
        b"ZRANGEBYLEX",
        b"ZRANGEBYSCORE",
        b"ZRANK",
        b"ZREM",
        b"ZREMRANGEBYLEX",
        b"ZREMRANGEBYRANK",
        b"ZREMRANGEBYSCORE",
        b"ZREVRANGE",
        b"ZREVRANGEBYLEX",
        b"ZREVRANGEBYSCORE",
        b"ZREVRANK",
        b"ZSCAN",
        b"ZSCORE",
    ];
    COMMANDS.iter().any(|candidate| eq(command, candidate))
}

fn matches_all_keys(command: &[u8]) -> bool {
    const COMMANDS: &[&[u8]] = &[
        b"DEL",
        b"EXISTS",
        b"MGET",
        b"PFCOUNT",
        b"PFMERGE",
        b"SDIFF",
        b"SDIFFSTORE",
        b"SINTER",
        b"SINTERSTORE",
        b"SUNION",
        b"SUNIONSTORE",
        b"TOUCH",
        b"UNLINK",
    ];
    COMMANDS.iter().any(|candidate| eq(command, candidate))
}

fn two_key_command(command: &[u8]) -> bool {
    const COMMANDS: &[&[u8]] = &[
        b"COPY",
        b"GEOSEARCHSTORE",
        b"LCS",
        b"LMOVE",
        b"RENAME",
        b"RENAMENX",
        b"RPOPLPUSH",
        b"SMOVE",
        b"ZRANGESTORE",
    ];
    COMMANDS.iter().any(|candidate| eq(command, candidate))
}

fn destination_counted_keys(command: &[u8]) -> bool {
    const COMMANDS: &[&[u8]] = &[b"ZDIFFSTORE", b"ZINTERSTORE", b"ZUNIONSTORE"];
    COMMANDS.iter().any(|candidate| eq(command, candidate))
}

fn counted_read_keys(command: &[u8]) -> bool {
    const COMMANDS: &[&[u8]] = &[b"SINTERCARD", b"ZDIFF", b"ZINTER", b"ZINTERCARD", b"ZUNION"];
    COMMANDS.iter().any(|candidate| eq(command, candidate))
}

fn unsupported(command: &[u8], reason: &str) -> CommandRoute {
    CommandRoute::Unsupported(format!(
        "Cluster command '{}' {reason}",
        String::from_utf8_lossy(command).to_ascii_uppercase()
    ))
}

fn eq(left: &[u8], right: &[u8]) -> bool {
    left.eq_ignore_ascii_case(right)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(argv: &[&[u8]]) -> CommandRoute {
        classify_command(argv)
    }

    #[test]
    fn single_key_commands_share_one_slot() {
        let route = classify(&[b"SET", b"cart:{user-1}", b"value"]);
        assert_eq!(
            route,
            CommandRoute::Slot {
                slot: slot_for_key(b"cart:{user-1}"),
                read_only: false,
            }
        );
        let read = classify(&[b"GET", b"orders:{user-1}"]);
        assert_eq!(
            read,
            CommandRoute::Slot {
                slot: slot_for_key(b"cart:{user-1}"),
                read_only: true,
            }
        );
    }

    #[test]
    fn multi_key_commands_fail_closed_across_slots() {
        assert!(matches!(
            classify(&[b"MGET", b"one", b"two"]),
            CommandRoute::Unsupported(message) if message.starts_with("CROSSSLOT")
        ));
        assert!(matches!(
            classify(&[b"MSET", b"{same}:one", b"1", b"{same}:two", b"2"]),
            CommandRoute::Slot {
                read_only: false,
                ..
            }
        ));
    }

    #[test]
    fn connection_and_catalog_commands_have_explicit_domains() {
        assert_eq!(classify(&[b"PING"]), CommandRoute::Local);
        assert_eq!(
            classify(&[b"TCREATE", b"orders", b"id", b"UUID"]),
            CommandRoute::System { read_only: false }
        );
        assert_eq!(
            classify(&[b"GRANT", b"READ", b"ON", b"orders", b"TO", b"authenticated"]),
            CommandRoute::System { read_only: false }
        );
        assert_eq!(
            classify(&[b"LUX", b"VERSION"]),
            CommandRoute::System { read_only: true }
        );
        assert_eq!(
            classify(&[b"KEYS", b"*"]),
            CommandRoute::System { read_only: true }
        );
        assert!(matches!(
            classify(&[b"DBSIZE"]),
            CommandRoute::Unsupported(_)
        ));
    }

    #[test]
    fn point_table_commands_route_by_table_and_primary_key() {
        let slot = slot_for_table_row(b"orders", b"order-17");
        assert_eq!(
            classify(&[b"TGET", b"orders", b"order-17"]),
            CommandRoute::Slot {
                slot,
                read_only: true,
            }
        );
        assert_eq!(
            classify(&[b"TSET", b"orders", b"order-17", b"state", b"paid"]),
            CommandRoute::Slot {
                slot,
                read_only: false,
            }
        );
        assert_eq!(
            classify(&[b"TGET", b"auth.users", b"user-1"]),
            CommandRoute::System { read_only: true }
        );
    }

    #[test]
    fn counted_commands_include_destinations_and_reject_bad_counts() {
        assert!(matches!(
            classify(&[b"ZUNIONSTORE", b"{x}:dst", b"2", b"{x}:a", b"{x}:b"]),
            CommandRoute::Slot {
                read_only: false,
                ..
            }
        ));
        assert!(matches!(
            classify(&[b"ZUNIONSTORE", b"{x}:dst", b"2", b"{x}:a", b"{y}:b"]),
            CommandRoute::Unsupported(message) if message.starts_with("CROSSSLOT")
        ));
        assert!(matches!(
            classify(&[b"ZUNIONSTORE", b"dst", b"not-a-number"]),
            CommandRoute::Unsupported(_)
        ));
    }

    #[test]
    fn every_registered_command_has_an_explicit_or_fail_closed_domain() {
        for command in crate::cmd::command_names() {
            let route = classify(&[
                command,
                b"{audit}:key-a",
                b"{audit}:key-b",
                b"1",
                b"{audit}:key-c",
                b"2",
            ]);
            if local_command(command) {
                assert_eq!(route, CommandRoute::Local, "local {command:?}");
            } else {
                assert!(
                    !matches!(route, CommandRoute::Local),
                    "registered command {command:?} silently fell through to one node"
                );
            }
        }
        assert_eq!(classify(&[b"NOT-A-LUX-COMMAND"]), CommandRoute::Local);
    }
}
