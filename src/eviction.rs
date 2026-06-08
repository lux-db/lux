use crate::store::{Store, StoreValue};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvictionPolicy {
    /// Reject writes when memory exceeds maxmemory.
    NoEviction,
    /// Evict least-recently-used keys from the full keyspace.
    AllKeysLru,
    /// Evict least-recently-used keys that have TTLs.
    VolatileLru,
    /// Evict random keys from the full keyspace.
    AllKeysRandom,
    /// Evict random keys that have TTLs.
    VolatileRandom,
}

/// Memory pressure configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvictionConfig {
    /// Maximum memory in bytes. `0` disables eviction.
    pub max_memory: usize,
    /// Eviction strategy used after `max_memory` is exceeded.
    pub policy: EvictionPolicy,
    /// Number of entries sampled per eviction attempt for approximate LRU.
    pub sample_size: usize,
}

impl Default for EvictionConfig {
    fn default() -> Self {
        Self {
            max_memory: 0,
            policy: EvictionPolicy::NoEviction,
            sample_size: 5,
        }
    }
}

pub fn parse_memory_size(s: &str) -> Option<usize> {
    let s = s.trim().to_lowercase();
    if s == "0" {
        return Some(0);
    }
    if let Some(rest) = s.strip_suffix("gb") {
        return rest
            .trim()
            .parse::<usize>()
            .ok()
            .map(|n| n * 1024 * 1024 * 1024);
    }
    if let Some(rest) = s.strip_suffix("mb") {
        return rest.trim().parse::<usize>().ok().map(|n| n * 1024 * 1024);
    }
    if let Some(rest) = s.strip_suffix("kb") {
        return rest.trim().parse::<usize>().ok().map(|n| n * 1024);
    }
    s.parse::<usize>().ok()
}

/// Parse Redis-compatible maxmemory policy names.
pub fn parse_eviction_policy(s: &str) -> EvictionPolicy {
    match s.to_lowercase().as_str() {
        "allkeys-lru" => EvictionPolicy::AllKeysLru,
        "volatile-lru" => EvictionPolicy::VolatileLru,
        "allkeys-random" => EvictionPolicy::AllKeysRandom,
        "volatile-random" => EvictionPolicy::VolatileRandom,
        "noeviction" => EvictionPolicy::NoEviction,
        _ => EvictionPolicy::NoEviction,
    }
}

#[inline(always)]
pub fn eviction_enabled(store: &Store) -> bool {
    let cfg = store.config().eviction;
    cfg.max_memory > 0
}

pub fn evict_if_needed(store: &Store) -> Result<(), &'static str> {
    if !eviction_enabled(store) {
        return Ok(());
    }
    let cfg = store.config().eviction;

    let max = cfg.max_memory;
    let tiered = store.is_tiered();

    let mut iterations = 0;
    while store.approximate_memory() > max {
        iterations += 1;
        if iterations > 128 {
            if tiered {
                // In tiered mode, data spills to disk. Never reject writes.
                return Ok(());
            }
            return Err("OOM command not allowed when used memory > 'maxmemory'");
        }

        let evicted = match cfg.policy {
            EvictionPolicy::AllKeysLru => evict_lru(store, cfg.sample_size, false),
            EvictionPolicy::VolatileLru => evict_lru(store, cfg.sample_size, true),
            EvictionPolicy::AllKeysRandom => evict_random(store, false),
            EvictionPolicy::VolatileRandom => evict_random(store, true),
            EvictionPolicy::NoEviction => false,
        };

        if !evicted {
            if tiered {
                return Ok(());
            }
            return Err("OOM command not allowed when used memory > 'maxmemory'");
        }
    }
    Ok(())
}

fn evict_lru(store: &Store, sample_size: usize, volatile_only: bool) -> bool {
    let n = store.shard_count();
    let seed = store.approximate_memory();
    let start_shard = seed % n;

    let mut best_key: Option<Vec<u8>> = None;
    let mut best_clock: u32 = u32::MAX;
    let mut best_shard: usize = 0;

    for offset in 0..n {
        let shard_idx = (start_shard + offset) % n;
        let shard = store.lock_read_shard(shard_idx);
        if shard.data.is_empty() {
            continue;
        }

        let mut sampled = 0;
        for (key, entry) in shard.data.iter() {
            if sampled >= sample_size {
                break;
            }
            if volatile_only && entry.expires_at.is_none() {
                continue;
            }
            if matches!(entry.value, StoreValue::Vector(_)) {
                continue;
            }
            sampled += 1;
            if entry.lru_clock < best_clock {
                best_clock = entry.lru_clock;
                best_key = Some(key.clone());
                best_shard = shard_idx;
            }
        }

        if sampled > 0 {
            break;
        }
    }

    if let Some(key) = best_key {
        store.evict_key(best_shard, &key)
    } else {
        false
    }
}

fn evict_random(store: &Store, volatile_only: bool) -> bool {
    let n = store.shard_count();
    let seed = store.approximate_memory();
    let start_shard = seed % n;

    for offset in 0..n {
        let shard_idx = (start_shard + offset) % n;
        let shard = store.lock_read_shard(shard_idx);
        if shard.data.is_empty() {
            continue;
        }

        let key = if volatile_only {
            shard
                .data
                .iter()
                .find(|(_, e)| e.expires_at.is_some() && !matches!(e.value, StoreValue::Vector(_)))
                .map(|(k, _)| k.clone())
        } else {
            shard
                .data
                .iter()
                .find(|(_, e)| !matches!(e.value, StoreValue::Vector(_)))
                .map(|(k, _)| k.clone())
        };
        drop(shard);

        if let Some(k) = key {
            return store.evict_key(shard_idx, &k);
        }
    }
    false
}

pub fn is_write_command(cmd: &[u8]) -> bool {
    fn eq(input: &[u8], expected: &[u8]) -> bool {
        input.eq_ignore_ascii_case(expected)
    }
    eq(cmd, b"SET")
        || eq(cmd, b"SETNX")
        || eq(cmd, b"SETEX")
        || eq(cmd, b"PSETEX")
        || eq(cmd, b"MSET")
        || eq(cmd, b"MSETNX")
        || eq(cmd, b"APPEND")
        || eq(cmd, b"INCR")
        || eq(cmd, b"DECR")
        || eq(cmd, b"INCRBY")
        || eq(cmd, b"DECRBY")
        || eq(cmd, b"INCRBYFLOAT")
        || eq(cmd, b"GETSET")
        || eq(cmd, b"SETRANGE")
        || eq(cmd, b"LPUSH")
        || eq(cmd, b"RPUSH")
        || eq(cmd, b"LPOP")
        || eq(cmd, b"RPOP")
        || eq(cmd, b"LSET")
        || eq(cmd, b"LREM")
        || eq(cmd, b"LMOVE")
        || eq(cmd, b"SADD")
        || eq(cmd, b"SREM")
        || eq(cmd, b"SPOP")
        || eq(cmd, b"SMOVE")
        || eq(cmd, b"SDIFFSTORE")
        || eq(cmd, b"SINTERSTORE")
        || eq(cmd, b"SUNIONSTORE")
        || eq(cmd, b"HSET")
        || eq(cmd, b"HSETNX")
        || eq(cmd, b"HDEL")
        || eq(cmd, b"HINCRBY")
        || eq(cmd, b"HINCRBYFLOAT")
        || eq(cmd, b"ZADD")
        || eq(cmd, b"ZREM")
        || eq(cmd, b"ZINCRBY")
        || eq(cmd, b"ZPOPMIN")
        || eq(cmd, b"ZPOPMAX")
        || eq(cmd, b"ZUNIONSTORE")
        || eq(cmd, b"ZINTERSTORE")
        || eq(cmd, b"ZDIFFSTORE")
        || eq(cmd, b"GEOADD")
        || eq(cmd, b"GEOSEARCHSTORE")
        || eq(cmd, b"GEORADIUS")
        || eq(cmd, b"GEORADIUSBYMEMBER")
        || eq(cmd, b"XADD")
        || eq(cmd, b"XDEL")
        || eq(cmd, b"XTRIM")
        || eq(cmd, b"XGROUP")
        || eq(cmd, b"XACK")
        || eq(cmd, b"RENAME")
        || eq(cmd, b"DEL")
        || eq(cmd, b"UNLINK")
        || eq(cmd, b"EXPIRE")
        || eq(cmd, b"PEXPIRE")
        || eq(cmd, b"EXPIREAT")
        || eq(cmd, b"PEXPIREAT")
        || eq(cmd, b"PERSIST")
        || eq(cmd, b"GETDEL")
        || eq(cmd, b"GETEX")
        || eq(cmd, b"FLUSHDB")
        || eq(cmd, b"FLUSHALL")
        || eq(cmd, b"COPY")
        || eq(cmd, b"VSET")
        || eq(cmd, b"PFADD")
        || eq(cmd, b"PFMERGE")
        || eq(cmd, b"SETBIT")
        || eq(cmd, b"BITOP")
        || eq(cmd, b"SORT")
        || eq(cmd, b"TSADD")
        || eq(cmd, b"TSMADD")
        || eq(cmd, b"TCREATE")
        || eq(cmd, b"TINSERT")
        || eq(cmd, b"TUPDATE")
        || eq(cmd, b"TDELETE")
        || eq(cmd, b"TDROP")
        || eq(cmd, b"TALTER")
        || eq(cmd, b"EVAL")
        || eq(cmd, b"EVALSHA")
        || eq(cmd, b"RPOPLPUSH")
        || eq(cmd, b"LINSERT")
        || eq(cmd, b"LPUSHX")
        || eq(cmd, b"RPUSHX")
        || eq(cmd, b"HMSET")
        || eq(cmd, b"LTRIM")
        || eq(cmd, b"ZRANGESTORE")
        || eq(cmd, b"ZREMRANGEBYRANK")
        || eq(cmd, b"ZREMRANGEBYSCORE")
        || eq(cmd, b"ZREMRANGEBYLEX")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_memory_sizes() {
        assert_eq!(parse_memory_size("0"), Some(0));
        assert_eq!(parse_memory_size("100mb"), Some(100 * 1024 * 1024));
        assert_eq!(parse_memory_size("1gb"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_memory_size("512kb"), Some(512 * 1024));
        assert_eq!(parse_memory_size("1048576"), Some(1048576));
        assert_eq!(parse_memory_size("100MB"), Some(100 * 1024 * 1024));
    }

    #[test]
    fn write_command_detection() {
        assert!(is_write_command(b"SET"));
        assert!(is_write_command(b"set"));
        assert!(is_write_command(b"LPUSH"));
        assert!(is_write_command(b"ZADD"));
        assert!(!is_write_command(b"GET"));
        assert!(!is_write_command(b"PING"));
        assert!(!is_write_command(b"INFO"));
    }
}
