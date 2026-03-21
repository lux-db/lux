use crate::store::{num_shards, Store, USED_MEMORY};
use std::sync::atomic::Ordering;
use std::sync::OnceLock;

#[derive(Clone, Copy, PartialEq)]
pub enum EvictionPolicy {
    NoEviction,
    AllKeysLru,
    VolatileLru,
    AllKeysRandom,
    VolatileRandom,
}

pub struct EvictionConfig {
    pub max_memory: usize,
    pub policy: EvictionPolicy,
    pub sample_size: usize,
}

pub fn eviction_config() -> &'static EvictionConfig {
    static CONFIG: OnceLock<EvictionConfig> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let max_memory = std::env::var("LUX_MAXMEMORY")
            .ok()
            .and_then(|s| parse_memory_size(&s))
            .unwrap_or(0);

        let policy = std::env::var("LUX_MAXMEMORY_POLICY")
            .ok()
            .map(|s| match s.to_lowercase().as_str() {
                "allkeys-lru" => EvictionPolicy::AllKeysLru,
                "volatile-lru" => EvictionPolicy::VolatileLru,
                "allkeys-random" => EvictionPolicy::AllKeysRandom,
                "volatile-random" => EvictionPolicy::VolatileRandom,
                "noeviction" => EvictionPolicy::NoEviction,
                _ => EvictionPolicy::NoEviction,
            })
            .unwrap_or(EvictionPolicy::NoEviction);

        let sample_size = std::env::var("LUX_MAXMEMORY_SAMPLES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5usize);

        EvictionConfig {
            max_memory,
            policy,
            sample_size,
        }
    })
}

fn parse_memory_size(s: &str) -> Option<usize> {
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

#[inline(always)]
pub fn eviction_enabled() -> bool {
    let cfg = eviction_config();
    cfg.max_memory > 0 && cfg.policy != EvictionPolicy::NoEviction
}

pub fn evict_if_needed(store: &Store) -> Result<(), &'static str> {
    if !eviction_enabled() {
        return Ok(());
    }

    let cfg = eviction_config();
    let max = cfg.max_memory;

    let mut iterations = 0;
    while USED_MEMORY.load(Ordering::Relaxed) > max {
        iterations += 1;
        if iterations > 128 {
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
            return Err("OOM command not allowed when used memory > 'maxmemory'");
        }
    }
    Ok(())
}

fn evict_lru(store: &Store, sample_size: usize, volatile_only: bool) -> bool {
    let n = num_shards();
    let seed = USED_MEMORY.load(Ordering::Relaxed);
    let start_shard = seed % n;

    let mut best_key: Option<String> = None;
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
        store.evict_key(best_shard, &key);
        true
    } else {
        false
    }
}

fn evict_random(store: &Store, volatile_only: bool) -> bool {
    let n = num_shards();
    let seed = USED_MEMORY.load(Ordering::Relaxed);
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
                .find(|(_, e)| e.expires_at.is_some())
                .map(|(k, _)| k.clone())
        } else {
            shard.data.keys().next().cloned()
        };
        drop(shard);

        if let Some(k) = key {
            store.evict_key(shard_idx, &k);
            return true;
        }
    }
    false
}

pub fn is_write_command(cmd: &[u8]) -> bool {
    fn eq(input: &[u8], expected: &[u8]) -> bool {
        input.len() == expected.len()
            && input
                .iter()
                .zip(expected)
                .all(|(a, b)| a.to_ascii_uppercase() == *b)
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
        || eq(cmd, b"TDEL")
        || eq(cmd, b"TDROP")
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
