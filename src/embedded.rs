use std::time::Duration;

use bytes::Bytes;

use crate::command::{self, Command, CommandOutput};
use crate::{EmbeddedClient, EmbeddedValue, LuxError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedisKeyType {
    String,
    List,
    Set,
    ZSet,
    Hash,
    Stream,
    None,
    Other,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SetOptions {
    expiration: Option<SetExpiration>,
    condition: Option<SetCondition>,
    keep_ttl: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SetExpiration {
    Ex(u64),
    Px(u64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SetCondition {
    Nx,
    Xx,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ScoredMember {
    pub member: Bytes,
    pub score: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GeoMember<'a> {
    pub longitude: f64,
    pub latitude: f64,
    pub member: &'a str,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GeoPosition {
    pub longitude: f64,
    pub latitude: f64,
}

/// Native embedded pipeline builder.
///
/// Arguments are borrowed and must outlive the pipeline. Commands execute in
/// insertion order; common single-shard commands use the native fast path and
/// `raw` remains the escape hatch for commands that are not modeled yet.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct EmbeddedPipeline<'a> {
    commands: Vec<Command<'a>>,
}

/// Reusable embedded pipeline with owned command arguments.
///
/// `EmbeddedPipeline` is zero-copy and borrows its arguments, which is ideal
/// for immediate execution. `PreparedPipeline` owns those arguments so callers
/// can build a command sequence once, share it between tasks, and execute it
/// repeatedly without reparsing Redis argv or maintaining their own command
/// enum.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PreparedPipeline {
    commands: Vec<command::OwnedCommand>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeoUnit {
    M,
    Km,
    Mi,
    Ft,
}

impl GeoUnit {
    fn as_bytes(self) -> &'static [u8] {
        match self {
            GeoUnit::M => b"m",
            GeoUnit::Km => b"km",
            GeoUnit::Mi => b"mi",
            GeoUnit::Ft => b"ft",
        }
    }
}

impl PreparedPipeline {
    pub fn new() -> Self {
        Self {
            commands: Vec::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            commands: Vec::with_capacity(capacity),
        }
    }

    pub fn len(&self) -> usize {
        self.commands.len()
    }

    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }

    pub fn clear(&mut self) {
        self.commands.clear();
    }

    pub fn extend(&mut self, other: &PreparedPipeline) -> &mut Self {
        self.commands.extend_from_slice(&other.commands);
        self
    }

    pub fn ping(&mut self) -> &mut Self {
        self.commands.push(command::OwnedCommand::Ping);
        self
    }

    pub fn dbsize(&mut self) -> &mut Self {
        self.commands.push(command::OwnedCommand::DbSize);
        self
    }

    pub fn get<K>(&mut self, key: K) -> &mut Self
    where
        K: AsRef<[u8]>,
    {
        self.commands.push(command::OwnedCommand::Get {
            key: key.as_ref().to_vec(),
        });
        self
    }

    pub fn set<K, V>(&mut self, key: K, value: V) -> &mut Self
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.commands.push(command::OwnedCommand::Set {
            key: key.as_ref().to_vec(),
            value: value.as_ref().to_vec(),
            options: Vec::new(),
        });
        self
    }

    pub fn mset<K, V>(&mut self, pairs: &[(K, V)]) -> &mut Self
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.commands.push(command::OwnedCommand::MSet {
            pairs: pairs
                .iter()
                .map(|(key, value)| (key.as_ref().to_vec(), value.as_ref().to_vec()))
                .collect(),
        });
        self
    }

    pub fn append<K, V>(&mut self, key: K, value: V) -> &mut Self
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.commands.push(command::OwnedCommand::Append {
            key: key.as_ref().to_vec(),
            value: value.as_ref().to_vec(),
        });
        self
    }

    pub fn hincrby<K, F>(&mut self, key: K, field: F, increment: i64) -> &mut Self
    where
        K: AsRef<[u8]>,
        F: AsRef<[u8]>,
    {
        self.commands.push(command::OwnedCommand::HIncrBy {
            key: key.as_ref().to_vec(),
            field: field.as_ref().to_vec(),
            increment,
        });
        self
    }

    pub fn xadd<K, I, F, V>(&mut self, key: K, id: I, fields: &[(F, V)]) -> &mut Self
    where
        K: AsRef<[u8]>,
        I: AsRef<[u8]>,
        F: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.commands.push(command::OwnedCommand::XAdd {
            key: key.as_ref().to_vec(),
            id: id.as_ref().to_vec(),
            fields: fields
                .iter()
                .map(|(field, value)| (field.as_ref().to_vec(), value.as_ref().to_vec()))
                .collect(),
        });
        self
    }

    pub fn raw<N, I, A>(&mut self, name: N, args: I) -> &mut Self
    where
        N: AsRef<[u8]>,
        I: IntoIterator<Item = A>,
        A: AsRef<[u8]>,
    {
        self.commands.push(command::OwnedCommand::Raw {
            name: name.as_ref().to_vec(),
            args: args.into_iter().map(|arg| arg.as_ref().to_vec()).collect(),
        });
        self
    }

    pub fn push_argv<I, A>(&mut self, argv: I) -> Result<&mut Self, LuxError>
    where
        I: IntoIterator<Item = A>,
        A: AsRef<[u8]>,
    {
        let argv = argv
            .into_iter()
            .map(|arg| arg.as_ref().to_vec())
            .collect::<Vec<_>>();
        self.commands.push(command::prepare_owned_argv(argv)?);
        Ok(self)
    }

    pub fn from_argv<I, A>(argv: I) -> Result<Self, LuxError>
    where
        I: IntoIterator<Item = A>,
        A: AsRef<[u8]>,
    {
        let mut pipeline = Self::new();
        pipeline.push_argv(argv)?;
        Ok(pipeline)
    }

    pub fn is_write_only(&self) -> bool {
        !self.commands.is_empty() && self.commands.iter().all(command::OwnedCommand::is_write)
    }

    pub fn is_read_only(&self) -> bool {
        !self.commands.is_empty() && self.commands.iter().all(command::OwnedCommand::is_read)
    }

    fn borrowed_commands(&self) -> Vec<Command<'_>> {
        self.commands
            .iter()
            .map(command::OwnedCommand::as_borrowed)
            .collect()
    }

    fn raw_argvs(&self) -> Option<Vec<Vec<Vec<u8>>>> {
        // Mixed typed/raw pipelines must still flow through the native command
        // path so typed commands keep their fast-path behavior.
        self.commands
            .iter()
            .map(command::OwnedCommand::raw_argv)
            .collect()
    }
}

impl<'a> EmbeddedPipeline<'a> {
    /// Creates an empty borrowed embedded pipeline.
    ///
    /// Commands: none until command builder methods are called.
    ///
    /// Example:
    /// ```rust,ignore
    /// let mut pipe = lux::EmbeddedPipeline::new();
    /// pipe.ping();
    /// ```
    pub fn new() -> Self {
        Self {
            commands: Vec::new(),
        }
    }

    /// Creates an empty borrowed embedded pipeline with preallocated command capacity.
    ///
    /// Commands: none until command builder methods are called.
    ///
    /// Example:
    /// ```rust,ignore
    /// let mut pipe = lux::EmbeddedPipeline::with_capacity(2);
    /// pipe.set(b"key", b"value");
    /// ```
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            commands: Vec::with_capacity(capacity),
        }
    }

    /// Returns the number of queued commands.
    ///
    /// Commands: none; this only inspects the local pipeline builder.
    ///
    /// Example:
    /// ```rust,ignore
    /// let count = pipe.len();
    /// ```
    pub fn len(&self) -> usize {
        self.commands.len()
    }

    /// Returns whether the pipeline has no queued commands.
    ///
    /// Commands: none; this only inspects the local pipeline builder.
    ///
    /// Example:
    /// ```rust,ignore
    /// let empty = pipe.is_empty();
    /// ```
    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }

    /// Removes all queued commands from the pipeline.
    ///
    /// Commands: none; this only mutates the local pipeline builder.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.clear();
    /// ```
    pub fn clear(&mut self) {
        self.commands.clear();
    }

    /// Queues `PING`.
    ///
    /// Commands: Redis `PING`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.ping();
    /// ```
    pub fn ping(&mut self) -> &mut Self {
        self.commands.push(Command::Ping);
        self
    }

    /// Queues `PUBLISH` for a channel and message.
    ///
    /// Commands: Redis `PUBLISH`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.publish(b"events", b"payload");
    /// ```
    pub fn publish(&mut self, channel: &'a [u8], message: &'a [u8]) -> &mut Self {
        self.commands.push(Command::Publish { channel, message });
        self
    }

    /// Queues `DBSIZE`.
    ///
    /// Commands: Redis `DBSIZE`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.dbsize();
    /// ```
    pub fn dbsize(&mut self) -> &mut Self {
        self.commands.push(Command::DbSize);
        self
    }

    /// Queues `GET` for a key.
    ///
    /// Commands: Redis `GET`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.get(b"key");
    /// ```
    pub fn get(&mut self, key: &'a [u8]) -> &mut Self {
        self.commands.push(Command::Get { key });
        self
    }

    /// Queues `SET` without options.
    ///
    /// Commands: Redis `SET`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.set(b"key", b"value");
    /// ```
    pub fn set(&mut self, key: &'a [u8], value: &'a [u8]) -> &mut Self {
        self.commands.push(Command::Set {
            key,
            value,
            options: Vec::new(),
        });
        self
    }

    /// Queues `SET` with native options.
    ///
    /// Commands: Redis `SET` with `EX`, `PX`, `NX`, `XX`, or `KEEPTTL` options.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.set_options(b"key", b"value", &lux::SetOptions::default().nx());
    /// ```
    pub fn set_options(
        &mut self,
        key: &'a [u8],
        value: &'a [u8],
        options: &SetOptions,
    ) -> &mut Self {
        self.commands.push(Command::Set {
            key,
            value,
            options: options.command_options(),
        });
        self
    }

    /// Queues an arbitrary raw command by name and borrowed byte arguments.
    ///
    /// Commands: any non-blocking Redis command accepted by the embedded runtime parser.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.raw(b"SET", vec![b"key".as_slice(), b"value".as_slice()]);
    /// ```
    pub fn raw(&mut self, name: &'a [u8], args: Vec<&'a [u8]>) -> &mut Self {
        self.commands.push(Command::Raw { name, args });
        self
    }

    /// Queues `GETSET`.
    ///
    /// Commands: Redis `GETSET`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.getset(b"key", b"new");
    /// ```
    pub fn getset(&mut self, key: &'a [u8], value: &'a [u8]) -> &mut Self {
        self.commands.push(Command::GetSet { key, value });
        self
    }

    /// Queues `SETNX`.
    ///
    /// Commands: Redis `SETNX`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.setnx(b"key", b"value");
    /// ```
    pub fn setnx(&mut self, key: &'a [u8], value: &'a [u8]) -> &mut Self {
        self.commands.push(Command::SetNx { key, value });
        self
    }

    /// Queues `SETEX` with a seconds-level expiration.
    ///
    /// Commands: Redis `SETEX`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.setex(b"key", 30, b"value");
    /// ```
    pub fn setex(&mut self, key: &'a [u8], seconds: u64, value: &'a [u8]) -> &mut Self {
        self.commands.push(Command::SetEx {
            key,
            seconds,
            value,
        });
        self
    }

    /// Queues `PSETEX` with a millisecond-level expiration.
    ///
    /// Commands: Redis `PSETEX`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.psetex(b"key", 500, b"value");
    /// ```
    pub fn psetex(&mut self, key: &'a [u8], milliseconds: u128, value: &'a [u8]) -> &mut Self {
        self.commands.push(Command::PSetEx {
            key,
            milliseconds,
            value,
        });
        self
    }

    /// Queues `MGET` for multiple keys.
    ///
    /// Commands: Redis `MGET`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.mget(vec![b"a".as_slice(), b"b".as_slice()]);
    /// ```
    pub fn mget(&mut self, keys: Vec<&'a [u8]>) -> &mut Self {
        self.commands.push(Command::MGet { keys });
        self
    }

    /// Queues `MSET` for multiple key/value pairs.
    ///
    /// Commands: Redis `MSET`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.mset(vec![(b"a".as_slice(), b"1".as_slice())]);
    /// ```
    pub fn mset(&mut self, pairs: Vec<(&'a [u8], &'a [u8])>) -> &mut Self {
        self.commands.push(Command::MSet { pairs });
        self
    }

    /// Queues `APPEND`.
    ///
    /// Commands: Redis `APPEND`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.append(b"key", b"tail");
    /// ```
    pub fn append(&mut self, key: &'a [u8], value: &'a [u8]) -> &mut Self {
        self.commands.push(Command::Append { key, value });
        self
    }

    /// Queues `STRLEN`.
    ///
    /// Commands: Redis `STRLEN`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.strlen(b"key");
    /// ```
    pub fn strlen(&mut self, key: &'a [u8]) -> &mut Self {
        self.commands.push(Command::StrLen { key });
        self
    }

    /// Queues `INCR`.
    ///
    /// Commands: Redis `INCR`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.incr(b"counter");
    /// ```
    pub fn incr(&mut self, key: &'a [u8]) -> &mut Self {
        self.commands.push(Command::Incr { key });
        self
    }

    /// Queues `DECR`.
    ///
    /// Commands: Redis `DECR`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.decr(b"counter");
    /// ```
    pub fn decr(&mut self, key: &'a [u8]) -> &mut Self {
        self.commands.push(Command::Decr { key });
        self
    }

    /// Queues `INCRBY`.
    ///
    /// Commands: Redis `INCRBY`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.incrby(b"counter", 5);
    /// ```
    pub fn incrby(&mut self, key: &'a [u8], increment: i64) -> &mut Self {
        self.commands.push(Command::IncrBy { key, increment });
        self
    }

    /// Queues `DECRBY`.
    ///
    /// Commands: Redis `DECRBY`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.decrby(b"counter", 5);
    /// ```
    pub fn decrby(&mut self, key: &'a [u8], decrement: i64) -> &mut Self {
        self.commands.push(Command::DecrBy { key, decrement });
        self
    }

    /// Queues `DEL` for one or more keys.
    ///
    /// Commands: Redis `DEL`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.del(vec![b"a".as_slice(), b"b".as_slice()]);
    /// ```
    pub fn del(&mut self, keys: Vec<&'a [u8]>) -> &mut Self {
        self.commands.push(Command::Del { keys });
        self
    }

    /// Queues `EXISTS` for one or more keys.
    ///
    /// Commands: Redis `EXISTS`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.exists(vec![b"a".as_slice(), b"b".as_slice()]);
    /// ```
    pub fn exists(&mut self, keys: Vec<&'a [u8]>) -> &mut Self {
        self.commands.push(Command::Exists { keys });
        self
    }

    /// Queues `EXPIRE` with a seconds-level timeout.
    ///
    /// Commands: Redis `EXPIRE`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.expire(b"key", 60);
    /// ```
    pub fn expire(&mut self, key: &'a [u8], seconds: u64) -> &mut Self {
        self.commands.push(Command::Expire { key, seconds });
        self
    }

    /// Queues `TTL`.
    ///
    /// Commands: Redis `TTL`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.ttl(b"key");
    /// ```
    pub fn ttl(&mut self, key: &'a [u8]) -> &mut Self {
        self.commands.push(Command::Ttl { key });
        self
    }

    /// Queues `PTTL`.
    ///
    /// Commands: Redis `PTTL`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.pttl(b"key");
    /// ```
    pub fn pttl(&mut self, key: &'a [u8]) -> &mut Self {
        self.commands.push(Command::PTtl { key });
        self
    }

    /// Queues `PERSIST`.
    ///
    /// Commands: Redis `PERSIST`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.persist(b"key");
    /// ```
    pub fn persist(&mut self, key: &'a [u8]) -> &mut Self {
        self.commands.push(Command::Persist { key });
        self
    }

    /// Queues `TYPE` for a key.
    ///
    /// Commands: Redis `TYPE`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.key_type(b"key");
    /// ```
    pub fn key_type(&mut self, key: &'a [u8]) -> &mut Self {
        self.commands.push(Command::Type { key });
        self
    }

    /// Queues `LPUSH`.
    ///
    /// Commands: Redis `LPUSH`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.lpush(b"list", vec![b"a".as_slice(), b"b".as_slice()]);
    /// ```
    pub fn lpush(&mut self, key: &'a [u8], values: Vec<&'a [u8]>) -> &mut Self {
        self.commands.push(Command::LPush { key, values });
        self
    }

    /// Queues `RPUSH`.
    ///
    /// Commands: Redis `RPUSH`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.rpush(b"list", vec![b"a".as_slice(), b"b".as_slice()]);
    /// ```
    pub fn rpush(&mut self, key: &'a [u8], values: Vec<&'a [u8]>) -> &mut Self {
        self.commands.push(Command::RPush { key, values });
        self
    }

    /// Queues `LPOP` for one element.
    ///
    /// Commands: Redis `LPOP`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.lpop(b"list");
    /// ```
    pub fn lpop(&mut self, key: &'a [u8]) -> &mut Self {
        self.commands.push(Command::LPop { key });
        self
    }

    /// Queues `RPOP` for one element.
    ///
    /// Commands: Redis `RPOP`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.rpop(b"list");
    /// ```
    pub fn rpop(&mut self, key: &'a [u8]) -> &mut Self {
        self.commands.push(Command::RPop { key });
        self
    }

    /// Queues `LLEN`.
    ///
    /// Commands: Redis `LLEN`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.llen(b"list");
    /// ```
    pub fn llen(&mut self, key: &'a [u8]) -> &mut Self {
        self.commands.push(Command::LLen { key });
        self
    }

    /// Queues `LINDEX`.
    ///
    /// Commands: Redis `LINDEX`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.lindex(b"list", 0);
    /// ```
    pub fn lindex(&mut self, key: &'a [u8], index: i64) -> &mut Self {
        self.commands.push(Command::LIndex { key, index });
        self
    }

    /// Queues `LRANGE`.
    ///
    /// Commands: Redis `LRANGE`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.lrange(b"list", 0, -1);
    /// ```
    pub fn lrange(&mut self, key: &'a [u8], start: i64, stop: i64) -> &mut Self {
        self.commands.push(Command::LRange { key, start, stop });
        self
    }

    /// Queues `HSET` for one field/value pair.
    ///
    /// Commands: Redis `HSET`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.hset(b"hash", b"field", b"value");
    /// ```
    pub fn hset(&mut self, key: &'a [u8], field: &'a [u8], value: &'a [u8]) -> &mut Self {
        self.commands.push(Command::HSet { key, field, value });
        self
    }

    /// Queues `HINCRBY`.
    ///
    /// Commands: Redis `HINCRBY`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.hincrby(b"hash", b"counter", 1);
    /// ```
    pub fn hincrby(&mut self, key: &'a [u8], field: &'a [u8], increment: i64) -> &mut Self {
        self.commands.push(Command::HIncrBy {
            key,
            field,
            increment,
        });
        self
    }

    /// Queues `HGET`.
    ///
    /// Commands: Redis `HGET`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.hget(b"hash", b"field");
    /// ```
    pub fn hget(&mut self, key: &'a [u8], field: &'a [u8]) -> &mut Self {
        self.commands.push(Command::HGet { key, field });
        self
    }

    /// Queues `HMGET`.
    ///
    /// Commands: Redis `HMGET`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.hmget(b"hash", vec![b"a".as_slice(), b"b".as_slice()]);
    /// ```
    pub fn hmget(&mut self, key: &'a [u8], fields: Vec<&'a [u8]>) -> &mut Self {
        self.commands.push(Command::HMGet { key, fields });
        self
    }

    /// Queues `HDEL`.
    ///
    /// Commands: Redis `HDEL`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.hdel(b"hash", vec![b"a".as_slice(), b"b".as_slice()]);
    /// ```
    pub fn hdel(&mut self, key: &'a [u8], fields: Vec<&'a [u8]>) -> &mut Self {
        self.commands.push(Command::HDel { key, fields });
        self
    }

    /// Queues `HEXISTS`.
    ///
    /// Commands: Redis `HEXISTS`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.hexists(b"hash", b"field");
    /// ```
    pub fn hexists(&mut self, key: &'a [u8], field: &'a [u8]) -> &mut Self {
        self.commands.push(Command::HExists { key, field });
        self
    }

    /// Queues `HLEN`.
    ///
    /// Commands: Redis `HLEN`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.hlen(b"hash");
    /// ```
    pub fn hlen(&mut self, key: &'a [u8]) -> &mut Self {
        self.commands.push(Command::HLen { key });
        self
    }

    /// Queues `HGETALL`.
    ///
    /// Commands: Redis `HGETALL`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.hgetall(b"hash");
    /// ```
    pub fn hgetall(&mut self, key: &'a [u8]) -> &mut Self {
        self.commands.push(Command::HGetAll { key });
        self
    }

    /// Queues `SADD`.
    ///
    /// Commands: Redis `SADD`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.sadd(b"set", vec![b"a".as_slice(), b"b".as_slice()]);
    /// ```
    pub fn sadd(&mut self, key: &'a [u8], members: Vec<&'a [u8]>) -> &mut Self {
        self.commands.push(Command::SAdd { key, members });
        self
    }

    /// Queues `SREM`.
    ///
    /// Commands: Redis `SREM`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.srem(b"set", vec![b"a".as_slice(), b"b".as_slice()]);
    /// ```
    pub fn srem(&mut self, key: &'a [u8], members: Vec<&'a [u8]>) -> &mut Self {
        self.commands.push(Command::SRem { key, members });
        self
    }

    /// Queues `SMEMBERS`.
    ///
    /// Commands: Redis `SMEMBERS`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.smembers(b"set");
    /// ```
    pub fn smembers(&mut self, key: &'a [u8]) -> &mut Self {
        self.commands.push(Command::SMembers { key });
        self
    }

    /// Queues `SISMEMBER`.
    ///
    /// Commands: Redis `SISMEMBER`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.sismember(b"set", b"a");
    /// ```
    pub fn sismember(&mut self, key: &'a [u8], member: &'a [u8]) -> &mut Self {
        self.commands.push(Command::SIsMember { key, member });
        self
    }

    /// Queues `SCARD`.
    ///
    /// Commands: Redis `SCARD`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.scard(b"set");
    /// ```
    pub fn scard(&mut self, key: &'a [u8]) -> &mut Self {
        self.commands.push(Command::SCard { key });
        self
    }

    /// Queues `SPOP` for one member.
    ///
    /// Commands: Redis `SPOP`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.spop(b"set");
    /// ```
    pub fn spop(&mut self, key: &'a [u8]) -> &mut Self {
        self.commands.push(Command::SPop { key });
        self
    }

    /// Queues `SUNION`.
    ///
    /// Commands: Redis `SUNION`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.sunion(vec![b"set:a".as_slice(), b"set:b".as_slice()]);
    /// ```
    pub fn sunion(&mut self, keys: Vec<&'a [u8]>) -> &mut Self {
        self.commands.push(Command::SUnion { keys });
        self
    }

    /// Queues `SINTER`.
    ///
    /// Commands: Redis `SINTER`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.sinter(vec![b"set:a".as_slice(), b"set:b".as_slice()]);
    /// ```
    pub fn sinter(&mut self, keys: Vec<&'a [u8]>) -> &mut Self {
        self.commands.push(Command::SInter { keys });
        self
    }

    /// Queues `SDIFF`.
    ///
    /// Commands: Redis `SDIFF`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.sdiff(vec![b"set:a".as_slice(), b"set:b".as_slice()]);
    /// ```
    pub fn sdiff(&mut self, keys: Vec<&'a [u8]>) -> &mut Self {
        self.commands.push(Command::SDiff { keys });
        self
    }

    /// Queues `ZADD` for one score/member pair.
    ///
    /// Commands: Redis `ZADD`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.zadd(b"zset", 1.0, b"member");
    /// ```
    pub fn zadd(&mut self, key: &'a [u8], score: f64, member: &'a [u8]) -> &mut Self {
        self.commands.push(Command::ZAdd { key, score, member });
        self
    }

    /// Queues `ZREM`.
    ///
    /// Commands: Redis `ZREM`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.zrem(b"zset", vec![b"a".as_slice(), b"b".as_slice()]);
    /// ```
    pub fn zrem(&mut self, key: &'a [u8], members: Vec<&'a [u8]>) -> &mut Self {
        self.commands.push(Command::ZRem { key, members });
        self
    }

    /// Queues `ZCARD`.
    ///
    /// Commands: Redis `ZCARD`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.zcard(b"zset");
    /// ```
    pub fn zcard(&mut self, key: &'a [u8]) -> &mut Self {
        self.commands.push(Command::ZCard { key });
        self
    }

    /// Queues `ZSCORE`.
    ///
    /// Commands: Redis `ZSCORE`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.zscore(b"zset", b"member");
    /// ```
    pub fn zscore(&mut self, key: &'a [u8], member: &'a [u8]) -> &mut Self {
        self.commands.push(Command::ZScore { key, member });
        self
    }

    /// Queues `ZINCRBY`.
    ///
    /// Commands: Redis `ZINCRBY`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.zincrby(b"zset", 1.5, b"member");
    /// ```
    pub fn zincrby(&mut self, key: &'a [u8], increment: f64, member: &'a [u8]) -> &mut Self {
        self.commands.push(Command::ZIncrBy {
            key,
            increment,
            member,
        });
        self
    }

    /// Queues `ZCOUNT`.
    ///
    /// Commands: Redis `ZCOUNT`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.zcount(b"zset", b"0", b"+inf");
    /// ```
    pub fn zcount(&mut self, key: &'a [u8], min: &'a [u8], max: &'a [u8]) -> &mut Self {
        self.commands.push(Command::ZCount { key, min, max });
        self
    }

    /// Queues `ZRANGE`, optionally with scores.
    ///
    /// Commands: Redis `ZRANGE` and `ZRANGE ... WITHSCORES`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.zrange(b"zset", 0, -1, false);
    /// ```
    pub fn zrange(&mut self, key: &'a [u8], start: i64, stop: i64, with_scores: bool) -> &mut Self {
        self.commands.push(Command::ZRange {
            key,
            start,
            stop,
            with_scores,
        });
        self
    }

    /// Queues `GEOADD`.
    ///
    /// Commands: Redis `GEOADD`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.geoadd(b"geo", vec![lux::GeoMember { longitude: 13.36, latitude: 38.11, member: "Palermo" }]);
    /// ```
    pub fn geoadd(&mut self, key: &'a [u8], members: Vec<GeoMember<'a>>) -> &mut Self {
        self.commands.push(Command::GeoAdd {
            key,
            members: members
                .into_iter()
                .map(|member| command::GeoAddMember {
                    longitude: member.longitude,
                    latitude: member.latitude,
                    member: member.member.as_bytes(),
                })
                .collect(),
        });
        self
    }

    /// Queues `GEOPOS`.
    ///
    /// Commands: Redis `GEOPOS`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.geopos(b"geo", vec![b"Palermo".as_slice()]);
    /// ```
    pub fn geopos(&mut self, key: &'a [u8], members: Vec<&'a [u8]>) -> &mut Self {
        self.commands.push(Command::GeoPos { key, members });
        self
    }

    /// Queues `GEODIST`.
    ///
    /// Commands: Redis `GEODIST`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.geodist(b"geo", b"Palermo", b"Catania", lux::GeoUnit::Km);
    /// ```
    pub fn geodist(
        &mut self,
        key: &'a [u8],
        member_a: &'a [u8],
        member_b: &'a [u8],
        unit: GeoUnit,
    ) -> &mut Self {
        self.commands.push(Command::GeoDist {
            key,
            member_a,
            member_b,
            unit: unit.as_bytes(),
        });
        self
    }

    /// Queues simple-form `XADD`.
    ///
    /// Commands: Redis `XADD key id field value ...`.
    ///
    /// Example:
    /// ```rust,ignore
    /// pipe.xadd(b"stream", b"*", vec![(b"field".as_slice(), b"value".as_slice())]);
    /// ```
    pub fn xadd(
        &mut self,
        key: &'a [u8],
        id: &'a [u8],
        fields: Vec<(&'a [u8], &'a [u8])>,
    ) -> &mut Self {
        self.commands.push(Command::XAdd { key, id, fields });
        self
    }
}

impl SetOptions {
    pub fn ex(mut self, seconds: u64) -> Self {
        self.expiration = Some(SetExpiration::Ex(seconds));
        self
    }

    pub fn px(mut self, milliseconds: u64) -> Self {
        self.expiration = Some(SetExpiration::Px(milliseconds));
        self
    }

    pub fn nx(mut self) -> Self {
        self.condition = Some(SetCondition::Nx);
        self
    }

    pub fn xx(mut self) -> Self {
        self.condition = Some(SetCondition::Xx);
        self
    }

    pub fn keep_ttl(mut self) -> Self {
        self.keep_ttl = true;
        self
    }

    fn command_options(&self) -> Vec<command::SetOption> {
        let mut options = Vec::new();
        match self.expiration {
            Some(SetExpiration::Ex(seconds)) => options.push(command::SetOption::Ex(seconds)),
            Some(SetExpiration::Px(milliseconds)) => {
                options.push(command::SetOption::Px(milliseconds as u128))
            }
            None => {}
        }
        match self.condition {
            Some(SetCondition::Nx) => options.push(command::SetOption::Nx),
            Some(SetCondition::Xx) => options.push(command::SetOption::Xx),
            None => {}
        }
        if self.keep_ttl {
            options.push(command::SetOption::KeepTtl);
        }
        options
    }
}

impl EmbeddedClient {
    /// Executes `PING` and returns the simple string reply.
    ///
    /// Commands: Redis `PING`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let pong = client.ping().await?;
    /// ```
    pub async fn ping(&self) -> Result<String, LuxError> {
        simple_string(self.exec(Command::Ping).await?)
    }

    /// Publishes a message to a channel and returns the subscriber count.
    ///
    /// Commands: Redis `PUBLISH`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let delivered = client.publish("events", "payload").await?;
    /// ```
    pub async fn publish(&self, channel: &str, message: &str) -> Result<usize, LuxError> {
        usize_value(
            self.exec(Command::Publish {
                channel: channel.as_bytes(),
                message: message.as_bytes(),
            })
            .await?,
        )
    }

    /// Returns the number of keys in the current embedded database.
    ///
    /// Commands: Redis `DBSIZE`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let keys = client.dbsize().await?;
    /// ```
    pub async fn dbsize(&self) -> Result<usize, LuxError> {
        usize_value(self.exec(Command::DbSize).await?)
    }

    /// Removes all keys from the current embedded database.
    ///
    /// Commands: Redis `FLUSHDB`.
    ///
    /// Example:
    /// ```rust,ignore
    /// client.flushdb().await?;
    /// ```
    pub async fn flushdb(&self) -> Result<(), LuxError> {
        ok(self.exec(Command::FlushDb).await?)
    }

    /// Removes all keys from the embedded runtime.
    ///
    /// Commands: Redis `FLUSHALL`.
    ///
    /// Example:
    /// ```rust,ignore
    /// client.flushall().await?;
    /// ```
    pub async fn flushall(&self) -> Result<(), LuxError> {
        ok(self.exec(Command::FlushAll).await?)
    }

    /// Returns keys matching a glob pattern.
    ///
    /// Commands: Redis `KEYS`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let keys = client.keys("user:*").await?;
    /// ```
    pub async fn keys(&self, pattern: &str) -> Result<Vec<String>, LuxError> {
        string_vec(
            self.exec(Command::Keys {
                pattern: pattern.as_bytes(),
            })
            .await?,
        )
    }

    /// Returns an arbitrary key, if the database is not empty.
    ///
    /// Commands: Redis `RANDOMKEY`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let key = client.randomkey().await?;
    /// ```
    pub async fn randomkey(&self) -> Result<Option<Bytes>, LuxError> {
        optional_bulk(self.exec(Command::RandomKey).await?)
    }

    /// Gets the bytes stored at a key.
    ///
    /// Commands: Redis `GET`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let value = client.get("key").await?;
    /// ```
    pub async fn get<K>(&self, key: K) -> Result<Option<Bytes>, LuxError>
    where
        K: AsRef<[u8]>,
    {
        optional_bulk(self.exec(Command::Get { key: key.as_ref() }).await?)
    }

    /// Sets a key to a byte value and reports whether Redis returned `OK`.
    ///
    /// Commands: Redis `SET` without options.
    ///
    /// Example:
    /// ```rust,ignore
    /// let stored = client.set("key", "value").await?;
    /// ```
    pub async fn set<K, V>(&self, key: K, value: V) -> Result<bool, LuxError>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.set_options(key, value, SetOptions::default()).await
    }

    /// Sets a key only when it does not already exist.
    ///
    /// Commands: Redis `SETNX`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let inserted = client.setnx("key", "value").await?;
    /// ```
    pub async fn setnx<K, V>(&self, key: K, value: V) -> Result<bool, LuxError>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        bool_int(
            self.exec(Command::SetNx {
                key: key.as_ref(),
                value: value.as_ref(),
            })
            .await?,
        )
    }

    /// Sets a key with a seconds-level expiration.
    ///
    /// Commands: Redis `SETEX`.
    ///
    /// Example:
    /// ```rust,ignore
    /// client.setex("key", std::time::Duration::from_secs(30), "value").await?;
    /// ```
    pub async fn setex<K, V>(&self, key: K, timeout: Duration, value: V) -> Result<(), LuxError>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        ok(self
            .exec(Command::SetEx {
                key: key.as_ref(),
                seconds: timeout.as_secs(),
                value: value.as_ref(),
            })
            .await?)
    }

    /// Sets a key with a millisecond-level expiration.
    ///
    /// Commands: Redis `PSETEX`.
    ///
    /// Example:
    /// ```rust,ignore
    /// client.psetex("key", std::time::Duration::from_millis(500), "value").await?;
    /// ```
    pub async fn psetex<K, V>(&self, key: K, timeout: Duration, value: V) -> Result<(), LuxError>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        ok(self
            .exec(Command::PSetEx {
                key: key.as_ref(),
                milliseconds: timeout.as_millis(),
                value: value.as_ref(),
            })
            .await?)
    }

    /// Sets a key with native `SET` options.
    ///
    /// Commands: Redis `SET` with `EX`, `PX`, `NX`, `XX`, or `KEEPTTL` options.
    ///
    /// Example:
    /// ```rust,ignore
    /// let stored = client.set_options("key", "value", lux::SetOptions::default().nx()).await?;
    /// ```
    pub async fn set_options<K, V>(
        &self,
        key: K,
        value: V,
        options: SetOptions,
    ) -> Result<bool, LuxError>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        match self
            .exec(Command::Set {
                key: key.as_ref(),
                value: value.as_ref(),
                options: options.command_options(),
            })
            .await?
        {
            CommandOutput::Nil => Ok(false),
            value => ok(value).map(|_| true),
        }
    }

    /// Executes a borrowed native embedded pipeline and returns parsed values for every command.
    ///
    /// Commands: Redis commands queued through `EmbeddedPipeline`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let mut pipe = lux::EmbeddedPipeline::new();
    /// pipe.set(b"key", b"value").get(b"key");
    /// let values = client.execute_embedded_pipeline(&pipe).await?;
    /// ```
    pub async fn execute_embedded_pipeline(
        &self,
        pipeline: &EmbeddedPipeline<'_>,
    ) -> Result<Vec<EmbeddedValue>, LuxError> {
        self.execute_command_pipeline_outputs(&pipeline.commands)
            .await?
            .into_iter()
            .map(command_output_to_embedded_value)
            .collect()
    }

    /// Executes a borrowed native embedded pipeline and discards command replies.
    ///
    /// Commands: Redis commands queued through `EmbeddedPipeline`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let mut pipe = lux::EmbeddedPipeline::new();
    /// pipe.set(b"key", b"value");
    /// client.execute_embedded_pipeline_discard(&pipe).await?;
    /// ```
    pub async fn execute_embedded_pipeline_discard(
        &self,
        pipeline: &EmbeddedPipeline<'_>,
    ) -> Result<(), LuxError> {
        self.execute_command_pipeline_discard(&pipeline.commands)
            .await
    }

    /// Executes a reusable prepared embedded pipeline and returns parsed values for every command.
    ///
    /// Commands: Redis commands queued or parsed through `PreparedPipeline`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let mut pipe = lux::PreparedPipeline::new();
    /// pipe.set("key", "value");
    /// let values = client.execute_prepared_pipeline(&pipe).await?;
    /// ```
    pub async fn execute_prepared_pipeline(
        &self,
        pipeline: &PreparedPipeline,
    ) -> Result<Vec<EmbeddedValue>, LuxError> {
        if let Some(commands) = pipeline.raw_argvs() {
            return self.pipeline_values(&commands).await;
        }

        let commands = pipeline.borrowed_commands();
        self.execute_command_pipeline_outputs(&commands)
            .await?
            .into_iter()
            .map(command_output_to_embedded_value)
            .collect()
    }

    /// Executes a reusable prepared embedded pipeline and discards command replies.
    ///
    /// Commands: Redis commands queued or parsed through `PreparedPipeline`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let mut pipe = lux::PreparedPipeline::new();
    /// pipe.set("key", "value");
    /// client.execute_prepared_pipeline_discard(&pipe).await?;
    /// ```
    pub async fn execute_prepared_pipeline_discard(
        &self,
        pipeline: &PreparedPipeline,
    ) -> Result<(), LuxError> {
        if let Some(commands) = pipeline.raw_argvs() {
            self.pipeline_values(&commands).await?;
            return Ok(());
        }

        let commands = pipeline.borrowed_commands();
        self.execute_command_pipeline_discard(&commands).await
    }

    /// Sets a new value and returns the previous value, if present.
    ///
    /// Commands: Redis `GETSET`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let old = client.getset("key", "new").await?;
    /// ```
    pub async fn getset<K, V>(&self, key: K, value: V) -> Result<Option<Bytes>, LuxError>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        optional_bulk(
            self.exec(Command::GetSet {
                key: key.as_ref(),
                value: value.as_ref(),
            })
            .await?,
        )
    }

    /// Gets multiple keys and preserves `nil` entries as `None`.
    ///
    /// Commands: Redis `MGET`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let values = client.mget(&["a", "b"]).await?;
    /// ```
    pub async fn mget<K>(&self, keys: &[K]) -> Result<Vec<Option<Bytes>>, LuxError>
    where
        K: AsRef<[u8]>,
    {
        optional_bulk_vec(self.exec(Command::MGet { keys: refs(keys) }).await?)
    }

    /// Sets multiple key/value pairs.
    ///
    /// Commands: Redis `MSET`.
    ///
    /// Example:
    /// ```rust,ignore
    /// client.mset(&[("a", "1"), ("b", "2")]).await?;
    /// ```
    pub async fn mset<K, V>(&self, pairs: &[(K, V)]) -> Result<(), LuxError>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        ok(self
            .exec(Command::MSet {
                pairs: pair_refs(pairs),
            })
            .await?)
    }

    /// Sets multiple key/value pairs only when none of the keys already exist.
    ///
    /// Commands: Redis `MSETNX`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let stored = client.msetnx(&[("a", "1"), ("b", "2")]).await?;
    /// ```
    pub async fn msetnx<K, V>(&self, pairs: &[(K, V)]) -> Result<bool, LuxError>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        bool_int(
            self.exec(Command::MSetNx {
                pairs: pair_refs(pairs),
            })
            .await?,
        )
    }

    /// Appends bytes to a string value and returns the new length.
    ///
    /// Commands: Redis `APPEND`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let len = client.append("key", "tail").await?;
    /// ```
    pub async fn append<K, V>(&self, key: K, value: V) -> Result<usize, LuxError>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        usize_value(
            self.exec(Command::Append {
                key: key.as_ref(),
                value: value.as_ref(),
            })
            .await?,
        )
    }

    /// Returns the byte length of a string value.
    ///
    /// Commands: Redis `STRLEN`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let len = client.strlen("key").await?;
    /// ```
    pub async fn strlen<K>(&self, key: K) -> Result<usize, LuxError>
    where
        K: AsRef<[u8]>,
    {
        usize_value(self.exec(Command::StrLen { key: key.as_ref() }).await?)
    }

    /// Increments an integer string value by one.
    ///
    /// Commands: Redis `INCR`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let n = client.incr("counter").await?;
    /// ```
    pub async fn incr<K>(&self, key: K) -> Result<i64, LuxError>
    where
        K: AsRef<[u8]>,
    {
        i64_value(self.exec(Command::Incr { key: key.as_ref() }).await?)
    }

    /// Decrements an integer string value by one.
    ///
    /// Commands: Redis `DECR`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let n = client.decr("counter").await?;
    /// ```
    pub async fn decr<K>(&self, key: K) -> Result<i64, LuxError>
    where
        K: AsRef<[u8]>,
    {
        i64_value(self.exec(Command::Decr { key: key.as_ref() }).await?)
    }

    /// Increments an integer string value by a signed amount.
    ///
    /// Commands: Redis `INCRBY`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let n = client.incrby("counter", 5).await?;
    /// ```
    pub async fn incrby<K>(&self, key: K, increment: i64) -> Result<i64, LuxError>
    where
        K: AsRef<[u8]>,
    {
        i64_value(
            self.exec(Command::IncrBy {
                key: key.as_ref(),
                increment,
            })
            .await?,
        )
    }

    /// Decrements an integer string value by a signed amount.
    ///
    /// Commands: Redis `DECRBY`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let n = client.decrby("counter", 5).await?;
    /// ```
    pub async fn decrby<K>(&self, key: K, decrement: i64) -> Result<i64, LuxError>
    where
        K: AsRef<[u8]>,
    {
        i64_value(
            self.exec(Command::DecrBy {
                key: key.as_ref(),
                decrement,
            })
            .await?,
        )
    }

    /// Deletes one or more keys and returns the number removed.
    ///
    /// Commands: Redis `DEL`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let removed = client.del(&["a", "b"]).await?;
    /// ```
    pub async fn del<K>(&self, keys: &[K]) -> Result<usize, LuxError>
    where
        K: AsRef<[u8]>,
    {
        usize_value(self.exec(Command::Del { keys: refs(keys) }).await?)
    }

    /// Asynchronously unlinks one or more keys and returns the number removed.
    ///
    /// Commands: Redis `UNLINK`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let removed = client.unlink(&["a", "b"]).await?;
    /// ```
    pub async fn unlink<K>(&self, keys: &[K]) -> Result<usize, LuxError>
    where
        K: AsRef<[u8]>,
    {
        usize_value(self.exec(Command::Unlink { keys: refs(keys) }).await?)
    }

    /// Counts how many of the supplied keys exist.
    ///
    /// Commands: Redis `EXISTS`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let count = client.exists(&["a", "b"]).await?;
    /// ```
    pub async fn exists<K>(&self, keys: &[K]) -> Result<usize, LuxError>
    where
        K: AsRef<[u8]>,
    {
        usize_value(self.exec(Command::Exists { keys: refs(keys) }).await?)
    }

    /// Sets a seconds-level key expiration.
    ///
    /// Commands: Redis `EXPIRE`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let changed = client.expire("key", std::time::Duration::from_secs(60)).await?;
    /// ```
    pub async fn expire<K>(&self, key: K, timeout: Duration) -> Result<bool, LuxError>
    where
        K: AsRef<[u8]>,
    {
        bool_int(
            self.exec(Command::Expire {
                key: key.as_ref(),
                seconds: timeout.as_secs(),
            })
            .await?,
        )
    }

    /// Returns the remaining key TTL in seconds.
    ///
    /// Commands: Redis `TTL`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let ttl = client.ttl("key").await?;
    /// ```
    pub async fn ttl<K>(&self, key: K) -> Result<i64, LuxError>
    where
        K: AsRef<[u8]>,
    {
        i64_value(self.exec(Command::Ttl { key: key.as_ref() }).await?)
    }

    /// Returns the remaining key TTL in milliseconds.
    ///
    /// Commands: Redis `PTTL`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let ttl = client.pttl("key").await?;
    /// ```
    pub async fn pttl<K>(&self, key: K) -> Result<i64, LuxError>
    where
        K: AsRef<[u8]>,
    {
        i64_value(self.exec(Command::PTtl { key: key.as_ref() }).await?)
    }

    /// Removes a key expiration.
    ///
    /// Commands: Redis `PERSIST`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let changed = client.persist("key").await?;
    /// ```
    pub async fn persist<K>(&self, key: K) -> Result<bool, LuxError>
    where
        K: AsRef<[u8]>,
    {
        bool_int(self.exec(Command::Persist { key: key.as_ref() }).await?)
    }

    /// Returns the Redis type of a key.
    ///
    /// Commands: Redis `TYPE`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let kind = client.key_type("key").await?;
    /// ```
    pub async fn key_type<K>(&self, key: K) -> Result<RedisKeyType, LuxError>
    where
        K: AsRef<[u8]>,
    {
        let value = simple_string(self.exec(Command::Type { key: key.as_ref() }).await?)?;
        Ok(match value.as_str() {
            "string" => RedisKeyType::String,
            "list" => RedisKeyType::List,
            "set" => RedisKeyType::Set,
            "zset" => RedisKeyType::ZSet,
            "hash" => RedisKeyType::Hash,
            "stream" => RedisKeyType::Stream,
            "none" => RedisKeyType::None,
            _ => RedisKeyType::Other,
        })
    }

    /// Renames a key.
    ///
    /// Commands: Redis `RENAME`.
    ///
    /// Example:
    /// ```rust,ignore
    /// client.rename("old", "new").await?;
    /// ```
    pub async fn rename<K, N>(&self, key: K, new_key: N) -> Result<(), LuxError>
    where
        K: AsRef<[u8]>,
        N: AsRef<[u8]>,
    {
        ok(self
            .exec(Command::Rename {
                key: key.as_ref(),
                new_key: new_key.as_ref(),
            })
            .await?)
    }

    /// Renames a key only if the destination does not exist.
    ///
    /// Commands: Redis `RENAMENX`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let changed = client.renamenx("old", "new").await?;
    /// ```
    pub async fn renamenx<K, N>(&self, key: K, new_key: N) -> Result<bool, LuxError>
    where
        K: AsRef<[u8]>,
        N: AsRef<[u8]>,
    {
        bool_int(
            self.exec(Command::RenameNx {
                key: key.as_ref(),
                new_key: new_key.as_ref(),
            })
            .await?,
        )
    }

    /// Pushes one or more values to the left side of a list.
    ///
    /// Commands: Redis `LPUSH`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let len = client.lpush("list", &["a", "b"]).await?;
    /// ```
    pub async fn lpush<K, V>(&self, key: K, values: &[V]) -> Result<usize, LuxError>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        usize_value(
            self.exec(Command::LPush {
                key: key.as_ref(),
                values: refs(values),
            })
            .await?,
        )
    }

    /// Pushes one or more values to the right side of a list.
    ///
    /// Commands: Redis `RPUSH`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let len = client.rpush("list", &["a", "b"]).await?;
    /// ```
    pub async fn rpush<K, V>(&self, key: K, values: &[V]) -> Result<usize, LuxError>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        usize_value(
            self.exec(Command::RPush {
                key: key.as_ref(),
                values: refs(values),
            })
            .await?,
        )
    }

    /// Pops one value from the left side of a list.
    ///
    /// Commands: Redis `LPOP`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let value = client.lpop("list").await?;
    /// ```
    pub async fn lpop<K>(&self, key: K) -> Result<Option<Bytes>, LuxError>
    where
        K: AsRef<[u8]>,
    {
        optional_bulk(self.exec(Command::LPop { key: key.as_ref() }).await?)
    }

    /// Pops one value from the right side of a list.
    ///
    /// Commands: Redis `RPOP`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let value = client.rpop("list").await?;
    /// ```
    pub async fn rpop<K>(&self, key: K) -> Result<Option<Bytes>, LuxError>
    where
        K: AsRef<[u8]>,
    {
        optional_bulk(self.exec(Command::RPop { key: key.as_ref() }).await?)
    }

    /// Returns the length of a list.
    ///
    /// Commands: Redis `LLEN`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let len = client.llen("list").await?;
    /// ```
    pub async fn llen<K>(&self, key: K) -> Result<usize, LuxError>
    where
        K: AsRef<[u8]>,
    {
        usize_value(self.exec(Command::LLen { key: key.as_ref() }).await?)
    }

    /// Returns the list element at an index.
    ///
    /// Commands: Redis `LINDEX`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let value = client.lindex("list", 0).await?;
    /// ```
    pub async fn lindex<K>(&self, key: K, index: i64) -> Result<Option<Bytes>, LuxError>
    where
        K: AsRef<[u8]>,
    {
        optional_bulk(
            self.exec(Command::LIndex {
                key: key.as_ref(),
                index,
            })
            .await?,
        )
    }

    /// Returns a range of list elements.
    ///
    /// Commands: Redis `LRANGE`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let values = client.lrange("list", 0, -1).await?;
    /// ```
    pub async fn lrange<K>(&self, key: K, start: i64, stop: i64) -> Result<Vec<Bytes>, LuxError>
    where
        K: AsRef<[u8]>,
    {
        bulk_vec(
            self.exec(Command::LRange {
                key: key.as_ref(),
                start,
                stop,
            })
            .await?,
        )
    }

    /// Sets one hash field and returns whether it was newly added.
    ///
    /// Commands: Redis `HSET` for a single field/value pair.
    ///
    /// Example:
    /// ```rust,ignore
    /// let added = client.hset("hash", "field", "value").await?;
    /// ```
    pub async fn hset<K, F, V>(&self, key: K, field: F, value: V) -> Result<usize, LuxError>
    where
        K: AsRef<[u8]>,
        F: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        usize_value(
            self.exec(Command::HSet {
                key: key.as_ref(),
                field: field.as_ref(),
                value: value.as_ref(),
            })
            .await?,
        )
    }

    /// Increments an integer hash field by a signed amount.
    ///
    /// Commands: Redis `HINCRBY`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let n = client.hincrby("hash", "counter", 1).await?;
    /// ```
    pub async fn hincrby<K, F>(&self, key: K, field: F, increment: i64) -> Result<i64, LuxError>
    where
        K: AsRef<[u8]>,
        F: AsRef<[u8]>,
    {
        i64_value(
            self.exec(Command::HIncrBy {
                key: key.as_ref(),
                field: field.as_ref(),
                increment,
            })
            .await?,
        )
    }

    /// Gets one hash field.
    ///
    /// Commands: Redis `HGET`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let value = client.hget("hash", "field").await?;
    /// ```
    pub async fn hget<K, F>(&self, key: K, field: F) -> Result<Option<Bytes>, LuxError>
    where
        K: AsRef<[u8]>,
        F: AsRef<[u8]>,
    {
        optional_bulk(
            self.exec(Command::HGet {
                key: key.as_ref(),
                field: field.as_ref(),
            })
            .await?,
        )
    }

    /// Gets multiple hash fields and preserves missing fields as `None`.
    ///
    /// Commands: Redis `HMGET`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let values = client.hmget("hash", &["a", "b"]).await?;
    /// ```
    pub async fn hmget<K, F>(&self, key: K, fields: &[F]) -> Result<Vec<Option<Bytes>>, LuxError>
    where
        K: AsRef<[u8]>,
        F: AsRef<[u8]>,
    {
        optional_bulk_vec(
            self.exec(Command::HMGet {
                key: key.as_ref(),
                fields: refs(fields),
            })
            .await?,
        )
    }

    /// Deletes one or more hash fields.
    ///
    /// Commands: Redis `HDEL`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let removed = client.hdel("hash", &["a", "b"]).await?;
    /// ```
    pub async fn hdel<K, F>(&self, key: K, fields: &[F]) -> Result<usize, LuxError>
    where
        K: AsRef<[u8]>,
        F: AsRef<[u8]>,
    {
        usize_value(
            self.exec(Command::HDel {
                key: key.as_ref(),
                fields: refs(fields),
            })
            .await?,
        )
    }

    /// Checks whether a hash field exists.
    ///
    /// Commands: Redis `HEXISTS`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let exists = client.hexists("hash", "field").await?;
    /// ```
    pub async fn hexists<K, F>(&self, key: K, field: F) -> Result<bool, LuxError>
    where
        K: AsRef<[u8]>,
        F: AsRef<[u8]>,
    {
        bool_int(
            self.exec(Command::HExists {
                key: key.as_ref(),
                field: field.as_ref(),
            })
            .await?,
        )
    }

    /// Returns the number of fields in a hash.
    ///
    /// Commands: Redis `HLEN`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let len = client.hlen("hash").await?;
    /// ```
    pub async fn hlen<K>(&self, key: K) -> Result<usize, LuxError>
    where
        K: AsRef<[u8]>,
    {
        usize_value(self.exec(Command::HLen { key: key.as_ref() }).await?)
    }

    /// Returns all field/value pairs from a hash.
    ///
    /// Commands: Redis `HGETALL`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let pairs = client.hgetall("hash").await?;
    /// ```
    pub async fn hgetall<K>(&self, key: K) -> Result<Vec<(Bytes, Bytes)>, LuxError>
    where
        K: AsRef<[u8]>,
    {
        pair_bulk_vec(self.exec(Command::HGetAll { key: key.as_ref() }).await?)
    }

    /// Adds one or more set members.
    ///
    /// Commands: Redis `SADD`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let added = client.sadd("set", &["a", "b"]).await?;
    /// ```
    pub async fn sadd<K, M>(&self, key: K, members: &[M]) -> Result<usize, LuxError>
    where
        K: AsRef<[u8]>,
        M: AsRef<[u8]>,
    {
        usize_value(
            self.exec(Command::SAdd {
                key: key.as_ref(),
                members: refs(members),
            })
            .await?,
        )
    }

    /// Removes one or more set members.
    ///
    /// Commands: Redis `SREM`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let removed = client.srem("set", &["a", "b"]).await?;
    /// ```
    pub async fn srem<K, M>(&self, key: K, members: &[M]) -> Result<usize, LuxError>
    where
        K: AsRef<[u8]>,
        M: AsRef<[u8]>,
    {
        usize_value(
            self.exec(Command::SRem {
                key: key.as_ref(),
                members: refs(members),
            })
            .await?,
        )
    }

    /// Returns all members of a set.
    ///
    /// Commands: Redis `SMEMBERS`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let members = client.smembers("set").await?;
    /// ```
    pub async fn smembers<K>(&self, key: K) -> Result<Vec<Bytes>, LuxError>
    where
        K: AsRef<[u8]>,
    {
        bulk_vec(self.exec(Command::SMembers { key: key.as_ref() }).await?)
    }

    /// Checks whether a value is a member of a set.
    ///
    /// Commands: Redis `SISMEMBER`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let member = client.sismember("set", "a").await?;
    /// ```
    pub async fn sismember<K, M>(&self, key: K, member: M) -> Result<bool, LuxError>
    where
        K: AsRef<[u8]>,
        M: AsRef<[u8]>,
    {
        bool_int(
            self.exec(Command::SIsMember {
                key: key.as_ref(),
                member: member.as_ref(),
            })
            .await?,
        )
    }

    /// Returns the number of members in a set.
    ///
    /// Commands: Redis `SCARD`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let len = client.scard("set").await?;
    /// ```
    pub async fn scard<K>(&self, key: K) -> Result<usize, LuxError>
    where
        K: AsRef<[u8]>,
    {
        usize_value(self.exec(Command::SCard { key: key.as_ref() }).await?)
    }

    /// Removes and returns one random set member.
    ///
    /// Commands: Redis `SPOP` for one member.
    ///
    /// Example:
    /// ```rust,ignore
    /// let member = client.spop("set").await?;
    /// ```
    pub async fn spop<K>(&self, key: K) -> Result<Option<Bytes>, LuxError>
    where
        K: AsRef<[u8]>,
    {
        optional_bulk(self.exec(Command::SPop { key: key.as_ref() }).await?)
    }

    /// Returns the union of one or more sets.
    ///
    /// Commands: Redis `SUNION`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let members = client.sunion(&["set:a", "set:b"]).await?;
    /// ```
    pub async fn sunion<K>(&self, keys: &[K]) -> Result<Vec<Bytes>, LuxError>
    where
        K: AsRef<[u8]>,
    {
        bulk_vec(self.exec(Command::SUnion { keys: refs(keys) }).await?)
    }

    /// Returns the intersection of one or more sets.
    ///
    /// Commands: Redis `SINTER`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let members = client.sinter(&["set:a", "set:b"]).await?;
    /// ```
    pub async fn sinter<K>(&self, keys: &[K]) -> Result<Vec<Bytes>, LuxError>
    where
        K: AsRef<[u8]>,
    {
        bulk_vec(self.exec(Command::SInter { keys: refs(keys) }).await?)
    }

    /// Returns the difference of one or more sets.
    ///
    /// Commands: Redis `SDIFF`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let members = client.sdiff(&["set:a", "set:b"]).await?;
    /// ```
    pub async fn sdiff<K>(&self, keys: &[K]) -> Result<Vec<Bytes>, LuxError>
    where
        K: AsRef<[u8]>,
    {
        bulk_vec(self.exec(Command::SDiff { keys: refs(keys) }).await?)
    }

    /// Adds or updates one sorted-set member.
    ///
    /// Commands: Redis `ZADD` for one score/member pair.
    ///
    /// Example:
    /// ```rust,ignore
    /// let added = client.zadd("zset", 1.0, "member").await?;
    /// ```
    pub async fn zadd<K, M>(&self, key: K, score: f64, member: M) -> Result<usize, LuxError>
    where
        K: AsRef<[u8]>,
        M: AsRef<[u8]>,
    {
        usize_value(
            self.exec(Command::ZAdd {
                key: key.as_ref(),
                score,
                member: member.as_ref(),
            })
            .await?,
        )
    }

    /// Removes one or more sorted-set members.
    ///
    /// Commands: Redis `ZREM`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let removed = client.zrem("zset", &["a", "b"]).await?;
    /// ```
    pub async fn zrem<K, M>(&self, key: K, members: &[M]) -> Result<usize, LuxError>
    where
        K: AsRef<[u8]>,
        M: AsRef<[u8]>,
    {
        usize_value(
            self.exec(Command::ZRem {
                key: key.as_ref(),
                members: refs(members),
            })
            .await?,
        )
    }

    /// Returns the number of members in a sorted set.
    ///
    /// Commands: Redis `ZCARD`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let len = client.zcard("zset").await?;
    /// ```
    pub async fn zcard<K>(&self, key: K) -> Result<usize, LuxError>
    where
        K: AsRef<[u8]>,
    {
        usize_value(self.exec(Command::ZCard { key: key.as_ref() }).await?)
    }

    /// Returns the score for a sorted-set member.
    ///
    /// Commands: Redis `ZSCORE`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let score = client.zscore("zset", "member").await?;
    /// ```
    pub async fn zscore<K, M>(&self, key: K, member: M) -> Result<Option<f64>, LuxError>
    where
        K: AsRef<[u8]>,
        M: AsRef<[u8]>,
    {
        optional_f64(
            self.exec(Command::ZScore {
                key: key.as_ref(),
                member: member.as_ref(),
            })
            .await?,
        )
    }

    /// Increments a sorted-set member score.
    ///
    /// Commands: Redis `ZINCRBY`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let score = client.zincrby("zset", 1.5, "member").await?;
    /// ```
    pub async fn zincrby<K, M>(&self, key: K, increment: f64, member: M) -> Result<f64, LuxError>
    where
        K: AsRef<[u8]>,
        M: AsRef<[u8]>,
    {
        let value = required_bulk(
            self.exec(Command::ZIncrBy {
                key: key.as_ref(),
                increment,
                member: member.as_ref(),
            })
            .await?,
        )?;
        parse_f64(&value)
    }

    /// Counts sorted-set members with scores in a range.
    ///
    /// Commands: Redis `ZCOUNT`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let count = client.zcount("zset", "0", "+inf").await?;
    /// ```
    pub async fn zcount<K>(&self, key: K, min: &str, max: &str) -> Result<usize, LuxError>
    where
        K: AsRef<[u8]>,
    {
        usize_value(
            self.exec(Command::ZCount {
                key: key.as_ref(),
                min: min.as_bytes(),
                max: max.as_bytes(),
            })
            .await?,
        )
    }

    /// Returns sorted-set members in an index range.
    ///
    /// Commands: Redis `ZRANGE` without `WITHSCORES`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let members = client.zrange("zset", 0, -1).await?;
    /// ```
    pub async fn zrange<K>(&self, key: K, start: i64, stop: i64) -> Result<Vec<Bytes>, LuxError>
    where
        K: AsRef<[u8]>,
    {
        bulk_vec(
            self.exec(Command::ZRange {
                key: key.as_ref(),
                start,
                stop,
                with_scores: false,
            })
            .await?,
        )
    }

    /// Returns sorted-set members and scores in an index range.
    ///
    /// Commands: Redis `ZRANGE ... WITHSCORES`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let members = client.zrange_withscores("zset", 0, -1).await?;
    /// ```
    pub async fn zrange_withscores<K>(
        &self,
        key: K,
        start: i64,
        stop: i64,
    ) -> Result<Vec<ScoredMember>, LuxError>
    where
        K: AsRef<[u8]>,
    {
        scored_members(
            self.exec(Command::ZRange {
                key: key.as_ref(),
                start,
                stop,
                with_scores: true,
            })
            .await?,
        )
    }

    /// Adds geospatial members to a sorted set.
    ///
    /// Commands: Redis `GEOADD`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let added = client.geoadd("geo", &[lux::GeoMember { longitude: 13.36, latitude: 38.11, member: "Palermo" }]).await?;
    /// ```
    pub async fn geoadd(&self, key: &str, members: &[GeoMember<'_>]) -> Result<usize, LuxError> {
        usize_value(
            self.exec(Command::GeoAdd {
                key: key.as_bytes(),
                members: members
                    .iter()
                    .map(|member| command::GeoAddMember {
                        longitude: member.longitude,
                        latitude: member.latitude,
                        member: member.member.as_bytes(),
                    })
                    .collect(),
            })
            .await?,
        )
    }

    /// Returns geospatial positions for members.
    ///
    /// Commands: Redis `GEOPOS`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let positions = client.geopos("geo", &["Palermo"]).await?;
    /// ```
    pub async fn geopos(
        &self,
        key: &str,
        members: &[&str],
    ) -> Result<Vec<Option<GeoPosition>>, LuxError> {
        geo_positions(
            self.exec(Command::GeoPos {
                key: key.as_bytes(),
                members: members.iter().map(|member| member.as_bytes()).collect(),
            })
            .await?,
        )
    }

    /// Returns the distance between two geospatial members.
    ///
    /// Commands: Redis `GEODIST`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let km = client.geodist("geo", "Palermo", "Catania", lux::GeoUnit::Km).await?;
    /// ```
    pub async fn geodist(
        &self,
        key: &str,
        member_a: &str,
        member_b: &str,
        unit: GeoUnit,
    ) -> Result<Option<f64>, LuxError> {
        optional_f64(
            self.exec(Command::GeoDist {
                key: key.as_bytes(),
                member_a: member_a.as_bytes(),
                member_b: member_b.as_bytes(),
                unit: unit.as_bytes(),
            })
            .await?,
        )
    }

    /// Adds one entry to a stream and returns the generated or supplied entry id.
    ///
    /// Commands: Redis `XADD` simple form: `XADD key id field value ...`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let id = client.xadd("stream", "*", &[("field", "value")]).await?;
    /// ```
    pub async fn xadd<K, I, F, V>(
        &self,
        key: K,
        id: I,
        fields: &[(F, V)],
    ) -> Result<String, LuxError>
    where
        K: AsRef<[u8]>,
        I: AsRef<[u8]>,
        F: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        simple_string(
            self.exec(Command::XAdd {
                key: key.as_ref(),
                id: id.as_ref(),
                fields: pair_refs(fields),
            })
            .await?,
        )
    }

    async fn exec(&self, command: Command<'_>) -> Result<CommandOutput, LuxError> {
        self.execute_command_output(command).await
    }
}

fn refs<T: AsRef<[u8]>>(values: &[T]) -> Vec<&[u8]> {
    values.iter().map(AsRef::as_ref).collect()
}

fn pair_refs<K: AsRef<[u8]>, V: AsRef<[u8]>>(pairs: &[(K, V)]) -> Vec<(&[u8], &[u8])> {
    pairs
        .iter()
        .map(|(key, value)| (key.as_ref(), value.as_ref()))
        .collect()
}

fn ok(value: CommandOutput) -> Result<(), LuxError> {
    match value {
        CommandOutput::Simple(s) if s.eq_ignore_ascii_case("OK") => Ok(()),
        CommandOutput::Bulk(bytes) if bytes.eq_ignore_ascii_case(b"OK") => Ok(()),
        other => Err(protocol(format!("expected OK, got {other:?}"))),
    }
}

fn simple_string(value: CommandOutput) -> Result<String, LuxError> {
    match value {
        CommandOutput::Simple(s) => Ok(s.to_string()),
        CommandOutput::Bulk(bytes) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
        other => Err(protocol(format!("expected string, got {other:?}"))),
    }
}

fn i64_value(value: CommandOutput) -> Result<i64, LuxError> {
    match value {
        CommandOutput::Int(n) => Ok(n),
        other => Err(protocol(format!("expected integer, got {other:?}"))),
    }
}

fn usize_value(value: CommandOutput) -> Result<usize, LuxError> {
    let n = i64_value(value)?;
    usize::try_from(n).map_err(|_| protocol(format!("expected non-negative integer, got {n}")))
}

fn bool_int(value: CommandOutput) -> Result<bool, LuxError> {
    match i64_value(value)? {
        0 => Ok(false),
        1 => Ok(true),
        n => Err(protocol(format!("expected boolean integer, got {n}"))),
    }
}

fn optional_bulk(value: CommandOutput) -> Result<Option<Bytes>, LuxError> {
    match value {
        CommandOutput::Nil => Ok(None),
        CommandOutput::Bulk(bytes) => Ok(Some(bytes)),
        CommandOutput::Simple(s) => Ok(Some(Bytes::from(s))),
        other => Err(protocol(format!("expected bulk string, got {other:?}"))),
    }
}

fn optional_bulk_vec(value: CommandOutput) -> Result<Vec<Option<Bytes>>, LuxError> {
    match value {
        CommandOutput::Array(items) => items.into_iter().map(optional_bulk).collect(),
        other => Err(protocol(format!("expected array, got {other:?}"))),
    }
}

fn bulk_vec(value: CommandOutput) -> Result<Vec<Bytes>, LuxError> {
    match value {
        CommandOutput::Array(items) => items.into_iter().map(required_bulk).collect(),
        other => Err(protocol(format!("expected array, got {other:?}"))),
    }
}

fn string_vec(value: CommandOutput) -> Result<Vec<String>, LuxError> {
    bulk_vec(value).map(|values| {
        values
            .into_iter()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .collect()
    })
}

fn pair_bulk_vec(value: CommandOutput) -> Result<Vec<(Bytes, Bytes)>, LuxError> {
    let values = bulk_vec(value)?;
    if values.len() % 2 != 0 {
        return Err(protocol("expected an even number of array items"));
    }
    Ok(values
        .chunks_exact(2)
        .map(|chunk| (chunk[0].clone(), chunk[1].clone()))
        .collect())
}

fn scored_members(value: CommandOutput) -> Result<Vec<ScoredMember>, LuxError> {
    let values = bulk_vec(value)?;
    if values.len() % 2 != 0 {
        return Err(protocol("expected member/score pairs"));
    }
    let mut out = Vec::with_capacity(values.len() / 2);
    for chunk in values.chunks_exact(2) {
        out.push(ScoredMember {
            member: chunk[0].clone(),
            score: parse_f64(&chunk[1])?,
        });
    }
    Ok(out)
}

fn optional_f64(value: CommandOutput) -> Result<Option<f64>, LuxError> {
    match optional_bulk(value)? {
        Some(bytes) => Ok(Some(parse_f64(&bytes)?)),
        None => Ok(None),
    }
}

fn required_bulk(value: CommandOutput) -> Result<Bytes, LuxError> {
    optional_bulk(value)?.ok_or_else(|| protocol("expected bulk string, got nil"))
}

fn geo_positions(value: CommandOutput) -> Result<Vec<Option<GeoPosition>>, LuxError> {
    let CommandOutput::Array(items) = value else {
        return Err(protocol("expected GEOPOS array"));
    };
    items
        .into_iter()
        .map(|item| match item {
            CommandOutput::Nil => Ok(None),
            CommandOutput::Array(pair) if pair.len() == 2 => {
                let mut iter = pair.into_iter();
                let lon = parse_f64(&required_bulk(iter.next().unwrap())?)?;
                let lat = parse_f64(&required_bulk(iter.next().unwrap())?)?;
                Ok(Some(GeoPosition {
                    longitude: lon,
                    latitude: lat,
                }))
            }
            other => Err(protocol(format!(
                "expected GEOPOS coordinate pair, got {other:?}"
            ))),
        })
        .collect()
}

fn parse_f64(bytes: &[u8]) -> Result<f64, LuxError> {
    let s = std::str::from_utf8(bytes).map_err(|_| protocol("expected UTF-8 float"))?;
    s.parse::<f64>()
        .map_err(|_| protocol(format!("expected float, got {s}")))
}

fn protocol(message: impl Into<String>) -> LuxError {
    LuxError::Protocol(message.into())
}

fn command_output_to_embedded_value(value: CommandOutput) -> Result<EmbeddedValue, LuxError> {
    Ok(match value {
        CommandOutput::Nil => EmbeddedValue::Nil,
        CommandOutput::Int(n) => EmbeddedValue::Int(n),
        CommandOutput::Simple(s) => EmbeddedValue::Simple(s.to_string()),
        CommandOutput::Bulk(bytes) => EmbeddedValue::Bulk(bytes),
        CommandOutput::Array(values) => EmbeddedValue::Array(
            values
                .into_iter()
                .map(command_output_to_embedded_value)
                .collect::<Result<Vec<_>, _>>()?,
        ),
    })
}
