//! Command argv parsing and metadata.
//!
//! This layer is transport-agnostic: RESP, HTTP, and embedded callers should
//! arrive here with argv slices and use the same validation/classification
//! before dispatching to the legacy command implementations.

use bytes::Bytes;

use crate::LuxError;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum CommandOutput {
    Nil,
    Int(i64),
    Simple(&'static str),
    Bulk(Bytes),
    Array(Vec<CommandOutput>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommandKind {
    General,
    Auth,
    Transaction,
    PubSub(PubSubCommand),
    Blocking,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PubSubCommand {
    Subscribe,
    Unsubscribe,
    PSubscribe,
    PUnsubscribe,
    KSubscribe,
    KUnsubscribe,
    Publish,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShardAccess {
    General,
    SingleRead,
    SingleWrite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SetOption {
    Ex(u64),
    Px(u128),
    Nx,
    Xx,
    KeepTtl,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct GeoAddMember<'a> {
    pub longitude: f64,
    pub latitude: f64,
    pub member: &'a [u8],
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum OwnedCommand {
    Ping,
    Publish {
        channel: Vec<u8>,
        message: Vec<u8>,
    },
    DbSize,
    Get {
        key: Vec<u8>,
    },
    Set {
        key: Vec<u8>,
        value: Vec<u8>,
        options: Vec<SetOption>,
    },
    GetSet {
        key: Vec<u8>,
        value: Vec<u8>,
    },
    SetNx {
        key: Vec<u8>,
        value: Vec<u8>,
    },
    SetEx {
        key: Vec<u8>,
        seconds: u64,
        value: Vec<u8>,
    },
    PSetEx {
        key: Vec<u8>,
        milliseconds: u128,
        value: Vec<u8>,
    },
    MGet {
        keys: Vec<Vec<u8>>,
    },
    MSet {
        pairs: Vec<(Vec<u8>, Vec<u8>)>,
    },
    Append {
        key: Vec<u8>,
        value: Vec<u8>,
    },
    StrLen {
        key: Vec<u8>,
    },
    Incr {
        key: Vec<u8>,
    },
    Decr {
        key: Vec<u8>,
    },
    IncrBy {
        key: Vec<u8>,
        increment: i64,
    },
    DecrBy {
        key: Vec<u8>,
        decrement: i64,
    },
    Exists {
        keys: Vec<Vec<u8>>,
    },
    Expire {
        key: Vec<u8>,
        seconds: u64,
    },
    Ttl {
        key: Vec<u8>,
    },
    PTtl {
        key: Vec<u8>,
    },
    Persist {
        key: Vec<u8>,
    },
    Type {
        key: Vec<u8>,
    },
    LPush {
        key: Vec<u8>,
        values: Vec<Vec<u8>>,
    },
    RPush {
        key: Vec<u8>,
        values: Vec<Vec<u8>>,
    },
    LPop {
        key: Vec<u8>,
    },
    RPop {
        key: Vec<u8>,
    },
    LLen {
        key: Vec<u8>,
    },
    LIndex {
        key: Vec<u8>,
        index: i64,
    },
    LRange {
        key: Vec<u8>,
        start: i64,
        stop: i64,
    },
    HSet {
        key: Vec<u8>,
        field: Vec<u8>,
        value: Vec<u8>,
    },
    HIncrBy {
        key: Vec<u8>,
        field: Vec<u8>,
        increment: i64,
    },
    HGet {
        key: Vec<u8>,
        field: Vec<u8>,
    },
    HMGet {
        key: Vec<u8>,
        fields: Vec<Vec<u8>>,
    },
    HExists {
        key: Vec<u8>,
        field: Vec<u8>,
    },
    HLen {
        key: Vec<u8>,
    },
    HGetAll {
        key: Vec<u8>,
    },
    SAdd {
        key: Vec<u8>,
        members: Vec<Vec<u8>>,
    },
    SPop {
        key: Vec<u8>,
    },
    SIsMember {
        key: Vec<u8>,
        member: Vec<u8>,
    },
    SCard {
        key: Vec<u8>,
    },
    SMembers {
        key: Vec<u8>,
    },
    SUnion {
        keys: Vec<Vec<u8>>,
    },
    SInter {
        keys: Vec<Vec<u8>>,
    },
    SDiff {
        keys: Vec<Vec<u8>>,
    },
    ZAdd {
        key: Vec<u8>,
        score: f64,
        member: Vec<u8>,
    },
    ZScore {
        key: Vec<u8>,
        member: Vec<u8>,
    },
    ZCard {
        key: Vec<u8>,
    },
    ZCount {
        key: Vec<u8>,
        min: Vec<u8>,
        max: Vec<u8>,
    },
    ZRange {
        key: Vec<u8>,
        start: i64,
        stop: i64,
        with_scores: bool,
    },
    ZIncrBy {
        key: Vec<u8>,
        increment: f64,
        member: Vec<u8>,
    },
    XAdd {
        key: Vec<u8>,
        id: Vec<u8>,
        fields: Vec<(Vec<u8>, Vec<u8>)>,
    },
    GeoAdd {
        key: Vec<u8>,
        members: Vec<OwnedGeoAddMember>,
    },
    GeoPos {
        key: Vec<u8>,
        members: Vec<Vec<u8>>,
    },
    GeoDist {
        key: Vec<u8>,
        member_a: Vec<u8>,
        member_b: Vec<u8>,
        unit: &'static [u8],
    },
    Raw {
        name: Vec<u8>,
        args: Vec<Vec<u8>>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct OwnedGeoAddMember {
    longitude: f64,
    latitude: f64,
    member: Vec<u8>,
}

impl OwnedCommand {
    pub(crate) fn as_borrowed(&self) -> Command<'_> {
        match self {
            OwnedCommand::Ping => Command::Ping,
            OwnedCommand::Publish { channel, message } => Command::Publish {
                channel: channel.as_slice(),
                message: message.as_slice(),
            },
            OwnedCommand::DbSize => Command::DbSize,
            OwnedCommand::Get { key } => Command::Get {
                key: key.as_slice(),
            },
            OwnedCommand::Set {
                key,
                value,
                options,
            } => Command::Set {
                key: key.as_slice(),
                value: value.as_slice(),
                options: options.clone(),
            },
            OwnedCommand::GetSet { key, value } => Command::GetSet {
                key: key.as_slice(),
                value: value.as_slice(),
            },
            OwnedCommand::SetNx { key, value } => Command::SetNx {
                key: key.as_slice(),
                value: value.as_slice(),
            },
            OwnedCommand::SetEx {
                key,
                seconds,
                value,
            } => Command::SetEx {
                key: key.as_slice(),
                seconds: *seconds,
                value: value.as_slice(),
            },
            OwnedCommand::PSetEx {
                key,
                milliseconds,
                value,
            } => Command::PSetEx {
                key: key.as_slice(),
                milliseconds: *milliseconds,
                value: value.as_slice(),
            },
            OwnedCommand::MGet { keys } => Command::MGet {
                keys: bytes_vec_refs(keys),
            },
            OwnedCommand::MSet { pairs } => Command::MSet {
                pairs: pair_vec_refs(pairs),
            },
            OwnedCommand::Append { key, value } => Command::Append {
                key: key.as_slice(),
                value: value.as_slice(),
            },
            OwnedCommand::StrLen { key } => Command::StrLen {
                key: key.as_slice(),
            },
            OwnedCommand::Incr { key } => Command::Incr {
                key: key.as_slice(),
            },
            OwnedCommand::Decr { key } => Command::Decr {
                key: key.as_slice(),
            },
            OwnedCommand::IncrBy { key, increment } => Command::IncrBy {
                key: key.as_slice(),
                increment: *increment,
            },
            OwnedCommand::DecrBy { key, decrement } => Command::DecrBy {
                key: key.as_slice(),
                decrement: *decrement,
            },
            OwnedCommand::Exists { keys } => Command::Exists {
                keys: bytes_vec_refs(keys),
            },
            OwnedCommand::Expire { key, seconds } => Command::Expire {
                key: key.as_slice(),
                seconds: *seconds,
            },
            OwnedCommand::Ttl { key } => Command::Ttl {
                key: key.as_slice(),
            },
            OwnedCommand::PTtl { key } => Command::PTtl {
                key: key.as_slice(),
            },
            OwnedCommand::Persist { key } => Command::Persist {
                key: key.as_slice(),
            },
            OwnedCommand::Type { key } => Command::Type {
                key: key.as_slice(),
            },
            OwnedCommand::LPush { key, values } => Command::LPush {
                key: key.as_slice(),
                values: bytes_vec_refs(values),
            },
            OwnedCommand::RPush { key, values } => Command::RPush {
                key: key.as_slice(),
                values: bytes_vec_refs(values),
            },
            OwnedCommand::LPop { key } => Command::LPop {
                key: key.as_slice(),
            },
            OwnedCommand::RPop { key } => Command::RPop {
                key: key.as_slice(),
            },
            OwnedCommand::LLen { key } => Command::LLen {
                key: key.as_slice(),
            },
            OwnedCommand::LIndex { key, index } => Command::LIndex {
                key: key.as_slice(),
                index: *index,
            },
            OwnedCommand::LRange { key, start, stop } => Command::LRange {
                key: key.as_slice(),
                start: *start,
                stop: *stop,
            },
            OwnedCommand::HSet { key, field, value } => Command::HSet {
                key: key.as_slice(),
                field: field.as_slice(),
                value: value.as_slice(),
            },
            OwnedCommand::HIncrBy {
                key,
                field,
                increment,
            } => Command::HIncrBy {
                key: key.as_slice(),
                field: field.as_slice(),
                increment: *increment,
            },
            OwnedCommand::HGet { key, field } => Command::HGet {
                key: key.as_slice(),
                field: field.as_slice(),
            },
            OwnedCommand::HMGet { key, fields } => Command::HMGet {
                key: key.as_slice(),
                fields: bytes_vec_refs(fields),
            },
            OwnedCommand::HExists { key, field } => Command::HExists {
                key: key.as_slice(),
                field: field.as_slice(),
            },
            OwnedCommand::HLen { key } => Command::HLen {
                key: key.as_slice(),
            },
            OwnedCommand::HGetAll { key } => Command::HGetAll {
                key: key.as_slice(),
            },
            OwnedCommand::SAdd { key, members } => Command::SAdd {
                key: key.as_slice(),
                members: bytes_vec_refs(members),
            },
            OwnedCommand::SPop { key } => Command::SPop {
                key: key.as_slice(),
            },
            OwnedCommand::SIsMember { key, member } => Command::SIsMember {
                key: key.as_slice(),
                member: member.as_slice(),
            },
            OwnedCommand::SCard { key } => Command::SCard {
                key: key.as_slice(),
            },
            OwnedCommand::SMembers { key } => Command::SMembers {
                key: key.as_slice(),
            },
            OwnedCommand::SUnion { keys } => Command::SUnion {
                keys: bytes_vec_refs(keys),
            },
            OwnedCommand::SInter { keys } => Command::SInter {
                keys: bytes_vec_refs(keys),
            },
            OwnedCommand::SDiff { keys } => Command::SDiff {
                keys: bytes_vec_refs(keys),
            },
            OwnedCommand::ZAdd { key, score, member } => Command::ZAdd {
                key: key.as_slice(),
                score: *score,
                member: member.as_slice(),
            },
            OwnedCommand::ZScore { key, member } => Command::ZScore {
                key: key.as_slice(),
                member: member.as_slice(),
            },
            OwnedCommand::ZCard { key } => Command::ZCard {
                key: key.as_slice(),
            },
            OwnedCommand::ZCount { key, min, max } => Command::ZCount {
                key: key.as_slice(),
                min: min.as_slice(),
                max: max.as_slice(),
            },
            OwnedCommand::ZRange {
                key,
                start,
                stop,
                with_scores,
            } => Command::ZRange {
                key: key.as_slice(),
                start: *start,
                stop: *stop,
                with_scores: *with_scores,
            },
            OwnedCommand::ZIncrBy {
                key,
                increment,
                member,
            } => Command::ZIncrBy {
                key: key.as_slice(),
                increment: *increment,
                member: member.as_slice(),
            },
            OwnedCommand::XAdd { key, id, fields } => Command::XAdd {
                key: key.as_slice(),
                id: id.as_slice(),
                fields: pair_vec_refs(fields),
            },
            OwnedCommand::GeoAdd { key, members } => Command::GeoAdd {
                key: key.as_slice(),
                members: members
                    .iter()
                    .map(|member| GeoAddMember {
                        longitude: member.longitude,
                        latitude: member.latitude,
                        member: member.member.as_slice(),
                    })
                    .collect(),
            },
            OwnedCommand::GeoPos { key, members } => Command::GeoPos {
                key: key.as_slice(),
                members: bytes_vec_refs(members),
            },
            OwnedCommand::GeoDist {
                key,
                member_a,
                member_b,
                unit,
            } => Command::GeoDist {
                key: key.as_slice(),
                member_a: member_a.as_slice(),
                member_b: member_b.as_slice(),
                unit,
            },
            OwnedCommand::Raw { name, args } => Command::Raw {
                name: name.as_slice(),
                args: bytes_vec_refs(args),
            },
        }
    }

    pub(crate) fn raw_argv(&self) -> Option<Vec<Vec<u8>>> {
        let OwnedCommand::Raw { name, args } = self else {
            return None;
        };
        let mut argv = Vec::with_capacity(args.len() + 1);
        argv.push(name.clone());
        argv.extend(args.iter().cloned());
        Some(argv)
    }

    pub(crate) fn is_write(&self) -> bool {
        self.as_borrowed().is_write()
    }

    pub(crate) fn is_read(&self) -> bool {
        self.as_borrowed().is_read()
    }
}

pub(crate) fn prepare_owned_argv(argv: Vec<Vec<u8>>) -> Result<OwnedCommand, LuxError> {
    let Some(name) = argv.first() else {
        return Err(LuxError::InvalidCommand("empty command".to_string()));
    };
    if name.is_empty() {
        return Err(LuxError::InvalidCommand("empty command".to_string()));
    }
    let args = &argv[1..];

    // Model the simple forms directly and leave complex/option-heavy forms as
    // raw argv so the generic command layer keeps exact Redis error semantics.
    let command = if eq(name, b"PING") && args.is_empty() {
        OwnedCommand::Ping
    } else if eq(name, b"PUBLISH") && args.len() == 2 {
        OwnedCommand::Publish {
            channel: args[0].clone(),
            message: args[1].clone(),
        }
    } else if eq(name, b"DBSIZE") && args.is_empty() {
        OwnedCommand::DbSize
    } else if eq(name, b"GET") && args.len() == 1 {
        OwnedCommand::Get {
            key: args[0].clone(),
        }
    } else if eq(name, b"SET") && args.len() >= 2 {
        match parse_set_options(&args[2..]) {
            Some(options) => OwnedCommand::Set {
                key: args[0].clone(),
                value: args[1].clone(),
                options,
            },
            None => owned_raw(argv.clone()),
        }
    } else if eq(name, b"GETSET") && args.len() == 2 {
        OwnedCommand::GetSet {
            key: args[0].clone(),
            value: args[1].clone(),
        }
    } else if eq(name, b"SETNX") && args.len() == 2 {
        OwnedCommand::SetNx {
            key: args[0].clone(),
            value: args[1].clone(),
        }
    } else if eq(name, b"SETEX") && args.len() == 3 {
        OwnedCommand::SetEx {
            key: args[0].clone(),
            seconds: parse_arg(&args[1], "SETEX seconds")?,
            value: args[2].clone(),
        }
    } else if eq(name, b"PSETEX") && args.len() == 3 {
        OwnedCommand::PSetEx {
            key: args[0].clone(),
            milliseconds: parse_arg(&args[1], "PSETEX milliseconds")?,
            value: args[2].clone(),
        }
    } else if eq(name, b"MGET") && !args.is_empty() {
        OwnedCommand::MGet {
            keys: args.to_vec(),
        }
    } else if eq(name, b"MSET") && args.len() >= 2 && args.len().is_multiple_of(2) {
        OwnedCommand::MSet {
            pairs: pairs_from_args(args),
        }
    } else if eq(name, b"APPEND") && args.len() == 2 {
        OwnedCommand::Append {
            key: args[0].clone(),
            value: args[1].clone(),
        }
    } else if eq(name, b"STRLEN") && args.len() == 1 {
        OwnedCommand::StrLen {
            key: args[0].clone(),
        }
    } else if eq(name, b"INCR") && args.len() == 1 {
        OwnedCommand::Incr {
            key: args[0].clone(),
        }
    } else if eq(name, b"DECR") && args.len() == 1 {
        OwnedCommand::Decr {
            key: args[0].clone(),
        }
    } else if eq(name, b"INCRBY") && args.len() == 2 {
        OwnedCommand::IncrBy {
            key: args[0].clone(),
            increment: parse_arg(&args[1], "INCRBY increment")?,
        }
    } else if eq(name, b"DECRBY") && args.len() == 2 {
        OwnedCommand::DecrBy {
            key: args[0].clone(),
            decrement: parse_arg(&args[1], "DECRBY decrement")?,
        }
    } else if eq(name, b"EXISTS") && !args.is_empty() {
        OwnedCommand::Exists {
            keys: args.to_vec(),
        }
    } else if eq(name, b"EXPIRE") && args.len() == 2 {
        OwnedCommand::Expire {
            key: args[0].clone(),
            seconds: parse_arg(&args[1], "EXPIRE seconds")?,
        }
    } else if eq(name, b"TTL") && args.len() == 1 {
        OwnedCommand::Ttl {
            key: args[0].clone(),
        }
    } else if eq(name, b"PTTL") && args.len() == 1 {
        OwnedCommand::PTtl {
            key: args[0].clone(),
        }
    } else if eq(name, b"PERSIST") && args.len() == 1 {
        OwnedCommand::Persist {
            key: args[0].clone(),
        }
    } else if eq(name, b"TYPE") && args.len() == 1 {
        OwnedCommand::Type {
            key: args[0].clone(),
        }
    } else if eq(name, b"LPUSH") && args.len() >= 2 {
        OwnedCommand::LPush {
            key: args[0].clone(),
            values: args[1..].to_vec(),
        }
    } else if eq(name, b"RPUSH") && args.len() >= 2 {
        OwnedCommand::RPush {
            key: args[0].clone(),
            values: args[1..].to_vec(),
        }
    } else if eq(name, b"LPOP") && args.len() == 1 {
        OwnedCommand::LPop {
            key: args[0].clone(),
        }
    } else if eq(name, b"RPOP") && args.len() == 1 {
        OwnedCommand::RPop {
            key: args[0].clone(),
        }
    } else if eq(name, b"LLEN") && args.len() == 1 {
        OwnedCommand::LLen {
            key: args[0].clone(),
        }
    } else if eq(name, b"LINDEX") && args.len() == 2 {
        OwnedCommand::LIndex {
            key: args[0].clone(),
            index: parse_arg(&args[1], "LINDEX index")?,
        }
    } else if eq(name, b"LRANGE") && args.len() == 3 {
        OwnedCommand::LRange {
            key: args[0].clone(),
            start: parse_arg(&args[1], "LRANGE start")?,
            stop: parse_arg(&args[2], "LRANGE stop")?,
        }
    } else if eq(name, b"HSET") && args.len() == 3 {
        OwnedCommand::HSet {
            key: args[0].clone(),
            field: args[1].clone(),
            value: args[2].clone(),
        }
    } else if eq(name, b"HINCRBY") && args.len() == 3 {
        OwnedCommand::HIncrBy {
            key: args[0].clone(),
            field: args[1].clone(),
            increment: parse_arg(&args[2], "HINCRBY increment")?,
        }
    } else if eq(name, b"HGET") && args.len() == 2 {
        OwnedCommand::HGet {
            key: args[0].clone(),
            field: args[1].clone(),
        }
    } else if eq(name, b"HMGET") && args.len() >= 2 {
        OwnedCommand::HMGet {
            key: args[0].clone(),
            fields: args[1..].to_vec(),
        }
    } else if eq(name, b"HEXISTS") && args.len() == 2 {
        OwnedCommand::HExists {
            key: args[0].clone(),
            field: args[1].clone(),
        }
    } else if eq(name, b"HLEN") && args.len() == 1 {
        OwnedCommand::HLen {
            key: args[0].clone(),
        }
    } else if eq(name, b"HGETALL") && args.len() == 1 {
        OwnedCommand::HGetAll {
            key: args[0].clone(),
        }
    } else if eq(name, b"SADD") && args.len() >= 2 {
        OwnedCommand::SAdd {
            key: args[0].clone(),
            members: args[1..].to_vec(),
        }
    } else if eq(name, b"SPOP") && args.len() == 1 {
        OwnedCommand::SPop {
            key: args[0].clone(),
        }
    } else if eq(name, b"SISMEMBER") && args.len() == 2 {
        OwnedCommand::SIsMember {
            key: args[0].clone(),
            member: args[1].clone(),
        }
    } else if eq(name, b"SCARD") && args.len() == 1 {
        OwnedCommand::SCard {
            key: args[0].clone(),
        }
    } else if eq(name, b"SMEMBERS") && args.len() == 1 {
        OwnedCommand::SMembers {
            key: args[0].clone(),
        }
    } else if eq(name, b"SUNION") && !args.is_empty() {
        OwnedCommand::SUnion {
            keys: args.to_vec(),
        }
    } else if eq(name, b"SINTER") && !args.is_empty() {
        OwnedCommand::SInter {
            keys: args.to_vec(),
        }
    } else if eq(name, b"SDIFF") && !args.is_empty() {
        OwnedCommand::SDiff {
            keys: args.to_vec(),
        }
    } else if eq(name, b"ZADD") && args.len() == 3 {
        OwnedCommand::ZAdd {
            key: args[0].clone(),
            score: parse_arg(&args[1], "ZADD score")?,
            member: args[2].clone(),
        }
    } else if eq(name, b"ZSCORE") && args.len() == 2 {
        OwnedCommand::ZScore {
            key: args[0].clone(),
            member: args[1].clone(),
        }
    } else if eq(name, b"ZCARD") && args.len() == 1 {
        OwnedCommand::ZCard {
            key: args[0].clone(),
        }
    } else if eq(name, b"ZCOUNT") && args.len() == 3 {
        OwnedCommand::ZCount {
            key: args[0].clone(),
            min: args[1].clone(),
            max: args[2].clone(),
        }
    } else if eq(name, b"ZRANGE") && (args.len() == 3 || args.len() == 4) {
        if args.len() == 4 && !eq(&args[3], b"WITHSCORES") {
            owned_raw(argv.clone())
        } else {
            OwnedCommand::ZRange {
                key: args[0].clone(),
                start: parse_arg(&args[1], "ZRANGE start")?,
                stop: parse_arg(&args[2], "ZRANGE stop")?,
                with_scores: args.len() == 4,
            }
        }
    } else if eq(name, b"ZINCRBY") && args.len() == 3 {
        OwnedCommand::ZIncrBy {
            key: args[0].clone(),
            increment: parse_arg(&args[1], "ZINCRBY increment")?,
            member: args[2].clone(),
        }
    } else if eq(name, b"XADD")
        && args.len() >= 4
        && (args.len() - 2).is_multiple_of(2)
        && !is_xadd_option(&args[1])
    {
        OwnedCommand::XAdd {
            key: args[0].clone(),
            id: args[1].clone(),
            fields: pairs_from_args(&args[2..]),
        }
    } else if eq(name, b"GEOADD") && args.len() >= 4 && args.len() % 3 == 1 {
        let mut members = Vec::with_capacity(args.len() / 3);
        for member in args[1..].chunks_exact(3) {
            members.push(OwnedGeoAddMember {
                longitude: parse_arg(&member[0], "GEOADD longitude")?,
                latitude: parse_arg(&member[1], "GEOADD latitude")?,
                member: member[2].clone(),
            });
        }
        OwnedCommand::GeoAdd {
            key: args[0].clone(),
            members,
        }
    } else if eq(name, b"GEOPOS") && args.len() >= 2 {
        OwnedCommand::GeoPos {
            key: args[0].clone(),
            members: args[1..].to_vec(),
        }
    } else if eq(name, b"GEODIST") && (args.len() == 3 || args.len() == 4) {
        if args.len() == 4 && parse_geo_unit(&args[3]).is_none() {
            owned_raw(argv.clone())
        } else {
            OwnedCommand::GeoDist {
                key: args[0].clone(),
                member_a: args[1].clone(),
                member_b: args[2].clone(),
                unit: args
                    .get(3)
                    .and_then(|unit| parse_geo_unit(unit))
                    .unwrap_or(b"m"),
            }
        }
    } else {
        owned_raw(argv.clone())
    };

    Ok(command)
}

fn owned_raw(mut argv: Vec<Vec<u8>>) -> OwnedCommand {
    let name = argv.remove(0);
    OwnedCommand::Raw { name, args: argv }
}

fn parse_set_options(args: &[Vec<u8>]) -> Option<Vec<SetOption>> {
    let mut options = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if eq(&args[i], b"EX") && i + 1 < args.len() {
            options.push(SetOption::Ex(parse_arg(&args[i + 1], "SET EX").ok()?));
            i += 2;
        } else if eq(&args[i], b"PX") && i + 1 < args.len() {
            options.push(SetOption::Px(parse_arg(&args[i + 1], "SET PX").ok()?));
            i += 2;
        } else if eq(&args[i], b"NX") {
            options.push(SetOption::Nx);
            i += 1;
        } else if eq(&args[i], b"XX") {
            options.push(SetOption::Xx);
            i += 1;
        } else if eq(&args[i], b"KEEPTTL") {
            options.push(SetOption::KeepTtl);
            i += 1;
        } else {
            return None;
        }
    }
    Some(options)
}

fn parse_geo_unit(unit: &[u8]) -> Option<&'static [u8]> {
    if eq(unit, b"M") {
        Some(b"m")
    } else if eq(unit, b"KM") {
        Some(b"km")
    } else if eq(unit, b"MI") {
        Some(b"mi")
    } else if eq(unit, b"FT") {
        Some(b"ft")
    } else {
        None
    }
}

fn is_xadd_option(arg: &[u8]) -> bool {
    eq(arg, b"NOMKSTREAM") || eq(arg, b"MAXLEN") || eq(arg, b"MINID")
}

fn parse_arg<T>(arg: &[u8], label: &str) -> Result<T, LuxError>
where
    T: std::str::FromStr,
{
    let text = std::str::from_utf8(arg)
        .map_err(|_| LuxError::InvalidCommand(format!("{label} is not valid UTF-8")))?;
    text.parse()
        .map_err(|_| LuxError::InvalidCommand(format!("invalid {label}: {text}")))
}

fn pairs_from_args(args: &[Vec<u8>]) -> Vec<(Vec<u8>, Vec<u8>)> {
    args.chunks_exact(2)
        .map(|pair| (pair[0].clone(), pair[1].clone()))
        .collect()
}

fn bytes_vec_refs(values: &[Vec<u8>]) -> Vec<&[u8]> {
    values.iter().map(Vec::as_slice).collect()
}

fn pair_vec_refs(pairs: &[(Vec<u8>, Vec<u8>)]) -> Vec<(&[u8], &[u8])> {
    pairs
        .iter()
        .map(|(key, value)| (key.as_slice(), value.as_slice()))
        .collect()
}

/// Typed command AST used by native embedded execution.
///
/// This intentionally models the common 90% of Redis commands directly so
/// embedded callers can avoid argv parsing. Complex or unmodeled commands use
/// `Raw` and fall back to the generic command path.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Command<'a> {
    Ping,
    Publish {
        channel: &'a [u8],
        message: &'a [u8],
    },
    DbSize,
    FlushDb,
    FlushAll,
    Keys {
        pattern: &'a [u8],
    },
    RandomKey,
    Get {
        key: &'a [u8],
    },
    Set {
        key: &'a [u8],
        value: &'a [u8],
        options: Vec<SetOption>,
    },
    GetSet {
        key: &'a [u8],
        value: &'a [u8],
    },
    SetNx {
        key: &'a [u8],
        value: &'a [u8],
    },
    SetEx {
        key: &'a [u8],
        seconds: u64,
        value: &'a [u8],
    },
    PSetEx {
        key: &'a [u8],
        milliseconds: u128,
        value: &'a [u8],
    },
    MGet {
        keys: Vec<&'a [u8]>,
    },
    MSet {
        pairs: Vec<(&'a [u8], &'a [u8])>,
    },
    MSetNx {
        pairs: Vec<(&'a [u8], &'a [u8])>,
    },
    Append {
        key: &'a [u8],
        value: &'a [u8],
    },
    StrLen {
        key: &'a [u8],
    },
    Incr {
        key: &'a [u8],
    },
    Decr {
        key: &'a [u8],
    },
    IncrBy {
        key: &'a [u8],
        increment: i64,
    },
    DecrBy {
        key: &'a [u8],
        decrement: i64,
    },
    Del {
        keys: Vec<&'a [u8]>,
    },
    Unlink {
        keys: Vec<&'a [u8]>,
    },
    Exists {
        keys: Vec<&'a [u8]>,
    },
    Expire {
        key: &'a [u8],
        seconds: u64,
    },
    Ttl {
        key: &'a [u8],
    },
    PTtl {
        key: &'a [u8],
    },
    Persist {
        key: &'a [u8],
    },
    Type {
        key: &'a [u8],
    },
    Rename {
        key: &'a [u8],
        new_key: &'a [u8],
    },
    RenameNx {
        key: &'a [u8],
        new_key: &'a [u8],
    },
    LPush {
        key: &'a [u8],
        values: Vec<&'a [u8]>,
    },
    RPush {
        key: &'a [u8],
        values: Vec<&'a [u8]>,
    },
    LPop {
        key: &'a [u8],
    },
    RPop {
        key: &'a [u8],
    },
    LLen {
        key: &'a [u8],
    },
    LIndex {
        key: &'a [u8],
        index: i64,
    },
    LRange {
        key: &'a [u8],
        start: i64,
        stop: i64,
    },
    HSet {
        key: &'a [u8],
        field: &'a [u8],
        value: &'a [u8],
    },
    HIncrBy {
        key: &'a [u8],
        field: &'a [u8],
        increment: i64,
    },
    HGet {
        key: &'a [u8],
        field: &'a [u8],
    },
    HMGet {
        key: &'a [u8],
        fields: Vec<&'a [u8]>,
    },
    HDel {
        key: &'a [u8],
        fields: Vec<&'a [u8]>,
    },
    HExists {
        key: &'a [u8],
        field: &'a [u8],
    },
    HLen {
        key: &'a [u8],
    },
    HGetAll {
        key: &'a [u8],
    },
    SAdd {
        key: &'a [u8],
        members: Vec<&'a [u8]>,
    },
    SRem {
        key: &'a [u8],
        members: Vec<&'a [u8]>,
    },
    SMembers {
        key: &'a [u8],
    },
    SIsMember {
        key: &'a [u8],
        member: &'a [u8],
    },
    SCard {
        key: &'a [u8],
    },
    SPop {
        key: &'a [u8],
    },
    SUnion {
        keys: Vec<&'a [u8]>,
    },
    SInter {
        keys: Vec<&'a [u8]>,
    },
    SDiff {
        keys: Vec<&'a [u8]>,
    },
    ZAdd {
        key: &'a [u8],
        score: f64,
        member: &'a [u8],
    },
    ZRem {
        key: &'a [u8],
        members: Vec<&'a [u8]>,
    },
    ZCard {
        key: &'a [u8],
    },
    ZScore {
        key: &'a [u8],
        member: &'a [u8],
    },
    ZIncrBy {
        key: &'a [u8],
        increment: f64,
        member: &'a [u8],
    },
    ZCount {
        key: &'a [u8],
        min: &'a [u8],
        max: &'a [u8],
    },
    ZRange {
        key: &'a [u8],
        start: i64,
        stop: i64,
        with_scores: bool,
    },
    GeoAdd {
        key: &'a [u8],
        members: Vec<GeoAddMember<'a>>,
    },
    GeoPos {
        key: &'a [u8],
        members: Vec<&'a [u8]>,
    },
    GeoDist {
        key: &'a [u8],
        member_a: &'a [u8],
        member_b: &'a [u8],
        unit: &'static [u8],
    },
    XAdd {
        key: &'a [u8],
        id: &'a [u8],
        fields: Vec<(&'a [u8], &'a [u8])>,
    },
    #[allow(dead_code)]
    Raw {
        name: &'a [u8],
        args: Vec<&'a [u8]>,
    },
}

impl<'a> Command<'a> {
    pub(crate) fn is_write(&self) -> bool {
        !matches!(
            self,
            Command::Ping
                | Command::DbSize
                | Command::Keys { .. }
                | Command::RandomKey
                | Command::Get { .. }
                | Command::MGet { .. }
                | Command::StrLen { .. }
                | Command::Exists { .. }
                | Command::Ttl { .. }
                | Command::PTtl { .. }
                | Command::Type { .. }
                | Command::LLen { .. }
                | Command::LIndex { .. }
                | Command::LRange { .. }
                | Command::HGet { .. }
                | Command::HMGet { .. }
                | Command::HExists { .. }
                | Command::HLen { .. }
                | Command::HGetAll { .. }
                | Command::SIsMember { .. }
                | Command::SCard { .. }
                | Command::SMembers { .. }
                | Command::SUnion { .. }
                | Command::SInter { .. }
                | Command::SDiff { .. }
                | Command::ZScore { .. }
                | Command::ZCard { .. }
                | Command::ZCount { .. }
                | Command::ZRange { .. }
                | Command::GeoPos { .. }
                | Command::GeoDist { .. }
                | Command::Raw { .. }
        )
    }

    pub(crate) fn is_read(&self) -> bool {
        matches!(
            self,
            Command::Ping
                | Command::DbSize
                | Command::Keys { .. }
                | Command::RandomKey
                | Command::Get { .. }
                | Command::MGet { .. }
                | Command::StrLen { .. }
                | Command::Exists { .. }
                | Command::Ttl { .. }
                | Command::PTtl { .. }
                | Command::Type { .. }
                | Command::LLen { .. }
                | Command::LIndex { .. }
                | Command::LRange { .. }
                | Command::HGet { .. }
                | Command::HMGet { .. }
                | Command::HExists { .. }
                | Command::HLen { .. }
                | Command::HGetAll { .. }
                | Command::SIsMember { .. }
                | Command::SCard { .. }
                | Command::SMembers { .. }
                | Command::SUnion { .. }
                | Command::SInter { .. }
                | Command::SDiff { .. }
                | Command::ZScore { .. }
                | Command::ZCard { .. }
                | Command::ZCount { .. }
                | Command::ZRange { .. }
                | Command::GeoPos { .. }
                | Command::GeoDist { .. }
        )
    }

    pub(crate) fn to_owned_argv(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        self.write_argv(&mut out);
        out
    }

    fn write_argv(&self, out: &mut Vec<Vec<u8>>) {
        match self {
            Command::Ping => push_name(out, b"PING"),
            Command::Publish { channel, message } => {
                push_name(out, b"PUBLISH");
                push_arg(out, channel);
                push_arg(out, message);
            }
            Command::DbSize => push_name(out, b"DBSIZE"),
            Command::FlushDb => push_name(out, b"FLUSHDB"),
            Command::FlushAll => push_name(out, b"FLUSHALL"),
            Command::Keys { pattern } => {
                push_name(out, b"KEYS");
                push_arg(out, pattern);
            }
            Command::RandomKey => push_name(out, b"RANDOMKEY"),
            Command::Get { key } => push_key(out, b"GET", key),
            Command::Set {
                key,
                value,
                options,
            } => {
                push_name(out, b"SET");
                push_arg(out, key);
                push_arg(out, value);
                for option in options {
                    match option {
                        SetOption::Ex(seconds) => {
                            push_name(out, b"EX");
                            push_int(out, *seconds);
                        }
                        SetOption::Px(milliseconds) => {
                            push_name(out, b"PX");
                            push_int(out, *milliseconds);
                        }
                        SetOption::Nx => push_name(out, b"NX"),
                        SetOption::Xx => push_name(out, b"XX"),
                        SetOption::KeepTtl => push_name(out, b"KEEPTTL"),
                    }
                }
            }
            Command::GetSet { key, value } => push_key_value(out, b"GETSET", key, value),
            Command::SetNx { key, value } => push_key_value(out, b"SETNX", key, value),
            Command::SetEx {
                key,
                seconds,
                value,
            } => {
                push_name(out, b"SETEX");
                push_arg(out, key);
                push_int(out, *seconds);
                push_arg(out, value);
            }
            Command::PSetEx {
                key,
                milliseconds,
                value,
            } => {
                push_name(out, b"PSETEX");
                push_arg(out, key);
                push_int(out, *milliseconds);
                push_arg(out, value);
            }
            Command::MGet { keys } => push_many(out, b"MGET", keys),
            Command::MSet { pairs } => push_pairs(out, b"MSET", pairs),
            Command::MSetNx { pairs } => push_pairs(out, b"MSETNX", pairs),
            Command::Append { key, value } => push_key_value(out, b"APPEND", key, value),
            Command::StrLen { key } => push_key(out, b"STRLEN", key),
            Command::Incr { key } => push_key(out, b"INCR", key),
            Command::Decr { key } => push_key(out, b"DECR", key),
            Command::IncrBy { key, increment } => {
                push_name(out, b"INCRBY");
                push_arg(out, key);
                push_int(out, *increment);
            }
            Command::DecrBy { key, decrement } => {
                push_name(out, b"DECRBY");
                push_arg(out, key);
                push_int(out, *decrement);
            }
            Command::Del { keys } => push_many(out, b"DEL", keys),
            Command::Unlink { keys } => push_many(out, b"UNLINK", keys),
            Command::Exists { keys } => push_many(out, b"EXISTS", keys),
            Command::Expire { key, seconds } => {
                push_name(out, b"EXPIRE");
                push_arg(out, key);
                push_int(out, *seconds);
            }
            Command::Ttl { key } => push_key(out, b"TTL", key),
            Command::PTtl { key } => push_key(out, b"PTTL", key),
            Command::Persist { key } => push_key(out, b"PERSIST", key),
            Command::Type { key } => push_key(out, b"TYPE", key),
            Command::Rename { key, new_key } => push_key_value(out, b"RENAME", key, new_key),
            Command::RenameNx { key, new_key } => push_key_value(out, b"RENAMENX", key, new_key),
            Command::LPush { key, values } => push_key_many(out, b"LPUSH", key, values),
            Command::RPush { key, values } => push_key_many(out, b"RPUSH", key, values),
            Command::LPop { key } => push_key(out, b"LPOP", key),
            Command::RPop { key } => push_key(out, b"RPOP", key),
            Command::LLen { key } => push_key(out, b"LLEN", key),
            Command::LIndex { key, index } => {
                push_name(out, b"LINDEX");
                push_arg(out, key);
                push_int(out, *index);
            }
            Command::LRange { key, start, stop } => {
                push_name(out, b"LRANGE");
                push_arg(out, key);
                push_int(out, *start);
                push_int(out, *stop);
            }
            Command::HSet { key, field, value } => {
                push_name(out, b"HSET");
                push_arg(out, key);
                push_arg(out, field);
                push_arg(out, value);
            }
            Command::HIncrBy {
                key,
                field,
                increment,
            } => {
                push_name(out, b"HINCRBY");
                push_arg(out, key);
                push_arg(out, field);
                push_int(out, *increment);
            }
            Command::HGet { key, field } => push_key_value(out, b"HGET", key, field),
            Command::HMGet { key, fields } => push_key_many(out, b"HMGET", key, fields),
            Command::HDel { key, fields } => push_key_many(out, b"HDEL", key, fields),
            Command::HExists { key, field } => push_key_value(out, b"HEXISTS", key, field),
            Command::HLen { key } => push_key(out, b"HLEN", key),
            Command::HGetAll { key } => push_key(out, b"HGETALL", key),
            Command::SAdd { key, members } => push_key_many(out, b"SADD", key, members),
            Command::SRem { key, members } => push_key_many(out, b"SREM", key, members),
            Command::SMembers { key } => push_key(out, b"SMEMBERS", key),
            Command::SIsMember { key, member } => push_key_value(out, b"SISMEMBER", key, member),
            Command::SCard { key } => push_key(out, b"SCARD", key),
            Command::SPop { key } => push_key(out, b"SPOP", key),
            Command::SUnion { keys } => push_many(out, b"SUNION", keys),
            Command::SInter { keys } => push_many(out, b"SINTER", keys),
            Command::SDiff { keys } => push_many(out, b"SDIFF", keys),
            Command::ZAdd { key, score, member } => {
                push_name(out, b"ZADD");
                push_arg(out, key);
                push_float(out, *score);
                push_arg(out, member);
            }
            Command::ZRem { key, members } => push_key_many(out, b"ZREM", key, members),
            Command::ZCard { key } => push_key(out, b"ZCARD", key),
            Command::ZScore { key, member } => push_key_value(out, b"ZSCORE", key, member),
            Command::ZIncrBy {
                key,
                increment,
                member,
            } => {
                push_name(out, b"ZINCRBY");
                push_arg(out, key);
                push_float(out, *increment);
                push_arg(out, member);
            }
            Command::ZCount { key, min, max } => {
                push_name(out, b"ZCOUNT");
                push_arg(out, key);
                push_arg(out, min);
                push_arg(out, max);
            }
            Command::ZRange {
                key,
                start,
                stop,
                with_scores,
            } => {
                push_name(out, b"ZRANGE");
                push_arg(out, key);
                push_int(out, *start);
                push_int(out, *stop);
                if *with_scores {
                    push_name(out, b"WITHSCORES");
                }
            }
            Command::GeoAdd { key, members } => {
                push_name(out, b"GEOADD");
                push_arg(out, key);
                for member in members {
                    push_float(out, member.longitude);
                    push_float(out, member.latitude);
                    push_arg(out, member.member);
                }
            }
            Command::GeoPos { key, members } => push_key_many(out, b"GEOPOS", key, members),
            Command::GeoDist {
                key,
                member_a,
                member_b,
                unit,
            } => {
                push_name(out, b"GEODIST");
                push_arg(out, key);
                push_arg(out, member_a);
                push_arg(out, member_b);
                push_arg(out, unit);
            }
            Command::XAdd { key, id, fields } => {
                push_name(out, b"XADD");
                push_arg(out, key);
                push_arg(out, id);
                for (field, value) in fields {
                    push_arg(out, field);
                    push_arg(out, value);
                }
            }
            Command::Raw { name, args } => {
                push_arg(out, name);
                for arg in args {
                    push_arg(out, arg);
                }
            }
        }
    }
}

fn push_name(out: &mut Vec<Vec<u8>>, name: &'static [u8]) {
    out.push(name.to_vec());
}

fn push_arg(out: &mut Vec<Vec<u8>>, arg: &[u8]) {
    out.push(arg.to_vec());
}

fn push_int<T: std::fmt::Display>(out: &mut Vec<Vec<u8>>, n: T) {
    out.push(n.to_string().into_bytes());
}

fn push_float(out: &mut Vec<Vec<u8>>, n: f64) {
    out.push(n.to_string().into_bytes());
}

fn push_key(out: &mut Vec<Vec<u8>>, name: &'static [u8], key: &[u8]) {
    push_name(out, name);
    push_arg(out, key);
}

fn push_key_value(out: &mut Vec<Vec<u8>>, name: &'static [u8], key: &[u8], value: &[u8]) {
    push_name(out, name);
    push_arg(out, key);
    push_arg(out, value);
}

fn push_many(out: &mut Vec<Vec<u8>>, name: &'static [u8], values: &[&[u8]]) {
    push_name(out, name);
    for value in values {
        push_arg(out, value);
    }
}

fn push_key_many(out: &mut Vec<Vec<u8>>, name: &'static [u8], key: &[u8], values: &[&[u8]]) {
    push_name(out, name);
    push_arg(out, key);
    for value in values {
        push_arg(out, value);
    }
}

fn push_pairs(out: &mut Vec<Vec<u8>>, name: &'static [u8], pairs: &[(&[u8], &[u8])]) {
    push_name(out, name);
    for (key, value) in pairs {
        push_arg(out, key);
        push_arg(out, value);
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CommandMeta {
    pub kind: CommandKind,
    pub access: ShardAccess,
    pub public_without_auth: bool,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ParsedCommand<'a> {
    pub args: &'a [&'a [u8]],
    pub name: &'a [u8],
    pub meta: CommandMeta,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CommandParseError {
    Empty,
    InvalidUtf8,
}

impl std::fmt::Display for CommandParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandParseError::Empty => write!(f, "empty command"),
            CommandParseError::InvalidUtf8 => {
                write!(
                    f,
                    "invalid UTF-8 in key, field, member, channel, or command name"
                )
            }
        }
    }
}

pub(crate) fn parse<'a>(args: &'a [&'a [u8]]) -> Result<ParsedCommand<'a>, CommandParseError> {
    let name = args.first().copied().ok_or(CommandParseError::Empty)?;
    if name.is_empty() {
        return Err(CommandParseError::Empty);
    }
    validate_utf8_identity_args(args)?;
    Ok(ParsedCommand {
        args,
        name,
        meta: meta(name),
    })
}

fn validate_utf8_identity_args(args: &[&[u8]]) -> Result<(), CommandParseError> {
    let Some(cmd) = args.first().copied() else {
        return Err(CommandParseError::Empty);
    };
    std::str::from_utf8(cmd).map_err(|_| CommandParseError::InvalidUtf8)?;

    let all_after_command = |args: &[&[u8]]| {
        args.iter()
            .skip(1)
            .try_for_each(|arg| std::str::from_utf8(arg).map(|_| ()))
            .map_err(|_| CommandParseError::InvalidUtf8)
    };
    let key_only = |args: &[&[u8]]| {
        if let Some(key) = args.get(1) {
            std::str::from_utf8(key).map_err(|_| CommandParseError::InvalidUtf8)?;
        }
        Ok(())
    };

    if eq(cmd, b"MGET")
        || eq(cmd, b"DEL")
        || eq(cmd, b"UNLINK")
        || eq(cmd, b"EXISTS")
        || eq(cmd, b"SUNION")
        || eq(cmd, b"SINTER")
        || eq(cmd, b"SDIFF")
        || matches!(command_kind(cmd), CommandKind::PubSub(_))
        || eq(cmd, b"KEYS")
        || eq(cmd, b"WATCH")
    {
        return all_after_command(args);
    }

    if eq(cmd, b"MSET") || eq(cmd, b"MSETNX") {
        for idx in (1..args.len()).step_by(2) {
            std::str::from_utf8(args[idx]).map_err(|_| CommandParseError::InvalidUtf8)?;
        }
        return Ok(());
    }

    if eq(cmd, b"HSET") || eq(cmd, b"HMSET") {
        key_only(args)?;
        for idx in (2..args.len()).step_by(2) {
            std::str::from_utf8(args[idx]).map_err(|_| CommandParseError::InvalidUtf8)?;
        }
        return Ok(());
    }

    if eq(cmd, b"HGET")
        || eq(cmd, b"HMGET")
        || eq(cmd, b"HDEL")
        || eq(cmd, b"HEXISTS")
        || eq(cmd, b"HINCRBY")
        || eq(cmd, b"HINCRBYFLOAT")
    {
        return all_after_command(args);
    }

    if eq(cmd, b"SADD")
        || eq(cmd, b"SREM")
        || eq(cmd, b"SISMEMBER")
        || eq(cmd, b"SRANDMEMBER")
        || eq(cmd, b"SPOP")
        || eq(cmd, b"ZREM")
        || eq(cmd, b"ZSCORE")
        || eq(cmd, b"ZINCRBY")
        || eq(cmd, b"GEOPOS")
        || eq(cmd, b"GEODIST")
    {
        return all_after_command(args);
    }

    if eq(cmd, b"ZADD") {
        key_only(args)?;
        let mut idx = 2;
        while idx < args.len() {
            if eq(args[idx], b"NX")
                || eq(args[idx], b"XX")
                || eq(args[idx], b"GT")
                || eq(args[idx], b"LT")
                || eq(args[idx], b"CH")
            {
                idx += 1;
            } else {
                break;
            }
        }
        while idx + 1 < args.len() {
            std::str::from_utf8(args[idx + 1]).map_err(|_| CommandParseError::InvalidUtf8)?;
            idx += 2;
        }
        return Ok(());
    }

    if eq(cmd, b"GEOADD") {
        key_only(args)?;
        let mut idx = 4;
        while idx < args.len() {
            std::str::from_utf8(args[idx]).map_err(|_| CommandParseError::InvalidUtf8)?;
            idx += 3;
        }
        return Ok(());
    }

    if eq(cmd, b"XADD") {
        key_only(args)?;
        let mut idx = 2;
        while idx < args.len() {
            if eq(args[idx], b"MAXLEN") {
                idx += 2;
                if idx < args.len() && args[idx - 1] == b"~" {
                    idx += 1;
                }
            } else if eq(args[idx], b"NOMKSTREAM") {
                idx += 1;
            } else {
                break;
            }
        }
        idx += 1;
        while idx < args.len() {
            std::str::from_utf8(args[idx]).map_err(|_| CommandParseError::InvalidUtf8)?;
            idx += 2;
        }
        return Ok(());
    }

    key_only(args)
}

pub(crate) fn eq(input: &[u8], expected: &[u8]) -> bool {
    input.len() == expected.len()
        && input
            .iter()
            .zip(expected)
            .all(|(a, b)| a.to_ascii_uppercase() == *b)
}

fn meta(cmd: &[u8]) -> CommandMeta {
    let kind = command_kind(cmd);
    CommandMeta {
        kind,
        access: shard_access(cmd),
        public_without_auth: public_without_auth(cmd),
    }
}

fn command_kind(cmd: &[u8]) -> CommandKind {
    if eq(cmd, b"AUTH") {
        return CommandKind::Auth;
    }
    if eq(cmd, b"MULTI")
        || eq(cmd, b"EXEC")
        || eq(cmd, b"DISCARD")
        || eq(cmd, b"WATCH")
        || eq(cmd, b"UNWATCH")
    {
        return CommandKind::Transaction;
    }
    if eq(cmd, b"SUBSCRIBE") {
        return CommandKind::PubSub(PubSubCommand::Subscribe);
    }
    if eq(cmd, b"UNSUBSCRIBE") {
        return CommandKind::PubSub(PubSubCommand::Unsubscribe);
    }
    if eq(cmd, b"PSUBSCRIBE") {
        return CommandKind::PubSub(PubSubCommand::PSubscribe);
    }
    if eq(cmd, b"PUNSUBSCRIBE") {
        return CommandKind::PubSub(PubSubCommand::PUnsubscribe);
    }
    if eq(cmd, b"KSUB") {
        return CommandKind::PubSub(PubSubCommand::KSubscribe);
    }
    if eq(cmd, b"KUNSUB") {
        return CommandKind::PubSub(PubSubCommand::KUnsubscribe);
    }
    if eq(cmd, b"PUBLISH") {
        return CommandKind::PubSub(PubSubCommand::Publish);
    }
    if eq(cmd, b"BLPOP")
        || eq(cmd, b"BRPOP")
        || eq(cmd, b"BLMOVE")
        || eq(cmd, b"BZPOPMIN")
        || eq(cmd, b"BZPOPMAX")
        || eq(cmd, b"XREAD")
        || eq(cmd, b"XREADGROUP")
    {
        return CommandKind::Blocking;
    }
    CommandKind::General
}

fn public_without_auth(cmd: &[u8]) -> bool {
    eq(cmd, b"AUTH") || eq(cmd, b"HELLO") || eq(cmd, b"PING") || eq(cmd, b"QUIT")
}

fn shard_access(cmd: &[u8]) -> ShardAccess {
    if eq(cmd, b"GET")
        || eq(cmd, b"STRLEN")
        || eq(cmd, b"LLEN")
        || eq(cmd, b"SCARD")
        || eq(cmd, b"HGET")
        || eq(cmd, b"HLEN")
        || eq(cmd, b"ZCARD")
        || eq(cmd, b"ZSCORE")
        || eq(cmd, b"TTL")
        || eq(cmd, b"PTTL")
        || eq(cmd, b"TYPE")
    {
        return ShardAccess::SingleRead;
    }
    if eq(cmd, b"SET")
        || eq(cmd, b"INCR")
        || eq(cmd, b"DECR")
        || eq(cmd, b"INCRBY")
        || eq(cmd, b"DECRBY")
        || eq(cmd, b"LPUSH")
        || eq(cmd, b"RPUSH")
        || eq(cmd, b"LPOP")
        || eq(cmd, b"RPOP")
        || eq(cmd, b"SADD")
        || eq(cmd, b"SREM")
        || eq(cmd, b"SPOP")
        || eq(cmd, b"HSET")
        || eq(cmd, b"HINCRBY")
        || eq(cmd, b"HDEL")
        || eq(cmd, b"ZADD")
        || eq(cmd, b"ZINCRBY")
        || eq(cmd, b"ZREM")
        || eq(cmd, b"ZPOPMIN")
        || eq(cmd, b"ZPOPMAX")
        || eq(cmd, b"XADD")
    {
        return ShardAccess::SingleWrite;
    }
    ShardAccess::General
}

#[cfg(test)]
mod tests {
    use super::{Command, GeoAddMember, SetOption};

    fn argv(command: Command<'_>) -> Vec<Vec<u8>> {
        command.to_owned_argv()
    }

    fn expected(args: &[&[u8]]) -> Vec<Vec<u8>> {
        args.iter().map(|arg| arg.to_vec()).collect()
    }

    #[test]
    fn command_ast_lowers_string_commands_to_redis_argv() {
        assert_eq!(
            argv(Command::Set {
                key: b"k",
                value: b"v",
                options: vec![SetOption::Ex(30), SetOption::Nx],
            }),
            expected(&[b"SET", b"k", b"v", b"EX", b"30", b"NX"])
        );
        assert_eq!(
            argv(Command::PSetEx {
                key: b"k",
                milliseconds: 25,
                value: b"v",
            }),
            expected(&[b"PSETEX", b"k", b"25", b"v"])
        );
        assert_eq!(
            argv(Command::MSet {
                pairs: vec![(b"k1", b"v1"), (b"k2", b"v2")],
            }),
            expected(&[b"MSET", b"k1", b"v1", b"k2", b"v2"])
        );
        assert_eq!(
            argv(Command::IncrBy {
                key: b"k",
                increment: -2,
            }),
            expected(&[b"INCRBY", b"k", b"-2"])
        );
    }

    #[test]
    fn command_ast_lowers_collection_commands_to_redis_argv() {
        assert_eq!(
            argv(Command::LPush {
                key: b"list",
                values: vec![b"a", b"b"],
            }),
            expected(&[b"LPUSH", b"list", b"a", b"b"])
        );
        assert_eq!(
            argv(Command::HSet {
                key: b"hash",
                field: b"field",
                value: b"value",
            }),
            expected(&[b"HSET", b"hash", b"field", b"value"])
        );
        assert_eq!(
            argv(Command::HIncrBy {
                key: b"hash",
                field: b"counter",
                increment: -2,
            }),
            expected(&[b"HINCRBY", b"hash", b"counter", b"-2"])
        );
        assert_eq!(
            argv(Command::SAdd {
                key: b"set",
                members: vec![b"a", b"b"],
            }),
            expected(&[b"SADD", b"set", b"a", b"b"])
        );
        assert_eq!(
            argv(Command::ZAdd {
                key: b"zset",
                score: 1.5,
                member: b"member",
            }),
            expected(&[b"ZADD", b"zset", b"1.5", b"member"])
        );
        assert_eq!(
            argv(Command::ZIncrBy {
                key: b"zset",
                increment: 2.5,
                member: b"member",
            }),
            expected(&[b"ZINCRBY", b"zset", b"2.5", b"member"])
        );
    }

    #[test]
    fn command_ast_lowers_geo_and_raw_commands_to_redis_argv() {
        assert_eq!(
            argv(Command::GeoAdd {
                key: b"geo",
                members: vec![GeoAddMember {
                    longitude: 1.25,
                    latitude: 2.5,
                    member: b"place",
                }],
            }),
            expected(&[b"GEOADD", b"geo", b"1.25", b"2.5", b"place"])
        );
        assert_eq!(
            argv(Command::GeoDist {
                key: b"geo",
                member_a: b"a",
                member_b: b"b",
                unit: b"km",
            }),
            expected(&[b"GEODIST", b"geo", b"a", b"b", b"km"])
        );
        assert_eq!(
            argv(Command::XAdd {
                key: b"stream",
                id: b"*",
                fields: vec![(b"field", b"value")],
            }),
            expected(&[b"XADD", b"stream", b"*", b"field", b"value"])
        );
        assert_eq!(
            argv(Command::Raw {
                name: b"ZPOPMIN",
                args: vec![b"zset"],
            }),
            expected(&[b"ZPOPMIN", b"zset"])
        );
    }
}
