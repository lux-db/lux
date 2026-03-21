mod cmd;
mod eviction;
mod geo;
mod hll;
mod hnsw;
mod lua;
mod pubsub;
mod resp;
mod snapshot;
mod store;
mod tables;

use bytes::BytesMut;
use cmd::CmdResult;
use pubsub::Broker;
use resp::Parser;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Instant;
use store::Store;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

pub static CONNECTED_CLIENTS: AtomicUsize = AtomicUsize::new(0);
pub static TOTAL_COMMANDS: AtomicUsize = AtomicUsize::new(0);
pub static START_TIME: OnceLock<Instant> = OnceLock::new();
static SCRIPT_GATE: parking_lot::RwLock<()> = parking_lot::RwLock::new(());

#[tokio::main]
async fn main() -> std::io::Result<()> {
    START_TIME.set(Instant::now()).ok();

    let port: u16 = std::env::var("LUX_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(6379);
    let addr = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(&addr).await?;
    let store = Arc::new(Store::new());
    let broker = Broker::new();
    let script_engine = Arc::new(lua::ScriptEngine::new());

    let require_auth = std::env::var("LUX_PASSWORD").is_ok_and(|p| !p.is_empty());

    match snapshot::load(&store) {
        Ok(0) => println!("no snapshot found"),
        Ok(n) => println!("loaded {n} keys from snapshot"),
        Err(e) => eprintln!("snapshot load error: {e}"),
    }

    tokio::spawn(snapshot::background_save_loop(store.clone()));
    tokio::spawn(broker.clone().run_key_event_loop());

    {
        let store = store.clone();
        tokio::spawn(async move {
            let start = Instant::now();
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                let now = Instant::now();
                let secs = now.duration_since(start).as_secs() as u32;
                store::LRU_CLOCK.store(secs & 0x00FF_FFFF, std::sync::atomic::Ordering::Relaxed);
                store.expire_sweep(now);
            }
        });
    }

    println!("lux v{} ready on {addr}", env!("CARGO_PKG_VERSION"));

    loop {
        let (socket, peer) = listener.accept().await?;
        let store = store.clone();
        let broker = broker.clone();
        let script_engine = script_engine.clone();
        socket.set_nodelay(true).ok();

        tokio::spawn(async move {
            CONNECTED_CLIENTS.fetch_add(1, Ordering::Relaxed);
            let result =
                handle_connection(socket, peer, store, broker, require_auth, script_engine).await;
            CONNECTED_CLIENTS.fetch_sub(1, Ordering::Relaxed);
            if let Err(e) = result {
                if e.kind() != std::io::ErrorKind::ConnectionReset {
                    eprintln!("connection error {peer}: {e}");
                }
            }
        });
    }
}

#[inline(always)]
fn cmd_eq_fast(input: &[u8], expected: &[u8]) -> bool {
    input.len() == expected.len()
        && input
            .iter()
            .zip(expected)
            .all(|(a, b)| a.to_ascii_uppercase() == *b)
}

#[inline(always)]
fn is_tx_cmd(cmd: &[u8]) -> bool {
    cmd_eq_fast(cmd, b"MULTI")
        || cmd_eq_fast(cmd, b"EXEC")
        || cmd_eq_fast(cmd, b"DISCARD")
        || cmd_eq_fast(cmd, b"WATCH")
        || cmd_eq_fast(cmd, b"UNWATCH")
}

#[inline(always)]
fn fire_key_events(broker: &Broker, args: &[&[u8]]) {
    if args.len() < 2 || !broker.has_key_subs() {
        return;
    }
    fire_key_events_slow(broker, args);
}

#[inline(never)]
fn fire_key_events_slow(broker: &Broker, args: &[&[u8]]) {
    let cmd = args[0];
    if !crate::eviction::is_write_command(cmd) {
        return;
    }
    if cmd_eq_fast(cmd, b"FLUSHDB") || cmd_eq_fast(cmd, b"FLUSHALL") {
        return;
    }

    if cmd_eq_fast(cmd, b"MSET") || cmd_eq_fast(cmd, b"MSETNX") {
        let mut i = 1;
        while i < args.len() {
            broker.enqueue_key_event(args[i], cmd);
            i += 2;
        }
    } else if cmd_eq_fast(cmd, b"DEL") || cmd_eq_fast(cmd, b"UNLINK") {
        for arg in &args[1..] {
            broker.enqueue_key_event(arg, cmd);
        }
    } else if cmd_eq_fast(cmd, b"RENAME") && args.len() >= 3 {
        broker.enqueue_key_event(args[1], cmd);
        broker.enqueue_key_event(args[2], cmd);
    } else {
        broker.enqueue_key_event(args[1], cmd);
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_tx_cmd(
    args: &[&[u8]],
    in_multi: &mut bool,
    tx_error: &mut bool,
    tx_queue: &mut Vec<Vec<Vec<u8>>>,
    watched: &mut Vec<(String, usize, u64)>,
    authenticated: &mut bool,
    store: &Arc<Store>,
    broker: &Broker,
    write_buf: &mut BytesMut,
    now: Instant,
) -> bool {
    if cmd_eq_fast(args[0], b"MULTI") {
        if *in_multi {
            let cmd_name = std::str::from_utf8(args[0])
                .unwrap_or("multi")
                .to_lowercase();
            resp::write_error(
                write_buf,
                &format!(
                    "ERR Command '{}' not allowed inside a transaction",
                    cmd_name
                ),
            );
            *tx_error = true;
        } else {
            *in_multi = true;
            *tx_error = false;
            resp::write_ok(write_buf);
        }
        return true;
    } else if cmd_eq_fast(args[0], b"EXEC") {
        if !*in_multi {
            resp::write_error(write_buf, "ERR EXEC without MULTI");
        } else if *tx_error {
            resp::write_error(
                write_buf,
                "EXECABORT Transaction discarded because of previous errors.",
            );
        } else {
            let mut aborted = false;
            for (_, shard_idx, version) in watched.iter() {
                if store.shard_version(*shard_idx) != *version {
                    aborted = true;
                    break;
                }
            }
            if aborted {
                resp::write_null_array(write_buf);
            } else {
                let queue = std::mem::take(tx_queue);
                resp::write_array_header(write_buf, queue.len());
                for owned_args in &queue {
                    let refs: Vec<&[u8]> = owned_args.iter().map(|v| v.as_slice()).collect();
                    let cmd_result = {
                        let _guard = SCRIPT_GATE.read();
                        cmd::execute(store, broker, &refs, write_buf, now)
                    };
                    match cmd_result {
                        CmdResult::Written => {}
                        CmdResult::Authenticated => {
                            *authenticated = true;
                        }
                        CmdResult::Subscribe { .. }
                        | CmdResult::PSubscribe { .. }
                        | CmdResult::KSubscribe { .. }
                        | CmdResult::KUnsubscribe { .. } => {
                            resp::write_error(
                                write_buf,
                                "ERR Command 'subscribe' not allowed inside a transaction",
                            );
                        }
                        CmdResult::Publish { channel, message } => {
                            let count = broker.publish(&channel, message);
                            resp::write_integer(write_buf, count);
                        }
                        CmdResult::BlockPop { .. }
                        | CmdResult::BlockMove { .. }
                        | CmdResult::BlockStreamRead { .. }
                        | CmdResult::BlockZPop { .. } => {
                            resp::write_error(
                                write_buf,
                                "ERR blocking commands not allowed inside a transaction",
                            );
                        }
                        CmdResult::Eval { .. } | CmdResult::ScriptOp => {
                            resp::write_error(write_buf, "ERR EVAL not supported in transaction");
                        }
                    }
                }
            }
        }
        *in_multi = false;
        *tx_error = false;
        tx_queue.clear();
        watched.clear();
        return true;
    } else if cmd_eq_fast(args[0], b"DISCARD") {
        if !*in_multi {
            resp::write_error(write_buf, "ERR DISCARD without MULTI");
        } else {
            *in_multi = false;
            *tx_error = false;
            tx_queue.clear();
            watched.clear();
            resp::write_ok(write_buf);
        }
        return true;
    } else if cmd_eq_fast(args[0], b"WATCH") {
        if *in_multi {
            resp::write_error(
                write_buf,
                "ERR Command 'watch' not allowed inside a transaction",
            );
            *tx_error = true;
        } else if args.len() < 2 {
            resp::write_error(
                write_buf,
                "ERR wrong number of arguments for 'watch' command",
            );
        } else {
            for key_bytes in &args[1..] {
                let key = std::str::from_utf8(key_bytes).unwrap_or("").to_string();
                let shard_idx = store.shard_for_key(key_bytes);
                let version = store.shard_version(shard_idx);
                watched.push((key, shard_idx, version));
            }
            resp::write_ok(write_buf);
        }
        return true;
    } else if cmd_eq_fast(args[0], b"UNWATCH") {
        watched.clear();
        resp::write_ok(write_buf);
        return true;
    }

    if *in_multi {
        if cmd_eq_fast(args[0], b"SUBSCRIBE")
            || cmd_eq_fast(args[0], b"PSUBSCRIBE")
            || cmd_eq_fast(args[0], b"KSUB")
            || cmd_eq_fast(args[0], b"KUNSUB")
        {
            resp::write_error(
                write_buf,
                &format!(
                    "ERR Command '{}' not allowed inside a transaction",
                    std::str::from_utf8(args[0])
                        .unwrap_or("subscribe")
                        .to_lowercase()
                ),
            );
            *tx_error = true;
        } else if is_blocking_cmd(args[0]) {
            resp::write_error(
                write_buf,
                &format!(
                    "ERR Command '{}' not allowed inside a transaction",
                    std::str::from_utf8(args[0])
                        .unwrap_or("unknown")
                        .to_lowercase()
                ),
            );
            *tx_error = true;
        } else if !cmd::is_known_command(args[0]) {
            let cmd_name = std::str::from_utf8(args[0])
                .unwrap_or("unknown")
                .to_lowercase();
            resp::write_error(write_buf, &format!("ERR unknown command '{cmd_name}'"));
            *tx_error = true;
        } else {
            match cmd::validate_args(args) {
                Ok(()) => {
                    let owned: Vec<Vec<u8>> = args.iter().map(|a| a.to_vec()).collect();
                    tx_queue.push(owned);
                    resp::write_queued(write_buf);
                }
                Err(e) => {
                    resp::write_error(write_buf, &e);
                    *tx_error = true;
                }
            }
        }
        return true;
    }

    false
}

#[inline(always)]
fn is_blocking_cmd(cmd: &[u8]) -> bool {
    cmd_eq_fast(cmd, b"BLPOP")
        || cmd_eq_fast(cmd, b"BRPOP")
        || cmd_eq_fast(cmd, b"BLMOVE")
        || cmd_eq_fast(cmd, b"BZPOPMIN")
        || cmd_eq_fast(cmd, b"BZPOPMAX")
        || cmd_eq_fast(cmd, b"EVAL")
        || cmd_eq_fast(cmd, b"EVALSHA")
        || cmd_eq_fast(cmd, b"SCRIPT")
}

async fn handle_connection(
    mut socket: tokio::net::TcpStream,
    _peer: std::net::SocketAddr,
    store: Arc<Store>,
    broker: Broker,
    require_auth: bool,
    script_engine: Arc<lua::ScriptEngine>,
) -> std::io::Result<()> {
    let mut read_buf = vec![0u8; 65536];
    let mut write_buf = BytesMut::with_capacity(65536);
    let mut pending = BytesMut::new();
    let mut subscriptions: HashMap<String, broadcast::Receiver<pubsub::Message>> = HashMap::new();
    let mut pattern_subs: HashMap<String, broadcast::Receiver<pubsub::Message>> = HashMap::new();
    let mut key_subs: HashMap<String, broadcast::Receiver<pubsub::Message>> = HashMap::new();
    let mut sub_mode = false;
    let mut authenticated = !require_auth;
    let mut in_multi = false;
    let mut tx_queue: Vec<Vec<Vec<u8>>> = Vec::new();
    let mut watched: Vec<(String, usize, u64)> = Vec::new();
    let mut tx_error = false;

    loop {
        if sub_mode {
            tokio::select! {
                result = socket.read(&mut read_buf) => {
                    let n = match result {
                        Ok(0) => return Ok(()),
                        Ok(n) => n,
                        Err(e) => return Err(e),
                    };
                    pending.extend_from_slice(&read_buf[..n]);
                    let now = Instant::now();
                    let mut parser = Parser::new(&pending);
                    while let Ok(Some(args)) = parser.parse_command() {
                        if args.is_empty() { continue; }
                        if cmd_eq_fast(args[0], b"SUBSCRIBE") {
                            for ch_bytes in &args[1..] {
                                let ch = std::str::from_utf8(ch_bytes).unwrap_or("").to_string();
                                if !subscriptions.contains_key(&ch) {
                                    let rx = broker.subscribe(&ch);
                                    subscriptions.insert(ch.clone(), rx);
                                }
                                resp::write_array_header(&mut write_buf, 3);
                                resp::write_bulk(&mut write_buf, "subscribe");
                                resp::write_bulk(&mut write_buf, &ch);
                                resp::write_integer(&mut write_buf, (subscriptions.len() + pattern_subs.len() + key_subs.len()) as i64);
                            }
                        } else if cmd_eq_fast(args[0], b"UNSUBSCRIBE") {
                            let channels: Vec<String> = if args.len() > 1 {
                                args[1..].iter().map(|a| std::str::from_utf8(a).unwrap_or("").to_string()).collect()
                            } else {
                                subscriptions.keys().cloned().collect()
                            };
                            for ch in &channels {
                                subscriptions.remove(ch);
                                resp::write_array_header(&mut write_buf, 3);
                                resp::write_bulk(&mut write_buf, "unsubscribe");
                                resp::write_bulk(&mut write_buf, ch);
                                resp::write_integer(&mut write_buf, (subscriptions.len() + pattern_subs.len() + key_subs.len()) as i64);
                            }
                            if subscriptions.is_empty() && pattern_subs.is_empty() {
                                sub_mode = false;
                            }
                        } else if cmd_eq_fast(args[0], b"PSUBSCRIBE") {
                            for pat_bytes in &args[1..] {
                                let pat = std::str::from_utf8(pat_bytes).unwrap_or("").to_string();
                                if !pattern_subs.contains_key(&pat) {
                                    let rx = broker.psubscribe(&pat);
                                    pattern_subs.insert(pat.clone(), rx);
                                }
                                resp::write_array_header(&mut write_buf, 3);
                                resp::write_bulk(&mut write_buf, "psubscribe");
                                resp::write_bulk(&mut write_buf, &pat);
                                resp::write_integer(&mut write_buf, (subscriptions.len() + pattern_subs.len() + key_subs.len()) as i64);
                            }
                        } else if cmd_eq_fast(args[0], b"PUNSUBSCRIBE") {
                            let patterns: Vec<String> = if args.len() > 1 {
                                args[1..].iter().map(|a| std::str::from_utf8(a).unwrap_or("").to_string()).collect()
                            } else {
                                pattern_subs.keys().cloned().collect()
                            };
                            for pat in &patterns {
                                pattern_subs.remove(pat);
                                resp::write_array_header(&mut write_buf, 3);
                                resp::write_bulk(&mut write_buf, "punsubscribe");
                                resp::write_bulk(&mut write_buf, pat);
                                resp::write_integer(&mut write_buf, (subscriptions.len() + pattern_subs.len() + key_subs.len()) as i64);
                            }
                            if subscriptions.is_empty() && pattern_subs.is_empty() && key_subs.is_empty() {
                                sub_mode = false;
                            }
                        } else if cmd_eq_fast(args[0], b"KSUB") {
                            if args.len() < 2 {
                                resp::write_error(&mut write_buf, "ERR wrong number of arguments for 'ksub' command");
                            } else {
                                for pat_bytes in &args[1..] {
                                    let pat = std::str::from_utf8(pat_bytes).unwrap_or("").to_string();
                                    if !key_subs.contains_key(&pat) {
                                        let rx = broker.ksubscribe(&pat);
                                        key_subs.insert(pat.clone(), rx);
                                    }
                                    resp::write_array_header(&mut write_buf, 3);
                                    resp::write_bulk(&mut write_buf, "ksub");
                                    resp::write_bulk(&mut write_buf, &pat);
                                    resp::write_integer(&mut write_buf, (subscriptions.len() + pattern_subs.len() + key_subs.len()) as i64);
                                }
                            }
                        } else if cmd_eq_fast(args[0], b"KUNSUB") {
                            let patterns: Vec<String> = if args.len() > 1 {
                                args[1..].iter().map(|a| std::str::from_utf8(a).unwrap_or("").to_string()).collect()
                            } else {
                                key_subs.keys().cloned().collect()
                            };
                            for pat in &patterns {
                                if key_subs.remove(pat).is_some() {
                                    broker.kunsub(pat);
                                }
                                resp::write_array_header(&mut write_buf, 3);
                                resp::write_bulk(&mut write_buf, "kunsub");
                                resp::write_bulk(&mut write_buf, pat);
                                resp::write_integer(&mut write_buf, (subscriptions.len() + pattern_subs.len() + key_subs.len()) as i64);
                            }
                            if subscriptions.is_empty() && pattern_subs.is_empty() && key_subs.is_empty() {
                                sub_mode = false;
                            }
                        } else if cmd_eq_fast(args[0], b"PING") {
                            if args.len() > 1 {
                                resp::write_bulk_raw(&mut write_buf, args[1]);
                            } else {
                                resp::write_pong(&mut write_buf);
                            }
                        } else {
                            resp::write_error(&mut write_buf, "ERR only SUBSCRIBE, UNSUBSCRIBE, and PING are allowed in subscribe mode");
                        }
                        let _ = now;
                    }
                    let consumed = parser.pos();
                    let _ = pending.split_to(consumed);
                    if !write_buf.is_empty() {
                        socket.write_all(&write_buf).await?;
                        write_buf.clear();
                    }
                }
                msg = async {
                    for (_ch, rx) in subscriptions.iter_mut() {
                        if let Ok(msg) = rx.try_recv() {
                            return Some(msg);
                        }
                    }
                    for (_pat, rx) in pattern_subs.iter_mut() {
                        if let Ok(msg) = rx.try_recv() {
                            return Some(msg);
                        }
                    }
                    for (_pat, rx) in key_subs.iter_mut() {
                        if let Ok(msg) = rx.try_recv() {
                            return Some(msg);
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    for (_ch, rx) in subscriptions.iter_mut() {
                        if let Ok(msg) = rx.try_recv() {
                            return Some(msg);
                        }
                    }
                    for (_pat, rx) in pattern_subs.iter_mut() {
                        if let Ok(msg) = rx.try_recv() {
                            return Some(msg);
                        }
                    }
                    for (_pat, rx) in key_subs.iter_mut() {
                        if let Ok(msg) = rx.try_recv() {
                            return Some(msg);
                        }
                    }
                    None
                } => {
                    if let Some(msg) = msg {
                        match msg.kind {
                            pubsub::MessageKind::KeyEvent => {
                                resp::write_array_header(&mut write_buf, 4);
                                resp::write_bulk(&mut write_buf, "kmessage");
                                resp::write_bulk(&mut write_buf, msg.pattern.as_deref().unwrap_or(""));
                                resp::write_bulk(&mut write_buf, &msg.channel);
                                resp::write_bulk(&mut write_buf, &msg.payload);
                            }
                            pubsub::MessageKind::PubSub => {
                                if let Some(ref pat) = msg.pattern {
                                    resp::write_array_header(&mut write_buf, 4);
                                    resp::write_bulk(&mut write_buf, "pmessage");
                                    resp::write_bulk(&mut write_buf, pat);
                                    resp::write_bulk(&mut write_buf, &msg.channel);
                                    resp::write_bulk(&mut write_buf, &msg.payload);
                                } else {
                                    resp::write_array_header(&mut write_buf, 3);
                                    resp::write_bulk(&mut write_buf, "message");
                                    resp::write_bulk(&mut write_buf, &msg.channel);
                                    resp::write_bulk(&mut write_buf, &msg.payload);
                                }
                            }
                        }
                        socket.write_all(&write_buf).await?;
                        write_buf.clear();
                    }
                }
            }
        } else {
            let n = match socket.read(&mut read_buf).await {
                Ok(0) => return Ok(()),
                Ok(n) => n,
                Err(e) => return Err(e),
            };

            pending.extend_from_slice(&read_buf[..n]);
            let now = Instant::now();
            let mut parser = Parser::new(&pending);

            let mut commands: Vec<Vec<&[u8]>> = Vec::new();
            while let Ok(Some(args)) = parser.parse_command() {
                if args.is_empty() {
                    continue;
                }
                commands.push(args);
            }
            let consumed = parser.pos();

            let mut deferred_action: Option<CmdResult> = None;

            if commands.len() <= 1 {
                for args in &commands {
                    if !authenticated
                        && !cmd_eq_fast(args[0], b"AUTH")
                        && !cmd_eq_fast(args[0], b"PING")
                        && !cmd_eq_fast(args[0], b"QUIT")
                    {
                        resp::write_error(&mut write_buf, "NOAUTH Authentication required");
                        continue;
                    }
                    TOTAL_COMMANDS.fetch_add(1, Ordering::Relaxed);

                    if handle_tx_cmd(
                        args,
                        &mut in_multi,
                        &mut tx_error,
                        &mut tx_queue,
                        &mut watched,
                        &mut authenticated,
                        &store,
                        &broker,
                        &mut write_buf,
                        now,
                    )
                    .await
                    {
                        continue;
                    }

                    let cmd_result = {
                        let _guard = SCRIPT_GATE.read();
                        cmd::execute(&store, &broker, args, &mut write_buf, now)
                    };
                    match cmd_result {
                        CmdResult::Written => {
                            fire_key_events(&broker, args);
                        }
                        CmdResult::Authenticated => {
                            authenticated = true;
                        }
                        CmdResult::Subscribe { channels } => {
                            for ch in &channels {
                                let rx = broker.subscribe(ch);
                                subscriptions.insert(ch.clone(), rx);
                                resp::write_array_header(&mut write_buf, 3);
                                resp::write_bulk(&mut write_buf, "subscribe");
                                resp::write_bulk(&mut write_buf, ch);
                                resp::write_integer(
                                    &mut write_buf,
                                    (subscriptions.len() + pattern_subs.len()) as i64,
                                );
                            }
                            sub_mode = true;
                            break;
                        }
                        CmdResult::PSubscribe { patterns } => {
                            for pat in &patterns {
                                let rx = broker.psubscribe(pat);
                                pattern_subs.insert(pat.clone(), rx);
                                resp::write_array_header(&mut write_buf, 3);
                                resp::write_bulk(&mut write_buf, "psubscribe");
                                resp::write_bulk(&mut write_buf, pat);
                                resp::write_integer(
                                    &mut write_buf,
                                    (subscriptions.len() + pattern_subs.len()) as i64,
                                );
                            }
                            sub_mode = true;
                            break;
                        }
                        CmdResult::KSubscribe { patterns } => {
                            for pat in &patterns {
                                if !key_subs.contains_key(pat) {
                                    let rx = broker.ksubscribe(pat);
                                    key_subs.insert(pat.clone(), rx);
                                }
                                resp::write_array_header(&mut write_buf, 3);
                                resp::write_bulk(&mut write_buf, "ksub");
                                resp::write_bulk(&mut write_buf, pat);
                                resp::write_integer(
                                    &mut write_buf,
                                    (subscriptions.len() + pattern_subs.len() + key_subs.len())
                                        as i64,
                                );
                            }
                            sub_mode = true;
                            break;
                        }
                        CmdResult::KUnsubscribe { patterns } => {
                            let pats: Vec<String> = if patterns.is_empty() {
                                key_subs.keys().cloned().collect()
                            } else {
                                patterns
                            };
                            for pat in &pats {
                                if key_subs.remove(pat).is_some() {
                                    broker.kunsub(pat);
                                }
                                resp::write_array_header(&mut write_buf, 3);
                                resp::write_bulk(&mut write_buf, "kunsub");
                                resp::write_bulk(&mut write_buf, pat);
                                resp::write_integer(
                                    &mut write_buf,
                                    (subscriptions.len() + pattern_subs.len() + key_subs.len())
                                        as i64,
                                );
                            }
                        }
                        CmdResult::Publish { channel, message } => {
                            let count = broker.publish(&channel, message);
                            resp::write_integer(&mut write_buf, count);
                        }
                        CmdResult::BlockPop { .. }
                        | CmdResult::BlockMove { .. }
                        | CmdResult::BlockStreamRead { .. }
                        | CmdResult::BlockZPop { .. } => {
                            deferred_action = Some(cmd_result);
                            break;
                        }
                        CmdResult::Eval { script, keys, argv } => {
                            handle_eval(
                                &mut write_buf,
                                &store,
                                &broker,
                                &script_engine,
                                &script,
                                &keys,
                                &argv,
                                now,
                            );
                        }
                        CmdResult::ScriptOp => {
                            let owned_args: Vec<Vec<u8>> =
                                args.iter().map(|a| a.to_vec()).collect();
                            let refs: Vec<&[u8]> =
                                owned_args.iter().map(|v| v.as_slice()).collect();
                            handle_script_op(&mut write_buf, &script_engine, &refs);
                        }
                    }
                }
            } else {
                let cmd_count = commands.len();
                TOTAL_COMMANDS.fetch_add(cmd_count, Ordering::Relaxed);

                let mut has_special = in_multi;
                let mut all_single_key_rw = true;
                for args in &commands {
                    if !authenticated
                        && !cmd_eq_fast(args[0], b"AUTH")
                        && !cmd_eq_fast(args[0], b"PING")
                        && !cmd_eq_fast(args[0], b"QUIT")
                    {
                        has_special = true;
                        break;
                    }
                    if cmd_eq_fast(args[0], b"SUBSCRIBE")
                        || cmd_eq_fast(args[0], b"PSUBSCRIBE")
                        || cmd_eq_fast(args[0], b"KSUB")
                        || cmd_eq_fast(args[0], b"KUNSUB")
                        || cmd_eq_fast(args[0], b"PUBLISH")
                        || cmd_eq_fast(args[0], b"AUTH")
                        || is_tx_cmd(args[0])
                        || is_blocking_cmd(args[0])
                    {
                        has_special = true;
                        break;
                    }
                    if args.len() < 2
                        || cmd_eq_fast(args[0], b"MGET")
                        || cmd_eq_fast(args[0], b"MSET")
                        || cmd_eq_fast(args[0], b"DEL")
                        || cmd_eq_fast(args[0], b"EXISTS")
                        || cmd_eq_fast(args[0], b"KEYS")
                        || cmd_eq_fast(args[0], b"SCAN")
                        || cmd_eq_fast(args[0], b"FLUSHDB")
                        || cmd_eq_fast(args[0], b"FLUSHALL")
                        || cmd_eq_fast(args[0], b"DBSIZE")
                        || cmd_eq_fast(args[0], b"SAVE")
                        || cmd_eq_fast(args[0], b"INFO")
                        || cmd_eq_fast(args[0], b"RENAME")
                        || cmd_eq_fast(args[0], b"SUNION")
                        || cmd_eq_fast(args[0], b"SINTER")
                        || cmd_eq_fast(args[0], b"SDIFF")
                        || cmd_eq_fast(args[0], b"ZUNIONSTORE")
                        || cmd_eq_fast(args[0], b"ZINTERSTORE")
                        || cmd_eq_fast(args[0], b"ZDIFFSTORE")
                    {
                        all_single_key_rw = false;
                    }
                }

                if has_special || !all_single_key_rw {
                    for args in &commands {
                        if !authenticated
                            && !cmd_eq_fast(args[0], b"AUTH")
                            && !cmd_eq_fast(args[0], b"PING")
                            && !cmd_eq_fast(args[0], b"QUIT")
                        {
                            resp::write_error(&mut write_buf, "NOAUTH Authentication required");
                            continue;
                        }

                        if handle_tx_cmd(
                            args,
                            &mut in_multi,
                            &mut tx_error,
                            &mut tx_queue,
                            &mut watched,
                            &mut authenticated,
                            &store,
                            &broker,
                            &mut write_buf,
                            now,
                        )
                        .await
                        {
                            continue;
                        }

                        let cmd_result = {
                            let _guard = SCRIPT_GATE.read();
                            cmd::execute(&store, &broker, args, &mut write_buf, now)
                        };
                        match cmd_result {
                            CmdResult::Written => {
                                fire_key_events(&broker, args);
                            }
                            CmdResult::Authenticated => {
                                authenticated = true;
                            }
                            CmdResult::Subscribe { channels } => {
                                for ch in &channels {
                                    let rx = broker.subscribe(ch);
                                    subscriptions.insert(ch.clone(), rx);
                                    resp::write_array_header(&mut write_buf, 3);
                                    resp::write_bulk(&mut write_buf, "subscribe");
                                    resp::write_bulk(&mut write_buf, ch);
                                    resp::write_integer(
                                        &mut write_buf,
                                        (subscriptions.len() + pattern_subs.len()) as i64,
                                    );
                                }
                                sub_mode = true;
                                break;
                            }
                            CmdResult::PSubscribe { patterns } => {
                                for pat in &patterns {
                                    let rx = broker.psubscribe(pat);
                                    pattern_subs.insert(pat.clone(), rx);
                                    resp::write_array_header(&mut write_buf, 3);
                                    resp::write_bulk(&mut write_buf, "psubscribe");
                                    resp::write_bulk(&mut write_buf, pat);
                                    resp::write_integer(
                                        &mut write_buf,
                                        (subscriptions.len() + pattern_subs.len()) as i64,
                                    );
                                }
                                sub_mode = true;
                                break;
                            }
                            CmdResult::KSubscribe { patterns } => {
                                for pat in &patterns {
                                    if !key_subs.contains_key(pat) {
                                        let rx = broker.ksubscribe(pat);
                                        key_subs.insert(pat.clone(), rx);
                                    }
                                    resp::write_array_header(&mut write_buf, 3);
                                    resp::write_bulk(&mut write_buf, "ksub");
                                    resp::write_bulk(&mut write_buf, pat);
                                    resp::write_integer(
                                        &mut write_buf,
                                        (subscriptions.len() + pattern_subs.len() + key_subs.len())
                                            as i64,
                                    );
                                }
                                sub_mode = true;
                                break;
                            }
                            CmdResult::KUnsubscribe { patterns } => {
                                let pats: Vec<String> = if patterns.is_empty() {
                                    key_subs.keys().cloned().collect()
                                } else {
                                    patterns
                                };
                                for pat in &pats {
                                    if key_subs.remove(pat).is_some() {
                                        broker.kunsub(pat);
                                    }
                                    resp::write_array_header(&mut write_buf, 3);
                                    resp::write_bulk(&mut write_buf, "kunsub");
                                    resp::write_bulk(&mut write_buf, pat);
                                    resp::write_integer(
                                        &mut write_buf,
                                        (subscriptions.len() + pattern_subs.len() + key_subs.len())
                                            as i64,
                                    );
                                }
                            }
                            CmdResult::Publish { channel, message } => {
                                let count = broker.publish(&channel, message);
                                resp::write_integer(&mut write_buf, count);
                            }
                            CmdResult::BlockPop { .. }
                            | CmdResult::BlockMove { .. }
                            | CmdResult::BlockStreamRead { .. }
                            | CmdResult::BlockZPop { .. } => {
                                deferred_action = Some(cmd_result);
                                break;
                            }
                            CmdResult::Eval { script, keys, argv } => {
                                handle_eval(
                                    &mut write_buf,
                                    &store,
                                    &broker,
                                    &script_engine,
                                    &script,
                                    &keys,
                                    &argv,
                                    now,
                                );
                            }
                            CmdResult::ScriptOp => {
                                let owned_args: Vec<Vec<u8>> =
                                    args.iter().map(|a| a.to_vec()).collect();
                                let refs: Vec<&[u8]> =
                                    owned_args.iter().map(|v| v.as_slice()).collect();
                                handle_script_op(&mut write_buf, &script_engine, &refs);
                            }
                        }
                    }
                } else {
                    const FL_NONE: u8 = 0;
                    const FL_READ: u8 = 1;
                    const FL_WRITE: u8 = 2;

                    let mut shards: Vec<u32> = Vec::with_capacity(cmd_count);
                    let mut flags: Vec<u8> = Vec::with_capacity(cmd_count);
                    for args in &commands {
                        shards.push(store.shard_for_key(args[1]) as u32);
                        let cmd = args[0];
                        flags.push(
                            if cmd_eq_fast(cmd, b"GET")
                                || cmd_eq_fast(cmd, b"STRLEN")
                                || cmd_eq_fast(cmd, b"LLEN")
                                || cmd_eq_fast(cmd, b"SCARD")
                                || cmd_eq_fast(cmd, b"HGET")
                                || cmd_eq_fast(cmd, b"HLEN")
                                || cmd_eq_fast(cmd, b"ZCARD")
                                || cmd_eq_fast(cmd, b"ZSCORE")
                                || cmd_eq_fast(cmd, b"TTL")
                                || cmd_eq_fast(cmd, b"PTTL")
                                || cmd_eq_fast(cmd, b"TYPE")
                            {
                                FL_READ
                            } else if cmd_eq_fast(cmd, b"SET")
                                || cmd_eq_fast(cmd, b"INCR")
                                || cmd_eq_fast(cmd, b"DECR")
                                || cmd_eq_fast(cmd, b"INCRBY")
                                || cmd_eq_fast(cmd, b"DECRBY")
                                || cmd_eq_fast(cmd, b"LPUSH")
                                || cmd_eq_fast(cmd, b"RPUSH")
                                || cmd_eq_fast(cmd, b"LPOP")
                                || cmd_eq_fast(cmd, b"RPOP")
                                || cmd_eq_fast(cmd, b"SADD")
                                || cmd_eq_fast(cmd, b"SREM")
                                || cmd_eq_fast(cmd, b"SPOP")
                                || cmd_eq_fast(cmd, b"HSET")
                                || cmd_eq_fast(cmd, b"HDEL")
                                || cmd_eq_fast(cmd, b"ZADD")
                                || cmd_eq_fast(cmd, b"ZREM")
                                || cmd_eq_fast(cmd, b"ZPOPMIN")
                                || cmd_eq_fast(cmd, b"ZPOPMAX")
                            {
                                FL_WRITE
                            } else {
                                FL_NONE
                            },
                        );
                    }

                    let mut i = 0usize;
                    while i < cmd_count {
                        let shard_idx = shards[i];
                        let mut batch_end = i + 1;
                        while batch_end < cmd_count && shards[batch_end] == shard_idx {
                            batch_end += 1;
                        }

                        let batch_flags = &flags[i..batch_end];
                        let all_classified = batch_flags.iter().all(|&f| f != FL_NONE);

                        if all_classified {
                            let has_writes = batch_flags.contains(&FL_WRITE);
                            if has_writes {
                                {
                                    let mut shard = store.lock_write_shard(shard_idx as usize);
                                    shard.version += 1;
                                    for args in &commands[i..batch_end] {
                                        cmd::execute_on_shard(
                                            &mut shard.data,
                                            &store,
                                            &broker,
                                            args,
                                            &mut write_buf,
                                            now,
                                        );
                                    }
                                }
                                if broker.has_key_subs() {
                                    for idx in i..batch_end {
                                        if batch_flags[idx - i] == FL_WRITE {
                                            let cmd_args = &commands[idx];
                                            broker.enqueue_key_event(cmd_args[1], cmd_args[0]);
                                        }
                                    }
                                }
                            } else {
                                let shard = store.lock_read_shard(shard_idx as usize);
                                for args in &commands[i..batch_end] {
                                    cmd::execute_on_shard_read(
                                        &shard.data,
                                        args,
                                        &mut write_buf,
                                        now,
                                    );
                                }
                            }
                        } else {
                            for args in &commands[i..batch_end] {
                                cmd::execute(&store, &broker, args, &mut write_buf, now);
                                fire_key_events(&broker, args);
                            }
                        }

                        i = batch_end;
                    }
                }
            }

            drop(commands);
            let _ = pending.split_to(consumed);

            if !write_buf.is_empty() {
                socket.write_all(&write_buf).await?;
                write_buf.clear();
            }

            if let Some(action) = deferred_action {
                match action {
                    CmdResult::BlockPop {
                        keys,
                        timeout,
                        pop_left,
                    } => {
                        handle_block_pop(&mut socket, &store, &broker, &keys, timeout, pop_left)
                            .await?;
                    }
                    CmdResult::BlockMove {
                        src,
                        dst,
                        src_left,
                        dst_left,
                        timeout,
                    } => {
                        handle_block_move(
                            &mut socket,
                            &store,
                            &broker,
                            &src,
                            &dst,
                            src_left,
                            dst_left,
                            timeout,
                        )
                        .await?;
                    }
                    CmdResult::BlockStreamRead {
                        keys,
                        ids,
                        group,
                        count,
                        noack,
                        timeout,
                    } => {
                        handle_block_stream_read(
                            &mut socket,
                            &store,
                            &broker,
                            &keys,
                            &ids,
                            group,
                            count,
                            noack,
                            timeout,
                        )
                        .await?;
                    }
                    CmdResult::BlockZPop {
                        keys,
                        timeout,
                        pop_min,
                    } => {
                        handle_block_zpop(&mut socket, &store, &keys, timeout, pop_min).await?;
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn handle_block_pop(
    socket: &mut tokio::net::TcpStream,
    _store: &Arc<Store>,
    broker: &Broker,
    keys: &[String],
    timeout: std::time::Duration,
    pop_left: bool,
) -> std::io::Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(String, bytes::Bytes)>(1);
    let waiter_id = broker.next_waiter_id();

    for key in keys {
        broker.register_list_waiter(
            key,
            pubsub::BlockedPopRequest {
                tx: tx.clone(),
                pop_left,
                waiter_id,
            },
        );
    }
    drop(tx);

    let mut write_buf = BytesMut::new();
    let result = tokio::select! {
        val = rx.recv() => val,
        _ = tokio::time::sleep(timeout) => None,
    };

    match result {
        Some((key, val)) => {
            resp::write_array_header(&mut write_buf, 2);
            resp::write_bulk(&mut write_buf, &key);
            resp::write_bulk_raw(&mut write_buf, &val);
        }
        None => {
            resp::write_null_array(&mut write_buf);
        }
    }

    broker.remove_list_waiters_by_id(keys, waiter_id);

    socket.write_all(&write_buf).await
}

#[allow(clippy::too_many_arguments)]
async fn handle_block_move(
    socket: &mut tokio::net::TcpStream,
    store: &Arc<Store>,
    broker: &Broker,
    src: &str,
    dst: &str,
    src_left: bool,
    dst_left: bool,
    timeout: std::time::Duration,
) -> std::io::Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(String, bytes::Bytes)>(1);
    let waiter_id = broker.next_waiter_id();

    broker.register_list_waiter(
        src,
        pubsub::BlockedPopRequest {
            tx: tx.clone(),
            pop_left: src_left,
            waiter_id,
        },
    );
    drop(tx);

    let mut write_buf = BytesMut::new();
    let result = tokio::select! {
        val = rx.recv() => val,
        _ = tokio::time::sleep(timeout) => None,
    };

    match result {
        Some((_key, val)) => {
            let now = Instant::now();
            let vals: &[&[u8]] = &[val.as_ref()];
            if dst_left {
                let _ = store.lpush(dst.as_bytes(), vals, now);
            } else {
                let _ = store.rpush(dst.as_bytes(), vals, now);
            }
            resp::write_bulk_raw(&mut write_buf, &val);
        }
        None => {
            resp::write_null(&mut write_buf);
        }
    }

    broker.remove_list_waiters_by_id(&[src.to_string()], waiter_id);

    socket.write_all(&write_buf).await
}

#[allow(clippy::too_many_arguments)]
async fn handle_block_stream_read(
    socket: &mut tokio::net::TcpStream,
    store: &Arc<Store>,
    broker: &Broker,
    keys: &[String],
    id_strs: &[String],
    group: Option<(String, String)>,
    count: Option<usize>,
    noack: bool,
    timeout: std::time::Duration,
) -> std::io::Result<()> {
    let now_pre = Instant::now();
    let resolved_ids: Vec<String> = id_strs
        .iter()
        .enumerate()
        .map(|(idx, s)| {
            if s == "$" {
                store
                    .stream_last_id(keys[idx].as_bytes(), now_pre)
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "0-0".to_string())
            } else {
                s.clone()
            }
        })
        .collect();

    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
    for key in keys {
        broker.register_stream_waiter(key, tx.clone());
    }
    drop(tx);

    let mut write_buf = BytesMut::new();
    let woken = tokio::select! {
        _ = rx.recv() => true,
        _ = tokio::time::sleep(timeout) => false,
    };

    if woken {
        let now = Instant::now();
        let result = if let Some((ref grp, ref consumer)) = group {
            store.xreadgroup(grp, consumer, keys, &resolved_ids, count, noack, now)
        } else {
            let ids: Vec<store::StreamId> = resolved_ids
                .iter()
                .map(|s| store::StreamId::parse(s).unwrap_or(store::StreamId::zero()))
                .collect();
            store.xread(keys, &ids, count, now)
        };

        match result {
            Ok(r) if !r.is_empty() => {
                write_xread_response(&mut write_buf, &r);
            }
            _ => {
                resp::write_null_array(&mut write_buf);
            }
        }
    } else {
        resp::write_null_array(&mut write_buf);
    }

    socket.write_all(&write_buf).await
}

#[allow(clippy::type_complexity)]
fn write_xread_response(
    out: &mut BytesMut,
    result: &[(String, Vec<(store::StreamId, Vec<(String, bytes::Bytes)>)>)],
) {
    resp::write_array_header(out, result.len());
    for (key, entries) in result {
        resp::write_array_header(out, 2);
        resp::write_bulk(out, key);
        resp::write_array_header(out, entries.len());
        for (id, fields) in entries {
            resp::write_array_header(out, 2);
            resp::write_bulk(out, &id.to_string());
            resp::write_array_header(out, fields.len() * 2);
            for (k, v) in fields {
                resp::write_bulk(out, k);
                resp::write_bulk_raw(out, v);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_eval(
    out: &mut BytesMut,
    store: &Arc<Store>,
    broker: &Broker,
    script_engine: &lua::ScriptEngine,
    script: &str,
    keys: &[Vec<u8>],
    argv: &[Vec<u8>],
    now: Instant,
) {
    let actual_script = if let Some(sha) = script.strip_prefix("__SHA:") {
        match script_engine.get(sha) {
            Some(s) => s,
            None => {
                resp::write_error(out, "NOSCRIPT No matching script. Use EVAL.");
                return;
            }
        }
    } else {
        script_engine.load(script);
        script.to_string()
    };

    let _guard = SCRIPT_GATE.write();
    match lua::eval(&actual_script, keys, argv, store, broker, now) {
        Ok(result) => {
            out.extend_from_slice(&result);
        }
        Err(e) => {
            resp::write_error(out, &e);
        }
    }
}

async fn handle_block_zpop(
    socket: &mut tokio::net::TcpStream,
    store: &Arc<Store>,
    keys: &[String],
    timeout: std::time::Duration,
    pop_min: bool,
) -> std::io::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut write_buf = BytesMut::new();

    loop {
        let now = Instant::now();
        for key in keys {
            let result = if pop_min {
                store.zpopmin(key.as_bytes(), 1, now)
            } else {
                store.zpopmax(key.as_bytes(), 1, now)
            };
            if let Ok(items) = result {
                if !items.is_empty() {
                    let (member, score) = &items[0];
                    resp::write_array_header(&mut write_buf, 3);
                    resp::write_bulk(&mut write_buf, key);
                    resp::write_bulk(&mut write_buf, member);
                    let score_str = if score.fract() == 0.0 && score.abs() < 1e15 {
                        format!("{}", *score as i64)
                    } else {
                        format!("{}", score)
                    };
                    resp::write_bulk(&mut write_buf, &score_str);
                    return socket.write_all(&write_buf).await;
                }
            }
        }

        if tokio::time::Instant::now() >= deadline {
            resp::write_null_array(&mut write_buf);
            return socket.write_all(&write_buf).await;
        }

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

fn handle_script_op(out: &mut BytesMut, script_engine: &lua::ScriptEngine, args: &[&[u8]]) {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'script' command");
        return;
    }
    let sub = std::str::from_utf8(args[1]).unwrap_or("").to_uppercase();
    match sub.as_str() {
        "LOAD" => {
            if args.len() < 3 {
                resp::write_error(
                    out,
                    "ERR wrong number of arguments for 'script|load' command",
                );
                return;
            }
            let script = std::str::from_utf8(args[2]).unwrap_or("");
            let sha = script_engine.load(script);
            resp::write_bulk(out, &sha);
        }
        "EXISTS" => {
            let count = args.len() - 2;
            resp::write_array_header(out, count);
            for arg in &args[2..] {
                let sha = std::str::from_utf8(arg).unwrap_or("").to_lowercase();
                resp::write_integer(out, if script_engine.exists(&sha) { 1 } else { 0 });
            }
        }
        "FLUSH" => {
            script_engine.flush();
            resp::write_ok(out);
        }
        _ => {
            resp::write_error(out, &format!("ERR unknown subcommand '{}'", sub));
        }
    }
}
