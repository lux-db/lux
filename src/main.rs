mod cmd;
mod pubsub;
mod resp;
mod snapshot;
mod store;

use bytes::BytesMut;
use cmd::CmdResult;
use pubsub::Broker;
use resp::Parser;
use store::Store;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

pub static CONNECTED_CLIENTS: AtomicUsize = AtomicUsize::new(0);
pub static TOTAL_COMMANDS: AtomicUsize = AtomicUsize::new(0);
pub static START_TIME: OnceLock<Instant> = OnceLock::new();

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

    let require_auth = std::env::var("LUX_PASSWORD").map_or(false, |p| !p.is_empty());

    match snapshot::load(&store) {
        Ok(0) => println!("no snapshot found"),
        Ok(n) => println!("loaded {n} keys from snapshot"),
        Err(e) => eprintln!("snapshot load error: {e}"),
    }

    tokio::spawn(snapshot::background_save_loop(store.clone()));

    {
        let store = store.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                store.expire_sweep(Instant::now());
            }
        });
    }

    println!("lux v{} ready on {addr}", env!("CARGO_PKG_VERSION"));

    loop {
        let (socket, peer) = listener.accept().await?;
        let store = store.clone();
        let broker = broker.clone();
        socket.set_nodelay(true).ok();

        tokio::spawn(async move {
            CONNECTED_CLIENTS.fetch_add(1, Ordering::Relaxed);
            let result = handle_connection(socket, peer, store, broker, require_auth).await;
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
        && input.iter().zip(expected).all(|(a, b)| a.to_ascii_uppercase() == *b)
}

async fn handle_connection(
    mut socket: tokio::net::TcpStream,
    _peer: std::net::SocketAddr,
    store: Arc<Store>,
    broker: Broker,
    require_auth: bool,
) -> std::io::Result<()> {
    let mut read_buf = vec![0u8; 65536];
    let mut write_buf = BytesMut::with_capacity(65536);
    let mut pending = BytesMut::new();
    let mut subscriptions: HashMap<String, broadcast::Receiver<pubsub::Message>> = HashMap::new();
    let mut sub_mode = false;
    let mut authenticated = !require_auth;

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
                                    let rx = broker.subscribe(&ch).await;
                                    subscriptions.insert(ch.clone(), rx);
                                }
                                resp::write_array_header(&mut write_buf, 3);
                                resp::write_bulk(&mut write_buf, "subscribe");
                                resp::write_bulk(&mut write_buf, &ch);
                                resp::write_integer(&mut write_buf, subscriptions.len() as i64);
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
                                resp::write_integer(&mut write_buf, subscriptions.len() as i64);
                            }
                            if subscriptions.is_empty() {
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
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    for (_ch, rx) in subscriptions.iter_mut() {
                        if let Ok(msg) = rx.try_recv() {
                            return Some(msg);
                        }
                    }
                    None
                } => {
                    if let Some(msg) = msg {
                        resp::write_array_header(&mut write_buf, 3);
                        resp::write_bulk(&mut write_buf, "message");
                        resp::write_bulk(&mut write_buf, &msg.channel);
                        resp::write_bulk(&mut write_buf, &msg.payload);
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
                if args.is_empty() { continue; }
                commands.push(args);
            }
            let consumed = parser.pos();

            if commands.len() <= 1 {
                for args in &commands {
                    if !authenticated {
                        if !cmd_eq_fast(args[0], b"AUTH") && !cmd_eq_fast(args[0], b"PING") && !cmd_eq_fast(args[0], b"QUIT") {
                            resp::write_error(&mut write_buf, "NOAUTH Authentication required");
                            continue;
                        }
                    }
                    TOTAL_COMMANDS.fetch_add(1, Ordering::Relaxed);
                    match cmd::execute(&store, &broker, args, &mut write_buf, now) {
                        CmdResult::Written => {}
                        CmdResult::Authenticated => { authenticated = true; }
                        CmdResult::Subscribe { channels } => {
                            for ch in &channels {
                                let rx = broker.subscribe(ch).await;
                                subscriptions.insert(ch.clone(), rx);
                                resp::write_array_header(&mut write_buf, 3);
                                resp::write_bulk(&mut write_buf, "subscribe");
                                resp::write_bulk(&mut write_buf, ch);
                                resp::write_integer(&mut write_buf, subscriptions.len() as i64);
                            }
                            sub_mode = true;
                            break;
                        }
                        CmdResult::Publish { channel, message } => {
                            let count = broker.publish(&channel, message).await;
                            resp::write_integer(&mut write_buf, count);
                        }
                    }
                }
            } else {
                let cmd_count = commands.len();
                TOTAL_COMMANDS.fetch_add(cmd_count, Ordering::Relaxed);

                let mut has_special = false;
                let mut all_single_key_rw = true;
                for args in &commands {
                    if !authenticated && !cmd_eq_fast(args[0], b"AUTH") && !cmd_eq_fast(args[0], b"PING") && !cmd_eq_fast(args[0], b"QUIT") {
                        has_special = true;
                        break;
                    }
                    if cmd_eq_fast(args[0], b"SUBSCRIBE") || cmd_eq_fast(args[0], b"PUBLISH") || cmd_eq_fast(args[0], b"AUTH") {
                        has_special = true;
                        break;
                    }
                    if args.len() < 2 || cmd_eq_fast(args[0], b"MGET") || cmd_eq_fast(args[0], b"MSET")
                        || cmd_eq_fast(args[0], b"DEL") || cmd_eq_fast(args[0], b"EXISTS")
                        || cmd_eq_fast(args[0], b"KEYS") || cmd_eq_fast(args[0], b"SCAN")
                        || cmd_eq_fast(args[0], b"FLUSHDB") || cmd_eq_fast(args[0], b"FLUSHALL")
                        || cmd_eq_fast(args[0], b"DBSIZE") || cmd_eq_fast(args[0], b"SAVE")
                        || cmd_eq_fast(args[0], b"INFO") || cmd_eq_fast(args[0], b"RENAME")
                        || cmd_eq_fast(args[0], b"SUNION") || cmd_eq_fast(args[0], b"SINTER")
                        || cmd_eq_fast(args[0], b"SDIFF")
                    {
                        all_single_key_rw = false;
                    }
                }

                if has_special || !all_single_key_rw {
                    for args in &commands {
                        if !authenticated {
                            if !cmd_eq_fast(args[0], b"AUTH") && !cmd_eq_fast(args[0], b"PING") && !cmd_eq_fast(args[0], b"QUIT") {
                                resp::write_error(&mut write_buf, "NOAUTH Authentication required");
                                continue;
                            }
                        }
                        match cmd::execute(&store, &broker, args, &mut write_buf, now) {
                            CmdResult::Written => {}
                            CmdResult::Authenticated => { authenticated = true; }
                            CmdResult::Subscribe { channels } => {
                                for ch in &channels {
                                    let rx = broker.subscribe(ch).await;
                                    subscriptions.insert(ch.clone(), rx);
                                    resp::write_array_header(&mut write_buf, 3);
                                    resp::write_bulk(&mut write_buf, "subscribe");
                                    resp::write_bulk(&mut write_buf, ch);
                                    resp::write_integer(&mut write_buf, subscriptions.len() as i64);
                                }
                                sub_mode = true;
                                break;
                            }
                            CmdResult::Publish { channel, message } => {
                                let count = broker.publish(&channel, message).await;
                                resp::write_integer(&mut write_buf, count);
                            }
                        }
                    }
                } else {
                    let mut sorted: Vec<(u32, u32)> = Vec::with_capacity(cmd_count);
                    for (i, args) in commands.iter().enumerate() {
                        sorted.push((store.shard_for_key(args[1]) as u32, i as u32));
                    }
                    sorted.sort_unstable_by_key(|&(shard, _)| shard);

                    let mut scratch = BytesMut::with_capacity(cmd_count * 32);
                    let mut resp_spans: Vec<(u32, u32)> = vec![(0, 0); cmd_count];

                    let mut batch_start = 0usize;
                    while batch_start < sorted.len() {
                        let shard_idx = sorted[batch_start].0;
                        let mut batch_end = batch_start + 1;
                        while batch_end < sorted.len() && sorted[batch_end].0 == shard_idx {
                            batch_end += 1;
                        }

                        let all_simple = sorted[batch_start..batch_end].iter().all(|&(_, ci)| {
                            let c = commands[ci as usize][0];
                            (cmd_eq_fast(c, b"SET") && commands[ci as usize].len() == 3)
                                || (cmd_eq_fast(c, b"GET") && commands[ci as usize].len() == 2)
                        });

                        if all_simple {
                            let has_writes = sorted[batch_start..batch_end].iter().any(|&(_, ci)| {
                                cmd_eq_fast(commands[ci as usize][0], b"SET")
                            });
                            if has_writes {
                                let mut shard = store.lock_write_shard(shard_idx as usize);
                                for &(_, ci) in &sorted[batch_start..batch_end] {
                                    let idx = ci as usize;
                                    let args = &commands[idx];
                                    let start = scratch.len() as u32;
                                    if cmd_eq_fast(args[0], b"SET") {
                                        Store::set_on_shard(&mut shard.data, args[1], args[2], None, now);
                                        scratch.extend_from_slice(resp::OK);
                                    } else {
                                        Store::get_and_write(&shard.data, args[1], now, &mut scratch);
                                    }
                                    resp_spans[idx] = (start, scratch.len() as u32);
                                }
                            } else {
                                let shard = store.lock_read_shard(shard_idx as usize);
                                for &(_, ci) in &sorted[batch_start..batch_end] {
                                    let idx = ci as usize;
                                    let start = scratch.len() as u32;
                                    Store::get_and_write(&shard.data, commands[idx][1], now, &mut scratch);
                                    resp_spans[idx] = (start, scratch.len() as u32);
                                }
                            }
                        } else {
                            for &(_, ci) in &sorted[batch_start..batch_end] {
                                let idx = ci as usize;
                                let start = scratch.len() as u32;
                                cmd::execute(&store, &broker, &commands[idx], &mut scratch, now);
                                resp_spans[idx] = (start, scratch.len() as u32);
                            }
                        }

                        batch_start = batch_end;
                    }

                    for &(start, end) in &resp_spans {
                        write_buf.extend_from_slice(&scratch[start as usize..end as usize]);
                    }
                }
            }

            let _ = pending.split_to(consumed);

            if !write_buf.is_empty() {
                socket.write_all(&write_buf).await?;
                write_buf.clear();
            }
        }
    }
}
