use bytes::Bytes;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};

type KeySubMap = Vec<(String, broadcast::Sender<Message>)>;
type KeyExactSubMap = HashMap<String, broadcast::Sender<Message>>;
type KeyEvent = (Box<[u8]>, Box<[u8]>);

const CHANNEL_CAPACITY: usize = 1024;
const KEY_EVENT_QUEUE_CAPACITY: usize = 65536;

pub static KEY_EVENTS_ENQUEUED: AtomicU64 = AtomicU64::new(0);
pub static KEY_EVENTS_DROPPED: AtomicU64 = AtomicU64::new(0);
pub static KEY_EVENTS_EMITTED: AtomicU64 = AtomicU64::new(0);
pub static KEY_EVENTS_COALESCED: AtomicU64 = AtomicU64::new(0);

pub struct BlockedPopRequest {
    pub tx: mpsc::Sender<(String, Bytes)>,
    pub pop_left: bool,
    pub waiter_id: u64,
}

#[derive(Clone)]
pub struct Broker {
    channels: Arc<parking_lot::RwLock<HashMap<String, broadcast::Sender<Message>>>>,
    pattern_subs: Arc<parking_lot::RwLock<HashMap<String, broadcast::Sender<Message>>>>,
    key_exact_subs: Arc<parking_lot::RwLock<Arc<KeyExactSubMap>>>,
    key_glob_subs: Arc<parking_lot::RwLock<Arc<KeySubMap>>>,
    key_sub_count: Arc<AtomicU64>,
    key_event_tx: mpsc::Sender<KeyEvent>,
    key_event_rx: Arc<parking_lot::Mutex<Option<mpsc::Receiver<KeyEvent>>>>,
    key_worker_txs: Arc<Vec<mpsc::UnboundedSender<KeyEvent>>>,
    key_worker_rxs: Arc<parking_lot::Mutex<Option<Vec<mpsc::UnboundedReceiver<KeyEvent>>>>>,
    key_event_overflow: Arc<parking_lot::Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
    list_waiters: Arc<parking_lot::Mutex<HashMap<String, VecDeque<BlockedPopRequest>>>>,
    list_waiter_count: Arc<AtomicU64>,
    stream_waiters: Arc<parking_lot::Mutex<HashMap<String, Vec<mpsc::Sender<()>>>>>,
    waiter_counter: Arc<AtomicU64>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum MessageKind {
    PubSub,
    KeyEvent,
}

#[derive(Clone, Debug)]
pub struct Message {
    pub channel: String,
    pub payload: Bytes,
    pub pattern: Option<String>,
    pub kind: MessageKind,
}

impl Broker {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(KEY_EVENT_QUEUE_CAPACITY);
        let worker_count = std::thread::available_parallelism()
            .map(|n| n.get().clamp(2, 8))
            .unwrap_or(4);
        let mut worker_txs = Vec::with_capacity(worker_count);
        let mut worker_rxs = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let (wtx, wrx) = mpsc::unbounded_channel();
            worker_txs.push(wtx);
            worker_rxs.push(wrx);
        }
        Self {
            channels: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            pattern_subs: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            key_exact_subs: Arc::new(parking_lot::RwLock::new(Arc::new(HashMap::new()))),
            key_glob_subs: Arc::new(parking_lot::RwLock::new(Arc::new(Vec::new()))),
            key_sub_count: Arc::new(AtomicU64::new(0)),
            key_event_tx: tx,
            key_event_rx: Arc::new(parking_lot::Mutex::new(Some(rx))),
            key_worker_txs: Arc::new(worker_txs),
            key_worker_rxs: Arc::new(parking_lot::Mutex::new(Some(worker_rxs))),
            key_event_overflow: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            list_waiters: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            list_waiter_count: Arc::new(AtomicU64::new(0)),
            stream_waiters: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            waiter_counter: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn next_waiter_id(&self) -> u64 {
        self.waiter_counter.fetch_add(1, Ordering::Relaxed)
    }

    pub fn has_list_waiters(&self, _key: &str) -> bool {
        self.list_waiter_count.load(Ordering::Relaxed) > 0
    }

    pub fn register_list_waiter(&self, key: &str, req: BlockedPopRequest) {
        let mut waiters = self.list_waiters.lock();
        waiters.entry(key.to_string()).or_default().push_back(req);
        self.list_waiter_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn drain_list_waiters(
        &self,
        key: &str,
        shard_data: &mut hashbrown::HashMap<
            String,
            crate::store::Entry,
            crate::store::FxBuildHasher,
        >,
        now: std::time::Instant,
    ) {
        let mut waiters = self.list_waiters.lock();
        let queue = match waiters.get_mut(key) {
            Some(q) => q,
            None => return,
        };

        while !queue.is_empty() {
            let entry = match shard_data.get_mut(key) {
                Some(e) if !e.is_expired_at(now) => e,
                _ => return,
            };
            let list = match &mut entry.value {
                crate::store::StoreValue::List(l) if !l.is_empty() => l,
                _ => return,
            };

            let req = queue.pop_front().unwrap();
            self.list_waiter_count.fetch_sub(1, Ordering::Relaxed);
            let val = if req.pop_left {
                list.pop_front()
            } else {
                list.pop_back()
            };
            if let Some(v) = val {
                let _ = req.tx.try_send((key.to_string(), v));
            }
        }

        if queue.is_empty() {
            waiters.remove(key);
        }
    }

    pub fn remove_list_waiters_by_id(&self, keys: &[String], id: u64) {
        let mut waiters = self.list_waiters.lock();
        for key in keys {
            if let Some(queue) = waiters.get_mut(key) {
                let before = queue.len();
                queue.retain(|r| r.waiter_id != id);
                let removed = before - queue.len();
                if removed > 0 {
                    self.list_waiter_count
                        .fetch_sub(removed as u64, Ordering::Relaxed);
                }
                if queue.is_empty() {
                    waiters.remove(key);
                }
            }
        }
    }

    pub fn register_stream_waiter(&self, key: &str, tx: mpsc::Sender<()>) {
        let mut waiters = self.stream_waiters.lock();
        waiters.entry(key.to_string()).or_default().push(tx);
    }

    pub fn wake_stream_waiters(&self, key: &str) {
        let mut waiters = self.stream_waiters.lock();
        if let Some(senders) = waiters.remove(key) {
            for tx in senders {
                let _ = tx.try_send(());
            }
        }
    }

    pub fn subscribe(&self, channel: &str) -> broadcast::Receiver<Message> {
        let mut channels = self.channels.write();
        let tx = channels
            .entry(channel.to_string())
            .or_insert_with(|| broadcast::channel(CHANNEL_CAPACITY).0);
        tx.subscribe()
    }

    pub fn psubscribe(&self, pattern: &str) -> broadcast::Receiver<Message> {
        let mut patterns = self.pattern_subs.write();
        let tx = patterns
            .entry(pattern.to_string())
            .or_insert_with(|| broadcast::channel(CHANNEL_CAPACITY).0);
        tx.subscribe()
    }

    pub fn publish(&self, channel: &str, payload: Bytes) -> i64 {
        let mut count = 0i64;
        {
            let channels = self.channels.read();
            if let Some(tx) = channels.get(channel) {
                let msg = Message {
                    channel: channel.to_string(),
                    payload: payload.clone(),
                    pattern: None,
                    kind: MessageKind::PubSub,
                };
                count += tx.send(msg).unwrap_or(0) as i64;
            }
        }
        {
            let patterns = self.pattern_subs.read();
            for (pat, tx) in patterns.iter() {
                if glob_match(pat, channel) {
                    let msg = Message {
                        channel: channel.to_string(),
                        payload: payload.clone(),
                        pattern: Some(pat.clone()),
                        kind: MessageKind::PubSub,
                    };
                    count += tx.send(msg).unwrap_or(0) as i64;
                }
            }
        }
        count
    }

    pub fn ksubscribe(&self, pattern: &str) -> broadcast::Receiver<Message> {
        if is_glob_pattern(pattern) {
            let mut subs = self.key_glob_subs.write();
            let inner = Arc::make_mut(&mut subs);
            if let Some((_, tx)) = inner.iter().find(|(p, _)| p == pattern) {
                return tx.subscribe();
            }
            let (tx, rx) = broadcast::channel(CHANNEL_CAPACITY);
            inner.push((pattern.to_string(), tx));
            let exact_len = self.key_exact_subs.read().len();
            self.key_sub_count
                .store((exact_len + inner.len()) as u64, Ordering::Release);
            return rx;
        }

        let mut subs = self.key_exact_subs.write();
        let inner = Arc::make_mut(&mut subs);
        if let Some(tx) = inner.get(pattern) {
            return tx.subscribe();
        }
        let (tx, rx) = broadcast::channel(CHANNEL_CAPACITY);
        inner.insert(pattern.to_string(), tx);
        let glob_len = self.key_glob_subs.read().len();
        self.key_sub_count
            .store((inner.len() + glob_len) as u64, Ordering::Release);
        rx
    }

    pub fn kunsub(&self, pattern: &str) {
        if is_glob_pattern(pattern) {
            let mut subs = self.key_glob_subs.write();
            let inner = Arc::make_mut(&mut subs);
            inner.retain(|(p, tx)| {
                if p != pattern {
                    return true;
                }
                tx.receiver_count() > 0
            });
            let exact_len = self.key_exact_subs.read().len();
            self.key_sub_count
                .store((exact_len + inner.len()) as u64, Ordering::Release);
            return;
        }

        let mut subs = self.key_exact_subs.write();
        let inner = Arc::make_mut(&mut subs);
        if let Some(tx) = inner.get(pattern) {
            if tx.receiver_count() > 0 {
                let glob_len = self.key_glob_subs.read().len();
                self.key_sub_count
                    .store((inner.len() + glob_len) as u64, Ordering::Release);
                return;
            }
        }
        inner.remove(pattern);
        let glob_len = self.key_glob_subs.read().len();
        self.key_sub_count
            .store((inner.len() + glob_len) as u64, Ordering::Release);
    }

    #[inline(always)]
    pub fn has_key_subs(&self) -> bool {
        self.key_sub_count.load(Ordering::Relaxed) > 0
    }

    #[inline(always)]
    pub fn enqueue_key_event(&self, key: &[u8], cmd: &[u8]) {
        if self.key_sub_count.load(Ordering::Relaxed) == 0 {
            return;
        }
        KEY_EVENTS_ENQUEUED.fetch_add(1, Ordering::Relaxed);
        match self.key_event_tx.try_send((key.into(), cmd.into())) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full((k, c))) => {
                let mut overflow = self.key_event_overflow.lock();
                overflow.insert(k.into_vec(), c.into_vec());
                KEY_EVENTS_COALESCED.fetch_add(1, Ordering::Relaxed);
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                KEY_EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn pop_overflow_event(&self) -> Option<KeyEvent> {
        let mut overflow = self.key_event_overflow.lock();
        let key = overflow.keys().next()?.clone();
        let cmd = overflow.remove(&key)?;
        Some((key.into_boxed_slice(), cmd.into_boxed_slice()))
    }

    #[inline(always)]
    fn key_worker_index(&self, key: &[u8]) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % self.key_worker_txs.len()
    }

    #[inline(always)]
    fn dispatch_key_event(&self, key: Box<[u8]>, cmd: Box<[u8]>) {
        let index = self.key_worker_index(&key);
        if self.key_worker_txs[index].send((key, cmd)).is_err() {
            KEY_EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn process_key_event(&self, key: &[u8], cmd: &[u8]) {
        let exact_snap = self.key_exact_subs.read().clone();
        let glob_snap = self.key_glob_subs.read().clone();
        if exact_snap.is_empty() && glob_snap.is_empty() {
            return;
        }
        if let Ok(key_str) = std::str::from_utf8(key) {
            Self::emit_key_event(exact_snap.as_ref(), glob_snap.as_ref(), key_str, cmd);
        }
    }

    pub fn take_key_event_rx(&self) -> Option<mpsc::Receiver<KeyEvent>> {
        self.key_event_rx.lock().take()
    }

    fn emit_key_event(
        exact_subs: &KeyExactSubMap,
        glob_subs: &[(String, broadcast::Sender<Message>)],
        key: &str,
        cmd: &[u8],
    ) {
        let mut op: Option<Bytes> = None;
        if let Some(tx) = exact_subs.get(key) {
            let operation =
                op.get_or_insert_with(|| Bytes::copy_from_slice(&cmd.to_ascii_lowercase()));
            let msg = Message {
                channel: key.to_string(),
                payload: operation.clone(),
                pattern: Some(key.to_string()),
                kind: MessageKind::KeyEvent,
            };
            let _ = tx.send(msg);
            KEY_EVENTS_EMITTED.fetch_add(1, Ordering::Relaxed);
        }
        for (pat, tx) in glob_subs.iter() {
            if glob_match(pat, key) {
                let operation =
                    op.get_or_insert_with(|| Bytes::copy_from_slice(&cmd.to_ascii_lowercase()));
                let msg = Message {
                    channel: key.to_string(),
                    payload: operation.clone(),
                    pattern: Some(pat.clone()),
                    kind: MessageKind::KeyEvent,
                };
                let _ = tx.send(msg);
                KEY_EVENTS_EMITTED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub async fn run_key_event_loop(self) {
        let mut rx = match self.take_key_event_rx() {
            Some(rx) => rx,
            None => return,
        };
        if let Some(worker_rxs) = self.key_worker_rxs.lock().take() {
            for mut worker_rx in worker_rxs {
                let broker = self.clone();
                tokio::spawn(async move {
                    while let Some((key, cmd)) = worker_rx.recv().await {
                        broker.process_key_event(&key, &cmd);
                    }
                });
            }
        }
        let mut overflow_tick = tokio::time::interval(std::time::Duration::from_millis(2));
        overflow_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                maybe = rx.recv() => {
                    let Some((key, cmd)) = maybe else {
                        break;
                    };
                    self.dispatch_key_event(key, cmd);
                }
                _ = overflow_tick.tick() => {
                    let mut drained = 0;
                    while drained < 1024 {
                        let Some((key, cmd)) = self.pop_overflow_event() else {
                            break;
                        };
                        self.dispatch_key_event(key, cmd);
                        drained += 1;
                    }
                }
            }
        }
    }
}

#[inline(always)]
fn is_glob_pattern(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?') || pattern.contains('[')
}

fn glob_match(pattern: &str, s: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        if !prefix.contains(['?', '[', '*']) {
            return s.starts_with(prefix);
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let sc: Vec<char> = s.chars().collect();
    do_glob(&p, &sc, 0, 0)
}

fn do_glob(p: &[char], s: &[char], pi: usize, si: usize) -> bool {
    if pi == p.len() && si == s.len() {
        return true;
    }
    if pi == p.len() {
        return false;
    }
    match p[pi] {
        '*' => {
            for i in si..=s.len() {
                if do_glob(p, s, pi + 1, i) {
                    return true;
                }
            }
            false
        }
        '?' if si < s.len() => do_glob(p, s, pi + 1, si + 1),
        '[' if si < s.len() => {
            let mut j = pi + 1;
            let negate = j < p.len() && p[j] == '^';
            if negate {
                j += 1;
            }
            let mut matched = false;
            while j < p.len() && p[j] != ']' {
                if j + 2 < p.len() && p[j + 1] == '-' {
                    if s[si] >= p[j] && s[si] <= p[j + 2] {
                        matched = true;
                    }
                    j += 3;
                } else {
                    if s[si] == p[j] {
                        matched = true;
                    }
                    j += 1;
                }
            }
            if negate {
                matched = !matched;
            }
            if matched && j < p.len() {
                do_glob(p, s, j + 1, si + 1)
            } else {
                false
            }
        }
        c if si < s.len() && c == s[si] => do_glob(p, s, pi + 1, si + 1),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscribe_and_publish() {
        let broker = Broker::new();
        let mut rx = broker.subscribe("test-channel");
        let count = broker.publish("test-channel", Bytes::from_static(b"hello"));
        assert_eq!(count, 1);
        let msg = rx.try_recv().unwrap();
        assert_eq!(msg.channel, "test-channel");
        assert_eq!(msg.payload.as_ref(), b"hello");
    }

    #[test]
    fn publish_to_empty_channel_returns_zero() {
        let broker = Broker::new();
        let count = broker.publish("nobody-listening", Bytes::from_static(b"hello"));
        assert_eq!(count, 0);
    }

    #[test]
    fn multiple_subscribers() {
        let broker = Broker::new();
        let mut rx1 = broker.subscribe("ch");
        let mut rx2 = broker.subscribe("ch");
        broker.publish("ch", Bytes::from_static(b"msg"));
        assert_eq!(rx1.try_recv().unwrap().payload.as_ref(), b"msg");
        assert_eq!(rx2.try_recv().unwrap().payload.as_ref(), b"msg");
    }

    #[test]
    fn separate_channels_are_isolated() {
        let broker = Broker::new();
        let mut rx_a = broker.subscribe("a");
        let _rx_b = broker.subscribe("b");
        broker.publish("a", Bytes::from_static(b"only-a"));
        assert_eq!(rx_a.try_recv().unwrap().payload.as_ref(), b"only-a");
    }

    #[test]
    fn multiple_messages_in_order() {
        let broker = Broker::new();
        let mut rx = broker.subscribe("ch");
        broker.publish("ch", Bytes::from_static(b"first"));
        broker.publish("ch", Bytes::from_static(b"second"));
        broker.publish("ch", Bytes::from_static(b"third"));
        assert_eq!(rx.try_recv().unwrap().payload.as_ref(), b"first");
        assert_eq!(rx.try_recv().unwrap().payload.as_ref(), b"second");
        assert_eq!(rx.try_recv().unwrap().payload.as_ref(), b"third");
    }

    #[test]
    fn kunsub_keeps_pattern_while_other_receivers_exist() {
        let broker = Broker::new();
        let rx1 = broker.ksubscribe("table:users");
        let mut rx2 = broker.ksubscribe("table:users");

        drop(rx1);
        broker.kunsub("table:users");

        Broker::emit_key_event(
            broker.key_exact_subs.read().as_ref(),
            broker.key_glob_subs.read().as_ref(),
            "table:users",
            b"set",
        );

        assert_eq!(rx2.try_recv().unwrap().channel, "table:users");
        assert_eq!(
            rx2.try_recv().err(),
            Some(broadcast::error::TryRecvError::Empty)
        );
    }
}
