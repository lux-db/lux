use bytes::Bytes;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};

use crate::glob::GlobPattern;
use crate::limits::{ByteBudget, ByteReservation, CountBudget, CountReservation};

type KeySubMap = Vec<(Arc<str>, GlobPattern, broadcast::Sender<Message>)>;
type KeyExactSubMap = HashMap<String, broadcast::Sender<Message>>;
struct KeyEvent {
    key: Box<[u8]>,
    command: Box<[u8]>,
    _buffer_reservation: Arc<ByteReservation>,
}

struct CoalescedKeyEvent {
    command: Box<[u8]>,
    buffer_reservation: Arc<ByteReservation>,
}

struct PatternSubscription {
    pattern: Arc<str>,
    matcher: GlobPattern,
    sender: broadcast::Sender<Message>,
}

const CHANNEL_CAPACITY: usize = 64;
const KEY_EVENT_QUEUE_CAPACITY: usize = 4096;
const KEY_EVENT_WORKER_CAPACITY: usize = 1024;
const KEY_EVENT_OVERFLOW_CAPACITY: usize = 4096;

/// Snapshot of key-event counters for this broker instance.
#[derive(Clone, Copy, Debug, Default)]
pub struct KeyEventStats {
    pub enqueued: u64,
    pub dropped: u64,
    pub emitted: u64,
    pub coalesced: u64,
}

struct KeyEventCounters {
    enqueued: AtomicU64,
    dropped: AtomicU64,
    emitted: AtomicU64,
    coalesced: AtomicU64,
}

impl KeyEventCounters {
    fn new() -> Self {
        Self {
            enqueued: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            emitted: AtomicU64::new(0),
            coalesced: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> KeyEventStats {
        KeyEventStats {
            enqueued: self.enqueued.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            emitted: self.emitted.load(Ordering::Relaxed),
            coalesced: self.coalesced.load(Ordering::Relaxed),
        }
    }
}

pub struct BlockedPopRequest {
    pub tx: mpsc::Sender<(String, Bytes)>,
    pub pop_left: bool,
    /// BLMOVE/BRPOPLPUSH are completed in the broker as one journaled move.
    /// Plain BLPOP/BRPOP leave this empty.
    pub destination: Option<(String, bool)>,
    pub waiter_id: u64,
}

pub struct StreamWaiter {
    pub tx: mpsc::Sender<()>,
    pub waiter_id: u64,
}

#[derive(Clone)]
pub struct Broker {
    channels: Arc<parking_lot::RwLock<HashMap<String, broadcast::Sender<Message>>>>,
    pattern_subs: Arc<parking_lot::RwLock<HashMap<String, PatternSubscription>>>,
    key_exact_subs: Arc<parking_lot::RwLock<Arc<KeyExactSubMap>>>,
    key_glob_subs: Arc<parking_lot::RwLock<Arc<KeySubMap>>>,
    key_sub_count: Arc<AtomicU64>,
    key_event_tx: mpsc::Sender<KeyEvent>,
    key_event_rx: Arc<parking_lot::Mutex<Option<mpsc::Receiver<KeyEvent>>>>,
    key_event_started: Arc<AtomicBool>,
    key_worker_txs: Arc<Vec<mpsc::Sender<KeyEvent>>>,
    key_worker_rxs: Arc<parking_lot::Mutex<Option<Vec<mpsc::Receiver<KeyEvent>>>>>,
    key_event_overflow: Arc<parking_lot::Mutex<HashMap<Vec<u8>, CoalescedKeyEvent>>>,
    key_event_counters: Arc<KeyEventCounters>,
    list_waiters: Arc<parking_lot::Mutex<HashMap<String, VecDeque<BlockedPopRequest>>>>,
    list_waiter_count: Arc<AtomicU64>,
    stream_waiters: Arc<parking_lot::Mutex<HashMap<String, Vec<StreamWaiter>>>>,
    stream_waiter_count: Arc<AtomicU64>,
    waiter_counter: Arc<AtomicU64>,
    /// Per-table broadcast of typed row deltas for reactive live queries.
    row_delta_subs: Arc<parking_lot::RwLock<HashMap<Arc<str>, broadcast::Sender<RowDelta>>>>,
    row_delta_sub_count: Arc<AtomicU64>,
    event_budget: ByteBudget,
    subscription_budget: CountBudget,
    dropped_event_messages: Arc<AtomicU64>,
}

#[derive(Debug)]
pub(crate) struct SubscriptionReservation {
    count: CountReservation,
    bytes: ByteReservation,
}

impl SubscriptionReservation {
    pub(crate) fn try_grow(&mut self, count: usize, bytes: usize) -> bool {
        if !self.count.try_grow(count) {
            return false;
        }
        if self.bytes.try_grow(bytes) {
            true
        } else {
            self.count.release(count);
            false
        }
    }

    pub(crate) fn release(&mut self, count: usize, bytes: usize) {
        self.count.release(count);
        self.bytes.release(bytes);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum MessageKind {
    PubSub,
    KeyEvent,
}

#[derive(Clone, Debug)]
pub struct Message {
    pub channel: Arc<str>,
    pub payload: Bytes,
    pub pattern: Option<Arc<str>>,
    pub kind: MessageKind,
    _buffer_reservation: Option<Arc<ByteReservation>>,
}

/// A typed hint, emitted at the table mutation site, that row `pk` in `table`
/// changed. The live-query engine re-evaluates just that pk against each
/// affected subscription, so the delta only carries the identity of what moved,
/// not the row image.
#[derive(Clone, Debug)]
pub struct RowDelta {
    /// Large primary keys use `None` to request a bounded full-query resync
    /// instead of retaining the key once per queued delta.
    pub pk: Option<Arc<str>>,
    _buffer_reservation: Option<Arc<ByteReservation>>,
}

const ROW_DELTA_CAPACITY: usize = 256;

impl Broker {
    #[cfg(any(test, feature = "fuzzing"))]
    pub fn new() -> Self {
        let limits = crate::ServerLimits::default();
        Self::with_budgets(
            ByteBudget::new(limits.max_request_buffer_bytes),
            CountBudget::new(limits.max_subscriptions),
        )
    }

    pub(crate) fn with_budgets(event_budget: ByteBudget, subscription_budget: CountBudget) -> Self {
        let (tx, rx) = mpsc::channel(KEY_EVENT_QUEUE_CAPACITY);
        let worker_count = std::thread::available_parallelism()
            .map(|n| n.get().clamp(2, 8))
            .unwrap_or(4);
        let mut worker_txs = Vec::with_capacity(worker_count);
        let mut worker_rxs = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let (wtx, wrx) = mpsc::channel(KEY_EVENT_WORKER_CAPACITY);
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
            key_event_started: Arc::new(AtomicBool::new(false)),
            key_worker_txs: Arc::new(worker_txs),
            key_worker_rxs: Arc::new(parking_lot::Mutex::new(Some(worker_rxs))),
            key_event_overflow: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            key_event_counters: Arc::new(KeyEventCounters::new()),
            list_waiters: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            list_waiter_count: Arc::new(AtomicU64::new(0)),
            stream_waiters: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            stream_waiter_count: Arc::new(AtomicU64::new(0)),
            waiter_counter: Arc::new(AtomicU64::new(0)),
            row_delta_subs: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            row_delta_sub_count: Arc::new(AtomicU64::new(0)),
            event_budget,
            subscription_budget,
            dropped_event_messages: Arc::new(AtomicU64::new(0)),
        }
    }

    pub(crate) fn subscription_reservation(&self) -> SubscriptionReservation {
        SubscriptionReservation {
            count: self.subscription_budget.reservation(),
            bytes: self.event_budget.reservation(),
        }
    }

    pub fn network_subscription_count(&self) -> usize {
        self.subscription_budget.used()
    }

    pub fn dropped_event_messages(&self) -> u64 {
        self.dropped_event_messages.load(Ordering::Relaxed)
    }

    /// Cheap global gate: are there any reactive live-query subscribers at all?
    /// Checked on the table write hot path before doing any delta work.
    pub fn has_any_row_delta_subs(&self) -> bool {
        self.row_delta_sub_count.load(Ordering::Relaxed) > 0
    }

    /// Subscribe to typed row deltas for `table`. The receiver is per live query.
    pub fn subscribe_row_deltas(&self, table: &str) -> broadcast::Receiver<RowDelta> {
        let mut subs = self.row_delta_subs.write();
        let tx = subs
            .entry(Arc::from(table))
            .or_insert_with(|| broadcast::channel(ROW_DELTA_CAPACITY).0);
        let rx = tx.subscribe();
        self.row_delta_sub_count.fetch_add(1, Ordering::Relaxed);
        rx
    }

    /// Drop one live-query subscription to `table`'s row deltas.
    pub fn unsubscribe_row_deltas(&self, table: &str) {
        self.row_delta_sub_count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(1))
            })
            .ok();
        let mut subs = self.row_delta_subs.write();
        if subs.get(table).is_some_and(|tx| tx.receiver_count() == 0) {
            subs.remove(table);
        }
    }

    /// Publish a typed row delta to any live queries watching its table.
    pub(crate) fn publish_row_delta(&self, table: &str, pk: &str) {
        let subs = self.row_delta_subs.read();
        let Some(tx) = subs.get(table) else {
            return;
        };
        let (pk, reservation) = match self.event_budget.try_reserve(pk.len()) {
            Some(reservation) => (Some(Arc::from(pk)), Some(Arc::new(reservation))),
            None => {
                self.dropped_event_messages.fetch_add(1, Ordering::Relaxed);
                (None, None)
            }
        };
        let _ = tx.send(RowDelta {
            pk,
            _buffer_reservation: reservation,
        });
    }

    pub fn next_waiter_id(&self) -> u64 {
        self.waiter_counter.fetch_add(1, Ordering::Relaxed)
    }

    pub fn key_event_stats(&self) -> KeyEventStats {
        self.key_event_counters.snapshot()
    }

    pub fn has_list_waiters(&self, _key: &str) -> bool {
        self.list_waiter_count.load(Ordering::Relaxed) > 0
    }

    pub fn list_waiter_count(&self) -> u64 {
        self.list_waiter_count.load(Ordering::Relaxed)
    }

    pub fn register_list_waiter(&self, key: &str, req: BlockedPopRequest) {
        let mut waiters = self.list_waiters.lock();
        waiters.entry(key.to_string()).or_default().push_back(req);
        self.list_waiter_count.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn drain_list_waiters(
        &self,
        key: &str,
        store: &crate::store::Store,
        now: std::time::Instant,
    ) {
        loop {
            let req = {
                let mut waiters = self.list_waiters.lock();
                let Some(queue) = waiters.get_mut(key) else {
                    return;
                };
                let Some(req) = queue.pop_front() else {
                    waiters.remove(key);
                    return;
                };
                self.list_waiter_count.fetch_sub(1, Ordering::Relaxed);
                if queue.is_empty() {
                    waiters.remove(key);
                }
                req
            };

            let permit = match req.tx.clone().try_reserve_owned() {
                Ok(permit) => permit,
                Err(mpsc::error::TrySendError::Closed(_)) => continue,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    let mut waiters = self.list_waiters.lock();
                    waiters.entry(key.to_string()).or_default().push_front(req);
                    self.list_waiter_count.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };

            let raw = if let Some((destination, push_left)) = &req.destination {
                let route: [&[u8]; 3] = [b"LMOVE", key.as_bytes(), destination.as_bytes()];
                store.commit_prepared(
                    &route,
                    || -> Result<crate::store::JournalPlan<Option<Bytes>>, String> {
                        let value = store.preview_lmove(
                            key.as_bytes(),
                            destination.as_bytes(),
                            req.pop_left,
                            now,
                        )?;
                        let Some(value) = value else {
                            return Ok(crate::store::JournalPlan::no_op(None));
                        };
                        let pop = if req.pop_left { b"LPOP" } else { b"RPOP" };
                        let push = if *push_left { b"LPUSH" } else { b"RPUSH" };
                        Ok(crate::store::JournalPlan::batch(
                            vec![
                                vec![pop.to_vec(), key.as_bytes().to_vec()],
                                vec![
                                    push.to_vec(),
                                    destination.as_bytes().to_vec(),
                                    value.to_vec(),
                                ],
                            ],
                            Some(value),
                        ))
                    },
                    |expected| -> Result<Option<Bytes>, String> {
                        let Some(expected) = expected else {
                            return Ok(None);
                        };
                        let moved = store.lmove(
                            key.as_bytes(),
                            destination.as_bytes(),
                            req.pop_left,
                            *push_left,
                            now,
                        );
                        if moved.as_ref() != Some(&expected) {
                            return Err(
                                "ERR list changed during journaled blocked move".to_string()
                            );
                        }
                        Ok(moved)
                    },
                )
            } else {
                let pop: &[u8] = if req.pop_left { b"LPOP" } else { b"RPOP" };
                let route: [&[u8]; 2] = [pop, key.as_bytes()];
                store.commit_prepared(
                    &route,
                    || -> Result<crate::store::JournalPlan<Option<Bytes>>, String> {
                        let preview =
                            store.preview_lmpop(&[key.as_bytes()], req.pop_left, 1, now)?;
                        let Some((_, mut values)) = preview else {
                            return Ok(crate::store::JournalPlan::no_op(None));
                        };
                        let value = values.pop().expect("non-empty blocked pop preview");
                        Ok(crate::store::JournalPlan::command(
                            vec![pop.to_vec(), key.as_bytes().to_vec()],
                            Some(value),
                        ))
                    },
                    |expected| -> Result<Option<Bytes>, String> {
                        let Some(expected) = expected else {
                            return Ok(None);
                        };
                        let value = if req.pop_left {
                            store.lpop(key.as_bytes(), now)
                        } else {
                            store.rpop(key.as_bytes(), now)
                        };
                        if value.as_ref() != Some(&expected) {
                            return Err("ERR list changed during journaled blocked pop".to_string());
                        }
                        Ok(value)
                    },
                )
            };

            let raw = match raw {
                Ok(Ok(Some(value))) => value,
                Ok(Ok(None)) => {
                    let mut waiters = self.list_waiters.lock();
                    waiters.entry(key.to_string()).or_default().push_front(req);
                    self.list_waiter_count.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                Ok(Err(_)) | Err(_) => {
                    let mut waiters = self.list_waiters.lock();
                    waiters.entry(key.to_string()).or_default().push_front(req);
                    self.list_waiter_count.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };
            let value = store.decrypt_list_element(raw.clone()).unwrap_or(raw);
            permit.send((key.to_string(), value));

            if let Some((destination, _)) = &req.destination {
                if destination != key && self.has_list_waiters(destination) {
                    self.drain_list_waiters(destination, store, now);
                }
            }
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

    pub fn stream_waiter_count(&self) -> u64 {
        self.stream_waiter_count.load(Ordering::Relaxed)
    }

    pub fn register_stream_waiter(&self, key: &str, tx: mpsc::Sender<()>, waiter_id: u64) {
        let mut waiters = self.stream_waiters.lock();
        waiters
            .entry(key.to_string())
            .or_default()
            .push(StreamWaiter { tx, waiter_id });
        self.stream_waiter_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn remove_stream_waiters_by_id(&self, keys: &[String], id: u64) {
        let mut waiters = self.stream_waiters.lock();
        for key in keys {
            if let Some(queue) = waiters.get_mut(key) {
                let before = queue.len();
                queue.retain(|r| r.waiter_id != id);
                let removed = before - queue.len();
                if removed > 0 {
                    self.stream_waiter_count
                        .fetch_sub(removed as u64, Ordering::Relaxed);
                }
                if queue.is_empty() {
                    waiters.remove(key);
                }
            }
        }
    }

    pub fn wake_stream_waiters(&self, key: &str) {
        let mut waiters = self.stream_waiters.lock();
        if let Some(senders) = waiters.remove(key) {
            self.stream_waiter_count
                .fetch_sub(senders.len() as u64, Ordering::Relaxed);
            for waiter in senders {
                let _ = waiter.tx.try_send(());
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

    pub fn unsubscribe_channel(&self, channel: &str) {
        let mut channels = self.channels.write();
        if channels
            .get(channel)
            .is_some_and(|tx| tx.receiver_count() == 0)
        {
            channels.remove(channel);
        }
    }

    pub fn psubscribe(&self, pattern: &str) -> broadcast::Receiver<Message> {
        let mut patterns = self.pattern_subs.write();
        let subscription =
            patterns
                .entry(pattern.to_string())
                .or_insert_with(|| PatternSubscription {
                    pattern: Arc::from(pattern),
                    matcher: GlobPattern::new(pattern),
                    sender: broadcast::channel(CHANNEL_CAPACITY).0,
                });
        subscription.sender.subscribe()
    }

    pub fn punsubscribe_pattern(&self, pattern: &str) {
        let mut patterns = self.pattern_subs.write();
        if patterns
            .get(pattern)
            .is_some_and(|subscription| subscription.sender.receiver_count() == 0)
        {
            patterns.remove(pattern);
        }
    }

    pub fn publish(&self, channel: &str, payload: Bytes) -> i64 {
        let Some(reservation) = self.reserve_event_message(channel.len(), payload.len()) else {
            self.record_dropped_event();
            return 0;
        };
        self.publish_reserved(channel, payload, reservation)
    }

    pub(crate) fn reserve_event_message(
        &self,
        channel_bytes: usize,
        payload_bytes: usize,
    ) -> Option<Arc<ByteReservation>> {
        channel_bytes
            .checked_add(payload_bytes)
            .and_then(|bytes| self.event_budget.try_reserve(bytes))
            .map(Arc::new)
    }

    pub(crate) fn record_dropped_event(&self) {
        self.dropped_event_messages.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn publish_reserved(
        &self,
        channel: &str,
        payload: Bytes,
        reservation: Arc<ByteReservation>,
    ) -> i64 {
        let mut count = 0i64;
        let channel: Arc<str> = Arc::from(channel);
        {
            let channels = self.channels.read();
            if let Some(tx) = channels.get(channel.as_ref()) {
                let msg = Message {
                    channel: channel.clone(),
                    payload: payload.clone(),
                    pattern: None,
                    kind: MessageKind::PubSub,
                    _buffer_reservation: Some(reservation.clone()),
                };
                count += tx.send(msg).unwrap_or(0) as i64;
            }
        }
        {
            let patterns = self.pattern_subs.read();
            for subscription in patterns.values() {
                if subscription.matcher.matches(channel.as_ref()) {
                    let msg = Message {
                        channel: channel.clone(),
                        payload: payload.clone(),
                        pattern: Some(subscription.pattern.clone()),
                        kind: MessageKind::PubSub,
                        _buffer_reservation: Some(reservation.clone()),
                    };
                    count += subscription.sender.send(msg).unwrap_or(0) as i64;
                }
            }
        }
        count
    }

    /// Return the delivery count a publish would report without sending it.
    /// EXEC uses this while its exclusive execution boundary is held, then
    /// releases the actual message only after the transaction's WAL frame is
    /// durable.
    pub(crate) fn publish_subscriber_count(&self, channel: &str) -> i64 {
        let exact = self
            .channels
            .read()
            .get(channel)
            .map(|tx| tx.receiver_count() as i64)
            .unwrap_or(0);
        let patterns = self
            .pattern_subs
            .read()
            .iter()
            .filter(|(_, subscription)| {
                subscription.matcher.matches(channel) && subscription.sender.receiver_count() > 0
            })
            .map(|(_, subscription)| subscription.sender.receiver_count() as i64)
            .sum::<i64>();
        exact + patterns
    }

    /// PUBSUB CHANNELS: active channels (those with at least one subscriber),
    /// optionally filtered by a glob `pattern`.
    pub fn pubsub_channels(&self, pattern: Option<&str>) -> Vec<String> {
        let matcher = pattern.map(GlobPattern::new);
        let channels = self.channels.read();
        channels
            .iter()
            .filter(|(_, tx)| tx.receiver_count() > 0)
            .map(|(name, _)| name.clone())
            .filter(|name| matcher.as_ref().is_none_or(|pattern| pattern.matches(name)))
            .collect()
    }

    /// PUBSUB NUMSUB: number of subscribers for an exact channel name.
    pub fn pubsub_numsub(&self, channel: &str) -> i64 {
        let channels = self.channels.read();
        channels
            .get(channel)
            .map(|tx| tx.receiver_count() as i64)
            .unwrap_or(0)
    }

    /// PUBSUB NUMPAT: number of active pattern subscriptions.
    pub fn pubsub_numpat(&self) -> i64 {
        let patterns = self.pattern_subs.read();
        patterns
            .values()
            .filter(|subscription| subscription.sender.receiver_count() > 0)
            .count() as i64
    }

    pub fn ksubscribe(&self, pattern: &str) -> broadcast::Receiver<Message> {
        if is_glob_pattern(pattern) {
            let (rx, inserted) = {
                let mut subs = self.key_glob_subs.write();
                let inner = Arc::make_mut(&mut subs);
                if let Some((_, _, tx)) = inner.iter().find(|(p, _, _)| p.as_ref() == pattern) {
                    (tx.subscribe(), false)
                } else {
                    let (tx, rx) = broadcast::channel(CHANNEL_CAPACITY);
                    inner.push((Arc::from(pattern), GlobPattern::new(pattern), tx));
                    (rx, true)
                }
            };
            if inserted {
                self.key_sub_count.fetch_add(1, Ordering::AcqRel);
            }
            self.ensure_key_event_loop_started();
            return rx;
        }

        let (rx, inserted) = {
            let mut subs = self.key_exact_subs.write();
            let inner = Arc::make_mut(&mut subs);
            if let Some(tx) = inner.get(pattern) {
                (tx.subscribe(), false)
            } else {
                let (tx, rx) = broadcast::channel(CHANNEL_CAPACITY);
                inner.insert(pattern.to_string(), tx);
                (rx, true)
            }
        };
        if inserted {
            self.key_sub_count.fetch_add(1, Ordering::AcqRel);
        }
        self.ensure_key_event_loop_started();
        rx
    }

    pub fn kunsub(&self, pattern: &str) {
        let removed = if is_glob_pattern(pattern) {
            {
                let mut subs = self.key_glob_subs.write();
                let inner = Arc::make_mut(&mut subs);
                let before = inner.len();
                inner.retain(|(p, _, tx)| p.as_ref() != pattern || tx.receiver_count() > 0);
                inner.len() != before
            }
        } else {
            let mut subs = self.key_exact_subs.write();
            let inner = Arc::make_mut(&mut subs);
            if inner.get(pattern).is_none_or(|tx| tx.receiver_count() == 0) {
                inner.remove(pattern).is_some()
            } else {
                false
            }
        };
        if removed {
            self.key_sub_count.fetch_sub(1, Ordering::AcqRel);
        }
    }

    #[inline(always)]
    pub fn has_key_subs(&self) -> bool {
        self.key_sub_count.load(Ordering::Relaxed) > 0
    }

    #[cfg(test)]
    pub(crate) fn key_event_loop_started(&self) -> bool {
        self.key_event_started.load(Ordering::Relaxed)
    }

    #[inline(always)]
    pub fn enqueue_key_event(&self, key: &[u8], cmd: &[u8]) {
        if self.key_sub_count.load(Ordering::Relaxed) == 0 {
            return;
        }
        self.key_event_counters
            .enqueued
            .fetch_add(1, Ordering::Relaxed);
        let Some(reservation) = key
            .len()
            .checked_add(cmd.len())
            .and_then(|bytes| self.event_budget.try_reserve(bytes))
            .map(Arc::new)
        else {
            self.key_event_counters
                .dropped
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        let event = KeyEvent {
            key: key.into(),
            command: cmd.into(),
            _buffer_reservation: reservation,
        };
        match self.key_event_tx.try_send(event) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(event)) => {
                self.coalesce_key_event(event);
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                self.key_event_counters
                    .dropped
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn pop_overflow_event(&self) -> Option<KeyEvent> {
        let mut overflow = self.key_event_overflow.lock();
        let key = overflow.keys().next()?.clone();
        let event = overflow.remove(&key)?;
        Some(KeyEvent {
            key: key.into_boxed_slice(),
            command: event.command,
            _buffer_reservation: event.buffer_reservation,
        })
    }

    fn coalesce_key_event(&self, event: KeyEvent) {
        let key = event.key.into_vec();
        let mut overflow = self.key_event_overflow.lock();
        if let Some(existing) = overflow.get_mut(&key) {
            existing.command = event.command;
            existing.buffer_reservation = event._buffer_reservation;
            self.key_event_counters
                .dropped
                .fetch_add(1, Ordering::Relaxed);
            self.key_event_counters
                .coalesced
                .fetch_add(1, Ordering::Relaxed);
        } else if overflow.len() < KEY_EVENT_OVERFLOW_CAPACITY {
            overflow.insert(
                key,
                CoalescedKeyEvent {
                    command: event.command,
                    buffer_reservation: event._buffer_reservation,
                },
            );
            self.key_event_counters
                .coalesced
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.key_event_counters
                .dropped
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    #[inline(always)]
    fn key_worker_index(&self, key: &[u8]) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % self.key_worker_txs.len()
    }

    #[inline(always)]
    fn dispatch_key_event(&self, event: KeyEvent) -> bool {
        let index = self.key_worker_index(&event.key);
        match self.key_worker_txs[index].try_send(event) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(event)) => {
                self.coalesce_key_event(event);
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.key_event_counters
                    .dropped
                    .fetch_add(1, Ordering::Relaxed);
                true
            }
        }
    }

    fn process_key_event(&self, event: &KeyEvent) {
        let exact_snap = self.key_exact_subs.read().clone();
        let glob_snap = self.key_glob_subs.read().clone();
        if exact_snap.is_empty() && glob_snap.is_empty() {
            return;
        }
        if let Ok(key_str) = std::str::from_utf8(&event.key) {
            self.emit_key_event(
                exact_snap.as_ref(),
                glob_snap.as_ref(),
                key_str,
                &event.command,
                event._buffer_reservation.clone(),
            );
        }
    }

    fn take_key_event_rx(&self) -> Option<mpsc::Receiver<KeyEvent>> {
        self.key_event_rx.lock().take()
    }

    fn ensure_key_event_loop_started(&self) {
        if self.key_event_started.swap(true, Ordering::AcqRel) {
            return;
        }
        // Key events are cold for most embedded deployments, so the worker is
        // started lazily on first key subscription instead of every runtime.
        if tokio::runtime::Handle::try_current().is_ok() {
            let broker = self.clone();
            tokio::spawn(async move {
                broker.run_key_event_loop().await;
            });
        } else {
            // `ksubscribe` is synchronous; if it is called outside Tokio, let
            // a later in-runtime subscription make another start attempt.
            self.key_event_started.store(false, Ordering::Release);
        }
    }

    fn emit_key_event(
        &self,
        exact_subs: &KeyExactSubMap,
        glob_subs: &KeySubMap,
        key: &str,
        cmd: &[u8],
        reservation: Arc<ByteReservation>,
    ) {
        let mut op: Option<Bytes> = None;
        let key: Arc<str> = Arc::from(key);
        if let Some(tx) = exact_subs.get(key.as_ref()) {
            let operation = op.get_or_insert_with(|| Bytes::from(cmd.to_ascii_lowercase()));
            let msg = Message {
                channel: key.clone(),
                payload: operation.clone(),
                pattern: Some(key.clone()),
                kind: MessageKind::KeyEvent,
                _buffer_reservation: Some(reservation.clone()),
            };
            let _ = tx.send(msg);
            self.key_event_counters
                .emitted
                .fetch_add(1, Ordering::Relaxed);
        }
        for (pat, matcher, tx) in glob_subs.iter() {
            if matcher.matches(key.as_ref()) {
                let operation = op.get_or_insert_with(|| Bytes::from(cmd.to_ascii_lowercase()));
                let msg = Message {
                    channel: key.clone(),
                    payload: operation.clone(),
                    pattern: Some(pat.clone()),
                    kind: MessageKind::KeyEvent,
                    _buffer_reservation: Some(reservation.clone()),
                };
                let _ = tx.send(msg);
                self.key_event_counters
                    .emitted
                    .fetch_add(1, Ordering::Relaxed);
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
                    while let Some(event) = worker_rx.recv().await {
                        broker.process_key_event(&event);
                    }
                });
            }
        }
        let mut overflow_tick = tokio::time::interval(std::time::Duration::from_millis(2));
        overflow_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                maybe = rx.recv() => {
                    let Some(event) = maybe else {
                        break;
                    };
                    self.dispatch_key_event(event);
                }
                _ = overflow_tick.tick() => {
                    let mut drained = 0;
                    while drained < 1024 {
                        let Some(event) = self.pop_overflow_event() else {
                            break;
                        };
                        if !self.dispatch_key_event(event) {
                            break;
                        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn key_event(broker: &Broker, key: &[u8], command: &[u8]) -> KeyEvent {
        let reservation = broker
            .event_budget
            .try_reserve(key.len().saturating_add(command.len()))
            .expect("test event should fit within the broker budget");
        KeyEvent {
            key: key.into(),
            command: command.into(),
            _buffer_reservation: Arc::new(reservation),
        }
    }
    use crate::{DurabilityConfig, DurabilityPolicy, ServerConfig, StorageConfig, StorageMode};
    use std::sync::Arc;
    use std::time::Instant;

    fn journal_store(dir: &std::path::Path) -> (crate::store::Store, Arc<ServerConfig>) {
        let config = Arc::new(ServerConfig {
            data_dir: dir.to_string_lossy().to_string(),
            storage: StorageConfig {
                mode: StorageMode::Tiered,
                dir: dir.to_string_lossy().to_string(),
            },
            durability: DurabilityConfig {
                policy: DurabilityPolicy::EverySecond,
                ..Default::default()
            },
            ..ServerConfig::default()
        });
        (crate::store::Store::new_with_config(config.clone()), config)
    }

    #[test]
    fn subscribe_and_publish() {
        let broker = Broker::new();
        let mut rx = broker.subscribe("test-channel");
        let count = broker.publish("test-channel", Bytes::from_static(b"hello"));
        assert_eq!(count, 1);
        let msg = rx.try_recv().unwrap();
        assert_eq!(msg.channel.as_ref(), "test-channel");
        assert_eq!(msg.payload.as_ref(), b"hello");
    }

    #[test]
    fn publish_to_empty_channel_returns_zero() {
        let broker = Broker::new();
        let count = broker.publish("nobody-listening", Bytes::from_static(b"hello"));
        assert_eq!(count, 0);
    }

    #[test]
    fn key_event_queues_are_bounded_under_backpressure() {
        let broker = Broker::new();
        let _subscription = broker.ksubscribe("*");
        assert!(!broker.key_event_loop_started());

        for index in 0..=KEY_EVENT_QUEUE_CAPACITY {
            broker.enqueue_key_event(format!("key-{index}").as_bytes(), b"set");
        }
        assert_eq!(broker.key_event_overflow.lock().len(), 1);

        for index in 0..KEY_EVENT_OVERFLOW_CAPACITY {
            let key = format!("overflow-{index}");
            broker.coalesce_key_event(key_event(&broker, key.as_bytes(), b"set"));
        }
        broker.coalesce_key_event(key_event(&broker, b"one-too-many", b"set"));

        assert_eq!(
            broker.key_event_overflow.lock().len(),
            KEY_EVENT_OVERFLOW_CAPACITY
        );
        let stats = broker.key_event_stats();
        assert!(stats.coalesced >= KEY_EVENT_OVERFLOW_CAPACITY as u64);
        assert!(stats.dropped >= 1);
    }

    #[test]
    fn key_event_is_dropped_when_its_buffer_budget_is_full() {
        let broker = Broker::with_budgets(ByteBudget::new(4), CountBudget::new(1));
        let _subscription = broker.ksubscribe("*");
        broker.enqueue_key_event(b"key", b"set");

        let stats = broker.key_event_stats();
        assert_eq!(stats.enqueued, 1);
        assert_eq!(stats.dropped, 1);
        assert!(broker.key_event_overflow.lock().is_empty());
        assert!(broker.take_key_event_rx().unwrap().try_recv().is_err());
    }

    #[test]
    fn worker_queue_overflow_coalesces_instead_of_growing() {
        let broker = Broker::new();
        for _ in 0..=KEY_EVENT_WORKER_CAPACITY {
            broker.dispatch_key_event(key_event(&broker, b"same-key", b"set"));
        }

        assert_eq!(broker.key_event_overflow.lock().len(), 1);
        assert_eq!(broker.key_event_stats().coalesced, 1);
        assert_eq!(broker.key_event_stats().dropped, 0);

        broker.dispatch_key_event(key_event(&broker, b"same-key", b"del"));
        assert_eq!(broker.key_event_stats().coalesced, 2);
        assert_eq!(broker.key_event_stats().dropped, 1);
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
    fn subscription_capacity_is_atomic_and_reusable() {
        let broker = Broker::with_budgets(ByteBudget::new(10), CountBudget::new(2));
        let mut first = broker.subscription_reservation();
        let mut second = broker.subscription_reservation();
        let mut third = broker.subscription_reservation();

        assert!(first.try_grow(1, 6));
        assert!(!second.try_grow(1, 5));
        assert_eq!(broker.network_subscription_count(), 1);
        assert!(second.try_grow(1, 4));
        assert!(!third.try_grow(1, 0));

        first.release(1, 6);
        assert!(third.try_grow(1, 6));
        assert_eq!(broker.network_subscription_count(), 2);
    }

    #[test]
    fn event_budget_recovers_after_every_receiver_releases_a_message() {
        let broker = Broker::with_budgets(ByteBudget::new(11), CountBudget::new(2));
        let mut first = broker.subscribe("events");
        let mut second = broker.subscribe("events");

        assert_eq!(broker.publish("events", Bytes::from_static(b"hello")), 2);
        assert_eq!(broker.publish("events", Bytes::from_static(b"x")), 0);
        assert_eq!(broker.dropped_event_messages(), 1);

        drop(first.try_recv().unwrap());
        assert_eq!(broker.publish("events", Bytes::from_static(b"x")), 0);
        drop(second.try_recv().unwrap());

        assert_eq!(broker.publish("events", Bytes::from_static(b"x")), 2);
        assert_eq!(first.try_recv().unwrap().payload.as_ref(), b"x");
        assert_eq!(second.try_recv().unwrap().payload.as_ref(), b"x");
    }

    #[test]
    fn fanout_messages_share_channel_and_retained_pattern_names() {
        let broker = Broker::new();
        let mut first = broker.psubscribe("room:*");
        let mut second = broker.psubscribe("*:events");

        assert_eq!(broker.publish("room:events", Bytes::from_static(b"one")), 2);
        let first_message = first.try_recv().unwrap();
        let second_message = second.try_recv().unwrap();
        assert!(Arc::ptr_eq(&first_message.channel, &second_message.channel));

        assert_eq!(broker.publish("room:events", Bytes::from_static(b"two")), 2);
        let next_first = first.try_recv().unwrap();
        assert!(Arc::ptr_eq(
            first_message.pattern.as_ref().unwrap(),
            next_first.pattern.as_ref().unwrap()
        ));
    }

    #[test]
    fn concurrent_exact_and_glob_key_registry_changes_do_not_deadlock() {
        let broker = Broker::new();
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let exact_broker = broker.clone();
        let exact_barrier = barrier.clone();
        let exact = std::thread::spawn(move || {
            exact_barrier.wait();
            for _ in 0..1_000 {
                let receiver = exact_broker.ksubscribe("exact");
                drop(receiver);
                exact_broker.kunsub("exact");
            }
        });
        let glob_broker = broker.clone();
        let glob_barrier = barrier.clone();
        let glob = std::thread::spawn(move || {
            glob_barrier.wait();
            for _ in 0..1_000 {
                let receiver = glob_broker.ksubscribe("glob:*");
                drop(receiver);
                glob_broker.kunsub("glob:*");
            }
        });

        barrier.wait();
        exact.join().unwrap();
        glob.join().unwrap();
        assert!(!broker.has_key_subs());
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

        broker.emit_key_event(
            broker.key_exact_subs.read().as_ref(),
            broker.key_glob_subs.read().as_ref(),
            "table:users",
            b"set",
            Arc::new(broker.event_budget.try_reserve(18).unwrap()),
        );

        assert_eq!(rx2.try_recv().unwrap().channel.as_ref(), "table:users");
        assert_eq!(
            rx2.try_recv().err(),
            Some(broadcast::error::TryRecvError::Empty)
        );
    }

    #[test]
    fn row_delta_subscriber_count_gates_and_reclaims() {
        let broker = Broker::new();
        assert!(!broker.has_any_row_delta_subs());

        let rx1 = broker.subscribe_row_deltas("tasks");
        let mut rx2 = broker.subscribe_row_deltas("tasks");
        assert!(broker.has_any_row_delta_subs());

        // A published delta reaches every live receiver on the table.
        broker.publish_row_delta("tasks", "t1");
        assert_eq!(rx2.try_recv().unwrap().pk.as_deref(), Some("t1"));

        // Dropping one receiver then unsubscribing keeps the channel (rx2 lives).
        drop(rx1);
        broker.unsubscribe_row_deltas("tasks");
        assert!(broker.has_any_row_delta_subs());
        assert!(broker.row_delta_subs.read().contains_key("tasks"));

        // Dropping the last receiver before unsubscribe reclaims the channel and
        // flips the global gate back off.
        drop(rx2);
        broker.unsubscribe_row_deltas("tasks");
        assert!(!broker.has_any_row_delta_subs());
        assert!(!broker.row_delta_subs.read().contains_key("tasks"));
    }

    #[test]
    fn publish_row_delta_to_idle_table_is_noop() {
        let broker = Broker::new();
        // No panic, no subscribers, nothing to receive.
        broker.publish_row_delta("ghost", "x");
        assert!(!broker.has_any_row_delta_subs());
    }

    #[test]
    fn row_delta_without_buffer_capacity_becomes_a_resync_marker() {
        let broker = Broker::with_budgets(ByteBudget::new(1), CountBudget::new(1));
        let mut receiver = broker.subscribe_row_deltas("tasks");
        broker.publish_row_delta("tasks", "too-large");

        assert_eq!(receiver.try_recv().unwrap().pk, None);
    }

    #[test]
    fn blocked_pop_does_not_mutate_when_the_journal_fails() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = journal_store(dir.path());
        let now = Instant::now();
        store.lpush(b"jobs", &[b"one"], now).unwrap();

        let broker = Broker::new();
        let (tx, mut rx) = mpsc::channel(1);
        broker.register_list_waiter(
            "jobs",
            BlockedPopRequest {
                tx,
                pop_left: true,
                destination: None,
                waiter_id: broker.next_waiter_id(),
            },
        );
        store.inject_journal_failures(1);
        broker.drain_list_waiters("jobs", &store, now);

        assert_eq!(store.llen(b"jobs", now).unwrap(), 1);
        assert!(rx.try_recv().is_err());
        assert_eq!(broker.list_waiter_count(), 1);

        broker.drain_list_waiters("jobs", &store, now);
        assert_eq!(rx.try_recv().unwrap().1.as_ref(), b"one");
        assert_eq!(store.llen(b"jobs", now).unwrap(), 0);
    }

    #[test]
    fn blocked_move_is_one_durable_resolved_effect() {
        let dir = tempfile::tempdir().unwrap();
        let (store, config) = journal_store(dir.path());
        let now = Instant::now();
        let push: [&[u8]; 3] = [b"LPUSH", b"source", b"one"];
        store
            .commit_journaled(&push, || store.lpush(b"source", &[b"one"], now))
            .unwrap()
            .unwrap();

        let broker = Broker::new();
        let (tx, mut rx) = mpsc::channel(1);
        broker.register_list_waiter(
            "source",
            BlockedPopRequest {
                tx,
                pop_left: true,
                destination: Some(("destination".to_string(), false)),
                waiter_id: broker.next_waiter_id(),
            },
        );
        broker.drain_list_waiters("source", &store, now);

        assert_eq!(rx.try_recv().unwrap().1.as_ref(), b"one");
        assert_eq!(store.llen(b"source", now).unwrap(), 0);
        assert_eq!(
            store.lrange(b"destination", 0, -1, now).unwrap()[0],
            b"one".as_slice()
        );
        store.fsync_wal();
        drop(store);

        let restored = crate::store::Store::new_with_config(config);
        restored.replay_wal(&Broker::new()).unwrap();
        assert_eq!(restored.llen(b"source", Instant::now()).unwrap(), 0);
        assert_eq!(
            restored
                .lrange(b"destination", 0, -1, Instant::now())
                .unwrap()[0],
            b"one".as_slice()
        );
    }
}
