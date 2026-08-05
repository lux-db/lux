pub use super::transfer_dirty::DirtyStats;
use super::transfer_dirty::DirtyTracker;
use super::{
    slot_for_key, slot_for_table_row, ClusterError, TransferDescriptor, TransferId,
    TransferJournalSnapshot, TransferPhase, TransferRole, CLUSTER_SLOT_COUNT,
};
use arc_swap::ArcSwap;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_TRANSFER_KEY_BYTES: usize = 64 * 1024 * 1024;
const MAX_TRANSFER_TABLE_BYTES: usize = 256;
const DIRTY_IDENTITY_OVERHEAD_BYTES: usize = 128;
const MAX_TRANSFER_IDENTITY_BYTES: usize =
    DIRTY_IDENTITY_OVERHEAD_BYTES + MAX_TRANSFER_TABLE_BYTES + MAX_TRANSFER_KEY_BYTES;
const PHASE_COPYING: u8 = 0;
const PHASE_FENCING: u8 = 1;
const PHASE_FENCED: u8 = 2;
const PHASE_REDIRECTING: u8 = 3;
const PHASE_RELEASED: u8 = 4;
const MAX_TRANSFER_FENCE_WAIT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct TransferRuntimeConfig {
    pub max_dirty_keys: usize,
    pub max_dirty_bytes: usize,
}

impl TransferRuntimeConfig {
    fn validate(&self) -> Result<(), ClusterError> {
        if self.max_dirty_keys == 0 || self.max_dirty_bytes < MAX_TRANSFER_IDENTITY_BYTES {
            return transfer_invalid(
                "dirty tracking requires a nonzero key limit and enough memory for one maximum-size identity",
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TransferDataKey {
    Kv(Vec<u8>),
    TableRow { table: String, primary_key: Vec<u8> },
}

impl TransferDataKey {
    pub fn kv(key: impl Into<Vec<u8>>) -> Result<Self, ClusterError> {
        let key = key.into();
        if key.len() > MAX_TRANSFER_KEY_BYTES {
            return transfer_invalid("KV transfer key exceeds 64 MiB");
        }
        Ok(Self::Kv(key))
    }

    pub fn table_row(
        table: impl Into<String>,
        primary_key: impl Into<Vec<u8>>,
    ) -> Result<Self, ClusterError> {
        let table = table.into();
        let primary_key = primary_key.into();
        validate_table_row(&table, &primary_key)?;
        Ok(Self::TableRow { table, primary_key })
    }

    #[inline]
    #[must_use]
    pub fn slot(&self) -> u16 {
        match self {
            Self::Kv(key) => slot_for_key(key),
            Self::TableRow { table, primary_key } => {
                slot_for_table_row(table.as_bytes(), primary_key)
            }
        }
    }

    pub(super) fn tracked_bytes(&self) -> usize {
        match self {
            Self::Kv(key) => DIRTY_IDENTITY_OVERHEAD_BYTES + key.len(),
            Self::TableRow { table, primary_key } => {
                DIRTY_IDENTITY_OVERHEAD_BYTES + table.len() + primary_key.len()
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferFence {
    pub transfer_id: TransferId,
    pub target_node_id: String,
    pub to_epoch: u64,
}

pub enum TransferWriteAdmission {
    Untracked,
    Admitted(TransferWriteGuard),
    Fenced(Arc<TransferFence>),
    Redirect(Arc<TransferFence>),
}

pub struct TransferWriteGuard {
    transfer: Arc<ActiveTransfer>,
    key: Option<TransferDataKey>,
    reserved_bytes: usize,
}

impl Drop for TransferWriteGuard {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            self.transfer.dirty.mark_reserved(key, self.reserved_bytes);
        }
        self.transfer.writer_finished();
    }
}

struct TransferRoutes {
    slots: Box<[Option<Arc<ActiveTransfer>>]>,
}

impl TransferRoutes {
    fn empty() -> Self {
        Self {
            slots: vec![None; usize::from(CLUSTER_SLOT_COUNT)].into_boxed_slice(),
        }
    }
}

pub struct TransferRuntime {
    local_node_id: String,
    config: TransferRuntimeConfig,
    published: ArcSwap<TransferRoutes>,
    mutation: parking_lot::Mutex<()>,
}

impl TransferRuntime {
    pub fn new(
        local_node_id: impl Into<String>,
        config: TransferRuntimeConfig,
    ) -> Result<Self, ClusterError> {
        config.validate()?;
        let local_node_id = local_node_id.into();
        if local_node_id.is_empty()
            || local_node_id.len() > 128
            || !local_node_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return transfer_invalid("local transfer node id is invalid");
        }
        Ok(Self {
            local_node_id,
            config,
            published: ArcSwap::from_pointee(TransferRoutes::empty()),
            mutation: parking_lot::Mutex::new(()),
        })
    }

    pub fn install_source(&self, descriptor: TransferDescriptor) -> Result<(), ClusterError> {
        self.install_source_in_phase(descriptor, PHASE_COPYING)
    }

    /// Rehydrate source admission state from a journal that was validated on
    /// open. This must run before request listeners start after a restart.
    pub fn recover_source(
        &self,
        durable_source: &TransferJournalSnapshot,
    ) -> Result<(), ClusterError> {
        if durable_source.role != TransferRole::Source || durable_source.attempt == 0 {
            return transfer_invalid("source recovery requires a started source journal");
        }
        let phase = match durable_source.phase {
            TransferPhase::Copying => PHASE_COPYING,
            TransferPhase::Fenced | TransferPhase::Sealed => PHASE_FENCED,
            TransferPhase::Activated | TransferPhase::Finalized => PHASE_REDIRECTING,
            TransferPhase::Prepared | TransferPhase::Aborted => {
                return transfer_invalid("source journal has no recoverable transfer")
            }
        };
        self.install_source_in_phase(durable_source.descriptor.clone(), phase)
    }

    fn install_source_in_phase(
        &self,
        descriptor: TransferDescriptor,
        initial_phase: u8,
    ) -> Result<(), ClusterError> {
        descriptor.validate()?;
        if descriptor.source_node_id != self.local_node_id {
            return transfer_invalid("source transfer belongs to another local node");
        }
        let _guard = self.mutation.lock();
        let current = self.published.load_full();
        let mut slots = current.slots.to_vec();
        let mut occupied = 0_usize;
        let mut expected = 0_usize;
        let mut installed = None;
        for range in &descriptor.ranges {
            for slot in range.start..=range.end {
                expected += 1;
                if let Some(active) = &slots[usize::from(slot)] {
                    if active.descriptor != descriptor {
                        return transfer_invalid(
                            "source transfer overlaps an active slot transfer",
                        );
                    }
                    if installed
                        .as_ref()
                        .is_some_and(|candidate| !Arc::ptr_eq(candidate, active))
                    {
                        return transfer_invalid(
                            "source transfer slots do not share one runtime state",
                        );
                    }
                    installed = Some(Arc::clone(active));
                    occupied += 1;
                }
            }
        }
        if occupied == expected {
            if initial_phase != PHASE_COPYING
                && installed
                    .as_ref()
                    .is_some_and(|active| active.phase.load(Ordering::Acquire) != initial_phase)
            {
                return transfer_invalid("source recovery conflicts with installed runtime state");
            }
            return Ok(());
        }
        if occupied != 0 {
            return transfer_invalid("source transfer overlaps an active slot transfer");
        }
        let transfer = Arc::new(ActiveTransfer::new(
            descriptor.clone(),
            self.config.max_dirty_keys,
            self.config.max_dirty_bytes,
            initial_phase,
        ));
        for range in &descriptor.ranges {
            for slot in range.start..=range.end {
                slots[usize::from(slot)] = Some(Arc::clone(&transfer));
            }
        }
        self.published.store(Arc::new(TransferRoutes {
            slots: slots.into_boxed_slice(),
        }));
        Ok(())
    }

    #[inline]
    pub fn begin_kv_write(&self, key: &[u8]) -> Result<TransferWriteAdmission, ClusterError> {
        validate_kv_key(key)?;
        self.begin_kv_write_at_slot(slot_for_key(key), key)
    }

    #[inline]
    pub(crate) fn begin_kv_write_at_slot(
        &self,
        slot: u16,
        key: &[u8],
    ) -> Result<TransferWriteAdmission, ClusterError> {
        validate_slot(slot)?;
        validate_kv_key(key)?;
        Ok(
            self.begin_write(slot, DIRTY_IDENTITY_OVERHEAD_BYTES + key.len(), || {
                TransferDataKey::Kv(key.to_vec())
            }),
        )
    }

    #[inline]
    pub fn begin_table_row_write(
        &self,
        table: &str,
        primary_key: &[u8],
    ) -> Result<TransferWriteAdmission, ClusterError> {
        validate_table_row(table, primary_key)?;
        self.begin_table_row_write_at_slot(
            slot_for_table_row(table.as_bytes(), primary_key),
            table,
            primary_key,
        )
    }

    #[inline]
    pub(crate) fn begin_table_row_write_at_slot(
        &self,
        slot: u16,
        table: &str,
        primary_key: &[u8],
    ) -> Result<TransferWriteAdmission, ClusterError> {
        validate_slot(slot)?;
        validate_table_row(table, primary_key)?;
        Ok(self.begin_write(
            slot,
            DIRTY_IDENTITY_OVERHEAD_BYTES + table.len() + primary_key.len(),
            || TransferDataKey::TableRow {
                table: table.to_owned(),
                primary_key: primary_key.to_vec(),
            },
        ))
    }

    #[inline]
    #[must_use]
    fn begin_write(
        &self,
        slot: u16,
        identity_bytes: usize,
        identity: impl FnOnce() -> TransferDataKey,
    ) -> TransferWriteAdmission {
        let mut identity = Some(identity);
        loop {
            let routes = self.published.load();
            let Some(transfer) = routes.slots[usize::from(slot)].as_ref() else {
                return TransferWriteAdmission::Untracked;
            };
            match transfer.begin_write(identity_bytes, &mut identity) {
                ActiveWrite::Admission(admission) => return admission,
                ActiveWrite::Retry => continue,
            }
        }
    }

    pub fn drain_dirty(
        &self,
        transfer_id: TransferId,
    ) -> Result<Vec<TransferDataKey>, ClusterError> {
        let _guard = self.mutation.lock();
        self.find(transfer_id)?.dirty.drain_round()
    }

    /// Stop admitting writes, wait for every previously admitted mutation to
    /// finish and record its dirty identity, then return the complete final
    /// dirty set. The caller sends this final delta, durably records the exact
    /// target receipt, and only then persists the source fence. Topology
    /// activation remains forbidden until both sides are sealed.
    pub fn fence_and_drain(
        &self,
        transfer_id: TransferId,
        timeout: Duration,
    ) -> Result<Arc<[TransferDataKey]>, ClusterError> {
        if timeout.is_zero() || timeout > MAX_TRANSFER_FENCE_WAIT {
            return transfer_invalid(
                "source fence wait must be between 1 nanosecond and 30 seconds",
            );
        }
        let _guard = self.mutation.lock();
        self.find(transfer_id)?.fence_and_drain(timeout)
    }

    /// Confirm that the final target receipt and source fence are durable.
    /// Until this succeeds the final batch remains retained for idempotent
    /// retries and topology activation is rejected.
    pub fn confirm_final(
        &self,
        durable_source: &TransferJournalSnapshot,
    ) -> Result<(), ClusterError> {
        if durable_source.role != TransferRole::Source
            || durable_source.phase != TransferPhase::Fenced
        {
            return transfer_invalid(
                "final transfer confirmation requires a fenced source journal",
            );
        }
        let _guard = self.mutation.lock();
        let transfer = self.find(durable_source.descriptor.transfer_id)?;
        if transfer.descriptor != durable_source.descriptor || durable_source.attempt == 0 {
            return transfer_invalid("source journal does not match the active transfer");
        }
        match transfer.phase.load(Ordering::Acquire) {
            PHASE_FENCING => {
                let mut final_dirty = transfer.final_dirty.lock();
                if final_dirty.is_none() {
                    return transfer_invalid("source final batch is not ready for confirmation");
                }
                transfer.phase.store(PHASE_FENCED, Ordering::Release);
                final_dirty.take();
                Ok(())
            }
            PHASE_FENCED | PHASE_REDIRECTING => Ok(()),
            _ => transfer_invalid("source final batch is not ready for confirmation"),
        }
    }

    /// Switch a durably fenced source into stale-client redirect mode only
    /// after the matching source journal proves that the signed target
    /// topology committed and is serving.
    pub fn mark_activated(
        &self,
        durable_source: &TransferJournalSnapshot,
    ) -> Result<(), ClusterError> {
        if durable_source.role != TransferRole::Source
            || !matches!(
                durable_source.phase,
                TransferPhase::Activated | TransferPhase::Finalized
            )
            || durable_source.attempt == 0
        {
            return transfer_invalid("source activation requires an activated source journal");
        }
        let _guard = self.mutation.lock();
        let transfer = self.find(durable_source.descriptor.transfer_id)?;
        if transfer.descriptor != durable_source.descriptor {
            return transfer_invalid("source journal does not match the active transfer");
        }
        match transfer.phase.compare_exchange(
            PHASE_FENCED,
            PHASE_REDIRECTING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) | Err(PHASE_REDIRECTING) => Ok(()),
            Err(_) => transfer_invalid("source transfer cannot activate before its final fence"),
        }
    }

    pub fn dirty_stats(&self, transfer_id: TransferId) -> Result<DirtyStats, ClusterError> {
        let transfer = self.find(transfer_id)?;
        let mut stats = transfer.dirty.stats();
        if let Some(final_dirty) = transfer.final_dirty.lock().as_ref() {
            stats.keys = stats.keys.saturating_add(final_dirty.len());
            stats.bytes =
                stats
                    .bytes
                    .saturating_add(final_dirty.iter().fold(0_usize, |total, key| {
                        total.saturating_add(key.tracked_bytes())
                    }));
        }
        Ok(stats)
    }

    /// Release a source fence only when the signed ownership transition was
    /// aborted before activation. Activated transfers intentionally retain the
    /// fence until a later RCU grace-period finalizer removes stale routes.
    pub fn release_aborted(&self, transfer_id: TransferId) -> Result<(), ClusterError> {
        let _guard = self.mutation.lock();
        let current = self.published.load_full();
        let transfer = find_in_routes(&current, transfer_id)?;
        if !matches!(
            transfer.phase.load(Ordering::Acquire),
            PHASE_COPYING | PHASE_FENCING | PHASE_FENCED
        ) {
            return transfer_invalid("activated source transfer cannot be aborted");
        }
        transfer.phase.store(PHASE_RELEASED, Ordering::Release);
        self.remove_routes(current, transfer_id);
        Ok(())
    }

    /// Remove redirect state only after every local request path observes the
    /// committed topology and the caller has completed its RCU grace period.
    pub fn release_activated(&self, transfer_id: TransferId) -> Result<(), ClusterError> {
        let _guard = self.mutation.lock();
        let current = self.published.load_full();
        let transfer = find_in_routes(&current, transfer_id)?;
        if transfer.phase.load(Ordering::Acquire) != PHASE_REDIRECTING {
            return transfer_invalid("source transfer is not activated");
        }
        transfer.phase.store(PHASE_RELEASED, Ordering::Release);
        self.remove_routes(current, transfer_id);
        Ok(())
    }

    fn remove_routes(&self, current: Arc<TransferRoutes>, transfer_id: TransferId) {
        let mut slots = current.slots.to_vec();
        for slot in &mut slots {
            if slot
                .as_ref()
                .is_some_and(|candidate| candidate.descriptor.transfer_id == transfer_id)
            {
                *slot = None;
            }
        }
        self.published.store(Arc::new(TransferRoutes {
            slots: slots.into_boxed_slice(),
        }));
    }

    fn find(&self, transfer_id: TransferId) -> Result<Arc<ActiveTransfer>, ClusterError> {
        find_in_routes(&self.published.load(), transfer_id)
    }
}

struct ActiveTransfer {
    descriptor: TransferDescriptor,
    fence: Arc<TransferFence>,
    phase: AtomicU8,
    active_writers: AtomicUsize,
    wait_lock: parking_lot::Mutex<()>,
    writers_drained: parking_lot::Condvar,
    dirty: DirtyTracker,
    final_dirty: parking_lot::Mutex<Option<Arc<[TransferDataKey]>>>,
}

impl ActiveTransfer {
    fn new(
        descriptor: TransferDescriptor,
        max_dirty_keys: usize,
        max_dirty_bytes: usize,
        initial_phase: u8,
    ) -> Self {
        let fence = Arc::new(TransferFence {
            transfer_id: descriptor.transfer_id,
            target_node_id: descriptor.target_node_id.clone(),
            to_epoch: descriptor.to_epoch,
        });
        Self {
            descriptor,
            fence,
            phase: AtomicU8::new(initial_phase),
            active_writers: AtomicUsize::new(0),
            wait_lock: parking_lot::Mutex::new(()),
            writers_drained: parking_lot::Condvar::new(),
            dirty: DirtyTracker::new(max_dirty_keys, max_dirty_bytes),
            final_dirty: parking_lot::Mutex::new(None),
        }
    }

    fn begin_write<F>(
        self: &Arc<Self>,
        identity_bytes: usize,
        identity: &mut Option<F>,
    ) -> ActiveWrite
    where
        F: FnOnce() -> TransferDataKey,
    {
        match self.phase.load(Ordering::Acquire) {
            PHASE_COPYING => {
                if self
                    .active_writers
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                        active.checked_add(1)
                    })
                    .is_err()
                {
                    return ActiveWrite::Admission(TransferWriteAdmission::Fenced(self.fence()));
                }
                match self.phase.load(Ordering::Acquire) {
                    PHASE_COPYING => {
                        if !self.dirty.reserve_identity(identity_bytes) {
                            return ActiveWrite::Admission(TransferWriteAdmission::Admitted(
                                TransferWriteGuard {
                                    transfer: Arc::clone(self),
                                    key: None,
                                    reserved_bytes: 0,
                                },
                            ));
                        }
                        let Some(identity) = identity.take() else {
                            self.dirty.release_identity(identity_bytes);
                            self.writer_finished();
                            return ActiveWrite::Admission(TransferWriteAdmission::Fenced(
                                self.fence(),
                            ));
                        };
                        ActiveWrite::Admission(TransferWriteAdmission::Admitted(
                            TransferWriteGuard {
                                transfer: Arc::clone(self),
                                key: Some(identity()),
                                reserved_bytes: identity_bytes,
                            },
                        ))
                    }
                    PHASE_RELEASED => {
                        self.writer_finished();
                        ActiveWrite::Retry
                    }
                    PHASE_REDIRECTING => {
                        self.writer_finished();
                        ActiveWrite::Admission(TransferWriteAdmission::Redirect(self.fence()))
                    }
                    _ => {
                        self.writer_finished();
                        ActiveWrite::Admission(TransferWriteAdmission::Fenced(self.fence()))
                    }
                }
            }
            PHASE_RELEASED => ActiveWrite::Retry,
            PHASE_REDIRECTING => {
                ActiveWrite::Admission(TransferWriteAdmission::Redirect(self.fence()))
            }
            _ => ActiveWrite::Admission(TransferWriteAdmission::Fenced(self.fence())),
        }
    }

    fn fence_and_drain(&self, timeout: Duration) -> Result<Arc<[TransferDataKey]>, ClusterError> {
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            ClusterError::InvalidTransfer("source fence deadline overflowed".to_owned())
        })?;
        match self.phase.compare_exchange(
            PHASE_COPYING,
            PHASE_FENCING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) | Err(PHASE_FENCING) => {}
            Err(_) => return transfer_invalid("source transfer is not accepting a final drain"),
        }
        let mut wait = self.wait_lock.lock();
        while self.active_writers.load(Ordering::Acquire) != 0 {
            let now = Instant::now();
            if now >= deadline {
                return transfer_invalid("source fence timed out waiting for active writes");
            }
            self.writers_drained.wait_for(&mut wait, deadline - now);
        }
        drop(wait);
        let mut retained = self.final_dirty.lock();
        if let Some(keys) = retained.as_ref() {
            return Ok(Arc::clone(keys));
        }
        let keys: Arc<[TransferDataKey]> = self.dirty.drain_all()?.into();
        *retained = Some(Arc::clone(&keys));
        Ok(keys)
    }

    fn writer_finished(&self) {
        if self.active_writers.fetch_sub(1, Ordering::AcqRel) == 1 {
            let _wait = self.wait_lock.lock();
            self.writers_drained.notify_all();
        }
    }

    fn fence(&self) -> Arc<TransferFence> {
        Arc::clone(&self.fence)
    }
}

enum ActiveWrite {
    Admission(TransferWriteAdmission),
    Retry,
}

fn find_in_routes(
    routes: &TransferRoutes,
    transfer_id: TransferId,
) -> Result<Arc<ActiveTransfer>, ClusterError> {
    routes
        .slots
        .iter()
        .flatten()
        .find(|transfer| transfer.descriptor.transfer_id == transfer_id)
        .cloned()
        .ok_or_else(|| ClusterError::InvalidTransfer("source transfer is not installed".to_owned()))
}

fn validate_table_row(table: &str, primary_key: &[u8]) -> Result<(), ClusterError> {
    if table.is_empty()
        || table.len() > MAX_TRANSFER_TABLE_BYTES
        || !table
            .chars()
            .all(|character| character.is_alphanumeric() || matches!(character, '_' | '.'))
        || table.starts_with('.')
        || table.ends_with('.')
        || table.contains("..")
        || primary_key.len() > MAX_TRANSFER_KEY_BYTES
    {
        return transfer_invalid("table-row transfer identity is invalid or too large");
    }
    Ok(())
}

fn validate_kv_key(key: &[u8]) -> Result<(), ClusterError> {
    if key.len() > MAX_TRANSFER_KEY_BYTES {
        return transfer_invalid("KV transfer key exceeds 64 MiB");
    }
    Ok(())
}

fn validate_slot(slot: u16) -> Result<(), ClusterError> {
    if slot >= CLUSTER_SLOT_COUNT {
        return transfer_invalid("transfer write slot is out of range");
    }
    Ok(())
}

fn transfer_invalid<T>(message: impl Into<String>) -> Result<T, ClusterError> {
    Err(ClusterError::InvalidTransfer(message.into()))
}

#[cfg(test)]
#[path = "transfer_runtime_tests.rs"]
mod tests;
