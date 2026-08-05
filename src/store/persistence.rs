use std::cell::RefCell;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use parking_lot::{Condvar, Mutex, MutexGuard};

thread_local! {
    static DEPTHS: RefCell<Vec<ThreadDepth>> = const { RefCell::new(Vec::new()) };
}

#[derive(Clone, Copy)]
struct ThreadDepth {
    barrier: usize,
    mutations: usize,
    cutovers: usize,
}

#[derive(Clone, Copy)]
enum DepthKind {
    Mutation,
    Cutover,
}

struct DepthGuard {
    barrier: usize,
    kind: DepthKind,
}

impl DepthGuard {
    fn enter(barrier: usize, kind: DepthKind) -> Self {
        DEPTHS.with(|depths| {
            let mut depths = depths.borrow_mut();
            let depth = match depths.iter_mut().find(|depth| depth.barrier == barrier) {
                Some(depth) => depth,
                None => {
                    depths.push(ThreadDepth {
                        barrier,
                        mutations: 0,
                        cutovers: 0,
                    });
                    depths.last_mut().expect("persistence depth was inserted")
                }
            };
            match kind {
                DepthKind::Mutation => depth.mutations += 1,
                DepthKind::Cutover => depth.cutovers += 1,
            }
        });
        Self { barrier, kind }
    }
}

impl Drop for DepthGuard {
    fn drop(&mut self) {
        DEPTHS.with(|depths| {
            let mut depths = depths.borrow_mut();
            let index = depths
                .iter()
                .position(|depth| depth.barrier == self.barrier)
                .expect("persistence depth must outlive its guard");
            let depth = &mut depths[index];
            match self.kind {
                DepthKind::Mutation => depth.mutations -= 1,
                DepthKind::Cutover => depth.cutovers -= 1,
            }
            if depth.mutations == 0 && depth.cutovers == 0 {
                depths.swap_remove(index);
            }
        });
    }
}

fn thread_depth(barrier: usize) -> Option<ThreadDepth> {
    DEPTHS.with(|depths| {
        depths
            .borrow()
            .iter()
            .find(|depth| depth.barrier == barrier)
            .copied()
    })
}

/// Coordinates point-in-time persistence without serializing unrelated writes.
///
/// Mutations take a shared, lock-free lease. A snapshot or ownership cutover
/// closes admission, waits for existing leases to drain, and then runs alone.
/// Nested mutation helpers on the same thread share the outer lease, which is
/// required for table/auth helpers and for commands issued from Lua.
pub(super) struct Barrier {
    closed: AtomicBool,
    active: AtomicUsize,
    cutover: Mutex<()>,
    wait: Mutex<()>,
    quiescent: Condvar,
}

impl Barrier {
    pub(super) fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
            active: AtomicUsize::new(0),
            cutover: Mutex::new(()),
            wait: Mutex::new(()),
            quiescent: Condvar::new(),
        }
    }

    #[inline]
    fn identity(&self) -> usize {
        self as *const Self as usize
    }

    pub(super) fn with_mutation<R>(&self, operation: impl FnOnce() -> R) -> R {
        let identity = self.identity();
        let nested =
            thread_depth(identity).is_some_and(|depth| depth.mutations > 0 || depth.cutovers > 0);
        if nested {
            let _depth = DepthGuard::enter(identity, DepthKind::Mutation);
            return operation();
        }

        self.enter_mutation();
        let _permit = MutationPermit { barrier: self };
        let _depth = DepthGuard::enter(identity, DepthKind::Mutation);
        operation()
    }

    pub(super) fn with_cutover<R>(&self, operation: impl FnOnce() -> R) -> Result<R, UpgradeError> {
        let identity = self.identity();
        if let Some(depth) = thread_depth(identity) {
            if depth.cutovers > 0 {
                let _depth = DepthGuard::enter(identity, DepthKind::Cutover);
                return Ok(operation());
            }
            if depth.mutations > 0 {
                return Err(UpgradeError);
            }
        }

        let permit = self.enter_cutover();
        let _depth = DepthGuard::enter(identity, DepthKind::Cutover);
        let result = operation();
        drop(permit);
        Ok(result)
    }

    fn enter_mutation(&self) {
        loop {
            if self.closed.load(Ordering::Acquire) {
                self.wait_until_open();
                continue;
            }

            let prior = self.active.fetch_add(1, Ordering::AcqRel);
            assert!(prior < usize::MAX, "persistence mutation count overflow");
            if !self.closed.load(Ordering::Acquire) {
                return;
            }

            self.leave_mutation();
            self.wait_until_open();
        }
    }

    fn leave_mutation(&self) {
        let prior = self.active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(prior > 0, "persistence mutation count underflow");
        if prior == 1 && self.closed.load(Ordering::Acquire) {
            // Pair the notification with the same mutex used by the waiter so a
            // last writer cannot signal between the cutover's check and wait.
            let _wait = self.wait.lock();
            self.quiescent.notify_all();
        }
    }

    fn wait_until_open(&self) {
        let mut wait = self.wait.lock();
        while self.closed.load(Ordering::Acquire) {
            self.quiescent.wait(&mut wait);
        }
    }

    fn enter_cutover(&self) -> CutoverPermit<'_> {
        let exclusive = self.cutover.lock();
        let mut wait = self.wait.lock();
        self.closed.store(true, Ordering::SeqCst);
        while self.active.load(Ordering::Acquire) != 0 {
            self.quiescent.wait(&mut wait);
        }
        drop(wait);
        CutoverPermit {
            barrier: self,
            _exclusive: exclusive,
        }
    }
}

struct MutationPermit<'a> {
    barrier: &'a Barrier,
}

impl Drop for MutationPermit<'_> {
    fn drop(&mut self) {
        self.barrier.leave_mutation();
    }
}

struct CutoverPermit<'a> {
    barrier: &'a Barrier,
    _exclusive: MutexGuard<'a, ()>,
}

impl Drop for CutoverPermit<'_> {
    fn drop(&mut self) {
        let _wait = self.barrier.wait.lock();
        self.barrier.closed.store(false, Ordering::Release);
        self.barrier.quiescent.notify_all();
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct UpgradeError;

impl fmt::Display for UpgradeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("cannot begin a persistence cutover from inside a mutation")
    }
}

impl std::error::Error for UpgradeError {}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::time::Duration;

    use super::Barrier;

    #[test]
    fn cutover_waits_for_an_inflight_mutation_and_blocks_new_ones() {
        let barrier = Arc::new(Barrier::new());
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let writer = {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.with_mutation(|| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                });
            })
        };
        entered_rx.recv().unwrap();

        let (cutover_tx, cutover_rx) = mpsc::channel();
        let cutover = {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier
                    .with_cutover(|| cutover_tx.send(()).unwrap())
                    .unwrap();
            })
        };
        assert!(cutover_rx.recv_timeout(Duration::from_millis(30)).is_err());

        let (second_tx, second_rx) = mpsc::channel();
        let second = {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.with_mutation(|| second_tx.send(()).unwrap());
            })
        };
        assert!(second_rx.recv_timeout(Duration::from_millis(30)).is_err());

        release_tx.send(()).unwrap();
        cutover_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        second_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        writer.join().unwrap();
        cutover.join().unwrap();
        second.join().unwrap();
    }

    #[test]
    fn mutation_and_cutover_are_reentrant_but_upgrades_fail_closed() {
        let barrier = Barrier::new();
        barrier.with_mutation(|| barrier.with_mutation(|| {}));
        barrier
            .with_cutover(|| barrier.with_cutover(|| {}).unwrap())
            .unwrap();
        let error = barrier.with_mutation(|| barrier.with_cutover(|| {}));
        assert!(error.is_err());
    }
}
