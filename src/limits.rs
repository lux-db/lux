use std::sync::Arc;
use std::time::Duration;

pub(crate) const RESP_RESPONSE_LIMIT_ERROR: &[u8] = b"-ERR RESP response exceeds maximum\r\n";

/// Resource and deadline limits shared by the network surfaces.
///
/// Every default is finite. Embedded users may tune a limit for their workload,
/// but cannot accidentally construct an unbounded listener by accepting the
/// default configuration.
#[derive(Clone, Copy, Debug)]
pub struct ServerLimits {
    /// Maximum simultaneously accepted RESP connections.
    pub max_resp_connections: usize,
    /// Maximum simultaneously accepted HTTP connections, including WebSockets.
    pub max_http_connections: usize,
    /// Maximum RESP clients allowed to wait in a blocking command at once.
    pub max_blocked_clients: usize,
    /// Maximum complete commands accepted from one RESP read buffer.
    pub max_resp_pipeline_commands: usize,
    /// Maximum arguments accepted in one RESP array command.
    pub max_resp_command_args: usize,
    /// Maximum channel, pattern, and key subscriptions on one RESP connection.
    pub max_resp_subscriptions: usize,
    /// Maximum UTF-8 bytes retained for one subscription name or pattern.
    pub max_subscription_name_bytes: usize,
    /// Maximum live-query subscriptions on one WebSocket connection.
    pub max_live_subscriptions: usize,
    /// Maximum broker receiver registrations retained by network clients.
    pub max_subscriptions: usize,
    /// Maximum candidate rows one table query may inspect.
    pub max_query_candidates: usize,
    /// Maximum number of keys registered by one blocking command.
    pub max_blocking_keys: usize,
    /// Maximum RESP bytes materialized for one connection output batch.
    pub max_resp_response: usize,
    /// Shared bytes retained by requests, session state, subscriptions, and
    /// realtime queues.
    pub max_request_buffer_bytes: usize,
    /// Shared bytes allowed in socket writes that have not completed yet.
    pub max_response_buffer_bytes: usize,
    /// Maximum concurrent app-auth requests that may perform expensive work.
    pub max_auth_workers: usize,
    /// Maximum heap bytes available to one Lua script VM.
    pub max_script_memory: usize,
    /// Idle lifetime for a RESP connection that has no partial request.
    pub resp_idle_timeout: Duration,
    /// Total lifetime of an incomplete RESP request.
    pub resp_request_timeout: Duration,
    /// Time allowed to receive an HTTP request head after its first byte.
    pub http_header_timeout: Duration,
    /// Time allowed to receive an HTTP request body.
    pub http_body_timeout: Duration,
    /// Idle lifetime between requests on an HTTP keep-alive connection.
    pub http_keep_alive_timeout: Duration,
    /// Idle lifetime for a live WebSocket without client traffic.
    pub live_idle_timeout: Duration,
    /// Maximum time a socket write may remain unable to make progress.
    pub write_timeout: Duration,
}

impl Default for ServerLimits {
    fn default() -> Self {
        let auth_workers = std::thread::available_parallelism()
            .map(|workers| workers.get().saturating_sub(1).clamp(1, 4))
            .unwrap_or(2);
        Self {
            max_resp_connections: 1_024,
            max_http_connections: 1_024,
            max_blocked_clients: 256,
            max_resp_pipeline_commands: 1_024,
            max_resp_command_args: 16_384,
            max_resp_subscriptions: 1_024,
            max_subscription_name_bytes: 16 * 1024,
            max_live_subscriptions: 128,
            max_subscriptions: 4_096,
            max_query_candidates: 1_000_000,
            max_blocking_keys: 1_024,
            max_resp_response: 64 * 1024 * 1024,
            max_request_buffer_bytes: 256 * 1024 * 1024,
            max_response_buffer_bytes: 256 * 1024 * 1024,
            max_auth_workers: auth_workers,
            max_script_memory: 64 * 1024 * 1024,
            resp_idle_timeout: Duration::from_secs(300),
            resp_request_timeout: Duration::from_secs(10),
            http_header_timeout: Duration::from_secs(10),
            http_body_timeout: Duration::from_secs(30),
            http_keep_alive_timeout: Duration::from_secs(60),
            live_idle_timeout: Duration::from_secs(300),
            write_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ByteBudget {
    inner: Arc<ByteBudgetInner>,
}

#[derive(Debug)]
struct ByteBudgetInner {
    limit: usize,
    used: std::sync::atomic::AtomicUsize,
}

impl ByteBudget {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            inner: Arc::new(ByteBudgetInner {
                limit,
                used: std::sync::atomic::AtomicUsize::new(0),
            }),
        }
    }

    pub(crate) fn reservation(&self) -> ByteReservation {
        ByteReservation {
            budget: self.clone(),
            bytes: 0,
        }
    }

    pub(crate) fn try_reserve(&self, bytes: usize) -> Option<ByteReservation> {
        let mut reservation = self.reservation();
        reservation.try_grow(bytes).then_some(reservation)
    }
}

#[derive(Debug)]
pub(crate) struct ByteReservation {
    budget: ByteBudget,
    bytes: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct CountBudget {
    inner: Arc<CountBudgetInner>,
}

#[derive(Debug)]
struct CountBudgetInner {
    limit: usize,
    used: std::sync::atomic::AtomicUsize,
}

impl CountBudget {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            inner: Arc::new(CountBudgetInner {
                limit,
                used: std::sync::atomic::AtomicUsize::new(0),
            }),
        }
    }

    pub(crate) fn reservation(&self) -> CountReservation {
        CountReservation {
            budget: self.clone(),
            count: 0,
        }
    }

    pub(crate) fn used(&self) -> usize {
        self.inner.used.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[derive(Debug)]
pub(crate) struct CountReservation {
    budget: CountBudget,
    count: usize,
}

impl CountReservation {
    pub(crate) fn try_grow(&mut self, count: usize) -> bool {
        if count == 0 {
            return true;
        }
        let used = &self.budget.inner.used;
        let mut current = used.load(std::sync::atomic::Ordering::Relaxed);
        loop {
            let Some(next) = current.checked_add(count) else {
                return false;
            };
            if next > self.budget.inner.limit {
                return false;
            }
            match used.compare_exchange_weak(
                current,
                next,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.count += count;
                    return true;
                }
                Err(observed) => current = observed,
            }
        }
    }

    pub(crate) fn release(&mut self, count: usize) {
        let released = count.min(self.count);
        if released == 0 {
            return;
        }
        self.count -= released;
        self.budget
            .inner
            .used
            .fetch_sub(released, std::sync::atomic::Ordering::AcqRel);
    }
}

impl Drop for CountReservation {
    fn drop(&mut self) {
        self.release(self.count);
    }
}

impl ByteReservation {
    pub(crate) fn try_grow(&mut self, bytes: usize) -> bool {
        if bytes == 0 {
            return true;
        }
        let used = &self.budget.inner.used;
        let mut current = used.load(std::sync::atomic::Ordering::Relaxed);
        loop {
            let Some(next) = current.checked_add(bytes) else {
                return false;
            };
            if next > self.budget.inner.limit {
                return false;
            }
            match used.compare_exchange_weak(
                current,
                next,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.bytes += bytes;
                    return true;
                }
                Err(observed) => current = observed,
            }
        }
    }

    pub(crate) fn release(&mut self, bytes: usize) {
        let released = bytes.min(self.bytes);
        if released == 0 {
            return;
        }
        self.bytes -= released;
        self.budget
            .inner
            .used
            .fetch_sub(released, std::sync::atomic::Ordering::AcqRel);
    }
}

impl Drop for ByteReservation {
    fn drop(&mut self) {
        self.release(self.bytes);
    }
}

pub(crate) struct DeadlineStream {
    inner: tokio::net::TcpStream,
    write_timeout: Duration,
    max_write_bytes: usize,
    pending_write_deadline: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    write_budget: Option<ByteBudget>,
    pending_write_reservation: Option<ByteReservation>,
    pending_write_bytes: usize,
}

impl DeadlineStream {
    pub(crate) fn new(
        inner: tokio::net::TcpStream,
        write_timeout: Duration,
        max_write_bytes: usize,
    ) -> Self {
        Self {
            inner,
            write_timeout,
            max_write_bytes,
            pending_write_deadline: None,
            write_budget: None,
            pending_write_reservation: None,
            pending_write_bytes: 0,
        }
    }

    pub(crate) fn with_write_budget(
        inner: tokio::net::TcpStream,
        write_timeout: Duration,
        max_write_bytes: usize,
        write_budget: ByteBudget,
    ) -> Self {
        let mut stream = Self::new(inner, write_timeout, max_write_bytes);
        stream.write_budget = Some(write_budget);
        stream
    }

    pub(crate) async fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let bytes = if bytes.len() > self.max_write_bytes {
            RESP_RESPONSE_LIMIT_ERROR
        } else {
            bytes
        };
        // Hold capacity for the complete logical write, including bytes the OS
        // accepts immediately. Otherwise many slow clients can each retain a
        // large response in their task while no individual poll is pending.
        let _reservation = match self.write_budget.as_ref() {
            Some(budget) => Some(budget.try_reserve(bytes.len()).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::OutOfMemory,
                    "network write buffer capacity exhausted",
                )
            })?),
            None => None,
        };
        let timeout = self.write_timeout;
        match tokio::time::timeout(
            timeout,
            tokio::io::AsyncWriteExt::write_all(&mut self.inner, bytes),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                self.clear_pending_write();
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "socket write deadline exceeded",
                ))
            }
        }
    }

    pub(crate) fn max_write_bytes(&self) -> usize {
        self.max_write_bytes
    }

    pub(crate) fn write_budget(&self) -> Option<ByteBudget> {
        self.write_budget.clone()
    }

    fn clear_pending_write(&mut self) {
        self.pending_write_deadline = None;
        self.pending_write_reservation = None;
        self.pending_write_bytes = 0;
    }

    /// Wait until a peer with no queued input closes its side of the socket.
    /// Blocking commands use this to release their global permit promptly when
    /// a client disappears. If input is already queued, preserve it for the
    /// next command rather than consuming bytes merely to detect disconnects.
    pub(crate) async fn wait_for_peer_close(&self) -> std::io::Result<()> {
        let mut byte = [0u8; 1];
        match self.inner.peek(&mut byte).await {
            Ok(0) => Ok(()),
            Ok(_) => std::future::pending().await,
            Err(error) => Err(error),
        }
    }
}

impl tokio::io::AsyncRead for DeadlineStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for DeadlineStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        if self.pending_write_reservation.is_some() && self.pending_write_bytes != buf.len() {
            self.clear_pending_write();
        }
        if self.pending_write_reservation.is_none() {
            if let Some(budget) = self.write_budget.as_ref() {
                let Some(reservation) = budget.try_reserve(buf.len()) else {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::OutOfMemory,
                        "network write buffer capacity exhausted",
                    )));
                };
                self.pending_write_reservation = Some(reservation);
                self.pending_write_bytes = buf.len();
            }
        }
        match std::pin::Pin::new(&mut self.inner).poll_write(cx, buf) {
            std::task::Poll::Ready(result) => {
                self.clear_pending_write();
                std::task::Poll::Ready(result)
            }
            std::task::Poll::Pending => {
                if self.pending_write_deadline.is_none() {
                    self.pending_write_deadline =
                        Some(Box::pin(tokio::time::sleep(self.write_timeout)));
                }
                let deadline = self.pending_write_deadline.as_mut().expect("set above");
                match std::future::Future::poll(deadline.as_mut(), cx) {
                    std::task::Poll::Ready(()) => {
                        self.clear_pending_write();
                        std::task::Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "socket write deadline exceeded",
                        )))
                    }
                    std::task::Poll::Pending => std::task::Poll::Pending,
                }
            }
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.clear_pending_write();
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.clear_pending_write();
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_budget_releases_partial_and_dropped_reservations() {
        let budget = ByteBudget::new(10);
        let mut first = budget.reservation();
        assert!(first.try_grow(7));
        assert!(!first.try_grow(4));
        first.release(3);

        let mut second = budget.reservation();
        assert!(second.try_grow(6));
        assert!(!first.try_grow(1));
        drop(second);
        assert!(first.try_grow(6));
        drop(first);

        let mut whole = budget.reservation();
        assert!(whole.try_grow(10));
    }

    #[test]
    fn byte_budget_never_overcommits_under_contention() {
        let budget = ByteBudget::new(8);
        let barrier = Arc::new(std::sync::Barrier::new(33));
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut threads = Vec::new();

        for _ in 0..32 {
            let budget = budget.clone();
            let barrier = barrier.clone();
            let active = active.clone();
            let peak = peak.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                let mut reservation = budget.reservation();
                if reservation.try_grow(1) {
                    let now = active.fetch_add(1, std::sync::atomic::Ordering::AcqRel) + 1;
                    peak.fetch_max(now, std::sync::atomic::Ordering::AcqRel);
                    std::thread::sleep(Duration::from_millis(10));
                    active.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                }
            }));
        }
        barrier.wait();
        for thread in threads {
            thread.join().unwrap();
        }

        assert!(peak.load(std::sync::atomic::Ordering::Acquire) <= 8);
        let mut reservation = budget.reservation();
        assert!(reservation.try_grow(8));
    }

    #[tokio::test]
    async fn deadline_stream_write_budget_sheds_and_recovers() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
            let mut byte = [0u8; 1];
            tokio::io::AsyncReadExt::read_exact(&mut socket, &mut byte)
                .await
                .unwrap();
            byte[0]
        });
        let (socket, _) = listener.accept().await.unwrap();
        let budget = ByteBudget::new(1);
        let held = budget.try_reserve(1).unwrap();
        let mut stream =
            DeadlineStream::with_write_budget(socket, Duration::from_secs(1), usize::MAX, budget);

        let error = stream.write_all(b"x").await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::OutOfMemory);
        drop(held);
        stream.write_all(b"y").await.unwrap();
        assert_eq!(client.await.unwrap(), b'y');
    }
}
