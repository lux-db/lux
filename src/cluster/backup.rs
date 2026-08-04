use super::{BackupPartDescriptor, ClusterError, ClusterNode};
use crate::store::Store;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SESSION_TTL: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Preparing,
    Ready,
    Capturing,
    Captured,
    Released,
}

enum Command {
    Capture(mpsc::SyncSender<Result<PathBuf, String>>),
    Release(mpsc::SyncSender<()>),
}

struct Session {
    id: String,
    credential_hash: [u8; 32],
    phase: Phase,
    descriptor: Option<BackupPartDescriptor>,
    path: Option<PathBuf>,
    commands: mpsc::SyncSender<Command>,
    deadline_ms: Arc<AtomicU64>,
}

#[derive(Default)]
pub(super) struct BackupCoordinator {
    session: Mutex<Option<Session>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SessionAccess {
    Missing,
    Authorized,
    Forbidden,
    Conflict,
}

impl BackupCoordinator {
    pub(super) fn prepare(
        self: &Arc<Self>,
        node: Arc<ClusterNode>,
        store: Arc<Store>,
        backup_id: &str,
        credential: &str,
    ) -> Result<BackupPartDescriptor, ClusterError> {
        validate_id(backup_id)?;
        self.expire_old_session()?;
        {
            let mut current = self.lock()?;
            if let Some(session) = current.as_mut() {
                if session.id != backup_id {
                    return Err(conflict("another cluster backup is active"));
                }
                if !credential_matches(&session.credential_hash, credential) {
                    return Err(conflict("cluster backup credential does not match"));
                }
                renew(&session.deadline_ms);
                return session
                    .descriptor
                    .clone()
                    .ok_or_else(|| conflict("cluster backup preparation is still in progress"));
            }
        }

        let (commands, receiver) = mpsc::sync_channel(1);
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let deadline_ms = Arc::new(AtomicU64::new(deadline()));
        {
            let mut current = self.lock()?;
            *current = Some(Session {
                id: backup_id.to_string(),
                credential_hash: credential_hash(credential),
                phase: Phase::Preparing,
                descriptor: None,
                path: None,
                commands,
                deadline_ms: deadline_ms.clone(),
            });
        }

        let id = backup_id.to_string();
        if let Err(error) = std::thread::Builder::new()
            .name(format!("lux-backup-{}", &backup_id[..8]))
            .spawn(move || {
                let result = run_barrier(&node, &store, &id, &deadline_ms, receiver, ready_sender);
                if let Err(error) = result {
                    eprintln!("cluster backup barrier failed: {error}");
                }
            })
        {
            self.clear_failed(backup_id)?;
            return Err(ClusterError::Io(error));
        }

        let descriptor = match ready_receiver.recv() {
            Ok(Ok(descriptor)) => descriptor,
            Ok(Err(error)) => {
                self.clear_failed(backup_id)?;
                return Err(conflict(error));
            }
            Err(_) => {
                self.clear_failed(backup_id)?;
                return Err(conflict(
                    "cluster backup barrier exited before becoming ready",
                ));
            }
        };
        let mut current = self.lock()?;
        let session = matching_session(&mut current, backup_id)?;
        session.phase = Phase::Ready;
        session.descriptor = Some(descriptor.clone());
        Ok(descriptor)
    }

    pub(super) fn capture(&self, backup_id: &str) -> Result<PathBuf, ClusterError> {
        validate_id(backup_id)?;
        let (sender, receiver) = mpsc::sync_channel(1);
        {
            let mut current = self.lock()?;
            let session = matching_session(&mut current, backup_id)?;
            renew(&session.deadline_ms);
            if matches!(session.phase, Phase::Captured | Phase::Released) {
                return session
                    .path
                    .clone()
                    .ok_or_else(|| conflict("cluster backup has no captured part"));
            }
            if session.phase != Phase::Ready {
                return Err(conflict("cluster backup is not ready to capture"));
            }
            session.phase = Phase::Capturing;
            if session.commands.send(Command::Capture(sender)).is_err() {
                session.phase = Phase::Released;
                return Err(conflict("cluster backup barrier is no longer active"));
            }
        }
        let result = match receiver.recv() {
            Ok(result) => result,
            Err(_) => {
                let mut current = self.lock()?;
                let session = matching_session(&mut current, backup_id)?;
                session.phase = Phase::Released;
                return Err(conflict("cluster backup capture exited unexpectedly"));
            }
        };
        let mut current = self.lock()?;
        let session = matching_session(&mut current, backup_id)?;
        let path = match result {
            Ok(path) => path,
            Err(error) => {
                session.phase = Phase::Released;
                return Err(conflict(error));
            }
        };
        session.phase = Phase::Captured;
        session.path = Some(path.clone());
        Ok(path)
    }

    pub(super) fn release(&self, backup_id: &str) -> Result<bool, ClusterError> {
        validate_id(backup_id)?;
        let receiver = {
            let mut current = self.lock()?;
            let Some(session) = current.as_mut() else {
                return Ok(false);
            };
            if session.id != backup_id {
                return Err(conflict("another cluster backup is active"));
            }
            if session.phase == Phase::Released {
                return Ok(false);
            }
            let (sender, receiver) = mpsc::sync_channel(1);
            if session.commands.send(Command::Release(sender)).is_err() {
                session.phase = Phase::Released;
                return Ok(true);
            }
            receiver
        };
        let _ = receiver.recv_timeout(Duration::from_secs(5));
        let mut current = self.lock()?;
        let session = matching_session(&mut current, backup_id)?;
        session.phase = Phase::Released;
        Ok(true)
    }

    pub(super) fn part(
        &self,
        backup_id: &str,
    ) -> Result<(BackupPartDescriptor, PathBuf), ClusterError> {
        validate_id(backup_id)?;
        let mut current = self.lock()?;
        let session = matching_session(&mut current, backup_id)?;
        if !matches!(session.phase, Phase::Captured | Phase::Released) {
            return Err(conflict("cluster backup part has not been captured"));
        }
        renew(&session.deadline_ms);
        Ok((
            session
                .descriptor
                .clone()
                .ok_or_else(|| conflict("cluster backup descriptor is unavailable"))?,
            session
                .path
                .clone()
                .ok_or_else(|| conflict("cluster backup part is unavailable"))?,
        ))
    }

    pub(super) fn finish(&self, backup_id: &str) -> Result<bool, ClusterError> {
        validate_id(backup_id)?;
        let _ = self.release(backup_id)?;
        let path = {
            let mut current = self.lock()?;
            let Some(session) = current.as_ref() else {
                return Ok(false);
            };
            if session.id != backup_id {
                return Err(conflict("another cluster backup is active"));
            }
            let path = session.path.clone();
            *current = None;
            path
        };
        if let Some(path) = path {
            crate::snapshot::remove_cluster_backup_part(&path).map_err(ClusterError::Io)?;
        }
        Ok(true)
    }

    pub(super) fn expire_old_session(&self) -> Result<(), ClusterError> {
        let expired = {
            let current = self.lock()?;
            current
                .as_ref()
                .filter(|session| session.deadline_ms.load(Ordering::Acquire) <= now_ms())
                .map(|session| session.id.clone())
        };
        if let Some(id) = expired {
            let _ = self.finish(&id)?;
        }
        Ok(())
    }

    pub(super) fn access(
        &self,
        backup_id: &str,
        credential: &str,
    ) -> Result<SessionAccess, ClusterError> {
        validate_id(backup_id)?;
        let current = self.lock()?;
        let Some(session) = current.as_ref() else {
            return Ok(SessionAccess::Missing);
        };
        if session.id != backup_id {
            return Ok(SessionAccess::Conflict);
        }
        if credential_matches(&session.credential_hash, credential) {
            Ok(SessionAccess::Authorized)
        } else {
            Ok(SessionAccess::Forbidden)
        }
    }

    fn clear_failed(&self, backup_id: &str) -> Result<(), ClusterError> {
        let mut current = self.lock()?;
        if current
            .as_ref()
            .is_some_and(|session| session.id == backup_id)
        {
            *current = None;
        }
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Option<Session>>, ClusterError> {
        self.session
            .lock()
            .map_err(|_| conflict("cluster backup session lock is poisoned"))
    }
}

fn run_barrier(
    node: &Arc<ClusterNode>,
    store: &Arc<Store>,
    backup_id: &str,
    deadline_ms: &Arc<AtomicU64>,
    receiver: mpsc::Receiver<Command>,
    ready: mpsc::SyncSender<Result<BackupPartDescriptor, String>>,
) -> Result<(), String> {
    let _control = node
        .backup_control
        .lock()
        .map_err(|_| "backup control lock is poisoned".to_string())?;
    store.with_write_barrier(|shards| {
        let descriptor = match node.backup_part_descriptor() {
            Ok(descriptor) => descriptor,
            Err(error) => {
                let _ = ready.send(Err(error.to_string()));
                return Err(error.to_string());
            }
        };
        ready
            .send(Ok(descriptor))
            .map_err(|_| "backup preparation caller disconnected".to_string())?;
        loop {
            if deadline_ms.load(Ordering::Acquire) <= now_ms() {
                return Ok(());
            }
            match receiver.recv_timeout(POLL_INTERVAL) {
                Ok(Command::Capture(response)) => {
                    let result = crate::snapshot::snapshot_cluster_part_from_locked_shards(
                        store, shards, backup_id,
                    )
                    .map_err(|error| error.to_string());
                    let failed = result.is_err();
                    let _ = response.send(result);
                    if failed {
                        return Ok(());
                    }
                }
                Ok(Command::Release(response)) => {
                    let _ = response.send(());
                    return Ok(());
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
            }
        }
    })
}

fn matching_session<'a>(
    current: &'a mut Option<Session>,
    backup_id: &str,
) -> Result<&'a mut Session, ClusterError> {
    let session = current
        .as_mut()
        .ok_or_else(|| conflict("cluster backup session was not prepared"))?;
    if session.id != backup_id {
        return Err(conflict("another cluster backup is active"));
    }
    Ok(session)
}

fn renew(deadline_ms: &AtomicU64) {
    deadline_ms.store(deadline(), Ordering::Release);
}

fn deadline() -> u64 {
    now_ms().saturating_add(SESSION_TTL.as_millis() as u64)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn validate_id(backup_id: &str) -> Result<(), ClusterError> {
    let bytes = backup_id.as_bytes();
    let valid = bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        });
    if valid {
        Ok(())
    } else {
        Err(conflict("backup id must be a UUID"))
    }
}

fn credential_hash(credential: &str) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(credential.as_bytes()).into()
}

fn credential_matches(expected: &[u8; 32], credential: &str) -> bool {
    let actual = credential_hash(credential);
    expected
        .iter()
        .zip(actual.iter())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn conflict(message: impl Into<String>) -> ClusterError {
    ClusterError::Protocol(message.into())
}
