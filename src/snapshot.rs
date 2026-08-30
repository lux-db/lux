use crate::store::{BackgroundSavePhase, DumpValue, Store};
use hashbrown::{HashMap, HashSet};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, BufRead, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

const HEADER_V1: &[u8; 4] = b"LUX\x01";
const HEADER_V2: &[u8; 4] = b"LUX\x02";
// V3 persists key TTLs as ABSOLUTE epoch-ms deadlines instead of relative
// remaining-ms. V2 rebased the remaining time to load-time, so a key with N ms
// left at save time got a full fresh N ms on restart -- TTLs paused across
// downtime and keys that should have expired while down resurrected. V3 subtracts
// elapsed wall-clock on load so deadlines are honored across restarts.
const HEADER: &[u8; 4] = b"LUX\x03";
// V4 prefixes the V3 entry stream with the exact end offset and generation of
// every WAL represented by the snapshot.
const HEADER_V4: &[u8; 4] = b"LUX\x04";
// V5 wraps the checkpoint + entry stream in an exact length and SHA-256 digest,
// so truncation or bit corruption cannot be mistaken for a smaller valid DB.
const HEADER_V5: &[u8; 4] = b"LUX\x05";
// V6 additionally binds every checkpoint to the one journal generation that
// may replace it after the snapshot commit. This distinguishes a legitimate
// rotation from a deleted or substituted journal.
const HEADER_V6: &[u8; 4] = b"LUX\x06";
// Single-key DUMP/LXRESTORE envelope. The payload remains the V3 entry format
// for backward compatibility, but new blobs carry an exact length and digest.
const DUMP_HEADER: &[u8; 4] = b"LXD\x01";
const SNAPSHOT_DIGEST_LEN: usize = 32;
const MAX_WAL_CHECKPOINTS: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SnapshotFormat {
    V1,
    V2,
    V3,
    V4,
    V5,
    V6,
}

impl SnapshotFormat {
    pub(crate) fn version(self) -> u8 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
            Self::V3 => 3,
            Self::V4 => 4,
            Self::V5 => 5,
            Self::V6 => 6,
        }
    }

    pub(crate) fn from_version(version: u8) -> io::Result<Self> {
        match version {
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            3 => Ok(Self::V3),
            4 => Ok(Self::V4),
            5 => Ok(Self::V5),
            6 => Ok(Self::V6),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported Lux snapshot format version {version}"),
            )),
        }
    }
}

pub(crate) struct BackupSnapshot {
    pub(crate) file: fs::File,
    pub(crate) len: u64,
    pub(crate) sha256: [u8; SNAPSHOT_DIGEST_LEN],
    pub(crate) format: SnapshotFormat,
}

impl BackupSnapshot {
    pub(crate) fn sha256_hex(&self) -> String {
        self.sha256
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

#[cfg(test)]
mod fault_injection {
    use std::cell::Cell;
    use std::io;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum Point {
        BeforeSnapshotRename,
        AfterSnapshotRename,
    }

    thread_local! {
        static POINT: Cell<Option<Point>> = const { Cell::new(None) };
    }

    pub(super) struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            POINT.set(None);
        }
    }

    pub(super) fn inject(point: Point) -> Guard {
        POINT.with(|slot| {
            assert!(
                slot.replace(Some(point)).is_none(),
                "fault already injected"
            );
        });
        Guard
    }

    pub(super) fn check(point: Point) -> io::Result<()> {
        POINT.with(|slot| {
            if slot.get() == Some(point) {
                slot.set(None);
                Err(io::Error::other(format!(
                    "injected snapshot failure at {point:?}"
                )))
            } else {
                Ok(())
            }
        })
    }
}

/// Wall-clock now in epoch milliseconds (for absolute TTL deadlines).
fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn snapshot_path(store: &Store) -> String {
    let dir = &store.config().data_dir;
    format!("{}/lux.dat", dir.trim_end_matches('/'))
}

fn snapshot_path_for_config(config: &crate::ServerConfig) -> std::path::PathBuf {
    Path::new(&config.data_dir).join("lux.dat")
}

/// Journal names whose generations are represented by the installed snapshot.
/// Startup must open these files without creating them: manufacturing an empty
/// replacement would erase the only evidence of post-snapshot writes. Older
/// snapshots without a global checkpoint may still create the global journal
/// as part of the one-way upgrade from per-shard journals.
pub(crate) fn required_existing_journals(
    config: &crate::ServerConfig,
) -> io::Result<HashSet<String>> {
    let path = snapshot_path_for_config(config);
    if !crate::file_security::regular_file_exists(&path)? {
        return Ok(HashSet::new());
    }
    let mut file = crate::file_security::open_private_file(&path, |options| {
        options.read(true);
    })?;
    let mut header = [0u8; 4];
    let read = file.read(&mut header)?;
    if read < header.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snapshot is truncated before its header",
        ));
    }

    let checkpoints = if &header == HEADER_V6 || &header == HEADER_V5 {
        let body_len = read_u64(&mut file)?;
        let mut expected_digest = [0u8; SNAPSHOT_DIGEST_LEN];
        file.read_exact(&mut expected_digest)?;
        verify_snapshot_body(&mut file, body_len, &expected_digest)?;
        let mut reader = io::BufReader::new(file.take(body_len));
        read_wal_checkpoints(&mut reader, &header == HEADER_V6)?
    } else if &header == HEADER_V4 {
        read_wal_checkpoints(&mut io::BufReader::new(file), false)?
    } else {
        return Ok(HashSet::new());
    };
    Ok(checkpoints.into_keys().collect())
}

/// Unix timestamp of the most recent successfully installed snapshot.
///
/// The snapshot is written to a temporary file and atomically renamed into
/// place only after it has been flushed, so the final file's modification time
/// represents a completed save. A missing snapshot means the engine has not
/// completed a save yet.
pub(crate) fn last_save_unix_seconds(store: &Store) -> io::Result<Option<u64>> {
    let path = snapshot_path(store);
    let file = match crate::file_security::open_private_file(Path::new(&path), |options| {
        options.read(true);
    }) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let modified = file.metadata()?.modified()?;
    Ok(Some(
        modified
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    ))
}

fn snapshot_interval(store: &Store) -> Duration {
    store.config().save_interval
}

fn write_bytes(w: &mut impl Write, data: &[u8]) -> io::Result<()> {
    w.write_all(&(data.len() as u32).to_le_bytes())?;
    w.write_all(data)
}

fn write_u32(w: &mut impl Write, v: u32) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

fn write_i64(w: &mut impl Write, v: i64) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

fn write_u64(w: &mut impl Write, v: u64) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

fn write_f64(w: &mut impl Write, v: f64) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

// Fail-closed bounds for snapshot loading: a corrupt or hostile snapshot must
// not be able to drive a huge up-front allocation (OOM) from an attacker-chosen
// length prefix. These cap a single byte string and a single collection's item
// count; loads that exceed them are rejected as InvalidData (no panic, no OOM).
const MAX_SNAPSHOT_BYTES: usize = 512 * 1024 * 1024;
const MAX_SNAPSHOT_ITEMS: usize = 64 * 1024 * 1024;

// Upper bound on how many elements we pre-allocate from an untrusted collection
// count. The count is validated as a loop bound, but a corrupt snapshot can
// *claim* tens of millions of items in a few bytes; pre-allocating that count
// times the element size is a multi-GB OOM. Reserve modestly and let the vec
// grow as real elements are actually read (a short/corrupt input hits EOF and
// errors long before the vec grows).
const SNAPSHOT_PREALLOC_CAP: usize = 64 * 1024;

fn read_bytes(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let len = read_u32(r)? as usize;
    if len > MAX_SNAPSHOT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snapshot byte string length exceeds maximum",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Read a u32 collection length, bounded so a corrupt count can't drive a huge
/// `Vec::with_capacity`. `label` names the collection for the error message.
fn read_count(r: &mut impl Read, label: &str) -> io::Result<usize> {
    let count = read_u32(r)? as usize;
    if count > MAX_SNAPSHOT_ITEMS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("snapshot {label} count exceeds maximum"),
        ));
    }
    Ok(count)
}

/// Like `read_count` but also caps `count * item_size` against the byte budget,
/// for collections of fixed-size elements (vectors, HLL registers, TS samples).
fn read_sized_count(r: &mut impl Read, label: &str, item_size: usize) -> io::Result<usize> {
    let count = read_count(r, label)?;
    if count.saturating_mul(item_size) > MAX_SNAPSHOT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("snapshot {label} byte size exceeds maximum"),
        ));
    }
    Ok(count)
}

fn read_u32(r: &mut impl Read) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_i64(r: &mut impl Read) -> io::Result<i64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(i64::from_le_bytes(buf))
}

fn read_u64(r: &mut impl Read) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

fn read_f64(r: &mut impl Read) -> io::Result<f64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(f64::from_le_bytes(buf))
}

fn read_string(r: &mut impl Read) -> io::Result<String> {
    let raw = read_bytes(r)?;
    String::from_utf8(raw).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn save_entries_observed(
    store: &Store,
    entries: &[crate::store::DumpEntry],
    checkpoints: &[(String, crate::disk::WalCheckpoint)],
    on_phase: &dyn Fn(BackgroundSavePhase),
) -> io::Result<usize> {
    on_phase(BackgroundSavePhase::Writing);
    let path = snapshot_path(store);
    if let Some(parent) = Path::new(&path).parent() {
        crate::disk::create_dir_all_synced(parent)?;
    }
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let nonce = nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let tmp = format!("{path}.{}.{nonce}.tmp", std::process::id());
    let file = crate::file_security::open_private_file(Path::new(&tmp), |options| {
        options.create_new(true).write(true);
    })?;
    let file = match (|| {
        let mut writer = BufWriter::new(file);
        save_snapshot_binary(&mut writer, entries, store, checkpoints)?;
        let file = writer.into_inner().map_err(io::Error::other)?;
        file.sync_all()?;
        Ok::<_, io::Error>(file)
    })() {
        Ok(file) => file,
        Err(error) => {
            let _ = fs::remove_file(&tmp);
            return Err(error);
        }
    };
    #[cfg(test)]
    if let Err(error) = store.fail_snapshot_before_install_if_injected() {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    #[cfg(test)]
    if let Err(error) = fault_injection::check(fault_injection::Point::BeforeSnapshotRename) {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    on_phase(BackgroundSavePhase::Committing);
    if let Err(error) = crate::file_security::ensure_regular_or_missing(Path::new(&path)) {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    if let Err(error) = fs::rename(&tmp, &path) {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    crate::file_security::verify_installed_file(Path::new(&path), &file)?;
    #[cfg(test)]
    fault_injection::check(fault_injection::Point::AfterSnapshotRename)?;
    if let Some(parent) = Path::new(&path).parent() {
        crate::disk::sync_directory(parent)?;
    }
    Ok(entries.len())
}

#[cfg(test)]
fn save_entries(
    store: &Store,
    entries: &[crate::store::DumpEntry],
    checkpoints: &[(String, crate::disk::WalCheckpoint)],
) -> io::Result<usize> {
    save_entries_observed(store, entries, checkpoints, &|_| {})
}

fn save_and_truncate_wal_observed(
    store: &Store,
    on_phase: &dyn Fn(BackgroundSavePhase),
) -> io::Result<usize> {
    let _snapshot_guard = store.snapshot_guard();
    on_phase(BackgroundSavePhase::Capturing);
    let (entries, checkpoints) = store.with_write_barrier(|shards| {
        let now = Instant::now();
        let mut checkpoints = store.wal_checkpoints()?;
        if checkpoints.is_empty() {
            checkpoints.push(("global".to_string(), crate::disk::WalCheckpoint::detached()));
        }
        let entries = store.dump_all_from_locked_shards(shards, now)?;
        store.ensure_journal_healthy()?;
        Ok::<_, io::Error>((entries, checkpoints))
    })?;

    #[cfg(test)]
    store.run_snapshot_after_capture_hook();

    let saved = save_entries_observed(store, &entries, &checkpoints, on_phase)?;
    // A mutation can fail and poison the journal while snapshot bytes are
    // being written. Leave the old journal untouched in that case so restart
    // recovery, rather than an uncertain in-process state, remains authoritative.
    store.ensure_journal_healthy()?;
    on_phase(BackgroundSavePhase::Rotating);
    store.truncate_wal(&checkpoints)?;
    Ok(saved)
}

pub(crate) fn save_and_truncate_wal_consistent(store: &Store) -> io::Result<usize> {
    save_and_truncate_wal_observed(store, &|_| {})
}

/// Produce a consistent on-disk snapshot for an out-of-band backup and return
/// its path. Runs the same consistent save the background timer performs (full
/// dump including tiered cold data, then WAL truncation), so the file is a
/// complete point-in-time image of the instance. Used by `GET /v1/snapshot`,
/// which lets the control plane back an instance up over its own HTTP port
/// without needing a shell inside the (distroless) container.
#[cfg(test)]
pub(crate) fn snapshot_for_backup(store: &Store) -> io::Result<String> {
    save_and_truncate_wal_consistent(store)?;
    Ok(snapshot_path(store))
}

pub(crate) fn snapshot_for_backup_artifact(store: &Store) -> io::Result<BackupSnapshot> {
    save_and_truncate_wal_consistent(store)?;
    let path = PathBuf::from(snapshot_path(store));
    let mut file = crate::file_security::open_private_file(&path, |options| {
        options.read(true);
    })?;
    let format = snapshot_format(&mut file)?;
    file.seek(SeekFrom::Start(0))?;
    let sha256 = sha256_reader(&mut file)?;
    let len = file.metadata()?.len();
    file.seek(SeekFrom::Start(0))?;
    Ok(BackupSnapshot {
        file,
        len,
        sha256,
        format,
    })
}

pub(crate) fn authorized_global_successor(path: &Path) -> io::Result<Option<[u8; 16]>> {
    let mut file = crate::file_security::open_private_file(path, |options| {
        options.read(true);
    })?;
    let mut header = [0u8; 4];
    file.read_exact(&mut header)?;
    if &header != HEADER_V6 {
        return Ok(None);
    }
    let body_len = read_u64(&mut file)?;
    let mut expected_digest = [0u8; SNAPSHOT_DIGEST_LEN];
    file.read_exact(&mut expected_digest)?;
    verify_snapshot_body(&mut file, body_len, &expected_digest)?;
    let mut reader = io::BufReader::new(file.take(body_len));
    Ok(read_wal_checkpoints(&mut reader, true)?
        .remove("global")
        .and_then(|checkpoint| checkpoint.successor_generation))
}

fn sha256_reader(reader: &mut impl Read) -> io::Result<[u8; SNAPSHOT_DIGEST_LEN]> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

fn save_binary(
    w: &mut impl Write,
    entries: &[crate::store::DumpEntry],
    store: &Store,
) -> io::Result<()> {
    w.write_all(HEADER)?;
    save_binary_entries(w, entries, store)
}

fn save_snapshot_binary(
    w: &mut (impl Write + Seek),
    entries: &[crate::store::DumpEntry],
    store: &Store,
    checkpoints: &[(String, crate::disk::WalCheckpoint)],
) -> io::Result<()> {
    let count = u32::try_from(checkpoints.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many WAL checkpoints"))?;
    w.write_all(HEADER_V6)?;
    write_u64(w, 0)?;
    w.write_all(&[0u8; SNAPSHOT_DIGEST_LEN])?;

    let (body_len, digest) = {
        let mut body = SnapshotDigestWriter::new(w);
        write_u32(&mut body, count)?;
        for (name, checkpoint) in checkpoints {
            write_bytes(&mut body, name.as_bytes())?;
            body.write_all(&checkpoint.generation)?;
            write_u64(&mut body, checkpoint.offset)?;
            body.write_all(&checkpoint.successor_generation.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "new snapshots require an authorized successor WAL generation",
                )
            })?)?;
        }
        save_binary_entries(&mut body, entries, store)?;
        body.finish()
    };

    w.seek(SeekFrom::Start(HEADER_V6.len() as u64))?;
    write_u64(w, body_len)?;
    w.write_all(&digest)?;
    w.seek(SeekFrom::End(0))?;
    Ok(())
}

struct SnapshotDigestWriter<'a, W: Write> {
    inner: &'a mut W,
    hasher: Sha256,
    len: u64,
}

impl<'a, W: Write> SnapshotDigestWriter<'a, W> {
    fn new(inner: &'a mut W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            len: 0,
        }
    }

    fn finish(self) -> (u64, [u8; SNAPSHOT_DIGEST_LEN]) {
        (self.len, self.hasher.finalize().into())
    }
}

impl<W: Write> Write for SnapshotDigestWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.hasher.update(&buf[..written]);
        self.len = self.len.checked_add(written as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "snapshot length overflow")
        })?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn save_binary_entries(
    w: &mut impl Write,
    entries: &[crate::store::DumpEntry],
    store: &Store,
) -> io::Result<()> {
    for entry in entries {
        let type_byte: u8 = match &entry.value {
            DumpValue::Str(_) => b'S',
            DumpValue::List(_) => b'L',
            // 'h' carries a per-field TTL section; 'H' stays backward-compatible.
            DumpValue::Hash(_, e) if !e.is_empty() => b'h',
            DumpValue::Hash(_, _) => b'H',
            DumpValue::Set(_) => b'T',
            DumpValue::SortedSet(_) => b'Z',
            DumpValue::Stream(..) => b'X',
            DumpValue::Vector(_, _, true) => b'W',
            DumpValue::Vector(_, _, false) => b'V',
            DumpValue::HyperLogLog(..) => b'P',
            DumpValue::TimeSeries(..) => b'I',
        };
        w.write_all(&[type_byte])?;
        write_bytes(w, entry.key.as_bytes())?;
        // `entry.ttl_ms` is relative remaining-ms (computed at dump time, a few ms
        // ago). Persist an ABSOLUTE epoch-ms deadline so load can subtract elapsed
        // downtime; `-1` means no expiry.
        let ttl = if entry.ttl_ms > 0 {
            now_epoch_ms().saturating_add(entry.ttl_ms as u64) as i64
        } else {
            -1
        };
        write_i64(w, ttl)?;

        match &entry.value {
            DumpValue::Str(v) => {
                write_bytes(w, v)?;
            }
            DumpValue::List(items) => {
                write_u32(w, items.len() as u32)?;
                for item in items {
                    write_bytes(w, item)?;
                }
            }
            DumpValue::Hash(pairs, expiries) => {
                write_u32(w, pairs.len() as u32)?;
                for (k, v) in pairs {
                    write_bytes(w, k.as_bytes())?;
                    write_bytes(w, v)?;
                }
                // The per-field TTL section is present only under the 'h' type byte.
                if !expiries.is_empty() {
                    write_u32(w, expiries.len() as u32)?;
                    for (f, ms) in expiries {
                        write_bytes(w, f.as_bytes())?;
                        write_i64(w, *ms)?;
                    }
                }
            }
            DumpValue::Set(members) => {
                write_u32(w, members.len() as u32)?;
                for m in members {
                    write_bytes(w, m.as_bytes())?;
                }
            }
            DumpValue::SortedSet(members) => {
                write_u32(w, members.len() as u32)?;
                for (m, score) in members {
                    write_bytes(w, m.as_bytes())?;
                    write_f64(w, *score)?;
                }
            }
            DumpValue::Stream(stream_entries, last_id, groups) => {
                write_bytes(w, last_id.as_bytes())?;
                write_u32(w, stream_entries.len() as u32)?;
                for (id, fields) in stream_entries {
                    write_bytes(w, id.as_bytes())?;
                    write_u32(w, fields.len() as u32)?;
                    for (k, v) in fields {
                        write_bytes(w, k.as_bytes())?;
                        write_bytes(w, v)?;
                    }
                }
                write_u32(w, groups.len() as u32)?;
                for (name, last_delivered_id, consumers, pending) in groups {
                    write_bytes(w, name.as_bytes())?;
                    write_bytes(w, last_delivered_id.as_bytes())?;
                    write_u32(w, consumers.len() as u32)?;
                    for (consumer, pending_ids) in consumers {
                        write_bytes(w, consumer.as_bytes())?;
                        write_u32(w, pending_ids.len() as u32)?;
                        for id in pending_ids {
                            write_bytes(w, id.as_bytes())?;
                        }
                    }
                    write_u32(w, pending.len() as u32)?;
                    for (id, consumer, delivery_count) in pending {
                        write_bytes(w, id.as_bytes())?;
                        write_bytes(w, consumer.as_bytes())?;
                        write_u32(w, (*delivery_count).min(u32::MAX as u64) as u32)?;
                    }
                }
            }
            DumpValue::Vector(data, metadata, encrypted) => {
                if *encrypted {
                    // Seal the f32 payload; the 'W' type byte marks it encrypted.
                    let sealed = store
                        .encrypt_vector(entry.key.as_bytes(), data)
                        .map_err(io::Error::other)?;
                    write_bytes(w, &sealed)?;
                } else {
                    write_u32(w, data.len() as u32)?;
                    for f in data {
                        w.write_all(&f.to_le_bytes())?;
                    }
                }
                match metadata {
                    Some(m) => {
                        w.write_all(&[1u8])?;
                        write_bytes(w, m.as_bytes())?;
                    }
                    None => {
                        w.write_all(&[0u8])?;
                    }
                }
            }
            DumpValue::HyperLogLog(regs, _) => {
                write_u32(w, regs.len() as u32)?;
                w.write_all(regs)?;
            }
            DumpValue::TimeSeries(samples, retention, labels) => {
                write_u32(w, samples.len() as u32)?;
                for (ts, val) in samples {
                    write_i64(w, *ts)?;
                    write_f64(w, *val)?;
                }
                write_i64(w, *retention as i64)?;
                write_u32(w, labels.len() as u32)?;
                for (k, v) in labels {
                    write_bytes(w, k.as_bytes())?;
                    write_bytes(w, v.as_bytes())?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
pub fn load(store: &Store) -> io::Result<usize> {
    load_with_mode(store, false)
}

pub(crate) fn load_for_recovery(store: &Store) -> io::Result<usize> {
    load_with_mode(store, true)
}

fn load_with_mode(store: &Store, preserve_expired: bool) -> io::Result<usize> {
    let path_str = snapshot_path(store);
    let path = Path::new(&path_str);
    if !crate::file_security::regular_file_exists(path)? {
        return Ok(0);
    }
    let file = crate::file_security::open_private_file(path, |options| {
        options.read(true);
    })?;
    load_from_reader(store, file, preserve_expired)
}

fn snapshot_format(reader: &mut (impl Read + Seek)) -> io::Result<SnapshotFormat> {
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("restore payload has an incomplete Lux snapshot header: {error}"),
        )
    })?;
    match &header {
        value if value == HEADER_V1 => Ok(SnapshotFormat::V1),
        value if value == HEADER_V2 => Ok(SnapshotFormat::V2),
        value if value == HEADER => Ok(SnapshotFormat::V3),
        value if value == HEADER_V4 => Ok(SnapshotFormat::V4),
        value if value == HEADER_V5 => Ok(SnapshotFormat::V5),
        value if value == HEADER_V6 => Ok(SnapshotFormat::V6),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "restore payload is not a supported Lux snapshot",
        )),
    }
}

pub(crate) fn validate_restore_reader(
    store: &Store,
    mut file: impl Read + Seek,
) -> io::Result<(SnapshotFormat, usize)> {
    let format = snapshot_format(&mut file)?;
    let entries = match format {
        SnapshotFormat::V6 | SnapshotFormat::V5 => {
            let body_len = read_u64(&mut file)?;
            let mut expected_digest = [0u8; SNAPSHOT_DIGEST_LEN];
            file.read_exact(&mut expected_digest)?;
            verify_snapshot_body(&mut file, body_len, &expected_digest)?;
            let mut reader = io::BufReader::new(file.take(body_len));
            read_wal_checkpoints(&mut reader, format == SnapshotFormat::V6)?;
            parse_binary(store, &mut reader, true, true, false, false)?
        }
        SnapshotFormat::V4 => {
            let mut reader = io::BufReader::new(file);
            read_wal_checkpoints(&mut reader, false)?;
            parse_binary(store, &mut reader, true, true, false, false)?
        }
        SnapshotFormat::V3 => parse_binary(
            store,
            &mut io::BufReader::new(file),
            true,
            true,
            false,
            false,
        )?,
        SnapshotFormat::V2 => parse_binary(
            store,
            &mut io::BufReader::new(file),
            true,
            false,
            false,
            false,
        )?,
        SnapshotFormat::V1 => parse_binary(
            store,
            &mut io::BufReader::new(file),
            false,
            false,
            false,
            false,
        )?,
    };
    Ok((format, entries))
}

pub(crate) fn canonicalize_restore(
    store: &Store,
    mut source: impl Read + Seek,
    prepare: impl FnOnce(&Store) -> io::Result<()>,
) -> io::Result<(SnapshotFormat, usize, Vec<u8>)> {
    let source_format = snapshot_format(&mut source)?;
    source.seek(SeekFrom::Start(0))?;
    load_from_reader(store, source, false)?;
    prepare(store)?;
    let entries = store
        .with_write_barrier(|shards| store.dump_all_from_locked_shards(shards, Instant::now()))?;
    let checkpoints = [("global".to_string(), crate::disk::WalCheckpoint::detached())];
    let mut canonical = io::Cursor::new(Vec::new());
    save_snapshot_binary(&mut canonical, &entries, store, &checkpoints)?;
    Ok((source_format, entries.len(), canonical.into_inner()))
}

fn load_from_reader(
    store: &Store,
    mut file: impl Read + Seek,
    preserve_expired: bool,
) -> io::Result<usize> {
    let mut header = [0u8; 4];
    let n = file.read(&mut header)?;
    if n < header.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snapshot is truncated before its header",
        ));
    }
    if &header == HEADER_V6 {
        let body_len = read_u64(&mut file)?;
        let mut expected_digest = [0u8; SNAPSHOT_DIGEST_LEN];
        file.read_exact(&mut expected_digest)?;
        verify_snapshot_body(&mut file, body_len, &expected_digest)?;
        let mut reader = io::BufReader::new(file.take(body_len));
        let checkpoints = read_wal_checkpoints(&mut reader, true)?;
        store.set_recovery_wal_checkpoints(checkpoints);
        load_binary(store, &mut reader, true, true, preserve_expired)
    } else if &header == HEADER_V5 {
        let body_len = read_u64(&mut file)?;
        let mut expected_digest = [0u8; SNAPSHOT_DIGEST_LEN];
        file.read_exact(&mut expected_digest)?;
        verify_snapshot_body(&mut file, body_len, &expected_digest)?;
        let mut reader = io::BufReader::new(file.take(body_len));
        let checkpoints = read_wal_checkpoints(&mut reader, false)?;
        store.set_recovery_wal_checkpoints(checkpoints);
        load_binary(store, &mut reader, true, true, preserve_expired)
    } else if &header == HEADER_V4 {
        let mut reader = io::BufReader::new(file);
        let checkpoints = read_wal_checkpoints(&mut reader, false)?;
        store.set_recovery_wal_checkpoints(checkpoints);
        load_binary(store, &mut reader, true, true, preserve_expired)
    } else if &header == HEADER {
        // V3: absolute-deadline TTLs, stream groups present.
        store.set_recovery_wal_checkpoints(HashMap::new());
        load_binary(
            store,
            &mut io::BufReader::new(file),
            true,
            true,
            preserve_expired,
        )
    } else if &header == HEADER_V2 {
        // V2: relative remaining-ms TTLs (legacy; rebased to now on load).
        store.set_recovery_wal_checkpoints(HashMap::new());
        load_binary(
            store,
            &mut io::BufReader::new(file),
            true,
            false,
            preserve_expired,
        )
    } else if &header == HEADER_V1 {
        store.set_recovery_wal_checkpoints(HashMap::new());
        load_binary(
            store,
            &mut io::BufReader::new(file),
            false,
            false,
            preserve_expired,
        )
    } else {
        store.set_recovery_wal_checkpoints(HashMap::new());
        file.seek(SeekFrom::Start(0))?;
        load_legacy(store, file)
    }
}

fn verify_snapshot_body(
    file: &mut (impl Read + Seek),
    body_len: u64,
    expected_digest: &[u8; SNAPSHOT_DIGEST_LEN],
) -> io::Result<()> {
    let body_start = file.stream_position()?;
    let expected_end = body_start.checked_add(body_len).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "snapshot body length overflow")
    })?;
    let file_end = file.seek(SeekFrom::End(0))?;
    if expected_end != file_end {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snapshot body length does not match the file",
        ));
    }
    file.seek(SeekFrom::Start(body_start))?;

    let mut hasher = Sha256::new();
    let mut remaining = body_len;
    let mut buffer = [0u8; 64 * 1024];
    while remaining > 0 {
        let wanted = remaining.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..wanted])?;
        hasher.update(&buffer[..wanted]);
        remaining -= wanted as u64;
    }
    let actual: [u8; SNAPSHOT_DIGEST_LEN] = hasher.finalize().into();
    if actual != *expected_digest {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snapshot SHA-256 mismatch",
        ));
    }
    file.seek(SeekFrom::Start(body_start))?;
    Ok(())
}

fn read_wal_checkpoints(
    reader: &mut impl Read,
    has_successor: bool,
) -> io::Result<HashMap<String, crate::disk::WalCheckpoint>> {
    let count = read_u32(reader)? as usize;
    if count > MAX_WAL_CHECKPOINTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snapshot WAL checkpoint count exceeds maximum",
        ));
    }
    let mut checkpoints = HashMap::with_capacity(count);
    for _ in 0..count {
        let name = read_string(reader)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "snapshot contains an invalid WAL checkpoint name",
            ));
        }
        let mut current_generation = [0u8; 16];
        reader.read_exact(&mut current_generation)?;
        let checkpoint = crate::disk::WalCheckpoint {
            generation: current_generation,
            offset: read_u64(reader)?,
            successor_generation: if has_successor {
                let mut successor_generation = [0u8; 16];
                reader.read_exact(&mut successor_generation)?;
                if successor_generation == [0u8; 16] {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "snapshot contains a zero successor WAL generation",
                    ));
                }
                if successor_generation == current_generation {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "snapshot successor WAL generation repeats its current generation",
                    ));
                }
                Some(successor_generation)
            } else {
                None
            },
        };
        if checkpoints.insert(name, checkpoint).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "snapshot contains duplicate WAL checkpoints",
            ));
        }
    }
    if has_successor && !checkpoints.contains_key("global") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal-bound snapshot is missing the global WAL checkpoint",
        ));
    }
    Ok(checkpoints)
}

fn parse_binary(
    store: &Store,
    r: &mut impl Read,
    stream_groups: bool,
    absolute_ttl: bool,
    preserve_expired: bool,
    apply: bool,
) -> io::Result<usize> {
    let mut count = 0;
    loop {
        let mut type_buf = [0u8; 1];
        match r.read_exact(&mut type_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }

        let key = read_string(r)?;
        let ttl_ms = read_i64(r)?;
        // V3 stores an absolute epoch-ms deadline: subtract elapsed wall-clock so
        // downtime counts (a key whose deadline already passed is dropped, not
        // resurrected). V2/V1 stored relative remaining-ms (legacy rebase).
        let (ttl, expired) = if ttl_ms <= 0 {
            (None, false)
        } else if absolute_ttl {
            let remaining = ttl_ms.saturating_sub(now_epoch_ms() as i64);
            if remaining <= 0 {
                (None, true)
            } else {
                (Some(Duration::from_millis(remaining as u64)), false)
            }
        } else {
            (Some(Duration::from_millis(ttl_ms as u64)), false)
        };

        let value = read_dump_value(store, r, type_buf[0], &key, stream_groups)?;

        // The value bytes were read above to advance the stream; only store the
        // entry if its absolute deadline hasn't already passed during downtime.
        if !apply {
            count += 1;
        } else if expired && preserve_expired {
            store.stage_expired_recovery_entry(key, value);
            count += 1;
        } else if !expired {
            store.load_entry(key, value, ttl);
            count += 1;
        }
    }
    Ok(count)
}

pub(crate) fn load_binary(
    store: &Store,
    r: &mut impl Read,
    stream_groups: bool,
    absolute_ttl: bool,
    preserve_expired: bool,
) -> io::Result<usize> {
    parse_binary(
        store,
        r,
        stream_groups,
        absolute_ttl,
        preserve_expired,
        true,
    )
}

fn read_dump_value(
    store: &Store,
    r: &mut impl Read,
    type_byte: u8,
    key: &str,
    stream_groups: bool,
) -> io::Result<DumpValue> {
    Ok(match type_byte {
        b'S' => DumpValue::Str(read_bytes(r)?),
        b'L' => {
            let len = read_count(r, "list item")?;
            let mut items = Vec::with_capacity(len.min(SNAPSHOT_PREALLOC_CAP));
            for _ in 0..len {
                items.push(read_bytes(r)?);
            }
            DumpValue::List(items)
        }
        b'H' | b'h' => {
            let len = read_count(r, "hash field")?;
            let mut pairs = Vec::with_capacity(len.min(SNAPSHOT_PREALLOC_CAP));
            for _ in 0..len {
                let k = read_string(r)?;
                let v = read_bytes(r)?;
                pairs.push((k, v));
            }
            // 'h' appends a per-field TTL section (absolute epoch-ms deadlines).
            let expiries = if type_byte == b'h' {
                let elen = read_count(r, "hash field ttl")?;
                let mut e = Vec::with_capacity(elen.min(SNAPSHOT_PREALLOC_CAP));
                for _ in 0..elen {
                    let f = read_string(r)?;
                    let ms = read_i64(r)?;
                    e.push((f, ms));
                }
                e
            } else {
                Vec::new()
            };
            DumpValue::Hash(pairs, expiries)
        }
        b'T' => {
            let len = read_count(r, "set member")?;
            let mut members = Vec::with_capacity(len.min(SNAPSHOT_PREALLOC_CAP));
            for _ in 0..len {
                members.push(read_string(r)?);
            }
            DumpValue::Set(members)
        }
        b'Z' => {
            let len = read_count(r, "sorted set member")?;
            let mut members = Vec::with_capacity(len.min(SNAPSHOT_PREALLOC_CAP));
            for _ in 0..len {
                let m = read_string(r)?;
                let s = read_f64(r)?;
                members.push((m, s));
            }
            DumpValue::SortedSet(members)
        }
        b'X' => {
            let last_id = read_string(r)?;
            let entry_count = read_count(r, "stream entry")?;
            let mut entries = Vec::with_capacity(entry_count.min(SNAPSHOT_PREALLOC_CAP));
            for _ in 0..entry_count {
                let id = read_string(r)?;
                let field_count = read_count(r, "stream field")?;
                let mut fields = Vec::with_capacity(field_count.min(SNAPSHOT_PREALLOC_CAP));
                for _ in 0..field_count {
                    let k = read_string(r)?;
                    let v = read_bytes(r)?;
                    fields.push((k, v));
                }
                entries.push((id, fields));
            }
            let mut groups = Vec::new();
            if stream_groups {
                let group_count = read_count(r, "stream group")?;
                groups.reserve(group_count.min(SNAPSHOT_PREALLOC_CAP));
                for _ in 0..group_count {
                    let name = read_string(r)?;
                    let last_delivered_id = read_string(r)?;
                    let consumer_count = read_count(r, "stream consumer")?;
                    let mut consumers =
                        Vec::with_capacity(consumer_count.min(SNAPSHOT_PREALLOC_CAP));
                    for _ in 0..consumer_count {
                        let consumer = read_string(r)?;
                        let pending_count = read_count(r, "stream consumer pending")?;
                        let mut pending_ids =
                            Vec::with_capacity(pending_count.min(SNAPSHOT_PREALLOC_CAP));
                        for _ in 0..pending_count {
                            pending_ids.push(read_string(r)?);
                        }
                        consumers.push((consumer, pending_ids));
                    }
                    let pending_count = read_count(r, "stream group pending")?;
                    let mut pending = Vec::with_capacity(pending_count.min(SNAPSHOT_PREALLOC_CAP));
                    for _ in 0..pending_count {
                        let id = read_string(r)?;
                        let consumer = read_string(r)?;
                        let delivery_count = read_u32(r)? as u64;
                        pending.push((id, consumer, delivery_count));
                    }
                    groups.push((name, last_delivered_id, consumers, pending));
                }
            }
            DumpValue::Stream(entries, last_id, groups)
        }
        b'V' => {
            let dims = read_sized_count(r, "vector dimension", std::mem::size_of::<f32>())?;
            let mut data = Vec::with_capacity(dims.min(SNAPSHOT_PREALLOC_CAP));
            for _ in 0..dims {
                let mut buf = [0u8; 4];
                r.read_exact(&mut buf)?;
                data.push(f32::from_le_bytes(buf));
            }
            let mut flag = [0u8; 1];
            r.read_exact(&mut flag)?;
            let metadata = if flag[0] == 1 {
                Some(read_string(r)?)
            } else {
                None
            };
            DumpValue::Vector(data, metadata, false)
        }
        b'W' => {
            // Encrypted vector: sealed f32 payload, decrypted with the key.
            let sealed = read_bytes(r)?;
            let mut flag = [0u8; 1];
            r.read_exact(&mut flag)?;
            let metadata = if flag[0] == 1 {
                Some(read_string(r)?)
            } else {
                None
            };
            let data = store
                .decrypt_vector(key.as_bytes(), &sealed)
                .map_err(io::Error::other)?;
            DumpValue::Vector(data, metadata, true)
        }
        b'P' => {
            let len = read_sized_count(r, "hyperloglog register", 1)?;
            let mut regs = vec![0u8; len];
            r.read_exact(&mut regs)?;
            let cached = crate::hll::hll_count(&regs);
            DumpValue::HyperLogLog(regs, cached)
        }
        b'I' => {
            let sample_count = read_sized_count(
                r,
                "timeseries sample",
                std::mem::size_of::<i64>() + std::mem::size_of::<f64>(),
            )?;
            let mut samples = Vec::with_capacity(sample_count.min(SNAPSHOT_PREALLOC_CAP));
            for _ in 0..sample_count {
                let ts = read_i64(r)?;
                let val = read_f64(r)?;
                samples.push((ts, val));
            }
            let retention = read_i64(r)? as u64;
            let label_count = read_count(r, "timeseries label")?;
            let mut labels = Vec::with_capacity(label_count.min(SNAPSHOT_PREALLOC_CAP));
            for _ in 0..label_count {
                let k = read_string(r)?;
                let v = read_string(r)?;
                labels.push((k, v));
            }
            DumpValue::TimeSeries(samples, retention, labels)
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown type byte: {type_byte}"),
            ))
        }
    })
}

/// Decode a blob produced by `encode_dump_blob` and return its value plus the
/// embedded TTL (ms) WITHOUT loading it, so RESTORE can apply the value under a
/// caller-chosen key and TTL.
pub(crate) fn decode_dump_blob_value(store: &Store, blob: &[u8]) -> io::Result<(DumpValue, i64)> {
    let payload = verified_dump_payload(blob)?;
    let mut cursor = io::Cursor::new(payload);
    let mut header = [0u8; 4];
    cursor.read_exact(&mut header)?;
    let stream_groups = if &header == HEADER || &header == HEADER_V2 {
        true
    } else if &header == HEADER_V1 {
        false
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "RESTORE payload is not a lux dump",
        ));
    };
    let mut type_buf = [0u8; 1];
    cursor.read_exact(&mut type_buf)?;
    let key = read_string(&mut cursor)?;
    let ttl_ms = read_i64(&mut cursor)?;
    let value = read_dump_value(store, &mut cursor, type_buf[0], &key, stream_groups)?;
    Ok((value, ttl_ms))
}

/// Encode a single key/value into the on-disk snapshot format (header + one
/// entry). Used to record COPY as a resolved `LXRESTORE dst <blob>` so replay
/// reconstructs the exact destination without re-reading a mutable source key.
pub(crate) fn encode_dump_blob(
    store: &Store,
    entry: &crate::store::DumpEntry,
) -> io::Result<Vec<u8>> {
    let mut payload = Vec::new();
    save_binary(&mut payload, std::slice::from_ref(entry), store)?;
    let payload_len = u64::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DUMP payload is too large"))?;
    let digest: [u8; SNAPSHOT_DIGEST_LEN] = Sha256::digest(&payload).into();
    let mut blob = Vec::with_capacity(DUMP_HEADER.len() + 8 + SNAPSHOT_DIGEST_LEN + payload.len());
    blob.extend_from_slice(DUMP_HEADER);
    blob.extend_from_slice(&payload_len.to_le_bytes());
    blob.extend_from_slice(&digest);
    blob.extend_from_slice(&payload);
    Ok(blob)
}

fn verified_dump_payload(blob: &[u8]) -> io::Result<&[u8]> {
    if !blob.starts_with(DUMP_HEADER) {
        // V1-V3 blobs predate the integrity envelope and remain readable.
        return Ok(blob);
    }
    let metadata_len = DUMP_HEADER.len() + 8 + SNAPSHOT_DIGEST_LEN;
    if blob.len() < metadata_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated DUMP integrity envelope",
        ));
    }
    let payload_len = u64::from_le_bytes(
        blob[DUMP_HEADER.len()..DUMP_HEADER.len() + 8]
            .try_into()
            .unwrap(),
    );
    let payload_len = usize::try_from(payload_len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "DUMP payload is too large"))?;
    let expected_len = metadata_len.checked_add(payload_len).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "DUMP payload length overflow")
    })?;
    if blob.len() != expected_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DUMP payload length mismatch",
        ));
    }
    let expected_digest = &blob[DUMP_HEADER.len() + 8..metadata_len];
    let payload = &blob[metadata_len..];
    let actual_digest: [u8; SNAPSHOT_DIGEST_LEN] = Sha256::digest(payload).into();
    if actual_digest.as_slice() != expected_digest {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DUMP payload SHA-256 mismatch",
        ));
    }
    Ok(payload)
}

/// Decode a blob produced by `encode_dump_blob` and load its entry into the
/// store, overwriting any existing key. Replay path for `LXRESTORE`.
pub(crate) fn decode_dump_blob(store: &Store, blob: &[u8]) -> io::Result<usize> {
    let payload = verified_dump_payload(blob)?;
    let mut cursor = io::Cursor::new(payload);
    let mut header = [0u8; 4];
    cursor.read_exact(&mut header)?;
    if &header == HEADER {
        load_binary(store, &mut cursor, true, true, false)
    } else if &header == HEADER_V2 {
        load_binary(store, &mut cursor, true, false, false)
    } else if &header == HEADER_V1 {
        load_binary(store, &mut cursor, false, false, false)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "LXRESTORE payload is not a lux snapshot",
        ))
    }
}

fn load_legacy(store: &Store, file: impl Read) -> io::Result<usize> {
    let reader = io::BufReader::new(file);
    let mut count = 0;
    for line in reader.lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }

        if !line.contains('\t')
            || line.chars().next().is_none_or(|c| !"SLHTZX".contains(c))
            || line.chars().nth(1) != Some('\t')
        {
            let parts: Vec<&str> = line.splitn(3, '\t').collect();
            if parts.len() != 3 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed legacy snapshot row",
                ));
            }
            let key = parts[0].to_string();
            let value = parts[1].to_string();
            let ttl_ms: i64 = parts[2].parse().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid legacy snapshot TTL")
            })?;
            let ttl = if ttl_ms > 0 {
                Some(Duration::from_millis(ttl_ms as u64))
            } else {
                None
            };
            store.load_entry(key, DumpValue::Str(value.into_bytes()), ttl);
            count += 1;
            continue;
        }

        let parts: Vec<&str> = line.splitn(4, '\t').collect();
        if parts.len() != 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed typed legacy snapshot row",
            ));
        }
        let type_char = parts[0];
        let key = parts[1].to_string();
        let raw_value = parts[2];
        let ttl_ms: i64 = parts[3].parse().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid legacy snapshot TTL")
        })?;
        let ttl = if ttl_ms > 0 {
            Some(Duration::from_millis(ttl_ms as u64))
        } else {
            None
        };

        let value = match type_char {
            "S" => DumpValue::Str(raw_value.as_bytes().to_vec()),
            "L" => {
                let items: Vec<Vec<u8>> = if raw_value.is_empty() {
                    vec![]
                } else {
                    raw_value
                        .split('\x1f')
                        .map(|s| s.as_bytes().to_vec())
                        .collect()
                };
                DumpValue::List(items)
            }
            "H" => {
                let pairs: Vec<(String, Vec<u8>)> = if raw_value.is_empty() {
                    vec![]
                } else {
                    raw_value
                        .split('\x1f')
                        .map(|pair| {
                            let kv: Vec<&str> = pair.splitn(2, '\x1e').collect();
                            if kv.len() == 2 {
                                Ok((kv[0].to_string(), kv[1].as_bytes().to_vec()))
                            } else {
                                Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "malformed legacy hash field",
                                ))
                            }
                        })
                        .collect::<io::Result<_>>()?
                };
                DumpValue::Hash(pairs, Vec::new())
            }
            "T" => {
                let members: Vec<String> = if raw_value.is_empty() {
                    vec![]
                } else {
                    raw_value.split('\x1f').map(|s| s.to_string()).collect()
                };
                DumpValue::Set(members)
            }
            "Z" => {
                let members: Vec<(String, f64)> = if raw_value.is_empty() {
                    vec![]
                } else {
                    raw_value
                        .split('\x1f')
                        .map(|pair| {
                            let kv: Vec<&str> = pair.splitn(2, '\x1e').collect();
                            if kv.len() == 2 {
                                let score = kv[1].parse::<f64>().map_err(|_| {
                                    io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "invalid legacy sorted-set score",
                                    )
                                })?;
                                Ok((kv[0].to_string(), score))
                            } else {
                                Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "malformed legacy sorted-set member",
                                ))
                            }
                        })
                        .collect::<io::Result<_>>()?
                };
                DumpValue::SortedSet(members)
            }
            "X" => {
                let parts_x: Vec<&str> = raw_value.splitn(2, '\x1c').collect();
                let last_id_str = if !parts_x.is_empty() {
                    parts_x[0].to_string()
                } else {
                    "0-0".to_string()
                };
                let entries_raw = if parts_x.len() >= 2 { parts_x[1] } else { "" };
                let mut entries = Vec::new();
                if !entries_raw.is_empty() {
                    for entry_str in entries_raw.split('\x1f') {
                        let parts_e: Vec<&str> = entry_str.split('\x1d').collect();
                        if parts_e.is_empty()
                            || parts_e[0].is_empty()
                            || !(parts_e.len() - 1).is_multiple_of(2)
                        {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "malformed legacy stream entry",
                            ));
                        }
                        let id = parts_e[0].to_string();
                        let mut fields = Vec::new();
                        let mut fi = 1;
                        while fi + 1 < parts_e.len() {
                            fields.push((
                                parts_e[fi].to_string(),
                                parts_e[fi + 1].as_bytes().to_vec(),
                            ));
                            fi += 2;
                        }
                        entries.push((id, fields));
                    }
                }
                DumpValue::Stream(entries, last_id_str, Vec::new())
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unknown legacy snapshot type",
                ))
            }
        };

        store.load_entry(key, value, ttl);
        count += 1;
    }
    Ok(count)
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum SnapshotWorkerMessage {
    Save,
    Wake,
}

pub(crate) struct SnapshotWorker {
    sender: mpsc::SyncSender<SnapshotWorkerMessage>,
    stopping: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl SnapshotWorker {
    pub(crate) fn request_shutdown(&self, store: &Store) {
        store.stop_background_saves();
        self.stopping.store(true, Ordering::Release);
        let _ = self.sender.try_send(SnapshotWorkerMessage::Wake);
    }

    pub(crate) fn join(&mut self) -> io::Result<()> {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        thread
            .join()
            .map_err(|_| io::Error::other("background snapshot worker panicked"))
    }
}

impl Drop for SnapshotWorker {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        let _ = self.sender.try_send(SnapshotWorkerMessage::Wake);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(crate) fn start_background_save_worker(store: Arc<Store>) -> io::Result<SnapshotWorker> {
    // The status transition plus a single queue slot provides strict
    // single-flight behavior without accumulating stale save requests.
    let (sender, receiver) = mpsc::sync_channel(1);
    let stopping = Arc::new(AtomicBool::new(false));
    let thread_stopping = stopping.clone();
    let thread_store = store.clone();
    let thread = std::thread::Builder::new()
        .name("lux-snapshot".to_string())
        .spawn(move || background_save_worker(thread_store, receiver, thread_stopping))?;

    if let Err(error) = store.install_background_save_sender(sender.clone()) {
        stopping.store(true, Ordering::Release);
        let _ = sender.try_send(SnapshotWorkerMessage::Wake);
        let _ = thread.join();
        return Err(error);
    }

    Ok(SnapshotWorker {
        sender,
        stopping,
        thread: Some(thread),
    })
}

fn background_save_worker(
    store: Arc<Store>,
    receiver: mpsc::Receiver<SnapshotWorkerMessage>,
    stopping: Arc<AtomicBool>,
) {
    let interval = snapshot_interval(&store);
    let scheduled = store.config().durability.policy.is_persistent() && !interval.is_zero();

    loop {
        let message = if stopping.load(Ordering::Acquire) {
            receiver.try_recv().ok()
        } else if scheduled {
            match receiver.recv_timeout(interval) {
                Ok(message) => Some(message),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    Some(if store.begin_scheduled_background_save() {
                        SnapshotWorkerMessage::Save
                    } else {
                        SnapshotWorkerMessage::Wake
                    })
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => None,
            }
        } else {
            receiver.recv().ok()
        };
        let Some(message) = message else {
            store.set_background_save_phase(BackgroundSavePhase::Idle);
            break;
        };
        match message {
            SnapshotWorkerMessage::Wake => {
                if stopping.load(Ordering::Acquire) {
                    store.set_background_save_phase(BackgroundSavePhase::Idle);
                    break;
                }
                continue;
            }
            SnapshotWorkerMessage::Save => {}
        }

        let started = Instant::now();
        let result = save_and_truncate_wal_observed(&store, &|phase| {
            store.set_background_save_phase(phase);
        });
        store.finish_background_save(&result, started.elapsed());

        match result {
            Ok(keys) => crate::emit_info(
                store.config(),
                crate::ServerInfoEvent::SnapshotSaved { keys },
            ),
            Err(error) => crate::emit_error(
                store.config(),
                crate::ServerErrorEvent::SnapshotSaveFailed {
                    error: error.to_string(),
                    path: snapshot_path(&store),
                },
            ),
        }
    }
}

#[cfg(test)]
fn save_to_path(store: &Store, path: &str) -> io::Result<usize> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    let now = Instant::now();
    let entries = store.dump_all(now)?;
    let tmp = format!("{path}.tmp");
    let file = fs::File::create(&tmp)?;
    let mut w = BufWriter::new(file);
    save_binary(&mut w, &entries, store)?;
    w.into_inner().map_err(io::Error::other)?.sync_all()?;
    fs::rename(&tmp, path)?;
    Ok(entries.len())
}

#[cfg(test)]
fn load_from_path(store: &Store, path: &str) -> io::Result<usize> {
    let p = Path::new(path);
    if !p.exists() {
        return Ok(0);
    }
    let file = fs::File::open(p)?;
    load_from_reader(store, file, false)
}

#[cfg(test)]
fn save_legacy_to_path(store: &Store, path: &str) -> io::Result<usize> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    let now = Instant::now();
    let entries = store.dump_all(now)?;
    let tmp = format!("{path}.tmp");
    let mut file = fs::File::create(&tmp)?;
    for entry in &entries {
        let type_char = match &entry.value {
            DumpValue::Str(_) => 'S',
            DumpValue::List(_) => 'L',
            DumpValue::Hash(_, _) => 'H',
            DumpValue::Set(_) => 'T',
            DumpValue::SortedSet(_) => 'Z',
            DumpValue::Stream(..) => 'X',
            DumpValue::Vector(..) | DumpValue::HyperLogLog(..) | DumpValue::TimeSeries(..) => {
                continue
            }
        };
        let encoded_value = match &entry.value {
            DumpValue::Str(s) => String::from_utf8_lossy(s).into_owned(),
            DumpValue::List(items) => items
                .iter()
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .collect::<Vec<_>>()
                .join("\x1f"),
            DumpValue::Hash(pairs, _) => pairs
                .iter()
                .map(|(k, v)| format!("{}\x1e{}", k, String::from_utf8_lossy(v)))
                .collect::<Vec<_>>()
                .join("\x1f"),
            DumpValue::Set(members) => members.join("\x1f"),
            DumpValue::SortedSet(members) => members
                .iter()
                .map(|(m, s)| format!("{}\x1e{}", m, s))
                .collect::<Vec<_>>()
                .join("\x1f"),
            DumpValue::Stream(stream_entries, last_id, _groups) => {
                let entries_str: Vec<String> = stream_entries
                    .iter()
                    .map(|(id, fields)| {
                        let flds: Vec<String> = fields
                            .iter()
                            .map(|(k, v)| format!("{}\x1d{}", k, String::from_utf8_lossy(v)))
                            .collect();
                        format!("{}\x1d{}", id, flds.join("\x1d"))
                    })
                    .collect();
                format!("{}\x1c{}", last_id, entries_str.join("\x1f"))
            }
            DumpValue::Vector(..) | DumpValue::HyperLogLog(..) | DumpValue::TimeSeries(..) => {
                unreachable!()
            }
        };
        writeln!(
            file,
            "{}\t{}\t{}\t{}",
            type_char, entry.key, encoded_value, entry.ttl_ms
        )?;
    }
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    Ok(entries.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use std::sync::atomic::{AtomicU32, Ordering};
    static TEST_ID: AtomicU32 = AtomicU32::new(0);

    fn test_path() -> (String, impl Drop) {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("lux_snap_test_{}_{}", std::process::id(), id));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lux.dat").to_str().unwrap().to_string();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        (path, Cleanup(dir))
    }

    #[test]
    fn roundtrip_strings() {
        let (path, _g) = test_path();
        let store = Store::new();
        let now = Instant::now();
        store.set(b"hello", b"world", None, now);
        store.set(b"num", b"42", None, now);
        assert_eq!(save_to_path(&store, &path).unwrap(), 2);
        let store2 = Store::new();
        assert_eq!(load_from_path(&store2, &path).unwrap(), 2);
        assert_eq!(store2.get(b"hello", Instant::now()).unwrap(), &b"world"[..]);
        assert_eq!(store2.get(b"num", Instant::now()).unwrap(), &b"42"[..]);
    }

    #[test]
    fn last_save_time_only_reports_an_installed_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::ServerConfig {
            data_dir: dir.path().to_string_lossy().into_owned(),
            ..Default::default()
        });
        let store = Store::new_with_config(config);

        assert_eq!(last_save_unix_seconds(&store).unwrap(), None);
        store.set(b"saved", b"value", None, Instant::now());
        save_and_truncate_wal_consistent(&store).unwrap();

        assert!(last_save_unix_seconds(&store).unwrap().is_some());
    }

    #[test]
    fn snapshot_waits_for_in_flight_journal_commit_before_truncating() {
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::ServerConfig {
            data_dir: dir.path().to_string_lossy().into_owned(),
            durability: crate::DurabilityConfig {
                policy: crate::DurabilityPolicy::AlwaysSync,
                ..Default::default()
            },
            ..Default::default()
        });
        let store = Arc::new(Store::new_with_config(config.clone()));
        let command: [&[u8]; 3] = [b"SET", b"snapshot-race", b"durable"];
        let prepared = store.prepare_journaled(&command).unwrap();

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let snapshot_store = store.clone();
        let snapshot_thread = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            done_tx
                .send(save_and_truncate_wal_consistent(&snapshot_store))
                .unwrap();
        });
        started_rx.recv().unwrap();
        assert!(
            done_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "snapshot crossed an in-flight journal mutation"
        );

        let commit = prepared.commit(&command).unwrap();
        store.set(b"snapshot-race", b"durable", None, Instant::now());
        commit.complete().unwrap();
        done_rx.recv().unwrap().unwrap();
        snapshot_thread.join().unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(Path::new(&config.data_dir).join("lux.dat"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        let recovered = Store::new_with_config(config);
        assert_eq!(load(&recovered).unwrap(), 1);
        recovered.replay_wal(&crate::pubsub::Broker::new()).unwrap();
        assert_eq!(
            recovered.get(b"snapshot-race", Instant::now()).unwrap(),
            &b"durable"[..]
        );
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_load_rejects_symlink_without_reading_target() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"not-a-snapshot").unwrap();
        symlink(&target, dir.path().join("lux.dat")).unwrap();
        let config = Arc::new(crate::ServerConfig {
            data_dir: dir.path().to_string_lossy().into_owned(),
            durability: crate::DurabilityConfig {
                policy: crate::DurabilityPolicy::Ephemeral,
                ..Default::default()
            },
            ..Default::default()
        });
        let store = Store::new_with_config(config);

        let error = load(&store).unwrap_err();
        assert!(error.to_string().contains("symbolic links"), "{error}");
        assert_eq!(fs::read(target).unwrap(), b"not-a-snapshot");
    }

    #[cfg(unix)]
    #[test]
    fn journal_aware_probe_rejects_snapshot_symlink() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, HEADER_V6).unwrap();
        symlink(&target, dir.path().join("lux.dat")).unwrap();
        let config = crate::ServerConfig {
            data_dir: dir.path().to_string_lossy().into_owned(),
            ..Default::default()
        };

        let error = required_existing_journals(&config).unwrap_err();
        assert!(error.to_string().contains("symbolic links"), "{error}");
        assert_eq!(fs::read(target).unwrap(), HEADER_V6);
    }

    #[test]
    fn tiered_snapshot_read_failure_preserves_the_journal() {
        let (store, data_dir, _guard) = store_in_temp_dir(crate::StorageMode::Tiered);
        let key = b"cold-durable";
        let command: [&[u8]; 3] = [b"SET", key, b"value"];
        store
            .commit_journaled(&command, || store.set(key, b"value", None, Instant::now()))
            .unwrap();
        assert!(store.evict_key(store.shard_index(key), key));

        let journal_path = Path::new(&store.config().storage.dir).join("global/wal.lux");
        let journal_before = fs::read(&journal_path).unwrap();
        let cold_path = fs::read_dir(&store.config().storage.dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path().join("data.lux"))
            .find(|path| fs::metadata(path).is_ok_and(|metadata| metadata.len() > 8))
            .expect("evicted key must have a cold data file");

        let mut cold_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&cold_path)
            .unwrap();
        cold_file.seek(SeekFrom::Start(8)).unwrap();
        let mut checksum_byte = [0u8; 1];
        cold_file.read_exact(&mut checksum_byte).unwrap();
        cold_file.seek(SeekFrom::Start(8)).unwrap();
        cold_file.write_all(&[checksum_byte[0] ^ 0xff]).unwrap();
        cold_file.sync_all().unwrap();

        assert!(store.try_promote(key, Instant::now()).is_err());
        assert!(
            store.disk_contains(key),
            "a failed cold read must retain the authoritative disk index entry"
        );
        let cache =
            std::sync::Arc::new(parking_lot::RwLock::new(crate::tables::SchemaCache::new()));
        let mut reply = bytes::BytesMut::new();
        crate::cmd::execute_with_wal(
            &store,
            &cache,
            &crate::pubsub::Broker::new(),
            &[b"GET", key],
            &mut reply,
            Instant::now(),
        );
        assert!(
            String::from_utf8_lossy(&reply).contains("cold storage read failed"),
            "a corrupt cold key must fail explicitly, not appear missing: {:?}",
            String::from_utf8_lossy(&reply)
        );

        let error = save_and_truncate_wal_consistent(&store)
            .expect_err("a corrupt cold entry must abort the snapshot");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!data_dir.join("lux.dat").exists());
        assert_eq!(fs::read(&journal_path).unwrap(), journal_before);

        drop(store);
        let config = Arc::new(crate::ServerConfig {
            data_dir: data_dir.to_string_lossy().into_owned(),
            storage: crate::StorageConfig {
                mode: crate::StorageMode::Tiered,
                dir: data_dir.join("storage").to_string_lossy().into_owned(),
            },
            ..Default::default()
        });
        let recovered = Store::new_with_config(config);
        load_for_recovery(&recovered).unwrap();
        recovered.replay_wal(&crate::pubsub::Broker::new()).unwrap();
        assert_eq!(recovered.get(key, Instant::now()).unwrap(), &b"value"[..]);
    }

    #[test]
    fn installed_snapshot_does_not_replay_its_included_journal_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::ServerConfig {
            data_dir: dir.path().to_string_lossy().into_owned(),
            durability: crate::DurabilityConfig {
                policy: crate::DurabilityPolicy::AlwaysSync,
                ..Default::default()
            },
            ..Default::default()
        });
        let store = Store::new_with_config(config.clone());
        let command: [&[u8]; 2] = [b"INCR", b"snapshot-counter"];
        for _ in 0..3 {
            store
                .commit_journaled(&command, || {
                    store.incr(b"snapshot-counter", 1, Instant::now())
                })
                .unwrap()
                .unwrap();
        }

        // Model a kill after the snapshot rename but before journal rotation:
        // install the complete snapshot while deliberately leaving its source
        // frames in place.
        store
            .with_write_barrier(|shards| {
                let checkpoints = store.wal_checkpoints()?;
                let entries = store.dump_all_from_locked_shards(shards, Instant::now())?;
                save_entries(&store, &entries, &checkpoints)
            })
            .unwrap();
        drop(store);

        let recovered = Store::new_with_config(config);
        load_for_recovery(&recovered).unwrap();
        recovered.replay_wal(&crate::pubsub::Broker::new()).unwrap();
        assert_eq!(
            recovered.get(b"snapshot-counter", Instant::now()).unwrap(),
            b"3".as_slice(),
            "journal frames already represented by the installed snapshot must be skipped"
        );
    }

    #[test]
    fn rotated_journal_replays_only_post_snapshot_generation() {
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::ServerConfig {
            data_dir: dir.path().to_string_lossy().into_owned(),
            durability: crate::DurabilityConfig {
                policy: crate::DurabilityPolicy::AlwaysSync,
                ..Default::default()
            },
            ..Default::default()
        });
        let store = Store::new_with_config(config.clone());
        let command: [&[u8]; 2] = [b"INCR", b"rotated-counter"];
        for _ in 0..3 {
            store
                .commit_journaled(&command, || {
                    store.incr(b"rotated-counter", 1, Instant::now())
                })
                .unwrap()
                .unwrap();
        }
        save_and_truncate_wal_consistent(&store).unwrap();
        for _ in 0..2 {
            store
                .commit_journaled(&command, || {
                    store.incr(b"rotated-counter", 1, Instant::now())
                })
                .unwrap()
                .unwrap();
        }
        drop(store);

        let recovered = Store::new_with_config(config);
        load_for_recovery(&recovered).unwrap();
        recovered.replay_wal(&crate::pubsub::Broker::new()).unwrap();
        assert_eq!(
            recovered.get(b"rotated-counter", Instant::now()).unwrap(),
            b"5".as_slice()
        );
    }

    #[test]
    fn partially_rotated_journals_recover_each_stream_independently() {
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::ServerConfig {
            data_dir: dir.path().to_string_lossy().into_owned(),
            storage: crate::StorageConfig {
                mode: crate::StorageMode::Tiered,
                dir: dir.path().to_string_lossy().into_owned(),
            },
            durability: crate::DurabilityConfig {
                policy: crate::DurabilityPolicy::AlwaysSync,
                ..Default::default()
            },
            ..Default::default()
        });
        {
            let mut legacy = crate::disk::Wal::open(dir.path(), 0).unwrap();
            legacy
                .append_command(&[b"INCR", b"legacy-counter"])
                .unwrap();
            legacy
                .append_command(&[b"INCR", b"legacy-counter"])
                .unwrap();
            legacy.fsync().unwrap();
        }

        let store = Store::new_with_config(config.clone());
        store.replay_wal(&crate::pubsub::Broker::new()).unwrap();
        let global: [&[u8]; 2] = [b"INCR", b"global-counter"];
        for _ in 0..3 {
            store
                .commit_journaled(&global, || store.incr(b"global-counter", 1, Instant::now()))
                .unwrap()
                .unwrap();
        }
        let checkpoints = store
            .with_write_barrier(|shards| -> io::Result<_> {
                let checkpoints = store.wal_checkpoints()?;
                let entries = store.dump_all_from_locked_shards(shards, Instant::now())?;
                save_entries(&store, &entries, &checkpoints)?;
                Ok(checkpoints)
            })
            .unwrap();
        drop(store);

        // Model a crash after only the legacy stream rotated. Its new command
        // must replay in full, while the unrotated global prefix must be skipped.
        {
            let mut legacy = crate::disk::Wal::open(dir.path(), 0).unwrap();
            let checkpoint = checkpoints
                .iter()
                .find(|(name, _)| name == "shard_0")
                .map(|(_, checkpoint)| *checkpoint)
                .unwrap();
            legacy.rotate_after(checkpoint).unwrap();
            legacy
                .append_command(&[b"INCR", b"legacy-counter"])
                .unwrap();
            legacy.fsync().unwrap();
        }

        let recovered = Store::new_with_config(config);
        load_for_recovery(&recovered).unwrap();
        recovered.replay_wal(&crate::pubsub::Broker::new()).unwrap();
        assert_eq!(
            recovered.get(b"legacy-counter", Instant::now()).unwrap(),
            b"3".as_slice()
        );
        assert_eq!(
            recovered.get(b"global-counter", Instant::now()).unwrap(),
            b"3".as_slice()
        );
    }

    #[derive(Clone, Copy, Debug)]
    enum SaveFailurePoint {
        Snapshot(fault_injection::Point),
        Journal(crate::disk::fault_injection::Point),
    }

    fn commit_counter(store: &Store, key: &[u8], count: usize) {
        let command: [&[u8]; 2] = [b"INCR", key];
        for _ in 0..count {
            store
                .commit_journaled(&command, || store.incr(key, 1, Instant::now()))
                .unwrap()
                .unwrap();
        }
    }

    fn assert_counter_recovers(config: Arc<crate::ServerConfig>, key: &[u8], expected: &[u8]) {
        let recovered = Store::try_new_with_config(config).unwrap();
        load_for_recovery(&recovered).unwrap();
        recovered.replay_wal(&crate::pubsub::Broker::new()).unwrap();
        assert_eq!(recovered.get(key, Instant::now()).unwrap(), expected);
    }

    #[test]
    fn every_snapshot_and_rotation_failure_state_recovers_exactly() {
        let cases = [
            SaveFailurePoint::Snapshot(fault_injection::Point::BeforeSnapshotRename),
            SaveFailurePoint::Snapshot(fault_injection::Point::AfterSnapshotRename),
            SaveFailurePoint::Journal(crate::disk::fault_injection::Point::BeforeRotateRename),
            SaveFailurePoint::Journal(crate::disk::fault_injection::Point::AfterRotateRename),
        ];

        for (index, point) in cases.into_iter().enumerate() {
            let dir = tempfile::tempdir().unwrap();
            let config = Arc::new(crate::ServerConfig {
                data_dir: dir.path().to_string_lossy().into_owned(),
                durability: crate::DurabilityConfig {
                    policy: crate::DurabilityPolicy::AlwaysSync,
                    ..Default::default()
                },
                ..Default::default()
            });
            let store = Store::try_new_with_config(config.clone()).unwrap();
            let key = format!("failure-state-{index}");
            commit_counter(&store, key.as_bytes(), 3);
            save_and_truncate_wal_consistent(&store).unwrap();
            commit_counter(&store, key.as_bytes(), 2);

            let result = match point {
                SaveFailurePoint::Snapshot(point) => {
                    let _fault = fault_injection::inject(point);
                    save_and_truncate_wal_consistent(&store)
                }
                SaveFailurePoint::Journal(point) => {
                    let _fault = crate::disk::fault_injection::inject(point);
                    save_and_truncate_wal_consistent(&store)
                }
            };
            assert!(result.is_err(), "fault {point:?} did not interrupt SAVE");

            let late_command: [&[u8]; 2] = [b"INCR", key.as_bytes()];
            let late_write = store.commit_journaled(&late_command, || {
                store.incr(key.as_bytes(), 1, Instant::now())
            });
            let expected = match point {
                SaveFailurePoint::Snapshot(_) => {
                    late_write
                        .expect("snapshot installation failures leave the journal writable")
                        .unwrap();
                    b"6".as_slice()
                }
                SaveFailurePoint::Journal(_) => {
                    assert!(
                        late_write.is_err(),
                        "a failed journal rotation must fence later writes"
                    );
                    b"5".as_slice()
                }
            };

            drop(store);
            assert_counter_recovers(config, key.as_bytes(), expected);
        }
    }

    #[test]
    fn failed_snapshot_rename_cleans_its_temporary_file() {
        let (store, data_dir, _guard) = store_in_temp_dir(crate::StorageMode::Memory);
        commit_counter(&store, b"tmp-cleanup", 1);
        let _fault = fault_injection::inject(fault_injection::Point::BeforeSnapshotRename);
        assert!(save_and_truncate_wal_consistent(&store).is_err());
        let leftovers: Vec<_> = fs::read_dir(data_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "failed SAVE left {leftovers:?}");
    }

    #[test]
    fn operating_system_snapshot_rename_failure_cleans_its_temporary_file() {
        let (store, data_dir, _guard) = store_in_temp_dir(crate::StorageMode::Memory);
        commit_counter(&store, b"rename-cleanup", 1);
        fs::create_dir(data_dir.join("lux.dat")).unwrap();

        let error = save_and_truncate_wal_consistent(&store)
            .expect_err("renaming a snapshot over a directory must fail");
        assert_ne!(error.kind(), io::ErrorKind::NotFound);
        let leftovers: Vec<_> = fs::read_dir(&data_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "failed SAVE left {leftovers:?}");
        assert!(data_dir.join("lux.dat").is_dir());
    }

    #[test]
    fn truncated_snapshot_header_blocks_journal_initialization() {
        let dir = tempfile::tempdir().unwrap();
        let config = crate::ServerConfig {
            data_dir: dir.path().to_string_lossy().into_owned(),
            ..Default::default()
        };
        fs::write(dir.path().join("lux.dat"), b"LUX").unwrap();

        let error = required_existing_journals(&config)
            .expect_err("a corrupt snapshot must fail before journal initialization");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_open_errors_propagate_before_journal_creation() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let config = crate::ServerConfig {
            data_dir: dir.path().to_string_lossy().into_owned(),
            ..Default::default()
        };
        symlink("lux.dat", dir.path().join("lux.dat")).unwrap();

        let error = required_existing_journals(&config)
            .expect_err("an unreadable snapshot path must not be treated as absent");
        assert_ne!(error.kind(), io::ErrorKind::NotFound);
    }

    fn legacy_snapshot_with_checkpoints(
        header: &[u8; 4],
        checkpoints: &[(String, crate::disk::WalCheckpoint)],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        write_u32(&mut body, checkpoints.len() as u32).unwrap();
        for (name, checkpoint) in checkpoints {
            write_bytes(&mut body, name.as_bytes()).unwrap();
            body.extend_from_slice(&checkpoint.generation);
            write_u64(&mut body, checkpoint.offset).unwrap();
        }

        if header == HEADER_V4 {
            [header.as_slice(), body.as_slice()].concat()
        } else {
            let mut snapshot = header.to_vec();
            snapshot.extend_from_slice(&(body.len() as u64).to_le_bytes());
            snapshot.extend_from_slice(&Sha256::digest(&body));
            snapshot.extend_from_slice(&body);
            snapshot
        }
    }

    #[test]
    fn legacy_snapshot_inventory_distinguishes_pre_global_formats() {
        let unbound_dir = tempfile::tempdir().unwrap();
        let unbound_config = crate::ServerConfig {
            data_dir: unbound_dir.path().to_string_lossy().into_owned(),
            ..Default::default()
        };
        fs::write(unbound_dir.path().join("lux.dat"), HEADER).unwrap();
        assert!(required_existing_journals(&unbound_config)
            .unwrap()
            .is_empty());

        let checkpoint = crate::disk::WalCheckpoint {
            generation: [1; 16],
            offset: 42,
            successor_generation: None,
        };
        for header in [HEADER_V4, HEADER_V5] {
            for (checkpoints, expected) in [
                (Vec::new(), Vec::new()),
                (vec![("shard_0".to_string(), checkpoint)], vec!["shard_0"]),
                (vec![("global".to_string(), checkpoint)], vec!["global"]),
            ] {
                let dir = tempfile::tempdir().unwrap();
                let config = crate::ServerConfig {
                    data_dir: dir.path().to_string_lossy().into_owned(),
                    ..Default::default()
                };
                fs::write(
                    dir.path().join("lux.dat"),
                    legacy_snapshot_with_checkpoints(header, &checkpoints),
                )
                .unwrap();

                let actual = required_existing_journals(&config).unwrap();
                assert_eq!(actual.len(), expected.len());
                for name in expected {
                    assert!(actual.contains(name));
                }
            }
        }
    }

    #[test]
    fn pre_global_snapshot_upgrades_without_losing_legacy_journal_writes() {
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::ServerConfig {
            data_dir: dir.path().to_string_lossy().into_owned(),
            durability: crate::DurabilityConfig {
                policy: crate::DurabilityPolicy::AlwaysSync,
                ..Default::default()
            },
            ..Default::default()
        });
        let mut legacy = crate::disk::Wal::open(&config.journal_dir(), 0).unwrap();
        let checkpoint = legacy.checkpoint().unwrap();
        legacy
            .append_command(&[b"SET", b"legacy-upgrade", b"preserved"])
            .unwrap();
        legacy.fsync().unwrap();
        drop(legacy);
        fs::write(
            dir.path().join("lux.dat"),
            legacy_snapshot_with_checkpoints(HEADER_V4, &[("shard_0".to_string(), checkpoint)]),
        )
        .unwrap();

        let store = Store::try_new_with_config(config.clone()).unwrap();
        assert_eq!(load_for_recovery(&store).unwrap(), 0);
        store.replay_wal(&crate::pubsub::Broker::new()).unwrap();
        assert_eq!(
            store.get(b"legacy-upgrade", Instant::now()).unwrap(),
            b"preserved".as_slice()
        );
        assert!(config.journal_dir().join("global/wal.lux").is_file());
    }

    #[test]
    fn missing_checkpointed_legacy_journal_fails_before_global_creation() {
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::ServerConfig {
            data_dir: dir.path().to_string_lossy().into_owned(),
            durability: crate::DurabilityConfig {
                policy: crate::DurabilityPolicy::AlwaysSync,
                ..Default::default()
            },
            ..Default::default()
        });
        let checkpoint = crate::disk::WalCheckpoint {
            generation: [1; 16],
            offset: 42,
            successor_generation: None,
        };
        fs::write(
            dir.path().join("lux.dat"),
            legacy_snapshot_with_checkpoints(HEADER_V4, &[("shard_0".to_string(), checkpoint)]),
        )
        .unwrap();

        let error = Store::try_new_with_config(config.clone())
            .err()
            .expect("a snapshot-recorded legacy journal must not be ignored");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!config.journal_dir().join("global").exists());
    }

    #[test]
    fn v6_writer_requires_an_authorized_successor_generation() {
        let (store, _data_dir, _guard) = store_in_temp_dir(crate::StorageMode::Memory);
        let checkpoint = crate::disk::WalCheckpoint {
            generation: [1; 16],
            offset: 0,
            successor_generation: None,
        };
        let mut output = io::Cursor::new(Vec::new());

        let error = save_snapshot_binary(
            &mut output,
            &[],
            &store,
            &[("global".to_string(), checkpoint)],
        )
        .expect_err("V6 must not serialize an unbound checkpoint");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn v6_reader_rejects_zero_and_repeated_successor_generations() {
        let current = [1; 16];
        for successor in [[0; 16], current] {
            let mut body = Vec::new();
            write_u32(&mut body, 1).unwrap();
            write_bytes(&mut body, b"global").unwrap();
            body.extend_from_slice(&current);
            write_u64(&mut body, 0).unwrap();
            body.extend_from_slice(&successor);

            let error = read_wal_checkpoints(&mut io::Cursor::new(body), true)
                .expect_err("an invalid successor generation must fail closed");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn legacy_checkpoint_reader_preserves_the_unbound_format() {
        let current = [1; 16];
        let mut body = Vec::new();
        write_u32(&mut body, 1).unwrap();
        write_bytes(&mut body, b"global").unwrap();
        body.extend_from_slice(&current);
        write_u64(&mut body, 42).unwrap();

        let checkpoints = read_wal_checkpoints(&mut io::Cursor::new(body), false).unwrap();
        let checkpoint = checkpoints.get("global").unwrap();
        assert_eq!(checkpoint.generation, current);
        assert_eq!(checkpoint.offset, 42);
        assert_eq!(checkpoint.successor_generation, None);
    }

    #[test]
    fn malformed_v4_checkpoint_metadata_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad-checkpoints.lux");
        let mut bytes = HEADER_V4.to_vec();
        bytes.extend_from_slice(&((MAX_WAL_CHECKPOINTS as u32) + 1).to_le_bytes());
        fs::write(&path, bytes).unwrap();
        let store = Store::new();
        let error = load_from_reader(&store, fs::File::open(path).unwrap(), false)
            .expect_err("oversized checkpoint metadata must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn v6_snapshot_rejects_every_truncation_and_bit_flip_before_loading() {
        let (store, data_dir, _guard) = store_in_temp_dir(crate::StorageMode::Memory);
        for (key, value) in [
            (b"first".as_slice(), b"one".as_slice()),
            (b"second", b"two"),
        ] {
            let command: [&[u8]; 3] = [b"SET", key, value];
            store
                .commit_journaled(&command, || store.set(key, value, None, Instant::now()))
                .unwrap();
        }
        save_and_truncate_wal_consistent(&store).unwrap();
        let snapshot = fs::read(data_dir.join("lux.dat")).unwrap();
        assert_eq!(&snapshot[..HEADER_V6.len()], HEADER_V6);
        drop(store);

        let restored = Store::new();
        assert_eq!(
            load_from_reader(&restored, io::Cursor::new(&snapshot), false).unwrap(),
            2
        );
        assert_eq!(restored.get(b"first", Instant::now()).unwrap(), &b"one"[..]);
        assert_eq!(
            restored.get(b"second", Instant::now()).unwrap(),
            &b"two"[..]
        );

        for end in 0..snapshot.len() {
            let candidate = Store::new();
            assert!(
                load_from_reader(&candidate, io::Cursor::new(&snapshot[..end]), false).is_err(),
                "truncation at byte {end} was accepted"
            );
        }
        for offset in 0..snapshot.len() {
            let mut corrupted = snapshot.clone();
            corrupted[offset] ^= 0x01;
            let candidate = Store::new();
            assert!(
                load_from_reader(&candidate, io::Cursor::new(corrupted), false).is_err(),
                "bit flip at byte {offset} was accepted"
            );
            assert!(candidate.get(b"first", Instant::now()).is_none());
        }
    }

    #[test]
    fn encrypted_v6_snapshot_validates_with_the_configured_keyring() {
        let (store, data_dir, _guard) = store_in_temp_dir(crate::StorageMode::Memory);
        store.encryption().init(Some("snapshot-key")).unwrap();
        let command: [&[u8]; 7] = [
            b"VSET",
            b"secret-vector",
            b"2",
            b"1.25",
            b"-2.5",
            b"META",
            b"classified",
        ];
        store
            .commit_journaled(&command, || {
                store.vset(
                    b"secret-vector",
                    vec![1.25, -2.5],
                    Some("classified".to_string()),
                    None,
                    true,
                    Instant::now(),
                )
            })
            .unwrap();
        save_and_truncate_wal_consistent(&store).unwrap();
        let snapshot = fs::read(data_dir.join("lux.dat")).unwrap();
        assert_eq!(&snapshot[..HEADER_V6.len()], HEADER_V6);

        assert_eq!(
            validate_restore_reader(&store, io::Cursor::new(snapshot)).unwrap(),
            (SnapshotFormat::V6, 1)
        );
    }

    #[test]
    fn checksummed_dump_rejects_every_truncation_and_single_bit_flip() {
        let store = Store::new();
        store.set(b"key", b"value", None, Instant::now());
        let blob = store.dump_key(b"key", Instant::now()).unwrap().unwrap();
        assert!(blob.starts_with(DUMP_HEADER));
        let (value, _) = decode_dump_blob_value(&store, &blob).unwrap();
        assert!(matches!(value, DumpValue::Str(value) if value == b"value"));

        for end in 0..blob.len() {
            assert!(
                decode_dump_blob_value(&store, &blob[..end]).is_err(),
                "DUMP truncation at byte {end} was accepted"
            );
        }
        for offset in 0..blob.len() {
            for bit in 0..8 {
                let mut corrupted = blob.clone();
                corrupted[offset] ^= 1 << bit;
                assert!(
                    decode_dump_blob_value(&store, &corrupted).is_err(),
                    "DUMP bit {bit} at byte {offset} was accepted"
                );
            }
        }
    }

    #[test]
    fn roundtrip_lists() {
        let (path, _g) = test_path();
        let store = Store::new();
        let now = Instant::now();
        store.rpush(b"mylist", &[b"a", b"b", b"c"], now).unwrap();
        save_to_path(&store, &path).unwrap();
        let store2 = Store::new();
        load_from_path(&store2, &path).unwrap();
        let n = Instant::now();
        assert_eq!(store2.llen(b"mylist", n).unwrap(), 3);
        let range = store2.lrange(b"mylist", 0, -1, n).unwrap();
        assert_eq!(range[0], &b"a"[..]);
        assert_eq!(range[2], &b"c"[..]);
    }

    #[test]
    fn roundtrip_hashes() {
        let (path, _g) = test_path();
        let store = Store::new();
        let now = Instant::now();
        store
            .hset(
                b"myhash",
                &[(b"f1" as &[u8], b"v1" as &[u8]), (b"f2", b"v2")],
                now,
            )
            .unwrap();
        save_to_path(&store, &path).unwrap();
        let store2 = Store::new();
        load_from_path(&store2, &path).unwrap();
        let n = Instant::now();
        assert_eq!(store2.hget(b"myhash", b"f1", n).unwrap(), &b"v1"[..]);
        assert_eq!(store2.hlen(b"myhash", n).unwrap(), 2);
    }

    #[test]
    fn roundtrip_sets() {
        let (path, _g) = test_path();
        let store = Store::new();
        let now = Instant::now();
        store.sadd(b"myset", &[b"a", b"b", b"c"], now).unwrap();
        save_to_path(&store, &path).unwrap();
        let store2 = Store::new();
        load_from_path(&store2, &path).unwrap();
        let n = Instant::now();
        assert_eq!(store2.scard(b"myset", n).unwrap(), 3);
        assert!(store2.sismember(b"myset", b"a", n).unwrap());
    }

    #[test]
    fn roundtrip_sorted_sets() {
        let (path, _g) = test_path();
        let store = Store::new();
        let now = Instant::now();
        store
            .zadd(
                b"myzset",
                &[(b"alice" as &[u8], 1.5), (b"bob", 2.5)],
                false,
                false,
                false,
                false,
                false,
                now,
            )
            .unwrap();
        save_to_path(&store, &path).unwrap();
        let store2 = Store::new();
        load_from_path(&store2, &path).unwrap();
        let n = Instant::now();
        assert_eq!(store2.zcard(b"myzset", n).unwrap(), 2);
        assert_eq!(store2.zscore(b"myzset", b"alice", n).unwrap(), Some(1.5));
        assert_eq!(store2.zscore(b"myzset", b"bob", n).unwrap(), Some(2.5));
    }

    #[test]
    fn roundtrip_with_ttl() {
        let (path, _g) = test_path();
        let store = Store::new();
        let now = Instant::now();
        store.set(b"expiring", b"val", Some(Duration::from_secs(3600)), now);
        store.set(b"permanent", b"val", None, now);
        save_to_path(&store, &path).unwrap();
        let store2 = Store::new();
        load_from_path(&store2, &path).unwrap();
        let n = Instant::now();
        assert!(store2.get(b"expiring", n).is_some());
        assert!(store2.ttl(b"expiring", n) > 0);
        assert_eq!(store2.ttl(b"permanent", n), -1);
    }

    #[test]
    fn roundtrip_all_types_together() {
        let (path, _g) = test_path();
        let store = Store::new();
        let now = Instant::now();
        store.set(b"str", b"val", None, now);
        store.rpush(b"list", &[b"a", b"b"], now).unwrap();
        store
            .hset(b"hash", &[(b"f" as &[u8], b"v" as &[u8])], now)
            .unwrap();
        store.sadd(b"set", &[b"x", b"y"], now).unwrap();
        store
            .zadd(
                b"zset",
                &[(b"m" as &[u8], 1.0)],
                false,
                false,
                false,
                false,
                false,
                now,
            )
            .unwrap();
        assert_eq!(save_to_path(&store, &path).unwrap(), 5);
        let store2 = Store::new();
        assert_eq!(load_from_path(&store2, &path).unwrap(), 5);
        let n = Instant::now();
        assert_eq!(store2.get(b"str", n).unwrap(), &b"val"[..]);
        assert_eq!(store2.llen(b"list", n).unwrap(), 2);
        assert_eq!(store2.hlen(b"hash", n).unwrap(), 1);
        assert_eq!(store2.scard(b"set", n).unwrap(), 2);
        assert_eq!(store2.zcard(b"zset", n).unwrap(), 1);
    }

    #[test]
    fn load_nonexistent_returns_zero() {
        let store = Store::new();
        assert_eq!(
            load_from_path(&store, "/tmp/lux_nonexistent_file_test.dat").unwrap(),
            0
        );
    }

    #[test]
    fn test_binary_roundtrip_with_newlines() {
        let (path, _g) = test_path();
        let store = Store::new();
        let now = Instant::now();
        store.set(b"key", b"hello\nworld\n", None, now);
        save_to_path(&store, &path).unwrap();
        let store2 = Store::new();
        load_from_path(&store2, &path).unwrap();
        assert_eq!(
            store2.get(b"key", Instant::now()).unwrap(),
            &b"hello\nworld\n"[..]
        );
    }

    #[test]
    fn test_binary_roundtrip_with_tabs() {
        let (path, _g) = test_path();
        let store = Store::new();
        let now = Instant::now();
        store.set(b"key", b"hello\tworld\t", None, now);
        save_to_path(&store, &path).unwrap();
        let store2 = Store::new();
        load_from_path(&store2, &path).unwrap();
        assert_eq!(
            store2.get(b"key", Instant::now()).unwrap(),
            &b"hello\tworld\t"[..]
        );
    }

    #[test]
    fn test_no_key_injection() {
        let (path, _g) = test_path();
        let store = Store::new();
        let now = Instant::now();
        store.set(b"legit", b"S\tsecret\toverwritten\t0\n", None, now);
        save_to_path(&store, &path).unwrap();
        let store2 = Store::new();
        load_from_path(&store2, &path).unwrap();
        let n = Instant::now();
        assert!(store2.get(b"secret", n).is_none());
        assert_eq!(
            store2.get(b"legit", n).unwrap(),
            &b"S\tsecret\toverwritten\t0\n"[..]
        );
    }

    #[test]
    fn test_binary_roundtrip_all_types() {
        let (path, _g) = test_path();
        let store = Store::new();
        let now = Instant::now();
        store.set(b"str", b"val\twith\ttabs\nand\nnewlines", None, now);
        store.rpush(b"list", &[b"a\tb", b"c\nd"], now).unwrap();
        store
            .hset(b"hash", &[(b"field\t1" as &[u8], b"val\n1" as &[u8])], now)
            .unwrap();
        store.sadd(b"set", &[b"mem\t1", b"mem\n2"], now).unwrap();
        store
            .zadd(
                b"zset",
                &[(b"m\t1" as &[u8], 1.5)],
                false,
                false,
                false,
                false,
                false,
                now,
            )
            .unwrap();
        save_to_path(&store, &path).unwrap();
        let store2 = Store::new();
        load_from_path(&store2, &path).unwrap();
        let n = Instant::now();
        assert_eq!(
            store2.get(b"str", n).unwrap(),
            &b"val\twith\ttabs\nand\nnewlines"[..]
        );
        let range = store2.lrange(b"list", 0, -1, n).unwrap();
        assert_eq!(range[0], &b"a\tb"[..]);
        assert_eq!(range[1], &b"c\nd"[..]);
        assert_eq!(
            store2.hget(b"hash", b"field\t1", n).unwrap(),
            &b"val\n1"[..]
        );
        assert_eq!(store2.scard(b"set", n).unwrap(), 2);
        assert_eq!(store2.zcard(b"zset", n).unwrap(), 1);
    }

    #[test]
    fn test_legacy_format_loads() {
        let (path, _g) = test_path();
        let store = Store::new();
        let now = Instant::now();
        store.set(b"hello", b"world", None, now);
        store.set(b"num", b"42", None, now);
        save_legacy_to_path(&store, &path).unwrap();

        let store2 = Store::new();
        assert_eq!(load_from_path(&store2, &path).unwrap(), 2);
        let n = Instant::now();
        assert_eq!(store2.get(b"hello", n).unwrap(), &b"world"[..]);
        assert_eq!(store2.get(b"num", n).unwrap(), &b"42"[..]);
    }

    #[test]
    fn test_binary_data_in_values() {
        let (path, _g) = test_path();
        let store = Store::new();
        let now = Instant::now();
        let binary_val: Vec<u8> = vec![0x00, 0x01, 0x02, 0xFF, 0xFE, 0x80, 0x00];
        store.set(b"binkey", &binary_val, None, now);
        save_to_path(&store, &path).unwrap();
        let store2 = Store::new();
        load_from_path(&store2, &path).unwrap();
        assert_eq!(
            store2.get(b"binkey", Instant::now()).unwrap(),
            &binary_val[..]
        );
    }

    #[test]
    fn test_issue_8_newline_corruption() {
        let (path, _g) = test_path();
        let store = Store::new();
        let now = Instant::now();
        store.set(b"key1", b"line1\nline2\nline3", None, now);
        store.set(b"key2", b"normal", None, now);
        save_to_path(&store, &path).unwrap();
        let store2 = Store::new();
        load_from_path(&store2, &path).unwrap();
        let n = Instant::now();
        assert_eq!(store2.get(b"key1", n).unwrap(), &b"line1\nline2\nline3"[..]);
        assert_eq!(store2.get(b"key2", n).unwrap(), &b"normal"[..]);
    }

    #[test]
    fn test_issue_8_tab_corruption() {
        let (path, _g) = test_path();
        let store = Store::new();
        let now = Instant::now();
        store.set(b"key1", b"col1\tcol2\tcol3", None, now);
        store.set(b"key2", b"safe", None, now);
        save_to_path(&store, &path).unwrap();
        let store2 = Store::new();
        load_from_path(&store2, &path).unwrap();
        let n = Instant::now();
        assert_eq!(store2.get(b"key1", n).unwrap(), &b"col1\tcol2\tcol3"[..]);
        assert_eq!(store2.get(b"key2", n).unwrap(), &b"safe"[..]);
    }

    // A corrupt/hostile snapshot with an attacker-chosen huge length prefix must
    // fail closed (InvalidData), not OOM or panic trying to pre-allocate.
    #[test]
    fn malformed_snapshot_huge_lengths_fail_closed() {
        use std::io::Cursor;

        let mut huge_count = Vec::new();
        huge_count.push(b'L');
        huge_count.extend_from_slice(&3u32.to_le_bytes());
        huge_count.extend_from_slice(b"abc");
        huge_count.extend_from_slice(&(-1i64).to_le_bytes()); // ttl: none
        huge_count.extend_from_slice(&u32::MAX.to_le_bytes()); // list count: huge
        let store = Store::new();
        let err = load_binary(
            &store,
            &mut Cursor::new(huge_count.as_slice()),
            true,
            true,
            false,
        )
        .expect_err("huge list count must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let mut huge_bytes = Vec::new();
        huge_bytes.push(b'S');
        huge_bytes.extend_from_slice(&3u32.to_le_bytes());
        huge_bytes.extend_from_slice(b"abc");
        huge_bytes.extend_from_slice(&(-1i64).to_le_bytes());
        huge_bytes.extend_from_slice(&u32::MAX.to_le_bytes()); // str byte len: huge
        let store = Store::new();
        let err = load_binary(
            &store,
            &mut Cursor::new(huge_bytes.as_slice()),
            true,
            true,
            false,
        )
        .expect_err("huge byte string length must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    // Found by the fuzzer: a hash entry whose pair count is ~50M (under the item
    // cap) drove Vec::with_capacity(count) into a 2.4GB allocation, OOMing on a
    // 24-byte input. Pre-allocation must be bounded, so this returns an error
    // (EOF) without a giant up-front malloc.
    #[test]
    fn malformed_snapshot_large_count_does_not_oom() {
        let data = [
            0x48u8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x61, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0xf5, 0xff, 0x02, 0x00, 0xff, 0xff, 0xff,
        ];
        let store = Store::new();
        let result = load_binary(
            &store,
            &mut std::io::Cursor::new(&data[..]),
            true,
            true,
            false,
        );
        assert!(
            result.is_err(),
            "truncated huge-count hash must error, not OOM"
        );
    }

    fn store_in_temp_dir(mode: crate::StorageMode) -> (Arc<Store>, std::path::PathBuf, impl Drop) {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("lux_restore_test_{}_{}", std::process::id(), id));
        let storage_dir = dir.join("storage");
        fs::create_dir_all(&storage_dir).unwrap();
        let cfg = crate::ServerConfig {
            data_dir: dir.to_str().unwrap().to_string(),
            storage: crate::StorageConfig {
                mode,
                dir: storage_dir.to_str().unwrap().to_string(),
            },
            ..Default::default()
        };
        let store = Arc::new(Store::new_with_config(Arc::new(cfg)));
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        (store, dir.clone(), Cleanup(dir))
    }

    // Fuzz: arbitrary bytes fed to the binary snapshot loader must never panic
    // or OOM -- only return cleanly (Ok or InvalidData). Guards the fail-closed
    // length/count bounds against attacker-chosen prefixes.
    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(2000))]

        #[test]
        fn fuzz_snapshot_load_no_panic(
            data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4096)
        ) {
            let store = Store::new();
            let _ = load_binary(
                &store,
                &mut std::io::Cursor::new(&data),
                true,
                true,
                false,
            );
            let store2 = Store::new();
            let _ = load_binary(
                &store2,
                &mut std::io::Cursor::new(&data),
                false,
                false,
                false,
            );
        }
    }
}
