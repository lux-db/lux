//! Tiered storage: per-shard disk backing and write-ahead log.
//!
//! When LUX_STORAGE_MODE=tiered, each shard gets a DiskShard (append-only
//! data file + in-memory index) and a Wal (command log for crash recovery).
//! Evicted entries are written to the DiskShard instead of being deleted.
//! On read miss, entries are transparently promoted back to memory.

use crate::store::{DumpEntry, DumpValue, StreamGroupDump};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

// Magic bytes written at the start of WAL and data files to identify the
// checksummed format (v2). Files without this magic are treated as legacy.
const WAL_MAGIC: &[u8; 4] = b"LXW1";
const DATA_MAGIC: &[u8; 4] = b"LXD1";

/// CRC32 (ISO 3309 / ITU-T V.42) computed with a lookup table.
/// Used to detect corruption in WAL frames and disk entries.
fn crc32(data: &[u8]) -> u32 {
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for i in 0..256u32 {
            let mut crc = i;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB8_8320;
                } else {
                    crc >>= 1;
                }
            }
            t[i as usize] = crc;
        }
        t
    });
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageMode {
    /// All data in memory. Eviction deletes permanently. Zero disk overhead.
    Memory,
    /// Hot data in memory, cold data on disk. Automatic promotion on access.
    Tiered,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageConfig {
    /// Storage mode used by the runtime.
    pub mode: StorageMode,
    /// Directory for tiered data files and WAL shards.
    pub dir: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            mode: StorageMode::Memory,
            dir: "./storage".to_string(),
        }
    }
}

impl StorageMode {
    /// Stable lowercase name used in INFO output and diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            StorageMode::Memory => "memory",
            StorageMode::Tiered => "tiered",
        }
    }
}

/// Write-ahead log for crash recovery.
///
/// Stores raw command bytes in a length-prefixed binary format. Every write
/// command is appended here before the in-memory mutation. On crash, the WAL
/// is replayed by re-executing each command. Truncated after each snapshot
/// since the snapshot contains all data.
///
/// v2 frame format: [4B frame_len][4B crc32][4B argc][for each arg: 4B len + bytes]
/// Legacy format:   [4B frame_len][4B argc][for each arg: 4B len + bytes]
pub struct Wal {
    file: File,
    /// True if this WAL file starts with WAL_MAGIC (v2 checksummed format).
    has_checksums: bool,
}

/// Checksum details for one corrupted WAL frame skipped during replay.
pub struct WalCorruptedFrame {
    pub stored_crc: u32,
    pub computed_crc: u32,
}

/// Result of scanning a WAL file for replay.
///
/// The low-level disk layer records corruption details here; the Store layer
/// owns configuration and emits the corresponding warning events.
pub struct WalReplay {
    pub commands: Vec<Vec<Vec<u8>>>,
    pub corrupted_frames: Vec<WalCorruptedFrame>,
}

impl Wal {
    pub fn open(dir: &Path, shard_id: usize) -> io::Result<Self> {
        let shard_dir = dir.join(format!("shard_{shard_id}"));
        fs::create_dir_all(&shard_dir)?;
        let path = shard_dir.join("wal.lux");
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;

        let file_len = file.seek(SeekFrom::End(0))?;
        let has_checksums = if file_len == 0 {
            // New file: write magic header and start in v2 mode.
            file.write_all(WAL_MAGIC)?;
            file.flush()?;
            true
        } else {
            // Existing file: check for magic.
            file.seek(SeekFrom::Start(0))?;
            let mut magic = [0u8; 4];
            if file.read_exact(&mut magic).is_ok() && &magic == WAL_MAGIC {
                file.seek(SeekFrom::End(0))?;
                true
            } else {
                file.seek(SeekFrom::End(0))?;
                false
            }
        };

        Ok(Wal {
            file,
            has_checksums,
        })
    }

    fn encode_command_frame(args: &[&[u8]], out: &mut Vec<u8>) {
        let mut payload = Vec::new();
        let argc = args.len() as u32;
        payload.extend_from_slice(&argc.to_le_bytes());
        for arg in args {
            let len = arg.len() as u32;
            payload.extend_from_slice(&len.to_le_bytes());
            payload.extend_from_slice(arg);
        }

        let checksum = crc32(&payload);
        let frame_len = (4 + payload.len()) as u32;

        out.extend_from_slice(&frame_len.to_le_bytes());
        out.extend_from_slice(&checksum.to_le_bytes());
        out.extend_from_slice(&payload);
    }

    /// Append a command to the WAL. Builds the entire frame in memory and
    /// writes it in a single call to minimize partial-write risk. If the
    /// write fails (e.g. ENOSPC), truncates back to the pre-write position
    /// so the WAL stays clean for the next attempt.
    pub fn append_command(&mut self, args: &[&[u8]]) -> io::Result<()> {
        let mut frame = Vec::new();
        Self::encode_command_frame(args, &mut frame);

        self.append_encoded_frames(&frame)
    }

    /// Append multiple command frames in one write/flush. Used by pipelined
    /// single-shard writes so durability preserves the same batching advantage
    /// as the in-memory executor.
    pub fn append_commands<'a, I>(&mut self, commands: I) -> io::Result<()>
    where
        I: IntoIterator<Item = &'a [&'a [u8]]>,
    {
        let mut frames = Vec::new();
        for args in commands {
            Self::encode_command_frame(args, &mut frames);
        }
        if frames.is_empty() {
            return Ok(());
        }
        self.append_encoded_frames(&frames)
    }

    fn append_encoded_frames(&mut self, frames: &[u8]) -> io::Result<()> {
        let pos_before = self.file.stream_position()?;
        if let Err(e) = self.file.write_all(frames).and_then(|_| self.file.flush()) {
            // Truncate back to clean position so partial bytes don't
            // corrupt future appends or waste space.
            let _ = self.file.set_len(pos_before);
            let _ = self.file.seek(SeekFrom::End(0));
            return Err(e);
        }
        Ok(())
    }

    pub fn fsync(&mut self) -> io::Result<()> {
        self.file.sync_all()
    }

    /// Read all commands from the WAL for replay. Partial/corrupt frames
    /// (from a crash mid-write) are safely skipped. Checksummed frames (v2)
    /// are validated; frames with bad checksums are rejected and counted.
    pub fn replay(&mut self) -> io::Result<WalReplay> {
        let file_len = self.file.seek(SeekFrom::End(0))?;
        if file_len == 0 {
            return Ok(WalReplay {
                commands: Vec::new(),
                corrupted_frames: Vec::new(),
            });
        }

        // Skip past magic header if present.
        if self.has_checksums {
            self.file.seek(SeekFrom::Start(4))?;
        } else {
            self.file.seek(SeekFrom::Start(0))?;
        }

        let mut commands = Vec::new();
        let mut corrupted_frames = Vec::new();

        loop {
            let frame_len = match read_u32(&mut self.file) {
                Ok(l) => l as usize,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(_) => break,
            };
            let payload_start = self.file.stream_position()?;
            if payload_start + frame_len as u64 > file_len {
                break;
            }

            let mut buf = vec![0u8; frame_len];
            match self.file.read_exact(&mut buf) {
                Ok(()) => {}
                Err(_) => break, // partial frame at end (crash mid-write)
            }

            let payload = if self.has_checksums {
                if buf.len() < 4 {
                    continue;
                }
                let stored_crc = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                let data = &buf[4..];
                let computed_crc = crc32(data);
                if stored_crc != computed_crc {
                    corrupted_frames.push(WalCorruptedFrame {
                        stored_crc,
                        computed_crc,
                    });
                    continue;
                }
                &buf[4..]
            } else {
                &buf[..]
            };

            let mut cursor = payload;
            let argc = match read_u32(&mut cursor) {
                Ok(n) => n as usize,
                Err(_) => continue,
            };

            let mut args = Vec::new();
            let mut valid = true;
            for _ in 0..argc {
                match read_bytes(&mut cursor) {
                    Ok(arg) => args.push(arg),
                    Err(_) => {
                        valid = false;
                        break;
                    }
                }
            }
            if valid && !args.is_empty() {
                commands.push(args);
            }
        }
        self.file.seek(SeekFrom::End(0))?;
        Ok(WalReplay {
            commands,
            corrupted_frames,
        })
    }

    pub fn truncate(&mut self) -> io::Result<()> {
        self.file.set_len(0)?;
        self.file.seek(SeekFrom::Start(0))?;
        // Re-write magic so new appends are checksummed.
        self.file.write_all(WAL_MAGIC)?;
        self.file.flush()?;
        self.has_checksums = true;
        Ok(())
    }
}

/// In-memory metadata for a cold entry on disk. The actual data lives in the
/// data file at `offset`. We track `created_at` so TTL can be correctly
/// decremented while the entry sits on disk.
struct DiskEntry {
    offset: u64,
    length: u32,
    ttl_ms: i64,
    created_at: Instant,
}

impl DiskEntry {
    fn is_expired(&self, now: Instant) -> bool {
        if self.ttl_ms <= 0 {
            return false;
        }
        let elapsed = now.duration_since(self.created_at).as_millis() as i64;
        elapsed >= self.ttl_ms
    }

    fn remaining_ttl_ms(&self, now: Instant) -> i64 {
        if self.ttl_ms <= 0 {
            return -1;
        }
        let elapsed = now.duration_since(self.created_at).as_millis() as i64;
        let remaining = self.ttl_ms - elapsed;
        if remaining <= 0 {
            0
        } else {
            remaining
        }
    }
}

/// Per-shard cold storage. Uses a Bitcask-style design:
/// - Append-only data file: serialized entries appended on eviction
/// - In-memory index: HashMap<key, file_offset> for O(1) lookups without scanning
/// - Compaction: periodic rewrite drops dead bytes from overwritten/deleted entries
///
/// v2 entry envelope: [4B entry_len][4B crc32][entry_data...]
/// Legacy: raw entry_data bytes (no envelope).
///
/// Protected by a Mutex in Store. Accessed only on eviction (write) and
/// cache miss (read), both cold paths. Never blocks the in-memory shard RwLock.
pub struct DiskShard {
    /// Maps key -> position in data file. Small footprint since it only
    /// stores offsets, not values.
    index: HashMap<String, DiskEntry>,
    data_file: File,
    path: PathBuf,
    /// Bytes in the data file that are no longer referenced (overwritten entries).
    /// When this exceeds 30% of total_bytes, compaction triggers.
    dead_bytes: usize,
    total_bytes: usize,
    /// True if this data file uses the v2 checksummed envelope format.
    has_checksums: bool,
    /// Corruption/parse details found during the last startup rebuild.
    rebuild_report: DiskRebuildReport,
}

/// Corruption details collected while rebuilding a disk shard index.
///
/// `DiskShard` cannot emit runtime events directly because it has no access to
/// `ServerConfig`; `Store::new_with_config` drains this report after opening.
#[derive(Clone, Debug, Default)]
pub struct DiskRebuildReport {
    pub corrupted_entries: Vec<DiskCorruptedEntry>,
    pub parse_errors: Vec<DiskEntryParseError>,
}

/// One disk entry rejected because its CRC did not match.
#[derive(Clone, Debug)]
pub struct DiskCorruptedEntry {
    pub offset: u64,
}

/// One disk entry rejected because its payload could not be decoded.
#[derive(Clone, Debug)]
pub struct DiskEntryParseError {
    pub offset: u64,
    pub error: String,
}

impl DiskShard {
    /// Opens or creates a disk shard. On startup, rebuilds the in-memory
    /// index by scanning the existing data file.
    pub fn open(dir: &Path, shard_id: usize) -> io::Result<Self> {
        let shard_dir = dir.join(format!("shard_{shard_id}"));
        fs::create_dir_all(&shard_dir)?;
        let path = shard_dir.join("data.lux");
        let mut data_file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;

        let file_len = data_file.seek(SeekFrom::End(0))?;
        let has_checksums = if file_len == 0 {
            data_file.write_all(DATA_MAGIC)?;
            data_file.flush()?;
            true
        } else {
            data_file.seek(SeekFrom::Start(0))?;
            let mut magic = [0u8; 4];
            if data_file.read_exact(&mut magic).is_ok() && &magic == DATA_MAGIC {
                data_file.seek(SeekFrom::End(0))?;
                true
            } else {
                data_file.seek(SeekFrom::End(0))?;
                false
            }
        };

        let mut ds = DiskShard {
            index: HashMap::new(),
            data_file,
            path,
            dead_bytes: 0,
            total_bytes: 0,
            has_checksums,
            rebuild_report: DiskRebuildReport::default(),
        };
        ds.rebuild_index()?;
        Ok(ds)
    }

    /// Drain corruption details captured by `rebuild_index`.
    pub fn take_rebuild_report(&mut self) -> DiskRebuildReport {
        std::mem::take(&mut self.rebuild_report)
    }

    /// Serialize and append an entry to the data file. If the key already
    /// exists on disk (re-eviction), the old bytes become dead and the index
    /// points to the new copy. Writes the entire envelope in a single call
    /// and truncates back on failure to avoid leaving partial entries.
    ///
    /// v2 envelope: [4B entry_len][4B crc32][entry_data...]
    pub fn put(&mut self, key: &str, dump: &DumpEntry) -> io::Result<()> {
        let file_offset = self.total_bytes as u64;
        let mut entry_data = Vec::new();
        write_single_entry(&mut entry_data, dump)?;

        let checksum = crc32(&entry_data);
        let entry_len = entry_data.len() as u32;
        let total_on_disk = 4 + 4 + entry_data.len();

        // Build complete envelope in one buffer.
        let mut buf = Vec::with_capacity(total_on_disk);
        buf.extend_from_slice(&entry_len.to_le_bytes());
        buf.extend_from_slice(&checksum.to_le_bytes());
        buf.extend_from_slice(&entry_data);

        if let Err(e) = self
            .data_file
            .write_all(&buf)
            .and_then(|_| self.data_file.flush())
        {
            // Truncate partial bytes so the data file stays clean.
            let _ = self.data_file.set_len(file_offset);
            let _ = self.data_file.seek(SeekFrom::End(0));
            return Err(e);
        }

        if let Some(old) = self.index.insert(
            key.to_string(),
            DiskEntry {
                offset: file_offset,
                length: total_on_disk as u32,
                ttl_ms: if dump.ttl_ms > 0 { dump.ttl_ms } else { -1 },
                created_at: Instant::now(),
            },
        ) {
            self.dead_bytes += old.length as usize;
        }
        self.total_bytes += total_on_disk;
        Ok(())
    }

    /// Read an entry from disk by seeking to its offset in the data file.
    /// Returns None if the key isn't in the index or has expired.
    /// Validates CRC32 checksum for v2 entries.
    pub fn get(
        &mut self,
        key: &str,
        now: Instant,
    ) -> io::Result<Option<(DumpValue, Option<Duration>)>> {
        let de = match self.index.get(key) {
            Some(de) => de,
            None => return Ok(None),
        };
        if de.is_expired(now) {
            let len = de.length as usize;
            self.index.remove(key);
            self.dead_bytes += len;
            return Ok(None);
        }

        let offset = de.offset;
        let length = de.length as usize;
        let remaining = de.remaining_ttl_ms(now);

        let mut buf = vec![0u8; length];
        let mut reader = &self.data_file;
        reader.seek(SeekFrom::Start(offset))?;
        reader.read_exact(&mut buf)?;

        let entry_data = if self.has_checksums {
            // Envelope: [4B entry_len][4B crc32][entry_data...]
            if buf.len() < 8 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "disk entry too short for checksum envelope",
                ));
            }
            let stored_crc = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
            let data = &buf[8..];
            let computed_crc = crc32(data);
            if stored_crc != computed_crc {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "disk entry checksum mismatch for key '{key}' \
                         (stored={stored_crc:#010x} computed={computed_crc:#010x})"
                    ),
                ));
            }
            data
        } else {
            &buf[..]
        };

        let mut cursor = entry_data;
        let (_key, value, _ttl_ms) = read_single_entry(&mut cursor)?;
        let ttl = if remaining > 0 {
            Some(Duration::from_millis(remaining as u64))
        } else {
            None
        };
        Ok(Some((value, ttl)))
    }

    pub fn remove(&mut self, key: &str) {
        if let Some(de) = self.index.remove(key) {
            self.dead_bytes += de.length as usize;
        }
    }

    pub fn contains(&self, key: &str) -> bool {
        self.index.contains_key(key)
    }

    pub fn contains_valid(&self, key: &str, now: Instant) -> bool {
        match self.index.get(key) {
            Some(de) => !de.is_expired(now),
            None => false,
        }
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.index.keys()
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn total_size(&self) -> usize {
        self.total_bytes
    }

    /// Check if compaction would be worthwhile. Triggers when >30% of the
    /// data file is dead bytes (overwritten/deleted entries), or when dead
    /// bytes exceed 100MB absolute.
    pub fn should_compact(&self) -> bool {
        if self.dead_bytes == 0 {
            return false;
        }
        let ratio = self.dead_bytes as f64 / self.total_bytes.max(1) as f64;
        (self.total_bytes > 64 * 1024 && ratio > 0.3) || self.dead_bytes > 100 * 1024 * 1024
    }

    /// Rewrite the data file keeping only live entries. Creates a new file,
    /// copies live data, then atomic-renames over the old file. Reclaims all
    /// dead bytes from overwritten/deleted entries. Always writes v2 format
    /// with magic header and checksummed envelopes (upgrades legacy files).
    pub fn compact(&mut self) -> io::Result<()> {
        let tmp_path = self.path.with_extension("compact.tmp");
        let tmp_file = File::create(&tmp_path)?;
        let mut writer = BufWriter::new(tmp_file);

        // Always write magic header -- compaction upgrades legacy to v2.
        writer.write_all(DATA_MAGIC)?;
        let mut new_total: usize = 4; // magic header size
        let mut new_index = HashMap::new();

        let keys: Vec<String> = self.index.keys().cloned().collect();
        for key in &keys {
            let de = &self.index[key];

            // Read existing entry and extract the raw entry_data.
            let mut buf = vec![0u8; de.length as usize];
            self.data_file.seek(SeekFrom::Start(de.offset))?;
            self.data_file.read_exact(&mut buf)?;

            let entry_data = if self.has_checksums {
                // Skip the 4B entry_len + 4B crc envelope, re-serialize fresh.
                buf[8..].to_vec()
            } else {
                buf
            };

            // Write v2 envelope: [4B entry_len][4B crc32][entry_data]
            let checksum = crc32(&entry_data);
            let entry_len = entry_data.len() as u32;
            let total_on_disk = 4 + 4 + entry_data.len();

            let new_offset = new_total as u64;
            writer.write_all(&entry_len.to_le_bytes())?;
            writer.write_all(&checksum.to_le_bytes())?;
            writer.write_all(&entry_data)?;

            new_index.insert(
                key.clone(),
                DiskEntry {
                    offset: new_offset,
                    length: total_on_disk as u32,
                    ttl_ms: de.ttl_ms,
                    created_at: de.created_at,
                },
            );
            new_total += total_on_disk;
        }

        writer.flush()?;
        drop(writer);

        fs::rename(&tmp_path, &self.path)?;
        self.data_file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&self.path)?;
        self.index = new_index;
        self.total_bytes = new_total;
        self.dead_bytes = 0;
        self.has_checksums = true;
        Ok(())
    }

    pub fn dump_all(&mut self, now: Instant) -> io::Result<Vec<DumpEntry>> {
        let mut entries = Vec::new();
        let keys: Vec<String> = self.index.keys().cloned().collect();
        for key in keys {
            if let Some((value, _ttl)) = self.get(&key, now)? {
                let de = &self.index[&key];
                let ttl_ms = de.remaining_ttl_ms(now);
                entries.push(DumpEntry { key, value, ttl_ms });
            }
        }
        Ok(entries)
    }

    /// Scan the data file from start to end, rebuilding the in-memory index.
    /// Called on startup to recover the index from an existing data file.
    /// If a key appears multiple times (from re-evictions), the last occurrence
    /// wins and earlier ones become dead bytes.
    fn rebuild_index(&mut self) -> io::Result<()> {
        let file_len = self.data_file.seek(SeekFrom::End(0))?;
        let header_size: u64 = if self.has_checksums { 4 } else { 0 };
        if file_len <= header_size {
            self.total_bytes = header_size as usize;
            return Ok(());
        }
        self.data_file.seek(SeekFrom::Start(header_size))?;
        self.total_bytes = header_size as usize;
        let now = Instant::now();
        if self.has_checksums {
            // v2 format: [4B entry_len][4B crc32][entry_data...]
            loop {
                let start = self.data_file.stream_position()?;
                if start >= file_len {
                    break;
                }
                let entry_len = match read_u32(&mut self.data_file) {
                    Ok(l) => l as usize,
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(e),
                };
                let stored_crc = match read_u32(&mut self.data_file) {
                    Ok(c) => c,
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(e),
                };
                let payload_start = self.data_file.stream_position()?;
                if payload_start + entry_len as u64 > file_len {
                    break;
                }

                let mut entry_data = vec![0u8; entry_len];
                match self.data_file.read_exact(&mut entry_data) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(e),
                }

                let computed_crc = crc32(&entry_data);
                if stored_crc != computed_crc {
                    self.rebuild_report
                        .corrupted_entries
                        .push(DiskCorruptedEntry { offset: start });
                    let total_on_disk = 4 + 4 + entry_len;
                    self.dead_bytes += total_on_disk;
                    self.total_bytes += total_on_disk;
                    continue;
                }

                let mut cursor = &entry_data[..];
                match read_single_entry(&mut cursor) {
                    Ok((key, _value, ttl_ms)) => {
                        let total_on_disk = 4 + 4 + entry_len;
                        if let Some(old) = self.index.insert(
                            key,
                            DiskEntry {
                                offset: start,
                                length: total_on_disk as u32,
                                ttl_ms,
                                created_at: now,
                            },
                        ) {
                            self.dead_bytes += old.length as usize;
                        }
                        self.total_bytes += total_on_disk;
                    }
                    Err(e) => {
                        self.rebuild_report.parse_errors.push(DiskEntryParseError {
                            offset: start,
                            error: e.to_string(),
                        });
                        let total_on_disk = 4 + 4 + entry_len;
                        self.dead_bytes += total_on_disk;
                        self.total_bytes += total_on_disk;
                    }
                }
            }
        } else {
            // Legacy format: raw read_single_entry bytes, no envelope.
            loop {
                let start = self.data_file.stream_position()?;
                if start >= file_len {
                    break;
                }
                match read_single_entry(&mut self.data_file) {
                    Ok((key, _value, ttl_ms)) => {
                        let end_pos = self.data_file.stream_position()?;
                        let length = (end_pos - start) as u32;

                        if let Some(old) = self.index.insert(
                            key,
                            DiskEntry {
                                offset: start,
                                length,
                                ttl_ms,
                                created_at: now,
                            },
                        ) {
                            self.dead_bytes += old.length as usize;
                        }
                        self.total_bytes += length as usize;
                    }
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(e),
                }
            }
        }

        self.data_file.seek(SeekFrom::End(0))?;
        Ok(())
    }
}

fn write_u32(w: &mut impl Write, v: u32) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

fn write_i64(w: &mut impl Write, v: i64) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

fn write_f64(w: &mut impl Write, v: f64) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

fn write_bytes(w: &mut impl Write, data: &[u8]) -> io::Result<()> {
    w.write_all(&(data.len() as u32).to_le_bytes())?;
    w.write_all(data)
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

fn read_f64(r: &mut impl Read) -> io::Result<f64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(f64::from_le_bytes(buf))
}

fn read_bytes(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let len = read_u32(r)? as usize;
    let mut limited = r.take(len as u64);
    let mut buf = Vec::new();
    limited.read_to_end(&mut buf)?;
    if buf.len() != len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short length-prefixed byte string",
        ));
    }
    Ok(buf)
}

fn read_string(r: &mut impl Read) -> io::Result<String> {
    let raw = read_bytes(r)?;
    String::from_utf8(raw).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn write_stream_groups(w: &mut impl Write, groups: &[StreamGroupDump]) -> io::Result<()> {
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
    Ok(())
}

fn read_stream_groups(r: &mut impl Read) -> io::Result<Vec<StreamGroupDump>> {
    let group_count = match read_u32(r) {
        Ok(count) => count as usize,
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut groups = Vec::with_capacity(group_count);
    for _ in 0..group_count {
        let name = read_string(r)?;
        let last_delivered_id = read_string(r)?;
        let consumer_count = read_u32(r)? as usize;
        let mut consumers = Vec::with_capacity(consumer_count);
        for _ in 0..consumer_count {
            let consumer = read_string(r)?;
            let pending_count = read_u32(r)? as usize;
            let mut pending_ids = Vec::with_capacity(pending_count);
            for _ in 0..pending_count {
                pending_ids.push(read_string(r)?);
            }
            consumers.push((consumer, pending_ids));
        }
        let pending_count = read_u32(r)? as usize;
        let mut pending = Vec::with_capacity(pending_count);
        for _ in 0..pending_count {
            let id = read_string(r)?;
            let consumer = read_string(r)?;
            let delivery_count = read_u32(r)? as u64;
            pending.push((id, consumer, delivery_count));
        }
        groups.push((name, last_delivered_id, consumers, pending));
    }
    Ok(groups)
}

pub fn write_single_entry(w: &mut impl Write, entry: &DumpEntry) -> io::Result<()> {
    let type_byte: u8 = match &entry.value {
        DumpValue::Str(_) => b'S',
        DumpValue::List(_) => b'L',
        DumpValue::Hash(_) => b'H',
        DumpValue::Set(_) => b'T',
        DumpValue::SortedSet(_) => b'Z',
        DumpValue::Stream(..) => b'X',
        DumpValue::Vector(..) => b'V',
        DumpValue::HyperLogLog(..) => b'P',
        DumpValue::TimeSeries(..) => b'I',
    };
    w.write_all(&[type_byte])?;
    write_bytes(w, entry.key.as_bytes())?;
    let ttl = if entry.ttl_ms > 0 { entry.ttl_ms } else { -1 };
    write_i64(w, ttl)?;

    match &entry.value {
        DumpValue::Str(v) => write_bytes(w, v)?,
        DumpValue::List(items) => {
            write_u32(w, items.len() as u32)?;
            for item in items {
                write_bytes(w, item)?;
            }
        }
        DumpValue::Hash(pairs) => {
            write_u32(w, pairs.len() as u32)?;
            for (k, v) in pairs {
                write_bytes(w, k.as_bytes())?;
                write_bytes(w, v)?;
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
            write_stream_groups(w, groups)?;
        }
        DumpValue::Vector(data, metadata) => {
            write_u32(w, data.len() as u32)?;
            for f in data {
                w.write_all(&f.to_le_bytes())?;
            }
            match metadata {
                Some(m) => {
                    w.write_all(&[1u8])?;
                    write_bytes(w, m.as_bytes())?;
                }
                None => w.write_all(&[0u8])?,
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
    Ok(())
}

pub fn read_single_entry(r: &mut impl Read) -> io::Result<(String, DumpValue, i64)> {
    let mut type_buf = [0u8; 1];
    r.read_exact(&mut type_buf)?;

    let key = read_string(r)?;
    let ttl_ms = read_i64(r)?;

    let value = match type_buf[0] {
        b'S' => DumpValue::Str(read_bytes(r)?),
        b'L' => {
            let len = read_u32(r)? as usize;
            let mut items = Vec::new();
            for _ in 0..len {
                items.push(read_bytes(r)?);
            }
            DumpValue::List(items)
        }
        b'H' => {
            let len = read_u32(r)? as usize;
            let mut pairs = Vec::new();
            for _ in 0..len {
                let k = read_string(r)?;
                let v = read_bytes(r)?;
                pairs.push((k, v));
            }
            DumpValue::Hash(pairs)
        }
        b'T' => {
            let len = read_u32(r)? as usize;
            let mut members = Vec::new();
            for _ in 0..len {
                members.push(read_string(r)?);
            }
            DumpValue::Set(members)
        }
        b'Z' => {
            let len = read_u32(r)? as usize;
            let mut members = Vec::new();
            for _ in 0..len {
                let m = read_string(r)?;
                let s = read_f64(r)?;
                members.push((m, s));
            }
            DumpValue::SortedSet(members)
        }
        b'X' => {
            let last_id = read_string(r)?;
            let entry_count = read_u32(r)? as usize;
            let mut entries = Vec::new();
            for _ in 0..entry_count {
                let id = read_string(r)?;
                let field_count = read_u32(r)? as usize;
                let mut fields = Vec::new();
                for _ in 0..field_count {
                    let k = read_string(r)?;
                    let v = read_bytes(r)?;
                    fields.push((k, v));
                }
                entries.push((id, fields));
            }
            let groups = read_stream_groups(r)?;
            DumpValue::Stream(entries, last_id, groups)
        }
        b'V' => {
            let dims = read_u32(r)? as usize;
            let mut data = Vec::new();
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
            DumpValue::Vector(data, metadata)
        }
        b'P' => {
            let len = read_u32(r)? as usize;
            let mut regs = vec![0u8; len];
            r.read_exact(&mut regs)?;
            let cached = crate::hll::hll_count(&regs);
            DumpValue::HyperLogLog(regs, cached)
        }
        b'I' => {
            let sample_count = read_u32(r)? as usize;
            let mut samples = Vec::new();
            for _ in 0..sample_count {
                let ts = read_i64(r)?;
                let val = read_f64(r)?;
                samples.push((ts, val));
            }
            let retention = read_i64(r)? as u64;
            let label_count = read_u32(r)? as usize;
            let mut labels = Vec::new();
            for _ in 0..label_count {
                let k = read_string(r)?;
                let v = read_string(r)?;
                labels.push((k, v));
            }
            DumpValue::TimeSeries(samples, retention, labels)
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown type byte: {other}"),
            ))
        }
    };

    Ok((key, value, ttl_ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_known_values() {
        // "123456789" should produce 0xCBF43926 per the CRC32 spec.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        // Empty input should produce 0x00000000.
        assert_eq!(crc32(b""), 0x0000_0000);
    }

    #[test]
    fn disk_shard_roundtrip_with_checksum() {
        let dir = tempfile::tempdir().unwrap();
        let entry = DumpEntry {
            key: "hello".to_string(),
            value: DumpValue::Str(b"world".to_vec()),
            ttl_ms: -1,
        };

        {
            let mut ds = DiskShard::open(dir.path(), 0).unwrap();
            assert!(ds.has_checksums);
            ds.put("hello", &entry).unwrap();
        }

        // Re-open and rebuild index from disk.
        {
            let mut ds = DiskShard::open(dir.path(), 0).unwrap();
            assert!(ds.has_checksums);
            assert_eq!(ds.len(), 1);
            let (value, ttl) = ds.get("hello", Instant::now()).unwrap().unwrap();
            assert!(matches!(value, DumpValue::Str(ref v) if v == b"world"));
            assert!(ttl.is_none());
        }
    }

    #[test]
    fn disk_shard_detects_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let entry = DumpEntry {
            key: "foo".to_string(),
            value: DumpValue::Str(b"bar".to_vec()),
            ttl_ms: -1,
        };

        {
            let mut ds = DiskShard::open(dir.path(), 0).unwrap();
            ds.put("foo", &entry).unwrap();
        }

        // Corrupt a byte inside the entry payload. The rebuild report records
        // the start offset of the failed entry, not the specific damaged byte.
        let data_path = dir.path().join("shard_0/data.lux");
        let mut data = fs::read(&data_path).unwrap();
        let entry_start_offset = DATA_MAGIC.len() as u64;
        let corrupt_byte_offset = DATA_MAGIC.len() + 4 + 4 + 2;
        if data.len() > corrupt_byte_offset {
            data[corrupt_byte_offset] ^= 0xFF;
        }
        fs::write(&data_path, &data).unwrap();

        // Re-open: rebuild_index should skip the corrupted entry.
        let mut ds = DiskShard::open(dir.path(), 0).unwrap();
        assert_eq!(ds.len(), 0, "corrupted entry should have been skipped");
        assert!(
            ds.dead_bytes > 0,
            "corrupted entry should count as dead bytes"
        );
        let report = ds.take_rebuild_report();
        assert_eq!(report.corrupted_entries.len(), 1);
        assert_eq!(report.corrupted_entries[0].offset, entry_start_offset);
    }

    #[test]
    fn wal_roundtrip_with_checksum() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut wal = Wal::open(dir.path(), 0).unwrap();
            assert!(wal.has_checksums);
            wal.append_command(&[b"SET", b"key1", b"val1"]).unwrap();
            wal.append_command(&[b"SET", b"key2", b"val2"]).unwrap();
            wal.fsync().unwrap();
        }

        {
            let mut wal = Wal::open(dir.path(), 0).unwrap();
            assert!(wal.has_checksums);
            let replay = wal.replay().unwrap();
            let commands = replay.commands;
            assert_eq!(commands.len(), 2);
            assert_eq!(commands[0][0], b"SET");
            assert_eq!(commands[0][1], b"key1");
            assert_eq!(commands[1][1], b"key2");
        }
    }

    #[test]
    fn wal_batch_append_roundtrips_commands() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut wal = Wal::open(dir.path(), 0).unwrap();
            let first: &[&[u8]] = &[b"SET", b"k1", b"v1"];
            let second: &[&[u8]] = &[b"SET", b"k2", b"v2"];
            wal.append_commands([first, second]).unwrap();
            wal.fsync().unwrap();
        }

        let mut wal = Wal::open(dir.path(), 0).unwrap();
        let replay = wal.replay().unwrap();
        assert_eq!(
            replay.commands,
            vec![
                vec![b"SET".to_vec(), b"k1".to_vec(), b"v1".to_vec()],
                vec![b"SET".to_vec(), b"k2".to_vec(), b"v2".to_vec()],
            ]
        );
        assert!(replay.corrupted_frames.is_empty());
    }

    #[test]
    fn wal_detects_corrupted_frame() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut wal = Wal::open(dir.path(), 0).unwrap();
            wal.append_command(&[b"SET", b"k1", b"v1"]).unwrap();
            wal.append_command(&[b"SET", b"k2", b"v2"]).unwrap();
            wal.fsync().unwrap();
        }

        // Corrupt the first frame's payload (after magic + frame_len + crc).
        let wal_path = dir.path().join("shard_0/wal.lux");
        let mut data = fs::read(&wal_path).unwrap();
        // Flip a byte after magic(4) + frame_len(4) + crc(4) = offset 12.
        if data.len() > 14 {
            data[14] ^= 0xFF;
        }
        fs::write(&wal_path, &data).unwrap();

        {
            let mut wal = Wal::open(dir.path(), 0).unwrap();
            let replay = wal.replay().unwrap();
            assert_eq!(replay.corrupted_frames.len(), 1);
            let commands = replay.commands;
            // First frame corrupted, second should still be valid.
            assert_eq!(commands.len(), 1);
            assert_eq!(commands[0][1], b"k2");
        }
    }

    #[test]
    fn wal_truncate_preserves_magic() {
        let dir = tempfile::tempdir().unwrap();
        let mut wal = Wal::open(dir.path(), 0).unwrap();
        wal.append_command(&[b"SET", b"x", b"y"]).unwrap();
        wal.truncate().unwrap();
        assert!(wal.has_checksums);

        // After truncate, replay should return empty.
        let commands = wal.replay().unwrap().commands;
        assert!(commands.is_empty());

        // New appends should still be checksummed.
        wal.append_command(&[b"SET", b"a", b"b"]).unwrap();
        let commands = wal.replay().unwrap().commands;
        assert_eq!(commands.len(), 1);
    }

    #[test]
    fn compact_upgrades_to_checksummed() {
        let dir = tempfile::tempdir().unwrap();
        let entry1 = DumpEntry {
            key: "k1".to_string(),
            value: DumpValue::Str(b"v1".to_vec()),
            ttl_ms: -1,
        };
        let entry2 = DumpEntry {
            key: "k2".to_string(),
            value: DumpValue::Str(b"v2".to_vec()),
            ttl_ms: -1,
        };

        let mut ds = DiskShard::open(dir.path(), 0).unwrap();
        ds.put("k1", &entry1).unwrap();
        ds.put("k2", &entry2).unwrap();
        // Overwrite k1 to create dead bytes.
        let entry1b = DumpEntry {
            key: "k1".to_string(),
            value: DumpValue::Str(b"v1_updated".to_vec()),
            ttl_ms: -1,
        };
        ds.put("k1", &entry1b).unwrap();

        assert!(ds.dead_bytes > 0);
        ds.compact().unwrap();
        assert!(ds.has_checksums);
        assert_eq!(ds.dead_bytes, 0);
        assert_eq!(ds.len(), 2);

        // Verify data survived compaction.
        let (val, _) = ds.get("k1", Instant::now()).unwrap().unwrap();
        assert!(matches!(val, DumpValue::Str(ref v) if v == b"v1_updated"));
        let (val, _) = ds.get("k2", Instant::now()).unwrap().unwrap();
        assert!(matches!(val, DumpValue::Str(ref v) if v == b"v2"));
    }

    #[test]
    fn wal_partial_frame_is_harmless() {
        // Simulate a crash mid-write by appending partial bytes to the WAL.
        let dir = tempfile::tempdir().unwrap();
        {
            let mut wal = Wal::open(dir.path(), 0).unwrap();
            wal.append_command(&[b"SET", b"k1", b"v1"]).unwrap();
            wal.fsync().unwrap();
        }

        // Append garbage (simulates partial frame from crash mid-write).
        let wal_path = dir.path().join("shard_0/wal.lux");
        let mut file = OpenOptions::new().append(true).open(&wal_path).unwrap();
        // Write a frame_len header but no actual payload.
        file.write_all(&100u32.to_le_bytes()).unwrap();
        file.write_all(b"partial").unwrap();
        file.flush().unwrap();
        drop(file);

        // Replay should recover the valid command and skip the partial frame.
        let mut wal = Wal::open(dir.path(), 0).unwrap();
        let commands = wal.replay().unwrap().commands;
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0][0], b"SET");
        assert_eq!(commands[0][1], b"k1");
    }

    #[test]
    fn disk_shard_partial_entry_is_harmless() {
        // Simulate a crash mid-write by appending partial bytes to the data file.
        let dir = tempfile::tempdir().unwrap();
        {
            let mut ds = DiskShard::open(dir.path(), 0).unwrap();
            let entry = DumpEntry {
                key: "good".to_string(),
                value: DumpValue::Str(b"data".to_vec()),
                ttl_ms: -1,
            };
            ds.put("good", &entry).unwrap();
        }

        // Append garbage entry_len + partial data.
        let data_path = dir.path().join("shard_0/data.lux");
        let mut file = OpenOptions::new().append(true).open(&data_path).unwrap();
        file.write_all(&50u32.to_le_bytes()).unwrap(); // entry_len = 50
        file.write_all(b"not enough bytes").unwrap(); // only 16 bytes, not 50
        file.flush().unwrap();
        drop(file);

        // Reopen: should recover the valid entry, skip the partial one.
        let mut ds = DiskShard::open(dir.path(), 0).unwrap();
        assert_eq!(ds.len(), 1);
        let (val, _) = ds.get("good", Instant::now()).unwrap().unwrap();
        assert!(matches!(val, DumpValue::Str(ref v) if v == b"data"));
    }

    #[test]
    fn disk_shard_survives_garbage_at_end() {
        // Simulate the worst case: valid entries followed by partial garbage
        // (what happens if a crash occurs mid-put before rollback runs).
        // Verifies that rebuild_index recovers all valid entries.
        let dir = tempfile::tempdir().unwrap();
        {
            let mut ds = DiskShard::open(dir.path(), 0).unwrap();
            for i in 0..5 {
                let entry = DumpEntry {
                    key: format!("k{i}"),
                    value: DumpValue::Str(format!("v{i}").into_bytes()),
                    ttl_ms: -1,
                };
                ds.put(&format!("k{i}"), &entry).unwrap();
            }
        }

        // Append garbage that looks like a partial entry envelope.
        let data_path = dir.path().join("shard_0/data.lux");
        let mut file = OpenOptions::new().append(true).open(&data_path).unwrap();
        // Write entry_len header claiming 200 bytes, but only write 5.
        file.write_all(&200u32.to_le_bytes()).unwrap();
        file.write_all(b"trash").unwrap();
        file.flush().unwrap();
        drop(file);

        // Reopen: all 5 valid entries should survive.
        let mut ds = DiskShard::open(dir.path(), 0).unwrap();
        assert_eq!(ds.len(), 5);
        for i in 0..5 {
            let (val, _) = ds.get(&format!("k{i}"), Instant::now()).unwrap().unwrap();
            assert!(matches!(val, DumpValue::Str(ref v) if *v == format!("v{i}").into_bytes()));
        }
    }

    #[test]
    fn wal_append_is_atomic_single_buffer() {
        // Verify that a WAL frame is written as a single contiguous block
        // by checking that the file grows by exactly the expected frame size.
        let dir = tempfile::tempdir().unwrap();
        let mut wal = Wal::open(dir.path(), 0).unwrap();

        let wal_path = dir.path().join("shard_0/wal.lux");
        let size_before = fs::metadata(&wal_path).unwrap().len();
        assert_eq!(size_before, 4, "should only have magic header");

        wal.append_command(&[b"SET", b"x", b"y"]).unwrap();
        let size_after = fs::metadata(&wal_path).unwrap().len();

        // Frame: 4B frame_len + 4B crc + 4B argc + (4B+3 "SET") + (4B+1 "x") + (4B+1 "y")
        let payload_size: u64 = 4 + 7 + 5 + 5; // argc + 3 args
        let frame_size = 4 + 4 + payload_size; // frame_len + crc + payload
        assert_eq!(
            size_after,
            4 + frame_size,
            "file should grow by exactly one frame"
        );
    }

    // -----------------------------------------------------------------------
    // Proptest: fuzz and property-based tests
    // -----------------------------------------------------------------------
    use proptest::prelude::*;

    fn arb_bytes() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 0..256)
    }

    fn arb_string() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9_]{0,64}"
    }

    fn arb_dump_value() -> impl Strategy<Value = DumpValue> {
        prop_oneof![
            arb_bytes().prop_map(DumpValue::Str),
            prop::collection::vec(arb_bytes(), 0..16).prop_map(DumpValue::List),
            prop::collection::vec((arb_string(), arb_bytes()), 0..16).prop_map(DumpValue::Hash),
            prop::collection::vec(arb_string(), 0..16).prop_map(DumpValue::Set),
            prop::collection::vec((arb_string(), (-1e10f64..1e10f64)), 0..16)
                .prop_map(DumpValue::SortedSet),
            (
                prop::collection::vec(-1e6f32..1e6f32, 0..64),
                prop::option::of(arb_string())
            )
                .prop_map(|(data, meta)| DumpValue::Vector(data, meta)),
            prop::collection::vec(any::<u8>(), 0..256).prop_map(|regs| {
                let cached = crate::hll::hll_count(&regs);
                DumpValue::HyperLogLog(regs, cached)
            }),
            (
                prop::collection::vec((any::<i64>(), (-1e10f64..1e10f64)), 0..16),
                any::<u64>(),
                prop::collection::vec((arb_string(), arb_string()), 0..8),
            )
                .prop_map(|(s, r, l)| DumpValue::TimeSeries(s, r, l)),
            (
                prop::collection::vec(
                    (
                        arb_string(),
                        prop::collection::vec((arb_string(), arb_bytes()), 0..8),
                    ),
                    0..8,
                ),
                arb_string(),
            )
                .prop_map(|(entries, last_id)| DumpValue::Stream(
                    entries,
                    last_id,
                    Vec::new()
                )),
        ]
    }

    fn arb_dump_entry() -> impl Strategy<Value = DumpEntry> {
        (
            arb_string(),
            arb_dump_value(),
            prop_oneof![Just(-1i64), 0i64..=3600000i64],
        )
            .prop_map(|(key, value, ttl_ms)| DumpEntry { key, value, ttl_ms })
    }

    fn values_match(a: &DumpValue, b: &DumpValue) -> bool {
        match (a, b) {
            (DumpValue::Str(a), DumpValue::Str(b)) => a == b,
            (DumpValue::List(a), DumpValue::List(b)) => a == b,
            (DumpValue::Hash(a), DumpValue::Hash(b)) => a == b,
            (DumpValue::Set(a), DumpValue::Set(b)) => a == b,
            (DumpValue::SortedSet(a), DumpValue::SortedSet(b)) => a == b,
            (DumpValue::Stream(ae, al, ag), DumpValue::Stream(be, bl, bg)) => {
                ae == be && al == bl && ag == bg
            }
            (DumpValue::Vector(ad, am), DumpValue::Vector(bd, bm)) => ad == bd && am == bm,
            (DumpValue::HyperLogLog(ar, _), DumpValue::HyperLogLog(br, _)) => ar == br,
            (DumpValue::TimeSeries(as_, ar, al), DumpValue::TimeSeries(bs, br, bl)) => {
                as_ == bs && ar == br && al == bl
            }
            _ => false,
        }
    }

    // Fuzz: arbitrary bytes into read_single_entry should never panic.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        #[test]
        fn fuzz_read_single_entry_no_panic(data in prop::collection::vec(any::<u8>(), 0..1024)) {
            let mut cursor = std::io::Cursor::new(&data);
            let _ = read_single_entry(&mut cursor);
        }
    }

    // Fuzz: arbitrary bytes appended to WAL should never panic on replay.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        #[test]
        fn fuzz_wal_replay_no_panic(garbage in prop::collection::vec(any::<u8>(), 0..2048)) {
            let dir = tempfile::tempdir().unwrap();
            {
                let mut wal = Wal::open(dir.path(), 0).unwrap();
                wal.append_command(&[b"SET", b"k", b"v"]).unwrap();
                wal.fsync().unwrap();
            }

            let wal_path = dir.path().join("shard_0/wal.lux");
            std::fs::OpenOptions::new()
                .append(true)
                .open(&wal_path)
                .unwrap()
                .write_all(&garbage)
                .unwrap();

            let mut wal = Wal::open(dir.path(), 0).unwrap();
            let commands = wal.replay().unwrap().commands;
            prop_assert!(!commands.is_empty(), "valid command should survive garbage");
            prop_assert_eq!(&commands[0][0], b"SET");
        }
    }

    // Fuzz: arbitrary bytes appended to data file should never panic on rebuild.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        #[test]
        fn fuzz_disk_rebuild_no_panic(garbage in prop::collection::vec(any::<u8>(), 0..2048)) {
            let dir = tempfile::tempdir().unwrap();
            {
                let mut ds = DiskShard::open(dir.path(), 0).unwrap();
                let entry = DumpEntry {
                    key: "valid".to_string(),
                    value: DumpValue::Str(b"data".to_vec()),
                    ttl_ms: -1,
                };
                ds.put("valid", &entry).unwrap();
            }

            let data_path = dir.path().join("shard_0/data.lux");
            std::fs::OpenOptions::new()
                .append(true)
                .open(&data_path)
                .unwrap()
                .write_all(&garbage)
                .unwrap();

            let ds = DiskShard::open(dir.path(), 0).unwrap();
            prop_assert!(ds.len() >= 1, "valid entry should survive garbage append");
        }
    }

    // Property: write_single_entry -> read_single_entry is lossless.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn roundtrip_disk_entry(entry in arb_dump_entry()) {
            let mut buf = Vec::new();
            write_single_entry(&mut buf, &entry).unwrap();

            let mut cursor = std::io::Cursor::new(&buf);
            let (key, value, ttl_ms) = read_single_entry(&mut cursor).unwrap();

            prop_assert_eq!(&key, &entry.key);
            let expected_ttl = if entry.ttl_ms > 0 { entry.ttl_ms } else { -1 };
            prop_assert_eq!(ttl_ms, expected_ttl);
            prop_assert!(values_match(&entry.value, &value), "value mismatch");
        }
    }

    // Property: WAL append -> replay round-trip preserves commands.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        #[test]
        fn roundtrip_wal_commands(
            commands in prop::collection::vec(
                prop::collection::vec(arb_bytes(), 1..8),
                1..20
            )
        ) {
            let dir = tempfile::tempdir().unwrap();
            {
                let mut wal = Wal::open(dir.path(), 0).unwrap();
                for cmd in &commands {
                    let refs: Vec<&[u8]> = cmd.iter().map(|a| a.as_slice()).collect();
                    wal.append_command(&refs).unwrap();
                }
                wal.fsync().unwrap();
            }

            let mut wal = Wal::open(dir.path(), 0).unwrap();
            let replayed = wal.replay().unwrap().commands;

            prop_assert_eq!(replayed.len(), commands.len());
            for (original, recovered) in commands.iter().zip(replayed.iter()) {
                prop_assert_eq!(original, recovered);
            }
        }
    }

    // Property: DiskShard put -> get round-trip preserves data.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(200))]

        #[test]
        fn roundtrip_disk_shard(entries in prop::collection::vec(arb_dump_entry(), 1..20)) {
            let dir = tempfile::tempdir().unwrap();
            let mut ds = DiskShard::open(dir.path(), 0).unwrap();

            for entry in &entries {
                ds.put(&entry.key, entry).unwrap();
            }

            let now = Instant::now();
            let mut expected: std::collections::HashMap<String, &DumpEntry> =
                std::collections::HashMap::new();
            for entry in &entries {
                expected.insert(entry.key.clone(), entry);
            }

            for (key, entry) in &expected {
                let result = ds.get(key, now).unwrap();
                match result {
                    Some((value, _ttl)) => {
                        prop_assert!(
                            values_match(&entry.value, &value),
                            "value mismatch for key '{}'",
                            key
                        );
                    }
                    None => {
                        prop_assert_eq!(
                            entry.ttl_ms, 0,
                            "non-expired key '{}' missing from disk",
                            key
                        );
                    }
                }
            }
        }
    }

    // Property: DiskShard survives reopen with arbitrary entries.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn disk_shard_reopen_roundtrip(entries in prop::collection::vec(arb_dump_entry(), 1..10)) {
            let dir = tempfile::tempdir().unwrap();
            {
                let mut ds = DiskShard::open(dir.path(), 0).unwrap();
                for entry in &entries {
                    ds.put(&entry.key, entry).unwrap();
                }
            }

            let mut ds = DiskShard::open(dir.path(), 0).unwrap();

            let mut expected: std::collections::HashMap<String, &DumpEntry> =
                std::collections::HashMap::new();
            for entry in &entries {
                expected.insert(entry.key.clone(), entry);
            }

            let now = Instant::now();
            for (key, entry) in &expected {
                if entry.ttl_ms > 0 {
                    let result = ds.get(key, now).unwrap();
                    if let Some((value, _)) = result {
                        prop_assert!(
                            values_match(&entry.value, &value),
                            "reopen: value mismatch for key '{}'",
                            key
                        );
                    }
                }
            }
        }
    }
}
