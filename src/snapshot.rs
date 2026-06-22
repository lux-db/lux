use crate::store::{DumpValue, Store};
use std::fs;
use std::io::{self, BufRead, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

const HEADER_V1: &[u8; 4] = b"LUX\x01";
const HEADER_V2: &[u8; 4] = b"LUX\x02";
// V3 persists key TTLs as ABSOLUTE epoch-ms deadlines instead of relative
// remaining-ms. V2 rebased the remaining time to load-time, so a key with N ms
// left at save time got a full fresh N ms on restart -- TTLs paused across
// downtime and keys that should have expired while down resurrected. V3 subtracts
// elapsed wall-clock on load so deadlines are honored across restarts.
const HEADER: &[u8; 4] = b"LUX\x03";

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

fn write_f64(w: &mut impl Write, v: f64) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

// Fail-closed bounds for snapshot loading: a corrupt or hostile snapshot must
// not be able to drive a huge up-front allocation (OOM) from an attacker-chosen
// length prefix. These cap a single byte string and a single collection's item
// count; loads that exceed them are rejected as InvalidData (no panic, no OOM).
const MAX_SNAPSHOT_BYTES: usize = 512 * 1024 * 1024;
const MAX_SNAPSHOT_ITEMS: usize = 64 * 1024 * 1024;

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

fn read_f64(r: &mut impl Read) -> io::Result<f64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(f64::from_le_bytes(buf))
}

fn read_string(r: &mut impl Read) -> io::Result<String> {
    let raw = read_bytes(r)?;
    String::from_utf8(raw).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn save_entries(store: &Store, entries: &[crate::store::DumpEntry]) -> io::Result<usize> {
    let path = snapshot_path(store);
    if let Some(parent) = Path::new(&path).parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = format!("{path}.{}.tmp", std::process::id());
    let file = fs::File::create(&tmp)?;
    let mut w = BufWriter::new(file);
    save_binary(&mut w, entries)?;
    w.into_inner().map_err(io::Error::other)?.sync_all()?;
    fs::rename(&tmp, &path)?;
    Ok(entries.len())
}

pub(crate) fn save_and_truncate_wal_consistent(store: &Store) -> io::Result<usize> {
    store.with_write_barrier(|shards| {
        let now = Instant::now();
        let entries = store.dump_all_from_locked_shards(shards, now);
        let saved = save_entries(store, &entries)?;
        store.truncate_wal();
        Ok(saved)
    })
}

/// Produce a consistent on-disk snapshot for an out-of-band backup and return
/// its path. Runs the same consistent save the background timer performs (full
/// dump including tiered cold data, then WAL truncation), so the file is a
/// complete point-in-time image of the instance. Used by `GET /v1/snapshot`,
/// which lets the control plane back an instance up over its own HTTP port
/// without needing a shell inside the (distroless) container.
pub fn snapshot_for_backup(store: &Store) -> io::Result<String> {
    save_and_truncate_wal_consistent(store)?;
    Ok(snapshot_path(store))
}

/// Lay a restored snapshot down on disk: write `dump` as lux.dat and remove the
/// per-shard WAL + tiered data dirs so a restart reloads purely from the dump,
/// with no stale WAL replaying post-snapshot writes over it. The caller restarts
/// the process so the standard startup load reconstructs state from the dump.
/// Used by `POST /v1/restore`.
pub fn restore_to_disk(store: &Store, dump: &[u8]) -> io::Result<()> {
    if dump.len() < 4 || (&dump[..4] != HEADER && &dump[..4] != HEADER_V1) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "restore payload is not a lux snapshot",
        ));
    }

    let path = snapshot_path(store);
    if let Some(parent) = Path::new(&path).parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = format!("{path}.restore.{}.tmp", std::process::id());
    {
        let file = fs::File::create(&tmp)?;
        let mut w = BufWriter::new(file);
        w.write_all(dump)?;
        w.into_inner().map_err(io::Error::other)?.sync_all()?;
    }
    fs::rename(&tmp, &path)?;

    // Drop the tiered storage tree (per-shard WAL + cold data) so startup loads
    // only lux.dat, with no WAL replaying post-snapshot writes over the restore.
    let storage_dir = store.config().storage.dir.clone();
    let _ = fs::remove_dir_all(Path::new(&storage_dir));
    Ok(())
}

fn save_binary(w: &mut impl Write, entries: &[crate::store::DumpEntry]) -> io::Result<()> {
    w.write_all(HEADER)?;
    for entry in entries {
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

pub fn load(store: &Store) -> io::Result<usize> {
    let path_str = snapshot_path(store);
    let path = Path::new(&path_str);
    if !path.exists() {
        return Ok(0);
    }
    let file = fs::File::open(path)?;
    load_from_reader(store, file)
}

fn load_from_reader(store: &Store, mut file: fs::File) -> io::Result<usize> {
    let mut header = [0u8; 4];
    let n = file.read(&mut header)?;
    if n == 4 && &header == HEADER {
        // V3: absolute-deadline TTLs, stream groups present.
        load_binary(store, &mut io::BufReader::new(file), true, true)
    } else if n == 4 && &header == HEADER_V2 {
        // V2: relative remaining-ms TTLs (legacy; rebased to now on load).
        load_binary(store, &mut io::BufReader::new(file), true, false)
    } else if n == 4 && &header == HEADER_V1 {
        load_binary(store, &mut io::BufReader::new(file), false, false)
    } else {
        file.seek(SeekFrom::Start(0))?;
        load_legacy(store, file)
    }
}

fn load_binary(
    store: &Store,
    r: &mut impl Read,
    stream_groups: bool,
    absolute_ttl: bool,
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

        let value = match type_buf[0] {
            b'S' => DumpValue::Str(read_bytes(r)?),
            b'L' => {
                let len = read_count(r, "list item")?;
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(read_bytes(r)?);
                }
                DumpValue::List(items)
            }
            b'H' => {
                let len = read_count(r, "hash field")?;
                let mut pairs = Vec::with_capacity(len);
                for _ in 0..len {
                    let k = read_string(r)?;
                    let v = read_bytes(r)?;
                    pairs.push((k, v));
                }
                DumpValue::Hash(pairs)
            }
            b'T' => {
                let len = read_count(r, "set member")?;
                let mut members = Vec::with_capacity(len);
                for _ in 0..len {
                    members.push(read_string(r)?);
                }
                DumpValue::Set(members)
            }
            b'Z' => {
                let len = read_count(r, "sorted set member")?;
                let mut members = Vec::with_capacity(len);
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
                let mut entries = Vec::with_capacity(entry_count);
                for _ in 0..entry_count {
                    let id = read_string(r)?;
                    let field_count = read_count(r, "stream field")?;
                    let mut fields = Vec::with_capacity(field_count);
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
                    groups.reserve(group_count);
                    for _ in 0..group_count {
                        let name = read_string(r)?;
                        let last_delivered_id = read_string(r)?;
                        let consumer_count = read_count(r, "stream consumer")?;
                        let mut consumers = Vec::with_capacity(consumer_count);
                        for _ in 0..consumer_count {
                            let consumer = read_string(r)?;
                            let pending_count = read_count(r, "stream consumer pending")?;
                            let mut pending_ids = Vec::with_capacity(pending_count);
                            for _ in 0..pending_count {
                                pending_ids.push(read_string(r)?);
                            }
                            consumers.push((consumer, pending_ids));
                        }
                        let pending_count = read_count(r, "stream group pending")?;
                        let mut pending = Vec::with_capacity(pending_count);
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
                let mut data = Vec::with_capacity(dims);
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
                let mut samples = Vec::with_capacity(sample_count);
                for _ in 0..sample_count {
                    let ts = read_i64(r)?;
                    let val = read_f64(r)?;
                    samples.push((ts, val));
                }
                let retention = read_i64(r)? as u64;
                let label_count = read_count(r, "timeseries label")?;
                let mut labels = Vec::with_capacity(label_count);
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
                    format!("unknown type byte: {}", type_buf[0]),
                ))
            }
        };

        // The value bytes were read above to advance the stream; only store the
        // entry if its absolute deadline hasn't already passed during downtime.
        if !expired {
            store.load_entry(key, value, ttl);
            count += 1;
        }
    }
    Ok(count)
}

fn load_legacy(store: &Store, file: fs::File) -> io::Result<usize> {
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
            if parts.len() == 3 {
                let key = parts[0].to_string();
                let value = parts[1].to_string();
                let ttl_ms: i64 = parts[2].parse().unwrap_or(0);
                let ttl = if ttl_ms > 0 {
                    Some(Duration::from_millis(ttl_ms as u64))
                } else {
                    None
                };
                store.load_entry(key, DumpValue::Str(value.into_bytes()), ttl);
                count += 1;
            }
            continue;
        }

        let parts: Vec<&str> = line.splitn(4, '\t').collect();
        if parts.len() != 4 {
            continue;
        }
        let type_char = parts[0];
        let key = parts[1].to_string();
        let raw_value = parts[2];
        let ttl_ms: i64 = parts[3].parse().unwrap_or(0);
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
                        .filter_map(|pair| {
                            let kv: Vec<&str> = pair.splitn(2, '\x1e').collect();
                            if kv.len() == 2 {
                                Some((kv[0].to_string(), kv[1].as_bytes().to_vec()))
                            } else {
                                None
                            }
                        })
                        .collect()
                };
                DumpValue::Hash(pairs)
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
                        .filter_map(|pair| {
                            let kv: Vec<&str> = pair.splitn(2, '\x1e').collect();
                            if kv.len() == 2 {
                                Some((kv[0].to_string(), kv[1].parse::<f64>().unwrap_or(0.0)))
                            } else {
                                None
                            }
                        })
                        .collect()
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
                        if !parts_e.is_empty() {
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
                }
                DumpValue::Stream(entries, last_id_str, Vec::new())
            }
            _ => continue,
        };

        store.load_entry(key, value, ttl);
        count += 1;
    }
    Ok(count)
}

pub async fn background_save_loop(store: Arc<Store>) {
    let interval = snapshot_interval(&store);
    if interval.is_zero() {
        return;
    }
    loop {
        tokio::time::sleep(interval).await;
        match save_and_truncate_wal_consistent(&store) {
            Ok(n) => {
                crate::emit_info(
                    store.config(),
                    crate::ServerInfoEvent::SnapshotSaved { keys: n },
                );
            }
            Err(e) => {
                crate::emit_error(
                    store.config(),
                    crate::ServerErrorEvent::SnapshotSaveFailed {
                        error: e.to_string(),
                        path: snapshot_path(&store),
                    },
                );
            }
        }
    }
}

#[cfg(test)]
fn save_to_path(store: &Store, path: &str) -> io::Result<usize> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    let now = Instant::now();
    let entries = store.dump_all(now);
    let tmp = format!("{path}.tmp");
    let file = fs::File::create(&tmp)?;
    let mut w = BufWriter::new(file);
    save_binary(&mut w, &entries)?;
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
    load_from_reader(store, file)
}

#[cfg(test)]
fn save_legacy_to_path(store: &Store, path: &str) -> io::Result<usize> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    let now = Instant::now();
    let entries = store.dump_all(now);
    let tmp = format!("{path}.tmp");
    let mut file = fs::File::create(&tmp)?;
    for entry in &entries {
        let type_char = match &entry.value {
            DumpValue::Str(_) => 'S',
            DumpValue::List(_) => 'L',
            DumpValue::Hash(_) => 'H',
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
            DumpValue::Hash(pairs) => pairs
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
        let err = load_binary(&store, &mut Cursor::new(huge_count.as_slice()), true, true)
            .expect_err("huge list count must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let mut huge_bytes = Vec::new();
        huge_bytes.push(b'S');
        huge_bytes.extend_from_slice(&3u32.to_le_bytes());
        huge_bytes.extend_from_slice(b"abc");
        huge_bytes.extend_from_slice(&(-1i64).to_le_bytes());
        huge_bytes.extend_from_slice(&u32::MAX.to_le_bytes()); // str byte len: huge
        let store = Store::new();
        let err = load_binary(&store, &mut Cursor::new(huge_bytes.as_slice()), true, true)
            .expect_err("huge byte string length must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
