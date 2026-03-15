use crate::store::{DumpValue, Store};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn snapshot_path() -> String {
    let dir = std::env::var("LUX_DATA_DIR").unwrap_or_else(|_| ".".to_string());
    format!("{}/lux.dat", dir.trim_end_matches('/'))
}

fn snapshot_interval() -> Duration {
    let secs: u64 = std::env::var("LUX_SAVE_INTERVAL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    Duration::from_secs(secs)
}

pub fn save(store: &Store) -> io::Result<usize> {
    let path = snapshot_path();
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
        };
        let encoded_value = match &entry.value {
            DumpValue::Str(s) => s.clone(),
            DumpValue::List(items) => items.join("\x1f"),
            DumpValue::Hash(pairs) => pairs
                .iter()
                .map(|(k, v)| format!("{}\x1e{}", k, v))
                .collect::<Vec<_>>()
                .join("\x1f"),
            DumpValue::Set(members) => members.join("\x1f"),
        };
        writeln!(file, "{}\t{}\t{}\t{}", type_char, entry.key, encoded_value, entry.ttl_ms)?;
    }
    file.sync_all()?;
    fs::rename(&tmp, &path)?;
    Ok(entries.len())
}

pub fn load(store: &Store) -> io::Result<usize> {
    let path_str = snapshot_path();
    let path = Path::new(&path_str);
    if !path.exists() {
        return Ok(0);
    }
    let file = fs::File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut count = 0;
    for line in reader.lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }

        if !line.contains('\t') || line.chars().next().map_or(true, |c| !"SLHT".contains(c))
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
                store.load_entry(key, DumpValue::Str(value), ttl);
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
            "S" => DumpValue::Str(raw_value.to_string()),
            "L" => {
                let items: Vec<String> = if raw_value.is_empty() {
                    vec![]
                } else {
                    raw_value.split('\x1f').map(|s| s.to_string()).collect()
                };
                DumpValue::List(items)
            }
            "H" => {
                let pairs: Vec<(String, String)> = if raw_value.is_empty() {
                    vec![]
                } else {
                    raw_value
                        .split('\x1f')
                        .filter_map(|pair| {
                            let kv: Vec<&str> = pair.splitn(2, '\x1e').collect();
                            if kv.len() == 2 {
                                Some((kv[0].to_string(), kv[1].to_string()))
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
            _ => continue,
        };

        store.load_entry(key, value, ttl);
        count += 1;
    }
    Ok(count)
}

pub async fn background_save_loop(store: Arc<Store>) {
    let interval = snapshot_interval();
    loop {
        tokio::time::sleep(interval).await;
        match save(&store) {
            Ok(n) => println!("snapshot: saved {n} keys"),
            Err(e) => eprintln!("snapshot error: {e}"),
        }
    }
}
