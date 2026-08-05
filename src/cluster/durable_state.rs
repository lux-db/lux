use super::ClusterError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand_core::{OsRng as SystemRandom, RngCore};
use serde::Serialize;
use std::io::{Read, Write};
use std::path::Path;

pub(super) fn write_json_atomic(
    path: &Path,
    value: &impl Serialize,
    state_kind: &str,
    maximum_bytes: usize,
) -> Result<(), ClusterError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    if bytes.len() > maximum_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("durable {state_kind} state exceeds the size limit"),
        )
        .into());
    }
    if let Some(parent) = state_parent(path) {
        std::fs::create_dir_all(parent)?;
    }
    let mut nonce = [0_u8; 16];
    SystemRandom.try_fill_bytes(&mut nonce).map_err(|error| {
        std::io::Error::other(format!(
            "failed to create {state_kind} state nonce: {error}"
        ))
    })?;
    let nonce = URL_SAFE_NO_PAD.encode(nonce);
    let temporary = path.with_extension(format!("tmp-{}-{nonce}", std::process::id()));
    let result = (|| -> Result<(), ClusterError> {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        if let Some(parent) = state_parent(path) {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

pub(super) fn read_bounded(path: &Path, maximum_bytes: u64) -> Result<Vec<u8>, ClusterError> {
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn state_parent(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_state_is_rejected_before_creating_a_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let result = write_json_atomic(&path, &vec!["larger-than-limit"], "test", 8);
        assert!(matches!(result, Err(ClusterError::Io(_))));
        assert!(!path.exists());
    }
}
