use crate::disk::Wal;
use crate::snapshot::{self, SnapshotFormat};
use crate::store::Store;
use crate::{DurabilityPolicy, ServerConfig, StorageMode};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const MANIFEST_MAGIC: &[u8; 8] = b"LUXRST1\0";
const MANIFEST_LEN: usize = 208;
const PENDING_MANIFEST: &str = ".lux-restore.pending";
const PENDING_MANIFEST_TMP: &str = ".lux-restore.pending.tmp";
const STAGED_SNAPSHOT: &str = ".lux-restore.snapshot";
const BACKUP_ROOT: &str = "restore-backups";
const BACKUP_COMPLETE: &str = "backup-complete";
const WAL_HEADER_LEN: u64 = 24;

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingRestore {
    id: [u8; 16],
    source_len: u64,
    payload_len: u64,
    source_format: SnapshotFormat,
    storage_mode: StorageMode,
    source_sha256: [u8; 32],
    payload_sha256: [u8; 32],
    data_dir_hash: [u8; 32],
    journal_dir_hash: [u8; 32],
    encryption_paths_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StagedRestore {
    pub(crate) id: String,
    pub(crate) source_len: u64,
    pub(crate) payload_len: u64,
    pub(crate) entries: usize,
    pub(crate) source_format: u8,
    pub(crate) format: u8,
    pub(crate) source_sha256: String,
    pub(crate) sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PendingRestoreStatus {
    pub(crate) id: String,
    pub(crate) source_len: u64,
    pub(crate) payload_len: u64,
    pub(crate) source_format: u8,
    pub(crate) format: u8,
    pub(crate) source_sha256: String,
    pub(crate) sha256: String,
}

#[cfg(test)]
mod fault_injection {
    use std::cell::Cell;
    use std::io;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum Point {
        Backup,
        SnapshotInstall,
        JournalInstall,
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
                    "injected restore failure at {point:?}"
                )))
            } else {
                Ok(())
            }
        })
    }
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn data_dir(config: &ServerConfig) -> PathBuf {
    PathBuf::from(&config.data_dir)
}

fn pending_path(config: &ServerConfig) -> PathBuf {
    data_dir(config).join(PENDING_MANIFEST)
}

fn pending_tmp_path(config: &ServerConfig) -> PathBuf {
    data_dir(config).join(PENDING_MANIFEST_TMP)
}

fn staged_path(config: &ServerConfig) -> PathBuf {
    data_dir(config).join(STAGED_SNAPSHOT)
}

fn snapshot_path(config: &ServerConfig) -> PathBuf {
    data_dir(config).join("lux.dat")
}

fn restore_id_hex(id: &[u8; 16]) -> String {
    hex_bytes(id)
}

fn backup_data_dir(config: &ServerConfig, id: &[u8; 16]) -> PathBuf {
    data_dir(config)
        .join(BACKUP_ROOT)
        .join(restore_id_hex(id))
        .join("data")
}

fn backup_complete_path(config: &ServerConfig, id: &[u8; 16]) -> PathBuf {
    backup_data_dir(config, id)
        .parent()
        .expect("backup data directory always has a restore parent")
        .join(BACKUP_COMPLETE)
}

fn ensure_backup_dir(root: &Path, id: &[u8; 16], leaf: &str) -> io::Result<PathBuf> {
    let backup_root = root.join(BACKUP_ROOT);
    crate::disk::create_dir_all_synced(&backup_root)?;
    crate::file_security::ensure_private_dir(&backup_root)?;
    let restore_root = backup_root.join(restore_id_hex(id));
    crate::disk::create_dir_all_synced(&restore_root)?;
    crate::file_security::ensure_private_dir(&restore_root)?;
    let destination = restore_root.join(leaf);
    crate::disk::create_dir_all_synced(&destination)?;
    crate::file_security::ensure_private_dir(&destination)?;
    crate::disk::sync_directory(&backup_root)?;
    crate::disk::sync_directory(&restore_root)?;
    Ok(destination)
}

fn storage_mode_byte(mode: StorageMode) -> u8 {
    match mode {
        StorageMode::Memory => 0,
        StorageMode::Tiered => 1,
    }
}

fn storage_mode_from_byte(value: u8) -> io::Result<StorageMode> {
    match value {
        0 => Ok(StorageMode::Memory),
        1 => Ok(StorageMode::Tiered),
        _ => Err(invalid_data(
            "restore manifest has an invalid storage layout",
        )),
    }
}

fn encode_manifest(manifest: &PendingRestore) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(MANIFEST_LEN);
    bytes.extend_from_slice(MANIFEST_MAGIC);
    bytes.extend_from_slice(&manifest.id);
    bytes.extend_from_slice(&manifest.source_len.to_le_bytes());
    bytes.extend_from_slice(&manifest.payload_len.to_le_bytes());
    bytes.push(manifest.source_format.version());
    bytes.push(storage_mode_byte(manifest.storage_mode));
    bytes.extend_from_slice(&[0; 6]);
    bytes.extend_from_slice(&manifest.source_sha256);
    bytes.extend_from_slice(&manifest.payload_sha256);
    bytes.extend_from_slice(&manifest.data_dir_hash);
    bytes.extend_from_slice(&manifest.journal_dir_hash);
    bytes.extend_from_slice(&manifest.encryption_paths_hash);
    debug_assert_eq!(bytes.len(), MANIFEST_LEN);
    bytes
}

fn read_exact_array<const N: usize>(reader: &mut impl Read) -> io::Result<[u8; N]> {
    let mut value = [0; N];
    reader.read_exact(&mut value)?;
    Ok(value)
}

fn decode_manifest(bytes: &[u8]) -> io::Result<PendingRestore> {
    if bytes.len() != MANIFEST_LEN {
        return Err(invalid_data("restore manifest has an invalid length"));
    }
    let mut reader = Cursor::new(bytes);
    if read_exact_array::<8>(&mut reader)? != *MANIFEST_MAGIC {
        return Err(invalid_data("restore manifest has an invalid header"));
    }
    let id = read_exact_array(&mut reader)?;
    if id == [0; 16] {
        return Err(invalid_data("restore manifest has an invalid identifier"));
    }
    let source_len = u64::from_le_bytes(read_exact_array(&mut reader)?);
    let payload_len = u64::from_le_bytes(read_exact_array(&mut reader)?);
    let source_format = SnapshotFormat::from_version(read_exact_array::<1>(&mut reader)?[0])?;
    let storage_mode = storage_mode_from_byte(read_exact_array::<1>(&mut reader)?[0])?;
    if read_exact_array::<6>(&mut reader)? != [0; 6] {
        return Err(invalid_data("restore manifest reserved bytes are not zero"));
    }
    let manifest = PendingRestore {
        id,
        source_len,
        payload_len,
        source_format,
        storage_mode,
        source_sha256: read_exact_array(&mut reader)?,
        payload_sha256: read_exact_array(&mut reader)?,
        data_dir_hash: read_exact_array(&mut reader)?,
        journal_dir_hash: read_exact_array(&mut reader)?,
        encryption_paths_hash: read_exact_array(&mut reader)?,
    };
    if manifest.source_len == 0 || manifest.payload_len == 0 {
        return Err(invalid_data("restore manifest contains an empty snapshot"));
    }
    Ok(manifest)
}

fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hash_reader(reader: &mut impl Read) -> io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

fn hash_path(path: &Path) -> [u8; 32] {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        hash_bytes(path.as_os_str().as_bytes())
    }
    #[cfg(not(unix))]
    hash_bytes(path.to_string_lossy().as_bytes())
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_sha256(value: &str) -> io::Result<[u8; 32]> {
    let value = value.trim();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "snapshot checksum must be exactly 64 hexadecimal characters",
        ));
    }
    let mut digest = [0; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "snapshot checksum is invalid")
        })?;
    }
    Ok(digest)
}

#[cfg(unix)]
fn available_space(path: &Path) -> io::Result<u64> {
    use std::mem::MaybeUninit;
    use std::os::unix::ffi::OsStrExt;

    let mut existing = path;
    while !existing.try_exists()? {
        existing = existing.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("state path has no existing ancestor: {}", path.display()),
            )
        })?;
    }
    let path = CString::new(existing.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("state path contains a NUL byte: {}", existing.display()),
        )
    })?;
    let mut stats = MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `path` is a NUL-terminated C string and `stats` points to writable,
    // correctly aligned storage for one statvfs result.
    if unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: statvfs returned success and initialized the result.
    let stats = unsafe { stats.assume_init() };
    let block_size = if stats.f_frsize == 0 {
        stats.f_bsize
    } else {
        stats.f_frsize
    };
    // libc exposes this field as different unsigned widths across Unix targets.
    #[allow(clippy::useless_conversion)]
    let available_blocks = u64::from(stats.f_bavail);
    Ok(available_blocks.saturating_mul(block_size))
}

#[cfg(not(unix))]
fn available_space(_path: &Path) -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "transactional restore requires Unix filesystem space reporting",
    ))
}

fn require_space(path: &Path, required: u64) -> io::Result<()> {
    let available = available_space(path)?;
    require_capacity(path, required, available)
}

fn require_capacity(path: &Path, required: u64, available: u64) -> io::Result<()> {
    if available < required {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            format!(
                "insufficient free space for restore in {}: {required} bytes required, {available} available",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn validation_store(config: &ServerConfig) -> io::Result<Store> {
    let mut validation = config.clone();
    validation.storage.mode = StorageMode::Memory;
    validation.durability.policy = DurabilityPolicy::Ephemeral;
    validation.save_interval = std::time::Duration::ZERO;
    validation.encryption.auto_init = false;
    Store::try_new_with_config(Arc::new(validation))
}

fn prepare_candidate_runtime(store: &Store) -> io::Result<()> {
    if !store.config().auth.enabled {
        return Ok(());
    }
    let cache = Arc::new(parking_lot::RwLock::new(crate::tables::SchemaCache::new()));
    crate::auth::bootstrap(store, &cache, &store.config().auth)
        .and_then(|()| crate::auth::bootstrap_runtime(store, &cache, &store.config().auth))
        .map_err(|error| invalid_data(format!("restore auth compatibility failed: {error}")))
}

fn write_private_new(path: &Path, bytes: &[u8]) -> io::Result<fs::File> {
    let mut file = crate::file_security::open_private_file(path, |options| {
        options.create_new(true).read(true).write(true);
    })?;
    file.write_all(bytes)?;
    file.sync_all()?;
    crate::file_security::verify_installed_file(path, &file)?;
    Ok(file)
}

fn configured_encryption_path(
    configured: Option<&str>,
    config: &ServerConfig,
    default_name: &str,
) -> Option<PathBuf> {
    if configured == Some("") {
        None
    } else {
        Some(
            configured
                .map(PathBuf::from)
                .unwrap_or_else(|| data_dir(config).join(default_name)),
        )
    }
}

fn encryption_paths_hash(config: &ServerConfig) -> io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(b"lux restore encryption paths\0");
    for path in [
        configured_encryption_path(config.encryption.state_path.as_deref(), config, "lux.enc"),
        configured_encryption_path(
            config.encryption.seal_path.as_deref(),
            config,
            "lux.enc.seal",
        ),
    ] {
        match path {
            Some(path) => {
                let path = if path.is_absolute() {
                    path
                } else {
                    std::env::current_dir()?.join(path)
                };
                hasher.update([1]);
                hasher.update(hash_path(&path));
            }
            None => hasher.update([0]),
        }
    }
    Ok(hasher.finalize().into())
}

fn encryption_backup_files(config: &ServerConfig) -> io::Result<Vec<(PathBuf, &'static str, u64)>> {
    let mut files = Vec::new();
    for (path, backup_name) in [
        (
            configured_encryption_path(config.encryption.state_path.as_deref(), config, "lux.enc"),
            "encryption-state",
        ),
        (
            configured_encryption_path(
                config.encryption.seal_path.as_deref(),
                config,
                "lux.enc.seal",
            ),
            "encryption-seal",
        ),
    ] {
        let Some(path) = path else {
            continue;
        };
        if crate::file_security::regular_file_exists(&path)? {
            let file = crate::file_security::open_private_file(&path, |options| {
                options.read(true);
            })?;
            files.push((path, backup_name, file.metadata()?.len()));
        }
    }
    Ok(files)
}

fn copy_private_once(source: &Path, destination: &Path) -> io::Result<()> {
    let mut source_file = crate::file_security::open_private_file(source, |options| {
        options.read(true);
    })?;
    if crate::file_security::regular_file_exists(destination)? {
        let mut destination_file =
            crate::file_security::open_private_file(destination, |options| {
                options.read(true);
            })?;
        if source_file.metadata()?.len() == destination_file.metadata()?.len()
            && hash_reader(&mut source_file)? == hash_reader(&mut destination_file)?
        {
            return Ok(());
        }
        return Err(invalid_data(format!(
            "restore backup collision at {}",
            destination.display()
        )));
    }

    let parent = destination
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "backup path has no parent"))?;
    let temporary = parent.join(format!(
        ".{}.tmp",
        destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid_data("restore backup filename is invalid"))?
    ));
    remove_regular_if_present(&temporary)?;
    let copy = (|| {
        source_file.seek(SeekFrom::Start(0))?;
        let mut temporary_file = crate::file_security::open_private_file(&temporary, |options| {
            options.create_new(true).read(true).write(true);
        })?;
        io::copy(&mut source_file, &mut temporary_file)?;
        temporary_file.sync_all()?;
        temporary_file.seek(SeekFrom::Start(0))?;
        source_file.seek(SeekFrom::Start(0))?;
        if source_file.metadata()?.len() != temporary_file.metadata()?.len()
            || hash_reader(&mut source_file)? != hash_reader(&mut temporary_file)?
        {
            return Err(invalid_data(
                "restore encryption backup failed verification",
            ));
        }
        fs::rename(&temporary, destination)?;
        crate::file_security::verify_installed_file(destination, &temporary_file)?;
        crate::disk::sync_directory(parent)
    })();
    if copy.is_err() {
        let _ = remove_regular_if_present(&temporary);
    }
    copy
}

fn remove_regular_if_present(path: &Path) -> io::Result<bool> {
    if !crate::file_security::regular_file_exists(path)? {
        return Ok(false);
    }
    fs::remove_file(path)?;
    Ok(true)
}

fn clean_uncommitted_stage(config: &ServerConfig) -> io::Result<()> {
    let root = data_dir(config);
    let mut changed = false;
    changed |= remove_regular_if_present(&staged_path(config))?;
    changed |= remove_regular_if_present(&pending_tmp_path(config))?;
    if changed {
        crate::disk::sync_directory(&root)?;
    }
    Ok(())
}

pub(crate) fn stage_restore(
    store: &Store,
    source: &[u8],
    expected_source_sha256: Option<&str>,
) -> io::Result<StagedRestore> {
    if !store.config().durability.policy.is_persistent() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "restore requires a persistent durability policy",
        ));
    }
    let _snapshot_guard = store.snapshot_guard();
    let config = store.config();
    let root = data_dir(config);
    crate::disk::create_dir_all_synced(&root)?;
    if crate::file_security::regular_file_exists(&pending_path(config))? {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "another restore is already staged and awaiting restart",
        ));
    }
    clean_uncommitted_stage(config)?;

    let source_len = u64::try_from(source.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "snapshot is too large"))?;
    if source_len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "restore payload is empty",
        ));
    }
    let source_sha256 = hash_bytes(source);
    if let Some(expected) = expected_source_sha256 {
        if decode_sha256(expected)? != source_sha256 {
            return Err(invalid_data(
                "snapshot checksum does not match the request header",
            ));
        }
    }

    let validation = validation_store(config)?;
    let (source_format, entries, canonical) = snapshot::canonicalize_restore(
        &validation,
        Cursor::new(source),
        prepare_candidate_runtime,
    )?;
    let payload_len = u64::try_from(canonical.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "snapshot is too large"))?;
    let payload_sha256 = hash_bytes(&canonical);
    let mut id = [0; 16];
    loop {
        OsRng.fill_bytes(&mut id);
        if id != [0; 16] {
            break;
        }
    }
    let manifest = PendingRestore {
        id,
        source_len,
        payload_len,
        source_format,
        storage_mode: config.storage.mode,
        source_sha256,
        payload_sha256,
        data_dir_hash: hash_path(&root),
        journal_dir_hash: hash_path(&config.journal_dir()),
        encryption_paths_hash: encryption_paths_hash(config)?,
    };
    let manifest_bytes = encode_manifest(&manifest);
    let required = payload_len
        .checked_add(manifest_bytes.len() as u64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "restore size overflow"))?;
    require_space(&root, required)?;

    let staged = staged_path(config);
    let marker_tmp = pending_tmp_path(config);
    let marker = pending_path(config);
    let publish = (|| {
        let mut staged_file = write_private_new(&staged, &canonical)?;
        staged_file.seek(SeekFrom::Start(0))?;
        if staged_file.metadata()?.len() != payload_len
            || hash_reader(&mut staged_file)? != payload_sha256
        {
            return Err(invalid_data(
                "staged restore snapshot failed read-back verification",
            ));
        }
        crate::disk::sync_directory(&root)?;

        let marker_file = write_private_new(&marker_tmp, &manifest_bytes)?;
        crate::file_security::ensure_regular_or_missing(&marker)?;
        fs::rename(&marker_tmp, &marker)?;
        crate::file_security::verify_installed_file(&marker, &marker_file)?;
        crate::disk::sync_directory(&root)
    })();
    if let Err(error) = publish {
        if !crate::file_security::regular_file_exists(&marker).unwrap_or(true) {
            let _ = clean_uncommitted_stage(config);
        }
        return Err(error);
    }

    Ok(StagedRestore {
        id: restore_id_hex(&id),
        source_len,
        payload_len,
        entries,
        source_format: source_format.version(),
        format: SnapshotFormat::V6.version(),
        source_sha256: hex_bytes(&source_sha256),
        sha256: hex_bytes(&payload_sha256),
    })
}

fn read_pending(config: &ServerConfig) -> io::Result<Option<(PendingRestore, Vec<u8>)>> {
    let path = pending_path(config);
    if !crate::file_security::regular_file_exists(&path)? {
        clean_uncommitted_stage(config)?;
        return Ok(None);
    }
    let mut file = crate::file_security::open_private_file(&path, |options| {
        options.read(true);
    })?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let manifest = decode_manifest(&bytes)?;
    Ok(Some((manifest, bytes)))
}

pub(crate) fn pending_restore_status(store: &Store) -> io::Result<Option<PendingRestoreStatus>> {
    let _snapshot_guard = store.snapshot_guard();
    let config = store.config();
    let Some((manifest, _)) = read_pending(config)? else {
        return Ok(None);
    };
    validate_binding(config, &manifest)?;
    validate_candidate(config, &staged_path(config), &manifest)?;
    Ok(Some(PendingRestoreStatus {
        id: restore_id_hex(&manifest.id),
        source_len: manifest.source_len,
        payload_len: manifest.payload_len,
        source_format: manifest.source_format.version(),
        format: SnapshotFormat::V6.version(),
        source_sha256: hex_bytes(&manifest.source_sha256),
        sha256: hex_bytes(&manifest.payload_sha256),
    }))
}

fn validate_binding(config: &ServerConfig, manifest: &PendingRestore) -> io::Result<()> {
    if manifest.storage_mode != config.storage.mode
        || manifest.data_dir_hash != hash_path(&data_dir(config))
        || manifest.journal_dir_hash != hash_path(&config.journal_dir())
        || manifest.encryption_paths_hash != encryption_paths_hash(config)?
    {
        return Err(invalid_data(
            "restore was staged for a different persistence configuration",
        ));
    }
    Ok(())
}

fn validate_candidate(
    config: &ServerConfig,
    path: &Path,
    manifest: &PendingRestore,
) -> io::Result<()> {
    let mut file = crate::file_security::open_private_file(path, |options| {
        options.read(true);
    })?;
    if file.metadata()?.len() != manifest.payload_len {
        return Err(invalid_data(
            "staged restore snapshot length does not match its manifest",
        ));
    }
    if hash_reader(&mut file)? != manifest.payload_sha256 {
        return Err(invalid_data(
            "staged restore snapshot checksum does not match its manifest",
        ));
    }
    file.seek(SeekFrom::Start(0))?;
    let validation = validation_store(config)?;
    let (format, _) = snapshot::validate_restore_reader(&validation, file)?;
    if format != SnapshotFormat::V6 {
        return Err(invalid_data(
            "staged restore snapshot is not in the current format",
        ));
    }
    Ok(())
}

fn ensure_directory_or_missing(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(invalid_data(format!(
            "unsafe state path {}: symbolic links are not allowed",
            path.display()
        ))),
        Ok(metadata) if !metadata.is_dir() => Err(invalid_data(format!(
            "unsafe state path {}: expected a directory",
            path.display()
        ))),
        Ok(_) => {
            crate::file_security::ensure_existing_private_dir(path)?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn move_file_once(source: &Path, destination: &Path) -> io::Result<()> {
    let source_exists = crate::file_security::regular_file_exists(source)?;
    let destination_exists = crate::file_security::regular_file_exists(destination)?;
    match (source_exists, destination_exists) {
        (true, false) => {
            let parent = destination.parent().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "backup path has no parent")
            })?;
            crate::disk::create_dir_all_synced(parent)?;
            fs::rename(source, destination)?;
            crate::disk::sync_directory(source.parent().unwrap_or(Path::new(".")))?;
            crate::disk::sync_directory(parent)
        }
        (false, true) | (false, false) => Ok(()),
        (true, true) => Err(invalid_data(format!(
            "restore backup collision between {} and {}",
            source.display(),
            destination.display()
        ))),
    }
}

fn move_directory_once(source: &Path, destination: &Path) -> io::Result<()> {
    let source_exists = ensure_directory_or_missing(source)?;
    let destination_exists = ensure_directory_or_missing(destination)?;
    match (source_exists, destination_exists) {
        (true, false) => {
            let parent = destination.parent().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "backup path has no parent")
            })?;
            crate::disk::create_dir_all_synced(parent)?;
            fs::rename(source, destination)?;
            crate::disk::sync_directory(source.parent().unwrap_or(Path::new(".")))?;
            crate::disk::sync_directory(parent)
        }
        (false, true) | (false, false) => Ok(()),
        (true, true) => Err(invalid_data(format!(
            "restore backup collision between {} and {}",
            source.display(),
            destination.display()
        ))),
    }
}

fn is_owned_state_directory(name: &str) -> bool {
    name == "global"
        || name.strip_prefix("shard_").is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn backup_current_state(
    config: &ServerConfig,
    manifest: &PendingRestore,
    manifest_bytes: &[u8],
    encryption_files: &[(PathBuf, &'static str, u64)],
) -> io::Result<()> {
    let backup_data = ensure_backup_dir(&data_dir(config), &manifest.id, "data")?;
    move_file_once(&snapshot_path(config), &backup_data.join("lux.dat"))?;
    for (source, backup_name, _) in encryption_files {
        copy_private_once(source, &backup_data.join(backup_name))?;
    }

    match config.storage.mode {
        StorageMode::Memory => {
            move_directory_once(&config.journal_dir(), &backup_data.join("journal"))?;
        }
        StorageMode::Tiered => {
            let state_root = PathBuf::from(&config.storage.dir);
            let backup_state = ensure_backup_dir(&state_root, &manifest.id, "state")?;
            let mut owned = Vec::new();
            for entry in fs::read_dir(&state_root)? {
                let entry = entry?;
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                if is_owned_state_directory(name) {
                    owned.push(name.to_owned());
                }
            }
            owned.sort();
            for name in owned {
                move_directory_once(&state_root.join(&name), &backup_state.join(&name))?;
            }
        }
    }

    let complete = backup_complete_path(config, &manifest.id);
    if !crate::file_security::regular_file_exists(&complete)? {
        write_private_new(&complete, manifest_bytes)?;
        crate::disk::sync_directory(
            complete
                .parent()
                .expect("backup-complete path always has a parent"),
        )?;
    } else {
        let mut file = crate::file_security::open_private_file(&complete, |options| {
            options.read(true);
        })?;
        let mut installed = Vec::new();
        file.read_to_end(&mut installed)?;
        if installed != manifest_bytes {
            return Err(invalid_data(
                "restore backup marker does not match the pending restore",
            ));
        }
    }
    Ok(())
}

fn install_snapshot(config: &ServerConfig, manifest: &PendingRestore) -> io::Result<()> {
    let staged = staged_path(config);
    let destination = snapshot_path(config);
    if crate::file_security::regular_file_exists(&staged)? {
        crate::file_security::ensure_regular_or_missing(&destination)?;
        if crate::file_security::regular_file_exists(&destination)? {
            return Err(invalid_data(
                "live snapshot still exists after restore backup completed",
            ));
        }
        fs::rename(&staged, &destination)?;
        crate::disk::sync_directory(&data_dir(config))?;
    }
    validate_candidate(config, &destination, manifest)
}

fn install_successor_journal(config: &ServerConfig) -> io::Result<()> {
    let snapshot = snapshot_path(config);
    let generation = snapshot::authorized_global_successor(&snapshot)?
        .ok_or_else(|| invalid_data("restored snapshot does not authorize a successor journal"))?;
    drop(Wal::create_named_with_generation(
        &config.journal_dir(),
        "global",
        generation,
    )?);
    Ok(())
}

pub(crate) fn commit_pending_restore(config: &ServerConfig) -> io::Result<bool> {
    let Some((manifest, manifest_bytes)) = read_pending(config)? else {
        return Ok(false);
    };
    if !config.durability.policy.is_persistent() {
        return Err(invalid_data(
            "pending restore cannot commit under an ephemeral durability policy",
        ));
    }
    validate_binding(config, &manifest)?;

    let complete = backup_complete_path(config, &manifest.id);
    let backup_complete = crate::file_security::regular_file_exists(&complete)?;
    let candidate = if crate::file_security::regular_file_exists(&staged_path(config))? {
        staged_path(config)
    } else if backup_complete {
        snapshot_path(config)
    } else {
        return Err(invalid_data(
            "pending restore is missing its staged snapshot before backup completion",
        ));
    };
    validate_candidate(config, &candidate, &manifest)?;

    let encryption_files = encryption_backup_files(config)?;
    let backup_bytes =
        encryption_files
            .iter()
            .try_fold(manifest_bytes.len() as u64, |total, (_, _, len)| {
                total.checked_add(*len).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "restore backup size overflow")
                })
            })?;
    require_space(&data_dir(config), backup_bytes)?;
    require_space(&config.journal_dir(), WAL_HEADER_LEN)?;
    if !backup_complete {
        backup_current_state(config, &manifest, &manifest_bytes, &encryption_files)?;
    }
    #[cfg(test)]
    fault_injection::check(fault_injection::Point::Backup)?;

    install_snapshot(config, &manifest)?;
    #[cfg(test)]
    fault_injection::check(fault_injection::Point::SnapshotInstall)?;

    install_successor_journal(config)?;
    #[cfg(test)]
    fault_injection::check(fault_injection::Point::JournalInstall)?;

    fs::remove_file(pending_path(config))?;
    crate::disk::sync_directory(&data_dir(config))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn config(root: &Path, mode: StorageMode) -> Arc<ServerConfig> {
        let storage = root.join("storage");
        fs::create_dir_all(&storage).unwrap();
        Arc::new(ServerConfig {
            data_dir: root.to_string_lossy().into_owned(),
            storage: crate::StorageConfig {
                mode,
                dir: storage.to_string_lossy().into_owned(),
            },
            durability: crate::DurabilityConfig {
                policy: DurabilityPolicy::AlwaysSync,
                ..Default::default()
            },
            save_interval: std::time::Duration::ZERO,
            ..Default::default()
        })
    }

    fn write(store: &Store, key: &'static [u8], value: &'static [u8]) {
        let command: [&[u8]; 3] = [b"SET", key, value];
        store
            .commit_journaled(&command, || store.set(key, value, None, Instant::now()))
            .unwrap();
    }

    fn snapshot_with(key: &'static [u8], value: &'static [u8]) -> Vec<u8> {
        let source_dir = tempfile::tempdir().unwrap();
        let source_config = config(source_dir.path(), StorageMode::Memory);
        let source = Store::try_new_with_config(source_config).unwrap();
        write(&source, key, value);
        snapshot::save_and_truncate_wal_consistent(&source).unwrap();
        fs::read(source_dir.path().join("lux.dat")).unwrap()
    }

    fn bootstrap_auth(store: &Store) {
        let cache = Arc::new(parking_lot::RwLock::new(crate::tables::SchemaCache::new()));
        crate::auth::bootstrap(store, &cache, &store.config().auth).unwrap();
        crate::auth::bootstrap_runtime(store, &cache, &store.config().auth).unwrap();
    }

    fn open_recovered(config: Arc<ServerConfig>) -> Store {
        let store = Store::try_new_with_config(config).unwrap();
        snapshot::load_for_recovery(&store).unwrap();
        store.replay_wal(&crate::pubsub::Broker::new()).unwrap();
        store
    }

    #[test]
    fn restore_stages_without_mutation_and_retains_an_exact_rollback() {
        let replacement = snapshot_with(b"replacement", b"new");
        let target_dir = tempfile::tempdir().unwrap();
        let target_config = config(target_dir.path(), StorageMode::Memory);
        let target = Store::try_new_with_config(target_config.clone()).unwrap();
        write(&target, b"old", b"snapshot");
        snapshot::save_and_truncate_wal_consistent(&target).unwrap();
        write(&target, b"late", b"journal");

        let source_sha = hex_bytes(&hash_bytes(&replacement));
        let staged = stage_restore(&target, &replacement, Some(&source_sha)).unwrap();
        assert!(target.get(b"old", Instant::now()).is_some());
        assert!(target.get(b"late", Instant::now()).is_some());
        assert!(target.get(b"replacement", Instant::now()).is_none());
        write(&target, b"after-stage", b"durable");
        drop(target);

        assert!(commit_pending_restore(&target_config).unwrap());
        let recovered = open_recovered(target_config.clone());
        assert_eq!(
            recovered
                .get(b"replacement", Instant::now())
                .unwrap()
                .as_ref(),
            b"new"
        );
        assert!(recovered.get(b"old", Instant::now()).is_none());
        assert!(recovered.get(b"late", Instant::now()).is_none());
        drop(recovered);

        let manifest = decode_manifest(
            &fs::read(
                target_dir
                    .path()
                    .join(BACKUP_ROOT)
                    .join(&staged.id)
                    .join(BACKUP_COMPLETE),
            )
            .unwrap(),
        )
        .unwrap();
        let rollback_root = backup_data_dir(&target_config, &manifest.id);
        let mut rollback_config = (*target_config).clone();
        rollback_config.data_dir = rollback_root.to_string_lossy().into_owned();
        rollback_config.storage.mode = StorageMode::Memory;
        let rollback = open_recovered(Arc::new(rollback_config));
        assert_eq!(
            rollback.get(b"old", Instant::now()).unwrap().as_ref(),
            b"snapshot"
        );
        assert_eq!(
            rollback.get(b"late", Instant::now()).unwrap().as_ref(),
            b"journal"
        );
        assert_eq!(
            rollback
                .get(b"after-stage", Instant::now())
                .unwrap()
                .as_ref(),
            b"durable"
        );
        assert!(rollback.get(b"replacement", Instant::now()).is_none());
    }

    #[test]
    fn checksum_and_truncation_fail_before_any_restore_is_published() {
        let replacement = snapshot_with(b"replacement", b"new");
        let target_dir = tempfile::tempdir().unwrap();
        let target_config = config(target_dir.path(), StorageMode::Memory);
        let target = Store::try_new_with_config(target_config.clone()).unwrap();

        let error = stage_restore(&target, &replacement, Some(&"0".repeat(64))).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let truncated = &replacement[..replacement.len() - 1];
        let error = stage_restore(&target, truncated, None).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!pending_path(&target_config).exists());
        assert!(!staged_path(&target_config).exists());
    }

    #[test]
    fn incompatible_target_auth_bootstrap_fails_before_publish() {
        let source_dir = tempfile::tempdir().unwrap();
        let mut source_config = (*config(source_dir.path(), StorageMode::Memory)).clone();
        source_config.auth.enabled = true;
        source_config.auth.initial_publishable_key = Some("lux_shared__source_key".to_string());
        let source = Store::try_new_with_config(Arc::new(source_config)).unwrap();
        bootstrap_auth(&source);
        snapshot::save_and_truncate_wal_consistent(&source).unwrap();
        let replacement = fs::read(source_dir.path().join("lux.dat")).unwrap();

        let target_dir = tempfile::tempdir().unwrap();
        let mut target_config = (*config(target_dir.path(), StorageMode::Memory)).clone();
        target_config.auth.enabled = true;
        target_config.auth.initial_publishable_key = Some("lux_shared__target_key".to_string());
        let target_config = Arc::new(target_config);
        let target = Store::try_new_with_config(target_config.clone()).unwrap();
        bootstrap_auth(&target);
        snapshot::save_and_truncate_wal_consistent(&target).unwrap();

        let error = stage_restore(&target, &replacement, None).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("auth compatibility"), "{error}");
        assert!(snapshot_path(&target_config).exists());
        assert!(!pending_path(&target_config).exists());
        assert!(!staged_path(&target_config).exists());
    }

    #[test]
    fn exact_capacity_check_has_no_arbitrary_reserve() {
        let path = Path::new("restore-volume");
        require_capacity(path, 4096, 4096).unwrap();
        let error = require_capacity(path, 4097, 4096).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::StorageFull);
    }

    #[test]
    fn every_commit_boundary_resumes_to_the_replacement() {
        let replacement = snapshot_with(b"replacement", b"new");
        for point in [
            fault_injection::Point::Backup,
            fault_injection::Point::SnapshotInstall,
            fault_injection::Point::JournalInstall,
        ] {
            let target_dir = tempfile::tempdir().unwrap();
            let target_config = config(target_dir.path(), StorageMode::Memory);
            let target = Store::try_new_with_config(target_config.clone()).unwrap();
            write(&target, b"old", b"state");
            snapshot::save_and_truncate_wal_consistent(&target).unwrap();
            stage_restore(&target, &replacement, None).unwrap();
            drop(target);

            let fault = fault_injection::inject(point);
            assert!(commit_pending_restore(&target_config).is_err());
            drop(fault);
            assert!(commit_pending_restore(&target_config).unwrap());

            let recovered = open_recovered(target_config);
            assert_eq!(
                recovered
                    .get(b"replacement", Instant::now())
                    .unwrap()
                    .as_ref(),
                b"new",
                "restore did not resume after {point:?}"
            );
            assert!(recovered.get(b"old", Instant::now()).is_none());
        }
    }

    #[test]
    fn commit_resumes_after_only_the_old_snapshot_was_backed_up() {
        let replacement = snapshot_with(b"replacement", b"new");
        let target_dir = tempfile::tempdir().unwrap();
        let target_config = config(target_dir.path(), StorageMode::Memory);
        let target = Store::try_new_with_config(target_config.clone()).unwrap();
        write(&target, b"old", b"snapshot");
        snapshot::save_and_truncate_wal_consistent(&target).unwrap();
        write(&target, b"late", b"journal");
        stage_restore(&target, &replacement, None).unwrap();
        drop(target);

        let (manifest, _) = read_pending(&target_config).unwrap().unwrap();
        let backup = ensure_backup_dir(&data_dir(&target_config), &manifest.id, "data").unwrap();
        move_file_once(&snapshot_path(&target_config), &backup.join("lux.dat")).unwrap();

        assert!(commit_pending_restore(&target_config).unwrap());
        let recovered = open_recovered(target_config.clone());
        assert_eq!(
            recovered
                .get(b"replacement", Instant::now())
                .unwrap()
                .as_ref(),
            b"new"
        );
        drop(recovered);

        let mut rollback_config = (*target_config).clone();
        rollback_config.data_dir = backup.to_string_lossy().into_owned();
        let rollback = open_recovered(Arc::new(rollback_config));
        assert_eq!(
            rollback.get(b"old", Instant::now()).unwrap().as_ref(),
            b"snapshot"
        );
        assert_eq!(
            rollback.get(b"late", Instant::now()).unwrap().as_ref(),
            b"journal"
        );
    }

    #[tokio::test]
    async fn runtime_commits_pending_restore_before_reporting_ready() {
        let replacement = snapshot_with(b"replacement", b"new");
        let target_dir = tempfile::tempdir().unwrap();
        let target_config = config(target_dir.path(), StorageMode::Memory);
        let target = Store::try_new_with_config(target_config.clone()).unwrap();
        write(&target, b"old", b"state");
        snapshot::save_and_truncate_wal_consistent(&target).unwrap();
        stage_restore(&target, &replacement, None).unwrap();
        drop(target);

        let mut runtime_config = (*target_config).clone();
        runtime_config.enable_resp = false;
        runtime_config.http_port = 0;
        let handle = crate::run_with_config(runtime_config).await.unwrap();
        assert_eq!(
            handle.client().get_value("replacement").await.unwrap(),
            crate::EmbeddedValue::Bulk(bytes::Bytes::from_static(b"new"))
        );
        assert_eq!(
            handle.client().get_value("old").await.unwrap(),
            crate::EmbeddedValue::Nil
        );
        handle.shutdown_and_wait().await.unwrap();
        assert!(!pending_path(&target_config).exists());
    }

    #[test]
    fn changed_persistence_binding_fails_before_old_state_moves() {
        let replacement = snapshot_with(b"replacement", b"new");
        let target_dir = tempfile::tempdir().unwrap();
        let target_config = config(target_dir.path(), StorageMode::Memory);
        let target = Store::try_new_with_config(target_config.clone()).unwrap();
        write(&target, b"old", b"state");
        snapshot::save_and_truncate_wal_consistent(&target).unwrap();
        stage_restore(&target, &replacement, None).unwrap();
        drop(target);

        let mut changed = (*target_config).clone();
        changed.storage.mode = StorageMode::Tiered;
        let error = commit_pending_restore(&changed).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(snapshot_path(&target_config).exists());
        assert!(!target_dir.path().join(BACKUP_ROOT).exists());

        let mut changed = (*target_config).clone();
        changed.encryption.state_path = Some(
            target_dir
                .path()
                .join("alternate.enc")
                .to_string_lossy()
                .into_owned(),
        );
        let error = commit_pending_restore(&changed).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(snapshot_path(&target_config).exists());
        assert!(!target_dir.path().join(BACKUP_ROOT).exists());
    }

    #[test]
    fn tiered_restore_backs_up_only_lux_state_directories() {
        let replacement = snapshot_with(b"replacement", b"new");
        let target_dir = tempfile::tempdir().unwrap();
        let target_config = config(target_dir.path(), StorageMode::Tiered);
        let target = Store::try_new_with_config(target_config.clone()).unwrap();
        write(&target, b"old", b"state");
        snapshot::save_and_truncate_wal_consistent(&target).unwrap();
        let storage = PathBuf::from(&target_config.storage.dir);
        fs::write(storage.join("keep.txt"), b"operator-owned").unwrap();
        let staged = stage_restore(&target, &replacement, None).unwrap();
        drop(target);

        commit_pending_restore(&target_config).unwrap();
        assert_eq!(
            fs::read(storage.join("keep.txt")).unwrap(),
            b"operator-owned"
        );
        let backup = storage.join(BACKUP_ROOT).join(staged.id).join("state");
        assert!(backup.join("global").is_dir());
        assert!(fs::read_dir(backup).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("shard_")
        }));
    }

    #[test]
    fn duplicate_stage_is_rejected_and_ephemeral_restore_is_unsupported() {
        let replacement = snapshot_with(b"replacement", b"new");
        let target_dir = tempfile::tempdir().unwrap();
        let target_config = config(target_dir.path(), StorageMode::Memory);
        let target = Store::try_new_with_config(target_config.clone()).unwrap();
        stage_restore(&target, &replacement, None).unwrap();
        assert_eq!(
            stage_restore(&target, &replacement, None)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        drop(target);
        let mut changed = (*target_config).clone();
        changed.durability.policy = DurabilityPolicy::Ephemeral;
        assert_eq!(
            commit_pending_restore(&changed).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(pending_path(&target_config).exists());

        let ephemeral_dir = tempfile::tempdir().unwrap();
        let mut ephemeral_config = (*config(ephemeral_dir.path(), StorageMode::Memory)).clone();
        ephemeral_config.durability.policy = DurabilityPolicy::Ephemeral;
        let ephemeral = Store::try_new_with_config(Arc::new(ephemeral_config)).unwrap();
        assert_eq!(
            stage_restore(&ephemeral, &replacement, None)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn every_historical_snapshot_format_is_canonicalized_to_v6() {
        let empty_body = 0u32.to_le_bytes();
        let mut v5 = b"LUX\x05".to_vec();
        v5.extend_from_slice(&(empty_body.len() as u64).to_le_bytes());
        v5.extend_from_slice(&Sha256::digest(empty_body));
        v5.extend_from_slice(&empty_body);
        let mut v4 = b"LUX\x04".to_vec();
        v4.extend_from_slice(&0u32.to_le_bytes());
        let sources = [
            b"LUX\x01".to_vec(),
            b"LUX\x02".to_vec(),
            b"LUX\x03".to_vec(),
            v4,
            v5,
        ];

        for (index, source) in sources.into_iter().enumerate() {
            let target_dir = tempfile::tempdir().unwrap();
            let target_config = config(target_dir.path(), StorageMode::Memory);
            let target = Store::try_new_with_config(target_config).unwrap();
            let staged = stage_restore(&target, &source, None)
                .unwrap_or_else(|error| panic!("format {} failed: {error}", index + 1));
            assert_eq!(staged.source_format, (index + 1) as u8);
            assert_eq!(staged.format, 6);
            assert!(fs::read(staged_path(target.config()))
                .unwrap()
                .starts_with(b"LUX\x06"));
        }

        let body = 0u32.to_le_bytes();
        let mut unbound_v6 = b"LUX\x06".to_vec();
        unbound_v6.extend_from_slice(&(body.len() as u64).to_le_bytes());
        unbound_v6.extend_from_slice(&Sha256::digest(body));
        unbound_v6.extend_from_slice(&body);
        let target_dir = tempfile::tempdir().unwrap();
        let target_config = config(target_dir.path(), StorageMode::Memory);
        let target = Store::try_new_with_config(target_config.clone()).unwrap();
        let error = stage_restore(&target, &unbound_v6, None).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("global WAL checkpoint"));
        assert!(!pending_path(&target_config).exists());
    }

    #[test]
    fn current_snapshot_from_an_ephemeral_source_restores_to_persistent_storage() {
        let source_dir = tempfile::tempdir().unwrap();
        let mut source_config = (*config(source_dir.path(), StorageMode::Memory)).clone();
        source_config.durability.policy = DurabilityPolicy::Ephemeral;
        let source = Store::try_new_with_config(Arc::new(source_config)).unwrap();
        source.set(b"ephemeral-source", b"value", None, Instant::now());
        snapshot::save_and_truncate_wal_consistent(&source).unwrap();
        let replacement = fs::read(source_dir.path().join("lux.dat")).unwrap();
        drop(source);

        let target_dir = tempfile::tempdir().unwrap();
        let target_config = config(target_dir.path(), StorageMode::Memory);
        let target = Store::try_new_with_config(target_config.clone()).unwrap();
        stage_restore(&target, &replacement, None).unwrap();
        drop(target);
        commit_pending_restore(&target_config).unwrap();

        let recovered = open_recovered(target_config);
        assert_eq!(
            recovered
                .get(b"ephemeral-source", Instant::now())
                .unwrap()
                .as_ref(),
            b"value"
        );
    }

    #[test]
    fn restored_snapshot_rejects_a_foreign_successor_journal() {
        let replacement = snapshot_with(b"replacement", b"new");
        let target_dir = tempfile::tempdir().unwrap();
        let target_config = config(target_dir.path(), StorageMode::Memory);
        let target = Store::try_new_with_config(target_config.clone()).unwrap();
        stage_restore(&target, &replacement, None).unwrap();
        drop(target);
        commit_pending_restore(&target_config).unwrap();

        let donor_dir = tempfile::tempdir().unwrap();
        drop(Wal::open_named(donor_dir.path(), "global").unwrap());
        fs::copy(
            donor_dir.path().join("global/wal.lux"),
            target_config.journal_dir().join("global/wal.lux"),
        )
        .unwrap();

        let rejected = Store::try_new_with_config(target_config).unwrap();
        snapshot::load_for_recovery(&rejected).unwrap();
        assert!(
            rejected.replay_wal(&crate::pubsub::Broker::new()).is_err(),
            "restored state accepted a journal generation it did not authorize"
        );
    }

    #[test]
    fn encrypted_snapshot_is_validated_canonicalized_and_reopened() {
        fn encrypted_config(root: &Path) -> Arc<ServerConfig> {
            let mut config = (*config(root, StorageMode::Memory)).clone();
            config.encryption.active_key_id = Some("restore-key".to_string());
            config.encryption.keys = vec![crate::EncryptionKeyConfig {
                id: "restore-key".to_string(),
                secret: vec![0x5a; 32],
                decrypt_only: false,
            }];
            Arc::new(config)
        }

        let source_dir = tempfile::tempdir().unwrap();
        let source = Store::try_new_with_config(encrypted_config(source_dir.path())).unwrap();
        let command: [&[u8]; 7] = [
            b"VSET",
            b"secret-vector",
            b"2",
            b"1.25",
            b"-2.5",
            b"META",
            b"classified",
        ];
        source
            .commit_journaled(&command, || {
                source.vset(
                    b"secret-vector",
                    vec![1.25, -2.5],
                    Some("classified".to_string()),
                    None,
                    true,
                    Instant::now(),
                )
            })
            .unwrap();
        snapshot::save_and_truncate_wal_consistent(&source).unwrap();
        let replacement = fs::read(source_dir.path().join("lux.dat")).unwrap();
        drop(source);

        let target_dir = tempfile::tempdir().unwrap();
        let target_config = encrypted_config(target_dir.path());
        let target = Store::try_new_with_config(target_config.clone()).unwrap();
        stage_restore(&target, &replacement, None).unwrap();
        drop(target);
        commit_pending_restore(&target_config).unwrap();

        let recovered = open_recovered(target_config);
        let (vector, metadata) = recovered
            .vget(b"secret-vector", Instant::now())
            .expect("encrypted vector was not restored");
        assert_eq!(vector, vec![1.25, -2.5]);
        assert_eq!(metadata.as_deref(), Some("classified"));
    }

    #[test]
    fn native_encryption_state_is_frozen_with_the_rollback() {
        let replacement = snapshot_with(b"replacement", b"new");
        let target_dir = tempfile::tempdir().unwrap();
        let target_config = config(target_dir.path(), StorageMode::Memory);
        let target = Store::try_new_with_config(target_config.clone()).unwrap();
        target.encryption().init(Some("rollback-key")).unwrap();
        let command: [&[u8]; 7] = [
            b"VSET",
            b"old-secret-vector",
            b"2",
            b"3.5",
            b"-7.25",
            b"META",
            b"rollback-only",
        ];
        target
            .commit_journaled(&command, || {
                target.vset(
                    b"old-secret-vector",
                    vec![3.5, -7.25],
                    Some("rollback-only".to_string()),
                    None,
                    true,
                    Instant::now(),
                )
            })
            .unwrap();
        snapshot::save_and_truncate_wal_consistent(&target).unwrap();

        let state_path = target_dir.path().join("lux.enc");
        let seal_path = target_dir.path().join("lux.enc.seal");
        let state_before = fs::read(&state_path).unwrap();
        let seal_before = fs::read(&seal_path).unwrap();
        let staged = stage_restore(&target, &replacement, None).unwrap();
        drop(target);

        commit_pending_restore(&target_config).unwrap();
        let rollback_root = target_dir
            .path()
            .join(BACKUP_ROOT)
            .join(staged.id)
            .join("data");
        let backup_state = rollback_root.join("encryption-state");
        let backup_seal = rollback_root.join("encryption-seal");
        assert_eq!(fs::read(&backup_state).unwrap(), state_before);
        assert_eq!(fs::read(&backup_seal).unwrap(), seal_before);

        let mut rollback_config = (*target_config).clone();
        rollback_config.data_dir = rollback_root.to_string_lossy().into_owned();
        rollback_config.storage.mode = StorageMode::Memory;
        rollback_config.encryption.state_path = Some(backup_state.to_string_lossy().into_owned());
        rollback_config.encryption.seal_path = Some(backup_seal.to_string_lossy().into_owned());
        let rollback = open_recovered(Arc::new(rollback_config));
        let (vector, metadata) = rollback
            .vget(b"old-secret-vector", Instant::now())
            .expect("encrypted rollback value was not recoverable");
        assert_eq!(vector, vec![3.5, -7.25]);
        assert_eq!(metadata.as_deref(), Some("rollback-only"));
        assert!(rollback.get(b"replacement", Instant::now()).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_pending_state_fails_closed() {
        use std::os::unix::fs::symlink;

        let target_dir = tempfile::tempdir().unwrap();
        let target_config = config(target_dir.path(), StorageMode::Memory);
        let outside = target_dir.path().join("outside");
        fs::write(&outside, vec![0; MANIFEST_LEN]).unwrap();
        symlink(&outside, pending_path(&target_config)).unwrap();
        let error = commit_pending_restore(&target_config).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(fs::read(outside).unwrap(), vec![0; MANIFEST_LEN]);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_backup_root_fails_before_current_state_moves() {
        use std::os::unix::fs::symlink;

        let replacement = snapshot_with(b"replacement", b"new");
        let target_dir = tempfile::tempdir().unwrap();
        let target_config = config(target_dir.path(), StorageMode::Memory);
        let target = Store::try_new_with_config(target_config.clone()).unwrap();
        write(&target, b"old", b"state");
        snapshot::save_and_truncate_wal_consistent(&target).unwrap();
        stage_restore(&target, &replacement, None).unwrap();
        drop(target);

        let outside = target_dir.path().join("outside-backup");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, target_dir.path().join(BACKUP_ROOT)).unwrap();
        let error = commit_pending_restore(&target_config).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(snapshot_path(&target_config).is_file());
        assert_eq!(fs::read_dir(outside).unwrap().count(), 0);
    }
}
