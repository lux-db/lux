use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

fn invalid_path(path: &Path, reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unsafe state path {}: {reason}", path.display()),
    )
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    // SAFETY: geteuid has no arguments, memory access, or caller preconditions.
    unsafe { libc::geteuid() }
}

fn containing_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn validate_directory(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(invalid_path(path, "expected a non-symlink directory"));
    }
    #[cfg(unix)]
    {
        if metadata.uid() != effective_uid() {
            return Err(invalid_path(path, "directory is owned by another user"));
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(invalid_path(path, "directory is writable by another user"));
        }
    }
    Ok(())
}

/// Relative state paths are rooted in the process working directory, which is
/// the caller's trust boundary. Reject links and unsafe directories below that
/// boundary instead of allowing `create_dir_all` to traverse them.
fn validate_relative_components(path: &Path) -> io::Result<()> {
    if path.is_absolute() {
        return Ok(());
    }
    let mut current = PathBuf::new();
    let mut inspect_existing = true;
    for component in path.components() {
        match component {
            Component::CurDir => continue,
            Component::Normal(part) => current.push(part),
            Component::ParentDir => {
                return Err(invalid_path(path, "parent traversal is not allowed"));
            }
            Component::RootDir | Component::Prefix(_) => continue,
        }
        if inspect_existing {
            match fs::symlink_metadata(&current) {
                Ok(metadata) => validate_directory(&current, &metadata)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    inspect_existing = false;
                }
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

pub(crate) fn ensure_regular_or_missing(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(invalid_path(path, "symbolic links are not allowed"))
        }
        Ok(metadata) if !metadata.is_file() => Err(invalid_path(path, "expected a regular file")),
        Ok(_metadata) => {
            #[cfg(unix)]
            if _metadata.uid() != effective_uid() {
                return Err(invalid_path(path, "file is owned by another user"));
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(crate) fn regular_file_exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(invalid_path(path, "symbolic links are not allowed"))
        }
        Ok(_metadata) if _metadata.is_file() => {
            #[cfg(unix)]
            if _metadata.uid() != effective_uid() {
                return Err(invalid_path(path, "file is owned by another user"));
            }
            Ok(true)
        }
        Ok(_) => Err(invalid_path(path, "expected a regular file")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn ensure_dir(path: &Path, tighten_existing: bool) -> io::Result<()> {
    validate_relative_components(path)?;
    let existed = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_directory(path, &metadata)?;
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error),
    };
    if !existed {
        fs::create_dir_all(path)?;
    }
    validate_relative_components(path)?;
    let metadata = fs::symlink_metadata(path)?;
    validate_directory(path, &metadata)?;

    #[cfg(unix)]
    if tighten_existing || !existed {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Validate a caller-owned directory and create it privately when missing.
/// Existing project roots keep their current non-writable-by-others mode.
pub(crate) fn ensure_safe_dir(path: &Path) -> io::Result<()> {
    ensure_dir(path, false)
}

/// Validate and tighten a dedicated Lux state directory to owner-only access.
pub(crate) fn ensure_private_dir(path: &Path) -> io::Result<()> {
    ensure_dir(path, true)
}

/// Validate and tighten an existing dedicated Lux state directory without
/// creating it. Recovery uses this when the presence of the directory itself
/// is part of the durable-state contract.
pub(crate) fn ensure_existing_private_dir(path: &Path) -> io::Result<()> {
    validate_relative_components(path)?;
    let metadata = fs::symlink_metadata(path)?;
    validate_directory(path, &metadata)?;

    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;

    Ok(())
}

/// Open a persisted engine file without following a final-component symlink.
/// Existing files are tightened to owner-only access on Unix. Other platforms
/// fail closed because Rust does not expose a portable owner-only ACL.
pub(crate) fn open_private_file(
    path: &Path,
    configure: impl FnOnce(&mut OpenOptions),
) -> io::Result<File> {
    ensure_safe_dir(containing_dir(path))?;
    ensure_regular_or_missing(path)?;

    #[cfg(not(unix))]
    {
        let _ = configure;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing persisted state file {} because owner-only permissions are unsupported on this platform",
                path.display()
            ),
        ));
    }

    #[cfg(unix)]
    {
        let mut options = OpenOptions::new();
        configure(&mut options);
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options.open(path)?;
        let opened = file.metadata()?;
        if !opened.is_file() {
            return Err(invalid_path(path, "expected a regular file"));
        }

        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        verify_installed_file(path, &file)?;

        Ok(file)
    }
}

pub(crate) fn verify_installed_file(path: &Path, file: &File) -> io::Result<()> {
    let opened = file.metadata()?;
    if !opened.is_file() {
        return Err(invalid_path(path, "expected a regular file"));
    }
    let installed = fs::symlink_metadata(path)?;
    if installed.file_type().is_symlink() || !installed.is_file() {
        return Err(invalid_path(path, "expected a non-symlink regular file"));
    }
    #[cfg(unix)]
    if opened.uid() != effective_uid()
        || opened.dev() != installed.dev()
        || opened.ino() != installed.ino()
    {
        return Err(invalid_path(path, "path changed while it was opened"));
    }
    Ok(())
}

/// Hold an exclusive advisory lock for a persistent state directory.
///
/// The lock file is never removed: unlinking a live lock file would let a
/// second process lock a different inode under the same name. Dropping the
/// returned handle releases the lock.
pub(crate) fn lock_state_dir(path: &Path) -> io::Result<File> {
    ensure_safe_dir(path)?;
    let lock_path = path.join(".lux.lock");
    let file = open_private_file(&lock_path, |options| {
        options.create(true).read(true).write(true);
    })?;

    #[cfg(not(unix))]
    return Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "persistent state locking is unsupported on this platform",
    ));

    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;

        // SAFETY: flock only reads the valid descriptor and integer flags.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = io::Error::last_os_error();
            let kind = if error.kind() == io::ErrorKind::WouldBlock {
                io::ErrorKind::AlreadyExists
            } else {
                error.kind()
            };
            return Err(io::Error::new(
                kind,
                format!(
                    "persistent state directory {} is already in use or cannot be locked: {error}",
                    path.display()
                ),
            ));
        }
        Ok(file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn private_files_and_directories_are_owner_only() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("state");
        ensure_private_dir(&dir).unwrap();
        let path = dir.join("state.lux");
        open_private_file(&path, |options| {
            options.create_new(true).write(true);
        })
        .unwrap();

        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn existing_private_directory_check_never_creates_state() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing");
        let error = ensure_existing_private_dir(&missing).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(!missing.exists());

        let existing = root.path().join("existing");
        fs::create_dir(&existing).unwrap();
        fs::set_permissions(&existing, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_existing_private_dir(&existing).unwrap();
        assert_eq!(
            fs::metadata(existing).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_files_and_directories_are_rejected() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let real_dir = root.path().join("real");
        fs::create_dir(&real_dir).unwrap();
        let linked_dir = root.path().join("linked");
        symlink(&real_dir, &linked_dir).unwrap();
        assert!(ensure_private_dir(&linked_dir).is_err());

        let real_file = root.path().join("real-file");
        fs::write(&real_file, b"state").unwrap();
        let linked_file = root.path().join("linked-file");
        symlink(&real_file, &linked_file).unwrap();
        assert!(open_private_file(&linked_file, |options| {
            options.read(true);
        })
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn regular_file_probes_reject_unexpected_types_and_tighten_permissions() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing");
        assert!(!regular_file_exists(&missing).unwrap());
        ensure_regular_or_missing(&missing).unwrap();

        let path = root.path().join("state.lux");
        fs::write(&path, b"state").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(regular_file_exists(&path).unwrap());
        open_private_file(&path, |options| {
            options.read(true);
        })
        .unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let directory = root.path().join("not-a-file");
        fs::create_dir(&directory).unwrap();
        assert!(regular_file_exists(&directory).is_err());
        assert!(ensure_regular_or_missing(&directory).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn writable_by_others_directory_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("unsafe");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();

        let error = ensure_safe_dir(&directory).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("writable by another user"));
    }

    #[cfg(unix)]
    #[test]
    fn replaced_path_is_rejected_after_open() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("state.lux");
        let file = open_private_file(&path, |options| {
            options.create_new(true).write(true);
        })
        .unwrap();
        fs::rename(&path, root.path().join("moved.lux")).unwrap();
        fs::write(&path, b"replacement").unwrap();

        assert!(verify_installed_file(&path, &file).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn installed_file_verification_rejects_non_files_on_either_side() {
        let root = tempfile::tempdir().unwrap();
        let directory_handle = File::open(root.path()).unwrap();
        assert!(verify_installed_file(root.path(), &directory_handle).is_err());

        let source = root.path().join("source");
        fs::write(&source, b"state").unwrap();
        let source_handle = File::open(&source).unwrap();
        let destination = root.path().join("destination");
        fs::create_dir(&destination).unwrap();
        assert!(verify_installed_file(&destination, &source_handle).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn persistent_directory_lock_is_exclusive_until_its_handle_drops() {
        let root = tempfile::tempdir().unwrap();
        let first = lock_state_dir(root.path()).unwrap();
        let error = lock_state_dir(root.path()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);

        drop(first);
        lock_state_dir(root.path()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn relative_intermediate_symlinks_are_rejected() {
        use std::os::unix::fs::symlink;

        let current = std::env::current_dir().unwrap();
        let root = tempfile::Builder::new()
            .prefix(".lux-path-test-")
            .tempdir_in(&current)
            .unwrap();
        let relative = root.path().strip_prefix(&current).unwrap();
        let target = root.path().join("target");
        fs::create_dir(&target).unwrap();
        symlink(&target, root.path().join("linked")).unwrap();

        assert!(ensure_safe_dir(&relative.join("linked").join("state")).is_err());
    }

    #[test]
    fn parent_traversal_is_rejected_even_after_a_missing_component() {
        let path = Path::new("missing-state-dir").join("..").join("escape");
        let error = ensure_safe_dir(&path).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("parent traversal"));
    }
}
