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
    for component in path.components() {
        match component {
            Component::CurDir => continue,
            Component::Normal(part) => current.push(part),
            Component::ParentDir => {
                return Err(invalid_path(path, "parent traversal is not allowed"));
            }
            Component::RootDir | Component::Prefix(_) => continue,
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) => validate_directory(&current, &metadata)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error) => return Err(error),
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
}
