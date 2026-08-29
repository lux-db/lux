use rand_core::{OsRng, RngCore};
#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

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

fn validate_directory(path: &Path, metadata: &std::fs::Metadata) -> Result<(), String> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "unsafe directory {}: expected a non-symlink directory",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        if metadata.uid() != effective_uid() {
            return Err(format!(
                "unsafe directory {}: owned by another user",
                path.display()
            ));
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(format!(
                "unsafe directory {}: writable by another user",
                path.display()
            ));
        }
    }
    Ok(())
}

/// Relative state paths are rooted in the project working directory. Reject
/// links below that boundary instead of allowing directory creation to follow
/// them. Absolute home paths treat the selected home directory as the boundary.
fn validate_relative_directories(path: &Path) -> Result<(), String> {
    if path.is_absolute() {
        return Ok(());
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => continue,
            Component::Normal(part) => current.push(part),
            Component::ParentDir => {
                return Err(format!(
                    "unsafe directory {}: parent traversal is not allowed",
                    path.display()
                ));
            }
            Component::RootDir | Component::Prefix(_) => continue,
        }
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) => validate_directory(&current, &metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(format!("inspect {}: {error}", current.display())),
        }
    }
    Ok(())
}

fn ensure_dir(path: &Path, tighten_existing: bool) -> Result<(), String> {
    validate_relative_directories(path)?;
    let existed = match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_directory(path, &metadata)?;
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(format!("inspect {}: {error}", path.display())),
    };
    if !existed {
        std::fs::create_dir_all(path).map_err(|e| format!("create {}: {e}", path.display()))?;
    }
    validate_relative_directories(path)?;
    let metadata =
        std::fs::symlink_metadata(path).map_err(|e| format!("inspect {}: {e}", path.display()))?;
    validate_directory(path, &metadata)?;
    #[cfg(unix)]
    if tighten_existing {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    }
    Ok(())
}

fn ensure_safe_dir(path: &Path) -> Result<(), String> {
    ensure_dir(path, false)
}

pub(crate) fn ensure_private_dir(path: &Path) -> Result<(), String> {
    ensure_dir(path, true)
}

fn inspect_secret_file(path: &Path) -> Result<bool, String> {
    let parent = containing_dir(path);
    validate_relative_directories(parent)?;
    match std::fs::symlink_metadata(parent) {
        Ok(metadata) => validate_directory(parent, &metadata)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("inspect {}: {error}", parent.display())),
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(format!(
            "unsafe secret path {}: symbolic links are not allowed",
            path.display()
        )),
        Ok(metadata) if !metadata.is_file() => Err(format!(
            "unsafe secret path {}: expected a regular file",
            path.display()
        )),
        Ok(_metadata) => {
            #[cfg(unix)]
            if _metadata.uid() != effective_uid() {
                return Err(format!(
                    "unsafe secret path {}: owned by another user",
                    path.display()
                ));
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("inspect {}: {error}", path.display())),
    }
}

#[cfg(unix)]
fn verify_open_secret_file(path: &Path, file: &std::fs::File) -> Result<(), String> {
    let opened = file
        .metadata()
        .map_err(|e| format!("inspect {}: {e}", path.display()))?;
    let installed =
        std::fs::symlink_metadata(path).map_err(|e| format!("inspect {}: {e}", path.display()))?;
    if installed.file_type().is_symlink()
        || !installed.is_file()
        || !opened.is_file()
        || opened.uid() != effective_uid()
        || opened.dev() != installed.dev()
        || opened.ino() != installed.ino()
    {
        return Err(format!(
            "unsafe secret path {}: path changed while it was open",
            path.display()
        ));
    }
    Ok(())
}

pub(crate) fn read_optional_secret_file(path: &Path) -> Result<Option<String>, String> {
    if !inspect_secret_file(path)? {
        return Ok(None);
    }
    #[cfg(not(unix))]
    return Err(format!(
        "refusing to read {} because owner-only secret files are unsupported on this platform",
        path.display()
    ));

    #[cfg(unix)]
    {
        let mut options = OpenOptions::new();
        options.read(true);
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let mut file = options
            .open(path)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        verify_open_secret_file(path, &file)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod {}: {e}", path.display()))?;
        let mut data = String::new();
        file.read_to_string(&mut data)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        Ok(Some(data))
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.read(true);
    options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options
        .open(path)
        .and_then(|dir| dir.sync_all())
        .map_err(|e| format!("sync {}: {e}", path.display()))
}

/// Atomically replace a secret-bearing file and force owner-only permissions.
pub(crate) fn write_secret_file(path: &Path, data: &[u8]) -> Result<(), String> {
    #[cfg(not(unix))]
    {
        let _ = data;
        return Err(format!(
            "refusing to write {} because owner-only secret files are unsupported on this platform",
            path.display()
        ));
    }

    #[cfg(unix)]
    {
        let parent = containing_dir(path);
        ensure_safe_dir(parent)?;
        inspect_secret_file(path)?;
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("lux-secret");
        let tmp = path.with_file_name(format!(".{filename}.tmp-{}", random_hex(16)));
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let mut file = options
            .open(&tmp)
            .map_err(|e| format!("write {}: {e}", path.display()))?;
        let result = file
            .write_all(data)
            .and_then(|_| file.sync_all())
            .map_err(|e| format!("write {}: {e}", path.display()))
            .and_then(|_| inspect_secret_file(path).map(|_| ()))
            .and_then(|_| {
                std::fs::rename(&tmp, path).map_err(|e| format!("replace {}: {e}", path.display()))
            })
            .and_then(|_| verify_open_secret_file(path, &file))
            .and_then(|_| sync_directory(parent));
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }
}

pub(crate) fn delete_secret_file(path: &Path) -> Result<(), String> {
    if !inspect_secret_file(path)? {
        return Ok(());
    }
    #[cfg(not(unix))]
    return Err(format!(
        "refusing to delete {} because secure state-file handling is unsupported on this platform",
        path.display()
    ));

    #[cfg(unix)]
    {
        std::fs::remove_file(path).map_err(|e| format!("delete {}: {e}", path.display()))?;
        sync_directory(containing_dir(path))
    }
}

/// Hex-encode bytes from the operating system CSPRNG.
pub(crate) fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn secret_files_are_owner_only_and_atomic() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("lux-cli-secret-test-{}", random_hex(8)));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = dir.join("secret.env");
        write_secret_file(&path, b"LUX_SECRET_KEY=test\n").unwrap();
        write_secret_file(&path, b"LUX_SECRET_KEY=replaced\n").unwrap();

        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o755,
            "writing a file must not tighten the caller-owned project root"
        );
        assert_eq!(
            read_optional_secret_file(&path).unwrap().unwrap(),
            "LUX_SECRET_KEY=replaced\n"
        );
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_and_unexpected_types_are_rejected() {
        use std::os::unix::fs::symlink;

        let dir = std::env::temp_dir().join(format!("lux-cli-link-test-{}", random_hex(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target");
        std::fs::write(&target, b"unchanged").unwrap();
        let linked = dir.join("linked.env");
        symlink(&target, &linked).unwrap();

        assert!(read_optional_secret_file(&linked).is_err());
        assert!(write_secret_file(&linked, b"replacement").is_err());
        assert!(delete_secret_file(&linked).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"unchanged");

        let unexpected = dir.join("directory.env");
        std::fs::create_dir(&unexpected).unwrap();
        assert!(write_secret_file(&unexpected, b"replacement").is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn relative_intermediate_symlinks_are_rejected() {
        use std::os::unix::fs::symlink;

        let root = PathBuf::from(format!(".lux-cli-path-test-{}", random_hex(8)));
        std::fs::create_dir(&root).unwrap();
        let target = root.join("target");
        std::fs::create_dir(&target).unwrap();
        symlink(&target, root.join("lux")).unwrap();

        assert!(ensure_safe_dir(&root.join("lux").join("profiles")).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bare_secret_filename_uses_the_working_directory() {
        assert_eq!(containing_dir(Path::new(".env.local")), Path::new("."));
    }

    #[cfg(unix)]
    #[test]
    fn identity_check_rejects_replacement_after_open() {
        let dir = std::env::temp_dir().join(format!("lux-cli-race-test-{}", random_hex(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret.env");
        std::fs::write(&path, b"original").unwrap();
        let file = OpenOptions::new().read(true).open(&path).unwrap();
        std::fs::rename(&path, dir.join("moved.env")).unwrap();
        std::fs::write(&path, b"replacement").unwrap();

        assert!(verify_open_secret_file(&path, &file).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
