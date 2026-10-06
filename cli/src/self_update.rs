use colored::Colorize;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use super::file_security::{ensure_private_dir, random_hex};
use super::sha256_bytes;

const RELEASE_INDEX_MAX_BYTES: usize = 2 * 1024 * 1024;
const RELEASE_CHECKSUMS_MAX_BYTES: usize = 64 * 1024;
const RELEASE_ARCHIVE_MAX_BYTES: usize = 128 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const RELEASE_CHECK_TIMEOUT: Duration = Duration::from_secs(30);
const RELEASE_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(5 * 60);

async fn response_bytes_with_limit(
    mut response: reqwest::Response,
    max_bytes: usize,
    context: &str,
) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(format!("{context} exceeded the {max_bytes}-byte limit"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("{context} failed: {error}"))?
    {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(format!("{context} exceeded the {max_bytes}-byte limit"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn release_checksum<'a>(manifest: &'a str, filename: &str) -> Result<&'a str, String> {
    for line in manifest.lines() {
        let mut fields = line.split_whitespace();
        let Some(checksum) = fields.next() else {
            continue;
        };
        let Some(candidate) = fields.next() else {
            continue;
        };
        if candidate.trim_start_matches('*') != filename {
            continue;
        }
        if fields.next().is_some()
            || checksum.len() != 64
            || !checksum.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(format!("invalid checksum entry for {filename}"));
        }
        return Ok(checksum);
    }
    Err(format!("checksum entry missing for {filename}"))
}

pub(super) async fn latest_cli_release() -> Result<(String, String), String> {
    let client = reqwest::Client::builder()
        .user_agent("lux-cli")
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(RELEASE_CHECK_TIMEOUT)
        .build()
        .map_err(|error| error.to_string())?;
    let response = client
        .get("https://api.github.com/repos/lux-db/lux/releases")
        .send()
        .await
        .map_err(|error| format!("release check failed: {error}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "release check failed (HTTP {})",
            response.status().as_u16()
        ));
    }
    let body =
        response_bytes_with_limit(response, RELEASE_INDEX_MAX_BYTES, "release check").await?;
    let releases: Vec<serde_json::Value> = serde_json::from_slice(&body)
        .map_err(|error| format!("invalid GitHub release response: {error}"))?;
    let tag = releases
        .iter()
        .filter_map(|release| release.get("tag_name")?.as_str())
        .find(|tag| tag.starts_with("cli-v"))
        .ok_or_else(|| "no Lux CLI releases found".to_string())?
        .to_string();
    let version = tag.trim_start_matches("cli-v").to_string();
    Ok((tag, version))
}

pub(super) fn newer_cli_version(current: &str, latest: &str) -> bool {
    match (
        semver::Version::parse(current),
        semver::Version::parse(latest),
    ) {
        (Ok(current), Ok(latest)) => latest > current,
        _ => latest != current,
    }
}

pub(super) async fn update_cli(check: bool) -> Result<(), String> {
    let current = env!("CARGO_PKG_VERSION");
    let (latest_tag, latest_version) = latest_cli_release().await?;
    println!("{} v{current}", "Current CLI:".bold());
    if !newer_cli_version(current, &latest_version) {
        println!("{}", "CLI is already up to date.".green());
        return Ok(());
    }
    println!(
        "{} v{current} → v{latest_version}",
        "Update available:".yellow()
    );
    if check {
        println!("Run {} to install.", "lux update cli".cyan());
        return Ok(());
    }

    let os = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        return Err("unsupported OS for self-update".to_string());
    };
    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else {
        return Err("unsupported architecture for self-update".to_string());
    };
    let artifact = format!("lux-cli-{os}-{arch}");
    let archive_name = format!("{artifact}.tar.gz");
    let release_base = format!("https://github.com/lux-db/lux/releases/download/{latest_tag}");
    let client = reqwest::Client::builder()
        .user_agent("lux-cli")
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(RELEASE_DOWNLOAD_TIMEOUT)
        .build()
        .map_err(|error| error.to_string())?;
    println!("{} Downloading v{latest_version}...", "...".dimmed());
    let checksum_response = client
        .get(format!("{release_base}/SHA256SUMS"))
        .send()
        .await
        .map_err(|error| format!("checksum download failed: {error}"))?;
    if !checksum_response.status().is_success() {
        return Err(format!(
            "checksum download failed (HTTP {})",
            checksum_response.status().as_u16()
        ));
    }
    let checksum_bytes = response_bytes_with_limit(
        checksum_response,
        RELEASE_CHECKSUMS_MAX_BYTES,
        "checksum download",
    )
    .await?;
    let checksum_manifest = std::str::from_utf8(&checksum_bytes)
        .map_err(|_| "checksum file is not valid UTF-8".to_string())?;
    let expected_checksum = release_checksum(checksum_manifest, &archive_name)?;

    let response = client
        .get(format!("{release_base}/{archive_name}"))
        .send()
        .await
        .map_err(|error| format!("download failed: {error}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "download failed (HTTP {})",
            response.status().as_u16()
        ));
    }
    let archive =
        response_bytes_with_limit(response, RELEASE_ARCHIVE_MAX_BYTES, "download").await?;
    if !sha256_bytes(&archive).eq_ignore_ascii_case(expected_checksum) {
        return Err("download checksum did not match the published release".to_string());
    }

    let current_exe = std::env::current_exe()
        .map_err(|error| format!("could not determine binary path: {error}"))?;
    let tmp_dir = std::env::temp_dir().join(format!(
        "lux-cli-update-{}-{}",
        std::process::id(),
        random_hex(8)
    ));
    ensure_private_dir(&tmp_dir)
        .map_err(|error| format!("failed to create private update directory: {error}"))?;
    let archive_path = tmp_dir.join("lux-cli.tar.gz");
    std::fs::write(&archive_path, &archive)
        .map_err(|error| format!("failed to stage update: {error}"))?;
    let status = std::process::Command::new("tar")
        .args([
            "xzf",
            archive_path.to_str().unwrap_or_default(),
            "-C",
            tmp_dir.to_str().unwrap_or_default(),
        ])
        .status()
        .map_err(|error| format!("failed to extract update: {error}"))?;
    if !status.success() {
        return Err("failed to extract update".to_string());
    }
    let new_binary = tmp_dir.join(&artifact);
    if !new_binary.is_file() {
        return Err("binary not found in release archive".to_string());
    }
    #[cfg(unix)]
    std::fs::set_permissions(&new_binary, std::fs::Permissions::from_mode(0o755))
        .map_err(|error| format!("failed to make update executable: {error}"))?;
    std::fs::rename(&new_binary, &current_exe)
        .or_else(|_| std::fs::copy(&new_binary, &current_exe).map(|_| ()))
        .map_err(|_| "could not replace binary; try with appropriate permissions".to_string())?;
    std::fs::remove_dir_all(&tmp_dir).ok();
    println!("{} Updated CLI to v{latest_version}.", "Done.".green());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn checksum_selects_and_validates_the_requested_archive() {
        let linux = "a".repeat(64);
        let macos = "b".repeat(64);
        let manifest =
            format!("{linux}  lux-cli-linux-x86_64.tar.gz\n{macos} *lux-cli-macos-arm64.tar.gz\n");
        assert_eq!(
            release_checksum(&manifest, "lux-cli-macos-arm64.tar.gz").unwrap(),
            macos
        );
        assert!(release_checksum(&manifest, "lux-cli-linux-arm64.tar.gz").is_err());
        assert!(release_checksum(
            "not-a-sha  lux-cli-macos-arm64.tar.gz\n",
            "lux-cli-macos-arm64.tar.gz"
        )
        .is_err());
    }

    #[test]
    fn check_never_offers_a_downgrade() {
        assert!(newer_cli_version("0.26.2", "0.27.0"));
        assert!(!newer_cli_version("0.27.0", "0.26.2"));
        assert!(!newer_cli_version("0.27.0", "0.27.0"));
    }

    async fn response(body: &'static [u8], content_length: Option<usize>) -> reqwest::Response {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = socket.read(&mut request).await.unwrap();
            let length = content_length
                .map(|value| format!("Content-Length: {value}\r\n"))
                .unwrap_or_default();
            socket
                .write_all(
                    format!("HTTP/1.1 200 OK\r\n{length}Connection: close\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();
            socket.write_all(body).await.unwrap();
        });
        let response = reqwest::Client::new()
            .get(format!("http://{address}"))
            .send()
            .await
            .unwrap();
        server.await.unwrap();
        response
    }

    #[tokio::test]
    async fn downloads_enforce_declared_and_streamed_size_limits() {
        let declared = response(b"", Some(9)).await;
        assert!(response_bytes_with_limit(declared, 8, "test")
            .await
            .is_err());

        let streamed = response(b"123456789", None).await;
        assert!(response_bytes_with_limit(streamed, 8, "test")
            .await
            .is_err());
    }
}
