//! Container-local operations used by the CLI while application networking is detached.
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

fn main() -> ExitCode {
    let result = match std::env::args().nth(1).as_deref() {
        Some("version") => {
            println!("1");
            Ok(())
        }
        Some("snapshot") => snapshot(),
        Some("restore-snapshot") => {
            restore_snapshot(std::env::args().nth(2).as_deref() == Some("final"))
        }
        Some("copy-snapshot") => copy_snapshot(Path::new("/source"), Path::new("/data")),
        _ => Err(io::Error::other(
            "expected version, snapshot, copy-snapshot, or restore-snapshot",
        )),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("lux-maintenance: {error}");
            ExitCode::FAILURE
        }
    }
}

fn command(stream: &mut BufReader<TcpStream>, args: &[&str]) -> io::Result<String> {
    let socket = stream.get_mut();
    write!(socket, "*{}\r\n", args.len())?;
    for arg in args {
        write!(socket, "${}\r\n{arg}\r\n", arg.len())?;
    }
    socket.flush()?;
    bounded_line(stream)
}

fn bounded_line(stream: &mut impl BufRead) -> io::Result<String> {
    let mut response = Vec::new();
    // AUTH and SAVE both return one short RESP line. Do not accept arbitrary bodies.
    for _ in 0..256 {
        let bytes = stream.fill_buf()?;
        let Some(&byte) = bytes.first() else {
            return Err(io::Error::other("incomplete command response"));
        };
        response.push(byte);
        stream.consume(1);
        if response.ends_with(b"\r\n") {
            return String::from_utf8(response)
                .map_err(|_| io::Error::other("invalid command response"));
        }
    }
    Err(io::Error::other("command response is too long"))
}

fn restore_snapshot(final_import: bool) -> io::Result<()> {
    let password =
        std::env::var("LUX_PASSWORD").map_err(|_| io::Error::other("LUX_PASSWORD is required"))?;
    if password.is_empty() || password.contains(['\r', '\n']) {
        return Err(io::Error::other("invalid management credential"));
    }
    let path = Path::new("/data/lux.import");
    let mut source = fs::File::open(path)?;
    let len = source.metadata()?.len();
    let mut socket = TcpStream::connect_timeout(
        &SocketAddr::from((Ipv4Addr::LOCALHOST, 5890)),
        Duration::from_secs(5),
    )?;
    socket.set_read_timeout(Some(Duration::from_secs(300)))?;
    socket.set_write_timeout(Some(Duration::from_secs(300)))?;
    write!(socket, "POST /v1/restore HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {password}\r\nContent-Type: application/octet-stream\r\nContent-Length: {len}\r\n\r\n")?;
    if io::copy(&mut source, &mut socket)? != len {
        return Err(io::Error::other("snapshot length changed during import"));
    }
    socket.flush()?;
    let mut stream = BufReader::new(socket);
    if bounded_line(&mut stream)? != "HTTP/1.1 202 Accepted\r\n" {
        return Err(io::Error::other("candidate refused snapshot import"));
    }
    let mut length = None;
    let mut ended = false;
    for _ in 0..32 {
        let line = bounded_line(&mut stream)?;
        if line == "\r\n" {
            ended = true;
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse::<usize>().ok();
            }
        }
    }
    let len = length
        .filter(|n| *n <= 8192 && ended)
        .ok_or_else(|| io::Error::other("invalid restore confirmation length"))?;
    let mut body = vec![0; len];
    stream.read_exact(&mut body)?;
    let body =
        String::from_utf8(body).map_err(|_| io::Error::other("invalid restore confirmation"))?;
    println!("{body}");
    if final_import {
        fs::remove_file(path)?;
        fs::File::open("/data")?.sync_all()?;
    }
    Ok(())
}

fn snapshot() -> io::Result<()> {
    let port = std::env::var("LUX_PORT")
        .unwrap_or_else(|_| "6379".into())
        .parse::<u16>()
        .map_err(|_| io::Error::other("invalid LUX_PORT"))?;
    let password =
        std::env::var("LUX_PASSWORD").map_err(|_| io::Error::other("LUX_PASSWORD is required"))?;
    if password.is_empty() {
        return Err(io::Error::other("LUX_PASSWORD must not be empty"));
    }
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let socket = connect_when_ready(address, Duration::from_secs(300))?;
    socket.set_read_timeout(Some(Duration::from_secs(300)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut stream = BufReader::new(socket);
    if command(&mut stream, &["AUTH", &password])? != "+OK\r\n" {
        return Err(io::Error::other("engine authentication failed"));
    }
    let response = command(&mut stream, &["SAVE"])?;
    if !save_succeeded(&response) {
        return Err(io::Error::other("engine did not confirm the snapshot"));
    }
    println!("Snapshot saved.");
    Ok(())
}

fn connect_when_ready(address: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match TcpStream::connect_timeout(&address, Duration::from_secs(1)) {
            Ok(socket) => return Ok(socket),
            Err(error) => {
                if std::time::Instant::now() >= deadline {
                    return Err(error);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn save_succeeded(response: &str) -> bool {
    response == "+OK\r\n"
        || response
            .strip_prefix("+OK (")
            .and_then(|s| s.strip_suffix(" keys saved)\r\n"))
            .is_some_and(|count| !count.is_empty() && count.bytes().all(|b| b.is_ascii_digit()))
}

fn copy_snapshot(source: &Path, target: &Path) -> io::Result<()> {
    for path in [source, target] {
        if !fs::symlink_metadata(path)?.is_dir() {
            return Err(io::Error::other("expected non-symlink volume directories"));
        }
    }
    if fs::read_dir(target)?.next().is_some() {
        return Err(io::Error::other("snapshot destination must be empty"));
    }
    let mut files = Vec::new();
    for name in ["lux.dat", "lux.enc", "lux.enc.seal"] {
        let path = source.join(name);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_file() => files.push((
                path,
                target.join(if name == "lux.dat" {
                    "lux.import"
                } else {
                    name
                }),
            )),
            Ok(_) => return Err(io::Error::other("snapshot inputs must be regular files")),
            Err(error) if error.kind() == io::ErrorKind::NotFound && name != "lux.dat" => {}
            Err(error) => return Err(error),
        }
    }
    // The source is read-only and stopped. Partial destinations are never reused.
    for (from, to) in files {
        let mut input = fs::File::open(from)?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options.open(&to)?;
        io::copy(&mut input, &mut output)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let owner = fs::metadata(target)?;
            std::os::unix::fs::chown(&to, Some(owner.uid()), Some(owner.gid()))?;
        }
        output.sync_all()?;
    }
    fs::File::open(target)?.sync_all()?;
    println!("{}", fs::metadata(target.join("lux.import"))?.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_complete_success_responses() {
        assert!(save_succeeded("+OK\r\n"));
        assert!(save_succeeded("+OK (123 keys saved)\r\n"));
        for invalid in [
            "+OK",
            "+OK ( keys saved)\r\n",
            "-ERR save failed\r\n",
            "+OK (1x keys saved)\r\n",
        ] {
            assert!(!save_succeeded(invalid));
        }
    }

    #[test]
    fn copies_only_snapshot_and_keys_into_an_empty_destination() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let target = root.path().join("target");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&target).unwrap();
        for name in ["lux.dat", "lux.enc", "lux.enc.seal", "wal"] {
            fs::write(source.join(name), name.as_bytes()).unwrap();
        }
        copy_snapshot(&source, &target).unwrap();
        assert_eq!(fs::read(target.join("lux.import")).unwrap(), b"lux.dat");
        assert!(!target.join("lux.dat").exists());
        assert!(!target.join("wal").exists());
        assert!(copy_snapshot(&source, &target).is_err());
    }

    #[test]
    fn missing_snapshot_leaves_destination_empty() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let target = root.path().join("target");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&target).unwrap();
        fs::write(source.join("lux.enc"), b"keys").unwrap();
        assert!(copy_snapshot(&source, &target).is_err());
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_linked_inputs_before_copying_anything() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let target = root.path().join("target");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&target).unwrap();
        fs::write(source.join("lux.dat"), b"snapshot").unwrap();
        symlink(source.join("lux.dat"), source.join("lux.enc")).unwrap();
        assert!(copy_snapshot(&source, &target).is_err());
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
        let alias = root.path().join("alias");
        symlink(&source, &alias).unwrap();
        assert!(copy_snapshot(&alias, &target).is_err());
        assert!(copy_snapshot(&target, &alias).is_err());
    }

    #[test]
    fn bounds_incomplete_and_oversized_responses() {
        for response in [b"+OK".to_vec(), vec![b'x'; 257], vec![255, 13, 10]] {
            let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                let mut input = BufReader::new(socket.try_clone().unwrap());
                for _ in 0..3 {
                    let mut line = String::new();
                    input.read_line(&mut line).unwrap();
                }
                socket.write_all(&response).unwrap();
            });
            let socket = TcpStream::connect(address).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            assert!(command(&mut BufReader::new(socket), &["PING"]).is_err());
            server.join().unwrap();
        }
    }
}
