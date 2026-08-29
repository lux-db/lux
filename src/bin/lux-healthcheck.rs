use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process::ExitCode;
use std::time::Duration;

const DEFAULT_HTTP_PORT: u16 = 5890;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("lux-healthcheck: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let path = match std::env::args().nth(1).as_deref() {
        Some("live") => "/health/live",
        Some("ready") | None => "/health/ready",
        Some(mode) => return Err(format!("unknown check {mode:?}; expected live or ready")),
    };
    let host = std::env::var("LUX_HEALTHCHECK_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port = std::env::var("LUX_HTTP_PORT")
        .ok()
        .map(|raw| {
            raw.parse::<u16>()
                .map_err(|_| "LUX_HTTP_PORT must be a valid non-zero port".to_string())
        })
        .transpose()?
        .unwrap_or(DEFAULT_HTTP_PORT);
    if port == 0 {
        return Err("LUX_HTTP_PORT must be non-zero".into());
    }

    check(&host, port, path, DEFAULT_TIMEOUT)
}

fn check(host: &str, port: u16, path: &str, timeout: Duration) -> Result<(), String> {
    let address = resolve(host, port)?;
    let mut stream = TcpStream::connect_timeout(&address, timeout)
        .map_err(|error| format!("cannot connect to {address}: {error}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("cannot set read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("cannot set write timeout: {error}"))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )
    .map_err(|error| format!("request failed: {error}"))?;

    let mut status_line = String::new();
    BufReader::new(stream)
        .read_line(&mut status_line)
        .map_err(|error| format!("response failed: {error}"))?;
    if status_line.split_whitespace().nth(1) == Some("200") {
        Ok(())
    } else {
        Err(format!("unhealthy response: {status_line}"))
    }
}

fn resolve(host: &str, port: u16) -> Result<SocketAddr, String> {
    (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("cannot resolve {host}:{port}: {error}"))?
        .next()
        .ok_or_else(|| format!("no address found for {host}:{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn accepts_only_http_success() {
        assert!(run_probe("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").is_ok());
        assert!(
            run_probe("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n").is_err()
        );
    }

    fn run_probe(response: &'static str) -> Result<(), String> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 256];
            let _ = stream.read(&mut request).unwrap();
            stream.write_all(response.as_bytes()).unwrap();
        });
        let result = check(
            "127.0.0.1",
            address.port(),
            "/health/ready",
            DEFAULT_TIMEOUT,
        );
        server.join().unwrap();
        result
    }
}
