use anyhow::{anyhow, bail, Context, Result};
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;

trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RespValue {
    Simple(String),
    Error(String),
    Integer(i64),
    Bulk(Vec<u8>),
    Array(Vec<RespValue>),
    Null,
}

impl RespValue {
    #[must_use]
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error(_))
    }

    #[must_use]
    pub fn error_message(&self) -> Option<&str> {
        match self {
            Self::Error(message) => Some(message),
            _ => None,
        }
    }
}

pub struct RespConnection {
    stream: BufReader<Box<dyn AsyncStream>>,
}

impl RespConnection {
    pub async fn connect(endpoint: &str, password: Option<&str>) -> Result<Self> {
        let url = normalize_url(endpoint)?;
        let host = url
            .host_str()
            .context("RESP endpoint must include a host")?
            .to_owned();
        let tls = matches!(url.scheme(), "rediss" | "luxs");
        let port = url.port().unwrap_or(if tls { 6380 } else { 6379 });
        let tcp = TcpStream::connect((host.as_str(), port))
            .await
            .with_context(|| format!("connect to RESP endpoint {host}:{port}"))?;
        tcp.set_nodelay(true).context("enable TCP_NODELAY")?;

        let stream: Box<dyn AsyncStream> = if tls {
            let roots =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let server_name = ServerName::try_from(host.clone())
                .map_err(|_| anyhow!("invalid TLS server name {host}"))?;
            let connection = TlsConnector::from(Arc::new(config))
                .connect(server_name, tcp)
                .await
                .with_context(|| format!("TLS handshake with {host}:{port}"))?;
            Box::new(connection)
        } else {
            Box::new(tcp)
        };

        let mut connection = Self::from_stream(stream);
        let url_password = url.password().filter(|value| !value.is_empty());
        if let Some(password) = password.or(url_password) {
            let response = connection
                .command(&[b"AUTH".to_vec(), password.as_bytes().to_vec()])
                .await?;
            if let Some(message) = response.error_message() {
                bail!("RESP authentication failed: {message}");
            }
        }
        Ok(connection)
    }

    pub async fn command(&mut self, command: &[Vec<u8>]) -> Result<RespValue> {
        self.write_commands(std::slice::from_ref(&command)).await?;
        self.read_response().await
    }

    pub async fn write_commands(&mut self, commands: &[&[Vec<u8>]]) -> Result<()> {
        let mut encoded = Vec::new();
        for command in commands {
            encode_command(command, &mut encoded);
        }
        self.stream
            .get_mut()
            .write_all(&encoded)
            .await
            .context("write RESP commands")?;
        self.stream
            .get_mut()
            .flush()
            .await
            .context("flush RESP commands")
    }

    pub async fn read_response(&mut self) -> Result<RespValue> {
        self.read_value().await
    }

    fn from_stream(stream: Box<dyn AsyncStream>) -> Self {
        Self {
            stream: BufReader::new(stream),
        }
    }

    fn read_value(&mut self) -> Pin<Box<dyn Future<Output = Result<RespValue>> + Send + '_>> {
        Box::pin(async move {
            let kind = self.stream.read_u8().await.context("read RESP type byte")?;
            match kind {
                b'+' => Ok(RespValue::Simple(self.read_line().await?)),
                b'-' => Ok(RespValue::Error(self.read_line().await?)),
                b':' => {
                    let value = self
                        .read_line()
                        .await?
                        .parse::<i64>()
                        .context("parse RESP integer")?;
                    Ok(RespValue::Integer(value))
                }
                b'$' => {
                    let length = self.read_length().await?;
                    if length < 0 {
                        return Ok(RespValue::Null);
                    }
                    let length = usize::try_from(length).context("RESP bulk length overflow")?;
                    let mut value = vec![0; length];
                    self.stream
                        .read_exact(&mut value)
                        .await
                        .context("read RESP bulk value")?;
                    self.read_crlf().await?;
                    Ok(RespValue::Bulk(value))
                }
                b'*' => {
                    let length = self.read_length().await?;
                    if length < 0 {
                        return Ok(RespValue::Null);
                    }
                    let length = usize::try_from(length).context("RESP array length overflow")?;
                    let mut values = Vec::with_capacity(length);
                    for _ in 0..length {
                        values.push(self.read_value().await?);
                    }
                    Ok(RespValue::Array(values))
                }
                other => bail!("unsupported RESP type byte 0x{other:02x}"),
            }
        })
    }

    async fn read_length(&mut self) -> Result<i64> {
        self.read_line()
            .await?
            .parse::<i64>()
            .context("parse RESP length")
    }

    async fn read_line(&mut self) -> Result<String> {
        let mut line = Vec::new();
        let read = self
            .stream
            .read_until(b'\n', &mut line)
            .await
            .context("read RESP line")?;
        if read == 0 {
            bail!("RESP connection closed");
        }
        if !line.ends_with(b"\r\n") {
            bail!("RESP line is missing CRLF");
        }
        line.truncate(line.len() - 2);
        String::from_utf8(line).context("RESP line is not UTF-8")
    }

    async fn read_crlf(&mut self) -> Result<()> {
        let mut terminator = [0_u8; 2];
        self.stream
            .read_exact(&mut terminator)
            .await
            .context("read RESP CRLF")?;
        if terminator != *b"\r\n" {
            bail!("invalid RESP bulk terminator");
        }
        Ok(())
    }
}

pub fn encode_command(command: &[Vec<u8>], output: &mut Vec<u8>) {
    output.extend_from_slice(format!("*{}\r\n", command.len()).as_bytes());
    for argument in command {
        output.extend_from_slice(format!("${}\r\n", argument.len()).as_bytes());
        output.extend_from_slice(argument);
        output.extend_from_slice(b"\r\n");
    }
}

fn normalize_url(endpoint: &str) -> Result<Url> {
    let with_scheme = if endpoint.contains("://") {
        endpoint.to_owned()
    } else {
        format!("redis://{endpoint}")
    };
    let url = Url::parse(&with_scheme).context("parse RESP endpoint")?;
    if !matches!(url.scheme(), "redis" | "rediss" | "lux" | "luxs") {
        bail!("unsupported RESP scheme {}", url.scheme());
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[test]
    fn command_encoding_is_binary_safe() {
        let mut output = Vec::new();
        encode_command(&[b"SET".to_vec(), vec![0, b'\r', b'\n']], &mut output);
        assert_eq!(output, b"*2\r\n$3\r\nSET\r\n$3\r\n\0\r\n\r\n");
    }

    #[tokio::test]
    async fn parses_nested_and_null_responses() {
        let (client, mut server_stream) = duplex(1024);
        let server = tokio::spawn(async move {
            let mut request = [0_u8; 14];
            server_stream.read_exact(&mut request).await.unwrap();
            server_stream
                .write_all(b"*3\r\n+OK\r\n$3\r\nhey\r\n$-1\r\n")
                .await
                .unwrap();
        });
        let mut connection = RespConnection::from_stream(Box::new(client));
        let response = connection.command(&[b"PING".to_vec()]).await.unwrap();
        assert_eq!(
            response,
            RespValue::Array(vec![
                RespValue::Simple("OK".into()),
                RespValue::Bulk(b"hey".to_vec()),
                RespValue::Null,
            ])
        );
        server.await.unwrap();
    }
}
