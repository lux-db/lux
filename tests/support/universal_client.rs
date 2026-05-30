use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Mutex;
use std::time::Duration;

pub enum UniversalClient {
    Embedded(Box<lux::EmbeddedClient>),
    Resp(Mutex<TcpStream>),
}

impl UniversalClient {
    #[allow(dead_code)]
    pub fn embedded(client: lux::EmbeddedClient) -> Self {
        Self::Embedded(Box::new(client))
    }

    #[allow(dead_code)]
    pub fn resp(addr: SocketAddr) -> Self {
        Self::Resp(Mutex::new(connect(addr)))
    }

    #[allow(dead_code)]
    pub async fn execute_bytes(&self, args: &[&[u8]]) -> Vec<u8> {
        match self {
            Self::Embedded(client) => client.execute_bytes(args).await.unwrap().to_vec(),
            Self::Resp(conn) => {
                let mut conn = conn.lock().unwrap();
                send_and_read_bytes(&mut conn, args)
            }
        }
    }

    #[allow(dead_code)]
    pub async fn set(&self, key: &str, value: &str) -> bool {
        match self {
            Self::Embedded(client) => {
                let ok = client.set(key, value).await.unwrap();
                assert!(ok, "embedded SET returned false for key={key}");
                ok
            }
            Self::Resp(_) => {
                let resp = self
                    .execute_bytes(&[b"SET", key.as_bytes(), value.as_bytes()])
                    .await;
                assert_eq!(resp, b"+OK\r\n", "RESP SET failed for key={key}: {resp:?}");
                true
            }
        }
    }

    #[allow(dead_code)]
    pub async fn get(&self, key: &str) -> Option<Vec<u8>> {
        match self {
            Self::Embedded(client) => client.get(key).await.unwrap().map(|b| b.to_vec()),
            Self::Resp(_) => {
                let resp = self.execute_bytes(&[b"GET", key.as_bytes()]).await;
                parse_resp_bulk(&resp)
            }
        }
    }

    #[allow(dead_code)]
    pub async fn setnx(&self, key: &str, value: &str) -> bool {
        match self {
            Self::Embedded(client) => client.setnx(key, value).await.unwrap(),
            Self::Resp(_) => {
                let resp = self
                    .execute_bytes(&[b"SETNX", key.as_bytes(), value.as_bytes()])
                    .await;
                parse_resp_int_frame(&resp) == 1
            }
        }
    }

    #[allow(dead_code)]
    pub async fn incrby(&self, key: &str, increment: i64) -> i64 {
        match self {
            Self::Embedded(client) => client.incrby(key, increment).await.unwrap(),
            Self::Resp(_) => {
                let increment = increment.to_string();
                let resp = self
                    .execute_bytes(&[b"INCRBY", key.as_bytes(), increment.as_bytes()])
                    .await;
                parse_resp_int_frame(&resp)
            }
        }
    }

    #[allow(dead_code)]
    pub async fn append(&self, key: &str, value: &str) -> i64 {
        match self {
            Self::Embedded(client) => client.append(key, value).await.unwrap() as i64,
            Self::Resp(_) => {
                let resp = self
                    .execute_bytes(&[b"APPEND", key.as_bytes(), value.as_bytes()])
                    .await;
                parse_resp_int_frame(&resp)
            }
        }
    }

    #[allow(dead_code)]
    pub async fn strlen(&self, key: &str) -> i64 {
        match self {
            Self::Embedded(client) => client.strlen(key).await.unwrap() as i64,
            Self::Resp(_) => {
                let resp = self.execute_bytes(&[b"STRLEN", key.as_bytes()]).await;
                parse_resp_int_frame(&resp)
            }
        }
    }

    #[allow(dead_code)]
    pub async fn lpush(&self, key: &str, values: &[&str]) {
        match self {
            Self::Embedded(c) => {
                let n = c.lpush(key, values).await.unwrap();
                assert_eq!(n, values.len(), "embedded LPUSH should add all elements");
            }
            Self::Resp(_) => {
                let mut args: Vec<&[u8]> = vec![b"LPUSH", key.as_bytes()];
                args.extend(values.iter().map(|v| v.as_bytes()));
                let resp = self.execute_bytes(&args).await;
                assert_eq!(parse_resp_int_frame(&resp), values.len() as i64);
            }
        }
    }

    #[allow(dead_code)]
    pub async fn sadd(&self, key: &str, values: &[&str]) {
        match self {
            Self::Embedded(c) => {
                let n = c.sadd(key, values).await.unwrap();
                assert_eq!(n, values.len(), "embedded SADD should add all elements");
            }
            Self::Resp(_) => {
                let mut args: Vec<&[u8]> = vec![b"SADD", key.as_bytes()];
                args.extend(values.iter().map(|v| v.as_bytes()));
                let resp = self.execute_bytes(&args).await;
                assert_eq!(parse_resp_int_frame(&resp), values.len() as i64);
            }
        }
    }

    #[allow(dead_code)]
    pub async fn hset(&self, key: &str, field: &str, value: &str) {
        match self {
            Self::Embedded(c) => {
                let n = c.hset(key, field, value).await.unwrap();
                assert_eq!(n, 1, "embedded HSET should add one field");
            }
            Self::Resp(_) => {
                let resp = self
                    .execute_bytes(&[b"HSET", key.as_bytes(), field.as_bytes(), value.as_bytes()])
                    .await;
                assert_eq!(parse_resp_int_frame(&resp), 1);
            }
        }
    }

    #[allow(dead_code)]
    pub async fn zadd(&self, key: &str, score: f64, member: &str) {
        match self {
            Self::Embedded(c) => {
                let n = c.zadd(key, score, member).await.unwrap();
                assert_eq!(n, 1, "embedded ZADD should add one member");
            }
            Self::Resp(_) => {
                let score_s = score.to_string();
                let resp = self
                    .execute_bytes(&[
                        b"ZADD",
                        key.as_bytes(),
                        score_s.as_bytes(),
                        member.as_bytes(),
                    ])
                    .await;
                assert_eq!(parse_resp_int_frame(&resp), 1);
            }
        }
    }

    #[allow(dead_code)]
    pub async fn save(&self) {
        let resp = self.execute_bytes(&[b"SAVE"]).await;
        assert!(resp.starts_with(b"+OK"), "SAVE failed: {resp:?}");
    }

    #[allow(dead_code)]
    pub async fn llen(&self, key: &str) -> i64 {
        match self {
            Self::Embedded(c) => c.llen(key).await.unwrap() as i64,
            Self::Resp(_) => {
                let resp = self.execute_bytes(&[b"LLEN", key.as_bytes()]).await;
                parse_resp_int_frame(&resp)
            }
        }
    }

    #[allow(dead_code)]
    pub async fn scard(&self, key: &str) -> i64 {
        match self {
            Self::Embedded(c) => c.scard(key).await.unwrap() as i64,
            Self::Resp(_) => {
                let resp = self.execute_bytes(&[b"SCARD", key.as_bytes()]).await;
                parse_resp_int_frame(&resp)
            }
        }
    }

    #[allow(dead_code)]
    pub async fn hget(&self, key: &str, field: &str) -> Option<Vec<u8>> {
        match self {
            Self::Embedded(c) => c.hget(key, field).await.unwrap().map(|v| v.to_vec()),
            Self::Resp(_) => {
                let resp = self
                    .execute_bytes(&[b"HGET", key.as_bytes(), field.as_bytes()])
                    .await;
                parse_resp_bulk(&resp)
            }
        }
    }

    #[allow(dead_code)]
    pub async fn zcard(&self, key: &str) -> i64 {
        match self {
            Self::Embedded(c) => c.zcard(key).await.unwrap() as i64,
            Self::Resp(_) => {
                let resp = self.execute_bytes(&[b"ZCARD", key.as_bytes()]).await;
                parse_resp_int_frame(&resp)
            }
        }
    }

    #[allow(dead_code)]
    pub async fn dbsize(&self) -> i64 {
        match self {
            Self::Embedded(c) => c.dbsize().await.unwrap() as i64,
            Self::Resp(_) => {
                let resp = self.execute_bytes(&[b"DBSIZE"]).await;
                parse_resp_int_frame(&resp)
            }
        }
    }
}

fn connect(addr: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect(addr).unwrap();
    stream.set_nodelay(true).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    stream
}

fn resp_cmd_bytes(args: &[&[u8]]) -> Vec<u8> {
    let mut buf = format!("*{}\r\n", args.len()).into_bytes();
    for arg in args {
        buf.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
        buf.extend_from_slice(arg);
        buf.extend_from_slice(b"\r\n");
    }
    buf
}

fn send_and_read_bytes(stream: &mut TcpStream, args: &[&[u8]]) -> Vec<u8> {
    stream.write_all(&resp_cmd_bytes(args)).unwrap();
    read_resp_frame(stream)
}

fn read_resp_line(stream: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut one = [0u8; 1];
    loop {
        read_exact_retry(stream, &mut one);
        out.push(one[0]);
        if out.len() >= 2 && out[out.len() - 2..] == *b"\r\n" {
            return out;
        }
    }
}

fn read_resp_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut prefix = [0u8; 1];
    read_exact_retry(stream, &mut prefix);
    let mut out = vec![prefix[0]];
    let line = read_resp_line(stream);
    out.extend_from_slice(&line);

    match prefix[0] {
        b'+' | b'-' | b':' => out,
        b'$' => {
            let len_str = std::str::from_utf8(&line[..line.len() - 2]).unwrap();
            let len = len_str.parse::<isize>().unwrap();
            if len < 0 {
                return out;
            }
            let mut payload = vec![0u8; len as usize + 2];
            read_exact_retry(stream, &mut payload);
            out.extend_from_slice(&payload);
            out
        }
        _ => panic!(
            "unsupported RESP prefix in test helper: {}",
            prefix[0] as char
        ),
    }
}

fn read_exact_retry(stream: &mut TcpStream, buf: &mut [u8]) {
    let mut read = 0usize;
    let mut retries = 0usize;
    while read < buf.len() {
        match stream.read(&mut buf[read..]) {
            Ok(0) => panic!("unexpected EOF while reading RESP frame"),
            Ok(n) => {
                read += n;
                retries = 0;
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                retries += 1;
                assert!(
                    retries <= 200,
                    "timed out while reading RESP frame after {retries} retries"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(e) => panic!("failed reading RESP frame: {e}"),
        }
    }
}

#[allow(dead_code)]
pub fn parse_resp_int_frame(resp: &[u8]) -> i64 {
    assert!(
        resp.starts_with(b":"),
        "expected integer RESP, got {resp:?}"
    );
    let s = std::str::from_utf8(resp).expect("integer RESP should be valid UTF-8 ASCII");
    s.trim()
        .trim_start_matches(':')
        .parse::<i64>()
        .unwrap_or_else(|e| panic!("invalid integer RESP {resp:?}: {e}"))
}

#[allow(dead_code)]
pub fn parse_resp_bulk(resp: &[u8]) -> Option<Vec<u8>> {
    if resp == b"$-1\r\n" {
        return None;
    }
    assert!(
        resp.starts_with(b"$"),
        "expected bulk RESP, got {:?}",
        String::from_utf8_lossy(resp)
    );
    let Some(header_end) = resp.windows(2).position(|w| w == b"\r\n") else {
        panic!(
            "invalid RESP bulk header: {:?}",
            String::from_utf8_lossy(resp)
        );
    };
    let len = std::str::from_utf8(&resp[1..header_end])
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let data_start = header_end + 2;
    let data_end = data_start + len;
    assert!(
        resp.len() >= data_end + 2,
        "truncated RESP bulk: {:?}",
        String::from_utf8_lossy(resp)
    );
    Some(resp[data_start..data_end].to_vec())
}
