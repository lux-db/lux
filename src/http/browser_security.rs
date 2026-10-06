use base64::Engine;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::HttpBrowserConfig;

#[derive(Clone, Debug)]
pub(super) struct BrowserPolicy {
    allowed_hosts: HashSet<String>,
    allow_loopback_hosts: bool,
    allowed_origins: HashSet<String>,
}

/// How a request's `Origin` header is answered.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum RequestOrigin {
    /// No `Origin` header: a native or server client.
    None,
    /// An exact configured origin. Only these can carry a Studio session.
    Trusted(String),
    /// Any other browser origin on a credential-gated engine. Credentials and
    /// grants, not the origin, decide what the request may do.
    Public,
}

#[derive(Clone, Debug)]
struct StudioSession {
    origin: String,
    expires_at: Instant,
}

#[derive(Clone)]
pub(super) struct StudioSessions {
    ttl: Duration,
    sessions: Arc<parking_lot::Mutex<HashMap<[u8; 32], StudioSession>>>,
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn normalize_host(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || value
            .chars()
            .any(|character| matches!(character, '/' | '\\' | '@' | ','))
    {
        return None;
    }

    let host = if let Some(rest) = value.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let suffix = &rest[end + 1..];
        if !suffix.is_empty() {
            let port = suffix.strip_prefix(':')?;
            port.parse::<u16>().ok()?;
        }
        host
    } else if value.parse::<std::net::IpAddr>().is_ok() {
        value
    } else {
        match value.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => {
                port.parse::<u16>().ok()?;
                host
            }
            Some(_) if value.contains(':') => return None,
            _ => value,
        }
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

pub(super) fn normalize_origin(value: &str) -> Option<String> {
    if value.trim() == "null" {
        return None;
    }
    let url = reqwest::Url::parse(value.trim()).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return None;
    }
    url.host_str()?;
    Some(url.origin().ascii_serialization())
}

impl BrowserPolicy {
    pub(super) fn try_new(bind_host: &str, config: &HttpBrowserConfig) -> std::io::Result<Self> {
        if !(Duration::from_secs(1)..=Duration::from_secs(24 * 60 * 60))
            .contains(&config.studio_session_ttl)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Studio session TTL must be between 1 and 86400 seconds",
            ));
        }

        let allow_loopback_hosts = is_loopback_host(bind_host);
        let mut allowed_hosts = HashSet::new();
        for configured in &config.allowed_hosts {
            let Some(host) = normalize_host(configured) else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid HTTP allowed host: {configured}"),
                ));
            };
            allowed_hosts.insert(host);
        }
        let mut allowed_origins = HashSet::new();
        for configured in &config.allowed_origins {
            let Some(origin) = normalize_origin(configured) else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid HTTP allowed origin: {configured}"),
                ));
            };
            allowed_origins.insert(origin);
        }
        if !allowed_origins.is_empty() && allowed_hosts.is_empty() && !allow_loopback_hosts {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "LUX_HTTP_ALLOWED_HOSTS is required when browser origins are enabled on a non-loopback HTTP bind",
            ));
        }

        Ok(Self {
            allowed_hosts,
            allow_loopback_hosts,
            allowed_origins,
        })
    }

    /// `credentials_required` is true once the engine has an operator password
    /// or project keys. DNS rebinding only matters for an engine that answers
    /// without credentials, so the Host allowlist applies only to that engine.
    pub(super) fn validate_host(
        &self,
        headers: &[(String, String)],
        credentials_required: bool,
    ) -> Result<(), &'static str> {
        let values: Vec<&str> = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
            .map(|(_, value)| value.as_str())
            .collect();
        if values.len() != 1 {
            return Err("exactly one Host header is required");
        }
        let Some(host) = normalize_host(values[0]) else {
            return Err("invalid Host header");
        };
        let host_allowlist_enabled = !self.allowed_hosts.is_empty() || self.allow_loopback_hosts;
        if !credentials_required
            && host_allowlist_enabled
            && !self.allowed_hosts.contains(&host)
            && !(self.allow_loopback_hosts && is_loopback_host(&host))
        {
            return Err("Host is not allowed");
        }
        Ok(())
    }

    /// A credential-gated engine answers every browser origin, as any
    /// publishable-key API does. An engine without credentials answers only
    /// configured origins, so an arbitrary page cannot read or write it.
    pub(super) fn request_origin(
        &self,
        headers: &[(String, String)],
        credentials_required: bool,
    ) -> Result<RequestOrigin, &'static str> {
        let values: Vec<&str> = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("origin"))
            .map(|(_, value)| value.as_str())
            .collect();
        if values.len() > 1 {
            return Err("duplicate Origin header");
        }
        let Some(raw) = values.first() else {
            return Ok(RequestOrigin::None);
        };
        match normalize_origin(raw) {
            Some(origin) if self.allowed_origins.contains(&origin) => {
                Ok(RequestOrigin::Trusted(origin))
            }
            _ if credentials_required => Ok(RequestOrigin::Public),
            Some(_) => Err("Origin is not allowed"),
            None => Err("invalid Origin header"),
        }
    }

    pub(super) fn allows_origin(&self, origin: &str) -> bool {
        self.allowed_origins.contains(origin)
    }
}

impl StudioSessions {
    pub(super) fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            sessions: Arc::new(parking_lot::Mutex::new(HashMap::new())),
        }
    }

    fn token_hash(token: &str) -> [u8; 32] {
        Sha256::digest(token.as_bytes()).into()
    }

    fn prune(sessions: &mut HashMap<[u8; 32], StudioSession>, now: Instant) {
        sessions.retain(|_, session| session.expires_at > now);
    }

    pub(super) fn authorize(&self, token: &str, origin: Option<&str>) -> bool {
        let Some(origin) = origin else {
            return false;
        };
        if !token.starts_with("lux_studio_") {
            return false;
        }
        let now = Instant::now();
        let mut sessions = self.sessions.lock();
        Self::prune(&mut sessions, now);
        sessions
            .get(&Self::token_hash(token))
            .is_some_and(|session| session.origin == origin)
    }

    pub(super) fn issue(&self, origin: String) -> (String, u64) {
        let mut random = [0u8; 32];
        OsRng.fill_bytes(&mut random);
        let token = format!(
            "lux_studio_{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random)
        );
        let expires_at = Instant::now() + self.ttl;
        let expires_at_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_add(self.ttl.as_secs());
        let mut sessions = self.sessions.lock();
        Self::prune(&mut sessions, Instant::now());
        sessions.retain(|_, session| session.origin != origin);
        if sessions.len() >= 32 {
            if let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, session)| session.expires_at)
                .map(|(token_hash, _)| *token_hash)
            {
                sessions.remove(&oldest);
            }
        }
        sessions.insert(
            Self::token_hash(&token),
            StudioSession { origin, expires_at },
        );
        (token, expires_at_epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn browser_config() -> HttpBrowserConfig {
        HttpBrowserConfig {
            allowed_hosts: Vec::new(),
            allowed_origins: Vec::new(),
            studio_session_ttl: Duration::from_secs(12 * 60 * 60),
        }
    }

    #[test]
    fn rejects_malformed_security_configuration() {
        let mut config = browser_config();
        config.allowed_hosts = vec!["localhost/attacker".to_string()];
        assert!(BrowserPolicy::try_new("127.0.0.1", &config).is_err());

        let mut config = browser_config();
        config.allowed_origins = vec!["https://user@example.test/path".to_string()];
        assert!(BrowserPolicy::try_new("127.0.0.1", &config).is_err());

        let mut config = browser_config();
        config.studio_session_ttl = Duration::from_secs(24 * 60 * 60 + 1);
        assert!(BrowserPolicy::try_new("127.0.0.1", &config).is_err());

        let config = browser_config();
        assert!(BrowserPolicy::try_new("0.0.0.0", &config).is_ok());

        let mut config = browser_config();
        config.allowed_origins = vec!["https://studio.example.com".to_string()];
        assert!(BrowserPolicy::try_new("0.0.0.0", &config).is_err());
    }

    #[test]
    fn normalizes_loopback_aliases_without_accepting_lookalikes() {
        assert_eq!(
            normalize_host("LOCALHOST.:5890"),
            Some("localhost".to_string())
        );
        assert_eq!(normalize_host("[::1]:5890"), Some("::1".to_string()));
        assert_eq!(normalize_host("::1"), Some("::1".to_string()));
        assert!(normalize_host("localhost:70000").is_none());
        assert!(!is_loopback_host("localhost.attacker.example"));
        assert_eq!(
            normalize_origin("http://[::1]:5891"),
            Some("http://[::1]:5891".to_string())
        );
        assert_eq!(normalize_origin("null"), None);

        let policy = BrowserPolicy::try_new("127.0.0.1", &browser_config()).unwrap();
        for host in [
            "localhost:5890",
            "LOCALHOST.:5890",
            "127.0.0.2:5890",
            "[::1]:5890",
        ] {
            assert!(policy
                .validate_host(&[("host".to_string(), host.to_string())], false)
                .is_ok());
        }
        let rebinding = [(
            "host".to_string(),
            "localhost.attacker.example:5890".to_string(),
        )];
        assert!(policy.validate_host(&rebinding, false).is_err());
        // A credential-gated engine is reachable under any valid Host name,
        // such as host.docker.internal or a tunnel, but never a malformed one.
        assert!(policy.validate_host(&rebinding, true).is_ok());
        assert!(policy
            .validate_host(&[("host".to_string(), "bad host".to_string())], true)
            .is_err());
        assert!(policy.validate_host(&[], true).is_err());
    }

    #[test]
    fn credential_gated_engines_answer_any_browser_origin() {
        let mut config = browser_config();
        config.allowed_origins = vec!["http://localhost:5891".to_string()];
        let policy = BrowserPolicy::try_new("127.0.0.1", &config).unwrap();
        let origin = |value: &str| vec![("origin".to_string(), value.to_string())];

        for credentials_required in [false, true] {
            assert_eq!(
                policy.request_origin(&[], credentials_required),
                Ok(RequestOrigin::None)
            );
            assert_eq!(
                policy.request_origin(&origin("http://localhost:5891"), credentials_required),
                Ok(RequestOrigin::Trusted("http://localhost:5891".to_string()))
            );
            let mut duplicate = origin("http://localhost:5891");
            duplicate.extend(origin("http://localhost:5891"));
            assert!(policy
                .request_origin(&duplicate, credentials_required)
                .is_err());
        }

        assert_eq!(
            policy.request_origin(&origin("http://localhost:5173"), true),
            Ok(RequestOrigin::Public)
        );
        assert_eq!(
            policy.request_origin(&origin("null"), true),
            Ok(RequestOrigin::Public)
        );
        assert!(policy
            .request_origin(&origin("http://localhost:5173"), false)
            .is_err());
        assert!(policy.request_origin(&origin("null"), false).is_err());
    }

    #[test]
    fn sessions_are_origin_bound_rotated_bounded_and_expiring() {
        let sessions = StudioSessions::new(Duration::from_millis(20));
        let (first, _) = sessions.issue("http://localhost:5891".to_string());
        assert!(sessions.authorize(&first, Some("http://localhost:5891")));
        assert!(!sessions.authorize(&first, Some("http://localhost:5892")));
        assert!(!sessions.authorize(&first, None));

        let (second, _) = sessions.issue("http://localhost:5891".to_string());
        assert_ne!(first, second);
        assert!(!sessions.authorize(&first, Some("http://localhost:5891")));
        assert!(sessions.authorize(&second, Some("http://localhost:5891")));

        std::thread::sleep(Duration::from_millis(25));
        assert!(!sessions.authorize(&second, Some("http://localhost:5891")));

        for port in 6000..6040 {
            sessions.issue(format!("http://localhost:{port}"));
        }
        assert!(sessions.sessions.lock().len() <= 32);
    }
}
