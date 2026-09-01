use serde::Deserialize;

#[derive(Deserialize)]
pub(crate) struct StudioSession {
    pub(crate) token: String,
    pub(crate) expires_at: u64,
}

pub(crate) struct StudioContainerConfig<'a> {
    pub(crate) engine_url: &'a str,
    pub(crate) session: &'a StudioSession,
    pub(crate) host: &'a str,
    pub(crate) publishable_key: &'a str,
    pub(crate) project_name: &'a str,
    pub(crate) openrouter_key: &'a str,
}

impl StudioContainerConfig<'_> {
    pub(crate) fn env(&self) -> Vec<String> {
        vec![
            format!("LUX_URL={}", self.engine_url),
            format!("LUX_STUDIO_TOKEN={}", self.session.token),
            format!("LUX_STUDIO_SESSION_EXPIRES_AT={}", self.session.expires_at),
            format!("LUX_STUDIO_HOST={}", self.host),
            format!("LUX_PUBLISHABLE_KEY={}", self.publishable_key),
            format!("LUX_PROJECT_NAME={}", self.project_name),
            format!("LUX_OPENROUTER_KEY={}", self.openrouter_key),
        ]
    }
}

fn endpoint(engine_url: &str, path: &str) -> Result<reqwest::Url, String> {
    let base = reqwest::Url::parse(engine_url.trim())
        .map_err(|error| format!("invalid engine URL: {error}"))?;
    if !matches!(base.scheme(), "http" | "https")
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
        || base.host_str().is_none()
    {
        return Err("engine URL must be an http(s) origin without credentials or a query".into());
    }
    let mut url = base;
    url.set_path(path);
    Ok(url)
}

fn client(
    engine_url: &reqwest::Url,
    timeout: std::time::Duration,
) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none());
    let host_is_loopback = engine_url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if host_is_loopback {
        builder = builder.no_proxy();
    }
    builder
        .build()
        .map_err(|error| format!("create HTTP client: {error}"))
}

pub(crate) async fn mint_session(
    engine_url: &str,
    operator_key: &str,
    origin: &str,
) -> Result<StudioSession, String> {
    let url = endpoint(engine_url, "/v1/studio/sessions")?;
    let response = client(&url, std::time::Duration::from_secs(5))?
        .post(url)
        .bearer_auth(operator_key)
        .json(&serde_json::json!({ "origin": origin }))
        .send()
        .await
        .map_err(|error| format!("request Studio session: {error}"))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| format!("read Studio session response: {error}"))?;
    if !status.is_success() {
        return Err(format!(
            "engine rejected Studio session ({status}): {body}. Update the local engine if this endpoint is unavailable"
        ));
    }
    let session: StudioSession = serde_json::from_str(&body)
        .map_err(|error| format!("invalid Studio session response: {error}"))?;
    if !session.token.starts_with("lux_studio_") || session.expires_at == 0 {
        return Err("engine returned an incomplete Studio session".to_string());
    }
    Ok(session)
}

pub(crate) async fn session_is_valid(engine_url: &str, origin: &str, token: &str) -> bool {
    if !token.starts_with("lux_studio_") {
        return false;
    }
    let Ok(url) = endpoint(engine_url, "/v1") else {
        return false;
    };
    let Ok(client) = client(&url, std::time::Duration::from_secs(2)) else {
        return false;
    };
    let Ok(response) = client
        .get(url)
        .bearer_auth(token)
        .header("Origin", origin)
        .send()
        .await
    else {
        return false;
    };
    response.status().is_success()
        && response
            .headers()
            .get("Access-Control-Allow-Origin")
            .and_then(|value| value.to_str().ok())
            == Some(origin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_env_contains_no_durable_engine_credentials() {
        let session = StudioSession {
            token: "lux_studio_ephemeral".to_string(),
            expires_at: 123_456,
        };
        let env = StudioContainerConfig {
            engine_url: "http://localhost:5890",
            session: &session,
            host: "localhost",
            publishable_key: "lux_pub_local_fixture",
            project_name: "example",
            openrouter_key: "",
        }
        .env();

        assert!(env
            .iter()
            .any(|entry| entry == "LUX_STUDIO_TOKEN=lux_studio_ephemeral"));
        assert!(env
            .iter()
            .any(|entry| entry == "LUX_PUBLISHABLE_KEY=lux_pub_local_fixture"));
        assert!(!env.iter().any(|entry| {
            [
                "LUX_KEY=",
                "LUX_PASSWORD=",
                "LUX_SECRET_KEY=",
                "LUX_DIRECT_URL=",
            ]
            .iter()
            .any(|secret| entry.starts_with(secret))
        }));
    }

    #[test]
    fn session_endpoint_rejects_embedded_authority() {
        assert!(endpoint("http://user:password@localhost:5890", "/v1").is_err());
        assert!(endpoint("file:///data/lux", "/v1").is_err());
        assert!(endpoint("http://localhost:5890?target=other", "/v1").is_err());
    }
}
