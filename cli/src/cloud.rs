use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

const CLOUD_API_PREFIX: &str = "/cloud/v1";
const POLL_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub(crate) struct CloudClient {
    http: reqwest::Client,
    base_url: String,
    token: String,
}

impl CloudClient {
    pub(crate) fn new(http: reqwest::Client, api_url: &str, token: &str) -> Self {
        Self {
            http,
            base_url: format!("{}{}", api_url.trim_end_matches('/'), CLOUD_API_PREFIX),
            token: token.to_string(),
        }
    }

    pub(crate) async fn workspaces(&self) -> Result<Vec<Workspace>, CloudError> {
        self.request(Method::GET, "/workspaces", None, None).await
    }

    pub(crate) async fn projects(&self, workspace_id: &str) -> Result<Vec<Project>, CloudError> {
        let mut url = reqwest::Url::parse(&format!("{}/projects", self.base_url))
            .map_err(|error| CloudError::client(format!("invalid cloud API URL: {error}")))?;
        url.query_pairs_mut()
            .append_pair("workspace_id", workspace_id);
        self.request_url(Method::GET, url, None, None).await
    }

    pub(crate) async fn resolve_project(&self, selector: &str) -> Result<Project, CloudError> {
        let workspaces = self.workspaces().await?;
        if workspaces.is_empty() {
            return Err(CloudError::client("no workspace found for this token"));
        }
        let mut projects = Vec::new();
        for workspace in workspaces {
            projects.extend(self.projects(&workspace.id).await?);
        }
        select_project(projects, selector)
    }

    pub(crate) async fn create_project(
        &self,
        workspace_id: &str,
        name: &str,
        memory_mb: u32,
        idempotency_key: &str,
    ) -> Result<Accepted<Project>, CloudError> {
        self.request(
            Method::POST,
            "/projects",
            Some(serde_json::json!({
                "workspace_id": workspace_id,
                "name": name,
                "memory_mb": memory_mb,
            })),
            Some(idempotency_key),
        )
        .await
    }

    pub(crate) async fn project_action(
        &self,
        project_id: &str,
        action: &str,
        payload: serde_json::Value,
        idempotency_key: &str,
    ) -> Result<Accepted<Project>, CloudError> {
        self.request(
            Method::POST,
            &format!("/projects/{project_id}/actions/{action}"),
            Some(payload),
            Some(idempotency_key),
        )
        .await
    }

    pub(crate) async fn delete_project(
        &self,
        project_id: &str,
        idempotency_key: &str,
    ) -> Result<Accepted<Project>, CloudError> {
        self.request(
            Method::DELETE,
            &format!("/projects/{project_id}"),
            None,
            Some(idempotency_key),
        )
        .await
    }

    pub(crate) async fn snapshots(&self, project_id: &str) -> Result<Vec<Snapshot>, CloudError> {
        self.request(
            Method::GET,
            &format!("/projects/{project_id}/snapshots"),
            None,
            None,
        )
        .await
    }

    pub(crate) async fn create_snapshot(
        &self,
        project_id: &str,
        idempotency_key: &str,
    ) -> Result<Accepted<Snapshot>, CloudError> {
        self.request(
            Method::POST,
            &format!("/projects/{project_id}/snapshots"),
            None,
            Some(idempotency_key),
        )
        .await
    }

    pub(crate) async fn restore_snapshot(
        &self,
        project_id: &str,
        snapshot_id: &str,
        idempotency_key: &str,
    ) -> Result<Accepted<Snapshot>, CloudError> {
        self.request(
            Method::POST,
            &format!("/projects/{project_id}/snapshots/{snapshot_id}/restore"),
            None,
            Some(idempotency_key),
        )
        .await
    }

    pub(crate) async fn operations(&self, project_id: &str) -> Result<Vec<Operation>, CloudError> {
        self.request(
            Method::GET,
            &format!("/projects/{project_id}/operations"),
            None,
            None,
        )
        .await
    }

    pub(crate) async fn operation(&self, operation_id: &str) -> Result<Operation, CloudError> {
        self.request(
            Method::GET,
            &format!("/operations/{operation_id}"),
            None,
            None,
        )
        .await
    }

    pub(crate) async fn wait_for_operation<F>(
        &self,
        operation_id: &str,
        timeout: Duration,
        mut on_change: F,
    ) -> Result<Operation, WaitError>
    where
        F: FnMut(&Operation),
    {
        let started = Instant::now();
        let mut last_state: Option<(String, String, u8, Option<String>)> = None;
        loop {
            let operation = self.operation(operation_id).await.map_err(WaitError::Api)?;
            let state = (
                operation.status.clone(),
                operation.phase.clone(),
                operation.progress,
                operation.message.clone(),
            );
            if last_state.as_ref() != Some(&state) {
                on_change(&operation);
                last_state = Some(state);
            }
            if operation.is_terminal() {
                return Ok(operation);
            }
            if started.elapsed() >= timeout {
                return Err(WaitError::Timeout {
                    operation_id: operation_id.to_string(),
                    timeout,
                });
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        payload: Option<serde_json::Value>,
        idempotency_key: Option<&str>,
    ) -> Result<T, CloudError> {
        let url = reqwest::Url::parse(&format!("{}{}", self.base_url, path))
            .map_err(|error| CloudError::client(format!("invalid cloud API URL: {error}")))?;
        self.request_url(method, url, payload, idempotency_key)
            .await
    }

    async fn request_url<T: DeserializeOwned>(
        &self,
        method: Method,
        url: reqwest::Url,
        payload: Option<serde_json::Value>,
        idempotency_key: Option<&str>,
    ) -> Result<T, CloudError> {
        let mut request = self
            .http
            .request(method, url)
            .bearer_auth(&self.token)
            .header("Accept", "application/json");
        if let Some(payload) = payload {
            request = request.json(&payload);
        }
        if let Some(key) = idempotency_key {
            request = request.header("Idempotency-Key", key);
        }
        let response = request.send().await.map_err(|error| CloudError {
            code: "cloud_unavailable".to_string(),
            message: format!("Cloud request failed: {error}"),
            request_id: None,
            status: None,
        })?;
        let status = response.status();
        let bytes = response.bytes().await.map_err(|error| CloudError {
            code: "invalid_response".to_string(),
            message: format!("Cloud response could not be read: {error}"),
            request_id: None,
            status: Some(status.as_u16()),
        })?;
        if status.is_success() {
            let envelope: DataEnvelope<T> =
                serde_json::from_slice(&bytes).map_err(|error| CloudError {
                    code: "invalid_response".to_string(),
                    message: format!(
                        "Cloud returned invalid JSON (HTTP {}): {error}",
                        status.as_u16()
                    ),
                    request_id: None,
                    status: Some(status.as_u16()),
                })?;
            return Ok(envelope.data);
        }
        let parsed: Result<ErrorEnvelope, _> = serde_json::from_slice(&bytes);
        match parsed {
            Ok(envelope) => Err(CloudError {
                code: envelope.error.code,
                message: envelope.error.message,
                request_id: Some(envelope.error.request_id),
                status: Some(status.as_u16()),
            }),
            Err(_) => Err(CloudError {
                code: "cloud_error".to_string(),
                message: format!("Cloud request failed (HTTP {}).", status.as_u16()),
                request_id: None,
                status: Some(status.as_u16()),
            }),
        }
    }
}

fn select_project(projects: Vec<Project>, selector: &str) -> Result<Project, CloudError> {
    if let Some(project) = projects.iter().find(|project| project.id == selector) {
        return Ok(project.clone());
    }
    let mut matches = projects
        .into_iter()
        .filter(|project| project.name == selector || project.slug == selector);
    let Some(project) = matches.next() else {
        return Err(CloudError {
            code: "project_not_found".to_string(),
            message: format!("Project '{selector}' was not found."),
            request_id: None,
            status: Some(StatusCode::NOT_FOUND.as_u16()),
        });
    };
    if matches.next().is_some() {
        return Err(CloudError::client(format!(
            "Project name '{selector}' is ambiguous across workspaces; use its ID."
        )));
    }
    Ok(project)
}

#[derive(Debug)]
pub(crate) struct CloudError {
    pub(crate) code: String,
    pub(crate) message: String,
    pub(crate) request_id: Option<String>,
    pub(crate) status: Option<u16>,
}

impl CloudError {
    fn client(message: impl Into<String>) -> Self {
        Self {
            code: "client_error".to_string(),
            message: message.into(),
            request_id: None,
            status: None,
        }
    }
}

impl std::fmt::Display for CloudError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)?;
        if let Some(status) = self.status {
            write!(formatter, " (HTTP {status})")?;
        }
        if let Some(request_id) = &self.request_id {
            write!(formatter, " (request {request_id})")?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum WaitError {
    Api(CloudError),
    Timeout {
        operation_id: String,
        timeout: Duration,
    },
}

impl std::fmt::Display for WaitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Api(error) => error.fmt(formatter),
            Self::Timeout {
                operation_id,
                timeout,
            } => write!(
                formatter,
                "operation {operation_id} did not finish within {} seconds",
                timeout.as_secs()
            ),
        }
    }
}

#[derive(Deserialize)]
struct DataEnvelope<T> {
    data: T,
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Deserialize)]
struct ErrorBody {
    code: String,
    message: String,
    request_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Workspace {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) slug: String,
    pub(crate) role: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Project {
    pub(crate) id: String,
    pub(crate) workspace_id: String,
    pub(crate) name: String,
    pub(crate) slug: String,
    pub(crate) status: String,
    pub(crate) desired_state: String,
    pub(crate) lifecycle_phase: String,
    pub(crate) generation: u64,
    pub(crate) observed_generation: u64,
    pub(crate) version: u64,
    pub(crate) region: String,
    pub(crate) memory_mb: u32,
    pub(crate) auth_enabled: bool,
    pub(crate) deletion_protection: bool,
    pub(crate) safe_error_code: Option<String>,
    pub(crate) safe_error_message: Option<String>,
    pub(crate) public_endpoints: PublicEndpoints,
    pub(crate) conditions: Vec<ProjectCondition>,
    pub(crate) created_at: String,
    pub(crate) started_at: Option<String>,
    pub(crate) deleted_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct PublicEndpoints {
    pub(crate) http: Option<String>,
    pub(crate) resp: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ProjectCondition {
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) status: bool,
    pub(crate) reason: String,
    pub(crate) message: Option<String>,
    pub(crate) observed_generation: u64,
    pub(crate) transitioned_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Operation {
    pub(crate) id: String,
    pub(crate) workspace_id: String,
    pub(crate) project_id: Option<String>,
    pub(crate) kind: String,
    pub(crate) status: String,
    pub(crate) phase: String,
    pub(crate) progress: u8,
    pub(crate) message: Option<String>,
    pub(crate) attempt: u32,
    pub(crate) max_attempts: u32,
    pub(crate) retryable: bool,
    pub(crate) error_code: Option<String>,
    pub(crate) error_message: Option<String>,
    pub(crate) requested_by: Option<String>,
    pub(crate) parent_operation_id: Option<String>,
    pub(crate) created_at: String,
    pub(crate) started_at: Option<String>,
    pub(crate) updated_at: String,
    pub(crate) completed_at: Option<String>,
}

impl Operation {
    pub(crate) fn is_terminal(&self) -> bool {
        matches!(self.status.as_str(), "succeeded" | "failed" | "canceled")
    }

    pub(crate) fn succeeded(&self) -> bool {
        self.status == "succeeded"
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Snapshot {
    pub(crate) id: String,
    pub(crate) project_id: String,
    pub(crate) status: String,
    pub(crate) file_size_bytes: Option<u64>,
    pub(crate) error_code: Option<String>,
    pub(crate) error_message: Option<String>,
    pub(crate) created_at: String,
    pub(crate) completed_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Accepted<T> {
    pub(crate) resource: T,
    pub(crate) operation: Operation,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    async fn server(status: &str, body: &'static str) -> (String, oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = oneshot::channel();
        let status = status.to_string();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                let header_end = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|position| position + 4);
                let Some(header_end) = header_end else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                if request.len() >= header_end + content_length {
                    break;
                }
            }
            request_tx
                .send(String::from_utf8_lossy(&request).into_owned())
                .unwrap();
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        (format!("http://{address}"), request_rx)
    }

    #[test]
    fn terminal_operation_states_are_explicit() {
        let operation = |status: &str| Operation {
            id: "op".to_string(),
            workspace_id: "workspace".to_string(),
            project_id: Some("project".to_string()),
            kind: "project.restart".to_string(),
            status: status.to_string(),
            phase: status.to_string(),
            progress: 100,
            message: None,
            attempt: 1,
            max_attempts: 3,
            retryable: false,
            error_code: None,
            error_message: None,
            requested_by: None,
            parent_operation_id: None,
            created_at: "now".to_string(),
            started_at: None,
            updated_at: "now".to_string(),
            completed_at: None,
        };
        assert!(!operation("queued").is_terminal());
        assert!(!operation("running").is_terminal());
        assert!(operation("succeeded").is_terminal());
        assert!(operation("failed").is_terminal());
        assert!(operation("canceled").is_terminal());
    }

    fn project(id: &str, workspace_id: &str, name: &str) -> Project {
        Project {
            id: id.to_string(),
            workspace_id: workspace_id.to_string(),
            name: name.to_string(),
            slug: name.to_lowercase(),
            status: "running".to_string(),
            desired_state: "running".to_string(),
            lifecycle_phase: "ready".to_string(),
            generation: 1,
            observed_generation: 1,
            version: 1,
            region: "nyc1".to_string(),
            memory_mb: 512,
            auth_enabled: true,
            deletion_protection: false,
            safe_error_code: None,
            safe_error_message: None,
            public_endpoints: PublicEndpoints {
                http: None,
                resp: None,
            },
            conditions: Vec::new(),
            created_at: "now".to_string(),
            started_at: None,
            deleted_at: None,
        }
    }

    #[test]
    fn project_selection_spans_workspaces_and_rejects_ambiguous_names() {
        let projects = vec![
            project("project-a", "workspace-a", "shared"),
            project("project-b", "workspace-b", "shared"),
            project("project-c", "workspace-b", "unique"),
        ];

        assert_eq!(
            select_project(projects.clone(), "project-b")
                .unwrap()
                .workspace_id,
            "workspace-b"
        );
        assert_eq!(
            select_project(projects.clone(), "unique").unwrap().id,
            "project-c"
        );
        assert!(select_project(projects, "shared")
            .unwrap_err()
            .message
            .contains("ambiguous"));
    }

    #[tokio::test]
    async fn mutations_use_v1_path_auth_and_idempotency_headers() {
        let body = r#"{"data":{"accepted":true}}"#;
        let (base_url, request) = server("202 Accepted", body).await;
        let client = CloudClient::new(reqwest::Client::new(), &base_url, "secret-token");

        let accepted: serde_json::Value = client
            .request(
                Method::POST,
                "/projects",
                Some(serde_json::json!({
                    "workspace_id": "workspace",
                    "name": "My Project",
                    "memory_mb": 512,
                })),
                Some("stable-key"),
            )
            .await
            .unwrap();
        let request = request.await.unwrap().to_ascii_lowercase();

        assert_eq!(accepted["accepted"], true);
        assert!(request.starts_with("post /cloud/v1/projects http/1.1\r\n"));
        assert!(request.contains("\r\nauthorization: bearer secret-token\r\n"));
        assert!(request.contains("\r\nidempotency-key: stable-key\r\n"));
        assert!(request.contains(r#""workspace_id":"workspace""#));
        assert!(request.contains(r#""memory_mb":512"#));
    }

    #[tokio::test]
    async fn nested_cloud_errors_preserve_status_and_request_id() {
        let body = r#"{"error":{"code":"PROJECT_OPERATION_CONFLICT","message":"Another lifecycle operation is active.","request_id":"request-123"}}"#;
        let (base_url, _request) = server("409 Conflict", body).await;
        let client = CloudClient::new(reqwest::Client::new(), &base_url, "secret-token");

        let error = client
            .delete_project("project", "stable-key")
            .await
            .unwrap_err();

        assert_eq!(error.code, "PROJECT_OPERATION_CONFLICT");
        assert_eq!(error.status, Some(409));
        assert_eq!(error.request_id.as_deref(), Some("request-123"));
        assert!(error.to_string().contains("HTTP 409"));
    }
}
