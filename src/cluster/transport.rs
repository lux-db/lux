use super::control::{decode_request, decode_response, encode_request, encode_response};
use super::durable_state::read_bounded;
use super::topology::decode_certificate;
use super::{
    certificate_fingerprint, ClusterError, ControlRejectCode, ControlRequest, ControlRequestBody,
    ControlRequestId, ControlResponse, ControlResponseBody, NodeDescriptor, ServingSnapshot,
    ServingState, TopologyState, CLUSTER_PROTOCOL_VERSION, MAX_CONTROL_DEADLINE_MS,
};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{
    ClientConfig, Connection, Endpoint, IdleTimeout, RecvStream, SendStream, ServerConfig,
    TransportConfig,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{server::WebPkiClientVerifier, RootCertStore};
use std::collections::HashMap;
use std::future::Future;
use std::io::Cursor;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const CONTROL_ALPN: &[u8] = b"lux-cluster-control/1";
const MIN_CONTROL_FRAME_BYTES: usize = 256;
const MAX_CONTROL_FRAME_BYTES: usize = 4 * 1024 * 1024;
const MAX_IDENTITY_FILE_BYTES: u64 = 1024 * 1024;
const MAX_SERVER_CONNECTIONS: usize = 64;
const MAX_SERVER_STREAM_TASKS: usize = 512;
const MAX_IN_FLIGHT_FRAME_BYTES: usize = 64 * 1024 * 1024;
const CONTROL_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct PeerControlConfig {
    pub local_node_id: String,
    pub peer_bind_addr: SocketAddr,
    pub certificate_chain_path: PathBuf,
    pub private_key_path: PathBuf,
    pub max_frame_bytes: usize,
    pub max_request_duration: Duration,
}

impl PeerControlConfig {
    fn validate(&self) -> Result<(), ClusterError> {
        if self.local_node_id.is_empty() || self.local_node_id.len() > 128 {
            return config_invalid("local node id must contain 1 to 128 bytes");
        }
        if self.peer_bind_addr.port() == 0 {
            return config_invalid("peer control bind port must be nonzero");
        }
        if !(MIN_CONTROL_FRAME_BYTES..=MAX_CONTROL_FRAME_BYTES).contains(&self.max_frame_bytes) {
            return config_invalid(format!(
                "peer control frame limit must be {MIN_CONTROL_FRAME_BYTES} to {MAX_CONTROL_FRAME_BYTES} bytes"
            ));
        }
        if self.max_request_duration.is_zero()
            || self.max_request_duration > Duration::from_millis(MAX_CONTROL_DEADLINE_MS)
        {
            return config_invalid(format!(
                "peer control request duration must be 1 to {MAX_CONTROL_DEADLINE_MS} milliseconds"
            ));
        }
        Ok(())
    }
}

struct IdentityMaterial {
    certificates: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
}

struct CachedConnection {
    certificate_sha256: String,
    connection: Connection,
}

#[derive(Clone)]
struct AuthenticatedPeer {
    node_id: String,
    certificate_sha256: String,
}

/// A request accepted only after mTLS identity and immutable serving-generation
/// validation. Handlers cannot observe topology and execution from different
/// publications.
pub struct AuthenticatedControlRequest {
    source_node_id: String,
    request: ControlRequest,
    serving: Arc<ServingSnapshot>,
}

impl AuthenticatedControlRequest {
    #[must_use]
    pub fn source_node_id(&self) -> &str {
        &self.source_node_id
    }

    #[must_use]
    pub fn request(&self) -> &ControlRequest {
        &self.request
    }

    #[must_use]
    pub fn serving(&self) -> &ServingSnapshot {
        &self.serving
    }
}

/// Persistent, multiplexed, mutually authenticated transport reserved for
/// cluster control, recovery, and explicitly modeled compatibility messages.
/// It has no generic user-command forwarding surface.
pub struct PeerControlTransport {
    local_node_id: String,
    endpoint: Endpoint,
    topology: Arc<TopologyState>,
    serving: Arc<ServingState>,
    identity: Arc<IdentityMaterial>,
    connections: tokio::sync::Mutex<HashMap<String, CachedConnection>>,
    connection_slots: Arc<tokio::sync::Semaphore>,
    stream_slots: Arc<tokio::sync::Semaphore>,
    frame_budget: Arc<tokio::sync::Semaphore>,
    max_frame_bytes: usize,
    max_request_duration: Duration,
}

impl PeerControlTransport {
    pub fn bind(
        config: &PeerControlConfig,
        topology: Arc<TopologyState>,
        serving: Arc<ServingState>,
    ) -> Result<Arc<Self>, ClusterError> {
        config.validate()?;
        let snapshot = serving.snapshot();
        let topology_snapshot = topology.snapshot();
        if topology_snapshot.current().signed() != snapshot.topology().signed() {
            return config_invalid(
                "peer transport topology state does not match the published serving topology",
            );
        }
        let local = snapshot
            .topology()
            .node(&config.local_node_id)
            .ok_or_else(|| {
                ClusterError::InvalidConfig(format!(
                    "local node {} is absent from serving topology epoch {}",
                    config.local_node_id,
                    snapshot.topology().manifest().epoch
                ))
            })?;
        if peer_port(&local.peer_addr) != Some(config.peer_bind_addr.port()) {
            return config_invalid(format!(
                "peer control bind port {} does not match signed endpoint {}",
                config.peer_bind_addr.port(),
                local.peer_addr
            ));
        }

        let certificates = load_certificates(&config.certificate_chain_path)?;
        let private_key = load_private_key(&config.private_key_path)?;
        if certificate_fingerprint(certificates[0].as_ref()) != local.peer_certificate_sha256 {
            return config_invalid("local certificate does not match the signed topology");
        }
        let identity = Arc::new(IdentityMaterial {
            certificates,
            private_key,
        });
        let server_config = build_server_config(&topology.trusted_nodes(), &identity)?;
        let endpoint = Endpoint::server(server_config, config.peer_bind_addr).map_err(|error| {
            ClusterError::Transport(format!("failed to bind peer control endpoint: {error}"))
        })?;

        Ok(Arc::new(Self {
            local_node_id: config.local_node_id.clone(),
            endpoint,
            topology,
            serving,
            identity,
            connections: tokio::sync::Mutex::new(HashMap::new()),
            connection_slots: Arc::new(tokio::sync::Semaphore::new(MAX_SERVER_CONNECTIONS)),
            stream_slots: Arc::new(tokio::sync::Semaphore::new(MAX_SERVER_STREAM_TASKS)),
            frame_budget: Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT_FRAME_BYTES)),
            max_frame_bytes: config.max_frame_bytes,
            max_request_duration: config.max_request_duration,
        }))
    }

    pub fn local_addr(&self) -> Result<SocketAddr, ClusterError> {
        self.endpoint.local_addr().map_err(|error| {
            ClusterError::Transport(format!("peer control endpoint has no address: {error}"))
        })
    }

    /// Admit prepared certificates for future handshakes. Per-stream
    /// authorization still requires the certificate to be committed in the
    /// one serving snapshot used for that request.
    pub fn refresh_server_trust(&self) -> Result<(), ClusterError> {
        let server_config = build_server_config(&self.topology.trusted_nodes(), &self.identity)?;
        self.endpoint.set_server_config(Some(server_config));
        Ok(())
    }

    pub async fn request(
        &self,
        target_node_id: &str,
        body: ControlRequestBody,
        timeout: Duration,
    ) -> Result<ControlResponse, ClusterError> {
        if timeout.is_zero() || timeout > self.max_request_duration {
            return protocol_error("control request timeout is outside the configured bound");
        }
        let serving = self.serving.snapshot();
        if serving.topology().node(target_node_id).is_none() {
            return Err(ClusterError::InvalidTopology(format!(
                "target node {target_node_id} is absent from serving topology"
            )));
        }
        if target_node_id == self.local_node_id {
            return protocol_error("local control work must use the direct handler path");
        }
        let now = unix_time_ms();
        let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(MAX_CONTROL_DEADLINE_MS);
        let request = ControlRequest {
            protocol_version: CLUSTER_PROTOCOL_VERSION,
            cluster_id: serving.topology().manifest().cluster_id.clone(),
            topology_epoch: serving.topology().manifest().epoch,
            execution_version: serving.execution().manifest().version,
            source_node_id: self.local_node_id.clone(),
            target_node_id: target_node_id.to_owned(),
            request_id: ControlRequestId::random()?,
            deadline_unix_ms: now.saturating_add(timeout_ms),
            body,
        };
        self.request_envelope(target_node_id, request, timeout)
            .await
    }

    async fn request_envelope(
        &self,
        target_node_id: &str,
        request: ControlRequest,
        timeout: Duration,
    ) -> Result<ControlResponse, ClusterError> {
        if request.source_node_id != self.local_node_id || request.target_node_id != target_node_id
        {
            return protocol_error("control request identity does not match its transport call");
        }
        request.validate_untrusted(unix_time_ms()).map_err(|code| {
            ClusterError::Protocol(format!("control request rejected: {code:?}"))
        })?;
        let encoded = encode_request(&request)?;
        let operation = async {
            let connection = self.connection(target_node_id).await?;
            let (mut send, mut receive) = connection.open_bi().await.map_err(|error| {
                ClusterError::Transport(format!("failed to open peer control stream: {error}"))
            })?;
            write_frame(&mut send, &encoded, self.max_frame_bytes).await?;
            send.finish().map_err(|error| {
                ClusterError::Transport(format!("failed to finish peer control request: {error}"))
            })?;
            let frame = read_frame(
                &mut receive,
                self.max_frame_bytes,
                Arc::clone(&self.frame_budget),
            )
            .await?;
            let response = decode_response(&frame.bytes)?;
            response.validate_for(&request)?;
            Ok(response)
        };
        tokio::time::timeout(timeout, operation)
            .await
            .map_err(|_| ClusterError::Transport("peer control request timed out".to_owned()))?
    }

    async fn connection(&self, target_node_id: &str) -> Result<Connection, ClusterError> {
        let serving = self.serving.snapshot();
        let peer = serving.topology().node(target_node_id).ok_or_else(|| {
            ClusterError::InvalidTopology(format!(
                "target node {target_node_id} is absent from serving topology"
            ))
        })?;
        {
            let mut connections = self.connections.lock().await;
            if let Some(cached) = connections.get(target_node_id) {
                if cached.certificate_sha256 == peer.peer_certificate_sha256
                    && cached.connection.close_reason().is_none()
                {
                    return Ok(cached.connection.clone());
                }
            }
            if let Some(stale) = connections.remove(target_node_id) {
                stale
                    .connection
                    .close(1_u32.into(), b"signed peer identity changed");
            }
        }

        let client_config = build_client_config(peer, &self.identity)?;
        let peer_addr = tokio::net::lookup_host(&peer.peer_addr)
            .await
            .map_err(|error| {
                ClusterError::Transport(format!(
                    "failed to resolve peer {} at {}: {error}",
                    peer.node_id, peer.peer_addr
                ))
            })?
            .next()
            .ok_or_else(|| {
                ClusterError::Transport(format!(
                    "peer {} address {} resolved to no endpoints",
                    peer.node_id, peer.peer_addr
                ))
            })?;
        let connecting = self
            .endpoint
            .connect_with(client_config, peer_addr, &peer.peer_server_name)
            .map_err(|error| {
                ClusterError::Transport(format!("failed to begin peer connection: {error}"))
            })?;
        let connection = tokio::time::timeout(self.max_request_duration, connecting)
            .await
            .map_err(|_| ClusterError::Transport("peer TLS handshake timed out".to_owned()))?
            .map_err(|error| {
                ClusterError::Transport(format!("peer TLS handshake failed: {error}"))
            })?;
        verify_connection_certificate(&connection, &peer.peer_certificate_sha256)?;

        let mut connections = self.connections.lock().await;
        if let Some(existing) = connections.get(target_node_id) {
            if existing.certificate_sha256 == peer.peer_certificate_sha256
                && existing.connection.close_reason().is_none()
            {
                connection.close(0_u32.into(), b"duplicate peer connection");
                return Ok(existing.connection.clone());
            }
        }
        connections.insert(
            target_node_id.to_owned(),
            CachedConnection {
                certificate_sha256: peer.peer_certificate_sha256.clone(),
                connection: connection.clone(),
            },
        );
        Ok(connection)
    }

    pub async fn serve<F, Fut>(self: Arc<Self>, handler: F)
    where
        F: Fn(AuthenticatedControlRequest) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<ControlResponseBody, ClusterError>> + Send + 'static,
    {
        while let Some(incoming) = self.endpoint.accept().await {
            let Ok(connection_slot) = Arc::clone(&self.connection_slots).try_acquire_owned() else {
                incoming.refuse();
                continue;
            };
            let transport = Arc::clone(&self);
            let handler = handler.clone();
            tokio::spawn(async move {
                let _connection_slot = connection_slot;
                let connection =
                    match tokio::time::timeout(transport.max_request_duration, incoming).await {
                        Ok(Ok(connection)) => connection,
                        _ => return,
                    };
                let authenticated_peer = match transport.authenticated_source(&connection) {
                    Ok(peer) => peer,
                    Err(_) => {
                        connection.close(1_u32.into(), b"untrusted peer certificate");
                        return;
                    }
                };
                loop {
                    let Ok((send, receive)) = connection.accept_bi().await else {
                        break;
                    };
                    let Ok(stream_slot) = Arc::clone(&transport.stream_slots).try_acquire_owned()
                    else {
                        drop(send);
                        drop(receive);
                        continue;
                    };
                    let transport = Arc::clone(&transport);
                    let handler = handler.clone();
                    let authenticated_peer = authenticated_peer.clone();
                    tokio::spawn(async move {
                        let _stream_slot = stream_slot;
                        let _ = transport
                            .handle_stream(send, receive, authenticated_peer, handler)
                            .await;
                    });
                }
            });
        }
    }

    async fn handle_stream<F, Fut>(
        &self,
        mut send: SendStream,
        mut receive: RecvStream,
        authenticated_peer: AuthenticatedPeer,
        handler: F,
    ) -> Result<(), ClusterError>
    where
        F: Fn(AuthenticatedControlRequest) -> Fut,
        Fut: Future<Output = Result<ControlResponseBody, ClusterError>>,
    {
        let encoded = tokio::time::timeout(
            self.max_request_duration,
            read_frame(
                &mut receive,
                self.max_frame_bytes,
                Arc::clone(&self.frame_budget),
            ),
        )
        .await
        .map_err(|_| ClusterError::Transport("peer control frame timed out".to_owned()))??;
        let request = decode_request(&encoded.bytes)?;
        let serving = self.serving.snapshot();
        let authorization = self.authorize(&request, &authenticated_peer, Arc::clone(&serving));
        let body = match authorization {
            Ok(authenticated) => {
                let remaining = request.deadline_unix_ms.saturating_sub(unix_time_ms());
                if remaining == 0 {
                    ControlResponseBody::Rejected {
                        code: ControlRejectCode::DeadlineElapsed,
                    }
                } else {
                    match tokio::time::timeout(
                        Duration::from_millis(remaining),
                        handler(authenticated),
                    )
                    .await
                    {
                        Ok(Ok(body)) => body,
                        _ => ControlResponseBody::Rejected {
                            code: ControlRejectCode::HandlerFailed,
                        },
                    }
                }
            }
            Err(code) => ControlResponseBody::Rejected { code },
        };
        let response = ControlResponse {
            protocol_version: CLUSTER_PROTOCOL_VERSION,
            cluster_id: request.cluster_id.clone(),
            topology_epoch: serving.topology().manifest().epoch,
            execution_version: serving.execution().manifest().version,
            source_node_id: self.local_node_id.clone(),
            target_node_id: request.source_node_id.clone(),
            request_id: request.request_id,
            body,
        };
        let encoded = encode_response(&response)?;
        let remaining = request.deadline_unix_ms.saturating_sub(unix_time_ms());
        if remaining == 0 {
            return Ok(());
        }
        tokio::time::timeout(
            Duration::from_millis(remaining),
            write_frame(&mut send, &encoded, self.max_frame_bytes),
        )
        .await
        .map_err(|_| ClusterError::Transport("peer control response timed out".to_owned()))??;
        send.finish().map_err(|error| {
            ClusterError::Transport(format!("failed to finish peer control response: {error}"))
        })?;
        Ok(())
    }

    fn authorize(
        &self,
        request: &ControlRequest,
        peer: &AuthenticatedPeer,
        serving: Arc<ServingSnapshot>,
    ) -> Result<AuthenticatedControlRequest, ControlRejectCode> {
        request.validate_untrusted(unix_time_ms())?;
        if request.cluster_id != serving.topology().manifest().cluster_id {
            return Err(ControlRejectCode::ClusterMismatch);
        }
        if request.source_node_id != peer.node_id {
            return Err(ControlRejectCode::SourceIdentityMismatch);
        }
        if serving
            .topology()
            .node(&peer.node_id)
            .is_none_or(|node| node.peer_certificate_sha256 != peer.certificate_sha256)
        {
            return Err(ControlRejectCode::MembershipPending);
        }
        if request.target_node_id != self.local_node_id {
            return Err(ControlRejectCode::TargetMismatch);
        }
        if request.topology_epoch < serving.topology().manifest().epoch {
            return Err(ControlRejectCode::TopologyStale);
        }
        if request.topology_epoch > serving.topology().manifest().epoch {
            return Err(ControlRejectCode::TopologyAhead);
        }
        if request.execution_version < serving.execution().manifest().version {
            return Err(ControlRejectCode::ExecutionStale);
        }
        if request.execution_version > serving.execution().manifest().version {
            return Err(ControlRejectCode::ExecutionAhead);
        }
        Ok(AuthenticatedControlRequest {
            source_node_id: peer.node_id.clone(),
            request: request.clone(),
            serving,
        })
    }

    fn authenticated_source(
        &self,
        connection: &Connection,
    ) -> Result<AuthenticatedPeer, ClusterError> {
        let certificate = peer_leaf_certificate(connection)?;
        let fingerprint = certificate_fingerprint(certificate.as_ref());
        self.topology
            .trusted_nodes()
            .iter()
            .find(|node| node.peer_certificate_sha256 == fingerprint)
            .map(|node| AuthenticatedPeer {
                node_id: node.node_id.clone(),
                certificate_sha256: fingerprint,
            })
            .ok_or_else(|| {
                ClusterError::Transport(
                    "peer certificate is absent from signed topology state".to_owned(),
                )
            })
    }
}

impl Drop for PeerControlTransport {
    fn drop(&mut self) {
        self.endpoint
            .close(0_u32.into(), b"Lux peer control shutdown");
    }
}

fn build_server_config(
    trusted_nodes: &[NodeDescriptor],
    identity: &IdentityMaterial,
) -> Result<ServerConfig, ClusterError> {
    let mut roots = RootCertStore::empty();
    for node in trusted_nodes {
        roots
            .add(CertificateDer::from(decode_certificate(node)?))
            .map_err(|error| {
                ClusterError::InvalidTopology(format!("invalid peer trust certificate: {error}"))
            })?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|error| {
            ClusterError::Transport(format!("failed to build peer client verifier: {error}"))
        })?;
    let mut tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            identity.certificates.clone(),
            identity.private_key.clone_key(),
        )
        .map_err(|error| {
            ClusterError::InvalidConfig(format!("invalid peer certificate/key: {error}"))
        })?;
    tls.alpn_protocols = vec![CONTROL_ALPN.to_vec()];
    tls.max_early_data_size = 0;
    let crypto = QuicServerConfig::try_from(tls).map_err(|error| {
        ClusterError::Transport(format!("invalid peer QUIC server config: {error}"))
    })?;
    let mut server = ServerConfig::with_crypto(Arc::new(crypto));
    let transport = Arc::get_mut(&mut server.transport).ok_or_else(|| {
        ClusterError::Transport("peer QUIC transport config is unexpectedly shared".to_owned())
    })?;
    transport.max_concurrent_bidi_streams(128_u32.into());
    transport.max_concurrent_uni_streams(0_u8.into());
    transport.max_idle_timeout(Some(control_idle_timeout()?));
    Ok(server)
}

fn build_client_config(
    peer: &NodeDescriptor,
    identity: &IdentityMaterial,
) -> Result<ClientConfig, ClusterError> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(decode_certificate(peer)?))
        .map_err(|error| {
            ClusterError::InvalidTopology(format!("invalid target peer certificate: {error}"))
        })?;
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            identity.certificates.clone(),
            identity.private_key.clone_key(),
        )
        .map_err(|error| {
            ClusterError::InvalidConfig(format!("invalid local peer identity: {error}"))
        })?;
    tls.alpn_protocols = vec![CONTROL_ALPN.to_vec()];
    tls.enable_early_data = false;
    let crypto = QuicClientConfig::try_from(tls).map_err(|error| {
        ClusterError::Transport(format!("invalid peer QUIC client config: {error}"))
    })?;
    let mut client = ClientConfig::new(Arc::new(crypto));
    let mut transport = TransportConfig::default();
    transport.max_concurrent_bidi_streams(0_u8.into());
    transport.max_concurrent_uni_streams(0_u8.into());
    transport.max_idle_timeout(Some(control_idle_timeout()?));
    client.transport_config(Arc::new(transport));
    Ok(client)
}

fn verify_connection_certificate(
    connection: &Connection,
    expected_fingerprint: &str,
) -> Result<(), ClusterError> {
    let certificate = peer_leaf_certificate(connection)?;
    if certificate_fingerprint(certificate.as_ref()) != expected_fingerprint {
        connection.close(1_u32.into(), b"signed certificate pin mismatch");
        return Err(ClusterError::Transport(
            "peer certificate does not match the signed topology".to_owned(),
        ));
    }
    Ok(())
}

fn peer_leaf_certificate(connection: &Connection) -> Result<CertificateDer<'static>, ClusterError> {
    let identity = connection
        .peer_identity()
        .ok_or_else(|| ClusterError::Transport("peer presented no certificate".to_owned()))?;
    let chain = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| {
            ClusterError::Transport("peer identity is not a certificate chain".to_owned())
        })?;
    chain
        .first()
        .cloned()
        .ok_or_else(|| ClusterError::Transport("peer certificate chain is empty".to_owned()))
}

fn load_certificates(path: &std::path::Path) -> Result<Vec<CertificateDer<'static>>, ClusterError> {
    let bytes = read_bounded(path, MAX_IDENTITY_FILE_BYTES)?;
    if bytes.len() as u64 > MAX_IDENTITY_FILE_BYTES {
        return config_invalid("peer certificate file exceeds the size limit");
    }
    let certificates = rustls_pemfile::certs(&mut Cursor::new(&bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            ClusterError::InvalidConfig(format!("failed to parse peer certificate PEM: {error}"))
        })?;
    if !certificates.is_empty() {
        return Ok(certificates);
    }
    if bytes.is_empty() {
        return config_invalid("peer certificate file is empty");
    }
    Ok(vec![CertificateDer::from(bytes)])
}

fn load_private_key(path: &std::path::Path) -> Result<PrivateKeyDer<'static>, ClusterError> {
    let bytes = read_bounded(path, MAX_IDENTITY_FILE_BYTES)?;
    if bytes.len() as u64 > MAX_IDENTITY_FILE_BYTES {
        return config_invalid("peer private-key file exceeds the size limit");
    }
    if let Some(key) = rustls_pemfile::private_key(&mut Cursor::new(&bytes)).map_err(|error| {
        ClusterError::InvalidConfig(format!("failed to parse peer private-key PEM: {error}"))
    })? {
        return Ok(key);
    }
    PrivateKeyDer::try_from(bytes).map_err(|error| {
        ClusterError::InvalidConfig(format!("failed to parse peer private-key DER: {error}"))
    })
}

async fn write_frame(
    stream: &mut SendStream,
    encoded: &[u8],
    max_frame_bytes: usize,
) -> Result<(), ClusterError> {
    if encoded.is_empty() || encoded.len() > max_frame_bytes || encoded.len() > u32::MAX as usize {
        return protocol_error(format!(
            "control frame length {} is outside the allowed range",
            encoded.len()
        ));
    }
    tokio::io::AsyncWriteExt::write_all(stream, &(encoded.len() as u32).to_be_bytes())
        .await
        .map_err(|error| {
            ClusterError::Transport(format!("failed to write control frame length: {error}"))
        })?;
    tokio::io::AsyncWriteExt::write_all(stream, encoded)
        .await
        .map_err(|error| {
            ClusterError::Transport(format!("failed to write control frame body: {error}"))
        })?;
    Ok(())
}

async fn read_frame(
    stream: &mut RecvStream,
    max_frame_bytes: usize,
    frame_budget: Arc<tokio::sync::Semaphore>,
) -> Result<BoundedFrame, ClusterError> {
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length).await.map_err(|error| {
        ClusterError::Transport(format!("failed to read control frame length: {error}"))
    })?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > max_frame_bytes {
        return protocol_error(format!(
            "control frame length {length} is outside the allowed range"
        ));
    }
    let budget = reserve_frame_bytes(frame_budget, length)?;
    let mut encoded = vec![0_u8; length];
    stream.read_exact(&mut encoded).await.map_err(|error| {
        ClusterError::Transport(format!("failed to read control frame body: {error}"))
    })?;
    stream.read_to_end(0).await.map_err(|error| {
        ClusterError::Protocol(format!(
            "control stream must finish after exactly one frame: {error}"
        ))
    })?;
    Ok(BoundedFrame {
        bytes: encoded,
        _budget: budget,
    })
}

struct BoundedFrame {
    bytes: Vec<u8>,
    _budget: tokio::sync::OwnedSemaphorePermit,
}

fn reserve_frame_bytes(
    frame_budget: Arc<tokio::sync::Semaphore>,
    length: usize,
) -> Result<tokio::sync::OwnedSemaphorePermit, ClusterError> {
    let permits = u32::try_from(length)
        .map_err(|_| ClusterError::Protocol("control frame length overflows".to_owned()))?;
    frame_budget
        .try_acquire_many_owned(permits)
        .map_err(|_| ClusterError::Transport("peer control frame budget exhausted".to_owned()))
}

fn control_idle_timeout() -> Result<IdleTimeout, ClusterError> {
    IdleTimeout::try_from(CONTROL_IDLE_TIMEOUT).map_err(|error| {
        ClusterError::InvalidConfig(format!("invalid peer control idle timeout: {error}"))
    })
}

fn peer_port(endpoint: &str) -> Option<u16> {
    reqwest::Url::parse(&format!("cluster-peer://{endpoint}"))
        .ok()?
        .port()
}

fn unix_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

fn config_invalid<T>(message: impl Into<String>) -> Result<T, ClusterError> {
    Err(ClusterError::InvalidConfig(message.into()))
}

fn protocol_error<T>(message: impl Into<String>) -> Result<T, ClusterError> {
    Err(ClusterError::Protocol(message.into()))
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
