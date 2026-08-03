use super::topology::{decode_certificate, peer_port};
use super::{
    certificate_fingerprint, ClusterConfig, ClusterError, PeerRequest, PeerResponse,
    PeerResponseBody, TopologyState, CLUSTER_PROTOCOL_VERSION,
};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{server::WebPkiClientVerifier, RootCertStore};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;
use std::future::Future;
use std::io::Cursor;
use std::sync::Arc;

const ALPN: &[u8] = b"lux-cluster/1";

struct IdentityMaterial {
    certificates: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
}

/// Persistent, multiplexed QUIC peer transport for a single Lux node.
pub(crate) struct PeerTransport {
    local_node_id: String,
    endpoint: Endpoint,
    topology: Arc<TopologyState>,
    identity: Arc<IdentityMaterial>,
    connections: tokio::sync::Mutex<HashMap<String, CachedConnection>>,
    max_frame_bytes: usize,
}

struct CachedConnection {
    certificate_sha256: String,
    connection: Connection,
}

impl PeerTransport {
    pub(crate) fn bind(
        config: &ClusterConfig,
        topology: Arc<TopologyState>,
    ) -> Result<Arc<Self>, ClusterError> {
        config.validate()?;
        let current = topology.current();
        let local = current.node(&config.local_node_id).ok_or_else(|| {
            ClusterError::InvalidConfig(format!(
                "local node {} is absent from topology epoch {}",
                config.local_node_id,
                current.manifest().epoch
            ))
        })?;
        if peer_port(&local.peer_addr) != Some(config.peer_bind_addr.port()) {
            return Err(ClusterError::InvalidConfig(format!(
                "peer bind port {} does not match advertised port {}",
                config.peer_bind_addr.port(),
                peer_port(&local.peer_addr).unwrap_or_default()
            )));
        }

        let certificates = load_certificates(&config.certificate_chain_path)?;
        let private_key = load_private_key(&config.private_key_path)?;
        let local_fingerprint = certificate_fingerprint(certificates[0].as_ref());
        if local_fingerprint != local.certificate_sha256 {
            return Err(ClusterError::InvalidConfig(
                "local certificate does not match the signed topology".to_string(),
            ));
        }
        let identity = Arc::new(IdentityMaterial {
            certificates,
            private_key,
        });
        let server_config = build_server_config(&current, &identity)?;
        let endpoint = Endpoint::server(server_config, config.peer_bind_addr).map_err(|error| {
            ClusterError::Transport(format!("failed to bind QUIC endpoint: {error}"))
        })?;

        Ok(Arc::new(Self {
            local_node_id: config.local_node_id.clone(),
            endpoint,
            topology,
            identity,
            connections: tokio::sync::Mutex::new(HashMap::new()),
            max_frame_bytes: config.max_frame_bytes,
        }))
    }

    pub(crate) fn local_addr(&self) -> Result<std::net::SocketAddr, ClusterError> {
        self.endpoint.local_addr().map_err(|error| {
            ClusterError::Transport(format!("QUIC endpoint has no address: {error}"))
        })
    }

    pub(crate) async fn request(
        &self,
        target_node_id: &str,
        request: &PeerRequest,
    ) -> Result<PeerResponse, ClusterError> {
        if request.source_node_id != self.local_node_id || request.target_node_id != target_node_id
        {
            return Err(ClusterError::Protocol(
                "request source/target does not match transport call".to_string(),
            ));
        }
        let deadline = remaining_deadline(request.deadline_unix_ms)?;
        let operation = async {
            let connection = self.connection(target_node_id).await?;
            let (mut send, mut receive) = connection.open_bi().await.map_err(|error| {
                ClusterError::Transport(format!("failed to open peer stream: {error}"))
            })?;
            write_frame(&mut send, request, self.max_frame_bytes).await?;
            send.finish().map_err(|error| {
                ClusterError::Transport(format!("failed to finish peer request: {error}"))
            })?;
            let response: PeerResponse = read_frame(&mut receive, self.max_frame_bytes).await?;
            if response.protocol_version != CLUSTER_PROTOCOL_VERSION {
                return Err(ClusterError::Protocol(format!(
                    "peer returned protocol version {}",
                    response.protocol_version
                )));
            }
            if response.request_id != request.request_id {
                return Err(ClusterError::Protocol(
                    "peer response request id mismatch".to_string(),
                ));
            }
            Ok(response)
        };
        tokio::time::timeout(deadline, operation)
            .await
            .map_err(|_| {
                ClusterError::Transport(
                    "peer request deadline elapsed; outcome may be unknown".to_string(),
                )
            })?
    }

    async fn connection(&self, target_node_id: &str) -> Result<Connection, ClusterError> {
        let topology = self.topology.current();
        let peer = topology.node(target_node_id).ok_or_else(|| {
            ClusterError::InvalidTopology(format!(
                "target node {target_node_id} is not in topology"
            ))
        })?;
        if peer.node_id == self.local_node_id {
            return Err(ClusterError::Protocol(
                "local requests must use the direct execution path".to_string(),
            ));
        }
        {
            let mut connections = self.connections.lock().await;
            if let Some(cached) = connections.get(target_node_id) {
                if cached.certificate_sha256 == peer.certificate_sha256
                    && cached.connection.close_reason().is_none()
                {
                    return Ok(cached.connection.clone());
                }
            }
            if let Some(stale) = connections.remove(target_node_id) {
                stale
                    .connection
                    .close(1u32.into(), b"topology or certificate changed");
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
            .connect_with(client_config, peer_addr, &peer.server_name)
            .map_err(|error| {
                ClusterError::Transport(format!("failed to begin peer connection: {error}"))
            })?;
        let connection = connecting.await.map_err(|error| {
            ClusterError::Transport(format!("peer TLS handshake failed: {error}"))
        })?;
        verify_connection_certificate(&connection, &peer.certificate_sha256)?;

        let mut connections = self.connections.lock().await;
        if let Some(existing) = connections.get(target_node_id) {
            if existing.certificate_sha256 == peer.certificate_sha256
                && existing.connection.close_reason().is_none()
            {
                connection.close(0u32.into(), b"duplicate peer connection");
                return Ok(existing.connection.clone());
            }
        }
        connections.insert(
            target_node_id.to_string(),
            CachedConnection {
                certificate_sha256: peer.certificate_sha256.clone(),
                connection: connection.clone(),
            },
        );
        Ok(connection)
    }

    /// Accept authenticated streams. The handler runs only after the transport
    /// validates certificate identity, envelope identity, topology epoch, and deadline.
    pub(crate) async fn serve<F, Fut>(self: Arc<Self>, handler: F)
    where
        F: Fn(String, PeerRequest) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = PeerResponse> + Send + 'static,
    {
        while let Some(incoming) = self.endpoint.accept().await {
            let transport = self.clone();
            let handler = handler.clone();
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                let Ok(authenticated_source) = transport.authenticated_source(&connection) else {
                    connection.close(1u32.into(), b"untrusted peer certificate");
                    return;
                };
                loop {
                    let Ok((send, receive)) = connection.accept_bi().await else {
                        break;
                    };
                    let transport = transport.clone();
                    let handler = handler.clone();
                    let authenticated_source = authenticated_source.clone();
                    tokio::spawn(async move {
                        let _ = transport
                            .handle_stream(send, receive, authenticated_source, handler)
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
        authenticated_source: String,
        handler: F,
    ) -> Result<(), ClusterError>
    where
        F: Fn(String, PeerRequest) -> Fut,
        Fut: Future<Output = PeerResponse>,
    {
        let request: PeerRequest = read_frame(&mut receive, self.max_frame_bytes).await?;
        let now = unix_time_ms();
        let topology = self.topology.current();
        let rejection = if let Err(message) = request.validate_envelope(now) {
            Some(PeerResponseBody::Error {
                message: message.to_string(),
            })
        } else if request.cluster_id != topology.manifest().cluster_id {
            Some(PeerResponseBody::Error {
                message: "cluster id mismatch".to_string(),
            })
        } else if request.source_node_id != authenticated_source {
            Some(PeerResponseBody::Error {
                message: "source node id does not match the client certificate".to_string(),
            })
        } else if request.target_node_id != self.local_node_id {
            Some(PeerResponseBody::Error {
                message: "request targeted another node".to_string(),
            })
        } else if request.topology_epoch != topology.manifest().epoch {
            Some(match request.slot {
                Some(slot) if slot < topology.manifest().slot_count => PeerResponseBody::Moved {
                    owner_node_id: topology.owner_for_slot(slot).node_id.clone(),
                    epoch: topology.manifest().epoch,
                },
                _ => PeerResponseBody::Fenced {
                    epoch: topology.manifest().epoch,
                },
            })
        } else {
            None
        };

        let response = match rejection {
            Some(body) => PeerResponse {
                protocol_version: CLUSTER_PROTOCOL_VERSION,
                request_id: request.request_id,
                topology_epoch: topology.manifest().epoch,
                body,
            },
            None => handler(authenticated_source, request).await,
        };
        write_frame(&mut send, &response, self.max_frame_bytes).await?;
        send.finish().map_err(|error| {
            ClusterError::Transport(format!("failed to finish peer response: {error}"))
        })?;
        Ok(())
    }

    fn authenticated_source(&self, connection: &Connection) -> Result<String, ClusterError> {
        let certificate = peer_leaf_certificate(connection)?;
        let fingerprint = certificate_fingerprint(certificate.as_ref());
        self.topology
            .current()
            .manifest()
            .nodes
            .iter()
            .find(|node| node.certificate_sha256 == fingerprint)
            .map(|node| node.node_id.clone())
            .ok_or_else(|| {
                ClusterError::Transport(
                    "client certificate is not in the signed topology".to_string(),
                )
            })
    }
}

impl Drop for PeerTransport {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"Lux node shutdown");
    }
}

fn build_server_config(
    topology: &super::CompiledTopology,
    identity: &IdentityMaterial,
) -> Result<ServerConfig, ClusterError> {
    let mut roots = RootCertStore::empty();
    for node in &topology.manifest().nodes {
        roots
            .add(CertificateDer::from(decode_certificate(node)?))
            .map_err(|error| {
                ClusterError::InvalidTopology(format!("invalid peer certificate: {error}"))
            })?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|error| {
            ClusterError::Transport(format!("failed to build client verifier: {error}"))
        })?;
    let mut tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            identity.certificates.clone(),
            identity.private_key.clone_key(),
        )
        .map_err(|error| {
            ClusterError::Transport(format!("invalid node certificate/key: {error}"))
        })?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.max_early_data_size = 0;
    let crypto = QuicServerConfig::try_from(tls)
        .map_err(|error| ClusterError::Transport(format!("invalid QUIC server config: {error}")))?;
    let mut server = ServerConfig::with_crypto(Arc::new(crypto));
    let transport =
        Arc::get_mut(&mut server.transport).expect("new server config is uniquely owned");
    transport.max_concurrent_bidi_streams(256u32.into());
    transport.max_concurrent_uni_streams(0u8.into());
    Ok(server)
}

fn build_client_config(
    peer: &super::NodeDescriptor,
    identity: &IdentityMaterial,
) -> Result<ClientConfig, ClusterError> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(decode_certificate(peer)?))
        .map_err(|error| {
            ClusterError::InvalidTopology(format!("invalid target certificate: {error}"))
        })?;
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            identity.certificates.clone(),
            identity.private_key.clone_key(),
        )
        .map_err(|error| {
            ClusterError::Transport(format!("invalid client certificate/key: {error}"))
        })?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.enable_early_data = false;
    let crypto = QuicClientConfig::try_from(tls)
        .map_err(|error| ClusterError::Transport(format!("invalid QUIC client config: {error}")))?;
    Ok(ClientConfig::new(Arc::new(crypto)))
}

fn verify_connection_certificate(
    connection: &Connection,
    expected_fingerprint: &str,
) -> Result<(), ClusterError> {
    let certificate = peer_leaf_certificate(connection)?;
    if certificate_fingerprint(certificate.as_ref()) != expected_fingerprint {
        connection.close(1u32.into(), b"certificate pin mismatch");
        return Err(ClusterError::Transport(
            "peer certificate did not match the signed topology".to_string(),
        ));
    }
    Ok(())
}

fn peer_leaf_certificate(connection: &Connection) -> Result<CertificateDer<'static>, ClusterError> {
    let identity = connection
        .peer_identity()
        .ok_or_else(|| ClusterError::Transport("peer did not present a certificate".to_string()))?;
    let chain = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| {
            ClusterError::Transport("peer identity was not a certificate chain".to_string())
        })?;
    chain
        .first()
        .cloned()
        .ok_or_else(|| ClusterError::Transport("peer certificate chain was empty".to_string()))
}

fn load_certificates(path: &std::path::Path) -> Result<Vec<CertificateDer<'static>>, ClusterError> {
    let bytes = std::fs::read(path)?;
    let certificates: Vec<_> = rustls_pemfile::certs(&mut Cursor::new(&bytes))
        .collect::<Result<_, _>>()
        .map_err(|error| {
            ClusterError::InvalidConfig(format!("failed to parse certificate PEM: {error}"))
        })?;
    if !certificates.is_empty() {
        return Ok(certificates);
    }
    if bytes.is_empty() {
        return Err(ClusterError::InvalidConfig(
            "certificate file is empty".to_string(),
        ));
    }
    Ok(vec![CertificateDer::from(bytes)])
}

fn load_private_key(path: &std::path::Path) -> Result<PrivateKeyDer<'static>, ClusterError> {
    let bytes = std::fs::read(path)?;
    if let Some(key) = rustls_pemfile::private_key(&mut Cursor::new(&bytes)).map_err(|error| {
        ClusterError::InvalidConfig(format!("failed to parse private key PEM: {error}"))
    })? {
        return Ok(key);
    }
    PrivateKeyDer::try_from(bytes).map_err(|error| {
        ClusterError::InvalidConfig(format!("failed to parse private key DER: {error}"))
    })
}

async fn write_frame<T: Serialize>(
    stream: &mut SendStream,
    value: &T,
    max_frame_bytes: usize,
) -> Result<(), ClusterError> {
    let encoded = rmp_serde::to_vec_named(value)
        .map_err(|error| ClusterError::Protocol(format!("failed to encode frame: {error}")))?;
    if encoded.len() > max_frame_bytes || encoded.len() > u32::MAX as usize {
        return Err(ClusterError::Protocol(format!(
            "encoded frame exceeds {max_frame_bytes} bytes"
        )));
    }
    tokio::io::AsyncWriteExt::write_all(stream, &(encoded.len() as u32).to_be_bytes())
        .await
        .map_err(|error| {
            ClusterError::Transport(format!("failed to write frame length: {error}"))
        })?;
    tokio::io::AsyncWriteExt::write_all(stream, &encoded)
        .await
        .map_err(|error| ClusterError::Transport(format!("failed to write frame body: {error}")))?;
    Ok(())
}

async fn read_frame<T: DeserializeOwned>(
    stream: &mut RecvStream,
    max_frame_bytes: usize,
) -> Result<T, ClusterError> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).await.map_err(|error| {
        ClusterError::Transport(format!("failed to read frame length: {error}"))
    })?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > max_frame_bytes {
        return Err(ClusterError::Protocol(format!(
            "peer frame length {length} is outside the allowed range"
        )));
    }
    let mut encoded = vec![0u8; length];
    stream
        .read_exact(&mut encoded)
        .await
        .map_err(|error| ClusterError::Transport(format!("failed to read frame body: {error}")))?;
    rmp_serde::from_slice(&encoded)
        .map_err(|error| ClusterError::Protocol(format!("failed to decode frame: {error}")))
}

fn remaining_deadline(deadline_unix_ms: u64) -> Result<std::time::Duration, ClusterError> {
    let now = unix_time_ms();
    let remaining = deadline_unix_ms.saturating_sub(now);
    if remaining == 0 {
        return Err(ClusterError::Protocol(
            "request deadline elapsed".to_string(),
        ));
    }
    Ok(std::time::Duration::from_millis(remaining))
}

pub(crate) fn unix_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::{
        NodeDescriptor, PeerRequestBody, RequestId, SignedTopology, SlotAssignment,
        TopologyManifest, CLUSTER_SLOT_COUNT, CLUSTER_TOPOLOGY_SCHEMA_VERSION,
    };
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::ecdsa::SigningKey;
    use rand_core::OsRng;
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair};

    fn reserve_udp_port() -> u16 {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn identity(
        server_name: &str,
        dir: &std::path::Path,
    ) -> (std::path::PathBuf, std::path::PathBuf, Vec<u8>) {
        let mut params = CertificateParams::new(vec![server_name.to_string()]).unwrap();
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let key = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        let cert_path = dir.join(format!("{server_name}.pem"));
        let key_path = dir.join(format!("{server_name}.key"));
        std::fs::write(&cert_path, certificate.pem()).unwrap();
        std::fs::write(&key_path, key.serialize_pem()).unwrap();
        (cert_path, key_path, certificate.der().to_vec())
    }

    #[tokio::test]
    async fn mutual_tls_transport_multiplexes_authenticated_requests() {
        let dir = tempfile::tempdir().unwrap();
        let port_a = reserve_udp_port();
        let port_b = reserve_udp_port();
        let (cert_a_path, key_a_path, cert_a) = identity("node-a.cluster.local", dir.path());
        let (cert_b_path, key_b_path, cert_b) = identity("node-b.cluster.local", dir.path());
        let signing_key = SigningKey::random(&mut OsRng);
        let public_key = URL_SAFE_NO_PAD.encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let nodes = vec![
            NodeDescriptor {
                node_id: "node-a".into(),
                peer_addr: format!("127.0.0.1:{port_a}"),
                server_name: "node-a.cluster.local".into(),
                certificate_der: URL_SAFE_NO_PAD.encode(&cert_a),
                certificate_sha256: certificate_fingerprint(&cert_a),
            },
            NodeDescriptor {
                node_id: "node-b".into(),
                peer_addr: format!("127.0.0.1:{port_b}"),
                server_name: "node-b.cluster.local".into(),
                certificate_der: URL_SAFE_NO_PAD.encode(&cert_b),
                certificate_sha256: certificate_fingerprint(&cert_b),
            },
        ];
        let manifest = TopologyManifest {
            schema_version: CLUSTER_TOPOLOGY_SCHEMA_VERSION,
            protocol_version: CLUSTER_PROTOCOL_VERSION,
            cluster_id: "cluster-a".into(),
            epoch: 1,
            system_node_id: "node-a".into(),
            slot_count: CLUSTER_SLOT_COUNT,
            catalog_version: 1,
            nodes,
            assignments: vec![
                SlotAssignment {
                    start: 0,
                    end: 2047,
                    node_id: "node-a".into(),
                },
                SlotAssignment {
                    start: 2048,
                    end: 4095,
                    node_id: "node-b".into(),
                },
            ],
        };
        let signed = SignedTopology::sign(manifest, &signing_key).unwrap();
        let compiled = signed.verify(&public_key).unwrap();
        let state_a = Arc::new(TopologyState::in_memory(
            compiled.clone(),
            public_key.clone(),
        ));
        let state_b = Arc::new(TopologyState::in_memory(compiled, public_key.clone()));
        let topology_path = dir.path().join("topology.json");
        std::fs::write(&topology_path, serde_json::to_vec(&signed).unwrap()).unwrap();

        let transport_a = PeerTransport::bind(
            &ClusterConfig {
                local_node_id: "node-a".into(),
                peer_bind_addr: format!("127.0.0.1:{port_a}").parse().unwrap(),
                certificate_chain_path: cert_a_path,
                private_key_path: key_a_path,
                topology_path: topology_path.clone(),
                topology_state_path: dir.path().join("node-a-state.json"),
                controller_public_key: public_key.clone(),
                max_frame_bytes: 1024 * 1024,
            },
            state_a,
        )
        .unwrap();
        let transport_b = PeerTransport::bind(
            &ClusterConfig {
                local_node_id: "node-b".into(),
                peer_bind_addr: format!("127.0.0.1:{port_b}").parse().unwrap(),
                certificate_chain_path: cert_b_path,
                private_key_path: key_b_path,
                topology_path,
                topology_state_path: dir.path().join("node-b-state.json"),
                controller_public_key: public_key,
                max_frame_bytes: 1024 * 1024,
            },
            state_b,
        )
        .unwrap();
        assert_eq!(transport_a.local_addr().unwrap().port(), port_a);
        assert_eq!(transport_b.local_addr().unwrap().port(), port_b);

        let server = transport_b.clone();
        let task = tokio::spawn(server.serve(|source, request| async move {
            PeerResponse {
                protocol_version: CLUSTER_PROTOCOL_VERSION,
                request_id: request.request_id,
                topology_epoch: request.topology_epoch,
                body: PeerResponseBody::Ok(source.into_bytes()),
            }
        }));

        for marker in 0..4u8 {
            let request = PeerRequest {
                protocol_version: CLUSTER_PROTOCOL_VERSION,
                cluster_id: "cluster-a".into(),
                topology_epoch: 1,
                source_node_id: "node-a".into(),
                target_node_id: "node-b".into(),
                request_id: RequestId([marker; 16]),
                deadline_unix_ms: unix_time_ms() + 5_000,
                slot: Some(3000),
                catalog_version: 1,
                body: PeerRequestBody::Probe,
            };
            let response = transport_a.request("node-b", &request).await.unwrap();
            assert_eq!(response.body, PeerResponseBody::Ok(b"node-a".to_vec()));
        }
        assert_eq!(transport_a.endpoint.open_connections(), 1);

        let wrong_cluster = PeerRequest {
            protocol_version: CLUSTER_PROTOCOL_VERSION,
            cluster_id: "another-cluster".into(),
            topology_epoch: 1,
            source_node_id: "node-a".into(),
            target_node_id: "node-b".into(),
            request_id: RequestId([9; 16]),
            deadline_unix_ms: unix_time_ms() + 5_000,
            slot: Some(3000),
            catalog_version: 1,
            body: PeerRequestBody::Probe,
        };
        let response = transport_a.request("node-b", &wrong_cluster).await.unwrap();
        assert!(matches!(response.body, PeerResponseBody::Error { .. }));

        let stale_epoch = PeerRequest {
            cluster_id: "cluster-a".into(),
            topology_epoch: 0,
            request_id: RequestId([10; 16]),
            ..wrong_cluster
        };
        let response = transport_a.request("node-b", &stale_epoch).await.unwrap();
        assert_eq!(
            response.body,
            PeerResponseBody::Moved {
                owner_node_id: "node-b".into(),
                epoch: 1,
            }
        );
        task.abort();
    }
}
