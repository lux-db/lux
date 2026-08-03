use super::{ClusterError, SignedTopology};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

fn default_max_frame_bytes() -> usize {
    16 * 1024 * 1024
}

/// Optional runtime configuration for one Cluster data node.
///
/// The standalone binary reads this object from `LUX_CLUSTER_CONFIG`. Embedded
/// users can construct it directly. All filesystem paths are resolved relative
/// to the config file when loaded with [`ClusterConfig::from_file`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub local_node_id: String,
    pub peer_bind_addr: SocketAddr,
    pub certificate_chain_path: PathBuf,
    pub private_key_path: PathBuf,
    pub topology_path: PathBuf,
    /// Node-local durable record of committed and prepared topology epochs.
    pub topology_state_path: PathBuf,
    /// Base64url SEC1-encoded P-256 public key used to verify topology manifests.
    pub controller_public_key: String,
    #[serde(default = "default_max_frame_bytes")]
    pub max_frame_bytes: usize,
}

impl ClusterConfig {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ClusterError> {
        let path = path.as_ref();
        let bytes = std::fs::read(path)?;
        let mut config: Self = serde_json::from_slice(&bytes)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        config.certificate_chain_path = resolve(base, &config.certificate_chain_path);
        config.private_key_path = resolve(base, &config.private_key_path);
        config.topology_path = resolve(base, &config.topology_path);
        config.topology_state_path = resolve(base, &config.topology_state_path);
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ClusterError> {
        if self.local_node_id.trim().is_empty() || self.local_node_id.len() > 128 {
            return Err(ClusterError::InvalidConfig(
                "local_node_id must contain 1 to 128 characters".to_string(),
            ));
        }
        if self.peer_bind_addr.port() == 0 {
            return Err(ClusterError::InvalidConfig(
                "peer_bind_addr must use an explicit port".to_string(),
            ));
        }
        if self.max_frame_bytes < 1024 || self.max_frame_bytes > 64 * 1024 * 1024 {
            return Err(ClusterError::InvalidConfig(
                "max_frame_bytes must be between 1 KiB and 64 MiB".to_string(),
            ));
        }
        if self.controller_public_key.trim().is_empty() {
            return Err(ClusterError::InvalidConfig(
                "controller_public_key is required".to_string(),
            ));
        }
        Ok(())
    }

    pub fn load_topology(&self) -> Result<SignedTopology, ClusterError> {
        let bytes = std::fs::read(&self.topology_path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

fn resolve(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_relative_paths_against_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("config");
        std::fs::create_dir_all(&nested).unwrap();
        let path = nested.join("node.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "local_node_id": "node-1",
                "peer_bind_addr": "127.0.0.1:7001",
                "certificate_chain_path": "node.pem",
                "private_key_path": "node.key",
                "topology_path": "topology.json",
                "topology_state_path": "data/topology-state.json",
                "controller_public_key": "not-decoded-until-topology-verification"
            })
            .to_string(),
        )
        .unwrap();

        let config = ClusterConfig::from_file(path).unwrap();
        assert_eq!(config.certificate_chain_path, nested.join("node.pem"));
        assert_eq!(config.private_key_path, nested.join("node.key"));
        assert_eq!(config.topology_path, nested.join("topology.json"));
        assert_eq!(
            config.topology_state_path,
            nested.join("data/topology-state.json")
        );
        assert_eq!(config.max_frame_bytes, 16 * 1024 * 1024);
    }
}
