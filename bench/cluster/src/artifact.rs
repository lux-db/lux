use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::ARTIFACT_SCHEMA_VERSION;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    Standalone,
    Native,
    Compatibility,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadProfile {
    Saturation,
    EqualRate,
}

impl LoadProfile {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Saturation => "saturation",
            Self::EqualRate => "equal_rate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadId {
    KvGet256,
    KvSet256,
    KvMixed256,
    TableGet1k,
    TableUpsert1k,
    TableMixed1k,
}

impl WorkloadId {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KvGet256 => "kv_get256",
            Self::KvSet256 => "kv_set256",
            Self::KvMixed256 => "kv_mixed256",
            Self::TableGet1k => "table_get1k",
            Self::TableUpsert1k => "table_upsert1k",
            Self::TableMixed1k => "table_mixed1k",
        }
    }

    #[must_use]
    pub const fn is_table(self) -> bool {
        matches!(
            self,
            Self::TableGet1k | Self::TableUpsert1k | Self::TableMixed1k
        )
    }

    #[must_use]
    pub const fn is_mixed(self) -> bool {
        matches!(self, Self::KvMixed256 | Self::TableMixed1k)
    }

    #[must_use]
    pub const fn is_read(self, operation: u64) -> bool {
        match self {
            Self::KvGet256 | Self::TableGet1k => true,
            Self::KvSet256 | Self::TableUpsert1k => false,
            Self::KvMixed256 | Self::TableMixed1k => !operation.is_multiple_of(5),
        }
    }

    #[must_use]
    pub const fn value_size(self) -> usize {
        if self.is_table() {
            1024
        } else {
            256
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct LatencySummary {
    pub count: u64,
    pub min_us: u64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
    pub mean_us: f64,
}

impl Default for LatencySummary {
    fn default() -> Self {
        Self {
            count: 0,
            min_us: 0,
            p50_us: 0,
            p95_us: 0,
            p99_us: 0,
            max_us: 0,
            mean_us: 0.0,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct RouteEvidence {
    pub owner_local_operations: u64,
    pub moved_responses: u64,
    pub ask_responses: u64,
    pub compatibility_forwards: u64,
    pub point_peer_frames: u64,
    pub point_peer_bytes: u64,
    pub connection_attempts: u64,
    pub tls_handshakes: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct OwnerMeasurement {
    pub owner_id: String,
    pub host_id: String,
    pub successful_operations: u64,
    pub failed_operations: u64,
    pub duration_seconds: f64,
    pub useful_operations_per_second: f64,
    pub latency: LatencySummary,
    pub one_second_successes: Vec<u64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SampleArtifact {
    pub sample_id: String,
    pub workload: WorkloadId,
    pub mode: RunMode,
    pub load_profile: LoadProfile,
    pub node_count: usize,
    pub pipeline_depth: usize,
    pub clients_per_owner: usize,
    pub key_space_per_owner: usize,
    pub value_size_bytes: usize,
    pub seed: u64,
    pub target_operations_per_second_per_owner: Option<f64>,
    pub valid: bool,
    #[serde(default)]
    pub invalid_reasons: Vec<String>,
    pub owners: Vec<OwnerMeasurement>,
    pub aggregate_successful_operations: u64,
    pub aggregate_failed_operations: u64,
    pub duration_seconds: f64,
    pub aggregate_useful_operations_per_second: f64,
    pub aggregate_latency: LatencySummary,
    #[serde(default)]
    pub route_evidence: RouteEvidence,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct TransitionArtifact {
    pub transition_id: String,
    pub workload: WorkloadId,
    pub from_nodes: usize,
    pub to_nodes: usize,
    pub valid: bool,
    #[serde(default)]
    pub invalid_reasons: Vec<String>,
    pub duration_seconds: f64,
    pub steady_operations_per_second: f64,
    pub one_second_successes: Vec<u64>,
    pub pre_transition_p99_us: u64,
    pub transition_p99_us: u64,
    pub failed_logical_operations: u64,
    pub missing_committed_operations: u64,
    pub duplicate_committed_operations: u64,
    pub source_target_divergences: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CostArtifact {
    pub workload: WorkloadId,
    pub node_count: usize,
    pub standalone_operations_per_core: f64,
    pub cluster_operations_per_core: f64,
    pub standalone_operations_per_dollar: f64,
    pub cluster_operations_per_dollar: f64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EnvironmentArtifact {
    pub provider: String,
    pub engine_binary_sha256: String,
    pub candidate_git_sha: String,
    pub harness_git_sha: String,
    pub load_generator_host: String,
    pub observer_host: String,
    pub engine_hosts: Vec<String>,
    pub isolated_processes: bool,
    pub external_load_generator: bool,
    pub homogeneous_engine_resources: bool,
    pub load_generator_headroom_ratio: f64,
    pub max_engine_nic_utilization: f64,
    pub max_engine_cpu_throttle_seconds: f64,
    pub max_observer_cpu_ratio: f64,
    pub max_clock_offset_ms: f64,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CertificationArtifact {
    pub schema_version: u32,
    pub run_id: String,
    pub environment: EnvironmentArtifact,
    pub samples: Vec<SampleArtifact>,
    #[serde(default)]
    pub transitions: Vec<TransitionArtifact>,
    #[serde(default)]
    pub costs: Vec<CostArtifact>,
}

impl CertificationArtifact {
    #[must_use]
    pub fn new(run_id: impl Into<String>, environment: EnvironmentArtifact) -> Self {
        Self {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            run_id: run_id.into(),
            environment,
            samples: Vec::new(),
            transitions: Vec::new(),
            costs: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_uses_snake_case_wire_values() {
        let value = serde_json::to_value(WorkloadId::TableUpsert1k).unwrap();
        assert_eq!(value, "table_upsert1k");
        let value = serde_json::to_value(RunMode::Compatibility).unwrap();
        assert_eq!(value, "compatibility");
        let value = serde_json::to_value(LoadProfile::EqualRate).unwrap();
        assert_eq!(value, "equal_rate");
    }

    #[test]
    fn mixed_workloads_are_deterministic_eighty_twenty() {
        let reads = (0..100)
            .filter(|operation| WorkloadId::KvMixed256.is_read(*operation))
            .count();
        assert_eq!(reads, 80);
    }
}
