use crate::artifact::{
    CertificationArtifact, CostArtifact, LoadProfile, RunMode, SampleArtifact, TransitionArtifact,
    WorkloadId,
};
use crate::stats::{bootstrap_median_95, coefficient_of_variation, median, ConfidenceInterval};
use crate::ARTIFACT_SCHEMA_VERSION;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GateConfig {
    pub minimum_samples: usize,
    pub bootstrap_iterations: usize,
    pub cluster_tax_minimum: f64,
    pub per_owner_minimum: f64,
    pub aggregate_minimums: BTreeMap<usize, f64>,
    pub one_node_p99_maximum: f64,
    pub multi_node_p99_maximum: f64,
    pub equal_rate_target_tolerance: f64,
    pub equal_rate_delivery_minimum: f64,
    pub resize_throughput_minimum: f64,
    pub resize_p99_maximum: f64,
    pub efficiency_minimum: f64,
    pub maximum_coefficient_of_variation: f64,
    pub maximum_invalid_samples: usize,
    pub maximum_invalid_transitions: usize,
    pub minimum_sample_duration_seconds: f64,
    pub require_certification_environment: bool,
    pub require_compatibility: bool,
    pub require_transitions: bool,
    pub require_costs: bool,
    pub require_equal_rate_latency: bool,
    pub required_workloads: Vec<WorkloadId>,
    pub kv_pipeline_depths: Vec<usize>,
    pub table_pipeline_depths: Vec<usize>,
    pub compatibility_node_counts: Vec<usize>,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            minimum_samples: 5,
            bootstrap_iterations: 10_000,
            cluster_tax_minimum: 0.97,
            per_owner_minimum: 0.97,
            aggregate_minimums: [(1, 0.97), (2, 1.90), (4, 3.70), (8, 7.20)]
                .into_iter()
                .collect(),
            one_node_p99_maximum: 1.05,
            multi_node_p99_maximum: 1.10,
            equal_rate_target_tolerance: 0.01,
            equal_rate_delivery_minimum: 0.99,
            resize_throughput_minimum: 0.90,
            resize_p99_maximum: 1.25,
            efficiency_minimum: 0.90,
            maximum_coefficient_of_variation: 0.03,
            maximum_invalid_samples: 0,
            maximum_invalid_transitions: 0,
            minimum_sample_duration_seconds: 30.0,
            require_certification_environment: true,
            require_compatibility: true,
            require_transitions: true,
            require_costs: true,
            require_equal_rate_latency: true,
            required_workloads: vec![
                WorkloadId::KvGet256,
                WorkloadId::KvSet256,
                WorkloadId::KvMixed256,
                WorkloadId::TableGet1k,
                WorkloadId::TableUpsert1k,
                WorkloadId::TableMixed1k,
            ],
            kv_pipeline_depths: vec![1, 16],
            table_pipeline_depths: vec![1],
            compatibility_node_counts: vec![2, 4, 8],
        }
    }
}

impl GateConfig {
    #[must_use]
    pub fn smoke() -> Self {
        Self {
            minimum_samples: 1,
            bootstrap_iterations: 1,
            minimum_sample_duration_seconds: 0.1,
            require_certification_environment: false,
            require_compatibility: false,
            require_transitions: false,
            require_costs: false,
            require_equal_rate_latency: false,
            required_workloads: vec![WorkloadId::KvSet256],
            kv_pipeline_depths: vec![1],
            aggregate_minimums: [(1, 0.97), (2, 1.90)].into_iter().collect(),
            ..Self::default()
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GateResult {
    pub gate_id: String,
    pub passed: bool,
    pub actual: Option<f64>,
    pub required: String,
    pub details: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerificationReport {
    pub schema_version: u32,
    pub run_id: String,
    pub passed: bool,
    pub gates: Vec<GateResult>,
    pub compatibility_samples: Vec<CompatibilityReport>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompatibilityReport {
    pub workload: WorkloadId,
    pub load_profile: LoadProfile,
    pub node_count: usize,
    pub pipeline_depth: usize,
    pub samples: usize,
    pub median_useful_operations_per_second: f64,
    pub median_p99_us: f64,
    pub forwarded_operations: u64,
    pub point_peer_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct BaselineKey {
    workload: WorkloadId,
    pipeline_depth: usize,
    load_profile: LoadProfile,
    clients_per_owner: usize,
    key_space_per_owner: usize,
    value_size_bytes: usize,
}

#[derive(Clone, Debug, Default)]
struct HostBaseline {
    throughput: Vec<f64>,
    p99_us: Vec<f64>,
    target_operations_per_second: Vec<f64>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct CaseKey {
    workload: WorkloadId,
    pipeline_depth: usize,
    node_count: usize,
    load_profile: LoadProfile,
}

pub fn verify(artifact: &CertificationArtifact, config: &GateConfig) -> Result<VerificationReport> {
    if artifact.schema_version != ARTIFACT_SCHEMA_VERSION {
        bail!(
            "unsupported artifact schema {}, expected {}",
            artifact.schema_version,
            ARTIFACT_SCHEMA_VERSION
        );
    }
    validate_config(config)?;

    let mut gates = Vec::new();
    verify_artifact_integrity(artifact, config, &mut gates);
    verify_environment(artifact, config, &mut gates);
    let baselines = collect_baselines(artifact, config, &mut gates);
    verify_native(artifact, config, &baselines, &mut gates);
    let compatibility_samples = verify_compatibility(artifact, config, &mut gates);
    verify_transitions(&artifact.transitions, config, &mut gates);
    verify_costs(&artifact.costs, config, &mut gates);

    Ok(VerificationReport {
        schema_version: ARTIFACT_SCHEMA_VERSION,
        run_id: artifact.run_id.clone(),
        passed: gates.iter().all(|gate| gate.passed),
        gates,
        compatibility_samples,
    })
}

fn verify_artifact_integrity(
    artifact: &CertificationArtifact,
    config: &GateConfig,
    gates: &mut Vec<GateResult>,
) {
    let unique_sample_ids = artifact
        .samples
        .iter()
        .map(|sample| sample.sample_id.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    count_at_most_gate(
        gates,
        "artifact.duplicate_sample_ids",
        artifact.samples.len().saturating_sub(unique_sample_ids),
        0,
        "duplicate sample ids",
    );
    let invalid_samples = artifact
        .samples
        .iter()
        .filter(|sample| !sample.valid)
        .count();
    count_at_most_gate(
        gates,
        "artifact.invalid_samples",
        invalid_samples,
        config.maximum_invalid_samples,
        "invalid samples",
    );

    for sample in &artifact.samples {
        let prefix = format!("artifact.sample.{}", sanitize(&sample.sample_id));
        boolean_gate(
            gates,
            format!("{prefix}.validity_reason_consistency"),
            sample.valid == sample.invalid_reasons.is_empty(),
            "valid iff invalid_reasons is empty",
            "invalid measurements must be explicit and explained",
        );
        boolean_gate(
            gates,
            format!("{prefix}.node_count"),
            sample.node_count > 0
                && (sample.mode == RunMode::Compatibility
                    || sample.node_count == sample.owners.len()),
            "positive; native/standalone equals measured owners",
            format!(
                "mode={:?}, logical_nodes={}, measured_owners={}",
                sample.mode,
                sample.node_count,
                sample.owners.len()
            ),
        );
        let unique_owners = sample
            .owners
            .iter()
            .map(|owner| owner.owner_id.as_str())
            .collect::<BTreeSet<_>>()
            .len();
        boolean_gate(
            gates,
            format!("{prefix}.unique_owners"),
            unique_owners == sample.owners.len(),
            "all owner_ids unique",
            "an owner cannot be counted twice in one sample",
        );

        let owner_successes = sample
            .owners
            .iter()
            .map(|owner| owner.successful_operations)
            .sum::<u64>();
        let owner_failures = sample
            .owners
            .iter()
            .map(|owner| owner.failed_operations)
            .sum::<u64>();
        boolean_gate(
            gates,
            format!("{prefix}.operation_totals"),
            owner_successes == sample.aggregate_successful_operations
                && owner_failures == sample.aggregate_failed_operations,
            "aggregate totals equal owner totals",
            format!(
                "success owner={owner_successes}/aggregate={}, failure owner={owner_failures}/aggregate={}",
                sample.aggregate_successful_operations, sample.aggregate_failed_operations
            ),
        );
        let expected_latency_count = sample
            .aggregate_successful_operations
            .saturating_add(sample.aggregate_failed_operations);
        boolean_gate(
            gates,
            format!("{prefix}.latency_count"),
            sample.aggregate_latency.count == expected_latency_count
                && sample.aggregate_latency.count
                    == sample
                        .owners
                        .iter()
                        .map(|owner| owner.latency.count)
                        .sum::<u64>(),
            "latency count equals all completed operations",
            format!(
                "latency={}, completed={expected_latency_count}",
                sample.aggregate_latency.count
            ),
        );
        boolean_gate(
            gates,
            format!("{prefix}.load_profile"),
            match sample.load_profile {
                LoadProfile::Saturation => sample.target_operations_per_second_per_owner.is_none(),
                LoadProfile::EqualRate => sample
                    .target_operations_per_second_per_owner
                    .is_some_and(|target| target.is_finite() && target > 0.0),
            },
            "saturation has no target; equal_rate has a positive finite target",
            "offered load must be unambiguous",
        );
        boolean_gate(
            gates,
            format!("{prefix}.workload_shape"),
            sample.clients_per_owner > 0
                && sample.key_space_per_owner > 0
                && sample.value_size_bytes == sample.workload.value_size(),
            "positive clients/key-space and exact workload payload size",
            format!(
                "clients_per_owner={}, key_space_per_owner={}, value_size_bytes={}, expected_value_size={}",
                sample.clients_per_owner,
                sample.key_space_per_owner,
                sample.value_size_bytes,
                sample.workload.value_size()
            ),
        );
        threshold_gate(
            gates,
            format!("{prefix}.duration_floor"),
            sample.duration_seconds,
            config.minimum_sample_duration_seconds,
            Comparison::AtLeast,
            "performance samples must run long enough to reject startup noise",
        );

        let maximum_owner_duration = sample
            .owners
            .iter()
            .map(|owner| owner.duration_seconds)
            .fold(0.0_f64, f64::max);
        let aggregate_expected_rate = if sample.duration_seconds > 0.0 {
            sample.aggregate_successful_operations as f64 / sample.duration_seconds
        } else {
            f64::NAN
        };
        boolean_gate(
            gates,
            format!("{prefix}.aggregate_rate"),
            sample.duration_seconds.is_finite()
                && sample.duration_seconds > 0.0
                && approximately_equal(sample.duration_seconds, maximum_owner_duration, 0.001)
                && approximately_equal(
                    sample.aggregate_useful_operations_per_second,
                    aggregate_expected_rate,
                    0.001,
                ),
            "duration/rate derived from owner window and successful operations",
            format!(
                "duration={}, max_owner_duration={maximum_owner_duration}, rate={}, expected_rate={aggregate_expected_rate}",
                sample.duration_seconds, sample.aggregate_useful_operations_per_second
            ),
        );

        for owner in &sample.owners {
            let owner_expected_rate = if owner.duration_seconds > 0.0 {
                owner.successful_operations as f64 / owner.duration_seconds
            } else {
                f64::NAN
            };
            let bucket_successes = owner.one_second_successes.iter().sum::<u64>();
            boolean_gate(
                gates,
                format!("{prefix}.owner_{}.measurement", sanitize(&owner.owner_id)),
                owner.duration_seconds.is_finite()
                    && owner.duration_seconds > 0.0
                    && owner.latency.count
                        == owner
                            .successful_operations
                            .saturating_add(owner.failed_operations)
                    && bucket_successes == owner.successful_operations
                    && approximately_equal(
                        owner.useful_operations_per_second,
                        owner_expected_rate,
                        0.001,
                    ),
                "owner counters, buckets, latency count, duration, and rate agree",
                format!(
                    "success={}, buckets={bucket_successes}, rate={}, expected_rate={owner_expected_rate}",
                    owner.successful_operations, owner.useful_operations_per_second
                ),
            );
        }
    }

    let unique_transition_ids = artifact
        .transitions
        .iter()
        .map(|transition| transition.transition_id.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    count_at_most_gate(
        gates,
        "artifact.duplicate_transition_ids",
        artifact
            .transitions
            .len()
            .saturating_sub(unique_transition_ids),
        0,
        "duplicate transition ids",
    );
    count_at_most_gate(
        gates,
        "artifact.invalid_transitions",
        artifact
            .transitions
            .iter()
            .filter(|transition| !transition.valid)
            .count(),
        config.maximum_invalid_transitions,
        "invalid transitions",
    );
    for transition in &artifact.transitions {
        let prefix = format!(
            "artifact.transition.{}",
            sanitize(&transition.transition_id)
        );
        boolean_gate(
            gates,
            format!("{prefix}.validity_reason_consistency"),
            transition.valid == transition.invalid_reasons.is_empty(),
            "valid iff invalid_reasons is empty",
            "invalid resize measurements must be explicit and explained",
        );
        boolean_gate(
            gates,
            format!("{prefix}.shape"),
            transition.from_nodes > 0
                && transition.to_nodes > 0
                && transition.from_nodes != transition.to_nodes
                && transition.duration_seconds.is_finite()
                && transition.duration_seconds > 0.0
                && transition.steady_operations_per_second.is_finite()
                && transition.steady_operations_per_second > 0.0
                && !transition.one_second_successes.is_empty()
                && transition.pre_transition_p99_us > 0,
            "non-empty, finite, positive resize measurement",
            format!(
                "{} -> {}, duration={}, buckets={}, steady_ops={}",
                transition.from_nodes,
                transition.to_nodes,
                transition.duration_seconds,
                transition.one_second_successes.len(),
                transition.steady_operations_per_second
            ),
        );
    }

    let unique_cost_cases = artifact
        .costs
        .iter()
        .map(|cost| (cost.workload, cost.node_count))
        .collect::<BTreeSet<_>>()
        .len();
    count_at_most_gate(
        gates,
        "artifact.duplicate_cost_cases",
        artifact.costs.len().saturating_sub(unique_cost_cases),
        0,
        "duplicate cost cases",
    );
    for cost in &artifact.costs {
        boolean_gate(
            gates,
            format!(
                "artifact.cost.{}.nodes_{}",
                cost.workload.as_str(),
                cost.node_count
            ),
            cost.node_count > 0
                && cost.standalone_operations_per_core.is_finite()
                && cost.standalone_operations_per_core > 0.0
                && cost.cluster_operations_per_core.is_finite()
                && cost.cluster_operations_per_core > 0.0
                && cost.standalone_operations_per_dollar.is_finite()
                && cost.standalone_operations_per_dollar > 0.0
                && cost.cluster_operations_per_dollar.is_finite()
                && cost.cluster_operations_per_dollar > 0.0,
            "positive finite cost-efficiency measurements",
            "cost gates cannot be satisfied with missing or non-finite denominators",
        );
    }
}

fn approximately_equal(actual: f64, expected: f64, relative_tolerance: f64) -> bool {
    if !actual.is_finite() || !expected.is_finite() {
        return false;
    }
    let scale = actual.abs().max(expected.abs()).max(1.0);
    (actual - expected).abs() <= scale * relative_tolerance
}

fn validate_config(config: &GateConfig) -> Result<()> {
    if config.minimum_samples == 0 {
        bail!("minimum_samples must be positive");
    }
    if config.bootstrap_iterations == 0 {
        bail!("bootstrap_iterations must be positive");
    }
    if !config.minimum_sample_duration_seconds.is_finite()
        || config.minimum_sample_duration_seconds <= 0.0
    {
        bail!("minimum_sample_duration_seconds must be positive and finite");
    }
    if config.kv_pipeline_depths.is_empty() || config.table_pipeline_depths.is_empty() {
        bail!("pipeline-depth requirements cannot be empty");
    }
    if config
        .kv_pipeline_depths
        .iter()
        .chain(&config.table_pipeline_depths)
        .any(|depth| *depth == 0)
    {
        bail!("pipeline-depth requirements must be positive");
    }
    if config.compatibility_node_counts.is_empty() || config.compatibility_node_counts.contains(&0)
    {
        bail!("compatibility_node_counts must contain positive node counts");
    }
    for (nodes, threshold) in &config.aggregate_minimums {
        if *nodes == 0 || !threshold.is_finite() || *threshold <= 0.0 {
            bail!("invalid aggregate threshold for {nodes} nodes");
        }
    }
    if !(0.0..1.0).contains(&config.equal_rate_target_tolerance) {
        bail!("equal_rate_target_tolerance must be between zero and one");
    }
    if !(0.0..=1.0).contains(&config.equal_rate_delivery_minimum) {
        bail!("equal_rate_delivery_minimum must be between zero and one");
    }
    Ok(())
}

fn verify_environment(
    artifact: &CertificationArtifact,
    config: &GateConfig,
    gates: &mut Vec<GateResult>,
) {
    if !config.require_certification_environment {
        return;
    }
    let environment = &artifact.environment;
    boolean_gate(
        gates,
        "environment.binary_digest",
        environment.engine_binary_sha256.len() == 64
            && environment
                .engine_binary_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "64 lowercase hexadecimal SHA-256 characters",
        "the measured Engine binary must be content-addressed",
    );
    boolean_gate(
        gates,
        "environment.source_revisions",
        !environment.candidate_git_sha.trim().is_empty()
            && !environment.harness_git_sha.trim().is_empty(),
        "candidate_git_sha and harness_git_sha are non-empty",
        "results must identify both implementation and harness revisions",
    );
    let unique_engine_hosts = environment
        .engine_hosts
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        .len();
    let maximum_measured_nodes = artifact
        .samples
        .iter()
        .map(|sample| sample.node_count)
        .max()
        .unwrap_or(0);
    boolean_gate(
        gates,
        "environment.host_identity",
        !environment.load_generator_host.trim().is_empty()
            && !environment.observer_host.trim().is_empty()
            && unique_engine_hosts == environment.engine_hosts.len()
            && unique_engine_hosts >= maximum_measured_nodes,
        "non-empty load/observer hosts and enough unique Engine hosts",
        format!(
            "unique_engine_hosts={unique_engine_hosts}, maximum_measured_nodes={maximum_measured_nodes}"
        ),
    );
    boolean_gate(
        gates,
        "environment.isolated_processes",
        environment.isolated_processes,
        "true",
        "engine nodes must run in isolated processes or machines",
    );
    boolean_gate(
        gates,
        "environment.external_load_generator",
        environment.external_load_generator,
        "true",
        "the load generator cannot run inside an engine process",
    );
    boolean_gate(
        gates,
        "environment.homogeneous_engine_resources",
        environment.homogeneous_engine_resources,
        "true",
        "all compared owners must receive equivalent resources",
    );
    threshold_gate(
        gates,
        "environment.load_generator_headroom",
        environment.load_generator_headroom_ratio,
        2.0,
        Comparison::AtLeast,
        "load-generator capacity must be at least 2x projected cluster throughput",
    );
    threshold_gate(
        gates,
        "environment.engine_nic_utilization",
        environment.max_engine_nic_utilization,
        0.80,
        Comparison::AtMost,
        "an engine NIC above 80% invalidates the run",
    );
    threshold_gate(
        gates,
        "environment.cpu_throttling",
        environment.max_engine_cpu_throttle_seconds,
        0.0,
        Comparison::AtMost,
        "engine CPU throttling invalidates the run",
    );
    threshold_gate(
        gates,
        "environment.observer_overhead",
        environment.max_observer_cpu_ratio,
        0.01,
        Comparison::AtMost,
        "observer CPU must stay at or below 1% per engine host",
    );
    threshold_gate(
        gates,
        "environment.clock_offset",
        environment.max_clock_offset_ms,
        5.0,
        Comparison::AtMost,
        "engine and load-generator clocks must stay within 5ms",
    );
}

fn collect_baselines(
    artifact: &CertificationArtifact,
    config: &GateConfig,
    gates: &mut Vec<GateResult>,
) -> HashMap<(BaselineKey, String), HostBaseline> {
    let mut baselines: HashMap<(BaselineKey, String), HostBaseline> = HashMap::new();
    for sample in artifact
        .samples
        .iter()
        .filter(|sample| sample.mode == RunMode::Standalone && sample.valid)
    {
        for owner in &sample.owners {
            let baseline = baselines
                .entry((
                    BaselineKey {
                        workload: sample.workload,
                        pipeline_depth: sample.pipeline_depth,
                        load_profile: sample.load_profile,
                        clients_per_owner: sample.clients_per_owner,
                        key_space_per_owner: sample.key_space_per_owner,
                        value_size_bytes: sample.value_size_bytes,
                    },
                    owner.host_id.clone(),
                ))
                .or_default();
            baseline.throughput.push(owner.useful_operations_per_second);
            baseline.p99_us.push(owner.latency.p99_us as f64);
            if let Some(target) = sample.target_operations_per_second_per_owner {
                baseline.target_operations_per_second.push(target);
            }
        }
    }

    let referenced_hosts = artifact
        .samples
        .iter()
        .filter(|sample| sample.mode == RunMode::Native && sample.valid)
        .flat_map(|sample| {
            sample.owners.iter().map(move |owner| {
                (
                    BaselineKey {
                        workload: sample.workload,
                        pipeline_depth: sample.pipeline_depth,
                        load_profile: sample.load_profile,
                        clients_per_owner: sample.clients_per_owner,
                        key_space_per_owner: sample.key_space_per_owner,
                        value_size_bytes: sample.value_size_bytes,
                    },
                    owner.host_id.clone(),
                )
            })
        })
        .collect::<BTreeSet<_>>();

    for (key, host_id) in referenced_hosts {
        let count = baselines
            .get(&(key, host_id.clone()))
            .map_or(0, |baseline| baseline.throughput.len());
        count_gate(
            gates,
            format!(
                "baseline.{}.{}.{}.pipeline_{}",
                sanitize(&host_id),
                key.workload.as_str(),
                key.load_profile.as_str(),
                key.pipeline_depth
            ),
            count,
            config.minimum_samples,
            "host-matched standalone samples",
        );
    }
    baselines
}

fn verify_native(
    artifact: &CertificationArtifact,
    config: &GateConfig,
    baselines: &HashMap<(BaselineKey, String), HostBaseline>,
    gates: &mut Vec<GateResult>,
) {
    let mut cases: HashMap<CaseKey, Vec<&SampleArtifact>> = HashMap::new();
    for sample in artifact
        .samples
        .iter()
        .filter(|sample| sample.mode == RunMode::Native && sample.valid)
    {
        cases
            .entry(CaseKey {
                workload: sample.workload,
                pipeline_depth: sample.pipeline_depth,
                node_count: sample.node_count,
                load_profile: sample.load_profile,
            })
            .or_default()
            .push(sample);
    }

    for workload in &config.required_workloads {
        let required_pipelines = if workload.is_table() {
            &config.table_pipeline_depths
        } else {
            &config.kv_pipeline_depths
        };
        for pipeline_depth in required_pipelines {
            for (&node_count, &aggregate_minimum) in &config.aggregate_minimums {
                let case = CaseKey {
                    workload: *workload,
                    pipeline_depth: *pipeline_depth,
                    node_count,
                    load_profile: LoadProfile::Saturation,
                };
                let samples = cases.get(&case).cloned().unwrap_or_default();
                let prefix = case_prefix(case);
                count_gate(
                    gates,
                    format!("{prefix}.sample_count"),
                    samples.len(),
                    config.minimum_samples,
                    "valid native samples",
                );
                if samples.len() < config.minimum_samples {
                    continue;
                }

                let rates = samples
                    .iter()
                    .map(|sample| sample.aggregate_useful_operations_per_second)
                    .collect::<Vec<_>>();
                threshold_gate(
                    gates,
                    format!("{prefix}.coefficient_of_variation"),
                    coefficient_of_variation(&rates),
                    config.maximum_coefficient_of_variation,
                    Comparison::AtMost,
                    "native aggregate throughput must be stable across samples",
                );
                verify_case_failures(&prefix, &samples, gates);
                verify_case_routing(&prefix, &samples, gates);
                verify_case_shape(&prefix, &samples, gates);
                verify_case_capacity(case, &samples, baselines, config, aggregate_minimum, gates);

                if !config.require_equal_rate_latency {
                    continue;
                }
                let latency_case = CaseKey {
                    load_profile: LoadProfile::EqualRate,
                    ..case
                };
                let latency_samples = cases.get(&latency_case).cloned().unwrap_or_default();
                let latency_prefix = case_prefix(latency_case);
                count_gate(
                    gates,
                    format!("{latency_prefix}.sample_count"),
                    latency_samples.len(),
                    config.minimum_samples,
                    "valid equal-rate native samples",
                );
                if latency_samples.len() < config.minimum_samples {
                    continue;
                }
                verify_case_failures(&latency_prefix, &latency_samples, gates);
                verify_case_routing(&latency_prefix, &latency_samples, gates);
                verify_case_shape(&latency_prefix, &latency_samples, gates);
                verify_case_latency(latency_case, &latency_samples, baselines, config, gates);
            }
        }
    }
}

fn verify_case_shape(prefix: &str, samples: &[&SampleArtifact], gates: &mut Vec<GateResult>) {
    let shapes = samples
        .iter()
        .map(|sample| {
            (
                sample.clients_per_owner,
                sample.key_space_per_owner,
                sample.value_size_bytes,
            )
        })
        .collect::<BTreeSet<_>>();
    boolean_gate(
        gates,
        format!("{prefix}.uniform_shape"),
        shapes.len() == 1,
        "one clients/key-space/value-size shape",
        format!("observed shapes: {shapes:?}"),
    );
}

fn verify_case_failures(prefix: &str, samples: &[&SampleArtifact], gates: &mut Vec<GateResult>) {
    let failures = samples
        .iter()
        .map(|sample| sample.aggregate_failed_operations)
        .sum::<u64>();
    threshold_gate(
        gates,
        format!("{prefix}.failed_operations"),
        failures as f64,
        0.0,
        Comparison::AtMost,
        "primary native workloads cannot contain failed logical operations",
    );
}

fn verify_case_routing(prefix: &str, samples: &[&SampleArtifact], gates: &mut Vec<GateResult>) {
    let successful = samples
        .iter()
        .map(|sample| sample.aggregate_successful_operations)
        .sum::<u64>();
    let owner_local = samples
        .iter()
        .map(|sample| sample.route_evidence.owner_local_operations)
        .sum::<u64>();
    let compatibility_forwards = samples
        .iter()
        .map(|sample| sample.route_evidence.compatibility_forwards)
        .sum::<u64>();
    let point_peer_frames = samples
        .iter()
        .map(|sample| sample.route_evidence.point_peer_frames)
        .sum::<u64>();
    let point_peer_bytes = samples
        .iter()
        .map(|sample| sample.route_evidence.point_peer_bytes)
        .sum::<u64>();
    let redirects = samples
        .iter()
        .map(|sample| sample.route_evidence.moved_responses + sample.route_evidence.ask_responses)
        .sum::<u64>();

    boolean_gate(
        gates,
        format!("{prefix}.owner_local"),
        successful > 0 && owner_local == successful,
        "owner_local_operations == successful_operations",
        format!("owner-local={owner_local}, successful={successful}"),
    );
    threshold_gate(
        gates,
        format!("{prefix}.compatibility_forwards"),
        compatibility_forwards as f64,
        0.0,
        Comparison::AtMost,
        "native point operations cannot use compatibility forwarding",
    );
    threshold_gate(
        gates,
        format!("{prefix}.point_peer_frames"),
        point_peer_frames as f64,
        0.0,
        Comparison::AtMost,
        "native stable point operations cannot emit peer data frames",
    );
    threshold_gate(
        gates,
        format!("{prefix}.point_peer_bytes"),
        point_peer_bytes as f64,
        0.0,
        Comparison::AtMost,
        "native stable point operations cannot emit peer data bytes",
    );
    threshold_gate(
        gates,
        format!("{prefix}.stable_redirects"),
        redirects as f64,
        0.0,
        Comparison::AtMost,
        "a stable owner-aligned run cannot rely on redirection",
    );
}

fn verify_case_capacity(
    case: CaseKey,
    samples: &[&SampleArtifact],
    baselines: &HashMap<(BaselineKey, String), HostBaseline>,
    config: &GateConfig,
    aggregate_minimum: f64,
    gates: &mut Vec<GateResult>,
) {
    let prefix = case_prefix(case);
    let baseline_key = BaselineKey {
        workload: case.workload,
        pipeline_depth: case.pipeline_depth,
        load_profile: case.load_profile,
        clients_per_owner: samples[0].clients_per_owner,
        key_space_per_owner: samples[0].key_space_per_owner,
        value_size_bytes: samples[0].value_size_bytes,
    };
    let mut aggregate_ratios = Vec::new();
    let mut owner_ratios: HashMap<String, Vec<f64>> = HashMap::new();

    for sample in samples {
        let mut host_baselines = Vec::with_capacity(sample.owners.len());
        for owner in &sample.owners {
            let Some(baseline) = baselines.get(&(baseline_key, owner.host_id.clone())) else {
                continue;
            };
            let baseline_rate = median(&baseline.throughput);
            if baseline_rate.is_finite() && baseline_rate > 0.0 {
                host_baselines.push(baseline_rate);
                owner_ratios
                    .entry(owner.owner_id.clone())
                    .or_default()
                    .push(owner.useful_operations_per_second / baseline_rate);
            }
        }
        if host_baselines.len() == sample.owners.len() && !host_baselines.is_empty() {
            let mean_baseline = host_baselines.iter().sum::<f64>() / host_baselines.len() as f64;
            aggregate_ratios.push(sample.aggregate_useful_operations_per_second / mean_baseline);
        }
    }

    interval_lower_gate(
        gates,
        format!("{prefix}.aggregate_scale"),
        &aggregate_ratios,
        aggregate_minimum,
        config,
        "lower 95% CI of native aggregate scale",
    );

    let owner_minimum = if case.node_count == 1 {
        config.cluster_tax_minimum
    } else {
        config.per_owner_minimum
    };
    for (owner_id, ratios) in owner_ratios {
        interval_lower_gate(
            gates,
            format!("{prefix}.owner_{}.throughput", sanitize(&owner_id)),
            &ratios,
            owner_minimum,
            config,
            "lower 95% CI of host-matched owner throughput",
        );
        if let Some(minimum) = ratios.iter().copied().reduce(f64::min) {
            threshold_gate(
                gates,
                format!("{prefix}.owner_{}.minimum_sample", sanitize(&owner_id)),
                minimum,
                owner_minimum,
                Comparison::AtLeast,
                "no individual owner sample may hide below the owner-local floor",
            );
        }
    }
}

fn verify_case_latency(
    case: CaseKey,
    samples: &[&SampleArtifact],
    baselines: &HashMap<(BaselineKey, String), HostBaseline>,
    config: &GateConfig,
    gates: &mut Vec<GateResult>,
) {
    let prefix = case_prefix(case);
    let baseline_key = BaselineKey {
        workload: case.workload,
        pipeline_depth: case.pipeline_depth,
        load_profile: LoadProfile::EqualRate,
        clients_per_owner: samples[0].clients_per_owner,
        key_space_per_owner: samples[0].key_space_per_owner,
        value_size_bytes: samples[0].value_size_bytes,
    };
    let mut p99_ratios: HashMap<String, Vec<f64>> = HashMap::new();
    let mut target_differences = Vec::new();
    let mut delivery_ratios: HashMap<String, Vec<f64>> = HashMap::new();

    for sample in samples {
        let Some(target) = sample.target_operations_per_second_per_owner else {
            continue;
        };
        for owner in &sample.owners {
            let Some(baseline) = baselines.get(&(baseline_key, owner.host_id.clone())) else {
                continue;
            };
            let baseline_p99 = median(&baseline.p99_us);
            let baseline_target = median(&baseline.target_operations_per_second);
            if baseline_p99.is_finite() && baseline_p99 > 0.0 {
                p99_ratios
                    .entry(owner.owner_id.clone())
                    .or_default()
                    .push(owner.latency.p99_us as f64 / baseline_p99);
            }
            if baseline_target.is_finite() && baseline_target > 0.0 {
                target_differences.push((target / baseline_target - 1.0).abs());
            }
            delivery_ratios
                .entry(owner.owner_id.clone())
                .or_default()
                .push(owner.useful_operations_per_second / target);
        }
    }

    let maximum_target_difference = target_differences
        .iter()
        .copied()
        .reduce(f64::max)
        .unwrap_or(f64::INFINITY);
    threshold_gate(
        gates,
        format!("{prefix}.target_match"),
        maximum_target_difference,
        config.equal_rate_target_tolerance,
        Comparison::AtMost,
        "native and host-matched standalone p99 samples must use the same offered load",
    );
    for (owner_id, ratios) in delivery_ratios {
        let minimum = ratios.iter().copied().reduce(f64::min).unwrap_or(0.0);
        threshold_gate(
            gates,
            format!("{prefix}.owner_{}.delivery", sanitize(&owner_id)),
            minimum,
            config.equal_rate_delivery_minimum,
            Comparison::AtLeast,
            "every owner must sustain the offered equal-rate load",
        );
    }

    let p99_maximum = if case.node_count == 1 {
        config.one_node_p99_maximum
    } else {
        config.multi_node_p99_maximum
    };
    for (owner_id, ratios) in p99_ratios {
        interval_upper_gate(
            gates,
            format!("{prefix}.owner_{}.p99", sanitize(&owner_id)),
            &ratios,
            p99_maximum,
            config,
            "upper 95% CI of host-matched p99 ratio",
        );
        if let Some(maximum) = ratios.iter().copied().reduce(f64::max) {
            threshold_gate(
                gates,
                format!("{prefix}.owner_{}.maximum_p99_sample", sanitize(&owner_id)),
                maximum,
                p99_maximum,
                Comparison::AtMost,
                "no individual p99 sample may hide above the latency floor",
            );
        }
    }
}

fn verify_compatibility(
    artifact: &CertificationArtifact,
    config: &GateConfig,
    gates: &mut Vec<GateResult>,
) -> Vec<CompatibilityReport> {
    let mut cases: HashMap<CaseKey, Vec<&SampleArtifact>> = HashMap::new();
    for sample in artifact
        .samples
        .iter()
        .filter(|sample| sample.mode == RunMode::Compatibility && sample.valid)
    {
        cases
            .entry(CaseKey {
                workload: sample.workload,
                pipeline_depth: sample.pipeline_depth,
                node_count: sample.node_count,
                load_profile: sample.load_profile,
            })
            .or_default()
            .push(sample);
    }

    let mut reports = Vec::new();
    for (case, samples) in cases {
        verify_case_shape(&case_prefix(case), &samples, gates);
        let failures = samples
            .iter()
            .map(|sample| sample.aggregate_failed_operations)
            .sum::<u64>();
        threshold_gate(
            gates,
            format!("{}.compatibility_correctness", case_prefix(case)),
            failures as f64,
            0.0,
            Comparison::AtMost,
            "compatibility performance is separate, but correctness is mandatory",
        );
        reports.push(CompatibilityReport {
            workload: case.workload,
            load_profile: case.load_profile,
            node_count: case.node_count,
            pipeline_depth: case.pipeline_depth,
            samples: samples.len(),
            median_useful_operations_per_second: median(
                &samples
                    .iter()
                    .map(|sample| sample.aggregate_useful_operations_per_second)
                    .collect::<Vec<_>>(),
            ),
            median_p99_us: median(
                &samples
                    .iter()
                    .map(|sample| sample.aggregate_latency.p99_us as f64)
                    .collect::<Vec<_>>(),
            ),
            forwarded_operations: samples
                .iter()
                .map(|sample| sample.route_evidence.compatibility_forwards)
                .sum(),
            point_peer_bytes: samples
                .iter()
                .map(|sample| sample.route_evidence.point_peer_bytes)
                .sum(),
        });
    }
    reports.sort_by_key(|report| {
        (
            report.workload,
            report.load_profile,
            report.node_count,
            report.pipeline_depth,
        )
    });

    if config.require_compatibility {
        for workload in &config.required_workloads {
            let required_pipelines = if workload.is_table() {
                &config.table_pipeline_depths
            } else {
                &config.kv_pipeline_depths
            };
            for pipeline_depth in required_pipelines {
                for node_count in &config.compatibility_node_counts {
                    let found = reports.iter().any(|report| {
                        report.workload == *workload
                            && report.load_profile == LoadProfile::Saturation
                            && report.pipeline_depth == *pipeline_depth
                            && report.node_count == *node_count
                            && report.samples >= config.minimum_samples
                    });
                    boolean_gate(
                        gates,
                        format!(
                            "compatibility.{}.saturation.pipeline_{}.nodes_{}.reported",
                            workload.as_str(),
                            pipeline_depth,
                            node_count
                        ),
                        found,
                        format!("at least {} valid samples", config.minimum_samples),
                        "compatibility results must cover the full matrix and stay separate",
                    );
                }
            }
        }
    }
    reports
}

fn verify_transitions(
    transitions: &[TransitionArtifact],
    config: &GateConfig,
    gates: &mut Vec<GateResult>,
) {
    if !config.require_transitions {
        return;
    }
    let required_directions = [(1, 2), (2, 4), (4, 8), (8, 4), (4, 2), (2, 1)];
    let required_workloads = [WorkloadId::KvMixed256, WorkloadId::TableMixed1k];
    for workload in required_workloads {
        for (from_nodes, to_nodes) in required_directions {
            let matching = transitions
                .iter()
                .filter(|transition| {
                    transition.valid
                        && transition.workload == workload
                        && transition.from_nodes == from_nodes
                        && transition.to_nodes == to_nodes
                })
                .collect::<Vec<_>>();
            let prefix = format!(
                "transition.{}.{from_nodes}_to_{to_nodes}",
                workload.as_str()
            );
            count_gate(
                gates,
                format!("{prefix}.sample_count"),
                matching.len(),
                config.minimum_samples,
                "valid resize samples",
            );
            for transition in matching {
                verify_transition(transition, config, &prefix, gates);
            }
        }
    }
}

fn verify_transition(
    transition: &TransitionArtifact,
    config: &GateConfig,
    prefix: &str,
    gates: &mut Vec<GateResult>,
) {
    let minimum_bucket = transition
        .one_second_successes
        .iter()
        .copied()
        .min()
        .unwrap_or(0) as f64;
    threshold_gate(
        gates,
        format!(
            "{prefix}.{}.throughput_floor",
            sanitize(&transition.transition_id)
        ),
        minimum_bucket,
        transition.steady_operations_per_second * config.resize_throughput_minimum,
        Comparison::AtLeast,
        "every one-second resize bucket must retain the foreground throughput floor",
    );
    let p99_ratio = if transition.pre_transition_p99_us == 0 {
        f64::INFINITY
    } else {
        transition.transition_p99_us as f64 / transition.pre_transition_p99_us as f64
    };
    threshold_gate(
        gates,
        format!("{prefix}.{}.p99", sanitize(&transition.transition_id)),
        p99_ratio,
        config.resize_p99_maximum,
        Comparison::AtMost,
        "resize p99 must remain bounded",
    );
    let correctness_failures = transition.failed_logical_operations
        + transition.missing_committed_operations
        + transition.duplicate_committed_operations
        + transition.source_target_divergences;
    threshold_gate(
        gates,
        format!(
            "{prefix}.{}.correctness",
            sanitize(&transition.transition_id)
        ),
        correctness_failures as f64,
        0.0,
        Comparison::AtMost,
        "resize cannot lose, duplicate, fail, or diverge committed logical operations",
    );
}

fn verify_costs(costs: &[CostArtifact], config: &GateConfig, gates: &mut Vec<GateResult>) {
    if !config.require_costs {
        return;
    }
    for workload in &config.required_workloads {
        for node_count in [2, 4, 8] {
            let matching = costs
                .iter()
                .filter(|cost| cost.workload == *workload && cost.node_count == node_count)
                .collect::<Vec<_>>();
            count_gate(
                gates,
                format!("cost.{}.{node_count}.sample_count", workload.as_str()),
                matching.len(),
                1,
                "cost artifact",
            );
            for cost in matching {
                let core_ratio = ratio(
                    cost.cluster_operations_per_core,
                    cost.standalone_operations_per_core,
                );
                threshold_gate(
                    gates,
                    format!("cost.{}.{node_count}.per_core", workload.as_str()),
                    core_ratio,
                    config.efficiency_minimum,
                    Comparison::AtLeast,
                    "useful operations per core cannot hide scaling overhead",
                );
                let dollar_ratio = ratio(
                    cost.cluster_operations_per_dollar,
                    cost.standalone_operations_per_dollar,
                );
                threshold_gate(
                    gates,
                    format!("cost.{}.{node_count}.per_dollar", workload.as_str()),
                    dollar_ratio,
                    config.efficiency_minimum,
                    Comparison::AtLeast,
                    "useful operations per dollar must retain at least 90% efficiency",
                );
            }
        }
    }
}

fn interval_lower_gate(
    gates: &mut Vec<GateResult>,
    gate_id: String,
    values: &[f64],
    required: f64,
    config: &GateConfig,
    details: &str,
) {
    let interval = interval(values, config, seed_for(&gate_id));
    gates.push(GateResult {
        gate_id,
        passed: interval.lower.is_finite() && interval.lower >= required,
        actual: interval.lower.is_finite().then_some(interval.lower),
        required: format!(">= {required:.6} (lower 95% CI)"),
        details: format!(
            "{details}; estimate={:.6}, lower={:.6}, upper={:.6}, samples={}",
            interval.estimate,
            interval.lower,
            interval.upper,
            values.len()
        ),
    });
}

fn interval_upper_gate(
    gates: &mut Vec<GateResult>,
    gate_id: String,
    values: &[f64],
    required: f64,
    config: &GateConfig,
    details: &str,
) {
    let interval = interval(values, config, seed_for(&gate_id));
    gates.push(GateResult {
        gate_id,
        passed: interval.upper.is_finite() && interval.upper <= required,
        actual: interval.upper.is_finite().then_some(interval.upper),
        required: format!("<= {required:.6} (upper 95% CI)"),
        details: format!(
            "{details}; estimate={:.6}, lower={:.6}, upper={:.6}, samples={}",
            interval.estimate,
            interval.lower,
            interval.upper,
            values.len()
        ),
    });
}

fn interval(values: &[f64], config: &GateConfig, seed: u64) -> ConfidenceInterval {
    bootstrap_median_95(values, config.bootstrap_iterations, seed)
}

fn ratio(numerator: f64, denominator: f64) -> f64 {
    if denominator > 0.0 {
        numerator / denominator
    } else {
        f64::INFINITY
    }
}

#[derive(Clone, Copy)]
enum Comparison {
    AtLeast,
    AtMost,
}

fn threshold_gate(
    gates: &mut Vec<GateResult>,
    gate_id: impl Into<String>,
    actual: f64,
    required: f64,
    comparison: Comparison,
    details: impl Into<String>,
) {
    let (passed, requirement) = match comparison {
        Comparison::AtLeast => (actual.is_finite() && actual >= required, ">="),
        Comparison::AtMost => (actual.is_finite() && actual <= required, "<="),
    };
    gates.push(GateResult {
        gate_id: gate_id.into(),
        passed,
        actual: actual.is_finite().then_some(actual),
        required: format!("{requirement} {required:.6}"),
        details: details.into(),
    });
}

fn boolean_gate(
    gates: &mut Vec<GateResult>,
    gate_id: impl Into<String>,
    passed: bool,
    required: impl Into<String>,
    details: impl Into<String>,
) {
    gates.push(GateResult {
        gate_id: gate_id.into(),
        passed,
        actual: None,
        required: required.into(),
        details: details.into(),
    });
}

fn count_gate(
    gates: &mut Vec<GateResult>,
    gate_id: impl Into<String>,
    actual: usize,
    required: usize,
    label: &str,
) {
    threshold_gate(
        gates,
        gate_id,
        actual as f64,
        required as f64,
        Comparison::AtLeast,
        format!("required {label}"),
    );
}

fn count_at_most_gate(
    gates: &mut Vec<GateResult>,
    gate_id: impl Into<String>,
    actual: usize,
    required: usize,
    label: &str,
) {
    threshold_gate(
        gates,
        gate_id,
        actual as f64,
        required as f64,
        Comparison::AtMost,
        format!("allowed {label}"),
    );
}

fn case_prefix(case: CaseKey) -> String {
    format!(
        "native.{}.{}.pipeline_{}.nodes_{}",
        case.workload.as_str(),
        case.load_profile.as_str(),
        case.pipeline_depth,
        case.node_count
    )
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' || character == '-' {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn seed_for(value: &str) -> u64 {
    value.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{EnvironmentArtifact, LatencySummary, RouteEvidence, SampleArtifact};

    fn environment() -> EnvironmentArtifact {
        EnvironmentArtifact {
            provider: "test".into(),
            engine_binary_sha256: "engine".into(),
            candidate_git_sha: "candidate".into(),
            harness_git_sha: "harness".into(),
            load_generator_host: "load".into(),
            observer_host: "observer".into(),
            engine_hosts: vec!["host-1".into(), "host-2".into()],
            isolated_processes: true,
            external_load_generator: true,
            homogeneous_engine_resources: true,
            load_generator_headroom_ratio: 2.5,
            max_engine_nic_utilization: 0.5,
            max_engine_cpu_throttle_seconds: 0.0,
            max_observer_cpu_ratio: 0.005,
            max_clock_offset_ms: 0.2,
            labels: BTreeMap::new(),
        }
    }

    fn owner(
        owner_id: &str,
        host_id: &str,
        rate: f64,
        p99_us: u64,
    ) -> crate::artifact::OwnerMeasurement {
        crate::artifact::OwnerMeasurement {
            owner_id: owner_id.into(),
            host_id: host_id.into(),
            successful_operations: rate as u64,
            failed_operations: 0,
            duration_seconds: 1.0,
            useful_operations_per_second: rate,
            latency: LatencySummary {
                count: rate as u64,
                min_us: 10,
                p50_us: 20,
                p95_us: 30,
                p99_us,
                max_us: 50,
                mean_us: 22.0,
            },
            one_second_successes: vec![rate as u64],
        }
    }

    fn sample(
        id: &str,
        mode: RunMode,
        owners: Vec<crate::artifact::OwnerMeasurement>,
        rate: f64,
        p99_us: u64,
    ) -> SampleArtifact {
        SampleArtifact {
            sample_id: id.into(),
            workload: WorkloadId::KvSet256,
            mode,
            load_profile: LoadProfile::Saturation,
            node_count: owners.len(),
            pipeline_depth: 1,
            clients_per_owner: 1,
            key_space_per_owner: 1_000,
            value_size_bytes: WorkloadId::KvSet256.value_size(),
            seed: 7,
            target_operations_per_second_per_owner: None,
            valid: true,
            invalid_reasons: Vec::new(),
            aggregate_successful_operations: rate as u64,
            aggregate_failed_operations: 0,
            duration_seconds: 1.0,
            aggregate_useful_operations_per_second: rate,
            aggregate_latency: LatencySummary {
                count: rate as u64,
                min_us: 10,
                p50_us: 20,
                p95_us: 30,
                p99_us,
                max_us: 50,
                mean_us: 22.0,
            },
            route_evidence: RouteEvidence {
                owner_local_operations: rate as u64,
                ..RouteEvidence::default()
            },
            owners,
        }
    }

    fn passing_smoke_artifact() -> CertificationArtifact {
        let mut artifact = CertificationArtifact::new("run", environment());
        artifact.samples.push(sample(
            "standalone-1",
            RunMode::Standalone,
            vec![owner("standalone", "host-1", 100.0, 100)],
            100.0,
            100,
        ));
        artifact.samples.push(sample(
            "standalone-2",
            RunMode::Standalone,
            vec![owner("standalone", "host-2", 100.0, 100)],
            100.0,
            100,
        ));
        artifact.samples.push(sample(
            "native-1",
            RunMode::Native,
            vec![owner("node-1", "host-1", 98.0, 104)],
            98.0,
            104,
        ));
        artifact.samples.push(sample(
            "native-2",
            RunMode::Native,
            vec![
                owner("node-1", "host-1", 98.0, 108),
                owner("node-2", "host-2", 98.0, 108),
            ],
            196.0,
            108,
        ));
        artifact
    }

    fn add_equal_rate_samples(artifact: &mut CertificationArtifact) {
        let mut standalone_1 = sample(
            "standalone-equal-1",
            RunMode::Standalone,
            vec![owner("standalone", "host-1", 70.0, 100)],
            70.0,
            100,
        );
        standalone_1.load_profile = LoadProfile::EqualRate;
        standalone_1.target_operations_per_second_per_owner = Some(70.0);
        artifact.samples.push(standalone_1);

        let mut standalone_2 = sample(
            "standalone-equal-2",
            RunMode::Standalone,
            vec![owner("standalone", "host-2", 70.0, 100)],
            70.0,
            100,
        );
        standalone_2.load_profile = LoadProfile::EqualRate;
        standalone_2.target_operations_per_second_per_owner = Some(70.0);
        artifact.samples.push(standalone_2);

        let mut native_1 = sample(
            "native-equal-1",
            RunMode::Native,
            vec![owner("node-1", "host-1", 70.0, 104)],
            70.0,
            104,
        );
        native_1.load_profile = LoadProfile::EqualRate;
        native_1.target_operations_per_second_per_owner = Some(70.0);
        artifact.samples.push(native_1);

        let mut native_2 = sample(
            "native-equal-2",
            RunMode::Native,
            vec![
                owner("node-1", "host-1", 70.0, 108),
                owner("node-2", "host-2", 70.0, 108),
            ],
            140.0,
            108,
        );
        native_2.load_profile = LoadProfile::EqualRate;
        native_2.target_operations_per_second_per_owner = Some(70.0);
        artifact.samples.push(native_2);
    }

    #[test]
    fn strict_defaults_encode_the_accepted_thresholds() {
        let config = GateConfig::default();
        assert_eq!(config.cluster_tax_minimum, 0.97);
        assert_eq!(config.aggregate_minimums[&2], 1.90);
        assert_eq!(config.aggregate_minimums[&4], 3.70);
        assert_eq!(config.aggregate_minimums[&8], 7.20);
        assert_eq!(config.resize_throughput_minimum, 0.90);
    }

    #[test]
    fn passing_smoke_artifact_clears_real_scaling_and_latency_gates() {
        let report = verify(&passing_smoke_artifact(), &GateConfig::smoke()).unwrap();
        let failures = report
            .gates
            .iter()
            .filter(|gate| !gate.passed)
            .map(|gate| (&gate.gate_id, &gate.details))
            .collect::<Vec<_>>();
        assert!(failures.is_empty(), "unexpected failures: {failures:?}");
        assert!(report.passed);
    }

    #[test]
    fn verifier_rejects_old_weak_two_node_scaling() {
        let mut artifact = passing_smoke_artifact();
        let native_two = artifact
            .samples
            .iter_mut()
            .find(|sample| sample.mode == RunMode::Native && sample.node_count == 2)
            .unwrap();
        native_two.aggregate_useful_operations_per_second = 125.0;
        let report = verify(&artifact, &GateConfig::smoke()).unwrap();
        assert!(!report.passed);
        assert!(report
            .gates
            .iter()
            .any(|gate| { gate.gate_id.ends_with("aggregate_scale") && !gate.passed }));
    }

    #[test]
    fn verifier_rejects_hidden_peer_forwarding() {
        let mut artifact = passing_smoke_artifact();
        let native_two = artifact
            .samples
            .iter_mut()
            .find(|sample| sample.mode == RunMode::Native && sample.node_count == 2)
            .unwrap();
        native_two.route_evidence.point_peer_frames = 1;
        let report = verify(&artifact, &GateConfig::smoke()).unwrap();
        assert!(!report.passed);
        assert!(report
            .gates
            .iter()
            .any(|gate| gate.gate_id.ends_with("point_peer_frames") && !gate.passed));
    }

    #[test]
    fn verifier_rejects_internally_inconsistent_artifacts() {
        let mut artifact = passing_smoke_artifact();
        artifact.samples[0].aggregate_successful_operations += 1;
        let report = verify(&artifact, &GateConfig::smoke()).unwrap();
        assert!(!report.passed);
        assert!(report
            .gates
            .iter()
            .any(|gate| gate.gate_id.ends_with("operation_totals") && !gate.passed));

        let mut invalid = passing_smoke_artifact();
        invalid.samples[0].valid = false;
        let report = verify(&invalid, &GateConfig::smoke()).unwrap();
        assert!(!report.passed);
        assert!(report
            .gates
            .iter()
            .any(|gate| gate.gate_id == "artifact.invalid_samples" && !gate.passed));
    }

    #[test]
    fn equal_rate_samples_gate_p99_without_conflating_saturation() {
        let mut artifact = passing_smoke_artifact();
        add_equal_rate_samples(&mut artifact);
        let mut config = GateConfig::smoke();
        config.require_equal_rate_latency = true;
        assert!(verify(&artifact, &config).unwrap().passed);

        let native_two = artifact
            .samples
            .iter_mut()
            .find(|sample| {
                sample.mode == RunMode::Native
                    && sample.node_count == 2
                    && sample.load_profile == LoadProfile::EqualRate
            })
            .unwrap();
        for owner in &mut native_two.owners {
            owner.latency.p99_us = 111;
        }
        let report = verify(&artifact, &config).unwrap();
        assert!(!report.passed);
        assert!(report
            .gates
            .iter()
            .any(|gate| { gate.gate_id.ends_with("maximum_p99_sample") && !gate.passed }));
    }

    #[test]
    fn transition_gate_checks_every_second_and_exact_correctness() {
        let transition = TransitionArtifact {
            transition_id: "move".into(),
            workload: WorkloadId::KvMixed256,
            from_nodes: 2,
            to_nodes: 4,
            valid: true,
            invalid_reasons: Vec::new(),
            duration_seconds: 3.0,
            steady_operations_per_second: 100.0,
            one_second_successes: vec![100, 89, 100],
            pre_transition_p99_us: 100,
            transition_p99_us: 110,
            failed_logical_operations: 0,
            missing_committed_operations: 0,
            duplicate_committed_operations: 1,
            source_target_divergences: 0,
        };
        let mut gates = Vec::new();
        verify_transition(
            &transition,
            &GateConfig::default(),
            "transition",
            &mut gates,
        );
        assert_eq!(gates.len(), 3);
        assert!(!gates[0].passed);
        assert!(gates[1].passed);
        assert!(!gates[2].passed);
    }
}
