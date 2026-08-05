use crate::artifact::{
    LatencySummary, LoadProfile, OwnerMeasurement, RouteEvidence, RunMode, SampleArtifact,
    WorkloadId,
};
use crate::resp::{RespConnection, RespValue};
use anyhow::{bail, Context, Result};
use futures_util::stream::{FuturesUnordered, StreamExt};
use hdrhistogram::Histogram;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Barrier;
use tokio::task::JoinSet;
use tokio::time::{sleep_until, Instant};
use url::Url;

pub const LOAD_PLAN_SCHEMA_VERSION: u32 = 1;
pub const ROUTE_SNAPSHOT_SCHEMA_VERSION: u32 = 1;
const SLOT_COUNT: u16 = 4096;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlotRange {
    pub start: u16,
    pub end: u16,
}

impl SlotRange {
    fn contains(&self, slot: u16) -> bool {
        self.start <= slot && slot <= self.end
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EndpointPlan {
    pub owner_id: String,
    pub host_id: String,
    pub resp_url: String,
    pub http_url: Option<String>,
    #[serde(default)]
    pub slots: Vec<SlotRange>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AuthPlan {
    /// Environment variable holding the RESP credential. Secret values are
    /// deliberately not representable in a serializable load plan.
    pub resp_password_env: Option<String>,
    #[serde(default)]
    /// HTTP header name to environment-variable name.
    pub http_header_env: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RouteObserverPlan {
    pub owner_id: String,
    pub url: String,
    #[serde(default)]
    pub http_header_env: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default)]
struct ResolvedAuth {
    resp_password: Option<String>,
    http_headers: BTreeMap<String, String>,
}

impl AuthPlan {
    fn validate(&self) -> Result<()> {
        if let Some(variable) = &self.resp_password_env {
            validate_env_name(variable)?;
        }
        validate_header_env(&self.http_header_env)
    }

    pub fn resolve_resp_password(&self) -> Result<Option<String>> {
        self.resp_password_env
            .as_deref()
            .map(resolve_env)
            .transpose()
    }

    fn resolve(&self) -> Result<ResolvedAuth> {
        Ok(ResolvedAuth {
            resp_password: self.resolve_resp_password()?,
            http_headers: resolve_header_env(&self.http_header_env)?,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct EngineRouteCounters {
    pub owner_local_operations: u64,
    pub compatibility_forwards: u64,
    pub point_peer_frames: u64,
    pub point_peer_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteCounterSnapshot {
    pub schema_version: u32,
    pub owner_id: String,
    pub topology_epoch: u64,
    pub execution_version: u64,
    pub counters: EngineRouteCounters,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LoadPlan {
    pub schema_version: u32,
    pub sample_id: String,
    pub mode: RunMode,
    pub workload: WorkloadId,
    pub load_profile: LoadProfile,
    /// Logical Engine node count represented by this sample. Compatibility
    /// runs normally drive one stable endpoint in front of multiple nodes.
    pub cluster_node_count: usize,
    pub duration_seconds: f64,
    pub warmup_seconds: f64,
    pub clients_per_owner: usize,
    pub pipeline_depth: usize,
    pub key_space_per_owner: usize,
    pub seed: u64,
    pub endpoints: Vec<EndpointPlan>,
    #[serde(default)]
    pub auth: AuthPlan,
    #[serde(default = "default_table_name")]
    pub table_name: String,
    pub target_operations_per_second_per_owner: Option<f64>,
    /// Independent Engine counter endpoints sampled around the measurement
    /// window. Native samples require exactly one observer per owner.
    #[serde(default)]
    pub route_observers: Vec<RouteObserverPlan>,
}

impl LoadPlan {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != LOAD_PLAN_SCHEMA_VERSION {
            bail!(
                "unsupported load-plan schema {}, expected {}",
                self.schema_version,
                LOAD_PLAN_SCHEMA_VERSION
            );
        }
        if self.sample_id.trim().is_empty() {
            bail!("sample_id cannot be empty");
        }
        if self.endpoints.is_empty() {
            bail!("at least one endpoint is required");
        }
        if self.cluster_node_count == 0 {
            bail!("cluster_node_count must be positive");
        }
        if self.mode == RunMode::Standalone
            && (self.endpoints.len() != 1 || self.cluster_node_count != 1)
        {
            bail!("standalone samples must contain exactly one logical node and endpoint");
        }
        if self.mode == RunMode::Native && self.cluster_node_count != self.endpoints.len() {
            bail!("native samples require one direct endpoint per logical node");
        }
        if !self.duration_seconds.is_finite() || self.duration_seconds <= 0.0 {
            bail!("duration_seconds must be positive and finite");
        }
        if !self.warmup_seconds.is_finite() || self.warmup_seconds < 0.0 {
            bail!("warmup_seconds must be finite and non-negative");
        }
        if self.clients_per_owner == 0 {
            bail!("clients_per_owner must be positive");
        }
        if self.pipeline_depth == 0 || self.pipeline_depth > 4096 {
            bail!("pipeline_depth must be between 1 and 4096");
        }
        if self.key_space_per_owner == 0 {
            bail!("key_space_per_owner must be positive");
        }
        if let Some(target) = self.target_operations_per_second_per_owner {
            if !target.is_finite() || target <= 0.0 {
                bail!("target operation rate must be positive and finite");
            }
        }
        match (
            self.load_profile,
            self.target_operations_per_second_per_owner,
        ) {
            (LoadProfile::Saturation, Some(_)) => {
                bail!("saturation samples cannot specify a target operation rate");
            }
            (LoadProfile::EqualRate, None) => {
                bail!("equal-rate samples require a target operation rate per owner");
            }
            _ => {}
        }
        if self.workload.is_table() && self.table_name.trim().is_empty() {
            bail!("table_name cannot be empty for table workloads");
        }
        self.auth.validate()?;

        let mut owner_ids = BTreeSet::new();
        let mut host_ids = BTreeSet::new();
        for endpoint in &self.endpoints {
            if endpoint.owner_id.trim().is_empty() || endpoint.host_id.trim().is_empty() {
                bail!("endpoint owner_id and host_id cannot be empty");
            }
            if !owner_ids.insert(endpoint.owner_id.as_str()) {
                bail!("duplicate owner_id {}", endpoint.owner_id);
            }
            host_ids.insert(endpoint.host_id.as_str());
            validate_resp_url(&endpoint.resp_url)?;
            if self.workload.is_table() {
                let http_url = endpoint
                    .http_url
                    .as_deref()
                    .context("table workload endpoint is missing http_url")?;
                validate_http_url(http_url)?;
            }
            for range in &endpoint.slots {
                if range.start > range.end || range.end >= SLOT_COUNT {
                    bail!(
                        "invalid slot range {}..={} for {}",
                        range.start,
                        range.end,
                        endpoint.owner_id
                    );
                }
            }
        }
        if host_ids.len() != self.endpoints.len() {
            bail!("each measured owner must have a distinct host_id");
        }
        if self.mode == RunMode::Native {
            validate_slot_coverage(&self.endpoints)?;
            validate_observers(&self.endpoints, &self.route_observers)?;
        } else {
            validate_optional_observers(&self.route_observers)?;
        }
        Ok(())
    }
}

#[derive(Default)]
struct BatchResult {
    successful: u64,
    failed: u64,
    moved: u64,
    ask: u64,
    latencies_us: Vec<u64>,
}

struct WorkerResult {
    owner_id: String,
    host_id: String,
    successful: u64,
    failed: u64,
    moved: u64,
    ask: u64,
    duration_seconds: f64,
    latency: Histogram<u64>,
    one_second_successes: Vec<u64>,
}

#[derive(Clone)]
struct WorkerPhases {
    connected: Arc<Barrier>,
    warmed: Arc<Barrier>,
    measurement: Arc<Barrier>,
}

pub async fn run_load(plan: &LoadPlan) -> Result<SampleArtifact> {
    plan.validate()?;
    let auth = Arc::new(plan.auth.resolve()?);
    let keys = plan
        .endpoints
        .iter()
        .map(|endpoint| generate_owned_keys(plan, endpoint))
        .collect::<Result<Vec<_>>>()?;
    prepare_data(plan, &keys, &auth).await?;

    let worker_count = plan.endpoints.len() * plan.clients_per_owner;
    let phases = WorkerPhases {
        connected: Arc::new(Barrier::new(worker_count + 1)),
        warmed: Arc::new(Barrier::new(worker_count + 1)),
        measurement: Arc::new(Barrier::new(worker_count + 1)),
    };
    let mut workers = JoinSet::new();
    for (endpoint_index, endpoint) in plan.endpoints.iter().cloned().enumerate() {
        for client_index in 0..plan.clients_per_owner {
            let plan = plan.clone();
            let endpoint = endpoint.clone();
            let keys = Arc::new(keys[endpoint_index].clone());
            let phases = phases.clone();
            let auth = Arc::clone(&auth);
            workers.spawn(async move {
                run_worker(
                    &plan,
                    endpoint_index,
                    client_index,
                    &endpoint,
                    keys,
                    phases,
                    auth,
                )
                .await
            });
        }
    }

    wait_for_phase(&phases.connected, "workers to connect", 30.0).await?;
    wait_for_phase(
        &phases.warmed,
        "workers to finish warmup",
        plan.warmup_seconds + 30.0,
    )
    .await?;
    let route_before = collect_route_snapshots(&plan.route_observers).await?;
    phases.measurement.wait().await;

    let mut worker_results = Vec::with_capacity(worker_count);
    while let Some(result) = workers.join_next().await {
        worker_results.push(result.context("load worker panicked")??);
    }
    let route_after = collect_route_snapshots(&plan.route_observers).await?;
    let engine_evidence = route_delta(&route_before, &route_after)?;
    build_sample(plan, worker_results, engine_evidence)
}

async fn run_worker(
    plan: &LoadPlan,
    endpoint_index: usize,
    client_index: usize,
    endpoint: &EndpointPlan,
    keys: Arc<Vec<String>>,
    phases: WorkerPhases,
    auth: Arc<ResolvedAuth>,
) -> Result<WorkerResult> {
    let mut protocol = if plan.workload.is_table() {
        WorkerProtocol::Table(build_http_client()?)
    } else {
        WorkerProtocol::Kv(
            RespConnection::connect(&endpoint.resp_url, auth.resp_password.as_deref()).await?,
        )
    };
    phases.connected.wait().await;

    let origin = Instant::now();
    let warmup_deadline = origin + Duration::from_secs_f64(plan.warmup_seconds);
    let mut operation = worker_operation_seed(plan, endpoint_index, client_index);
    while Instant::now() < warmup_deadline {
        let _ = perform_batch(plan, endpoint, &keys, &mut protocol, &auth, operation).await?;
        operation = operation.wrapping_add(plan.pipeline_depth as u64);
    }
    sleep_until(warmup_deadline).await;
    phases.warmed.wait().await;
    phases.measurement.wait().await;

    let measurement_start = Instant::now();
    let measurement_deadline = measurement_start + Duration::from_secs_f64(plan.duration_seconds);
    let bucket_count = plan.duration_seconds.ceil() as usize + 1;
    let mut result = WorkerResult {
        owner_id: endpoint.owner_id.clone(),
        host_id: endpoint.host_id.clone(),
        successful: 0,
        failed: 0,
        moved: 0,
        ask: 0,
        duration_seconds: 0.0,
        latency: Histogram::new(3).context("create latency histogram")?,
        one_second_successes: vec![0; bucket_count],
    };

    while Instant::now() < measurement_deadline {
        pace(plan, measurement_start, result.successful + result.failed).await;
        let batch = perform_batch(plan, endpoint, &keys, &mut protocol, &auth, operation).await?;
        operation = operation.wrapping_add(plan.pipeline_depth as u64);
        let bucket = Instant::now()
            .saturating_duration_since(measurement_start)
            .as_secs() as usize;
        let bucket = bucket.min(result.one_second_successes.len() - 1);
        result.one_second_successes[bucket] += batch.successful;
        result.successful += batch.successful;
        result.failed += batch.failed;
        result.moved += batch.moved;
        result.ask += batch.ask;
        for latency_us in batch.latencies_us {
            result
                .latency
                .record(latency_us.max(1))
                .context("record operation latency")?;
        }
    }
    result.duration_seconds = Instant::now()
        .saturating_duration_since(measurement_start)
        .as_secs_f64();
    Ok(result)
}

enum WorkerProtocol {
    Kv(RespConnection),
    Table(reqwest::Client),
}

async fn perform_batch(
    plan: &LoadPlan,
    endpoint: &EndpointPlan,
    keys: &[String],
    protocol: &mut WorkerProtocol,
    auth: &ResolvedAuth,
    operation: u64,
) -> Result<BatchResult> {
    match protocol {
        WorkerProtocol::Kv(connection) => perform_kv_batch(plan, keys, connection, operation).await,
        WorkerProtocol::Table(client) => {
            perform_table_batch(plan, endpoint, keys, client, &auth.http_headers, operation).await
        }
    }
}

async fn perform_kv_batch(
    plan: &LoadPlan,
    keys: &[String],
    connection: &mut RespConnection,
    operation: u64,
) -> Result<BatchResult> {
    let value = vec![b'x'; plan.workload.value_size()];
    let commands = (0..plan.pipeline_depth)
        .map(|offset| {
            let operation = operation.wrapping_add(offset as u64);
            let key = &keys[operation as usize % keys.len()];
            if plan.workload.is_read(operation) {
                vec![b"GET".to_vec(), key.as_bytes().to_vec()]
            } else {
                vec![b"SET".to_vec(), key.as_bytes().to_vec(), value.clone()]
            }
        })
        .collect::<Vec<_>>();
    let command_refs = commands.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let started = Instant::now();
    connection.write_commands(&command_refs).await?;
    let mut result = BatchResult::default();
    for _ in 0..commands.len() {
        let response = connection.read_response().await?;
        let elapsed = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        classify_resp(response, &mut result);
        result.latencies_us.push(elapsed.max(1));
    }
    Ok(result)
}

async fn perform_table_batch(
    plan: &LoadPlan,
    endpoint: &EndpointPlan,
    keys: &[String],
    client: &reqwest::Client,
    http_headers: &BTreeMap<String, String>,
    operation: u64,
) -> Result<BatchResult> {
    let mut requests = FuturesUnordered::new();
    for offset in 0..plan.pipeline_depth {
        let operation = operation.wrapping_add(offset as u64);
        let key = &keys[operation as usize % keys.len()];
        let url = table_row_url(endpoint, &plan.table_name, key)?;
        let mut request = if plan.workload.is_read(operation) {
            client.get(url)
        } else {
            client.put(url).json(&json!({
                "payload": payload(plan.workload.value_size()),
                "version": operation,
            }))
        };
        request = apply_headers(request, http_headers)?;
        requests.push(async move {
            let started = Instant::now();
            let response = request.send().await;
            (response, started.elapsed())
        });
    }

    let mut result = BatchResult::default();
    while let Some((response, elapsed)) = requests.next().await {
        let elapsed_us = elapsed.as_micros().min(u128::from(u64::MAX)) as u64;
        result.latencies_us.push(elapsed_us.max(1));
        match response {
            Ok(response) if response.status().is_success() => result.successful += 1,
            Ok(response) => {
                result.failed += 1;
                let status = response.status().as_u16();
                if status == 307 || status == 308 {
                    result.moved += 1;
                } else if status == 409
                    && response
                        .headers()
                        .get("x-lux-route")
                        .is_some_and(|value| value == "ask")
                {
                    result.ask += 1;
                }
            }
            Err(_) => result.failed += 1,
        }
    }
    Ok(result)
}

fn classify_resp(response: RespValue, result: &mut BatchResult) {
    match response {
        RespValue::Error(message) => {
            result.failed += 1;
            let upper = message.to_ascii_uppercase();
            if upper.starts_with("MOVED ") {
                result.moved += 1;
            } else if upper.starts_with("ASK ") {
                result.ask += 1;
            }
        }
        _ => result.successful += 1,
    }
}

async fn pace(plan: &LoadPlan, started: Instant, completed: u64) {
    let Some(per_owner) = plan.target_operations_per_second_per_owner else {
        return;
    };
    let per_worker = per_owner / plan.clients_per_owner as f64;
    let expected = Duration::from_secs_f64(completed as f64 / per_worker);
    let target = started + expected;
    if target > Instant::now() {
        sleep_until(target).await;
    }
}

fn build_sample(
    plan: &LoadPlan,
    results: Vec<WorkerResult>,
    engine_evidence: Option<RouteEvidence>,
) -> Result<SampleArtifact> {
    let mut owners: BTreeMap<String, Vec<WorkerResult>> = BTreeMap::new();
    for result in results {
        owners
            .entry(result.owner_id.clone())
            .or_default()
            .push(result);
    }

    let mut aggregate_histogram = Histogram::<u64>::new(3)?;
    let mut owner_measurements = Vec::with_capacity(owners.len());
    let mut successful = 0_u64;
    let mut failed = 0_u64;
    let mut moved = 0_u64;
    let mut ask = 0_u64;
    let mut maximum_duration = 0.0_f64;
    for (owner_id, workers) in owners {
        let host_id = workers[0].host_id.clone();
        let duration = workers
            .iter()
            .map(|worker| worker.duration_seconds)
            .fold(0.0_f64, f64::max);
        maximum_duration = maximum_duration.max(duration);
        let owner_successful = workers.iter().map(|worker| worker.successful).sum::<u64>();
        let owner_failed = workers.iter().map(|worker| worker.failed).sum::<u64>();
        let mut histogram = Histogram::<u64>::new(3)?;
        let bucket_count = workers
            .iter()
            .map(|worker| worker.one_second_successes.len())
            .max()
            .unwrap_or(0);
        let mut buckets = vec![0_u64; bucket_count];
        for worker in &workers {
            histogram.add(&worker.latency)?;
            aggregate_histogram.add(&worker.latency)?;
            moved += worker.moved;
            ask += worker.ask;
            for (index, count) in worker.one_second_successes.iter().enumerate() {
                buckets[index] += count;
            }
        }
        successful += owner_successful;
        failed += owner_failed;
        owner_measurements.push(OwnerMeasurement {
            owner_id,
            host_id,
            successful_operations: owner_successful,
            failed_operations: owner_failed,
            duration_seconds: duration,
            useful_operations_per_second: owner_successful as f64 / duration,
            latency: summarize_latency(&histogram),
            one_second_successes: buckets,
        });
    }

    let mut invalid_reasons = Vec::new();
    if successful == 0 {
        invalid_reasons.push("sample completed no successful operations".to_owned());
    }
    if plan.mode == RunMode::Native && engine_evidence.is_none() {
        invalid_reasons
            .push("native sample is missing independent Engine route evidence".to_owned());
    }
    let mut route_evidence = engine_evidence.unwrap_or_default();
    route_evidence.moved_responses += moved;
    route_evidence.ask_responses += ask;
    route_evidence.connection_attempts += (plan.endpoints.len() * plan.clients_per_owner) as u64;
    route_evidence.tls_handshakes += plan
        .endpoints
        .iter()
        .filter(|endpoint| {
            endpoint.resp_url.starts_with("rediss://")
                || endpoint.resp_url.starts_with("luxs://")
                || endpoint
                    .http_url
                    .as_deref()
                    .is_some_and(|url| url.starts_with("https://"))
        })
        .count() as u64
        * plan.clients_per_owner as u64;

    Ok(SampleArtifact {
        sample_id: plan.sample_id.clone(),
        workload: plan.workload,
        mode: plan.mode,
        load_profile: plan.load_profile,
        node_count: plan.cluster_node_count,
        pipeline_depth: plan.pipeline_depth,
        clients_per_owner: plan.clients_per_owner,
        key_space_per_owner: plan.key_space_per_owner,
        value_size_bytes: plan.workload.value_size(),
        seed: plan.seed,
        target_operations_per_second_per_owner: plan.target_operations_per_second_per_owner,
        valid: invalid_reasons.is_empty(),
        invalid_reasons,
        owners: owner_measurements,
        aggregate_successful_operations: successful,
        aggregate_failed_operations: failed,
        duration_seconds: maximum_duration,
        aggregate_useful_operations_per_second: successful as f64 / maximum_duration,
        aggregate_latency: summarize_latency(&aggregate_histogram),
        route_evidence,
    })
}

async fn wait_for_phase(barrier: &Barrier, phase: &str, timeout_seconds: f64) -> Result<()> {
    tokio::time::timeout(Duration::from_secs_f64(timeout_seconds), barrier.wait())
        .await
        .with_context(|| format!("timed out waiting for {phase}"))?;
    Ok(())
}

async fn collect_route_snapshots(
    observers: &[RouteObserverPlan],
) -> Result<BTreeMap<String, RouteCounterSnapshot>> {
    if observers.is_empty() {
        return Ok(BTreeMap::new());
    }
    let client = build_http_client()?;
    let mut requests = FuturesUnordered::new();
    for observer in observers {
        let owner_id = observer.owner_id.clone();
        let request = client.get(&observer.url);
        let headers = resolve_header_env(&observer.http_header_env)?;
        let request = apply_headers(request, &headers)?;
        requests.push(async move {
            let response = request
                .send()
                .await
                .with_context(|| format!("read route counters for {owner_id}"))?;
            let status = response.status();
            if !status.is_success() {
                let body = response.text().await.unwrap_or_default();
                bail!("route observer {owner_id} returned {status}: {body}");
            }
            let snapshot = response
                .json::<RouteCounterSnapshot>()
                .await
                .with_context(|| format!("decode route counters for {owner_id}"))?;
            if snapshot.schema_version != ROUTE_SNAPSHOT_SCHEMA_VERSION {
                bail!(
                    "route observer {owner_id} schema is {}, expected {}",
                    snapshot.schema_version,
                    ROUTE_SNAPSHOT_SCHEMA_VERSION
                );
            }
            if snapshot.owner_id != owner_id {
                bail!(
                    "route observer owner mismatch: requested {owner_id}, received {}",
                    snapshot.owner_id
                );
            }
            Ok::<_, anyhow::Error>((owner_id, snapshot))
        });
    }

    let mut snapshots = BTreeMap::new();
    while let Some(result) = requests.next().await {
        let (owner_id, snapshot) = result?;
        snapshots.insert(owner_id, snapshot);
    }
    Ok(snapshots)
}

fn route_delta(
    before: &BTreeMap<String, RouteCounterSnapshot>,
    after: &BTreeMap<String, RouteCounterSnapshot>,
) -> Result<Option<RouteEvidence>> {
    if before.is_empty() && after.is_empty() {
        return Ok(None);
    }
    if before.keys().collect::<Vec<_>>() != after.keys().collect::<Vec<_>>() {
        bail!("route observer set changed during measurement");
    }
    let mut evidence = RouteEvidence::default();
    for (owner_id, before) in before {
        let after = &after[owner_id];
        if before.topology_epoch != after.topology_epoch {
            bail!("owner {owner_id} topology changed during stable measurement");
        }
        if before.execution_version != after.execution_version {
            bail!("owner {owner_id} execution metadata changed during stable measurement");
        }
        evidence.owner_local_operations += checked_delta(
            owner_id,
            "owner_local_operations",
            before.counters.owner_local_operations,
            after.counters.owner_local_operations,
        )?;
        evidence.compatibility_forwards += checked_delta(
            owner_id,
            "compatibility_forwards",
            before.counters.compatibility_forwards,
            after.counters.compatibility_forwards,
        )?;
        evidence.point_peer_frames += checked_delta(
            owner_id,
            "point_peer_frames",
            before.counters.point_peer_frames,
            after.counters.point_peer_frames,
        )?;
        evidence.point_peer_bytes += checked_delta(
            owner_id,
            "point_peer_bytes",
            before.counters.point_peer_bytes,
            after.counters.point_peer_bytes,
        )?;
    }
    Ok(Some(evidence))
}

fn checked_delta(owner_id: &str, counter: &str, before: u64, after: u64) -> Result<u64> {
    after.checked_sub(before).with_context(|| {
        format!("route counter {counter} reset on owner {owner_id} during measurement")
    })
}

fn summarize_latency(histogram: &Histogram<u64>) -> LatencySummary {
    if histogram.is_empty() {
        return LatencySummary::default();
    }
    LatencySummary {
        count: histogram.len(),
        min_us: histogram.min(),
        p50_us: histogram.value_at_quantile(0.50),
        p95_us: histogram.value_at_quantile(0.95),
        p99_us: histogram.value_at_quantile(0.99),
        max_us: histogram.max(),
        mean_us: histogram.mean(),
    }
}

async fn prepare_data(plan: &LoadPlan, keys: &[Vec<String>], auth: &ResolvedAuth) -> Result<()> {
    if plan.workload.is_table() {
        prepare_table(plan, keys, &auth.http_headers).await
    } else if plan.workload.is_read(0) || plan.workload.is_mixed() {
        prepare_kv(plan, keys, auth.resp_password.as_deref()).await
    } else {
        Ok(())
    }
}

async fn prepare_kv(
    plan: &LoadPlan,
    keys: &[Vec<String>],
    resp_password: Option<&str>,
) -> Result<()> {
    let value = vec![b'x'; plan.workload.value_size()];
    for (endpoint, keys) in plan.endpoints.iter().zip(keys) {
        let mut connection = RespConnection::connect(&endpoint.resp_url, resp_password).await?;
        for chunk in keys.chunks(256) {
            let commands = chunk
                .iter()
                .map(|key| vec![b"SET".to_vec(), key.as_bytes().to_vec(), value.clone()])
                .collect::<Vec<_>>();
            let references = commands.iter().map(Vec::as_slice).collect::<Vec<_>>();
            connection.write_commands(&references).await?;
            for _ in chunk {
                if let RespValue::Error(message) = connection.read_response().await? {
                    bail!("preload SET failed: {message}");
                }
            }
        }
    }
    Ok(())
}

async fn prepare_table(
    plan: &LoadPlan,
    keys: &[Vec<String>],
    http_headers: &BTreeMap<String, String>,
) -> Result<()> {
    let client = build_http_client()?;
    let create_url = table_collection_url(&plan.endpoints[0], None)?;
    let request = client.post(create_url).json(&json!({
        "name": plan.table_name,
        "columns": ["id STR PRIMARY KEY", "payload STR", "version INT"]
    }));
    let response = apply_headers(request, http_headers)?.send().await?;
    if !response.status().is_success() && response.status().as_u16() != 409 {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !body.to_ascii_lowercase().contains("already exists") {
            bail!("create benchmark table failed with {status}: {body}");
        }
    }

    for (endpoint, keys) in plan.endpoints.iter().zip(keys) {
        for chunk in keys.chunks(64) {
            let mut requests = FuturesUnordered::new();
            for key in chunk {
                let url = table_collection_url(endpoint, Some(&plan.table_name))?;
                let request = client.post(url).json(&json!({
                    "id": key,
                    "payload": payload(plan.workload.value_size()),
                    "version": 0,
                }));
                requests.push(apply_headers(request, http_headers)?.send());
            }
            while let Some(response) = requests.next().await {
                let response = response?;
                if !response.status().is_success() && response.status().as_u16() != 409 {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    if !body.to_ascii_lowercase().contains("already exists") {
                        bail!("preload table row failed with {status}: {body}");
                    }
                }
            }
        }
    }
    Ok(())
}

fn generate_owned_keys(plan: &LoadPlan, endpoint: &EndpointPlan) -> Result<Vec<String>> {
    let mut keys = Vec::with_capacity(plan.key_space_per_owner);
    let mut candidate = 0_u64;
    let maximum_candidates = (plan.key_space_per_owner as u64)
        .saturating_mul(SLOT_COUNT as u64)
        .max(SLOT_COUNT as u64);
    while keys.len() < plan.key_space_per_owner && candidate < maximum_candidates {
        let key = format!("bench:{}:{:016x}", plan.seed, candidate);
        let slot = if plan.workload.is_table() {
            slot_for_table_row(plan.table_name.as_bytes(), key.as_bytes())
        } else {
            slot_for_key(key.as_bytes())
        };
        if endpoint.slots.is_empty() || endpoint.slots.iter().any(|range| range.contains(slot)) {
            keys.push(key);
        }
        candidate = candidate.wrapping_add(1);
    }
    if keys.len() != plan.key_space_per_owner {
        bail!(
            "could not generate {} owned keys for {}",
            plan.key_space_per_owner,
            endpoint.owner_id
        );
    }
    Ok(keys)
}

fn validate_slot_coverage(endpoints: &[EndpointPlan]) -> Result<()> {
    let mut owners = vec![None::<&str>; SLOT_COUNT as usize];
    for endpoint in endpoints {
        if endpoint.slots.is_empty() {
            bail!("native endpoint {} has no owned slots", endpoint.owner_id);
        }
        for range in &endpoint.slots {
            for slot in range.start..=range.end {
                if let Some(existing) = owners[slot as usize] {
                    bail!(
                        "slot {slot} is assigned to both {existing} and {}",
                        endpoint.owner_id
                    );
                }
                owners[slot as usize] = Some(&endpoint.owner_id);
            }
        }
    }
    if let Some((slot, _)) = owners.iter().enumerate().find(|(_, owner)| owner.is_none()) {
        bail!("native endpoint plan does not assign slot {slot}");
    }
    Ok(())
}

fn validate_observers(endpoints: &[EndpointPlan], observers: &[RouteObserverPlan]) -> Result<()> {
    if observers.len() != endpoints.len() {
        bail!("native samples require exactly one route observer per owner");
    }
    validate_optional_observers(observers)?;
    let expected = endpoints
        .iter()
        .map(|endpoint| endpoint.owner_id.as_str())
        .collect::<BTreeSet<_>>();
    let actual = observers
        .iter()
        .map(|observer| observer.owner_id.as_str())
        .collect::<BTreeSet<_>>();
    if expected != actual {
        bail!("route observer owner_ids must exactly match endpoint owner_ids");
    }
    Ok(())
}

fn validate_optional_observers(observers: &[RouteObserverPlan]) -> Result<()> {
    let mut owners = BTreeSet::new();
    for observer in observers {
        if observer.owner_id.trim().is_empty() {
            bail!("route observer owner_id cannot be empty");
        }
        if !owners.insert(observer.owner_id.as_str()) {
            bail!("duplicate route observer for {}", observer.owner_id);
        }
        validate_http_url(&observer.url)?;
        validate_header_env(&observer.http_header_env)?;
    }
    Ok(())
}

fn validate_resp_url(raw: &str) -> Result<()> {
    let raw = if raw.contains("://") {
        raw.to_owned()
    } else {
        format!("redis://{raw}")
    };
    let url = Url::parse(&raw).context("parse resp_url")?;
    if !matches!(url.scheme(), "redis" | "rediss" | "lux" | "luxs") {
        bail!("unsupported RESP URL scheme {}", url.scheme());
    }
    url.host_str().context("resp_url is missing a host")?;
    Ok(())
}

fn validate_http_url(raw: &str) -> Result<()> {
    let url = Url::parse(raw).context("parse http_url")?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("unsupported HTTP URL scheme {}", url.scheme());
    }
    url.host_str().context("http_url is missing a host")?;
    Ok(())
}

fn table_collection_url(endpoint: &EndpointPlan, table: Option<&str>) -> Result<Url> {
    let mut url = Url::parse(
        endpoint
            .http_url
            .as_deref()
            .context("endpoint is missing http_url")?,
    )?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("http_url cannot be a base URL"))?;
        segments.pop_if_empty().push("v1").push("tables");
        if let Some(table) = table {
            segments.push(table);
        }
    }
    Ok(url)
}

fn table_row_url(endpoint: &EndpointPlan, table: &str, key: &str) -> Result<Url> {
    let mut url = table_collection_url(endpoint, Some(table))?;
    url.path_segments_mut()
        .map_err(|_| anyhow::anyhow!("http_url cannot be a base URL"))?
        .push(key);
    Ok(url)
}

fn apply_headers(
    mut request: reqwest::RequestBuilder,
    headers: &BTreeMap<String, String>,
) -> Result<reqwest::RequestBuilder> {
    for (name, value) in headers {
        let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .with_context(|| format!("invalid HTTP header name {name}"))?;
        let value = reqwest::header::HeaderValue::from_str(value)
            .with_context(|| format!("invalid HTTP header value for {name}"))?;
        request = request.header(name, value);
    }
    Ok(request)
}

fn validate_header_env(headers: &BTreeMap<String, String>) -> Result<()> {
    for (name, variable) in headers {
        reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .with_context(|| format!("invalid HTTP header name {name}"))?;
        validate_env_name(variable)?;
    }
    Ok(())
}

fn resolve_header_env(headers: &BTreeMap<String, String>) -> Result<BTreeMap<String, String>> {
    headers
        .iter()
        .map(|(name, variable)| Ok((name.clone(), resolve_env(variable)?)))
        .collect()
}

fn resolve_env(variable: &str) -> Result<String> {
    validate_env_name(variable)?;
    std::env::var(variable)
        .with_context(|| format!("required credential environment variable {variable} is not set"))
}

fn validate_env_name(variable: &str) -> Result<()> {
    let mut characters = variable.chars();
    let Some(first) = characters.next() else {
        bail!("credential environment-variable name cannot be empty");
    };
    if !(first == '_' || first.is_ascii_alphabetic())
        || !characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
    {
        bail!("invalid credential environment-variable name {variable}");
    }
    Ok(())
}

fn build_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .pool_idle_timeout(Duration::from_secs(60))
        .tcp_nodelay(true)
        .build()
        .context("build HTTP client")
}

fn payload(size: usize) -> String {
    "x".repeat(size)
}

fn worker_operation_seed(plan: &LoadPlan, endpoint: usize, client: usize) -> u64 {
    plan.seed
        ^ (endpoint as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ (client as u64).wrapping_mul(0xbf58_476d_1ce4_e5b9)
}

#[inline]
fn slot_for_key(key: &[u8]) -> u16 {
    redis_crc16(hash_tag(key)) % SLOT_COUNT
}

#[inline]
fn slot_for_table_row(table: &[u8], primary_key: &[u8]) -> u16 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x100_0000_01b3;
    let mut hash = fnv1a64_continue(FNV_OFFSET, table);
    hash ^= 0;
    hash = hash.wrapping_mul(FNV_PRIME);
    hash = fnv1a64_continue(hash, primary_key);
    (hash % u64::from(SLOT_COUNT)) as u16
}

fn redis_crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0_u16;
    for &byte in bytes {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

fn fnv1a64_continue(mut hash: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

fn hash_tag(key: &[u8]) -> &[u8] {
    let Some(open) = key.iter().position(|byte| *byte == b'{') else {
        return key;
    };
    let tail = &key[open + 1..];
    match tail.iter().position(|byte| *byte == b'}') {
        Some(length) if length > 0 => &tail[..length],
        _ => key,
    }
}

fn default_table_name() -> String {
    "bench_rows".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(owner: &str, start: u16, end: u16) -> EndpointPlan {
        EndpointPlan {
            owner_id: owner.into(),
            host_id: format!("host-{owner}"),
            resp_url: "redis://127.0.0.1:6379".into(),
            http_url: Some("http://127.0.0.1:5890".into()),
            slots: vec![SlotRange { start, end }],
        }
    }

    fn plan() -> LoadPlan {
        LoadPlan {
            schema_version: LOAD_PLAN_SCHEMA_VERSION,
            sample_id: "sample".into(),
            mode: RunMode::Native,
            workload: WorkloadId::KvSet256,
            load_profile: LoadProfile::Saturation,
            cluster_node_count: 2,
            duration_seconds: 1.0,
            warmup_seconds: 0.0,
            clients_per_owner: 1,
            pipeline_depth: 1,
            key_space_per_owner: 64,
            seed: 7,
            endpoints: vec![endpoint("a", 0, 2047), endpoint("b", 2048, 4095)],
            auth: AuthPlan::default(),
            table_name: default_table_name(),
            target_operations_per_second_per_owner: None,
            route_observers: vec![
                RouteObserverPlan {
                    owner_id: "a".into(),
                    url: "http://127.0.0.1:5890/v1/cluster/route-counters".into(),
                    http_header_env: BTreeMap::new(),
                },
                RouteObserverPlan {
                    owner_id: "b".into(),
                    url: "http://127.0.0.1:5891/v1/cluster/route-counters".into(),
                    http_header_env: BTreeMap::new(),
                },
            ],
        }
    }

    #[test]
    fn routing_hashes_match_engine_contract() {
        assert_eq!(redis_crc16(b"123456789"), 0x31c3);
        assert_eq!(slot_for_key(b"123456789"), 451);
        assert_eq!(
            slot_for_key(b"cart:{user-1}"),
            slot_for_key(b"order:{user-1}")
        );
        assert_ne!(
            slot_for_table_row(b"orders", b"42"),
            slot_for_table_row(b"users", b"42")
        );
    }

    #[test]
    fn native_plan_requires_exact_non_overlapping_coverage() {
        assert!(plan().validate().is_ok());
        let mut gap = plan();
        gap.endpoints[0].slots[0].end = 2046;
        assert!(gap.validate().is_err());
        let mut overlap = plan();
        overlap.endpoints[1].slots[0].start = 2047;
        assert!(overlap.validate().is_err());
    }

    #[test]
    fn generated_keys_belong_to_the_declared_owner() {
        let plan = plan();
        for endpoint in &plan.endpoints {
            let keys = generate_owned_keys(&plan, endpoint).unwrap();
            assert_eq!(keys.len(), plan.key_space_per_owner);
            assert!(keys.iter().all(|key| endpoint
                .slots
                .iter()
                .any(|range| range.contains(slot_for_key(key.as_bytes())))));
        }
    }

    #[test]
    fn native_sample_without_engine_evidence_is_invalid() {
        let plan = plan();
        let result = WorkerResult {
            owner_id: "a".into(),
            host_id: "host-a".into(),
            successful: 10,
            failed: 0,
            moved: 0,
            ask: 0,
            duration_seconds: 1.0,
            latency: Histogram::new(3).unwrap(),
            one_second_successes: vec![10],
        };
        let sample = build_sample(&plan, vec![result], None).unwrap();
        assert!(!sample.valid);
        assert!(sample.invalid_reasons[0].contains("route evidence"));
    }

    #[test]
    fn load_profile_and_target_rate_cannot_disagree() {
        let mut invalid = plan();
        invalid.target_operations_per_second_per_owner = Some(1_000.0);
        assert!(invalid.validate().is_err());
        invalid.load_profile = LoadProfile::EqualRate;
        assert!(invalid.validate().is_ok());
        invalid.target_operations_per_second_per_owner = None;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn serialized_plans_reference_credentials_only_by_environment_name() {
        let mut plan = plan();
        plan.auth = AuthPlan {
            resp_password_env: Some("LUX_BENCH_RESP_PASSWORD".into()),
            http_header_env: BTreeMap::from([(
                "authorization".into(),
                "LUX_BENCH_AUTHORIZATION".into(),
            )]),
        };
        let json = serde_json::to_string(&plan).unwrap();
        assert!(json.contains("LUX_BENCH_RESP_PASSWORD"));
        assert!(json.contains("LUX_BENCH_AUTHORIZATION"));
        assert!(!json.contains("bearer secret"));
        assert!(plan.validate().is_ok());

        plan.auth.resp_password_env = Some("not a variable".into());
        assert!(plan.validate().is_err());
    }

    #[test]
    fn route_evidence_is_a_checked_counter_delta() {
        let before = BTreeMap::from([("a".into(), snapshot("a", 10, 2, 3, 40))]);
        let after = BTreeMap::from([("a".into(), snapshot("a", 110, 2, 3, 40))]);
        let delta = route_delta(&before, &after).unwrap().unwrap();
        assert_eq!(delta.owner_local_operations, 100);
        assert_eq!(delta.compatibility_forwards, 0);
        assert_eq!(delta.point_peer_frames, 0);
        assert_eq!(delta.point_peer_bytes, 0);

        let mut changed_epoch = after.clone();
        changed_epoch.get_mut("a").unwrap().topology_epoch = 3;
        assert!(route_delta(&before, &changed_epoch).is_err());

        let reset = BTreeMap::from([("a".into(), snapshot("a", 9, 2, 3, 40))]);
        assert!(route_delta(&before, &reset).is_err());
    }

    fn snapshot(
        owner_id: &str,
        owner_local_operations: u64,
        topology_epoch: u64,
        execution_version: u64,
        point_peer_bytes: u64,
    ) -> RouteCounterSnapshot {
        RouteCounterSnapshot {
            schema_version: ROUTE_SNAPSHOT_SCHEMA_VERSION,
            owner_id: owner_id.into(),
            topology_epoch,
            execution_version,
            counters: EngineRouteCounters {
                owner_local_operations,
                compatibility_forwards: 0,
                point_peer_frames: 0,
                point_peer_bytes,
            },
        }
    }
}
