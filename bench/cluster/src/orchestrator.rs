use crate::artifact::{CertificationArtifact, EnvironmentArtifact};
use crate::load::{run_load, LoadPlan};
use crate::resp::{RespConnection, RespValue};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::time::{sleep, Instant};

pub const RUN_PLAN_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProcessPlan {
    pub process_id: String,
    pub binary: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    pub working_directory: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RunPlan {
    pub schema_version: u32,
    pub run_id: String,
    pub processes: Vec<ProcessPlan>,
    pub loads: Vec<LoadPlan>,
    pub environment: EnvironmentArtifact,
    pub log_directory: PathBuf,
    #[serde(default = "default_readiness_timeout_seconds")]
    pub readiness_timeout_seconds: f64,
    #[serde(default)]
    pub settle_seconds: f64,
}

impl RunPlan {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != RUN_PLAN_SCHEMA_VERSION {
            bail!(
                "unsupported run-plan schema {}, expected {}",
                self.schema_version,
                RUN_PLAN_SCHEMA_VERSION
            );
        }
        if self.run_id.trim().is_empty() {
            bail!("run_id cannot be empty");
        }
        if self.processes.is_empty() {
            bail!("run plan must contain at least one Engine process");
        }
        if self.loads.is_empty() {
            bail!("run plan must contain at least one load sample");
        }
        if !self.readiness_timeout_seconds.is_finite() || self.readiness_timeout_seconds <= 0.0 {
            bail!("readiness_timeout_seconds must be positive and finite");
        }
        if !self.settle_seconds.is_finite() || self.settle_seconds < 0.0 {
            bail!("settle_seconds must be finite and non-negative");
        }
        let mut process_ids = BTreeSet::new();
        for process in &self.processes {
            if process.process_id.trim().is_empty() {
                bail!("process_id cannot be empty");
            }
            if !process_ids.insert(process.process_id.as_str()) {
                bail!("duplicate process_id {}", process.process_id);
            }
            if !process.binary.is_file() {
                bail!("Engine binary does not exist: {}", process.binary.display());
            }
        }
        for load in &self.loads {
            load.validate()?;
        }
        Ok(())
    }
}

struct ManagedProcess {
    process_id: String,
    child: Child,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

pub async fn run_local(plan: &RunPlan) -> Result<CertificationArtifact> {
    plan.validate()?;
    std::fs::create_dir_all(&plan.log_directory)
        .with_context(|| format!("create log directory {}", plan.log_directory.display()))?;

    let binary_hashes = hash_binaries(&plan.processes).await?;
    if binary_hashes.len() != 1 {
        bail!("all compared Engine processes must use byte-identical binaries");
    }
    let engine_binary_sha256 = binary_hashes.into_iter().next().unwrap();

    let mut processes = Vec::with_capacity(plan.processes.len());
    for process in &plan.processes {
        processes.push(spawn_process(process, &plan.log_directory)?);
    }

    wait_for_readiness(plan, &mut processes).await?;
    if plan.settle_seconds > 0.0 {
        sleep(Duration::from_secs_f64(plan.settle_seconds)).await;
    }

    let mut environment = plan.environment.clone();
    environment.provider = "local_process".to_owned();
    environment.engine_binary_sha256 = engine_binary_sha256;
    environment.isolated_processes = true;
    environment.external_load_generator = true;
    let mut artifact = CertificationArtifact::new(&plan.run_id, environment);
    for load in &plan.loads {
        ensure_processes_alive(&mut processes)?;
        artifact.samples.push(
            run_load(load)
                .await
                .with_context(|| format!("run sample {}", load.sample_id))?,
        );
    }
    ensure_processes_alive(&mut processes)?;
    shutdown_processes(&mut processes).await;
    Ok(artifact)
}

fn spawn_process(process: &ProcessPlan, log_directory: &Path) -> Result<ManagedProcess> {
    let stdout_path = log_directory.join(format!("{}.stdout.log", process.process_id));
    let stderr_path = log_directory.join(format!("{}.stderr.log", process.process_id));
    let stdout = std::fs::File::create(&stdout_path)
        .with_context(|| format!("create {}", stdout_path.display()))?;
    let stderr = std::fs::File::create(&stderr_path)
        .with_context(|| format!("create {}", stderr_path.display()))?;
    let mut command = Command::new(&process.binary);
    command
        .args(&process.args)
        .envs(&process.env)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .kill_on_drop(true);
    if let Some(directory) = &process.working_directory {
        command.current_dir(directory);
    }
    let child = command.spawn().with_context(|| {
        format!(
            "spawn Engine process {} from {}",
            process.process_id,
            process.binary.display()
        )
    })?;
    Ok(ManagedProcess {
        process_id: process.process_id.clone(),
        child,
        stdout_path,
        stderr_path,
    })
}

async fn wait_for_readiness(plan: &RunPlan, processes: &mut [ManagedProcess]) -> Result<()> {
    let mut endpoints = BTreeMap::<String, Option<String>>::new();
    for load in &plan.loads {
        let password = load.auth.resolve_resp_password()?;
        for endpoint in &load.endpoints {
            let existing = endpoints
                .entry(endpoint.resp_url.clone())
                .or_insert_with(|| password.clone());
            if *existing != password {
                bail!(
                    "RESP endpoint {} has conflicting credentials across samples",
                    endpoint.resp_url
                );
            }
        }
    }

    let deadline = Instant::now() + Duration::from_secs_f64(plan.readiness_timeout_seconds);
    let mut pending = endpoints;
    while !pending.is_empty() {
        ensure_processes_alive(processes)?;
        let candidates = pending
            .iter()
            .map(|(endpoint, password)| (endpoint.clone(), password.clone()))
            .collect::<Vec<_>>();
        for (endpoint, password) in candidates {
            if endpoint_ready(&endpoint, password.as_deref()).await {
                pending.remove(&endpoint);
            }
        }
        if pending.is_empty() {
            break;
        }
        if Instant::now() >= deadline {
            let endpoints = pending.keys().cloned().collect::<Vec<_>>().join(", ");
            bail!("Engine readiness timed out for: {endpoints}");
        }
        sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}

async fn endpoint_ready(endpoint: &str, password: Option<&str>) -> bool {
    let Ok(mut connection) = RespConnection::connect(endpoint, password).await else {
        return false;
    };
    matches!(
        connection.command(&[b"PING".to_vec()]).await,
        Ok(RespValue::Simple(value)) if value.eq_ignore_ascii_case("PONG")
    )
}

fn ensure_processes_alive(processes: &mut [ManagedProcess]) -> Result<()> {
    for process in processes {
        if let Some(status) = process
            .child
            .try_wait()
            .with_context(|| format!("inspect process {}", process.process_id))?
        {
            bail!(
                "Engine process {} exited with {status}; stdout={}, stderr={}",
                process.process_id,
                process.stdout_path.display(),
                process.stderr_path.display()
            );
        }
    }
    Ok(())
}

async fn shutdown_processes(processes: &mut [ManagedProcess]) {
    for process in processes.iter_mut() {
        let _ = process.child.start_kill();
    }
    for process in processes.iter_mut() {
        let _ = process.child.wait().await;
    }
}

async fn hash_binaries(processes: &[ProcessPlan]) -> Result<BTreeSet<String>> {
    let mut hashes = BTreeSet::new();
    for process in processes {
        hashes.insert(sha256_file(&process.binary).await?);
    }
    Ok(hashes)
}

pub async fn sha256_file(path: &Path) -> Result<String> {
    let mut file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("open {}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .with_context(|| format!("read {}", path.display()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn default_readiness_timeout_seconds() -> f64 {
    30.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn file_hash_is_stable() {
        let file = NamedTempFile::new().unwrap();
        let first = sha256_file(file.path()).await.unwrap();
        let second = sha256_file(file.path()).await.unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn artifact_schema_stays_independent_of_run_plan_schema() {
        assert_eq!(crate::ARTIFACT_SCHEMA_VERSION, 1);
        assert_eq!(RUN_PLAN_SCHEMA_VERSION, 1);
    }
}
