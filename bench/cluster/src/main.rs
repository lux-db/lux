use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use lux_cluster_bench::artifact::CertificationArtifact;
use lux_cluster_bench::load::{run_load, LoadPlan};
use lux_cluster_bench::orchestrator::{run_local, sha256_file, RunPlan};
use lux_cluster_bench::verify::{verify, GateConfig, VerificationReport};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "lux-cluster-bench")]
#[command(about = "External Project Cluster certification harness")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Execute one load plan against already-running Engine endpoints.
    Load {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Spawn isolated Engine processes and execute a sequence of load plans.
    RunLocal {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Evaluate a certification artifact against hard release gates.
    Verify {
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Compute the exact Engine binary digest recorded in an artifact.
    Hash {
        #[arg(long)]
        binary: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Load { plan, output } => {
            let plan: LoadPlan = read_json(&plan).await?;
            let sample = run_load(&plan).await?;
            write_json_atomic(&output, &sample).await?;
        }
        Command::RunLocal { plan, output } => {
            let plan: RunPlan = read_json(&plan).await?;
            let artifact = run_local(&plan).await?;
            write_json_atomic(&output, &artifact).await?;
        }
        Command::Verify {
            artifact,
            config,
            output,
        } => {
            let artifact: CertificationArtifact = read_json(&artifact).await?;
            let config = match config {
                Some(path) => read_json(&path).await?,
                None => GateConfig::default(),
            };
            let report = verify(&artifact, &config)?;
            emit_report(&report, output.as_deref()).await?;
            if !report.passed {
                std::process::exit(2);
            }
        }
        Command::Hash { binary } => {
            println!("{}", sha256_file(&binary).await?);
        }
    }
    Ok(())
}

async fn emit_report(report: &VerificationReport, output: Option<&Path>) -> Result<()> {
    if let Some(path) = output {
        write_json_atomic(path, report).await?;
    }
    let rendered = serde_json::to_string_pretty(report).context("serialize report")?;
    println!("{rendered}");
    Ok(())
}

async fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

async fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value).context("serialize JSON artifact")?;
    let temporary = temporary_path(path);
    tokio::fs::write(&temporary, bytes)
        .await
        .with_context(|| format!("write {}", temporary.display()))?;
    tokio::fs::rename(&temporary, path)
        .await
        .with_context(|| format!("publish {}", path.display()))?;
    Ok(())
}

fn temporary_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("artifact.json");
    path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn atomic_json_round_trip() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("sample.json");
        let value = vec!["snake_case", "stable"];
        write_json_atomic(&path, &value).await.unwrap();
        let loaded: Vec<String> = read_json(&path).await.unwrap();
        assert_eq!(loaded, value);
        assert!(!temporary_path(&path).exists());
    }
}
