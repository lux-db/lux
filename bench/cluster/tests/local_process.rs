use lux_cluster_bench::artifact::{EnvironmentArtifact, LoadProfile, RunMode, WorkloadId};
use lux_cluster_bench::load::{AuthPlan, EndpointPlan, LoadPlan, LOAD_PLAN_SCHEMA_VERSION};
use lux_cluster_bench::orchestrator::{run_local, ProcessPlan, RunPlan, RUN_PLAN_SCHEMA_VERSION};
use std::collections::BTreeMap;
use std::net::TcpListener;
use std::path::PathBuf;
use tempfile::tempdir;

#[tokio::test]
#[ignore = "requires a separately built Lux Engine binary"]
async fn orchestrates_a_real_out_of_process_engine() {
    let binary = PathBuf::from(
        std::env::var_os("LUX_BENCH_ENGINE_BIN")
            .expect("LUX_BENCH_ENGINE_BIN must point to a separately built Engine binary"),
    );
    assert!(
        binary.is_file(),
        "missing Engine binary: {}",
        binary.display()
    );

    let resp_port = available_port();
    let http_port = available_port();
    let directory = tempdir().unwrap();
    let data_directory = directory.path().join("engine-data");
    let log_directory = directory.path().join("logs");
    let endpoint = EndpointPlan {
        owner_id: "owner-1".into(),
        host_id: "engine-host-1".into(),
        resp_url: format!("redis://127.0.0.1:{resp_port}"),
        http_url: Some(format!("http://127.0.0.1:{http_port}")),
        slots: Vec::new(),
    };
    let load = LoadPlan {
        schema_version: LOAD_PLAN_SCHEMA_VERSION,
        sample_id: "standalone-kv-set".into(),
        mode: RunMode::Standalone,
        workload: WorkloadId::KvSet256,
        load_profile: LoadProfile::Saturation,
        cluster_node_count: 1,
        duration_seconds: 0.25,
        warmup_seconds: 0.05,
        clients_per_owner: 2,
        pipeline_depth: 1,
        key_space_per_owner: 128,
        seed: 42,
        endpoints: vec![endpoint],
        auth: AuthPlan::default(),
        table_name: "bench_rows".into(),
        target_operations_per_second_per_owner: None,
        route_observers: Vec::new(),
    };
    let process = ProcessPlan {
        process_id: "engine-1".into(),
        binary,
        args: Vec::new(),
        env: BTreeMap::from([
            ("LUX_BIND_HOST".into(), "127.0.0.1".into()),
            ("LUX_PORT".into(), resp_port.to_string()),
            ("LUX_HTTP_PORT".into(), http_port.to_string()),
            ("LUX_SHARDS".into(), "2".into()),
            ("LUX_SAVE_INTERVAL".into(), "0".into()),
            (
                "LUX_DATA_DIR".into(),
                data_directory.to_string_lossy().into_owned(),
            ),
        ]),
        working_directory: Some(directory.path().to_path_buf()),
    };
    let plan = RunPlan {
        schema_version: RUN_PLAN_SCHEMA_VERSION,
        run_id: "separate-process-smoke".into(),
        processes: vec![process],
        loads: vec![load],
        environment: EnvironmentArtifact {
            provider: String::new(),
            engine_binary_sha256: String::new(),
            candidate_git_sha: "integration-test".into(),
            harness_git_sha: "integration-test".into(),
            load_generator_host: "load-generator".into(),
            observer_host: "observer".into(),
            engine_hosts: vec!["engine-host-1".into()],
            isolated_processes: false,
            external_load_generator: false,
            homogeneous_engine_resources: true,
            load_generator_headroom_ratio: 2.0,
            max_engine_nic_utilization: 0.0,
            max_engine_cpu_throttle_seconds: 0.0,
            max_observer_cpu_ratio: 0.0,
            max_clock_offset_ms: 0.0,
            labels: BTreeMap::new(),
        },
        log_directory: log_directory.clone(),
        readiness_timeout_seconds: 10.0,
        settle_seconds: 0.0,
    };

    let artifact = run_local(&plan).await.unwrap_or_else(|error| {
        let stderr =
            std::fs::read_to_string(log_directory.join("engine-1.stderr.log")).unwrap_or_default();
        panic!("separate-process run failed: {error:#}\nEngine stderr:\n{stderr}");
    });
    assert_eq!(artifact.samples.len(), 1);
    let sample = &artifact.samples[0];
    assert!(sample.valid, "invalid sample: {:?}", sample.invalid_reasons);
    assert!(sample.aggregate_successful_operations > 0);
    assert_eq!(sample.aggregate_failed_operations, 0);
    assert_eq!(sample.owners.len(), 1);
    assert!(artifact.environment.isolated_processes);
    assert!(artifact.environment.external_load_generator);
    assert_eq!(artifact.environment.engine_binary_sha256.len(), 64);
}

fn available_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
