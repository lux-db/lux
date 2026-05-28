use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lux::{EmbeddedClient, EmbeddedPipeline, EmbeddedValue, PreparedPipeline, ServerConfig};
use tokio::task::JoinHandle;

#[derive(Clone, Copy)]
struct TrialConfig {
    requests: usize,
    clients: usize,
    pipeline: usize,
    min_seconds: f64,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut args = env::args().skip(1);
    let suite = args.next().unwrap_or_else(|| usage());

    let requests = read_usize("BENCH_REQUESTS", 1_000_000);
    let clients = read_usize("BENCH_CLIENTS", 50).max(1);
    let pipeline = read_usize("BENCH_PIPELINE", 1).max(1);
    let geo_members = read_usize("GEO_MEMBERS", 1_000);
    let keyspace = read_usize("BENCH_KEYSPACE", 1_024).max(1);
    let min_seconds = read_f64("BENCH_MIN_SECONDS", 0.0).max(0.0);

    let data_dir = bench_data_dir();
    std::fs::create_dir_all(&data_dir)?;

    let handle = lux::run_with_config(ServerConfig {
        enable_resp: false,
        http_port: 0,
        data_dir: data_dir.display().to_string(),
        save_interval: Duration::ZERO,
        ..Default::default()
    })
    .await?;
    let client = handle.client();

    if suite == "validate" {
        let (command, postcheck) = split_validate_args(args.collect());
        if command.is_empty() {
            usage();
        }
        if is_geo_command(&command) {
            seed_geo(&client, geo_key_from_command(&command), geo_members).await?;
        }
        let output = validate_command(client, command, postcheck).await?;
        handle.shutdown_and_wait().await?;
        let _ = std::fs::remove_dir_all(&data_dir);
        println!("{}", serde_json::to_string(&output)?);
        return Ok(());
    }

    let rps = match suite.as_str() {
        "set" => bench_set(client, requests, clients, pipeline, min_seconds).await?,
        "cmd" => {
            let command: Vec<String> = args.collect();
            if command.is_empty() {
                usage();
            }
            if is_geo_command(&command) {
                seed_geo(&client, geo_key_from_command(&command), geo_members).await?;
            }
            bench_command(
                client,
                requests,
                clients,
                pipeline,
                keyspace,
                min_seconds,
                command,
            )
            .await?
        }
        "geo" => {
            let command: Vec<String> = args.collect();
            if command.is_empty() {
                usage();
            }
            seed_geo(&client, geo_key_from_command(&command), geo_members).await?;
            bench_command(
                client,
                requests,
                clients,
                pipeline,
                keyspace,
                min_seconds,
                command,
            )
            .await?
        }
        _ => usage(),
    };

    handle.shutdown_and_wait().await?;
    let _ = std::fs::remove_dir_all(&data_dir);
    println!("{rps:.2}");
    Ok(())
}

fn usage() -> ! {
    eprintln!(
        "usage: embedded_bench <set|cmd COMMAND [ARGS...]|geo [COMMAND ARGS...]|validate COMMAND [ARGS...] [--post COMMAND [ARGS...]]>
\n\
         env: BENCH_REQUESTS BENCH_CLIENTS BENCH_PIPELINE BENCH_MIN_SECONDS GEO_MEMBERS"
    );
    std::process::exit(2);
}

fn is_geo_command(command: &[String]) -> bool {
    command
        .first()
        .is_some_and(|cmd| cmd.to_ascii_uppercase().starts_with("GEO"))
}

fn geo_key_from_command(command: &[String]) -> &str {
    command.get(1).map(String::as_str).unwrap_or("mygeo")
}

fn split_validate_args(args: Vec<String>) -> (Vec<String>, Option<Vec<String>>) {
    let Some(pos) = args.iter().position(|arg| arg == "--post") else {
        return (args, None);
    };
    let command = args[..pos].to_vec();
    let postcheck = args[pos + 1..].to_vec();
    let postcheck = if postcheck.is_empty() {
        None
    } else {
        Some(postcheck)
    };
    (command, postcheck)
}

fn read_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn read_f64(name: &str, default: f64) -> f64 {
    env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn bench_data_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    env::temp_dir().join(format!("lux-embedded-bench-{}-{nanos}", std::process::id()))
}

async fn bench_set(
    client: EmbeddedClient,
    requests: usize,
    clients: usize,
    pipeline: usize,
    min_seconds: f64,
) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    if min_seconds > 0.0 {
        let mut total_requests = 0usize;
        let mut total_elapsed = Duration::ZERO;
        let target = Duration::from_secs_f64(min_seconds);
        while total_elapsed < target {
            let started = Instant::now();
            run_set_trial(client.clone(), requests, clients, pipeline).await?;
            total_elapsed += started.elapsed();
            total_requests += requests;
        }
        return rps_for_elapsed(total_requests, total_elapsed);
    }

    let started = Instant::now();
    run_set_trial(client, requests, clients, pipeline).await?;
    rps(requests, started)
}

async fn run_set_trial(
    client: EmbeddedClient,
    requests: usize,
    clients: usize,
    pipeline: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let started = Instant::now();
    let mut tasks: Vec<JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>> =
        Vec::new();

    for worker in 0..clients {
        let client = client.clone();
        let count = requests / clients + usize::from(worker < requests % clients);
        tasks.push(tokio::spawn(async move {
            let full_batches = count / pipeline;
            let remainder = count % pipeline;
            let key = b"__lux_bench_key".as_slice();
            let value = b"__lux_bench_value".as_slice();
            let mut batch = EmbeddedPipeline::with_capacity(pipeline);
            for _ in 0..pipeline {
                batch.set(key, value);
            }

            for _ in 0..full_batches {
                client.execute_embedded_pipeline_discard(&batch).await?;
            }
            if remainder > 0 {
                let mut partial = EmbeddedPipeline::with_capacity(remainder);
                for _ in 0..remainder {
                    partial.set(key, value);
                }
                client.execute_embedded_pipeline_discard(&partial).await?;
            }
            Ok(())
        }));
    }

    for task in tasks {
        task.await??;
    }

    let _ = started;
    Ok(())
}

async fn bench_command(
    client: EmbeddedClient,
    requests: usize,
    clients: usize,
    pipeline: usize,
    keyspace: usize,
    min_seconds: f64,
    command: Vec<String>,
) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    let command = command
        .into_iter()
        .map(|arg| arg.into_bytes())
        .collect::<Vec<_>>();

    if command_has_rand_int(&command) {
        seed_rand_keyspace(&client, &command, keyspace).await?;
        return bench_rand_keyspace_command(
            client,
            requests,
            clients,
            pipeline,
            keyspace,
            min_seconds,
            command,
        )
        .await;
    }

    let mut prepared = PreparedPipeline::with_capacity(1);
    prepared.push_argv(command.iter().map(Vec::as_slice))?;

    if min_seconds > 0.0 && !prepared.is_read_only() {
        let reseed_each_trial = command
            .first()
            .and_then(|name| std::str::from_utf8(name).ok())
            .is_some_and(reseed_each_trial);
        return bench_prepared_pipeline_trials(
            client,
            TrialConfig {
                requests,
                clients,
                pipeline,
                min_seconds,
            },
            &command,
            prepared,
            reseed_each_trial,
        )
        .await;
    }

    seed_owned_command(&client, &command, requests).await?;
    bench_prepared_pipeline(client, requests, clients, pipeline, min_seconds, prepared).await
}

async fn validate_command(
    client: EmbeddedClient,
    command: Vec<String>,
    postcheck: Option<Vec<String>>,
) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    let command = command
        .into_iter()
        .map(|arg| arg.into_bytes())
        .collect::<Vec<_>>();
    seed_owned_command(
        &client,
        &command,
        read_usize("BENCH_VALIDATE_REQUESTS", 1).max(1),
    )
    .await?;
    let mut output = Vec::new();
    output.push(execute_one_prepared(&client, &command).await?);

    if let Some(postcheck) = postcheck {
        let postcheck = postcheck
            .into_iter()
            .map(|arg| arg.into_bytes())
            .collect::<Vec<_>>();
        output.push(execute_one_prepared(&client, &postcheck).await?);
    }

    Ok(serde_json::Value::Array(output))
}

async fn execute_one_prepared(
    client: &EmbeddedClient,
    command: &[Vec<u8>],
) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    let mut prepared = PreparedPipeline::with_capacity(1);
    prepared.push_argv(command.iter().map(Vec::as_slice))?;
    let mut values = client.execute_prepared_pipeline(&prepared).await?;
    if values.len() != 1 {
        return Err(format!("expected one embedded reply, got {}", values.len()).into());
    }
    Ok(embedded_value_to_json(values.remove(0)))
}

fn embedded_value_to_json(value: EmbeddedValue) -> serde_json::Value {
    match value {
        EmbeddedValue::Nil => serde_json::Value::Null,
        EmbeddedValue::Int(n) => serde_json::json!(n),
        EmbeddedValue::Simple(value) => serde_json::json!(value),
        EmbeddedValue::Bulk(bytes) => {
            serde_json::json!(String::from_utf8_lossy(&bytes).into_owned())
        }
        EmbeddedValue::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(embedded_value_to_json).collect())
        }
        EmbeddedValue::Map(entries) => serde_json::Value::Array(
            entries
                .into_iter()
                .map(|(key, value)| {
                    serde_json::Value::Array(vec![
                        embedded_value_to_json(key),
                        embedded_value_to_json(value),
                    ])
                })
                .collect(),
        ),
        EmbeddedValue::Error(message) => serde_json::json!({ "error": message }),
    }
}

fn command_has_rand_int(command: &[Vec<u8>]) -> bool {
    command.iter().any(|arg| {
        arg.windows(b"__rand_int__".len())
            .any(|w| w == b"__rand_int__")
    })
}

fn replace_rand_int(arg: &[u8], value: usize) -> Vec<u8> {
    let token = b"__rand_int__";
    let replacement = format!("{value:012}");
    if !arg.windows(token.len()).any(|w| w == token) {
        return arg.to_vec();
    }

    let mut out = Vec::with_capacity(arg.len() + replacement.len());
    let mut i = 0;
    while i < arg.len() {
        if i + token.len() <= arg.len() && &arg[i..i + token.len()] == token {
            out.extend_from_slice(replacement.as_bytes());
            i += token.len();
        } else {
            out.push(arg[i]);
            i += 1;
        }
    }
    out
}

fn command_for_keyspace_index(command: &[Vec<u8>], index: usize) -> Vec<Vec<u8>> {
    command
        .iter()
        .map(|arg| replace_rand_int(arg, index))
        .collect()
}

async fn seed_rand_keyspace(
    client: &EmbeddedClient,
    command: &[Vec<u8>],
    keyspace: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for index in 0..keyspace {
        let seeded = command_for_keyspace_index(command, index);
        seed_owned_command(client, &seeded, 1).await?;
    }
    Ok(())
}

async fn seed_owned_command(
    client: &EmbeddedClient,
    command: &[Vec<u8>],
    requests: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Some(name) = command
        .first()
        .and_then(|name| std::str::from_utf8(name).ok())
    else {
        return Ok(());
    };
    match name.to_ascii_uppercase().as_str() {
        "DBSIZE" => {
            seed_string(client, b"__lux_bench_key").await?;
        }
        "MGET" | "EXISTS" => {
            for key in &command[1..] {
                seed_string(client, key).await?;
            }
        }
        "GET" | "GETSET" | "SETNX" | "APPEND" | "STRLEN" | "EXPIRE" | "TYPE"
            if command.len() >= 2 =>
        {
            seed_string(client, &command[1]).await?;
        }
        "TTL" | "PTTL" | "PERSIST" if command.len() >= 2 => {
            seed_expiring_string(client, &command[1]).await?;
        }
        "LLEN" | "LINDEX" | "LRANGE" if command.len() >= 2 => {
            seed_list(client, &command[1], seed_items()).await?;
        }
        "LPOP" | "RPOP" if command.len() >= 2 => seed_list(client, &command[1], requests).await?,
        "HGET" | "HMGET" | "HEXISTS" | "HLEN" | "HINCRBY" if command.len() >= 2 => {
            seed_hash(client, &command[1], 4).await?;
        }
        "HGETALL" if command.len() >= 2 => {
            seed_hash(client, &command[1], seed_items()).await?;
        }
        "SISMEMBER" | "SCARD" | "SMEMBERS" | "SRANDMEMBER" if command.len() >= 2 => {
            seed_set(client, &command[1], seed_items()).await?;
        }
        "SUNION" | "SINTER" | "SDIFF" => {
            for key in &command[1..] {
                seed_set(client, key, seed_items()).await?;
            }
        }
        "SPOP" if command.len() >= 2 => seed_set(client, &command[1], requests).await?,
        "ZSCORE" | "ZCARD" | "ZCOUNT" | "ZRANGE" | "ZINCRBY" if command.len() >= 2 => {
            seed_zset(client, &command[1], seed_items()).await?;
        }
        "ZPOPMIN" | "ZPOPMAX" if command.len() >= 2 => {
            seed_zset(client, &command[1], requests).await?
        }
        "XLEN" | "XRANGE" if command.len() >= 2 => {
            seed_stream(client, &command[1], seed_items()).await?;
        }
        _ => {}
    }
    Ok(())
}

async fn seed_string(
    client: &EmbeddedClient,
    key: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    client.set(key, b"__lux_bench_value").await?;
    Ok(())
}

async fn seed_expiring_string(
    client: &EmbeddedClient,
    key: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    client.set(key, b"__lux_bench_value").await?;
    let args = [b"EXPIRE".as_slice(), key, b"3600".as_slice()];
    client.execute_bytes_value(&args).await?;
    Ok(())
}

async fn seed_list(
    client: &EmbeddedClient,
    key: &[u8],
    count: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let value = b"__lux_bench_value".as_slice();
    for chunk in chunks(count, 1024) {
        let mut batch = EmbeddedPipeline::with_capacity(chunk);
        for _ in 0..chunk {
            batch.rpush(key, vec![value]);
        }
        client.execute_embedded_pipeline_discard(&batch).await?;
    }
    Ok(())
}

async fn seed_hash(
    client: &EmbeddedClient,
    key: &[u8],
    count: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut batch = EmbeddedPipeline::with_capacity(count);
    let mut fields = Vec::with_capacity(count);
    let mut values = Vec::with_capacity(count);
    for i in 0..count {
        fields.push(format!("field:{i}").into_bytes());
        values.push(format!("value:{i}").into_bytes());
    }
    for (field, value) in fields.iter().zip(values.iter()) {
        batch.hset(key, field.as_slice(), value.as_slice());
    }
    client.execute_embedded_pipeline_discard(&batch).await?;
    let args = [
        b"HSET".as_slice(),
        key,
        b"counter".as_slice(),
        b"0".as_slice(),
    ];
    client.execute_bytes_value(&args).await?;
    Ok(())
}

async fn seed_set(
    client: &EmbeddedClient,
    key: &[u8],
    count: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for (start, chunk) in indexed_chunks(count, 1024) {
        let members = (start..start + chunk)
            .map(|i| format!("member:{i}").into_bytes())
            .collect::<Vec<_>>();
        let mut batch = EmbeddedPipeline::with_capacity(chunk);
        for member in &members {
            batch.sadd(key, vec![member.as_slice()]);
        }
        client.execute_embedded_pipeline_discard(&batch).await?;
    }
    Ok(())
}

async fn seed_stream(
    client: &EmbeddedClient,
    key: &[u8],
    count: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for i in 0..count {
        let id = format!("{}-0", i + 1);
        let value = format!("value:{i}");
        let args = [
            b"XADD".as_slice(),
            key,
            id.as_bytes(),
            b"field".as_slice(),
            value.as_bytes(),
        ];
        client.execute_bytes_value(&args).await?;
    }
    Ok(())
}

async fn seed_zset(
    client: &EmbeddedClient,
    key: &[u8],
    count: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for (start, chunk) in indexed_chunks(count, 1024) {
        let members = (start..start + chunk)
            .map(|i| format!("member:{i}").into_bytes())
            .collect::<Vec<_>>();
        let mut batch = EmbeddedPipeline::with_capacity(chunk);
        for (offset, member) in members.iter().enumerate() {
            batch.zadd(key, (start + offset) as f64, member.as_slice());
        }
        client.execute_embedded_pipeline_discard(&batch).await?;
    }
    Ok(())
}

fn seed_items() -> usize {
    read_usize("BENCH_SEED_ITEMS", 128).max(1)
}

fn chunks(total: usize, chunk_size: usize) -> impl Iterator<Item = usize> {
    (0..total)
        .step_by(chunk_size)
        .map(move |start| (total - start).min(chunk_size))
}

fn indexed_chunks(total: usize, chunk_size: usize) -> impl Iterator<Item = (usize, usize)> {
    (0..total)
        .step_by(chunk_size)
        .map(move |start| (start, (total - start).min(chunk_size)))
}

async fn bench_prepared_pipeline(
    client: EmbeddedClient,
    requests: usize,
    clients: usize,
    pipeline: usize,
    min_seconds: f64,
    plan: PreparedPipeline,
) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    if min_seconds > 0.0 && plan.is_read_only() {
        return bench_prepared_pipeline_for_duration(client, clients, pipeline, min_seconds, plan)
            .await;
    }

    let started = Instant::now();
    run_prepared_pipeline_trial(client, requests, clients, pipeline, plan).await?;
    rps(requests, started)
}

async fn bench_prepared_pipeline_trials(
    client: EmbeddedClient,
    config: TrialConfig,
    command: &[Vec<u8>],
    plan: PreparedPipeline,
    reseed_each_trial: bool,
) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    let target = Duration::from_secs_f64(config.min_seconds);
    let mut total_requests = 0usize;
    let mut total_elapsed = Duration::ZERO;

    if !reseed_each_trial {
        seed_owned_command(&client, command, config.requests).await?;
    }
    while total_elapsed < target {
        if reseed_each_trial {
            seed_owned_command(&client, command, config.requests).await?;
        }
        let started = Instant::now();
        run_prepared_pipeline_trial(
            client.clone(),
            config.requests,
            config.clients,
            config.pipeline,
            plan.clone(),
        )
        .await?;
        total_elapsed += started.elapsed();
        total_requests += config.requests;
    }

    rps_for_elapsed(total_requests, total_elapsed)
}

fn reseed_each_trial(command: &str) -> bool {
    matches!(
        command.to_ascii_uppercase().as_str(),
        "LPOP" | "RPOP" | "SPOP" | "ZPOPMIN" | "ZPOPMAX" | "APPEND" | "PERSIST"
    )
}

async fn run_prepared_pipeline_trial(
    client: EmbeddedClient,
    requests: usize,
    clients: usize,
    pipeline: usize,
    plan: PreparedPipeline,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let discard_writes = env::var("EMBEDDED_DISCARD_WRITES")
        .map(|value| value != "0")
        .unwrap_or(false)
        && plan.is_write_only();
    let mut tasks: Vec<JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>> =
        Vec::new();
    let plan = Arc::new(plan);

    for worker in 0..clients {
        let client = client.clone();
        let plan = plan.clone();
        let count = requests / clients + usize::from(worker < requests % clients);
        tasks.push(tokio::spawn(async move {
            let full_batches = count / pipeline;
            let remainder = count % pipeline;
            let mut batch = PreparedPipeline::with_capacity(plan.len() * pipeline);
            for _ in 0..pipeline {
                batch.extend(&plan);
            }

            for _ in 0..full_batches {
                if discard_writes {
                    client.execute_prepared_pipeline_discard(&batch).await?;
                } else {
                    client.execute_prepared_pipeline(&batch).await?;
                }
            }
            if remainder > 0 {
                let mut partial = PreparedPipeline::with_capacity(plan.len() * remainder);
                for _ in 0..remainder {
                    partial.extend(&plan);
                }
                if discard_writes {
                    client.execute_prepared_pipeline_discard(&partial).await?;
                } else {
                    client.execute_prepared_pipeline(&partial).await?;
                }
            }
            Ok(())
        }));
    }

    for task in tasks {
        task.await??;
    }

    Ok(())
}

async fn bench_rand_keyspace_command(
    client: EmbeddedClient,
    requests: usize,
    clients: usize,
    pipeline: usize,
    keyspace: usize,
    min_seconds: f64,
    command: Vec<Vec<u8>>,
) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    if min_seconds > 0.0 {
        let started = Instant::now();
        let deadline = started + Duration::from_secs_f64(min_seconds);
        let operations = run_rand_keyspace_until_deadline(
            client,
            clients,
            pipeline,
            keyspace,
            Arc::new(command),
            deadline,
        )
        .await?;
        return rps(operations, started);
    }

    let started = Instant::now();
    run_rand_keyspace_trial(
        client,
        requests,
        clients,
        pipeline,
        keyspace,
        Arc::new(command),
    )
    .await?;
    rps(requests, started)
}

async fn run_rand_keyspace_trial(
    client: EmbeddedClient,
    requests: usize,
    clients: usize,
    pipeline: usize,
    keyspace: usize,
    command: Arc<Vec<Vec<u8>>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut tasks: Vec<JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>> =
        Vec::new();

    for worker in 0..clients {
        let client = client.clone();
        let command = command.clone();
        let count = requests / clients + usize::from(worker < requests % clients);
        tasks.push(tokio::spawn(async move {
            let mut completed = 0usize;
            while completed < count {
                let batch_len = pipeline.min(count - completed);
                let mut batch = PreparedPipeline::with_capacity(batch_len);
                for offset in 0..batch_len {
                    let index = (worker + completed + offset) % keyspace;
                    let argv = command_for_keyspace_index(&command, index);
                    batch.push_argv(argv.iter().map(Vec::as_slice))?;
                }
                client.execute_prepared_pipeline(&batch).await?;
                completed += batch_len;
            }
            Ok(())
        }));
    }

    for task in tasks {
        task.await??;
    }
    Ok(())
}

async fn run_rand_keyspace_until_deadline(
    client: EmbeddedClient,
    clients: usize,
    pipeline: usize,
    keyspace: usize,
    command: Arc<Vec<Vec<u8>>>,
    deadline: Instant,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let mut tasks: Vec<JoinHandle<Result<usize, Box<dyn std::error::Error + Send + Sync>>>> =
        Vec::new();

    for worker in 0..clients {
        let client = client.clone();
        let command = command.clone();
        tasks.push(tokio::spawn(async move {
            let mut operations = 0usize;
            while Instant::now() < deadline {
                let mut batch = PreparedPipeline::with_capacity(pipeline);
                for offset in 0..pipeline {
                    let index = (worker + operations + offset) % keyspace;
                    let argv = command_for_keyspace_index(&command, index);
                    batch.push_argv(argv.iter().map(Vec::as_slice))?;
                }
                client.execute_prepared_pipeline(&batch).await?;
                operations += pipeline;
            }
            Ok(operations)
        }));
    }

    let mut operations = 0usize;
    for task in tasks {
        operations += task.await??;
    }
    Ok(operations)
}

async fn bench_prepared_pipeline_for_duration(
    client: EmbeddedClient,
    clients: usize,
    pipeline: usize,
    min_seconds: f64,
    plan: PreparedPipeline,
) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    let started = Instant::now();
    let deadline = started + Duration::from_secs_f64(min_seconds);
    let mut tasks: Vec<JoinHandle<Result<usize, Box<dyn std::error::Error + Send + Sync>>>> =
        Vec::new();
    let plan = Arc::new(plan);

    for _ in 0..clients {
        let client = client.clone();
        let plan = plan.clone();
        tasks.push(tokio::spawn(async move {
            let mut operations = 0usize;
            let mut batch = PreparedPipeline::with_capacity(plan.len() * pipeline);
            for _ in 0..pipeline {
                batch.extend(&plan);
            }

            while Instant::now() < deadline {
                client.execute_prepared_pipeline(&batch).await?;
                operations += pipeline;
            }
            Ok(operations)
        }));
    }

    let mut operations = 0usize;
    for task in tasks {
        operations += task.await??;
    }

    rps(operations, started)
}

fn rps(requests: usize, started: Instant) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    rps_for_elapsed(requests, started.elapsed())
}

fn rps_for_elapsed(
    requests: usize,
    elapsed: Duration,
) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    let elapsed = elapsed.as_secs_f64();
    if elapsed == 0.0 {
        return Ok(0.0);
    }
    Ok(requests as f64 / elapsed)
}

async fn seed_geo(
    client: &EmbeddedClient,
    key: &str,
    members: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut i = 0;
    while i < members {
        let batch_end = (i + 50).min(members);
        let mut names = Vec::with_capacity(batch_end - i);
        let mut coords = Vec::with_capacity(batch_end - i);

        for j in i..batch_end {
            let lon = -180.0 + j as f64 * (360.0 / members as f64);
            let mut lat = -80.0 + j as f64 * (170.0 / members as f64);
            lat = lat.clamp(-85.0, 85.0);
            names.push(format!("place:{j}"));
            coords.push((lon, lat));
        }
        let geo_members = names
            .iter()
            .zip(coords.iter())
            .map(|(name, (lon, lat))| lux::GeoMember {
                longitude: *lon,
                latitude: *lat,
                member: name.as_str(),
            })
            .collect::<Vec<_>>();

        client.geoadd(key, &geo_members).await?;
        i = batch_end;
    }
    Ok(())
}
