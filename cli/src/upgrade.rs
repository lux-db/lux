use super::*;

const ACTIVE: &str = "lux/.backups/engine-upgrade.json";

pub(super) fn lock_and_recover() -> Result<std::fs::File, String> {
    ensure_private_dir(Path::new("lux/.backups"))?;
    let path = Path::new("lux/.backups/engine.lock");
    read_optional_secret_file(path)?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: file owns a valid descriptor for the lifetime of this lock.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("another local engine operation is still running".into());
        }
        // A pending Docker command must keep the operation exclusive if the
        // CLI exits before that command completes. This descriptor holds only
        // an empty lock file, never credentials.
        // SAFETY: fcntl operates on the valid descriptor owned above.
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
        if flags < 0
            || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, flags & !libc::FD_CLOEXEC) }
                < 0
        {
            return Err("could not preserve the local operation lock for Docker".into());
        }
    }
    recover()?;
    Ok(file)
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Preparing,
    // After this point the candidate may accept application writes. Never roll back automatically.
    Cutover,
}

#[derive(Serialize, Deserialize)]
struct Upgrade {
    phase: Phase,
    source: LocalState,
    target: LocalState,
    source_id: String,
    backup_container: String,
    probe_container: String,
    network: String,
    restart_policy: String,
    was_running: bool,
    engine_env: Vec<String>,
}

fn persist(upgrade: &Upgrade) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(upgrade).map_err(|e| e.to_string())?;
    write_secret_file(Path::new(ACTIVE), &bytes)
}

fn archive(upgrade: &Upgrade) -> Result<(), String> {
    let path = format!("lux/.backups/{}.json", upgrade.backup_container);
    write_secret_file(
        Path::new(&path),
        &serde_json::to_vec_pretty(upgrade).map_err(|e| e.to_string())?,
    )?;
    delete_secret_file(Path::new(ACTIVE))
}

fn helper(image: &str, network: &str, args: &[&str], env: &[String]) -> Result<String, String> {
    let mut command = vec![
        "run",
        "--rm",
        "--network",
        network,
        "--read-only",
        "--cap-drop",
        "ALL",
    ];
    for value in env {
        command.extend(["-e", value]);
    }
    command.extend(["--entrypoint", "/lux-maintenance", image]);
    command.extend(args);
    docker_output(&command)
}

fn stop(name: &str) -> Result<(), String> {
    if docker_container_state(name).as_deref() == Some("running") {
        docker_output(&["stop", "--timeout", "300", name])?;
    }
    Ok(())
}

fn connected(name: &str, network: &str) -> Result<bool, String> {
    let raw = docker_output(&["inspect", "-f", "{{json .NetworkSettings.Networks}}", name])?;
    let networks: serde_json::Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    Ok(networks.get(network).is_some())
}

fn wait_ready(state: &LocalState) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    while std::time::Instant::now() < deadline {
        if let Ok(mut connection) =
            DirectConn::connect(&state.connection_host(), state.resp_port, &state.password)
        {
            if connection
                .exec("PING")
                .is_ok_and(|value| value.trim() == "PONG")
            {
                return true;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    false
}

fn verify_target_container(name: &str, target: &LocalState) -> Result<(), String> {
    let raw = docker_output(&["inspect", name])?;
    let containers: Vec<serde_json::Value> =
        serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    let container = containers.first().ok_or("container inspection was empty")?;
    let matches = container["Image"] == target.image
        && container["Mounts"].as_array().is_some_and(|mounts| {
            mounts.len() == 1
                && mounts[0]["Type"] == "volume"
                && mounts[0]["Destination"] == "/data"
                && mounts[0]["Name"] == target.volume
        });
    if !matches {
        return Err(format!(
            "container {name} does not match the pending upgrade image and volume; left untouched"
        ));
    }
    Ok(())
}

fn restore_source(upgrade: &Upgrade) -> Result<(), String> {
    if docker_container_state(&upgrade.probe_container).is_some() {
        verify_target_container(&upgrade.probe_container, &upgrade.target)?;
        stop(&upgrade.probe_container)?;
        docker_output(&["rm", &upgrade.probe_container])?;
    }
    let name = docker_output(&["inspect", "-f", "{{.Name}}", &upgrade.source_id])?;
    if name.trim_start_matches('/') != upgrade.source.container {
        docker_output(&["rename", &upgrade.source_id, &upgrade.source.container])?;
    }
    if !upgrade.was_running {
        // Keep a previously stopped stack offline while restoring its original
        // network configuration for the next start or update.
        if docker_container_state(&upgrade.source_id).as_deref() == Some("running") {
            // This boot was isolated before it started, so it could not accept
            // application writes. Preserve its original files even when SAVE
            // was the operation that failed; do not require SAVE to recover.
            docker_output(&["kill", "--signal", "KILL", &upgrade.source_id])?;
        }
        if !connected(&upgrade.source_id, &upgrade.network)? {
            docker_output(&["network", "connect", &upgrade.network, &upgrade.source_id])?;
        }
        docker_output(&[
            "update",
            "--restart",
            &upgrade.restart_policy,
            &upgrade.source_id,
        ])?;
        save_local_state(&upgrade.source);
        return Ok(());
    }
    if !connected(&upgrade.source_id, &upgrade.network)? {
        docker_output(&["network", "connect", &upgrade.network, &upgrade.source_id])?;
    }
    // Reattach before starting so Docker reinstalls the published port mappings.
    if docker_container_state(&upgrade.source_id).as_deref() != Some("running") {
        docker_output(&["start", &upgrade.source_id])?;
    }
    if !wait_ready(&upgrade.source) {
        return Err("original engine did not become ready during recovery".into());
    }
    docker_output(&[
        "update",
        "--restart",
        &upgrade.restart_policy,
        &upgrade.source_id,
    ])?;
    save_local_state(&upgrade.source);
    Ok(())
}

fn finish_cutover(upgrade: &Upgrade) -> Result<(), String> {
    // Docker otherwise silently creates an empty volume when a named mount
    // disappears between preparation and recovery.
    docker_output(&["volume", "inspect", &upgrade.target.volume]).map_err(|_| {
        format!(
            "verified data volume {} is missing; upgrade cannot resume",
            upgrade.target.volume
        )
    })?;
    // Save the target before publishing any port. An interrupted CLI must resume this
    // volume, not silently return to a backup missing newly acknowledged writes.
    save_local_state(&upgrade.target);
    if docker_container_state(&upgrade.target.container).is_none() {
        create_engine_container(&upgrade.target, &upgrade.engine_env, upgrade.was_running)?;
    } else {
        verify_target_container(&upgrade.target.container, &upgrade.target)?;
        if upgrade.was_running
            && docker_container_state(&upgrade.target.container).as_deref() != Some("running")
        {
            docker_output(&["start", &upgrade.target.container])?;
        }
    }
    if upgrade.was_running && !wait_ready(&upgrade.target) {
        return Err(format!(
            "candidate did not become ready after cutover; its data volume {} is retained. Retry `lux start`. The old backup will not overwrite possible new writes",
            upgrade.target.volume
        ));
    }
    if docker_container_state(&upgrade.probe_container).is_some() {
        verify_target_container(&upgrade.probe_container, &upgrade.target)?;
        docker_output(&["rm", &upgrade.probe_container])?;
    }
    refresh_local_profile(&upgrade.target)?;
    archive(upgrade)
}

pub(super) fn recover() -> Result<(), String> {
    let Some(bytes) = read_optional_secret_file(Path::new(ACTIVE))? else {
        return Ok(());
    };
    let upgrade: Upgrade = serde_json::from_str(&bytes)
        .map_err(|e| format!("cannot read pending engine upgrade: {e}"))?;
    println!("Recovering interrupted local engine upgrade...");
    match upgrade.phase {
        Phase::Preparing => {
            restore_source(&upgrade)?;
            archive(&upgrade)?;
            println!("Original engine restored. Retry `lux update engine` to upgrade.");
            Ok(())
        }
        Phase::Cutover => finish_cutover(&upgrade),
    }
}

pub(super) fn perform(
    state: &LocalState,
    image_id: &str,
    engine_env: Vec<String>,
) -> Result<LocalState, String> {
    let mut source = load_local_state().ok_or("run `lux start` first")?;
    let source_id = docker_output(&["inspect", "-f", "{{.Id}}", &source.container])?;
    source.image = docker_output(&["inspect", "-f", "{{.Image}}", &source_id])?;
    let mounts = docker_output(&["inspect", "-f", "{{json .Mounts}}", &source_id])?;
    let mounts: Vec<serde_json::Value> =
        serde_json::from_str(&mounts).map_err(|e| e.to_string())?;
    if mounts.len() != 1
        || !mounts.iter().any(|m| {
            m["Type"] == "volume" && m["Destination"] == "/data" && m["Name"] == source.volume
        })
    {
        return Err(
            "local engine mounts do not match its recorded data volume; nothing changed".into(),
        );
    }
    let policy = docker_output(&[
        "inspect",
        "-f",
        "{{json .HostConfig.RestartPolicy}}",
        &source_id,
    ])?;
    let policy: serde_json::Value = serde_json::from_str(&policy).map_err(|e| e.to_string())?;
    let mut restart_policy = policy["Name"].as_str().unwrap_or("no").to_string();
    if restart_policy == "on-failure" {
        let retries = policy["MaximumRetryCount"].as_u64().unwrap_or(0);
        if retries != 0 {
            restart_policy = format!("on-failure:{retries}");
        }
    }
    let source_status =
        docker_container_state(&source_id).ok_or("old engine container is missing")?;
    if !matches!(source_status.as_str(), "running" | "exited" | "created") {
        return Err("engine must be running or stopped before updating".into());
    }
    let networks = docker_output(&[
        "inspect",
        "-f",
        "{{json .NetworkSettings.Networks}}",
        &source_id,
    ])?;
    let networks: HashMap<String, serde_json::Value> =
        serde_json::from_str(&networks).map_err(|e| e.to_string())?;
    if networks.len() != 1 || !networks.contains_key("bridge") {
        return Err("automatic local upgrades require the CLI-managed bridge network; old engine left unchanged".into());
    }
    let maintenance_version = helper(image_id, "none", &["version"], &[]).map_err(|error| {
        format!(
            "target image does not support automatic snapshot upgrades ({error}); current engine and data left unchanged"
        )
    })?;
    if maintenance_version.trim() != "1" {
        return Err(
            "target image does not support automatic snapshot upgrades; current engine and data left unchanged"
                .into(),
        );
    }
    let suffix = random_hex(8);
    let mut target = state.clone();
    target.volume = format!("{}-data-{suffix}", source.container);
    // Runtime identity, not a user-configured version pin. Other project pulls
    // must not replace this engine during a later configuration-only restart.
    target.image = image_id.to_string();
    let mut upgrade = Upgrade {
        phase: Phase::Preparing,
        backup_container: format!("{}-backup-{suffix}", source.container),
        probe_container: format!("{}-verify-{suffix}", source.container),
        source_id,
        was_running: source_status == "running",
        network: "bridge".into(),
        restart_policy,
        source,
        target,
        engine_env,
    };
    persist(&upgrade)?;
    let prepared = (|| -> Result<(), String> {
        // Retained backups must never start themselves on a daemon restart.
        docker_output(&["update", "--restart", "no", &upgrade.source_id])?;
        println!("Temporarily disconnecting application access...");
        docker_output(&[
            "network",
            "disconnect",
            "--force",
            &upgrade.network,
            &upgrade.source_id,
        ])?;
        if !upgrade.was_running {
            docker_output(&["start", &upgrade.source_id])?;
        }
        println!("Saving the final snapshot with the current engine...");
        helper(
            image_id,
            &format!("container:{}", upgrade.source_id),
            &["snapshot"],
            &[
                format!("LUX_PASSWORD={}", upgrade.source.password),
                "LUX_PORT=6379".into(),
            ],
        )?;
        // Application networking is detached and SAVE has completed. The old
        // release does not handle SIGTERM as PID 1; its snapshot, not shutdown,
        // is the persistence boundary for this handoff.
        docker_output(&["kill", "--signal", "KILL", &upgrade.source_id])?;
        docker_output(&["rename", &upgrade.source_id, &upgrade.backup_container])?;
        docker_output(&["volume", "create", &upgrade.target.volume])?;
        println!("Importing the snapshot into a separate data volume...");
        let snapshot_size = docker_output(&[
            "run",
            "--rm",
            "--network",
            "none",
            "--user",
            "0:0",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "CHOWN",
            "--cap-add",
            "DAC_OVERRIDE",
            "-v",
            &format!("{}:/source:ro", upgrade.source.volume),
            "-v",
            &format!("{}:/data", upgrade.target.volume),
            "--entrypoint",
            "/lux-maintenance",
            image_id,
            "copy-snapshot",
        ])?
        .parse::<u64>()
        .map_err(|_| "invalid copied snapshot size")?;
        if snapshot_size == 0 {
            return Err("source snapshot is empty".into());
        }
        println!("Verifying the candidate with application access still closed...");
        let volume = format!("{}:/data", upgrade.target.volume);
        let mut args = vec![
            "run",
            "-d",
            "--name",
            &upgrade.probe_container,
            "--network",
            "none",
            "-v",
            &volume,
        ];
        for entry in &upgrade.engine_env {
            args.extend(["-e", entry]);
        }
        // This listener has no application network access. Its import limit
        // accommodates the known snapshot without changing the public config.
        let body_limit = format!("LUX_MAX_BODY_SIZE={}", snapshot_size.max(1024 * 1024));
        args.extend(["-e", &body_limit, "-e", "LUX_HTTP_BODY_TIMEOUT_MS=300000"]);
        args.push(image_id);
        docker_output(&args)?;
        wait_probe_ready(&upgrade.probe_container)?;
        stage_import(&upgrade.probe_container, snapshot_size, false)?;
        stop_probe_cleanly(&upgrade.probe_container)?;
        docker_output(&["start", &upgrade.probe_container])?;
        wait_probe_ready(&upgrade.probe_container)?;
        // Verification can run background jobs against the isolated copy.
        // Stage the original snapshot again so those trial delivery attempts
        // or other verification-time writes never become application state.
        stage_import(&upgrade.probe_container, snapshot_size, true)?;
        stop_probe_cleanly(&upgrade.probe_container)?;
        // Keep the stopped probe attached until the public container exists.
        Ok(())
    })();
    if let Err(error) = prepared {
        restore_source(&upgrade).map_err(|rollback| {
            format!("{error}; recovery incomplete: {rollback}. Retry `lux start`")
        })?;
        archive(&upgrade)?;
        return Err(format!(
            "{error}; original engine restored. Upgrade details retained under lux/.backups"
        ));
    }
    upgrade.phase = Phase::Cutover;
    persist(&upgrade)?;
    println!("Candidate verified. Switching the local engine...");
    finish_cutover(&upgrade)?;
    println!(
        "Old engine retained as {} on volume {}.",
        upgrade.backup_container, upgrade.source.volume
    );
    Ok(upgrade.target)
}

fn stage_import(probe: &str, snapshot_size: u64, final_import: bool) -> Result<(), String> {
    let mut args = vec!["exec", probe, "/lux-maintenance", "restore-snapshot"];
    if final_import {
        args.push("final");
    }
    let confirmation = docker_output(&args)?;
    let confirmation: serde_json::Value = serde_json::from_str(&confirmation)
        .map_err(|_| "candidate returned an invalid restore confirmation")?;
    if confirmation["staged"] != true
        || confirmation["restart_required"] != true
        || confirmation["source_bytes"].as_u64() != Some(snapshot_size)
    {
        return Err("candidate did not confirm the complete snapshot import".into());
    }
    Ok(())
}

fn wait_probe_ready(probe: &str) -> Result<(), String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    loop {
        if docker_output(&["exec", probe, "/lux-healthcheck", "ready"]).is_ok() {
            break;
        }
        if docker_container_state(probe).as_deref() != Some("running")
            || std::time::Instant::now() >= deadline
        {
            return Err("candidate failed isolated startup verification".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    Ok(())
}

fn stop_probe_cleanly(probe: &str) -> Result<(), String> {
    stop(probe)?;
    if docker_output(&["inspect", "-f", "{{.State.ExitCode}}", probe])? != "0" {
        return Err("candidate did not finish a clean persistence shutdown".into());
    }
    Ok(())
}
