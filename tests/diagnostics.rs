use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn malformed_runtime_settings_exit_before_creating_data() {
    for (name, value) in [
        ("LUX_RUNTIME_THREADS", "zero"),
        ("LUX_PORT", "65536"),
        ("LUX_HTTP_PORT", "no"),
        ("LUX_SHARDS", "no"),
        ("LUX_SAVE_INTERVAL", "no"),
        ("LUX_MAXMEMORY", "18446744073709551615gb"),
        ("LUX_MAXMEMORY_POLICY", "noevicton"),
        ("LUX_MAXMEMORY_SAMPLES", "0"),
        ("LUX_RESTRICTED", "yes"),
        ("LUX_ENABLE_RESP", "yes"),
        ("LUX_AUTH_ENABLED", "yes"),
        ("LUX_AUTH_ACCESS_TOKEN_TTL", "0"),
        ("LUX_AUTH_ACCESS_TOKEN_TTL", "18446744073709551615"),
        ("LUX_AUTH_REFRESH_TOKEN_TTL", "18446744073709551615"),
        ("LUX_AUTH_FLOW_TOKEN_TTL_SECONDS", "18446744073709551615"),
        ("LUX_AUTH_REFRESH_TOKEN_TTL", "no"),
        ("LUX_AUTH_FLOW_TOKEN_TTL_SECONDS", "no"),
        ("LUX_ENC_AUTO_INIT", "yes"),
        ("LUX_LOG_LEVEL", "verbose"),
        ("LUX_LOG_FORMAT", "jsn"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_lux"))
            .env_clear()
            .env("LUX_DATA_DIR", directory.path())
            .env("LUX_RUNTIME_THREADS", "2")
            .env("LUX_AUTH_ENABLED", "true")
            .env("LUX_LOG_FORMAT", "json")
            .env(name, value)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{name}: invalid configuration did not exit");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let mut output = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut output)
            .unwrap();
        assert_eq!(status.code(), Some(1), "{name}: {output}");
        assert!(output.contains(name), "{name}: {output}");
        assert_eq!(
            std::fs::read_dir(directory.path()).unwrap().count(),
            0,
            "{name}: startup wrote data before validating configuration"
        );
        if !name.starts_with("LUX_LOG_") {
            for line in output.lines() {
                let _: serde_json::Value =
                    serde_json::from_str(line).expect("structured diagnostic");
            }
        }
    }
}
