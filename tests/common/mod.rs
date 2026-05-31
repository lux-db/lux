pub fn lux_command<P: AsRef<std::ffi::OsStr>>(program: P) -> std::process::Command {
    std::process::Command::new(program)
}

pub fn terminate_child(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("kill")
            .arg("-TERM")
            .arg(child.id().to_string())
            .status();

        for _ in 0..50 {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(20)),
                Err(_) => return,
            }
        }
    }

    child.kill().ok();
    child.wait().ok();
}
