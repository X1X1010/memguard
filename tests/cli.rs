use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_memguard"))
}

#[test]
fn version_and_help() {
    let out = bin().arg("version").output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains(env!("CARGO_PKG_VERSION")));
    let out = bin().output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("USAGE"));
    let out = bin().arg("bogus").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn check_config_default_and_overrides() {
    let out = bin()
        .args([
            "check-config",
            "--quiet",
            "--config",
            "/nonexistent/memguard.conf",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "explicit missing config must fail");
    let dir = std::env::temp_dir().join(format!("memguard-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("t.conf");
    std::fs::write(&cfg, "floor = 6G\nwarn = 12G\nkill_mode = tree\n").unwrap();
    let out = bin()
        .args(["check-config", "--quiet", "--config", cfg.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("floor") && text.contains("6.0G"));
    let out = bin()
        .args([
            "check-config",
            "--quiet",
            "--config",
            cfg.to_str().unwrap(),
            "-o",
            "floor=20G",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "floor >= warn must be rejected");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn status_and_ps_run() {
    let out = bin()
        .args(["status", "--json", "--top", "3"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.trim_start().starts_with('{') && text.contains("\"total\":"));
    let out = bin().args(["status"]).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("memguard status"));
    let out = bin()
        .args(["ps", "-n", "3", "--sort", "rss"])
        .output()
        .unwrap();
    assert!(out.status.success());
}

#[test]
fn replay_synthetic_burst() {
    let dir = std::env::temp_dir().join(format!("memguard-replay-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let trace = dir.join("burst.csv");
    let gib: u64 = 1 << 30;
    let total = 120 * gib;
    let mut s = String::from("t_ns,total,free,avail,free2m,swap_total,swap_free,psi_some_us,psi_full_us,level,may_kill,gate\n");
    let mut avail = 110 * gib;
    for i in 0..200u64 {
        if i >= 20 {
            avail = avail.saturating_sub((34.0 * gib as f64 * 0.05) as u64);
        }
        s.push_str(&format!(
            "{},{},{},{},{},{},{},0,0,OK,0,x\n",
            1_000_000_000 + i * 50_000_000,
            total,
            avail,
            avail,
            avail,
            16 * gib,
            16 * gib
        ));
    }
    std::fs::write(&trace, s).unwrap();
    let out = bin()
        .args([
            "replay",
            trace.to_str().unwrap(),
            "--config",
            "/nonexistent-but-ignored",
            "-o",
            "floor=8G",
            "-o",
            "warn=16G",
        ])
        .output()
        .unwrap();
    // explicit missing config is an error; use defaults instead
    assert!(!out.status.success());
    let out = bin()
        .args([
            "replay",
            trace.to_str().unwrap(),
            "-o",
            "floor=8G",
            "-o",
            "warn=16G",
        ])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("KILL would be issued"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn run_validates_options_before_starting_the_job() {
    for args in [
        vec!["--interval-ms", "oops"],
        vec!["--interval-ms", "0"],
        vec!["--oom-adj", "1001"],
    ] {
        let out = bin()
            .arg("run")
            .args(args)
            .args(["--", "/bin/sh", "-c", "echo STARTED"])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&out.stdout).contains("STARTED"));
    }
}

#[test]
fn replay_rejects_corrupt_or_nonmonotonic_samples() {
    let path = std::env::temp_dir().join(format!(
        "memguard-bad-trace-{}-{}",
        std::process::id(),
        memguard::mono_ns()
    ));
    for content in [
        "",
        "1,2,3\n",
        "1,128849018880,0,bad,0,0,0,0,0\n",
        "2,128849018880,0,0,0,0,0,0,0\n1,128849018880,0,0,0,0,0,0,0\n",
    ] {
        std::fs::write(&path, content).unwrap();
        let out = bin()
            .args(["replay", path.to_str().unwrap(), "--config", "/dev/null"])
            .output()
            .unwrap();
        assert!(!out.status.success(), "{content}");
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn run_exit_code_and_small_memory_budget() {
    let out = bin()
        .args([
            "run",
            "--no-scope",
            "--config",
            "/dev/null",
            "--floor",
            "0",
            "--",
            "/bin/sh",
            "-c",
            "exit 17",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(17));
    let mem = memguard::sys::meminfo::read_meminfo().unwrap();
    if mem.available < 512 << 20 {
        return;
    }
    for dry in [false, true] {
        let mut cmd = bin();
        cmd.args([
            "run",
            "--no-scope",
            "--config",
            "/dev/null",
            "--mem",
            "8M",
            "--floor",
            "0",
        ]);
        if dry {
            cmd.arg("--dry-run");
        }
        let out = cmd
            .arg("--")
            .arg(env!("CARGO_BIN_EXE_memguard-hog"))
            .args([
                "--anon",
                "32M",
                "--max",
                "32M",
                "--min-avail",
                "256M",
                "--step",
                "8M",
                "--hold",
                "0.5",
                "--quiet",
            ])
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(if dry { 0 } else { 137 }),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stderr).contains("memory budget"));
    }
}

#[test]
fn dry_run_does_not_install_kernel_limits() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!(
        "memguard-fake-systemd-{}-{}",
        std::process::id(),
        memguard::mono_ns()
    ));
    std::fs::create_dir(&dir).unwrap();
    let fake = dir.join("systemd-run");
    std::fs::write(
        &fake,
        "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$MEMGUARD_TEST_ARGS\"\nexit 0\n",
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let log = dir.join("args");
    let out = bin()
        .env("PATH", &dir)
        .env("MEMGUARD_TEST_ARGS", &log)
        .args([
            "run",
            "--config",
            "/dev/null",
            "--dry-run",
            "--mem",
            "1M",
            "--swap",
            "0",
            "--",
            "/bin/true",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let args = std::fs::read_to_string(&log).unwrap();
    assert!(
        !args.contains("MemoryMax=")
            && !args.contains("MemorySwapMax=")
            && !args.contains("OOMPolicy="),
        "{args}"
    );
    std::fs::write(&log, "").unwrap();
    let out = bin()
        .env("PATH", &dir)
        .env("MEMGUARD_TEST_ARGS", &log)
        .args([
            "run",
            "--config",
            "/dev/null",
            "--mem",
            "1M",
            "--",
            "/bin/true",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let args = std::fs::read_to_string(&log).unwrap();
    assert!(args.contains("OOMPolicy=kill") && args.contains("MemoryMax=1048576"));
    assert!(!args.contains("MemoryOOMGroup"));
    std::fs::remove_dir_all(dir).unwrap();
}
