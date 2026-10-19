//! `memguard doctor` (environment checks, optional cgroup-charging probe) and
//! `memguard check-config` (validate and show what the protect rules match).

use std::process::{Command, Stdio};

use crate::cli;
use crate::config::{matches_any, Config, DEFAULT_CONFIG_PATH};
use crate::helper;
use crate::sys::meminfo::{read_meminfo, read_vmstat};
use crate::sys::{cgroup, nvml, procfs};
use crate::units::fmt_bytes;

fn ok(msg: &str) {
    println!("  [ ok ] {msg}");
}
fn warn(msg: &str) {
    println!("  [warn] {msg}");
}
fn fail(msg: &str) {
    println!("  [FAIL] {msg}");
}

fn read_trim(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn unit_active(unit: &str) -> bool {
    crate::actuator::unit_active(unit)
}

pub fn doctor_main(args: &[String]) -> i32 {
    let p = match cli::parse(args, &["config"], &[], &["probe"]) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("memguard doctor: {e}");
            return 2;
        }
    };
    let mut failures = 0;
    println!("memguard doctor");

    // kernel & memory
    let release = read_trim("/proc/sys/kernel/osrelease").unwrap_or_default();
    ok(&format!("kernel {release}"));
    match read_meminfo() {
        Ok(m) => {
            ok(&format!(
                "MemTotal {}  MemAvailable {}  swap {}/{}",
                fmt_bytes(m.total),
                fmt_bytes(m.available),
                fmt_bytes(m.swap_used()),
                fmt_bytes(m.swap_total)
            ));
            if m.swap_total > 0 {
                warn(&format!("swap is enabled ({}); swap thrash extends freezes. memguard treats swap growth as a trigger; consider a smaller swap or none for pure compute use", fmt_bytes(m.swap_total)));
            }
        }
        Err(e) => {
            fail(&format!("/proc/meminfo: {e}"));
            failures += 1;
        }
    }
    match read_vmstat() {
        Ok(v) if v.has_free_pages_blocks => ok(&format!(
            "nr_free_pages_blocks present ({} free in 2 MiB blocks)",
            fmt_bytes(v.nr_free_pages_blocks * crate::sys::meminfo::page_size())
        )),
        Ok(_) => warn("nr_free_pages_blocks missing (older kernel); free2m falls back to MemFree"),
        Err(e) => warn(&format!("/proc/vmstat: {e}")),
    }
    match crate::sys::psi::read_system_memory() {
        Ok(ps) => ok(&format!(
            "PSI memory available (some avg10={:.2} full avg10={:.2})",
            ps.some_avg10, ps.full_avg10
        )),
        Err(e) => {
            fail(&format!("PSI unavailable: {e} (CONFIG_PSI / psi=1)"));
            failures += 1;
        }
    }
    for (k, path) in [
        ("vm.min_free_kbytes", "/proc/sys/vm/min_free_kbytes"),
        (
            "vm.watermark_scale_factor",
            "/proc/sys/vm/watermark_scale_factor",
        ),
        ("vm.swappiness", "/proc/sys/vm/swappiness"),
        ("vm.overcommit_memory", "/proc/sys/vm/overcommit_memory"),
    ] {
        if let Some(v) = read_trim(path) {
            ok(&format!("{k} = {v}"));
        }
    }

    // cgroups
    match read_trim("/sys/fs/cgroup/cgroup.controllers") {
        Some(c) if c.split_whitespace().any(|x| x == "memory") => {
            ok(&format!("cgroup v2 unified; controllers: {c}"))
        }
        Some(c) => {
            fail(&format!("cgroup v2 without memory controller: {c}"));
            failures += 1;
        }
        None => {
            fail("cgroup v2 not mounted at /sys/fs/cgroup");
            failures += 1;
        }
    }
    if cgroup::root_reclaim_available() {
        ok("root memory.reclaim available (headroom controller)");
    } else {
        warn("root memory.reclaim missing: headroom reclaim disabled");
    }
    // SAFETY: trivial libc call.
    let euid = unsafe { libc::geteuid() };
    if let Some(me) = cgroup::self_cgroup() {
        let path = cgroup::fs_path(&me);
        let owner = std::fs::metadata(&path)
            .ok()
            .map(|m| std::os::unix::fs::MetadataExt::uid(&m));
        match owner {
            Some(u) if u == euid => ok(&format!("own cgroup {me} is owned by uid {u}: unprivileged `memguard run` budgets work")),
            Some(u) => warn(&format!("own cgroup {me} owned by uid {u} (we are {euid}); `memguard run` uses systemd-run --user, which should still work")),
            None => warn(&format!("cannot stat own cgroup {me}")),
        }
    }
    let have_systemd_run = Command::new("systemd-run")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if have_systemd_run {
        ok("systemd-run present");
    } else {
        warn("systemd-run missing: `memguard run` falls back to process-tree supervision");
    }
    if euid != 0 {
        // SAFETY: trivial libc call.
        let uid = unsafe { libc::getuid() };
        if let Ok(out) = Command::new("loginctl")
            .args(["show-user", &uid.to_string(), "-p", "Linger", "--value"])
            .stderr(Stdio::null())
            .output()
        {
            let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if v == "yes" {
                ok("loginctl Linger=yes");
            } else if !v.is_empty() {
                warn("loginctl Linger=no: user scopes (memguard run) end with your last session; `loginctl enable-linger` keeps them");
            }
        }
    }

    // competing killers
    let mut competing = false;
    for unit in [
        "systemd-oomd.service",
        "earlyoom.service",
        "nohang.service",
        "nohang-desktop.service",
    ] {
        if unit_active(unit) {
            competing = true;
            warn(&format!("{unit} is active: it ranks by RSS and will pick the wrong victim on GB10; memguard refuses to start alongside it unless allow_coexist = true"));
        }
    }
    if !competing {
        ok("no competing userspace OOM killer active (systemd-oomd/earlyoom/nohang)");
    }

    // NVIDIA
    match helper::query_direct() {
        Ok((procs, ver)) => {
            let sum: u64 = procs.iter().map(|p| p.bytes).sum();
            ok(&format!(
                "NVML ok, driver {ver}: {} GPU process(es), {} GPU memory in use",
                procs.len(),
                fmt_bytes(sum)
            ));
        }
        Err(e) => {
            fail(&format!(
                "NVML: {e} (per-process GPU attribution unavailable; VmSize heuristics only)"
            ));
            failures += 1;
        }
    }
    match nvml::driver_major_from_proc() {
        Some(m) => warn(&format!("driver major {m}: accounting cannot be inferred from version alone; auto adds GPU usage conservatively. Measure with `memguard doctor --probe` before setting vidmem_charged=yes")),
        None => warn("cannot read /proc/driver/nvidia/version"),
    }

    // daemon
    if unit_active("memguard.service") {
        ok("memguard.service is active");
    } else {
        warn("memguard.service is not active");
    }
    let cfg_path = p.opt("config").unwrap_or(DEFAULT_CONFIG_PATH);
    match Config::load(cfg_path, p.opt("config").is_some()) {
        Ok(c) => {
            let total = read_meminfo().map(|m| m.total).unwrap_or(1);
            match c.validate(total) {
                Ok(()) => ok(&format!(
                    "config {cfg_path}: valid (floor {} warn {} headroom {})",
                    fmt_bytes(c.floor.resolve(total)),
                    fmt_bytes(c.warn.resolve(total)),
                    fmt_bytes(c.headroom.resolve(total))
                )),
                Err(e) => {
                    fail(&format!("config {cfg_path}: {e}"));
                    failures += 1;
                }
            }
            match crate::daemon::read_status_file(&c.status_file) {
                Some(m) => {
                    let mono: u64 = m.get("mono_ns").and_then(|s| s.parse().ok()).unwrap_or(0);
                    let age = crate::mono_ns().saturating_sub(mono) / 1_000_000_000;
                    if age <= 3 {
                        ok(&format!(
                            "daemon status file fresh: level={} kills={}",
                            m.get("level").cloned().unwrap_or_default(),
                            m.get("kills_total").cloned().unwrap_or_default()
                        ));
                    } else {
                        warn(&format!("daemon status file stale ({age}s)"));
                    }
                }
                None => warn(&format!("no daemon status file at {}", c.status_file)),
            }
        }
        Err(e) => {
            fail(&format!("config: {e}"));
            failures += 1;
        }
    }

    if p.flag("probe") {
        println!(
            "probe: measuring whether cudaMalloc memory is charged to the allocating cgroup..."
        );
        match run_probe(have_systemd_run, euid != 0) {
            Ok((charged, kernel_delta, current_delta, alloc)) => {
                ok(&format!(
                    "probe: cuMemAlloc {} -> memcg kernel +{} current +{} => vidmem_charged = {}",
                    fmt_bytes(alloc),
                    fmt_bytes(kernel_delta),
                    fmt_bytes(current_delta),
                    if charged { "yes" } else { "no" }
                ));
            }
            Err(e) => {
                fail(&format!("probe failed: {e}"));
                failures += 1;
            }
        }
    }
    println!(
        "{}",
        if failures == 0 {
            "all checks passed"
        } else {
            "some checks FAILED"
        }
    );
    if failures == 0 {
        0
    } else {
        1
    }
}

fn run_probe(use_scope: bool, user: bool) -> Result<(bool, u64, u64, u64), String> {
    if !use_scope {
        return Err("an isolated systemd scope is required to measure GPU charging".into());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut cmd = Command::new("systemd-run");
    if user {
        cmd.arg("--user");
    }
    cmd.args([
        "--scope",
        "--quiet",
        "--collect",
        "--unit",
        &format!("memguard-probe-{}", std::process::id()),
        "--",
    ])
    .arg(&exe)
    .arg("probe-child");
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let deadline = crate::mono_ns() + 10_000_000_000;
    while child.try_wait().map_err(|e| e.to_string())?.is_none() {
        if crate::mono_ns() >= deadline {
            let _ = child.kill();
            return Err("GPU charging probe timed out; driver may be stalled".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "isolated probe failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut kv = std::collections::HashMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            kv.insert(k.to_string(), v.to_string());
        }
    }
    if let Some(e) = kv.get("error") {
        return Err(e.clone());
    }
    let g = |k: &str| {
        kv.get(k)
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or_else(|| format!("probe output missing {k}: {text}"))
    };
    let alloc = g("alloc")?;
    let kernel_delta = g("kernel_after")?.saturating_sub(g("kernel_before")?);
    let current_delta = g("current_after")?.saturating_sub(g("current_before")?);
    Ok((
        kernel_delta >= alloc * 3 / 4 || current_delta >= alloc * 3 / 4,
        kernel_delta,
        current_delta,
        alloc,
    ))
}

/// Hidden: runs inside the probe scope, allocates GPU memory and reports its own cgroup deltas.
pub fn probe_child_main() -> i32 {
    if !read_meminfo().is_ok_and(|m| m.available >= 2 << 30) {
        println!("error=at least 2 GiB MemAvailable is required for the probe");
        return 1;
    }
    let cg = match cgroup::self_cgroup() {
        Some(c) => c,
        None => {
            println!("error=cannot determine own cgroup");
            return 1;
        }
    };
    let cuda = match crate::sys::cuda::Cuda::load().and_then(|c| c.init_primary().map(|_| c)) {
        Ok(c) => c,
        Err(e) => {
            println!("error={e}");
            return 1;
        }
    };
    std::thread::sleep(std::time::Duration::from_millis(100));
    let counters = || -> Result<(u64, u64), std::io::Error> {
        Ok((
            cgroup::read_u64(&cg, "memory.current")?,
            cgroup::read_memstat(&cg)?.kernel,
        ))
    };
    let (before_cur, before_k) = match counters() {
        Ok(v) => v,
        Err(e) => {
            println!("error=read cgroup counters: {e}");
            return 1;
        }
    };
    let alloc: usize = 256 << 20;
    let ptr = match cuda.mem_alloc(alloc) {
        Ok(p) => p,
        Err(e) => {
            println!("error={e}");
            return 1;
        }
    };
    let _ = cuda.memset_d8(ptr, 1, alloc);
    let _ = cuda.sync();
    std::thread::sleep(std::time::Duration::from_millis(200));
    let after = counters();
    cuda.mem_free(ptr);
    let (after_cur, after_k) = match after {
        Ok(v) => v,
        Err(e) => {
            println!("error=read cgroup counters: {e}");
            return 1;
        }
    };
    println!("cg={cg}\nalloc={alloc}\ncurrent_before={before_cur}\ncurrent_after={after_cur}\nkernel_before={before_k}\nkernel_after={after_k}");
    0
}

pub fn check_config_main(args: &[String]) -> i32 {
    let p = match cli::parse(args, &["config"], &["o"], &["quiet"]) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("memguard check-config: {e}");
            return 2;
        }
    };
    let path = p.opt("config").unwrap_or(DEFAULT_CONFIG_PATH);
    let mut cfg = match Config::load(path, p.opt("config").is_some()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("check-config: {e}");
            return 1;
        }
    };
    for o in p.multi("o") {
        if let Err(e) = cfg.apply_override(o) {
            eprintln!("check-config: {e}");
            return 1;
        }
    }
    let total = match read_meminfo() {
        Ok(m) => m.total,
        Err(e) => {
            eprintln!("check-config: {e}");
            return 1;
        }
    };
    if let Err(e) = cfg.validate(total) {
        eprintln!("check-config: INVALID: {e}");
        return 1;
    }
    println!(
        "# effective configuration ({path}, MemTotal {})",
        fmt_bytes(total)
    );
    print!("{}", cfg.describe(total));
    if p.flag("quiet") {
        return 0;
    }
    let table = procfs::scan(&procfs::ScanOptions {
        maps_for: &[],
        maps_min_vmsize: 0,
        detail_min: 0,
    });
    let mut never = Vec::new();
    let mut avoid = Vec::new();
    let mut prefer = Vec::new();
    let mut cgkill = Vec::new();
    for pr in &table.procs {
        if pr.kthread || pr.is_zombie() {
            continue;
        }
        let base = pr.exe_base();
        let label = format!(
            "{} {} ({})",
            pr.pid,
            pr.comm,
            if base.is_empty() { "?" } else { base }
        );
        if matches_any(&cfg.never_exe, &pr.exe, &pr.comm)
            || pr.cgroup == "/init.scope"
            || cfg
                .never_cgroup
                .iter()
                .any(|g| crate::config::glob_match(g, &pr.cgroup))
        {
            never.push(label.clone());
        } else if matches_any(&cfg.prefer_exe, &pr.exe, &pr.comm) {
            prefer.push(label.clone());
        } else if matches_any(&cfg.avoid_exe, &pr.exe, &pr.comm) {
            avoid.push(label.clone());
        }
        if cgroup::kill_allowed(&pr.cgroup, &cfg.cgroup_kill_match) {
            cgkill.push(format!(
                "{} {} in {}",
                pr.pid,
                pr.comm,
                cgroup::unit_name(&pr.cgroup).unwrap_or("/")
            ));
        }
    }
    let show = |title: &str, v: &[String]| {
        println!("\n# {title}: {} process(es)", v.len());
        for s in v.iter().take(12) {
            println!("  {s}");
        }
        if v.len() > 12 {
            println!("  ... {} more", v.len() - 12);
        }
    };
    show("never killed (never_exe / init.scope)", &never);
    show("avoided (score x0.5)", &avoid);
    show("preferred victims (prefer_exe)", &prefer);
    show("cgroup.kill allowed for their unit", &cgkill);
    0
}
