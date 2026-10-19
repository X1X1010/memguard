//! `memguard run`: execute one job inside a transient systemd scope with memory budgets.
//!
//! `--mem` is enforced by the kernel (MemoryMax). `--gpu` and `--total` are enforced here in user
//! space because on this driver cudaMalloc memory is not charged to the cgroup. The system floor
//! is deferred to the daemon when one is running; without a daemon the job is only sacrificed when
//! it is a major contributor (>= 25 % of RAM or the top GPU holder).

use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use crate::cli;
use crate::config::{Config, VidmemCharged, DEFAULT_CONFIG_PATH};
use crate::daemon;
use crate::helper::NvmlFeed;
use crate::sampler::HotSampler;
use crate::sys::{cgroup, procfs};
use crate::units::{fmt_bytes, parse_size};

pub struct RunArgs {
    pub gpu: Option<u64>,
    pub mem: Option<u64>,
    pub total: Option<u64>,
    /// None = unlimited swap; Some(bytes) = MemorySwapMax
    pub swap: Option<u64>,
    pub floor: Option<u64>,
    pub oom_adj: Option<i32>,
    pub unit: Option<String>,
    pub no_scope: bool,
    pub dry_run: bool,
    pub verbose: bool,
    pub interval_ms: u64,
    pub config_path: String,
    pub config_explicit: bool,
    pub vidmem_charged: Option<bool>,
    pub cmd: Vec<String>,
}

pub fn main(args: &[String]) -> i32 {
    let p = match cli::parse(
        args,
        &[
            "gpu",
            "mem",
            "total",
            "swap",
            "floor",
            "oom-adj",
            "unit",
            "interval-ms",
            "config",
            "vidmem-charged",
        ],
        &[],
        &["prefer-kill", "no-scope", "dry-run", "v", "verbose"],
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("memguard run: {e}");
            return 2;
        }
    };
    if p.rest.is_empty() {
        eprintln!("memguard run: missing command after '--'");
        return 2;
    }
    let size = |k: &str| -> Result<Option<u64>, String> { p.opt(k).map(parse_size).transpose() };
    let built = (|| -> Result<RunArgs, String> {
        let swap = match p.opt("swap") {
            None => Some(0),
            Some(s) if s.eq_ignore_ascii_case("max") || s.eq_ignore_ascii_case("infinity") => None,
            Some(s) => Some(parse_size(s)?),
        };
        let oom_adj = if p.flag("prefer-kill") {
            Some(1000)
        } else {
            p.opt("oom-adj")
                .map(|s| s.parse::<i32>().map_err(|_| format!("bad --oom-adj '{s}'")))
                .transpose()?
        };
        let vidmem_charged = match p.opt("vidmem-charged") {
            None => None,
            Some(s) if s.eq_ignore_ascii_case("auto") => None,
            Some(s) => Some(crate::units::parse_bool(s)?),
        };
        Ok(RunArgs {
            gpu: size("gpu")?,
            mem: size("mem")?,
            total: size("total")?,
            swap,
            floor: size("floor")?,
            oom_adj,
            unit: p.opt("unit").map(|s| s.to_string()),
            no_scope: p.flag("no-scope"),
            dry_run: p.flag("dry-run"),
            verbose: p.flag("v") || p.flag("verbose"),
            interval_ms: match p.opt("interval-ms") {
                Some(s) => s
                    .parse::<u64>()
                    .ok()
                    .filter(|v| (10..=1000).contains(v))
                    .ok_or("--interval-ms must be within 10..1000")?,
                None => 50,
            },
            config_path: p.opt("config").unwrap_or(DEFAULT_CONFIG_PATH).to_string(),
            config_explicit: p.opt("config").is_some(),
            vidmem_charged,
            cmd: p.rest.clone(),
        })
    })();
    match built {
        Ok(a) if a.oom_adj.is_some_and(|v| !(-1000..=1000).contains(&v)) => {
            eprintln!("memguard run: --oom-adj must be within -1000..1000");
            2
        }
        Ok(a) => run(a),
        Err(e) => {
            eprintln!("memguard run: {e}");
            2
        }
    }
}

fn sanitize_unit(s: &str) -> String {
    let mut out: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .take(40)
        .collect();
    if out.is_empty() {
        out = "job".into();
    }
    out
}

fn systemd_run_available(user: bool, unit: &str, oom_group: bool) -> bool {
    let mut c = Command::new("systemd-run");
    if user {
        c.arg("--user");
    }
    c.args(["--scope", "--quiet", "--collect", "--unit", unit]);
    if oom_group {
        c.args(["-p", "OOMPolicy=kill"]);
    }
    c.args(["--", "/bin/true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    c.status().map(|s| s.success()).unwrap_or(false)
}

fn linger_enabled() -> Option<bool> {
    // SAFETY: trivial libc call.
    let uid = unsafe { libc::getuid() };
    let out = Command::new("loginctl")
        .args(["show-user", &uid.to_string(), "-p", "Linger", "--value"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    Some(s.trim() == "yes")
}

struct JobView {
    pids: Vec<u32>,
    job_mem: u64,
    gpu: u64,
    gpu_fresh: bool,
    oom_kills: u64,
    accounting_ok: bool,
}

pub fn run(a: RunArgs) -> i32 {
    crate::log::set_level_str(if a.verbose { "debug" } else { "info" });
    crate::log::set_plain(true);
    let mut cfg = match Config::load(&a.config_path, a.config_explicit) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("memguard run: {e}");
            return 2;
        }
    };
    let mut sampler = match HotSampler::open() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("memguard run: {e}");
            return 2;
        }
    };
    let total = sampler.last_meminfo.total;
    if let Err(e) = cfg.validate(total) {
        eprintln!("memguard run: {e}");
        return 2;
    }
    let floor = a.floor.unwrap_or_else(|| cfg.floor.resolve(total));
    let vidmem_charged = match a.vidmem_charged {
        Some(b) => b,
        None => match cfg.vidmem_charged {
            VidmemCharged::Yes => true,
            VidmemCharged::No => false,
            // A driver version is not evidence of this kernel's accounting behavior.
            VidmemCharged::Auto => false,
        },
    };
    if a.vidmem_charged.is_some() {
        cfg.vidmem_charged = if vidmem_charged {
            VidmemCharged::Yes
        } else {
            VidmemCharged::No
        };
    }
    // SAFETY: trivial libc call.
    let user_mode = unsafe { libc::geteuid() } != 0;
    let base = a.cmd[0].rsplit('/').next().unwrap_or("job");
    let unit = a.unit.clone().unwrap_or_else(|| {
        format!(
            "memguard-{}-{:x}",
            sanitize_unit(base),
            (std::process::id() as u64) ^ (crate::mono_ns() & 0xffff)
        )
    });
    let unit = unit.trim_end_matches(".scope").to_string();

    if procfs::self_nspid_depth() > 1 {
        if (a.gpu.is_some() || a.total.is_some()) && !a.dry_run {
            eprintln!("memguard run: GPU budgets cannot be enforced inside a PID namespace");
            return 2;
        }
        crate::warn!("running inside a PID namespace: NVML reports host PIDs, so --gpu/--total cannot see GPU memory here; only --mem is enforced");
    }

    let scope_mode =
        !a.no_scope && systemd_run_available(user_mode, &format!("{unit}-probe"), !a.dry_run);
    if !a.no_scope && !scope_mode {
        crate::warn!("systemd-run {}--scope is not usable here; supervising the process tree instead (no kernel-enforced --mem, no cgroup.kill)", if user_mode { "--user " } else { "" });
    }
    if scope_mode && user_mode {
        if let Some(false) = linger_enabled() {
            crate::debug!("note: Linger=no; the job's scope ends with your last login session (loginctl enable-linger to keep jobs alive)");
        }
    }

    // Verify GPU telemetry before launching a workload whose requested limit depends on it.
    let mut feed = NvmlFeed::spawn(a.interval_ms).ok();
    if a.gpu.is_some() || a.total.is_some() {
        let deadline = crate::mono_ns() + 2_000_000_000;
        while let Some(f) = feed.as_mut() {
            let now = crate::mono_ns();
            f.poll(now);
            if f.snapshot().valid || now >= deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        if feed.as_ref().is_none_or(|f| !f.snapshot().valid) {
            if !a.dry_run {
                eprintln!("memguard run: NVML unavailable; refusing to launch a job with unenforceable GPU/total budgets");
                return 2;
            }
            crate::warn!("NVML unavailable; dry-run GPU/total accounting is incomplete");
        }
    }

    let mut cmd = if scope_mode {
        let mut c = Command::new("systemd-run");
        if user_mode {
            c.arg("--user");
        }
        c.args(["--scope", "--quiet", "--collect", "--unit", &unit]);
        if !a.dry_run {
            match a.swap {
                Some(b) => {
                    c.arg("-p").arg(format!("MemorySwapMax={b}"));
                }
                None => {
                    c.arg("-p").arg("MemorySwapMax=infinity");
                }
            }
        }
        if let Some(m) = a.mem {
            if !a.dry_run {
                c.arg("-p").arg(format!("MemoryMax={m}"));
            }
        }
        if !a.dry_run {
            c.args(["-p", "OOMPolicy=kill"]);
        }
        c.arg("--");
        c.args(&a.cmd);
        c
    } else {
        if a.mem.is_some() {
            crate::warn!("--mem cannot be kernel-enforced without a scope; treating it as a user-space --total check on anon+shmem+swap");
        }
        let mut c = Command::new(&a.cmd[0]);
        c.args(&a.cmd[1..]);
        c
    };
    if let Some(adj) = a.oom_adj {
        // SAFETY: only writes a /proc file in the child before exec.
        unsafe {
            cmd.pre_exec(move || std::fs::write("/proc/self/oom_score_adj", adj.to_string()));
        }
    }
    daemon::install_signal_handlers();
    let start_ns = crate::mono_ns();
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("memguard run: cannot start {}: {e}", a.cmd[0]);
            return 127;
        }
    };
    let child_pid = child.id();
    let child_identity = procfs::ProcessIdentity::read(child_pid);

    let mut cg_path: Option<String> = None;
    if scope_mode {
        let want = format!("/{unit}.scope");
        let t0 = crate::mono_ns();
        loop {
            if let Some(cg) = procfs::pid_cgroup(child_pid) {
                if cg.ends_with(&want) {
                    cg_path = Some(cg);
                    break;
                }
            }
            if matches!(child.try_wait(), Ok(Some(_))) || crate::mono_ns() - t0 > 5_000_000_000 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        match &cg_path {
            Some(cg) => {
                crate::debug!("job cgroup {cg}");
            }
            None => {
                if matches!(child.try_wait(), Ok(None)) {
                    crate::warn!("scope {unit}.scope did not appear; falling back to process-tree supervision");
                }
            }
        }
    }

    if feed.is_none() {
        crate::warn!("nvml-helper unavailable: --gpu cannot be enforced");
    }
    let interval = a.interval_ms * 1_000_000;
    let mut deadline = crate::mono_ns();
    let mut peak_gpu = 0u64;
    let mut peak_mem = 0u64;
    let mut peak_total = 0u64;
    let mut oom_kills_seen = 0u64;
    let mut last_gpu = 0u64;
    let mut killed: Option<String> = None;
    let mut dry_reported: Vec<String> = Vec::new();
    let mut term_seen = 0u32;
    let mut last_scan_ns = 0u64;
    let mut tree_pids: Vec<u32> = vec![child_pid];
    let mut tree_targets: Vec<procfs::ProcessIdentity> = child_identity.into_iter().collect();
    let mut last_mem = 0;
    let mut pids_buf: Vec<u32> = Vec::new();
    let mut floor_deferred_logged = false;
    let mut accounting_warned_ns: Option<u64> = None;
    let mut stale_warned_ns: Option<u64> = None;
    let mut leader_status = None;
    let status;

    loop {
        deadline += interval;
        crate::sleep_until_mono(deadline);
        let now = crate::mono_ns();
        if now > deadline + interval * 4 {
            deadline = now;
        }
        if let Ok(Some(st)) = child.try_wait() {
            leader_status = Some(st);
            let remaining = if let Some(cg) = &cg_path {
                cgroup::read_procs_recursive(cg, &mut pids_buf).is_ok() && !pids_buf.is_empty()
            } else {
                tree_targets.iter().any(|p| p.pid != child_pid && p.alive())
            };
            if !remaining {
                status = st;
                break;
            }
        }
        let tc = daemon::term_count();
        if tc > term_seen {
            term_seen = tc;
            let pids = tree_targets.clone();
            if tc == 1 {
                crate::warn!("signal received: forwarding SIGTERM to the job ({} process(es)); again to SIGKILL", pids.len());
                crate::actuator::signal_pids(&pids, libc::SIGTERM);
            } else {
                crate::warn!("second signal: SIGKILL");
                if let Some(cg) = &cg_path {
                    let _ = cgroup::kill(cg);
                }
                crate::actuator::signal_pids(&pids, libc::SIGKILL);
            }
        }
        let s = match sampler.sample(now) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if let Some(f) = feed.as_mut() {
            f.poll(now);
        }

        let view = if let Some(cg) = &cg_path {
            let stat_result = cgroup::read_memstat(cg);
            let swap_result = cgroup::read_u64(cg, "memory.swap.current");
            let pids_result = cgroup::read_procs_recursive(cg, &mut pids_buf);
            let accounting_ok = stat_result.is_ok() && swap_result.is_ok() && pids_result.is_ok();
            let stat = stat_result.unwrap_or_default();
            let swap = swap_result.unwrap_or(0);
            let ev = cgroup::read_events(cg).unwrap_or_default();
            JobView {
                pids: pids_buf.clone(),
                job_mem: stat
                    .anon
                    .saturating_add(stat.shmem)
                    .saturating_add(stat.kernel)
                    .saturating_add(swap),
                gpu: 0,
                gpu_fresh: false,
                oom_kills: ev.oom_kill,
                accounting_ok,
            }
        } else {
            if now.saturating_sub(last_scan_ns) >= 250_000_000 || tree_pids.len() == 1 {
                last_scan_ns = now;
                let t = procfs::scan(&procfs::ScanOptions {
                    maps_for: &[],
                    maps_min_vmsize: 0,
                    detail_min: 0,
                });
                let mut v = Vec::new();
                for target in &tree_targets {
                    if t.get(target.pid)
                        .is_some_and(|p| p.starttime == target.starttime)
                    {
                        v.extend(t.descendants(target.pid));
                        v.push(target.pid);
                    }
                }
                v.sort_unstable();
                v.dedup();
                let mem: u64 = v
                    .iter()
                    .filter_map(|p| t.get(*p))
                    .map(|p| p.rss_anon + p.rss_shmem + p.vm_swap)
                    .sum();
                tree_targets = v
                    .iter()
                    .filter_map(|pid| t.get(*pid).map(procfs::ProcInfo::identity))
                    .collect();
                tree_pids = v;
                last_mem = mem;
                JobView {
                    pids: tree_pids.clone(),
                    job_mem: mem,
                    gpu: 0,
                    gpu_fresh: false,
                    oom_kills: 0,
                    accounting_ok: !tree_targets.is_empty() || leader_status.is_some(),
                }
            } else {
                JobView {
                    pids: tree_pids.clone(),
                    job_mem: last_mem,
                    gpu: 0,
                    gpu_fresh: false,
                    oom_kills: 0,
                    accounting_ok: true,
                }
            }
        };
        let mut view = view;
        if cg_path.is_some() {
            tree_pids = view.pids.clone();
            tree_targets = tree_pids
                .iter()
                .filter_map(|pid| procfs::ProcessIdentity::read(*pid))
                .collect();
        }
        let mut top_gpu_global = 0u64;
        if let Some(f) = feed.as_ref() {
            let snap = f.snapshot();
            if snap.valid {
                view.gpu_fresh = f.age_ns(now) <= 1_000_000_000;
                let g: u64 = snap
                    .procs
                    .iter()
                    .filter(|p| view.pids.contains(&p.pid))
                    .map(|p| p.bytes)
                    .sum();
                top_gpu_global = snap.procs.iter().map(|p| p.bytes).max().unwrap_or(0);
                if view.gpu_fresh {
                    last_gpu = g;
                }
            }
        }
        view.gpu = last_gpu;
        // Process RSS does not include charged kernel pages; only a real cgroup can deduplicate.
        let total_used = if vidmem_charged && cg_path.is_some() {
            view.job_mem.max(view.gpu)
        } else {
            view.job_mem.saturating_add(view.gpu)
        };
        peak_gpu = peak_gpu.max(view.gpu);
        peak_mem = peak_mem.max(view.job_mem);
        peak_total = peak_total.max(total_used);
        if view.oom_kills > oom_kills_seen {
            crate::warn!("kernel memcg OOM killer acted inside the job ({} kill event(s) so far; MemoryMax={})", view.oom_kills, a.mem.map(fmt_bytes).unwrap_or_else(|| "none".into()));
            oom_kills_seen = view.oom_kills;
        }

        let mut reason: Option<String> = None;
        if !view.accounting_ok {
            // Usually the scope is being torn down because the job just exited. A missing
            // cgroup file is never a reason to kill; skip enforcement for this tick.
            if accounting_warned_ns.is_none_or(|t| now.saturating_sub(t) > 10_000_000_000) {
                crate::warn!("job memory accounting unavailable this tick; budgets are not enforced until it returns");
                accounting_warned_ns = Some(now);
            }
            continue;
        }
        if (a.gpu.is_some() || a.total.is_some()) && !view.gpu_fresh {
            // NVML blocks while *any* process is inside a large allocation ioctl (measured
            // 715 ms for 24 GiB), so stale telemetry is not the job's fault. Keep the last
            // known GPU figure and warn instead of killing.
            if stale_warned_ns.is_none_or(|t| now.saturating_sub(t) > 10_000_000_000) {
                crate::warn!(
                    "GPU telemetry stale for over 1 s (NVML blocked by a driver allocation?); enforcing with the last known value {}",
                    fmt_bytes(view.gpu)
                );
                stale_warned_ns = Some(now);
            }
        }
        if let Some(lim) = a.gpu {
            if view.gpu > lim {
                reason = Some(format!(
                    "GPU budget {} exceeded ({})",
                    fmt_bytes(lim),
                    fmt_bytes(view.gpu)
                ));
            }
        }
        if reason.is_none() {
            if let Some(lim) = a.total {
                if total_used > lim {
                    reason = Some(format!(
                        "total budget {} exceeded ({} = mem {} + gpu {})",
                        fmt_bytes(lim),
                        fmt_bytes(total_used),
                        fmt_bytes(view.job_mem),
                        fmt_bytes(view.gpu)
                    ));
                }
            }
        }
        if reason.is_none() && (cg_path.is_none() || a.dry_run) {
            if let Some(lim) = a.mem {
                if view.job_mem > lim {
                    reason = Some(format!(
                        "memory budget {} exceeded ({}, user-space check)",
                        fmt_bytes(lim),
                        fmt_bytes(view.job_mem)
                    ));
                }
            }
        }
        if reason.is_none() && s.avail < floor {
            if daemon::daemon_fresh(&cfg.status_file, now, 3_000_000_000) {
                if !floor_deferred_logged {
                    crate::debug!("system MemAvailable {} below floor {}; the memguard daemon is running and decides who dies", fmt_bytes(s.avail), fmt_bytes(floor));
                    floor_deferred_logged = true;
                }
            } else {
                let major = total_used >= total / 4 || (view.gpu > 0 && view.gpu >= top_gpu_global);
                if major {
                    reason = Some(format!("system MemAvailable {} below floor {} and this job holds {} (no daemon running)", fmt_bytes(s.avail), fmt_bytes(floor), fmt_bytes(total_used)));
                }
            }
        }

        if let Some(r) = reason {
            if a.dry_run {
                let kind = r
                    .split(" exceeded")
                    .next()
                    .unwrap_or(&r)
                    .split(" below")
                    .next()
                    .unwrap_or(&r)
                    .to_string();
                if !dry_reported.contains(&kind) {
                    crate::warn!("DRY-RUN would kill the job: {r}");
                    dry_reported.push(kind);
                }
            } else {
                crate::error!("killing job: {r}");
                let mut done = false;
                if let Some(cg) = &cg_path {
                    match cgroup::kill(cg) {
                        Ok(()) => done = true,
                        Err(e) => crate::warn!("cgroup.kill failed ({e}); signalling the tree"),
                    }
                }
                if !done {
                    crate::actuator::signal_pids(&tree_targets, libc::SIGKILL);
                }
                killed = Some(r);
                // A job stuck in a driver ioctl may not exit after SIGKILL. Report the
                // requested termination without blocking the supervisor indefinitely.
                use std::os::unix::process::ExitStatusExt;
                status = child
                    .try_wait()
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| std::process::ExitStatus::from_raw(libc::SIGKILL));
                break;
            }
        }
    }

    // a kernel memcg kill can finish before our next tick: look once more, or infer it
    if killed.is_none() {
        if let Some(cg) = &cg_path {
            if let Ok(ev) = cgroup::read_events(cg) {
                oom_kills_seen = oom_kills_seen.max(ev.oom_kill);
            }
        }
        use std::os::unix::process::ExitStatusExt;
        if oom_kills_seen == 0
            && a.mem.is_some()
            && cg_path.is_some()
            && status.signal() == Some(libc::SIGKILL)
        {
            crate::warn!("job died by SIGKILL inside a MemoryMax={} scope; OOM is possible but could not be confirmed", fmt_bytes(a.mem.unwrap_or(0)));
        } else if oom_kills_seen > 0 {
            crate::warn!("kernel memcg OOM killer acted inside the job ({oom_kills_seen} kill event(s); MemoryMax={})", a.mem.map(fmt_bytes).unwrap_or_else(|| "none".into()));
        }
    }
    let elapsed = (crate::mono_ns() - start_ns) as f64 / 1e9;
    if let Some(mut f) = feed.take() {
        f.shutdown();
    }
    let peaks = format!(
        "peak gpu={} mem={} total={}{}",
        fmt_bytes(peak_gpu),
        fmt_bytes(peak_mem),
        fmt_bytes(peak_total),
        if oom_kills_seen > 0 {
            format!(" memcg-oom-kills={oom_kills_seen}")
        } else {
            String::new()
        }
    );
    use std::os::unix::process::ExitStatusExt;
    match killed {
        Some(r) => {
            eprintln!(
                "memguard: KILLED {} after {elapsed:.1}s: {r}; {peaks}",
                a.cmd[0]
            );
            137
        }
        None => {
            let code = match (status.code(), status.signal()) {
                (Some(c), _) => c,
                (None, Some(sig)) => 128 + sig,
                _ => 1,
            };
            crate::info!(
                "{} exited with status {code} after {elapsed:.1}s; {peaks}",
                a.cmd[0]
            );
            code
        }
    }
}
