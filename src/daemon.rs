//! `memguard daemon`: the system-wide watchdog loop.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::actuator;
use crate::cli;
use crate::config::{Action, Config, KillSignal, DEFAULT_CONFIG_PATH};
use crate::engine::{Engine, EngineConfig, Level, VerifyOutcome};
use crate::helper::NvmlFeed;
use crate::sampler::{HotSampler, Reclaimer, Scanner};
use crate::sdnotify::SdNotify;
use crate::sys::procfs::ProcessIdentity;
use crate::sys::{cgroup, procfs};
use crate::units::{fmt_bytes, fmt_rate};
use crate::victim::{self, History, RankInput, VictimConfig};

static SIG_TERM: AtomicU32 = AtomicU32::new(0);
static SIG_HUP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(sig: libc::c_int) {
    if sig == libc::SIGHUP {
        SIG_HUP.store(true, Ordering::SeqCst);
    } else {
        SIG_TERM.fetch_add(1, Ordering::SeqCst);
    }
}

pub fn install_signal_handlers() {
    // SAFETY: handler only touches atomics; sigaction with a zeroed struct is valid.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0; // no SA_RESTART: wake clock_nanosleep
        for s in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            libc::sigaction(s, &sa, std::ptr::null_mut());
        }
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

pub fn term_requested() -> bool {
    SIG_TERM.load(Ordering::SeqCst) > 0
}

/// Number of SIGTERM/SIGINT received so far.
pub fn term_count() -> u32 {
    SIG_TERM.load(Ordering::SeqCst)
}

pub fn take_hup() -> bool {
    SIG_HUP.swap(false, Ordering::SeqCst)
}

pub struct DaemonArgs {
    pub config_path: String,
    pub config_explicit: bool,
    pub overrides: Vec<String>,
    pub dry_run: bool,
    pub only_kill_exe: Option<String>,
    pub record: Option<String>,
    pub verbose: bool,
}

impl DaemonArgs {
    fn load_config(&self) -> Result<Config, String> {
        let mut cfg = Config::load(&self.config_path, self.config_explicit)?;
        for o in &self.overrides {
            cfg.apply_override(o)?;
        }
        if self.dry_run {
            cfg.action = Action::DryRun;
        }
        if let Some(x) = &self.only_kill_exe {
            cfg.only_kill_exe = x.clone();
        }
        if let Some(r) = &self.record {
            cfg.record = r.clone();
        }
        Ok(cfg)
    }
}

pub fn main(args: &[String]) -> i32 {
    let p = match cli::parse(
        args,
        &["config", "only-kill-exe", "record"],
        &["o"],
        &["dry-run", "v", "verbose", "foreground"],
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("memguard daemon: {e}");
            return 2;
        }
    };
    let a = DaemonArgs {
        config_path: p.opt("config").unwrap_or(DEFAULT_CONFIG_PATH).to_string(),
        config_explicit: p.opt("config").is_some(),
        overrides: p.multi("o").to_vec(),
        dry_run: p.flag("dry-run"),
        only_kill_exe: p.opt("only-kill-exe").map(|s| s.to_string()),
        record: p.opt("record").map(|s| s.to_string()),
        verbose: p.flag("v") || p.flag("verbose"),
    };
    match run(a) {
        Ok(()) => 0,
        Err(e) => {
            crate::error!("{e}");
            1
        }
    }
}

fn is_root() -> bool {
    // SAFETY: trivial libc call.
    unsafe { libc::geteuid() == 0 }
}

fn lock_path() -> String {
    if is_root() {
        let _ = std::fs::create_dir_all("/run/memguard");
        "/run/memguard/lock".into()
    } else {
        let dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into());
        use std::os::unix::fs::DirBuilderExt;
        let d = format!("{dir}/memguard-{}", unsafe { libc::geteuid() });
        let _ = std::fs::DirBuilder::new().mode(0o700).create(&d);
        format!("{d}/lock")
    }
}

fn take_lock(path: &str) -> Result<std::fs::File, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::os::unix::io::AsRawFd;
    let parent = std::path::Path::new(path)
        .parent()
        .ok_or("lock has no parent")?;
    let metadata = std::fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        return Err("lock directory must be owned by this user and not writable by others".into());
    }
    let f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("{path}: {e}"))?;
    // SAFETY: flock on a valid fd.
    let r = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if r != 0 {
        return Err(format!("another memguard daemon holds {path}"));
    }
    let _ = (&f).write_all(format!("{}\n", std::process::id()).as_bytes());
    Ok(f)
}

fn mlock_all() -> Result<(), String> {
    // SAFETY: plain syscall.
    let r = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if r != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

struct StatusFile {
    path: String,
    tmp: String,
    enabled: bool,
}

impl StatusFile {
    fn new(path: &str) -> StatusFile {
        let enabled = if let Some(dir) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(dir).is_ok()
        } else {
            false
        };
        StatusFile {
            path: path.to_string(),
            tmp: format!("{path}.{}.{}.tmp", std::process::id(), crate::mono_ns()),
            enabled,
        }
    }
    fn write(&mut self, content: &str) {
        use std::os::unix::fs::OpenOptionsExt;
        if !self.enabled {
            return;
        }
        if std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.tmp)
            .and_then(|mut f| f.write_all(content.as_bytes()))
            .and_then(|_| std::fs::rename(&self.tmp, &self.path))
            .is_err()
        {
            self.enabled = false;
            crate::warn!("status file {} not writable; disabled", self.path);
        }
    }
}

enum OutputEvent {
    Status(String),
    Trace(String),
}

/// Disk writes must not stall the decision loop. A bounded queue drops diagnostics under load.
struct Outputs {
    tx: std::sync::mpsc::SyncSender<OutputEvent>,
    handle: std::thread::JoinHandle<()>,
}

impl Outputs {
    fn start(mut status: StatusFile, mut record: Option<std::fs::File>) -> Result<Self, String> {
        let (tx, rx) = std::sync::mpsc::sync_channel(128);
        let handle = std::thread::Builder::new()
            .name("memguard-output".into())
            .stack_size(256 * 1024)
            .spawn(move || {
                crate::sampler::drop_realtime();
                for event in rx {
                    match event {
                        OutputEvent::Status(text) => status.write(&text),
                        OutputEvent::Trace(text) => {
                            if let Some(f) = record.as_mut() {
                                if let Err(e) = f.write_all(text.as_bytes()) {
                                    crate::warn!("trace write failed; recording disabled: {e}");
                                    record = None;
                                }
                            }
                        }
                    }
                }
            })
            .map_err(|e| format!("spawn output thread: {e}"))?;
        Ok(Self { tx, handle })
    }

    fn send(&self, event: OutputEvent) {
        if self.tx.try_send(event).is_err() {
            crate::log::record_drop();
        }
    }

    fn stop(self) {
        drop(self.tx);
        for _ in 0..10 {
            if self.handle.is_finished() {
                let _ = self.handle.join();
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

/// Parse a status file written by a daemon. Returns (mono_ns, level, dry_run) if present.
pub fn read_status_file(path: &str) -> Option<HashMap<String, String>> {
    let t = std::fs::read_to_string(path).ok()?;
    let mut m = HashMap::new();
    for line in t.lines() {
        if let Some((k, v)) = line.split_once('=') {
            m.insert(k.to_string(), v.to_string());
        }
    }
    Some(m)
}

/// True if a daemon status file was written within `max_age_ns` of now (same monotonic clock).
pub fn daemon_fresh(path: &str, now_ns: u64, max_age_ns: u64) -> bool {
    read_status_file(path).is_some_and(|m| {
        let t = m
            .get("mono_ns")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let pid = m
            .get("pid")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        let start = m
            .get("starttime")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        t > 0
            && t <= now_ns
            && now_ns - t <= max_age_ns
            && m.get("dry_run").is_some_and(|s| s == "0")
            && m.get("test_mode").is_some_and(|s| s == "0")
            && m.get("level").is_some_and(|s| s != "STOPPED")
            && start > 0
            && (ProcessIdentity {
                pid,
                starttime: start,
            })
            .alive()
    })
}

struct RateLimitedLog {
    last: HashMap<u64, u64>,
}

impl RateLimitedLog {
    fn allow(&mut self, key: u64, now: u64, every_ns: u64) -> bool {
        match self.last.get(&key) {
            Some(t) if now.saturating_sub(*t) < every_ns => false,
            _ => {
                self.last.insert(key, now);
                if self.last.len() > 1024 {
                    self.last.clear();
                }
                true
            }
        }
    }
}

const GIB: u64 = 1 << 30;

pub fn run(a: DaemonArgs) -> Result<(), String> {
    let mut cfg = a.load_config()?;
    crate::log::set_level_str(if a.verbose { "debug" } else { &cfg.log_level });

    let mut sampler = HotSampler::open()?;
    let total = sampler.last_meminfo.total;
    cfg.validate(total)?;
    let mut dry_run = cfg.action == Action::DryRun;
    let root = is_root();
    if !root && !dry_run && cfg.only_kill_exe.is_empty() {
        return Err("memguard daemon must run as root to kill other users' processes (use --dry-run or --only-kill-exe for tests)".into());
    }
    if !cfg.allow_coexist {
        for unit in [
            "systemd-oomd.service",
            "earlyoom.service",
            "nohang.service",
            "nohang-desktop.service",
        ] {
            if actuator::unit_active(unit) {
                let msg = format!("{unit} is active; two userspace OOM killers will fight (set allow_coexist = true to override)");
                if dry_run {
                    crate::warn!("{msg}");
                } else {
                    return Err(msg);
                }
            }
        }
    }
    let _lock = take_lock(&lock_path())?;
    crate::log::set_nonblocking_stderr();
    install_signal_handlers();

    if cfg.mlock {
        match mlock_all() {
            Ok(()) => crate::debug!("mlockall ok"),
            Err(e) => {
                crate::warn!("mlockall failed ({e}); the daemon may be paged out under pressure")
            }
        }
    }

    let ecfg = EngineConfig::from_config(&cfg, total);
    let mut engine = Engine::new(ecfg.clone());
    let mut vcfg = VictimConfig::from_config(&cfg, total);

    let mut feed = match NvmlFeed::spawn(cfg.interval_ms) {
        Ok(f) => Some(f),
        Err(e) => {
            crate::warn!(
                "cannot start nvml-helper ({e}); GPU attribution degraded to VmSize heuristics"
            );
            None
        }
    };
    let scanner = Scanner::start(
        cfg.scan_interval_ms,
        cfg.warn_scan_interval_ms,
        16 * GIB,
        64 << 20,
    );
    scanner.wait_first(3000);
    let reclaimer = if cfg.headroom_reclaim && !dry_run && root && cgroup::root_reclaim_available()
    {
        Some(Reclaimer::start(true))
    } else {
        if cfg.headroom_reclaim {
            crate::info!(
                "headroom reclaim disabled ({})",
                if root {
                    "no memory.reclaim"
                } else {
                    "not root"
                }
            );
        }
        None
    };

    let sd = SdNotify::from_env();
    let status_file = StatusFile::new(&cfg.status_file);
    let record: Option<std::fs::File> = if cfg.record.is_empty() {
        None
    } else {
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&cfg.record)
        {
            Ok(mut f) => {
                if f.metadata().map(|m| m.len() == 0).unwrap_or(false) {
                    let _ = writeln!(f, "t_ns,total,free,avail,free2m,swap_total,swap_free,psi_some_us,psi_full_us,level,may_kill,gate");
                }
                Some(f)
            }
            Err(e) => {
                crate::warn!("cannot open record file {}: {e}", cfg.record);
                None
            }
        }
    };

    let recording = record.is_some();
    let outputs = Outputs::start(status_file, record)?;

    crate::info!(
        "memguard {} starting: total={} floor={} warn={} horizon={}ms tick={}ms headroom={} action={} kill_mode={:?} nvml={} psi={} free2m={}",
        env!("CARGO_PKG_VERSION"),
        fmt_bytes(total),
        fmt_bytes(ecfg.floor),
        fmt_bytes(ecfg.warn),
        cfg.horizon_ms,
        cfg.interval_ms,
        fmt_bytes(ecfg.headroom),
        if dry_run { "DRY-RUN" } else { "kill" },
        cfg.kill_mode,
        feed.is_some(),
        sampler.psi_available,
        sampler.free2m_available
    );
    if !cfg.only_kill_exe.is_empty() {
        crate::warn!("TEST MODE: only processes whose exe/comm matches '{}' will be killed; everything else is dry-run", cfg.only_kill_exe);
    }
    if let Some(sd) = &sd {
        sd.ready();
        sd.status(if dry_run {
            "DRY-RUN: monitoring only"
        } else {
            "monitoring"
        });
    }

    let interval = cfg.interval_ms * 1_000_000;
    let mut deadline = crate::mono_ns();
    let mut last_hz = 0u64;
    let mut boot_delta = crate::boot_ns().wrapping_sub(crate::mono_ns());
    let mut last_level = Level::Ok;
    let mut hist = History::default();
    let mut last_rank_table_ns = 0u64;
    let mut dying: HashMap<ProcessIdentity, u64> = HashMap::new();
    let mut escalations: Vec<(Vec<ProcessIdentity>, u64)> = Vec::new();
    let mut rl = RateLimitedLog {
        last: HashMap::new(),
    };
    let mut last_kill_desc = String::new();
    let mut late_ticks = 0u64;
    let self_pid = std::process::id();
    let self_start = procfs::starttime(self_pid).unwrap_or(0);

    loop {
        deadline += interval;
        crate::sleep_until_mono(deadline);
        let now = crate::mono_ns();
        if now > deadline + interval * 4 {
            late_ticks += 1;
            if rl.allow(1, now, 5_000_000_000) {
                crate::warn!(
                    "late tick: {} ms behind (system stalling?)",
                    (now - deadline) / 1_000_000
                );
            }
            deadline = now;
        }
        if term_requested() {
            break;
        }
        if take_hup() {
            match a.load_config() {
                Ok(c) => {
                    let mut ok = true;
                    if c.interval_ms != cfg.interval_ms
                        || c.scan_interval_ms != cfg.scan_interval_ms
                        || c.warn_scan_interval_ms != cfg.warn_scan_interval_ms
                        || c.status_file != cfg.status_file
                        || c.record != cfg.record
                        || c.mlock != cfg.mlock
                        || c.headroom_reclaim != cfg.headroom_reclaim
                        || (dry_run && c.action == Action::Kill)
                        || c.allow_coexist != cfg.allow_coexist
                        || c.only_kill_exe != cfg.only_kill_exe
                    {
                        crate::error!("reload rejected: changing runtime resources or kill permissions requires a restart");
                        ok = false;
                    }
                    if ok {
                        match c.validate(total) {
                            Ok(()) => {
                                engine.cfg = EngineConfig::from_config(&c, total);
                                vcfg = VictimConfig::from_config(&c, total);
                                crate::log::set_level_str(if a.verbose {
                                    "debug"
                                } else {
                                    &c.log_level
                                });
                                cfg = c;
                                dry_run = cfg.action == Action::DryRun;
                                crate::info!(
                                    "configuration reloaded (floor={} warn={})",
                                    fmt_bytes(engine.cfg.floor),
                                    fmt_bytes(engine.cfg.warn)
                                );
                            }
                            Err(e) => crate::error!("reload rejected: {e}"),
                        }
                    }
                }
                Err(e) => crate::error!("reload failed: {e}"),
            }
        }
        let bd = crate::boot_ns().wrapping_sub(crate::mono_ns());
        if bd.abs_diff(boot_delta) > 1_000_000_000 {
            crate::info!("suspend/resume detected; resetting rate windows");
            engine.reset_windows();
            boot_delta = bd;
        }

        let s = match sampler.sample(now) {
            Ok(s) => s,
            Err(e) => {
                if rl.allow(2, now, 5_000_000_000) {
                    crate::error!("sampling failed: {e}");
                }
                continue;
            }
        };
        if let Some(f) = feed.as_mut() {
            f.poll(now);
        }
        let a_ = engine.step(&s);
        let m = &a_.metrics;

        scanner.set_fast(a_.level >= Level::Warn);
        if let Some(f) = feed.as_mut() {
            f.set_fast(a_.level >= Level::Warn);
        }

        if a_.level != last_level {
            crate::info!(
                "level {} -> {} (reasons={} avail={} free={} free2m={} rate={} proj={} psi_some={:.2} psi_full={:.2} swap_used={} gate={})",
                last_level.as_str(),
                a_.level.as_str(),
                a_.reasons.describe(),
                fmt_bytes(s.avail),
                fmt_bytes(s.free),
                fmt_bytes(s.free2m),
                fmt_rate(m.rate),
                fmt_bytes(m.proj.max(0) as u64),
                m.psi_some_1s,
                m.psi_full_1s,
                fmt_bytes(m.swap_used),
                a_.gate.as_str()
            );
            if let Some(sd) = &sd {
                sd.status(&format!(
                    "{}{} avail={} kills={}",
                    if dry_run { "DRY-RUN " } else { "" },
                    a_.level.as_str(),
                    fmt_bytes(s.avail),
                    engine.kills_total
                ));
            }
            last_level = a_.level;
        }

        if !dry_run && a_.want_reclaim > 0 {
            if let Some(r) = &reclaimer {
                if r.request(a_.want_reclaim) && rl.allow(3, now, 10_000_000_000) {
                    crate::info!(
                        "headroom: free={} < {}; reclaiming {} of file cache",
                        fmt_bytes(s.free),
                        fmt_bytes(engine.cfg.headroom),
                        fmt_bytes(a_.want_reclaim)
                    );
                }
            }
        }

        escalations.retain(|(targets, dl)| {
            if dry_run {
                return false;
            }
            if now < *dl {
                return true;
            }
            let n = actuator::signal_pids(targets, libc::SIGKILL);
            crate::warn!("grace expired: SIGKILL sent to {n} surviving process(es)");
            false
        });

        if let Some(v) = engine.verification().copied() {
            let alive = dying.keys().any(|p| p.pid == v.pid && p.alive());
            let in_d = procfs::state(v.pid) == Some(b'D');
            if let Some(outcome) = engine.verify_tick(now, alive, in_d, s.avail, a_.level) {
                match outcome {
                    VerifyOutcome::Recovered => crate::info!("kill of pid {} verified: avail {} -> {} ({} ms)", v.pid, fmt_bytes(v.avail_at_kill), fmt_bytes(s.avail), (now - v.started_ns) / 1_000_000),
                    VerifyOutcome::NoEffect => crate::warn!("kill of pid {} had no measurable effect (avail {} -> {}); backing off {} ms", v.pid, fmt_bytes(v.avail_at_kill), fmt_bytes(s.avail), engine.backoff_remaining_ns(now) / 1_000_000),
                    VerifyOutcome::Stuck => crate::error!("pid {} is still alive in uninterruptible sleep after SIGKILL: likely wedged in the driver; a reboot may be required", v.pid),
                    VerifyOutcome::VictimAliveTimeout => crate::warn!("pid {} still alive {} ms after the signal (slow teardown?); backing off", v.pid, (now - v.started_ns) / 1_000_000),
                }
                if let Some(sd) = &sd {
                    sd.status(&format!(
                        "{} last kill pid {}: {:?}",
                        a_.level.as_str(),
                        v.pid,
                        outcome
                    ));
                }
            }
        }

        dying.retain(|identity, t| {
            procfs::starttime(identity.pid) == Some(identity.starttime)
                && (now.saturating_sub(*t) < 10_000_000_000 || identity.alive())
        });

        let table = scanner.table();
        let table_changed = table.t_ns != last_rank_table_ns && !table.is_empty();
        let mut next_history = None;
        if table_changed
            && (a_.level >= Level::Warn || now.saturating_sub(last_rank_table_ns) >= 1_000_000_000)
        {
            last_rank_table_ns = table.t_ns;
            let exclude = exclusion_set(self_pid, feed.as_ref(), &dying);
            let empty = HashSet::new();
            let snap = feed
                .as_ref()
                .map(|f| f.snapshot().clone())
                .unwrap_or_default();
            let seen = feed.as_ref().map(|f| &f.cuda_seen).unwrap_or(&empty);
            let r = victim::rank(&RankInput {
                table: &table,
                nvml: &snap,
                now_ns: now,
                cfg: &vcfg,
                hist: &hist,
                exclude: &exclude,
                cuda_seen: seen,
                total,
            });
            next_history = Some(r.all);
            if let Some(f) = feed.as_ref() {
                let pids: Vec<u32> = f.snapshot().procs.iter().map(|p| p.pid).collect();
                scanner.set_maps_for(&pids);
            }
            if a_.level >= Level::Warn && rl.allow(4, now, 5_000_000_000) {
                if let Some(top) = r.cands.first() {
                    crate::info!("top candidate: {}", top.describe());
                }
            }
        }

        if a_.may_kill {
            let exclude = exclusion_set(self_pid, feed.as_ref(), &dying);
            let empty = HashSet::new();
            let snap = feed
                .as_ref()
                .map(|f| f.snapshot().clone())
                .unwrap_or_default();
            let seen = feed.as_ref().map(|f| &f.cuda_seen).unwrap_or(&empty);
            let r = victim::rank(&RankInput {
                table: &table,
                nvml: &snap,
                now_ns: now,
                cfg: &vcfg,
                hist: &hist,
                exclude: &exclude,
                cuda_seen: seen,
                total,
            });
            match victim::choose(&r, &table, &vcfg) {
                None => {
                    if rl.allow(5, now, 2_000_000_000) {
                        crate::error!(
                            "CRITICAL ({}) but no eligible victim (avail={} min_victim={} skipped_never={}{})",
                            a_.reasons.describe(),
                            fmt_bytes(s.avail),
                            fmt_bytes(vcfg.min_victim),
                            r.skipped_never,
                            r.top_immune.as_ref().map(|t| format!("; immune pid {} holds {}", t.pid, fmt_bytes(t.tree_footprint))).unwrap_or_default()
                        );
                    }
                }
                Some(choice) => {
                    let c = &choice.cand;
                    let test_mismatch = !cfg.only_kill_exe.is_empty()
                        && !(crate::config::glob_match(&cfg.only_kill_exe, &c.exe)
                            || crate::config::glob_match(
                                &cfg.only_kill_exe,
                                c.exe.rsplit('/').next().unwrap_or(""),
                            )
                            || crate::config::glob_match(&cfg.only_kill_exe, &c.comm));
                    if dry_run || test_mismatch {
                        if rl.allow(1000 + c.pid as u64, now, 2_000_000_000) {
                            crate::warn!(
                                "{} would kill ({}; avail={} rate={} psi_full={:.2}): {} plan={:?}{}",
                                if dry_run { "DRY-RUN" } else { "TEST-MODE" },
                                a_.reasons.describe(),
                                fmt_bytes(s.avail),
                                fmt_rate(m.rate),
                                m.psi_full_1s,
                                c.describe(),
                                choice.plan,
                                if r.nvml_fresh { "" } else { " [nvml stale]" }
                            );
                        }
                    } else {
                        let out = actuator::execute(
                            &choice.plan,
                            c.pid,
                            c.starttime,
                            &choice.targets,
                            cfg.signal,
                            false,
                        );
                        if out.aborted_pid_reuse {
                            crate::warn!("pid {} changed identity before the kill; aborted", c.pid);
                        } else if out.method == "gone" {
                            crate::info!("victim pid {} exited before the kill", c.pid);
                            dying.insert(
                                ProcessIdentity {
                                    pid: c.pid,
                                    starttime: c.starttime,
                                },
                                now,
                            );
                        } else if out.signaled.is_empty() {
                            if rl.allow(6, now, 2_000_000_000) {
                                crate::error!("kill failed for pid {}: {:?}", c.pid, out.failed);
                            }
                        } else {
                            crate::error!(
                                "KILL ({}; avail={} free={} rate={} psi_full={:.2}{}) via {}: {} plan={:?} signaled={:?}{}{}",
                                a_.reasons.describe(),
                                fmt_bytes(s.avail),
                                fmt_bytes(s.free),
                                fmt_rate(m.rate),
                                m.psi_full_1s,
                                if r.nvml_fresh { "" } else { "; nvml stale" },
                                out.method,
                                c.describe(),
                                choice.plan,
                                out.signaled,
                                if out.failed.is_empty() { String::new() } else { format!(" failed={:?}", out.failed) },
                                if choice.immune_override { " [oom_score_adj=-1000 overridden]" } else { "" }
                            );
                            engine.record_kill(now, c.pid, c.key(), c.tree_footprint, s.avail);
                            last_kill_desc = format!(
                                "{} pid={} comm={} fp={}",
                                crate::unix_secs(),
                                c.pid,
                                c.comm,
                                fmt_bytes(c.tree_footprint)
                            );
                            for target in &choice.targets {
                                if out.method == "cgroup.kill" || out.signaled.contains(&target.pid)
                                {
                                    dying.insert(*target, now);
                                }
                            }
                            if cfg.signal == KillSignal::Term {
                                escalations
                                    .push((choice.targets.clone(), now + cfg.grace_ms * 1_000_000));
                            }
                            if cfg.stop_unit_after_kill && choice.stop_unit_allowed {
                                if let Some(unit) = cgroup::system_service_unit(&c.cgroup) {
                                    crate::warn!("stopping {unit} so Restart= cannot relaunch the same job into the same crash");
                                    actuator::stop_unit_async(unit);
                                }
                            }
                            if let Some(sd) = &sd {
                                sd.status(&format!("CRITICAL: killed pid {} ({})", c.pid, c.comm));
                            }
                        }
                    }
                }
            }
        }

        if let Some(candidates) = next_history {
            hist.update(&candidates, now);
        }
        if recording {
            outputs.send(OutputEvent::Trace(format!(
                "{},{},{},{},{},{},{},{},{},{},{},{}\n",
                s.t_ns,
                s.total,
                s.free,
                s.avail,
                s.free2m,
                s.swap_total,
                s.swap_free,
                s.psi_some_us,
                s.psi_full_us,
                a_.level.as_str(),
                a_.may_kill as u8,
                a_.gate.as_str()
            )));
        }
        if now.saturating_sub(last_hz) >= 1_000_000_000 {
            last_hz = now;
            if let Some(sd) = &sd {
                sd.watchdog();
            }
            let nvml_desc = feed
                .as_ref()
                .map(|f| f.describe(now))
                .unwrap_or_else(|| "disabled".into());
            let (nvml_age, nvml_n, nvml_status) = feed
                .as_ref()
                .map(|f| {
                    (
                        f.age_ns(now) / 1_000_000,
                        f.snapshot().procs.len(),
                        f.stats.status,
                    )
                })
                .unwrap_or((u64::MAX, 0, -1));
            let rstats = reclaimer.as_ref().map(|r| r.stats()).unwrap_or_default();
            let content = format!(
                "version={}\npid={}\nts_unix={}\nmono_ns={}\ntick={}\nlevel={}\ngate={}\ndry_run={}\ntest_mode={}\ntotal={}\nfree={}\navail={}\nfree2m={}\nswap_total={}\nswap_used={}\nrate={:.0}\nproj={}\npsi_some_1s={:.3}\npsi_full_1s={:.3}\nfloor={}\nwarn={}\nheadroom={}\nnvml_age_ms={}\nnvml_procs={}\nnvml_status={}\nnvml={}\nkills_total={}\nlast_kill={}\nreclaims={}\nreclaim_bytes={}\nreclaim_disabled={}\nreclaim_error={}\nscan_age_ms={}\nscan_us={}\nlate_ticks={}\nlog_dropped={}\n",
                env!("CARGO_PKG_VERSION"),
                self_pid,
                crate::unix_secs(),
                now,
                a_.tick,
                a_.level.as_str(),
                a_.gate.as_str(),
                dry_run as u8,
                !cfg.only_kill_exe.is_empty() as u8,
                s.total,
                s.free,
                s.avail,
                s.free2m,
                s.swap_total,
                m.swap_used,
                m.rate,
                m.proj,
                m.psi_some_1s,
                m.psi_full_1s,
                engine.cfg.floor,
                engine.cfg.warn,
                engine.cfg.headroom,
                if nvml_age == u64::MAX { -1 } else { nvml_age as i64 },
                nvml_n,
                nvml_status,
                nvml_desc,
                engine.kills_total,
                last_kill_desc,
                rstats.done,
                rstats.bytes_total,
                rstats.disabled as u8,
                rstats.last_error,
                now.saturating_sub(table.t_ns) / 1_000_000,
                table.scan_us,
                late_ticks,
                crate::log::dropped_lines()
            );
            outputs.send(OutputEvent::Status(format!(
                "{content}starttime={self_start}\n"
            )));
            if a_.level >= Level::Warn {
                crate::debug!("tick {} {} avail={} free={} rate={} psi_some={:.2} psi_full={:.2} gate={} nvml={}", a_.tick, a_.level.as_str(), fmt_bytes(s.avail), fmt_bytes(s.free), fmt_rate(m.rate), m.psi_some_1s, m.psi_full_1s, a_.gate.as_str(), nvml_desc);
            }
        }
    }

    crate::info!("memguard stopping (kills={})", engine.kills_total);
    if let Some(sd) = &sd {
        sd.stopping();
    }
    outputs.send(OutputEvent::Status(format!(
        "version={}\npid={}\nts_unix={}\nmono_ns=0\nlevel=STOPPED\n",
        env!("CARGO_PKG_VERSION"),
        self_pid,
        crate::unix_secs()
    )));
    outputs.stop();
    if let Some(mut f) = feed.take() {
        f.shutdown();
    }
    scanner.stop();
    if let Some(r) = reclaimer {
        r.stop();
    }
    Ok(())
}

fn exclusion_set(
    self_pid: u32,
    feed: Option<&NvmlFeed>,
    dying: &HashMap<ProcessIdentity, u64>,
) -> HashSet<u32> {
    let mut ex: HashSet<u32> = dying.keys().map(|p| p.pid).collect();
    ex.insert(self_pid);
    if let Some(h) = feed.and_then(|f| f.helper_pid()) {
        ex.insert(h);
    }
    ex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reload_retains_cli_safety_restrictions() {
        let path = std::env::temp_dir().join(format!(
            "memguard-reload-{}-{}",
            std::process::id(),
            crate::mono_ns()
        ));
        std::fs::write(&path, "action=kill\nonly_kill_exe=anything\n").unwrap();
        let args = DaemonArgs {
            config_path: path.to_string_lossy().into_owned(),
            config_explicit: true,
            overrides: vec!["floor=6G".into()],
            dry_run: true,
            only_kill_exe: Some("/opt/test-hog".into()),
            record: Some("trace.csv".into()),
            verbose: false,
        };
        for _ in 0..2 {
            let cfg = args.load_config().unwrap();
            assert_eq!(cfg.action, Action::DryRun);
            assert_eq!(cfg.only_kill_exe, "/opt/test-hog");
            assert_eq!(cfg.record, "trace.csv");
            assert_eq!(cfg.floor.resolve(120 << 30), 6 << 30);
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn floor_is_not_deferred_to_dry_run_test_stopped_or_reused_daemon() {
        let path = std::env::temp_dir().join(format!(
            "memguard-status-test-{}-{}",
            std::process::id(),
            crate::mono_ns()
        ));
        let path_str = path.to_str().unwrap();
        let me = ProcessIdentity::read(std::process::id()).unwrap();
        for (time, dry, test, level, start, expected) in [
            (100, 0, 0, "OK", me.starttime, true),
            (100, 1, 0, "OK", me.starttime, false),
            (100, 0, 1, "OK", me.starttime, false),
            (100, 0, 0, "STOPPED", me.starttime, false),
            (201, 0, 0, "OK", me.starttime, false),
            (100, 0, 0, "OK", me.starttime + 1, false),
            (0, 0, 0, "OK", me.starttime, false),
        ] {
            std::fs::write(&path, format!("pid={}\nstarttime={start}\nmono_ns={time}\ndry_run={dry}\ntest_mode={test}\nlevel={level}\n", me.pid)).unwrap();
            assert_eq!(daemon_fresh(path_str, 200, 150), expected);
        }
        std::fs::remove_file(path).unwrap();
    }
}
