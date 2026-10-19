//! Configuration: defaults, `key = value` file parsing, `-o key=value` overrides and validation.
//!
//! The file format is deliberately tiny: one `key = value` per line, `#` comments, quoted strings
//! optional, lists as `[a, b*, "c"]`. Sizes accept `8G`/`512M`/`5%`, durations `150ms`/`2s`,
//! fractions `0.30`/`30%`.

use crate::units::{
    fmt_bytes, parse_bool, parse_duration_ms, parse_fraction, parse_size_spec, SizeSpec,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Kill,
    DryRun,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KillSignal {
    Kill,
    Term,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KillMode {
    Auto,
    Process,
    Tree,
    Cgroup,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VidmemCharged {
    Auto,
    Yes,
    No,
}

pub const DEFAULT_CONFIG_PATH: &str = "/etc/memguard/memguard.conf";

/// Executables that must never be killed (matched on exe basename and comm).
pub const BUILTIN_NEVER_EXE: &[&str] = &[
    "systemd",
    "systemd-*",
    "(sd-pam)",
    "init",
    "sshd",
    "dbus-daemon",
    "dbus-broker",
    "dbus-broker-launch",
    "memguard",
];

/// Executables that are only killed when nothing else is plausible (score x 0.5).
pub const BUILTIN_AVOID_EXE: &[&str] = &[
    "Xorg",
    "Xwayland",
    "gnome-shell",
    "gdm*",
    "mutter*",
    "tmux*",
    "screen",
    "dockerd",
    "containerd*",
    "tailscaled",
    "NetworkManager",
    "pipewire*",
    "wireplumber",
    "nvidia-persistenced",
    "polkitd",
    "snapd",
    "cron",
    "rsyslogd",
    "udisksd",
    "login",
    "su",
    "sudo",
    "bash",
    "zsh",
    "sh",
    "dash",
    "fish",
];

#[derive(Clone, Debug)]
pub struct Config {
    pub interval_ms: u64,
    pub scan_interval_ms: u64,
    pub warn_scan_interval_ms: u64,
    pub floor: SizeSpec,
    pub warn: SizeSpec,
    pub horizon_ms: u64,
    pub rate_ema_ms: u64,
    pub rate_min: SizeSpec,
    pub rate_warn: SizeSpec,
    pub psi_window_ms: u64,
    pub psi_full_critical: f64,
    pub psi_full_emergency: f64,
    pub psi_some_warn: f64,
    pub swap_rate_critical: SizeSpec,
    pub headroom: SizeSpec,
    pub headroom_reclaim: bool,
    pub action: Action,
    pub signal: KillSignal,
    pub grace_ms: u64,
    pub kill_mode: KillMode,
    pub cgroup_kill_match: Vec<String>,
    pub stop_unit_after_kill: bool,
    pub debounce_ticks: u32,
    pub cooldown_ms: u64,
    pub emergency_cooldown_ms: u64,
    pub verify_ms: u64,
    pub backoff_ms: Vec<u64>,
    pub max_kills_per_min: u32,
    pub max_kills_per_10min: u32,
    pub min_victim: SizeSpec,
    pub never_exe: Vec<String>,
    pub never_cgroup: Vec<String>,
    pub avoid_exe: Vec<String>,
    pub prefer_exe: Vec<String>,
    pub immune_override_pct: f64,
    pub shmem_weight: f64,
    pub growth_weight: f64,
    pub cuda_file_rss_weight: f64,
    pub vidmem_charged: VidmemCharged,
    pub status_file: String,
    pub log_level: String,
    pub mlock: bool,
    pub allow_coexist: bool,
    pub allow_huge_floor: bool,
    pub only_kill_exe: String,
    pub record: String,
    pub startup_grace_ticks: u32,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            interval_ms: 50,
            scan_interval_ms: 2000,
            warn_scan_interval_ms: 250,
            floor: SizeSpec::Bytes(8 << 30),
            warn: SizeSpec::Bytes(16 << 30),
            horizon_ms: 150,
            rate_ema_ms: 200,
            rate_min: SizeSpec::Bytes(1 << 30),
            rate_warn: SizeSpec::Bytes(4 << 30),
            psi_window_ms: 1000,
            psi_full_critical: 0.30,
            psi_full_emergency: 0.60,
            psi_some_warn: 0.20,
            swap_rate_critical: SizeSpec::Bytes(512 << 20),
            headroom: SizeSpec::Bytes(4 << 30),
            headroom_reclaim: true,
            action: Action::Kill,
            signal: KillSignal::Kill,
            grace_ms: 0,
            kill_mode: KillMode::Auto,
            cgroup_kill_match: vec![
                "docker-*.scope".into(),
                "libpod-*.scope".into(),
                "cri-containerd-*.scope".into(),
                "memguard-*.scope".into(),
            ],
            stop_unit_after_kill: true,
            debounce_ticks: 2,
            cooldown_ms: 2000,
            emergency_cooldown_ms: 500,
            verify_ms: 5000,
            backoff_ms: vec![10_000, 30_000, 60_000],
            max_kills_per_min: 3,
            max_kills_per_10min: 6,
            min_victim: SizeSpec::Bytes(512 << 20),
            never_exe: BUILTIN_NEVER_EXE.iter().map(|s| s.to_string()).collect(),
            never_cgroup: vec!["/init.scope".into()],
            avoid_exe: BUILTIN_AVOID_EXE.iter().map(|s| s.to_string()).collect(),
            prefer_exe: Vec::new(),
            immune_override_pct: 50.0,
            shmem_weight: 0.5,
            growth_weight: 2.0,
            cuda_file_rss_weight: 0.0,
            vidmem_charged: VidmemCharged::Auto,
            status_file: "/run/memguard/status".into(),
            log_level: "info".into(),
            mlock: true,
            allow_coexist: false,
            allow_huge_floor: false,
            only_kill_exe: String::new(),
            record: String::new(),
            startup_grace_ticks: 5,
        }
    }
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Parse `[a, b, "c d"]` or `a, b` into a list of trimmed, unquoted strings. `[]` is empty.
pub fn parse_list(v: &str) -> Vec<String> {
    let v = v.trim();
    let inner = if v.starts_with('[') && v.ends_with(']') {
        &v[1..v.len() - 1]
    } else {
        v
    };
    inner
        .split(',')
        .map(unquote)
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_u64_list(v: &str) -> Result<Vec<u64>, String> {
    parse_list(v).iter().map(|s| parse_duration_ms(s)).collect()
}

fn parse_u32(v: &str) -> Result<u32, String> {
    v.trim()
        .parse::<u32>()
        .map_err(|_| format!("invalid integer '{v}'"))
}

fn parse_f64(v: &str) -> Result<f64, String> {
    let x: f64 = v
        .trim()
        .parse()
        .map_err(|_| format!("invalid number '{v}'"))?;
    if !x.is_finite() || x < 0.0 {
        return Err(format!("invalid number '{v}'"));
    }
    Ok(x)
}

impl Config {
    /// Apply one `key = value` pair. Unknown keys are errors.
    pub fn apply(&mut self, key: &str, value: &str) -> Result<(), String> {
        let v = value.trim();
        let uq = unquote(v);
        match key.trim() {
            "interval_ms" => self.interval_ms = parse_duration_ms(v)?,
            "scan_interval_ms" => self.scan_interval_ms = parse_duration_ms(v)?,
            "warn_scan_interval_ms" => self.warn_scan_interval_ms = parse_duration_ms(v)?,
            "floor" => self.floor = parse_size_spec(v)?,
            "warn" => self.warn = parse_size_spec(v)?,
            "horizon_ms" => self.horizon_ms = parse_duration_ms(v)?,
            "rate_ema_ms" => self.rate_ema_ms = parse_duration_ms(v)?,
            "rate_min" => self.rate_min = parse_size_spec(v)?,
            "rate_warn" => self.rate_warn = parse_size_spec(v)?,
            "psi_window_ms" => self.psi_window_ms = parse_duration_ms(v)?,
            "psi_full_critical" => self.psi_full_critical = parse_fraction(v)?,
            "psi_full_emergency" => self.psi_full_emergency = parse_fraction(v)?,
            "psi_some_warn" => self.psi_some_warn = parse_fraction(v)?,
            "swap_rate_critical" => self.swap_rate_critical = parse_size_spec(v)?,
            "headroom" => self.headroom = parse_size_spec(v)?,
            "headroom_reclaim" => self.headroom_reclaim = parse_bool(v)?,
            "action" => {
                self.action = match uq.to_ascii_lowercase().as_str() {
                    "kill" => Action::Kill,
                    "dry-run" | "dry_run" | "dryrun" => Action::DryRun,
                    other => return Err(format!("action must be kill|dry-run, got '{other}'")),
                }
            }
            "signal" => {
                self.signal = match uq.to_ascii_uppercase().as_str() {
                    "KILL" | "SIGKILL" | "9" => KillSignal::Kill,
                    "TERM" | "SIGTERM" | "15" => KillSignal::Term,
                    other => return Err(format!("signal must be KILL|TERM, got '{other}'")),
                }
            }
            "grace_ms" => self.grace_ms = parse_duration_ms(v)?,
            "kill_mode" => {
                self.kill_mode = match uq.to_ascii_lowercase().as_str() {
                    "auto" => KillMode::Auto,
                    "process" => KillMode::Process,
                    "tree" => KillMode::Tree,
                    "cgroup" => KillMode::Cgroup,
                    other => {
                        return Err(format!(
                            "kill_mode must be auto|process|tree|cgroup, got '{other}'"
                        ))
                    }
                }
            }
            "cgroup_kill_match" => self.cgroup_kill_match = parse_list(v),
            "stop_unit_after_kill" => self.stop_unit_after_kill = parse_bool(v)?,
            "debounce_ticks" => self.debounce_ticks = parse_u32(v)?,
            "cooldown_ms" => self.cooldown_ms = parse_duration_ms(v)?,
            "emergency_cooldown_ms" => self.emergency_cooldown_ms = parse_duration_ms(v)?,
            "verify_ms" => self.verify_ms = parse_duration_ms(v)?,
            "backoff_ms" => self.backoff_ms = parse_u64_list(v)?,
            "max_kills_per_min" => self.max_kills_per_min = parse_u32(v)?,
            "max_kills_per_10min" => self.max_kills_per_10min = parse_u32(v)?,
            "min_victim" => self.min_victim = parse_size_spec(v)?,
            "never_exe" => self.never_exe = merge_builtin(BUILTIN_NEVER_EXE, parse_list(v)),
            "never_cgroup" => self.never_cgroup = parse_list(v),
            "avoid_exe" => self.avoid_exe = merge_builtin(BUILTIN_AVOID_EXE, parse_list(v)),
            "prefer_exe" => self.prefer_exe = parse_list(v),
            "immune_override_pct" => {
                self.immune_override_pct = if uq.eq_ignore_ascii_case("off") {
                    0.0
                } else {
                    parse_f64(uq.trim_end_matches('%'))?
                }
            }
            "shmem_weight" => self.shmem_weight = parse_f64(v)?,
            "growth_weight" => self.growth_weight = parse_f64(v)?,
            "cuda_file_rss_weight" => self.cuda_file_rss_weight = parse_f64(v)?,
            "vidmem_charged" => {
                self.vidmem_charged = match uq.to_ascii_lowercase().as_str() {
                    "auto" => VidmemCharged::Auto,
                    "yes" | "true" | "1" => VidmemCharged::Yes,
                    "no" | "false" | "0" => VidmemCharged::No,
                    other => {
                        return Err(format!("vidmem_charged must be auto|yes|no, got '{other}'"))
                    }
                }
            }
            "status_file" => self.status_file = uq,
            "log_level" => match uq.to_ascii_lowercase().as_str() {
                "error" | "warn" | "info" | "debug" => self.log_level = uq.to_ascii_lowercase(),
                other => {
                    return Err(format!(
                        "log_level must be error|warn|info|debug, got '{other}'"
                    ))
                }
            },
            "mlock" => self.mlock = parse_bool(v)?,
            "allow_coexist" => self.allow_coexist = parse_bool(v)?,
            "allow_huge_floor" => self.allow_huge_floor = parse_bool(v)?,
            "only_kill_exe" => self.only_kill_exe = uq,
            "record" => self.record = uq,
            "startup_grace_ticks" => self.startup_grace_ticks = parse_u32(v)?,
            other => return Err(format!("unknown key '{other}'")),
        }
        Ok(())
    }

    /// Apply a `key=value` override (from `-o`).
    pub fn apply_override(&mut self, kv: &str) -> Result<(), String> {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| format!("override '{kv}' is not key=value"))?;
        self.apply(k, v)
            .map_err(|e| format!("override '{kv}': {e}"))
    }

    /// Parse config text into `self`. Errors carry the line number.
    pub fn parse_text(&mut self, text: &str) -> Result<(), String> {
        for (i, raw) in text.lines().enumerate() {
            let mut quote = None;
            let mut end = raw.len();
            for (idx, ch) in raw.char_indices() {
                match (quote, ch) {
                    (None, '\'' | '"') => quote = Some(ch),
                    (Some(q), c) if q == c => quote = None,
                    (None, '#') => {
                        end = idx;
                        break;
                    }
                    _ => {}
                }
            }
            if quote.is_some() {
                return Err(format!("line {}: unterminated quote", i + 1));
            }
            let line = &raw[..end];
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (k, v) = line
                .split_once('=')
                .ok_or_else(|| format!("line {}: expected key = value", i + 1))?;
            self.apply(k, v)
                .map_err(|e| format!("line {}: {e}", i + 1))?;
        }
        Ok(())
    }

    /// Load from a file on top of defaults. A missing file at the default path yields defaults.
    pub fn load(path: &str, must_exist: bool) -> Result<Config, String> {
        let mut cfg = Config::default();
        match std::fs::read_to_string(path) {
            Ok(text) => cfg.parse_text(&text).map_err(|e| format!("{path}: {e}"))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !must_exist => {}
            Err(e) => return Err(format!("{path}: {e}")),
        }
        Ok(cfg)
    }

    /// Validate against the machine's total RAM.
    pub fn validate(&self, total: u64) -> Result<(), String> {
        // Keep millisecond-to-nanosecond conversions and deadline additions bounded.
        for (name, value) in [
            ("scan_interval_ms", self.scan_interval_ms),
            ("warn_scan_interval_ms", self.warn_scan_interval_ms),
            ("rate_ema_ms", self.rate_ema_ms),
            ("grace_ms", self.grace_ms),
            ("cooldown_ms", self.cooldown_ms),
            ("emergency_cooldown_ms", self.emergency_cooldown_ms),
            ("verify_ms", self.verify_ms),
        ] {
            if value > 86_400_000 {
                return Err(format!("{name} must be at most 24 hours"));
            }
        }
        if self.backoff_ms.iter().any(|v| *v > 86_400_000) {
            return Err("backoff_ms entries must be at most 24 hours".into());
        }
        if self.scan_interval_ms < 100 || self.warn_scan_interval_ms < 50 {
            return Err("scan intervals must be >= 100 ms (normal) and >= 50 ms (warn)".into());
        }
        if self.rate_ema_ms == 0 || self.verify_ms == 0 {
            return Err("rate_ema_ms and verify_ms must be positive".into());
        }
        if self.signal == KillSignal::Term && self.grace_ms > self.verify_ms {
            return Err("grace_ms must not exceed verify_ms".into());
        }
        if self.psi_window_ms > self.interval_ms.saturating_mul(255) {
            return Err("psi_window_ms exceeds the 256-sample PSI history; shorten it or increase interval_ms".into());
        }
        if self.interval_ms < 10 || self.interval_ms > 5000 {
            return Err("interval_ms must be within 10..5000".into());
        }
        let floor = self.floor.resolve(total);
        let warn = self.warn.resolve(total);
        if self.headroom.resolve(total) > total {
            return Err("headroom must not exceed MemTotal".into());
        }
        if floor == 0 {
            return Err("floor must be > 0".into());
        }
        if floor >= warn {
            return Err(format!(
                "floor ({}) must be below warn ({})",
                fmt_bytes(floor),
                fmt_bytes(warn)
            ));
        }
        if warn >= total {
            return Err(format!(
                "warn ({}) must be below MemTotal ({})",
                fmt_bytes(warn),
                fmt_bytes(total)
            ));
        }
        if floor > total / 2 && !self.allow_huge_floor {
            return Err(format!(
                "floor ({}) is above 50% of RAM; set allow_huge_floor = true if this is intended (tests only)",
                fmt_bytes(floor)
            ));
        }
        if self.horizon_ms == 0 || self.horizon_ms > 10_000 {
            return Err("horizon_ms must be within 1..10000".into());
        }
        if self.psi_window_ms < 200 || self.psi_window_ms > 60_000 {
            return Err("psi_window_ms must be within 200..60000".into());
        }
        if self.psi_full_emergency < self.psi_full_critical {
            return Err("psi_full_emergency must be >= psi_full_critical".into());
        }
        if self.debounce_ticks == 0 {
            return Err("debounce_ticks must be >= 1".into());
        }
        if self.backoff_ms.is_empty() {
            return Err("backoff_ms must have at least one entry".into());
        }
        if self.max_kills_per_min == 0 || self.max_kills_per_10min == 0 {
            return Err("max_kills_per_* must be >= 1".into());
        }
        if self.shmem_weight > 1.0 {
            return Err("shmem_weight must be within 0..1".into());
        }
        if self.cuda_file_rss_weight > 1.0 {
            return Err("cuda_file_rss_weight must be within 0..1".into());
        }
        if self.immune_override_pct > 100.0 {
            return Err("immune_override_pct must be within 0..100 or off".into());
        }
        Ok(())
    }

    /// Multi-line summary of the effective configuration.
    pub fn describe(&self, total: u64) -> String {
        let mut s = String::new();
        let line = |s: &mut String, k: &str, v: String| s.push_str(&format!("{k:<22} = {v}\n"));
        line(&mut s, "interval_ms", self.interval_ms.to_string());
        line(
            &mut s,
            "floor",
            format!("{} ({})", self.floor, fmt_bytes(self.floor.resolve(total))),
        );
        line(
            &mut s,
            "warn",
            format!("{} ({})", self.warn, fmt_bytes(self.warn.resolve(total))),
        );
        line(&mut s, "horizon_ms", self.horizon_ms.to_string());
        line(&mut s, "rate_ema_ms", self.rate_ema_ms.to_string());
        line(
            &mut s,
            "rate_min",
            format!("{}/s", fmt_bytes(self.rate_min.resolve(total))),
        );
        line(
            &mut s,
            "rate_warn",
            format!("{}/s", fmt_bytes(self.rate_warn.resolve(total))),
        );
        line(&mut s, "psi_window_ms", self.psi_window_ms.to_string());
        line(
            &mut s,
            "psi_full_critical",
            format!("{:.2}", self.psi_full_critical),
        );
        line(
            &mut s,
            "psi_full_emergency",
            format!("{:.2}", self.psi_full_emergency),
        );
        line(
            &mut s,
            "psi_some_warn",
            format!("{:.2}", self.psi_some_warn),
        );
        line(
            &mut s,
            "swap_rate_critical",
            format!("{}/s", fmt_bytes(self.swap_rate_critical.resolve(total))),
        );
        line(
            &mut s,
            "headroom",
            format!(
                "{} ({})",
                self.headroom,
                fmt_bytes(self.headroom.resolve(total))
            ),
        );
        line(
            &mut s,
            "headroom_reclaim",
            self.headroom_reclaim.to_string(),
        );
        line(
            &mut s,
            "action",
            format!("{:?}", self.action).to_lowercase(),
        );
        line(
            &mut s,
            "signal",
            format!("{:?}", self.signal).to_uppercase(),
        );
        line(&mut s, "grace_ms", self.grace_ms.to_string());
        line(
            &mut s,
            "kill_mode",
            format!("{:?}", self.kill_mode).to_lowercase(),
        );
        line(
            &mut s,
            "cgroup_kill_match",
            format!("{:?}", self.cgroup_kill_match),
        );
        line(
            &mut s,
            "stop_unit_after_kill",
            self.stop_unit_after_kill.to_string(),
        );
        line(&mut s, "debounce_ticks", self.debounce_ticks.to_string());
        line(&mut s, "cooldown_ms", self.cooldown_ms.to_string());
        line(
            &mut s,
            "emergency_cooldown_ms",
            self.emergency_cooldown_ms.to_string(),
        );
        line(&mut s, "verify_ms", self.verify_ms.to_string());
        line(&mut s, "backoff_ms", format!("{:?}", self.backoff_ms));
        line(
            &mut s,
            "max_kills_per_min",
            self.max_kills_per_min.to_string(),
        );
        line(
            &mut s,
            "max_kills_per_10min",
            self.max_kills_per_10min.to_string(),
        );
        line(
            &mut s,
            "min_victim",
            fmt_bytes(self.min_victim.resolve(total)),
        );
        line(&mut s, "never_exe", format!("{:?}", self.never_exe));
        line(&mut s, "never_cgroup", format!("{:?}", self.never_cgroup));
        line(&mut s, "avoid_exe", format!("{:?}", self.avoid_exe));
        line(&mut s, "prefer_exe", format!("{:?}", self.prefer_exe));
        line(
            &mut s,
            "immune_override_pct",
            format!("{}", self.immune_override_pct),
        );
        line(&mut s, "shmem_weight", format!("{}", self.shmem_weight));
        line(&mut s, "growth_weight", format!("{}", self.growth_weight));
        line(
            &mut s,
            "cuda_file_rss_weight",
            format!("{}", self.cuda_file_rss_weight),
        );
        line(
            &mut s,
            "vidmem_charged",
            format!("{:?}", self.vidmem_charged).to_lowercase(),
        );
        line(&mut s, "status_file", self.status_file.clone());
        line(&mut s, "log_level", self.log_level.clone());
        line(&mut s, "mlock", self.mlock.to_string());
        line(&mut s, "allow_coexist", self.allow_coexist.to_string());
        line(
            &mut s,
            "only_kill_exe",
            if self.only_kill_exe.is_empty() {
                "(unset)".into()
            } else {
                self.only_kill_exe.clone()
            },
        );
        line(
            &mut s,
            "record",
            if self.record.is_empty() {
                "(unset)".into()
            } else {
                self.record.clone()
            },
        );
        s
    }
}

/// User-provided list entries are added to the builtin ones; a leading `!` removes a builtin entry.
fn merge_builtin(builtin: &[&str], user: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = builtin.iter().map(|s| s.to_string()).collect();
    for u in user {
        if let Some(stripped) = u.strip_prefix('!') {
            out.retain(|b| b != stripped);
        } else if !out.contains(&u) {
            out.push(u);
        }
    }
    out
}

/// Shell-style glob match supporting `*` (any run) and `?` (one char). Case-sensitive.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_p, mut star_t) = (usize::MAX, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_p = pi;
            star_t = ti;
            pi += 1;
        } else if star_p != usize::MAX {
            pi = star_p + 1;
            star_t += 1;
            ti = star_t;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Path patterns match exe only; bare patterns match its basename or comm.
pub fn matches_any(globs: &[String], exe: &str, comm: &str) -> bool {
    globs.iter().any(|g| {
        if g.contains('/') {
            glob_match(g, exe.strip_suffix(" (deleted)").unwrap_or(exe))
        } else {
            (!exe.is_empty() && glob_match(g, basename(exe)))
                || (!comm.is_empty() && glob_match(g, comm))
        }
    })
}

/// Basename of a path ("/usr/bin/python3.12" -> "python3.12"); deleted executables lose " (deleted)".
pub fn basename(path: &str) -> &str {
    let p = path.strip_suffix(" (deleted)").unwrap_or(path);
    p.rsplit('/').next().unwrap_or(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_values_with_trailing_comments_and_full_paths() {
        let mut cfg = Config::default();
        cfg.parse_text("never_exe = [\"/opt/keep#me\"] # retain this process\nstatus_file = \"/tmp/status\" # note\n").unwrap();
        assert_eq!(cfg.status_file, "/tmp/status");
        assert!(matches_any(&cfg.never_exe, "/opt/keep#me", "different"));
        assert!(!matches_any(
            &["/opt/keep#me".into()],
            "/else/keep#me",
            "keep#me"
        ));
    }

    #[test]
    fn reject_unrepresentable_timers_and_psi_history() {
        let mut cfg = Config::default();
        cfg.apply("cooldown_ms", "18446744073709551").unwrap();
        assert!(cfg.validate(120 << 30).is_err());
        let mut cfg = Config::default();
        cfg.apply("psi_window_ms", "60000").unwrap();
        assert!(cfg.validate(120 << 30).is_err());
        assert!(crate::units::parse_size("999999999999999999999999T").is_err());
        assert!(crate::units::parse_duration_ms("99999999999999999999999h").is_err());
        let mut cfg = Config::default();
        cfg.apply("headroom", "18000000000000000000").unwrap();
        assert!(cfg.validate(120 << 30).is_err());
    }

    #[test]
    fn globs() {
        assert!(glob_match("systemd-*", "systemd-logind"));
        assert!(glob_match("systemd", "systemd"));
        assert!(!glob_match("systemd", "systemd-logind"));
        assert!(glob_match("docker-*.scope", "docker-abc123.scope"));
        assert!(!glob_match("docker-*.scope", "session-3.scope"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"));
        assert!(glob_match("pt_*", "pt_main_thread"));
        assert!(glob_match("*", ""));
        assert!(!glob_match("x", ""));
    }

    #[test]
    fn parse_and_defaults() {
        let mut c = Config::default();
        c.parse_text(
            "# comment\nfloor = 10G\nwarn = 5%  # inline\nkill_mode = tree\nbackoff_ms = [1s, 30s]\nprefer_exe = [\"python*\", ollama]\nnever_exe = [!bash, myjob]\n",
        )
        .unwrap();
        assert_eq!(c.floor, SizeSpec::Bytes(10 << 30));
        assert_eq!(c.warn, SizeSpec::Percent(5.0));
        assert_eq!(c.kill_mode, KillMode::Tree);
        assert_eq!(c.backoff_ms, vec![1000, 30000]);
        assert_eq!(
            c.prefer_exe,
            vec!["python*".to_string(), "ollama".to_string()]
        );
        assert!(c.never_exe.contains(&"myjob".to_string()));
        assert!(c.never_exe.contains(&"sshd".to_string()));
        assert!(Config::default().parse_text("bogus = 1").is_err());
        assert!(Config::default().parse_text("floor 8G").is_err());
        assert!(Config::default().apply_override("floor=3G").is_ok());
    }

    #[test]
    fn validation() {
        let total = 120u64 << 30;
        assert!(Config::default().validate(total).is_ok());
        let mut c = Config::default();
        c.apply("floor", "20G").unwrap();
        assert!(c.validate(total).is_err()); // floor >= warn
        c.apply("warn", "30G").unwrap();
        assert!(c.validate(total).is_ok());
        c.apply("floor", "70G").unwrap();
        c.apply("warn", "80G").unwrap();
        assert!(c.validate(total).is_err()); // huge floor
        c.apply("allow_huge_floor", "true").unwrap();
        assert!(c.validate(total).is_ok());
    }

    #[test]
    fn lists_and_basenames() {
        assert_eq!(parse_list("[a, \"b c\", 'd']"), vec!["a", "b c", "d"]);
        assert_eq!(parse_list("[]"), Vec::<String>::new());
        assert_eq!(basename("/usr/bin/python3.12"), "python3.12");
        assert_eq!(basename("/opt/x/hog (deleted)"), "hog");
        assert!(matches_any(
            &["python*".into()],
            "python3.12",
            "pt_main_thread"
        ));
        assert!(matches_any(
            &["pt_*".into()],
            "python3.12",
            "pt_main_thread"
        ));
    }
}
