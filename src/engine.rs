//! Pure decision engine: one `Sample` in per tick, one `Assessment` out. No I/O, no heap
//! allocation on the tick path. Kill gating (debounce, cooldown, verification, backoff, rate
//! limits) lives here too so it can be unit-tested with synthetic time series.

use std::collections::VecDeque;

use crate::config::Config;
use crate::sys::psi::PsiRing;

const GIB: u64 = 1 << 30;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Sample {
    pub t_ns: u64,
    pub total: u64,
    pub free: u64,
    pub avail: u64,
    /// Free memory in whole >=2 MiB blocks (nr_free_pages_blocks * page size); falls back to free.
    pub free2m: u64,
    pub swap_total: u64,
    pub swap_free: u64,
    pub psi_some_us: u64,
    pub psi_full_us: u64,
}

impl Sample {
    pub fn swap_used(&self) -> u64 {
        self.swap_total.saturating_sub(self.swap_free)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Ok,
    Warn,
    Critical,
}

impl Level {
    pub fn as_str(&self) -> &'static str {
        match self {
            Level::Ok => "OK",
            Level::Warn => "WARN",
            Level::Critical => "CRITICAL",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reasons {
    pub floor: bool,
    pub projection: bool,
    pub thrash: bool,
    pub swap_storm: bool,
}

impl Reasons {
    pub fn any(&self) -> bool {
        self.floor || self.projection || self.thrash || self.swap_storm
    }
    pub fn describe(&self) -> String {
        let mut v = Vec::new();
        if self.floor {
            v.push("floor");
        }
        if self.projection {
            v.push("projection");
        }
        if self.thrash {
            v.push("thrash");
        }
        if self.swap_storm {
            v.push("swap-storm");
        }
        if v.is_empty() {
            "-".into()
        } else {
            v.join("+")
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Metrics {
    pub dt_ns: u64,
    /// Consumption rate used for decisions (bytes/s, >= 0).
    pub rate: f64,
    pub rate_raw: f64,
    /// Projected MemAvailable at now + horizon (may be negative).
    pub proj: i64,
    pub tt_floor_s: f64,
    pub psi_some_1s: f64,
    pub psi_full_1s: f64,
    pub swap_rate: f64,
    pub swap_used: u64,
    pub headroom_deficit: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    Open,
    NotCritical,
    Grace,
    Debounce,
    Verifying,
    Backoff,
    Cooldown,
    RateLimited,
}

impl Gate {
    pub fn as_str(&self) -> &'static str {
        match self {
            Gate::Open => "open",
            Gate::NotCritical => "not-critical",
            Gate::Grace => "startup-grace",
            Gate::Debounce => "debounce",
            Gate::Verifying => "verifying",
            Gate::Backoff => "backoff",
            Gate::Cooldown => "cooldown",
            Gate::RateLimited => "rate-limited",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Assessment {
    pub tick: u64,
    pub level: Level,
    pub raw: Level,
    pub reasons: Reasons,
    pub emergency: bool,
    pub may_kill: bool,
    pub gate: Gate,
    pub metrics: Metrics,
    /// Bytes the daemon should ask the reclaim thread to free from file cache (0 = none).
    pub want_reclaim: u64,
}

#[derive(Clone, Debug)]
pub struct EngineConfig {
    pub interval_ns: u64,
    pub floor: u64,
    pub warn: u64,
    pub horizon_ns: u64,
    pub rate_ema_ns: u64,
    pub rate_min: f64,
    pub rate_warn: f64,
    pub psi_window_ns: u64,
    pub psi_full_critical: f64,
    pub psi_full_emergency: f64,
    pub psi_some_warn: f64,
    pub swap_rate_critical: f64,
    pub headroom: u64,
    pub headroom_reclaim: bool,
    pub reclaim_min_interval_ns: u64,
    pub reclaim_max_chunk: u64,
    pub debounce_ticks: u32,
    pub cooldown_ns: u64,
    pub emergency_cooldown_ns: u64,
    pub verify_ns: u64,
    pub backoff_ns: Vec<u64>,
    pub max_kills_per_min: u32,
    pub max_kills_per_10min: u32,
    pub startup_grace_ticks: u32,
    pub warn_clear_ns: u64,
}

impl EngineConfig {
    pub fn from_config(cfg: &Config, total: u64) -> Self {
        EngineConfig {
            interval_ns: cfg.interval_ms * 1_000_000,
            floor: cfg.floor.resolve(total),
            warn: cfg.warn.resolve(total),
            horizon_ns: cfg.horizon_ms * 1_000_000,
            rate_ema_ns: cfg.rate_ema_ms.max(1) * 1_000_000,
            rate_min: cfg.rate_min.resolve(total) as f64,
            rate_warn: cfg.rate_warn.resolve(total) as f64,
            psi_window_ns: cfg.psi_window_ms * 1_000_000,
            psi_full_critical: cfg.psi_full_critical,
            psi_full_emergency: cfg.psi_full_emergency,
            psi_some_warn: cfg.psi_some_warn,
            swap_rate_critical: cfg.swap_rate_critical.resolve(total) as f64,
            headroom: cfg.headroom.resolve(total),
            headroom_reclaim: cfg.headroom_reclaim,
            reclaim_min_interval_ns: 500_000_000,
            reclaim_max_chunk: 4 * GIB,
            debounce_ticks: cfg.debounce_ticks.max(1),
            cooldown_ns: cfg.cooldown_ms * 1_000_000,
            emergency_cooldown_ns: cfg.emergency_cooldown_ms * 1_000_000,
            verify_ns: cfg.verify_ms * 1_000_000,
            backoff_ns: cfg.backoff_ms.iter().map(|m| m * 1_000_000).collect(),
            max_kills_per_min: cfg.max_kills_per_min,
            max_kills_per_10min: cfg.max_kills_per_10min,
            startup_grace_ticks: cfg.startup_grace_ticks,
            warn_clear_ns: 3_000_000_000,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Verification {
    pub pid: u32,
    pub key: u64,
    pub claimed: u64,
    pub avail_at_kill: u64,
    pub started_ns: u64,
    pub until_ns: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Victim gone and memory came back (or the level dropped below CRITICAL).
    Recovered,
    /// Victim gone, still CRITICAL, no measurable recovery: back off before the next kill.
    NoEffect,
    /// Victim alive in uninterruptible sleep after the window: likely wedged in the driver.
    Stuck,
    /// Victim alive but not in D state after the window (slow teardown or ignored signal).
    VictimAliveTimeout,
}

pub struct Engine {
    pub cfg: EngineConfig,
    prev: Option<Sample>,
    rate_ema: f64,
    swap_ema: f64,
    psi: PsiRing,
    tick: u64,
    crit_streak: u32,
    thrash_streak: u32,
    level: Level,
    clear_since: Option<u64>,
    last_kill_ns: Option<u64>,
    kills: VecDeque<(u64, u64)>,
    verify: Option<Verification>,
    backoff_until: Option<u64>,
    backoff_idx: usize,
    last_reclaim_ns: Option<u64>,
    pub kills_total: u64,
    pub reclaims_total: u64,
}

impl Engine {
    pub fn new(cfg: EngineConfig) -> Self {
        Engine {
            cfg,
            prev: None,
            rate_ema: 0.0,
            swap_ema: 0.0,
            psi: PsiRing::new(),
            tick: 0,
            crit_streak: 0,
            thrash_streak: 0,
            level: Level::Ok,
            clear_since: None,
            last_kill_ns: None,
            kills: VecDeque::with_capacity(64),
            verify: None,
            backoff_until: None,
            backoff_idx: 0,
            last_reclaim_ns: None,
            kills_total: 0,
            reclaims_total: 0,
        }
    }

    pub fn level(&self) -> Level {
        self.level
    }

    pub fn tick(&self) -> u64 {
        self.tick
    }

    pub fn verification(&self) -> Option<&Verification> {
        self.verify.as_ref()
    }

    pub fn backoff_remaining_ns(&self, now: u64) -> u64 {
        self.backoff_until
            .map(|u| u.saturating_sub(now))
            .unwrap_or(0)
    }

    /// Forget rate/PSI history (after suspend/resume or a long stall).
    pub fn reset_windows(&mut self) {
        self.prev = None;
        self.rate_ema = 0.0;
        self.swap_ema = 0.0;
        self.psi.clear();
        self.crit_streak = 0;
        self.thrash_streak = 0;
    }

    fn kills_since(&self, now: u64, window_ns: u64) -> u32 {
        self.kills
            .iter()
            .filter(|(t, _)| now.saturating_sub(*t) <= window_ns)
            .count() as u32
    }

    pub fn recent_kills_of(&self, now: u64, key: u64, window_ns: u64) -> u32 {
        self.kills
            .iter()
            .filter(|(t, k)| *k == key && now.saturating_sub(*t) <= window_ns)
            .count() as u32
    }

    pub fn step(&mut self, s: &Sample) -> Assessment {
        let c = &self.cfg;
        let now = s.t_ns;
        self.tick += 1;
        let mut m = Metrics::default();

        let dt = self.prev.map(|p| now.saturating_sub(p.t_ns)).unwrap_or(0);
        m.dt_ns = dt;
        let dt_normal = dt > 0 && dt <= c.interval_ns.saturating_mul(5) / 2;
        if let Some(p) = self.prev {
            if dt > 0 {
                let dt_s = dt as f64 / 1e9;
                m.rate_raw = (p.avail as f64 - s.avail as f64) / dt_s;
                let swap_raw = (s.swap_used() as f64 - p.swap_used() as f64) / dt_s;
                if dt_normal {
                    let a = 1.0 - (-(dt as f64) / c.rate_ema_ns as f64).exp();
                    self.rate_ema = a * m.rate_raw + (1.0 - a) * self.rate_ema;
                    self.swap_ema = a * swap_raw + (1.0 - a) * self.swap_ema;
                } else {
                    // gap: history is meaningless, start over
                    self.rate_ema = 0.0;
                    self.swap_ema = 0.0;
                    self.thrash_streak = 0;
                    self.psi.clear();
                }
            }
        }
        let rate = if dt_normal {
            self.rate_ema.max(m.rate_raw).max(0.0)
        } else {
            0.0
        };
        m.rate = rate;
        m.swap_rate = self.swap_ema;
        m.swap_used = s.swap_used();

        self.psi.push(now, s.psi_some_us, s.psi_full_us);
        if let Some((some, full, _)) = self.psi.fractions(c.psi_window_ns) {
            m.psi_some_1s = some;
            m.psi_full_1s = full;
        }

        let horizon_s = c.horizon_ns as f64 / 1e9;
        m.proj = (s.avail as f64 - rate * horizon_s) as i64;
        m.tt_floor_s = if rate > 0.0 {
            (s.avail as f64 - c.floor as f64) / rate
        } else {
            f64::INFINITY
        };
        m.headroom_deficit = c.headroom.saturating_sub(s.free);

        let past_grace = self.tick > c.startup_grace_ticks as u64;
        if m.psi_full_1s >= c.psi_full_critical {
            self.thrash_streak = self.thrash_streak.saturating_add(1);
        } else {
            self.thrash_streak = 0;
        }
        let reasons = Reasons {
            floor: s.avail < c.floor,
            projection: dt_normal && past_grace && rate >= c.rate_min && m.proj < c.floor as i64,
            thrash: self.thrash_streak >= 2,
            swap_storm: s.swap_total > 0
                && self.swap_ema >= c.swap_rate_critical
                && (s.avail < c.warn || m.psi_some_1s >= 0.30),
        };
        let emergency = s.avail < c.floor / 2 || m.psi_full_1s >= c.psi_full_emergency;

        let early_warn = dt_normal
            && rate >= c.rate_min
            && (s.avail as f64 - rate * 3.0 * horizon_s) < c.floor as f64;
        let raw = if reasons.any() {
            Level::Critical
        } else if s.avail < c.warn
            || m.psi_some_1s >= c.psi_some_warn
            || s.free < c.headroom
            || early_warn
            || (dt_normal && rate >= c.rate_warn)
        {
            Level::Warn
        } else {
            Level::Ok
        };

        self.crit_streak = if raw == Level::Critical {
            self.crit_streak.saturating_add(1)
        } else {
            0
        };
        let debounced = self.crit_streak >= c.debounce_ticks || emergency;
        match raw {
            Level::Critical => {
                self.clear_since = None;
                self.level = if debounced {
                    Level::Critical
                } else {
                    Level::Warn.max(self.level.min(Level::Warn))
                };
            }
            Level::Warn => {
                self.clear_since = None;
                self.level = Level::Warn;
            }
            Level::Ok => {
                if self.level == Level::Critical {
                    self.level = Level::Warn;
                    self.clear_since = Some(now);
                } else if self.level == Level::Warn {
                    let since = *self.clear_since.get_or_insert(now);
                    if now.saturating_sub(since) >= c.warn_clear_ns {
                        self.level = Level::Ok;
                        self.clear_since = None;
                    }
                }
            }
        }

        // headroom controller: keep `headroom` bytes truly free by dropping file cache
        let mut want_reclaim = 0u64;
        if c.headroom_reclaim && s.free < c.headroom && s.avail.saturating_sub(s.free) >= GIB {
            let due = self
                .last_reclaim_ns
                .map(|t| now.saturating_sub(t) >= c.reclaim_min_interval_ns)
                .unwrap_or(true);
            if due {
                want_reclaim = (c.headroom - s.free + GIB).min(c.reclaim_max_chunk);
                self.last_reclaim_ns = Some(now);
                self.reclaims_total += 1;
            }
        }

        let gate = if raw != Level::Critical {
            Gate::NotCritical
        } else if !past_grace && !emergency {
            Gate::Grace
        } else if !debounced {
            Gate::Debounce
        } else if self.verify.is_some() {
            Gate::Verifying
        } else if self.backoff_until.is_some_and(|u| now < u) {
            Gate::Backoff
        } else if self.last_kill_ns.is_some_and(|t| {
            now.saturating_sub(t)
                < if emergency {
                    c.emergency_cooldown_ns
                } else {
                    c.cooldown_ns
                }
        }) {
            Gate::Cooldown
        } else {
            if self.kills_since(now, 60_000_000_000) >= c.max_kills_per_min
                || self.kills_since(now, 600_000_000_000) >= c.max_kills_per_10min
            {
                Gate::RateLimited
            } else {
                Gate::Open
            }
        };

        self.prev = Some(*s);
        Assessment {
            tick: self.tick,
            level: self.level,
            raw,
            reasons,
            emergency,
            may_kill: gate == Gate::Open,
            gate,
            metrics: m,
            want_reclaim,
        }
    }

    /// Record a kill we just issued. `key` identifies the job (hash of exe + cgroup) so restart
    /// loops are recognised; a repeat within 10 minutes starts the backoff immediately.
    pub fn record_kill(&mut self, now: u64, pid: u32, key: u64, claimed: u64, avail: u64) {
        self.last_kill_ns = Some(now);
        self.kills_total += 1;
        let repeats = self.recent_kills_of(now, key, 600_000_000_000);
        self.kills.push_back((now, key));
        while self
            .kills
            .front()
            .is_some_and(|(t, _)| now.saturating_sub(*t) > 600_000_000_000)
        {
            self.kills.pop_front();
        }
        if self.kills.len() > 256 {
            self.kills.pop_front();
        }
        self.verify = Some(Verification {
            pid,
            key,
            claimed,
            avail_at_kill: avail,
            started_ns: now,
            until_ns: now + self.cfg.verify_ns,
        });
        if repeats > 0 {
            self.apply_backoff(now);
        }
    }

    fn apply_backoff(&mut self, now: u64) {
        let idx = self
            .backoff_idx
            .min(self.cfg.backoff_ns.len().saturating_sub(1));
        let d = self
            .cfg
            .backoff_ns
            .get(idx)
            .copied()
            .unwrap_or(10_000_000_000);
        let until = now + d;
        self.backoff_until = Some(self.backoff_until.map_or(until, |u| u.max(until)));
        self.backoff_idx = self.backoff_idx.saturating_add(1);
    }

    /// Drive the verification window after a kill. Call every tick while `verification()` is Some.
    pub fn verify_tick(
        &mut self,
        now: u64,
        victim_alive: bool,
        victim_in_d: bool,
        avail: u64,
        level: Level,
    ) -> Option<VerifyOutcome> {
        let v = self.verify?;
        let recovered_mem = avail
            >= v.avail_at_kill
                .saturating_add((v.claimed as f64 * 0.3) as u64);
        if !victim_alive && (recovered_mem || level != Level::Critical) {
            self.verify = None;
            self.backoff_idx = 0;
            return Some(VerifyOutcome::Recovered);
        }
        if now < v.until_ns {
            return None;
        }
        self.verify = None;
        if victim_alive && victim_in_d {
            self.apply_backoff(now);
            return Some(VerifyOutcome::Stuck);
        }
        if victim_alive {
            self.apply_backoff(now);
            return Some(VerifyOutcome::VictimAliveTimeout);
        }
        if level == Level::Critical && !recovered_mem {
            self.apply_backoff(now);
            return Some(VerifyOutcome::NoEffect);
        }
        self.backoff_idx = 0;
        Some(VerifyOutcome::Recovered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 120 * GIB;
    const TICK: u64 = 50_000_000;

    fn cfg() -> EngineConfig {
        let mut c = Config::default();
        c.apply("floor", "8G").unwrap();
        c.apply("warn", "16G").unwrap();
        EngineConfig::from_config(&c, T)
    }

    fn sample(i: u64, avail: u64) -> Sample {
        Sample {
            t_ns: 1_000_000_000 + i * TICK,
            total: T,
            free: avail,
            avail,
            free2m: avail,
            swap_total: 16 * GIB,
            swap_free: 16 * GIB,
            psi_some_us: 0,
            psi_full_us: 0,
        }
    }

    #[test]
    fn steady_is_ok() {
        let mut e = Engine::new(cfg());
        for i in 0..200 {
            let a = e.step(&sample(i, 100 * GIB));
            assert_eq!(a.level, Level::Ok);
            assert!(!a.may_kill);
            assert_eq!(a.want_reclaim, 0);
        }
    }

    #[test]
    fn burst_kills_near_projection_point_not_earlier() {
        let mut e = Engine::new(cfg());
        let per_tick = (34.0 * GIB as f64 * 0.05) as u64; // 34 GiB/s
        let mut avail = 110 * GIB;
        let mut first_kill_avail = None;
        for i in 0..200u64 {
            if i >= 20 {
                avail = avail.saturating_sub(per_tick);
            }
            let a = e.step(&sample(i, avail));
            if a.may_kill {
                first_kill_avail = Some(avail);
                break;
            }
            // must not fire while avail is comfortably above floor + rate*horizon (+ one tick)
            if avail > 8 * GIB + per_tick * 5 {
                assert!(!a.may_kill, "fired too early at avail={}", avail / GIB);
            }
        }
        let k = first_kill_avail.expect("burst should trigger a kill") as f64 / GIB as f64;
        // projection: 8 + 34*0.15 = 13.1 GiB, minus debounce (2 ticks * 1.7 GiB)
        assert!(k < 13.5 && k > 6.0, "kill at {k} GiB");
    }

    #[test]
    fn single_floor_tick_is_debounced() {
        let mut e = Engine::new(cfg());
        for i in 0..10 {
            e.step(&sample(i, 100 * GIB));
        }
        let a = e.step(&sample(10, 7 * GIB));
        assert_eq!(a.raw, Level::Critical);
        assert!(!a.may_kill);
        assert_eq!(a.gate, Gate::Debounce);
        let a = e.step(&sample(11, 7 * GIB));
        assert!(a.may_kill);
        assert_eq!(a.level, Level::Critical);
        assert!(a.reasons.floor);
    }

    #[test]
    fn emergency_bypasses_grace_and_debounce() {
        let mut e = Engine::new(cfg());
        let a = e.step(&sample(0, 3 * GIB));
        assert!(a.emergency);
        assert!(a.may_kill, "gate={:?}", a.gate);
    }

    #[test]
    fn grace_blocks_early_projection() {
        let mut e = Engine::new(cfg());
        let per_tick = (34.0 * GIB as f64 * 0.05) as u64;
        let mut avail = 20 * GIB;
        for i in 0..3u64 {
            avail -= per_tick;
            let a = e.step(&sample(i, avail));
            assert!(!a.reasons.projection);
        }
    }

    #[test]
    fn psi_thrash_with_high_avail() {
        let mut e = Engine::new(cfg());
        let mut s = sample(0, 100 * GIB);
        for i in 0..60u64 {
            s = sample(i, 100 * GIB);
            s.psi_full_us = i * 25_000; // 50% full stall
            s.psi_some_us = i * 30_000;
        }
        let mut e2 = Engine::new(cfg());
        let mut fired = false;
        for i in 0..60u64 {
            let mut s = sample(i, 100 * GIB);
            s.psi_full_us = i * 25_000;
            s.psi_some_us = i * 30_000;
            let a = e2.step(&s);
            if a.may_kill {
                assert!(a.reasons.thrash);
                fired = true;
                break;
            }
        }
        assert!(fired, "thrash should trigger despite high MemAvailable");
        let _ = e.step(&s);
    }

    #[test]
    fn swap_storm_requires_low_avail_or_psi() {
        let mut e = Engine::new(cfg());
        // swap growing 1 GiB/s with avail high and no PSI: no trigger (state, not event)
        for i in 0..40u64 {
            let mut s = sample(i, 100 * GIB);
            s.swap_free = (16 * GIB).saturating_sub(i * (GIB / 20));
            let a = e.step(&s);
            assert!(!a.reasons.swap_storm);
        }
        // same growth with avail below warn: trigger
        let mut e = Engine::new(cfg());
        let mut fired = false;
        for i in 0..40u64 {
            let mut s = sample(i, 12 * GIB);
            s.swap_free = (16 * GIB).saturating_sub(i * (GIB / 20));
            let a = e.step(&s);
            if a.reasons.swap_storm {
                fired = true;
            }
        }
        assert!(fired);
    }

    #[test]
    fn absolute_swap_usage_never_triggers() {
        let mut e = Engine::new(cfg());
        for i in 0..100u64 {
            let mut s = sample(i, 12 * GIB);
            s.swap_free = GIB; // 15 of 16 GiB used, static
            let a = e.step(&s);
            assert!(!a.reasons.swap_storm);
            assert_eq!(a.level, Level::Warn);
        }
    }

    #[test]
    fn kill_cooldown_verification_and_backoff() {
        let mut e = Engine::new(cfg());
        let mut i = 0u64;
        let mut a = e.step(&sample(i, 7 * GIB));
        while !a.may_kill {
            i += 1;
            a = e.step(&sample(i, 7 * GIB));
        }
        let now = sample(i, 0).t_ns;
        e.record_kill(now, 4242, 1, 40 * GIB, 7 * GIB);
        i += 1;
        let a = e.step(&sample(i, 7 * GIB));
        assert_eq!(a.gate, Gate::Verifying);
        // victim gone, memory back: recovered
        let out = e.verify_tick(sample(i, 0).t_ns, false, false, 60 * GIB, Level::Ok);
        assert_eq!(out, Some(VerifyOutcome::Recovered));
        // still critical right after: cooldown
        i += 1;
        let a = e.step(&sample(i, 7 * GIB));
        assert_eq!(a.gate, Gate::Cooldown);
        // after cooldown: open again
        i += 50;
        let a = e.step(&sample(i, 7 * GIB));
        assert_eq!(a.gate, Gate::Open);
        // second kill with no effect -> backoff
        let now = sample(i, 0).t_ns;
        e.record_kill(now, 4343, 2, 10 * GIB, 7 * GIB);
        let later = now + e.cfg.verify_ns + 1;
        let out = e.verify_tick(later, false, false, 7 * GIB, Level::Critical);
        assert_eq!(out, Some(VerifyOutcome::NoEffect));
        assert!(e.backoff_remaining_ns(later) > 9_000_000_000);
        i += 200;
        let a = e.step(&sample(i, 7 * GIB));
        assert_eq!(a.gate, Gate::Backoff);
        // stuck victim (alive in D) after the window
        let now = later + 70_000_000_000;
        e.backoff_until = None;
        e.record_kill(now, 4444, 3, 10 * GIB, 7 * GIB);
        let out = e.verify_tick(
            now + e.cfg.verify_ns + 1,
            true,
            true,
            7 * GIB,
            Level::Critical,
        );
        assert_eq!(out, Some(VerifyOutcome::Stuck));
    }

    #[test]
    fn repeat_kill_of_same_key_backs_off() {
        let mut e = Engine::new(cfg());
        e.record_kill(10_000_000_000, 1, 77, GIB, GIB);
        assert_eq!(e.backoff_remaining_ns(10_000_000_000), 0);
        e.verify = None;
        e.record_kill(20_000_000_000, 2, 77, GIB, GIB);
        assert!(e.backoff_remaining_ns(20_000_000_000) > 0);
    }

    #[test]
    fn rate_limit() {
        let mut e = Engine::new(cfg());
        for k in 0..3u64 {
            e.record_kill(100_000_000 * (k + 1), 100 + k as u32, 1000 + k, GIB, GIB);
            e.verify = None;
        }
        let mut i = 0u64;
        let mut a = e.step(&sample(i, 7 * GIB));
        for _ in 0..100 {
            i += 1;
            a = e.step(&sample(i, 7 * GIB));
        }
        assert_eq!(a.gate, Gate::RateLimited);
        assert_eq!(
            e.step(&sample(102, 0)).gate,
            Gate::RateLimited,
            "hard caps also apply in an emergency"
        );
    }

    #[test]
    fn warn_hysteresis() {
        let mut e = Engine::new(cfg());
        for i in 0..10 {
            e.step(&sample(i, 100 * GIB));
        }
        let a = e.step(&sample(10, 15 * GIB));
        assert_eq!(a.level, Level::Warn);
        let a = e.step(&sample(11, 100 * GIB));
        assert_eq!(a.level, Level::Warn, "must hold WARN for a while");
        let a = e.step(&sample(11 + 70, 100 * GIB)); // +3.5 s
        assert_eq!(a.level, Level::Ok);
    }

    #[test]
    fn abnormal_dt_skips_projection() {
        let mut e = Engine::new(cfg());
        for i in 0..10 {
            e.step(&sample(i, 100 * GIB));
        }
        let mut s = sample(10, 100 * GIB);
        s.t_ns += 2_000_000_000; // 2 s gap, then a huge drop
        s.avail = 20 * GIB;
        let a = e.step(&s);
        assert!(!a.reasons.projection);
        assert_eq!(a.metrics.rate, 0.0);
    }

    #[test]
    fn headroom_reclaim_requests() {
        let mut e = Engine::new(cfg());
        let mut s = sample(0, 100 * GIB);
        s.free = GIB; // 1 GiB free, 99 GiB of cache
        let a = e.step(&s);
        assert_eq!(a.want_reclaim, 4 * GIB); // min(4-1+1, 4)
        let s2 = Sample {
            t_ns: s.t_ns + TICK,
            ..s
        };
        let a2 = e.step(&s2);
        assert_eq!(a2.want_reclaim, 0, "rate limited to one request per 500 ms");
        let s3 = Sample {
            t_ns: s.t_ns + 600_000_000,
            ..s
        };
        let a3 = e.step(&s3);
        assert!(a3.want_reclaim > 0);
        // nothing reclaimable (free == avail): no request
        let mut s4 = sample(100, 2 * GIB);
        s4.free = 2 * GIB;
        let a4 = e.step(&s4);
        assert_eq!(a4.want_reclaim, 0);
    }
}
