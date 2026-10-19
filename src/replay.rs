//! `memguard replay TRACE`: run the decision engine over a recorded sample trace offline.

use crate::cli;
use crate::config::{Config, DEFAULT_CONFIG_PATH};
use crate::engine::{Engine, EngineConfig, Level, Sample};
use crate::units::{fmt_bytes, fmt_rate};

pub fn main(args: &[String]) -> i32 {
    let p = match cli::parse(args, &["config"], &["o"], &["v", "verbose"]) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("memguard replay: {e}");
            return 2;
        }
    };
    let path = match p.positional.first() {
        Some(p) => p.clone(),
        None => {
            eprintln!("memguard replay: missing TRACE file");
            return 2;
        }
    };
    let mut cfg = match Config::load(
        p.opt("config").unwrap_or(DEFAULT_CONFIG_PATH),
        p.opt("config").is_some(),
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("replay: {e}");
            return 1;
        }
    };
    for o in p.multi("o") {
        if let Err(e) = cfg.apply_override(o) {
            eprintln!("replay: {e}");
            return 1;
        }
    }
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("replay: {path}: {e}");
            return 1;
        }
    };
    let verbose = p.flag("v") || p.flag("verbose");
    let mut engine: Option<Engine> = None;
    let mut last = Level::Ok;
    let mut n = 0u64;
    let mut crit = 0u64;
    let mut kills = 0u64;
    let mut first_kill: Option<(u64, u64)> = None;
    let mut t0 = 0u64;
    let mut previous_ns = None;
    for (line_index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split(',').collect();
        if f[0] == "t_ns" {
            continue;
        }
        if f.len() < 9 {
            eprintln!(
                "replay: line {}: expected at least 9 fields",
                line_index + 1
            );
            return 1;
        }
        let numbers: Vec<u64> = match f[..9]
            .iter()
            .map(|s| s.trim().parse())
            .collect::<Result<_, _>>()
        {
            Ok(n) => n,
            Err(e) => {
                eprintln!("replay: line {}: invalid sample: {e}", line_index + 1);
                return 1;
            }
        };
        let g = |i: usize| numbers[i];
        let s = Sample {
            t_ns: g(0),
            total: g(1),
            free: g(2),
            avail: g(3),
            free2m: g(4),
            swap_total: g(5),
            swap_free: g(6),
            psi_some_us: g(7),
            psi_full_us: g(8),
        };
        if previous_ns.is_some_and(|t| s.t_ns <= t) {
            eprintln!(
                "replay: line {}: timestamps must strictly increase",
                line_index + 1
            );
            return 1;
        }
        previous_ns = Some(s.t_ns);
        if engine.is_none() {
            if let Err(e) = cfg.validate(s.total) {
                eprintln!("replay: {e}");
                return 1;
            }
            engine = Some(Engine::new(EngineConfig::from_config(&cfg, s.total)));
            t0 = s.t_ns;
        }
        let e = engine.as_mut().unwrap();
        if e.verification()
            .is_some_and(|v| s.t_ns.saturating_sub(v.started_ns) >= 2_000_000_000)
        {
            let _ = e.verify_tick(s.t_ns, false, false, s.avail, Level::Ok);
        }
        let a = e.step(&s);
        n += 1;
        if a.level == Level::Critical {
            crit += 1;
        }
        let t = (s.t_ns - t0) as f64 / 1e9;
        if a.level != last || verbose {
            println!("{t:9.3}s {:<8} raw={:<8} reasons={:<16} avail={} free={} rate={} proj={} psi_some={:.2} psi_full={:.2} gate={}", a.level.as_str(), a.raw.as_str(), a.reasons.describe(), fmt_bytes(s.avail), fmt_bytes(s.free), fmt_rate(a.metrics.rate), fmt_bytes(a.metrics.proj.max(0) as u64), a.metrics.psi_some_1s, a.metrics.psi_full_1s, a.gate.as_str());
            last = a.level;
        }
        if a.may_kill {
            kills += 1;
            if first_kill.is_none() {
                first_kill = Some((s.t_ns - t0, s.avail));
                println!("{t:9.3}s KILL would be issued here (avail={} reasons={}); simulating a 2 s recovery", fmt_bytes(s.avail), a.reasons.describe());
            }
            // simulate: the kill happens, verification succeeds after 2 s
            e.record_kill(s.t_ns, 1, 1, 0, s.avail);
        }
    }
    if n == 0 {
        eprintln!("replay: trace has no samples");
        return 1;
    }
    println!(
        "replayed {n} samples: CRITICAL ticks={crit}, kill decisions={kills}{}",
        first_kill
            .map(|(t, a)| format!(
                ", first at {:.3}s with avail {}",
                t as f64 / 1e9,
                fmt_bytes(a)
            ))
            .unwrap_or_default()
    );
    0
}
