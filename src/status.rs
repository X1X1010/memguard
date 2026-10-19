//! `memguard status` and `memguard ps`: one-shot views combining /proc, PSI, NVML and the
//! daemon's status file. NVML queries use a helper with a bounded timeout.

use std::collections::HashSet;

use crate::cli;
use crate::config::{Config, DEFAULT_CONFIG_PATH};
use crate::daemon::read_status_file;
use crate::helper;
use crate::sys::meminfo::{page_size, read_meminfo, read_vmstat};
use crate::sys::psi;
use crate::sys::{cgroup, procfs};
use crate::units::fmt_bytes;
use crate::victim::{self, History, NvmlSnapshot, RankInput, VictimConfig};

fn json_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

pub struct Snapshot {
    pub cfg: Config,
    pub total: u64,
    pub mem: crate::sys::meminfo::MemInfo,
    pub free2m: Option<u64>,
    pub psi: Option<psi::Psi>,
    pub nvml: Result<(Vec<crate::sys::nvml::GpuProc>, String), String>,
    pub ranking: victim::Ranking,
    pub daemon: Option<std::collections::HashMap<String, String>>,
}

pub fn collect(config_path: &str, explicit: bool) -> Result<Snapshot, String> {
    let cfg = Config::load(config_path, explicit)?;
    let mem = read_meminfo()?;
    let total = mem.total;
    let vm = read_vmstat().ok();
    let free2m = vm
        .filter(|v| v.has_free_pages_blocks)
        .map(|v| v.nr_free_pages_blocks * page_size());
    let psi = psi::read_system_memory().ok();
    let nvml = helper::query_direct();
    let now = crate::mono_ns();
    let (snap, seen): (NvmlSnapshot, HashSet<u32>) = match &nvml {
        Ok((procs, _)) => (
            NvmlSnapshot {
                procs: procs.clone(),
                t_ns: now,
                valid: true,
            },
            procs.iter().map(|p| p.pid).collect(),
        ),
        Err(_) => (NvmlSnapshot::default(), HashSet::new()),
    };
    let maps_for: Vec<u32> = seen.iter().copied().collect();
    let table = procfs::scan(&procfs::ScanOptions {
        maps_for: &maps_for,
        maps_min_vmsize: 16 << 30,
        detail_min: 0,
    });
    let vcfg = VictimConfig::from_config(&cfg, total);
    let mut exclude = HashSet::new();
    exclude.insert(std::process::id());
    let ranking = victim::rank(&RankInput {
        table: &table,
        nvml: &snap,
        now_ns: now,
        cfg: &vcfg,
        hist: &History::default(),
        exclude: &exclude,
        cuda_seen: &seen,
        total,
    });
    let daemon = read_status_file(&cfg.status_file);
    Ok(Snapshot {
        cfg,
        total,
        mem,
        free2m,
        psi,
        nvml,
        ranking,
        daemon,
    })
}

fn daemon_line(d: &Option<std::collections::HashMap<String, String>>) -> String {
    match d {
        None => "not running (no status file)".into(),
        Some(m) => {
            let level = m.get("level").cloned().unwrap_or_default();
            if level == "STOPPED" {
                return "stopped".into();
            }
            let mono: u64 = m.get("mono_ns").and_then(|s| s.parse().ok()).unwrap_or(0);
            let age = crate::mono_ns().saturating_sub(mono) / 1_000_000_000;
            let fresh = age <= 3;
            format!(
                "{} level={} gate={} kills={}{}{} nvml={} (updated {}s ago)",
                if fresh { "running" } else { "STALE" },
                level,
                m.get("gate").cloned().unwrap_or_default(),
                m.get("kills_total").cloned().unwrap_or_default(),
                if m.get("dry_run").map(|s| s == "1").unwrap_or(false) {
                    " DRY-RUN"
                } else {
                    ""
                },
                if m.get("test_mode").map(|s| s == "1").unwrap_or(false) {
                    " TEST-MODE"
                } else {
                    ""
                },
                m.get("nvml").cloned().unwrap_or_default(),
                age
            )
        }
    }
}

pub fn status_main(args: &[String]) -> i32 {
    let p = match cli::parse(args, &["top", "config"], &[], &["json"]) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("memguard status: {e}");
            return 2;
        }
    };
    let top: usize = p.opt("top").and_then(|s| s.parse().ok()).unwrap_or(8);
    let snap = match collect(
        p.opt("config").unwrap_or(DEFAULT_CONFIG_PATH),
        p.opt("config").is_some(),
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("memguard status: {e}");
            return 1;
        }
    };
    if p.flag("json") {
        print_json(&snap, top);
        return 0;
    }
    let m = &snap.mem;
    let t = snap.total;
    println!("memguard status");
    println!("  daemon      {}", daemon_line(&snap.daemon));
    println!(
        "  memory      total {}  available {} ({:.0}%)  free {}  free-2MiB-blocks {}  swap {}/{}",
        fmt_bytes(t),
        fmt_bytes(m.available),
        m.available as f64 * 100.0 / t as f64,
        fmt_bytes(m.free),
        snap.free2m.map(fmt_bytes).unwrap_or_else(|| "n/a".into()),
        fmt_bytes(m.swap_used()),
        fmt_bytes(m.swap_total)
    );
    println!(
        "  breakdown   page cache {}  anon {}  shmem {}  slab {}  driver/other (est.) {}",
        fmt_bytes(m.cached + m.buffers),
        fmt_bytes(m.anon_pages),
        fmt_bytes(m.shmem),
        fmt_bytes(m.slab),
        fmt_bytes(m.other_estimate())
    );
    match &snap.psi {
        Some(ps) => println!(
            "  psi memory  some avg10={:.2} avg60={:.2}  full avg10={:.2} avg60={:.2}",
            ps.some_avg10, ps.some_avg60, ps.full_avg10, ps.full_avg60
        ),
        None => println!("  psi memory  unavailable"),
    }
    match &snap.nvml {
        Ok((procs, ver)) => {
            let sum: u64 = procs.iter().map(|p| p.bytes).sum();
            println!(
                "  nvml        ok (driver {ver}): {} GPU process(es) holding {}",
                procs.len(),
                fmt_bytes(sum)
            );
        }
        Err(e) => println!("  nvml        unavailable: {e}"),
    }
    println!(
        "  thresholds  floor {}  warn {}  headroom {}  (config {})",
        fmt_bytes(snap.cfg.floor.resolve(t)),
        fmt_bytes(snap.cfg.warn.resolve(t)),
        fmt_bytes(snap.cfg.headroom.resolve(t)),
        p.opt("config").unwrap_or(DEFAULT_CONFIG_PATH)
    );
    println!(
        "  top {} by footprint (GPU + anon + {}*shmem + swap):",
        top, snap.cfg.shmem_weight
    );
    print_table(&snap.ranking.all, top, false);
    0
}

fn print_table(cands: &[victim::Candidate], n: usize, all: bool) {
    println!(
        "  {:>7} {:>9} {:>9} {:>9} {:>9} {:>8} {:>8} {:>9} {:<9} {:<16} CGROUP UNIT",
        "PID", "FOOTPRINT", "TREE", "GPU", "ANON", "SHMEM", "SWAP", "VMSIZE", "TIER", "COMM"
    );
    for c in cands.iter().filter(|c| all || c.footprint > 0).take(n) {
        println!(
            "  {:>7} {:>9} {:>9} {:>8}{} {:>9} {:>8} {:>8} {:>9} {:<9} {:<16} {}",
            c.pid,
            fmt_bytes(c.footprint),
            if c.tree_footprint > c.footprint {
                fmt_bytes(c.tree_footprint)
            } else {
                "-".to_string()
            },
            fmt_bytes(c.vidmem),
            if c.vidmem_est { "~" } else { " " },
            fmt_bytes(c.rss_anon),
            fmt_bytes(c.rss_shmem),
            fmt_bytes(c.vm_swap),
            fmt_bytes(c.vm_size),
            c.tier.as_str(),
            c.comm.chars().take(16).collect::<String>(),
            cgroup::unit_name(&c.cgroup).unwrap_or("/")
        );
    }
}

fn print_json(s: &Snapshot, top: usize) {
    let m = &s.mem;
    let mut o = String::from("{");
    o.push_str(&format!("\"total\":{},\"available\":{},\"free\":{},\"free2m\":{},\"swap_total\":{},\"swap_used\":{},\"page_cache\":{},\"anon\":{},\"shmem\":{},\"driver_other_estimate\":{},", m.total, m.available, m.free, s.free2m.map(|v| v.to_string()).unwrap_or_else(|| "null".into()), m.swap_total, m.swap_used(), m.cached + m.buffers, m.anon_pages, m.shmem, m.other_estimate()));
    match &s.psi {
        Some(p) => o.push_str(&format!("\"psi\":{{\"some_avg10\":{},\"full_avg10\":{},\"some_total_us\":{},\"full_total_us\":{}}},", p.some_avg10, p.full_avg10, p.some_total_us, p.full_total_us)),
        None => o.push_str("\"psi\":null,"),
    }
    match &s.nvml {
        Ok((procs, ver)) => {
            o.push_str(&format!(
                "\"nvml\":{{\"driver\":{},\"processes\":[",
                json_str(ver)
            ));
            o.push_str(
                &procs
                    .iter()
                    .map(|p| format!("{{\"pid\":{},\"bytes\":{}}}", p.pid, p.bytes))
                    .collect::<Vec<_>>()
                    .join(","),
            );
            o.push_str("]},");
        }
        Err(e) => o.push_str(&format!("\"nvml\":{{\"error\":{}}},", json_str(e))),
    }
    o.push_str("\"daemon\":");
    match &s.daemon {
        None => o.push_str("null,"),
        Some(d) => {
            o.push('{');
            o.push_str(
                &d.iter()
                    .map(|(k, v)| format!("{}:{}", json_str(k), json_str(v)))
                    .collect::<Vec<_>>()
                    .join(","),
            );
            o.push_str("},");
        }
    }
    o.push_str(&format!(
        "\"thresholds\":{{\"floor\":{},\"warn\":{},\"headroom\":{}}},",
        s.cfg.floor.resolve(s.total),
        s.cfg.warn.resolve(s.total),
        s.cfg.headroom.resolve(s.total)
    ));
    o.push_str("\"top\":[");
    o.push_str(
        &s.ranking
            .all
            .iter()
            .take(top)
            .map(|c| format!("{{\"pid\":{},\"comm\":{},\"exe\":{},\"cgroup\":{},\"footprint\":{},\"gpu\":{},\"gpu_estimated\":{},\"anon\":{},\"shmem\":{},\"swap\":{},\"vmsize\":{},\"tier\":{},\"oom_score_adj\":{}}}", c.pid, json_str(&c.comm), json_str(&c.exe), json_str(&c.cgroup), c.tree_footprint, c.vidmem, c.vidmem_est, c.rss_anon, c.rss_shmem, c.vm_swap, c.vm_size, json_str(c.tier.as_str()), c.oom_score_adj))
            .collect::<Vec<_>>()
            .join(","),
    );
    o.push_str("]}");
    println!("{o}");
}

pub fn ps_main(args: &[String]) -> i32 {
    let p = match cli::parse(args, &["sort", "n", "config"], &[], &["all"]) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("memguard ps: {e}");
            return 2;
        }
    };
    let n: usize = p.opt("n").and_then(|s| s.parse().ok()).unwrap_or(25);
    let snap = match collect(
        p.opt("config").unwrap_or(DEFAULT_CONFIG_PATH),
        p.opt("config").is_some(),
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("memguard ps: {e}");
            return 1;
        }
    };
    let mut rows = snap.ranking.all.clone();
    match p.opt("sort").unwrap_or("footprint") {
        "vidmem" | "gpu" => rows.sort_by_key(|a| std::cmp::Reverse(a.vidmem)),
        "rss" | "anon" => rows.sort_by_key(|a| std::cmp::Reverse(a.rss_anon)),
        "swap" => rows.sort_by_key(|a| std::cmp::Reverse(a.vm_swap)),
        "vmsize" => rows.sort_by_key(|a| std::cmp::Reverse(a.vm_size)),
        _ => {}
    }
    if let Err(e) = &snap.nvml {
        eprintln!(
            "note: NVML unavailable ({e}); GPU column is estimated from VmSize for CUDA processes"
        );
    }
    print_table(&rows, n, p.flag("all"));
    0
}
