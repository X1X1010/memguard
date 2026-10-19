//! Pure victim selection: who holds the memory, and how to kill it.
//!
//! footprint = GPU memory (NVML, or a VmSize-based estimate while NVML is stale) + RssAnon +
//! shmem_weight * RssShmem + VmSwap. Virtual mappings are not resident memory. Trees aggregate eligible descendants.
//! Tiers: never / immune / avoid / normal / prefer / preferred (oom_score_adj >= 900).

use std::collections::{HashMap, HashSet};

use crate::config::{basename, glob_match, matches_any, Config, KillMode};
use crate::sys::cgroup;
use crate::sys::nvml::GpuProc;
use crate::sys::procfs::{ProcInfo, ProcTable, ProcessIdentity};
use crate::units::{fmt_bytes, fmt_rate};

pub const GIB: u64 = 1 << 30;

#[derive(Clone, Debug, Default)]
pub struct NvmlSnapshot {
    pub procs: Vec<GpuProc>,
    pub t_ns: u64,
    pub valid: bool,
}

impl NvmlSnapshot {
    pub fn age_ns(&self, now: u64) -> u64 {
        now.saturating_sub(self.t_ns)
    }
}

#[derive(Clone, Debug)]
pub struct VictimConfig {
    pub min_victim: u64,
    pub tree_root_min: u64,
    pub shmem_weight: f64,
    pub growth_weight: f64,
    pub immune_override_pct: f64,
    pub kill_mode: KillMode,
    pub cgroup_kill_match: Vec<String>,
    pub never_exe: Vec<String>,
    pub never_cgroup: Vec<String>,
    pub avoid_exe: Vec<String>,
    pub prefer_exe: Vec<String>,
    pub nvml_fresh_ns: u64,
    pub vmsize_proxy_base: u64,
    pub only_kill_exe: String,
    pub cuda_file_rss_weight: f64,
}

impl VictimConfig {
    pub fn from_config(cfg: &Config, total: u64) -> Self {
        VictimConfig {
            min_victim: cfg.min_victim.resolve(total),
            tree_root_min: 128 << 20,
            shmem_weight: cfg.shmem_weight,
            growth_weight: cfg.growth_weight,
            immune_override_pct: cfg.immune_override_pct,
            kill_mode: cfg.kill_mode,
            cgroup_kill_match: cfg.cgroup_kill_match.clone(),
            never_exe: cfg.never_exe.clone(),
            never_cgroup: cfg.never_cgroup.clone(),
            avoid_exe: cfg.avoid_exe.clone(),
            prefer_exe: cfg.prefer_exe.clone(),
            nvml_fresh_ns: 250_000_000,
            vmsize_proxy_base: 16 * GIB,
            only_kill_exe: cfg.only_kill_exe.clone(),
            cuda_file_rss_weight: cfg.cuda_file_rss_weight,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    Never,
    Immune,
    Avoid,
    Normal,
    Prefer,
    Preferred,
}

impl Tier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Tier::Never => "never",
            Tier::Immune => "immune",
            Tier::Avoid => "avoid",
            Tier::Normal => "normal",
            Tier::Prefer => "prefer",
            Tier::Preferred => "preferred",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Candidate {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: String,
    pub exe: String,
    pub cgroup: String,
    pub state: u8,
    pub oom_score_adj: i32,
    pub cuda: bool,
    pub vidmem: u64,
    pub vidmem_est: bool,
    pub rss_anon: u64,
    pub rss_shmem: u64,
    pub vm_swap: u64,
    pub uvm: u64,
    pub vm_size: u64,
    pub footprint: u64,
    pub tree_footprint: u64,
    pub descendants: usize,
    /// bytes per second over the last history interval
    pub growth: f64,
    pub tier: Tier,
    pub weight: f64,
    pub score: f64,
    pub starttime: u64,
}

impl Candidate {
    pub fn describe(&self) -> String {
        format!(
            "pid={} comm={} exe={} cg={} tier={} fp={} tree={} (vid={}{} anon={} shm={} swap={} cudafile={}) growth={} adj={} score={:.3e}",
            self.pid,
            self.comm,
            basename(&self.exe),
            cgroup::unit_name(&self.cgroup).unwrap_or("/"),
            self.tier.as_str(),
            fmt_bytes(self.footprint),
            fmt_bytes(self.tree_footprint),
            fmt_bytes(self.vidmem),
            if self.vidmem_est { "~" } else { "" },
            fmt_bytes(self.rss_anon),
            fmt_bytes(self.rss_shmem),
            fmt_bytes(self.vm_swap),
            fmt_bytes(self.uvm),
            fmt_rate(self.growth),
            self.oom_score_adj,
            self.score
        )
    }

    /// Stable identity for rate limiting across restarts of the same job.
    pub fn key(&self) -> u64 {
        let mut h: u64 = 0xcbf29ce484222325;
        for b in basename(&self.exe)
            .bytes()
            .chain(b"|".iter().copied())
            .chain(self.cgroup.bytes())
        {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h
    }
}

/// Per-pid history for growth estimation.
#[derive(Default)]
pub struct History {
    map: HashMap<ProcessIdentity, (u64, u64, u64)>, // tree_footprint, t_ns, vm_size
}

impl History {
    pub fn update(&mut self, cands: &[Candidate], t_ns: u64) {
        let mut next = HashMap::with_capacity(cands.len());
        for c in cands {
            next.insert(
                ProcessIdentity {
                    pid: c.pid,
                    starttime: c.starttime,
                },
                (c.tree_footprint, t_ns, c.vm_size),
            );
        }
        self.map = next;
    }

    fn growth(
        &self,
        identity: ProcessIdentity,
        tree_fp: u64,
        vm_size: u64,
        now: u64,
        add_vmsize: bool,
    ) -> f64 {
        match self.map.get(&identity) {
            Some((fp0, t0, vm0)) => {
                let dt = now.saturating_sub(*t0) as f64 / 1e9;
                if !(0.2..=5.0).contains(&dt) {
                    return 0.0;
                }
                let mut g = tree_fp.saturating_sub(*fp0) as f64 / dt;
                if add_vmsize {
                    g += vm_size.saturating_sub(*vm0) as f64 / dt;
                }
                g
            }
            None => 0.0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KillPlan {
    Process(u32),
    /// Descendants deepest-first, root last.
    Tree(Vec<u32>),
    Cgroup(String),
}

#[derive(Clone, Debug)]
pub struct Choice {
    pub cand: Candidate,
    pub plan: KillPlan,
    pub immune_override: bool,
    pub targets: Vec<ProcessIdentity>,
    pub stop_unit_allowed: bool,
}

#[derive(Default)]
pub struct Ranking {
    /// Eligible candidates sorted by score, best first.
    pub cands: Vec<Candidate>,
    /// All scored processes (including ineligible) for `ps`/status display, sorted by own footprint.
    pub all: Vec<Candidate>,
    pub skipped_never: usize,
    pub top_immune: Option<Candidate>,
    pub nvml_fresh: bool,
    pub protected: HashSet<u32>,
}

pub struct RankInput<'a> {
    pub table: &'a ProcTable,
    pub nvml: &'a NvmlSnapshot,
    pub now_ns: u64,
    pub cfg: &'a VictimConfig,
    pub hist: &'a History,
    pub exclude: &'a HashSet<u32>,
    pub cuda_seen: &'a HashSet<u32>,
    pub total: u64,
}

fn tier_of(p: &ProcInfo, cfg: &VictimConfig) -> Tier {
    if p.pid <= 1 || p.kthread {
        return Tier::Never;
    }
    if matches_any(&cfg.never_exe, &p.exe, &p.comm) {
        return Tier::Never;
    }
    if !p.cgroup.is_empty()
        && (p.cgroup == "/init.scope" || cfg.never_cgroup.iter().any(|g| glob_match(g, &p.cgroup)))
    {
        return Tier::Never;
    }
    if p.oom_score_adj <= -1000 {
        return Tier::Immune;
    }
    if p.oom_score_adj >= 900 {
        return Tier::Preferred;
    }
    if matches_any(&cfg.prefer_exe, &p.exe, &p.comm) {
        return Tier::Prefer;
    }
    if matches_any(&cfg.avoid_exe, &p.exe, &p.comm) {
        return Tier::Avoid;
    }
    Tier::Normal
}

/// Score every process. Pure; the only inputs are the snapshots and the config.
pub fn rank(inp: &RankInput<'_>) -> Ranking {
    let cfg = inp.cfg;
    let nvml_fresh = inp.nvml.valid && inp.nvml.age_ns(inp.now_ns) <= cfg.nvml_fresh_ns;
    let mut nvml_map: HashMap<u32, u64> = HashMap::with_capacity(inp.nvml.procs.len());
    for g in &inp.nvml.procs {
        let value = nvml_map.entry(g.pid).or_insert(0u64);
        *value = value.saturating_add(g.bytes);
    }
    let top_gpu_pid = nvml_map.iter().max_by_key(|(_, b)| **b).map(|(p, _)| *p);

    let mut cands: Vec<Candidate> = Vec::with_capacity(inp.table.len());
    let mut skipped_never = 0usize;
    let mut protected = inp.exclude.clone();
    for p in &inp.table.procs {
        if matches!(tier_of(p, cfg), Tier::Never | Tier::Immune)
            || (!cfg.only_kill_exe.is_empty()
                && !matches_any(std::slice::from_ref(&cfg.only_kill_exe), &p.exe, &p.comm))
        {
            protected.insert(p.pid);
        }
    }
    for p in &inp.table.procs {
        if p.kthread || p.is_zombie() || inp.exclude.contains(&p.pid) {
            continue;
        }
        let tier = tier_of(p, cfg);
        if tier == Tier::Never {
            skipped_never += 1;
            continue;
        }
        let known = nvml_map.get(&p.pid).copied().unwrap_or(0);
        let cuda = known > 0
            || nvml_map.contains_key(&p.pid)
            || inp.cuda_seen.contains(&p.pid)
            || p.nvidia_maps;
        let (vidmem, vidmem_est) = if nvml_fresh {
            (known, false)
        } else if cuda {
            let proxy = p
                .vm_size
                .saturating_sub(cfg.vmsize_proxy_base)
                .min(inp.total);
            (known.max(proxy), true)
        } else {
            (0, false)
        };
        // UVM virtual address reservations are not resident memory and are never counted.
        // Managed pages populated by the GPU do show up as RssFile, but so do shared libraries
        // and mmapped model files (reclaimable page cache), so RssFile of CUDA processes is only
        // counted when cuda_file_rss_weight is configured for managed-memory workloads.
        let uvm = if cuda {
            (p.rss_file as f64 * cfg.cuda_file_rss_weight) as u64
        } else {
            0
        };
        let footprint = vidmem
            .saturating_add(p.rss_anon)
            .saturating_add((p.rss_shmem as f64 * cfg.shmem_weight) as u64)
            .saturating_add(p.vm_swap)
            .saturating_add(uvm);
        let tier_factor = match tier {
            Tier::Avoid => 0.5,
            Tier::Prefer => 2.0,
            _ => 1.0,
        };
        let weight = (((1000 + p.oom_score_adj.clamp(-1000, 1000)) as f64) / 1000.0).max(0.001)
            * tier_factor;
        cands.push(Candidate {
            pid: p.pid,
            ppid: p.ppid,
            uid: p.uid,
            comm: p.comm.clone(),
            exe: p.exe.clone(),
            cgroup: p.cgroup.clone(),
            state: p.state,
            oom_score_adj: p.oom_score_adj,
            cuda,
            vidmem,
            vidmem_est,
            rss_anon: p.rss_anon,
            rss_shmem: p.rss_shmem,
            vm_swap: p.vm_swap,
            uvm,
            vm_size: p.vm_size,
            footprint,
            tree_footprint: footprint,
            descendants: 0,
            growth: 0.0,
            tier,
            weight,
            score: 0.0,
            starttime: p.starttime,
        });
    }

    // tree aggregation (descendants that are themselves candidates or not: all count, they die too)
    let use_tree = matches!(cfg.kill_mode, KillMode::Auto | KillMode::Tree);
    let fp_by_pid: HashMap<u32, u64> = cands.iter().map(|c| (c.pid, c.footprint)).collect();
    if use_tree {
        for c in cands.iter_mut() {
            let desc = inp.table.descendants(c.pid);
            if desc.iter().any(|p| protected.contains(p)) {
                continue; // only this process may be killed, so only its own memory counts
            }
            c.descendants = desc.len();
            let mut sum = c.footprint;
            for d in &desc {
                sum = sum.saturating_add(fp_by_pid.get(d).copied().unwrap_or(0));
            }
            c.tree_footprint = sum;
        }
    }

    for c in cands.iter_mut() {
        c.growth = inp
            .hist
            .growth(
                ProcessIdentity {
                    pid: c.pid,
                    starttime: c.starttime,
                },
                c.tree_footprint,
                c.vm_size,
                inp.now_ns,
                !nvml_fresh && c.cuda,
            )
            .max(0.0);
        let base = c.tree_footprint as f64 + cfg.growth_weight * c.growth;
        c.score = base * c.weight;
        if c.tier == Tier::Preferred {
            c.score += 1e18;
        }
    }

    let mut all = cands.clone();
    all.sort_by_key(|a| std::cmp::Reverse(a.footprint));

    let mut top_immune: Option<Candidate> = None;
    let total = inp.total;
    let mut eligible: Vec<Candidate> = Vec::with_capacity(cands.len());
    for mut c in cands {
        if c.tree_footprint < cfg.min_victim {
            continue;
        }
        if use_tree && c.descendants > 0 && c.footprint < cfg.tree_root_min {
            // a shell or launcher with no memory of its own must not be the kill root
            continue;
        }
        if c.tier == Tier::Immune {
            let override_ok = cfg.immune_override_pct > 0.0
                && nvml_fresh
                && top_gpu_pid == Some(c.pid)
                && (c.vidmem as f64) >= total as f64 * cfg.immune_override_pct / 100.0;
            if !override_ok {
                if top_immune
                    .as_ref()
                    .is_none_or(|t| c.tree_footprint > t.tree_footprint)
                {
                    top_immune = Some(c.clone());
                }
                continue;
            }
            // overriding -1000: rank it like a normal process holding that much memory
            c.weight = 1.0;
            c.score = c.tree_footprint as f64 + cfg.growth_weight * c.growth;
        }
        eligible.push(c);
    }
    eligible.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Ranking {
        cands: eligible,
        all,
        skipped_never,
        top_immune,
        nvml_fresh,
        protected,
    }
}

/// Pick the top candidate and decide how to kill it.
pub fn choose(r: &Ranking, table: &ProcTable, cfg: &VictimConfig) -> Option<Choice> {
    let c = r.cands.first()?.clone();
    let cg_members: Vec<_> = table
        .procs
        .iter()
        .filter(|p| cgroup::contains(&c.cgroup, &p.cgroup))
        .collect();
    let whole_cgroup_safe = !c.cgroup.is_empty()
        && !cg_members.is_empty()
        && cg_members
            .iter()
            .all(|p| p.pid == c.pid || !r.protected.contains(&p.pid));
    let cg_ok = cfg.only_kill_exe.is_empty()
        && whole_cgroup_safe
        && cgroup::kill_allowed(&c.cgroup, &cfg.cgroup_kill_match);
    let tree_plan = || {
        let mut v = table.descendants(c.pid);
        if v.iter().any(|p| r.protected.contains(p)) {
            return KillPlan::Process(c.pid);
        }
        v.push(c.pid);
        KillPlan::Tree(v)
    };
    let plan = match cfg.kill_mode {
        KillMode::Process => KillPlan::Process(c.pid),
        KillMode::Tree => tree_plan(),
        KillMode::Cgroup | KillMode::Auto => {
            if cg_ok {
                KillPlan::Cgroup(c.cgroup.clone())
            } else {
                tree_plan()
            }
        }
    };
    let immune_override = c.tier == Tier::Immune;
    let targets = match &plan {
        KillPlan::Process(pid) => table
            .get(*pid)
            .map(|p| vec![p.identity()])
            .unwrap_or_default(),
        KillPlan::Tree(pids) => pids
            .iter()
            .filter_map(|pid| table.get(*pid).map(ProcInfo::identity))
            .collect(),
        KillPlan::Cgroup(_) => cg_members.iter().map(|p| p.identity()).collect(),
    };
    Some(Choice {
        cand: c,
        plan,
        immune_override,
        targets,
        stop_unit_allowed: whole_cgroup_safe && cfg.only_kill_exe.is_empty(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(
        pid: u32,
        ppid: u32,
        exe: &str,
        anon: u64,
        vm_size: u64,
        adj: i32,
        cg: &str,
    ) -> ProcInfo {
        ProcInfo {
            pid,
            ppid,
            uid: 1001,
            starttime: 100 + pid as u64,
            state: b'S',
            comm: basename(exe).chars().take(15).collect(),
            exe: exe.to_string(),
            cgroup: cg.to_string(),
            vm_size,
            rss_anon: anon,
            oom_score_adj: adj,
            ..Default::default()
        }
    }

    fn vcfg() -> VictimConfig {
        VictimConfig::from_config(&Config::default(), 120 * GIB)
    }

    fn run(table: &ProcTable, nvml: &NvmlSnapshot, cfg: &VictimConfig, hist: &History) -> Ranking {
        let ex = HashSet::new();
        let seen = HashSet::new();
        rank(&RankInput {
            table,
            nvml,
            now_ns: 1_000_000_000,
            cfg,
            hist,
            exclude: &ex,
            cuda_seen: &seen,
            total: 120 * GIB,
        })
    }

    const SCOPE: &str = "/user.slice/user-1001.slice/user@1001.service/tmux-spawn-abc.scope";

    #[test]
    fn gpu_hog_beats_big_rss_and_never_list_holds() {
        let table = ProcTable::from_procs(
            0,
            vec![
                proc(
                    1,
                    0,
                    "/usr/lib/systemd/systemd",
                    10 << 20,
                    GIB,
                    0,
                    "/init.scope",
                ),
                proc(
                    100,
                    1,
                    "/usr/sbin/sshd",
                    30 * GIB,
                    40 * GIB,
                    0,
                    "/system.slice/ssh.service",
                ),
                proc(200, 1, "/usr/bin/node", 20 * GIB, 25 * GIB, 0, SCOPE),
                proc(300, 1, "/usr/bin/python3.12", GIB, 80 * GIB, 0, SCOPE),
            ],
            0,
        );
        let nvml = NvmlSnapshot {
            procs: vec![GpuProc {
                pid: 300,
                bytes: 60 * GIB,
            }],
            t_ns: 1_000_000_000,
            valid: true,
        };
        let r = run(&table, &nvml, &vcfg(), &History::default());
        assert!(r.nvml_fresh);
        assert_eq!(r.cands[0].pid, 300);
        assert_eq!(r.cands[0].vidmem, 60 * GIB);
        assert!(!r.cands[0].vidmem_est);
        assert!(
            r.cands.iter().all(|c| c.pid != 100),
            "sshd must never be a candidate"
        );
        assert!(r.skipped_never >= 2);
        let ch = choose(&r, &table, &vcfg()).unwrap();
        assert_eq!(ch.plan, KillPlan::Tree(vec![300]));
    }

    #[test]
    fn stale_nvml_uses_vmsize_proxy_for_cuda_processes() {
        let table = ProcTable::from_procs(
            0,
            vec![
                proc(200, 1, "/usr/bin/node", 20 * GIB, 25 * GIB, 0, SCOPE),
                {
                    let mut p = proc(300, 1, "/usr/bin/python3.12", 50 << 20, 150 * GIB, 0, SCOPE);
                    p.nvidia_maps = true;
                    p
                },
            ],
            0,
        );
        // NVML snapshot is 700 ms old and does not list the new hog
        let nvml = NvmlSnapshot {
            procs: vec![],
            t_ns: 300_000_000,
            valid: true,
        };
        let r = run(&table, &nvml, &vcfg(), &History::default());
        assert!(!r.nvml_fresh);
        assert_eq!(r.cands[0].pid, 300);
        assert!(r.cands[0].vidmem_est);
        assert_eq!(r.cands[0].vidmem, 120 * GIB); // clipped to total
                                                  // without NVML and without nvidia maps, only RSS counts
        let table2 = ProcTable::from_procs(
            0,
            vec![
                proc(200, 1, "/usr/bin/node", 20 * GIB, 25 * GIB, 0, SCOPE),
                proc(300, 1, "/usr/bin/python3.12", 50 << 20, 150 * GIB, 0, SCOPE),
            ],
            0,
        );
        let r2 = run(&table2, &nvml, &vcfg(), &History::default());
        assert_eq!(r2.cands[0].pid, 200);
    }

    #[test]
    fn immune_skipped_unless_override() {
        let table = ProcTable::from_procs(
            0,
            vec![
                proc(300, 1, "/usr/bin/python3.12", GIB, 80 * GIB, -1000, SCOPE),
                proc(200, 1, "/usr/bin/node", 4 * GIB, 25 * GIB, 0, SCOPE),
            ],
            0,
        );
        let nvml = NvmlSnapshot {
            procs: vec![GpuProc {
                pid: 300,
                bytes: 30 * GIB,
            }],
            t_ns: 1_000_000_000,
            valid: true,
        };
        let r = run(&table, &nvml, &vcfg(), &History::default());
        assert_eq!(r.cands[0].pid, 200);
        assert_eq!(r.top_immune.as_ref().unwrap().pid, 300);
        // holding > 50% of RAM as top GPU holder: override
        let nvml2 = NvmlSnapshot {
            procs: vec![GpuProc {
                pid: 300,
                bytes: 70 * GIB,
            }],
            t_ns: 1_000_000_000,
            valid: true,
        };
        let r2 = run(&table, &nvml2, &vcfg(), &History::default());
        assert_eq!(r2.cands[0].pid, 300);
        let ch = choose(&r2, &table, &vcfg()).unwrap();
        assert!(ch.immune_override);
        // override disabled by config
        let mut c = vcfg();
        c.immune_override_pct = 0.0;
        let r3 = run(&table, &nvml2, &c, &History::default());
        assert_eq!(r3.cands[0].pid, 200);
    }

    #[test]
    fn tree_aggregation_and_shell_roots() {
        let table = ProcTable::from_procs(
            0,
            vec![
                proc(50, 1, "/usr/bin/bash", 5 << 20, 10 << 20, 0, SCOPE),
                proc(60, 50, "/usr/bin/python3.12", 300 << 20, 2 * GIB, 0, SCOPE), // torchrun launcher
                proc(61, 60, "/usr/bin/python3.12", 10 * GIB, 30 * GIB, 0, SCOPE),
                proc(62, 60, "/usr/bin/python3.12", 10 * GIB, 30 * GIB, 0, SCOPE),
                proc(200, 1, "/usr/bin/node", 15 * GIB, 25 * GIB, 0, SCOPE),
            ],
            0,
        );
        let nvml = NvmlSnapshot {
            procs: vec![],
            t_ns: 1_000_000_000,
            valid: true,
        };
        let r = run(&table, &nvml, &vcfg(), &History::default());
        // launcher aggregates its workers (20.3 GiB) and beats node (15 GiB); bash is not a root
        assert_eq!(
            r.cands[0].pid,
            60,
            "{:?}",
            r.cands
                .iter()
                .map(|c| (c.pid, c.tree_footprint / GIB))
                .collect::<Vec<_>>()
        );
        assert!(r.cands.iter().all(|c| c.pid != 50));
        let ch = choose(&r, &table, &vcfg()).unwrap();
        match ch.plan {
            KillPlan::Tree(v) => {
                assert_eq!(*v.last().unwrap(), 60);
                assert!(v.contains(&61) && v.contains(&62));
            }
            other => panic!("unexpected plan {other:?}"),
        }
    }

    #[test]
    fn cgroup_kill_only_on_allowlist_and_preferred_tier() {
        let docker = "/system.slice/docker-0123abcd.scope";
        let table = ProcTable::from_procs(
            0,
            vec![
                proc(400, 1, "/usr/bin/python3", 20 * GIB, 30 * GIB, 0, docker),
                proc(500, 1, "/opt/hog", 2 * GIB, 3 * GIB, 1000, SCOPE),
            ],
            0,
        );
        let nvml = NvmlSnapshot {
            procs: vec![],
            t_ns: 1_000_000_000,
            valid: true,
        };
        let r = run(&table, &nvml, &vcfg(), &History::default());
        // adj 1000 is the preferred victim despite the smaller footprint
        assert_eq!(r.cands[0].pid, 500);
        assert_eq!(r.cands[0].tier, Tier::Preferred);
        let ch = choose(&r, &table, &vcfg()).unwrap();
        assert_eq!(ch.plan, KillPlan::Tree(vec![500]));
        // container victim -> cgroup kill
        let table2 = ProcTable::from_procs(
            0,
            vec![proc(
                400,
                1,
                "/usr/bin/python3",
                20 * GIB,
                30 * GIB,
                0,
                docker,
            )],
            0,
        );
        let r2 = run(&table2, &nvml, &vcfg(), &History::default());
        let ch2 = choose(&r2, &table2, &vcfg()).unwrap();
        assert_eq!(ch2.plan, KillPlan::Cgroup(docker.to_string()));
        let mut c = vcfg();
        c.kill_mode = KillMode::Process;
        let ch3 = choose(&r2, &table2, &c).unwrap();
        assert_eq!(ch3.plan, KillPlan::Process(400));
    }

    #[test]
    fn growth_bonus_and_min_victim() {
        let table = ProcTable::from_procs(
            0,
            vec![
                proc(600, 1, "/usr/bin/python3", 10 * GIB, 20 * GIB, 0, SCOPE),
                proc(700, 1, "/usr/bin/python3", 12 * GIB, 20 * GIB, 0, SCOPE),
                proc(800, 1, "/usr/bin/tiny", 100 << 20, GIB, 0, SCOPE),
            ],
            0,
        );
        let nvml = NvmlSnapshot {
            procs: vec![],
            t_ns: 1_000_000_000,
            valid: true,
        };
        let mut hist = History::default();
        // one second ago pid 600 had 2 GiB (growing 8 GiB/s), pid 700 was static
        let prev = vec![
            Candidate {
                pid: 600,
                starttime: 700,
                tree_footprint: 2 * GIB,
                vm_size: 20 * GIB,
                ..dummy()
            },
            Candidate {
                pid: 700,
                starttime: 800,
                tree_footprint: 12 * GIB,
                vm_size: 20 * GIB,
                ..dummy()
            },
        ];
        hist.update(&prev, 0);
        let r = run(&table, &nvml, &vcfg(), &hist);
        assert_eq!(r.cands[0].pid, 600, "fast grower should win");
        assert!(r.cands.iter().all(|c| c.pid != 800), "below min_victim");
    }

    #[test]
    fn protected_descendants_and_cgroup_members_prevent_broad_kills() {
        for (exe, adj) in [("/usr/sbin/sshd", 0), ("/opt/worker", -1000)] {
            let cg = "/system.slice/memguard-test.scope";
            let table = ProcTable::from_procs(
                0,
                vec![
                    proc(300, 1, "/usr/bin/python3", 30 * GIB, 40 * GIB, 0, cg),
                    proc(301, 300, exe, GIB, 2 * GIB, adj, cg),
                ],
                0,
            );
            let cfg = vcfg();
            let r = run(&table, &NvmlSnapshot::default(), &cfg, &History::default());
            let choice = choose(&r, &table, &cfg).unwrap();
            assert_eq!(choice.cand.tree_footprint, 30 * GIB);
            assert_eq!(choice.plan, KillPlan::Process(300));
            assert!(!choice.stop_unit_allowed);
            assert_eq!(choice.targets, vec![table.get(300).unwrap().identity()]);
        }
    }

    #[test]
    fn test_mode_cannot_kill_nonmatching_child_or_entire_scope() {
        let cg = "/system.slice/memguard-test.scope";
        let table = ProcTable::from_procs(
            0,
            vec![
                proc(300, 1, "/opt/hog", 30 * GIB, 40 * GIB, 1000, cg),
                proc(301, 300, "/usr/bin/sleep", 0, 0, 0, cg),
            ],
            0,
        );
        let mut cfg = vcfg();
        cfg.only_kill_exe = "/opt/hog".into();
        let r = run(&table, &NvmlSnapshot::default(), &cfg, &History::default());
        let choice = choose(&r, &table, &cfg).unwrap();
        assert_eq!(choice.plan, KillPlan::Process(300));
        assert!(!choice.stop_unit_allowed);
    }

    #[test]
    fn uvm_reservations_are_not_resident_memory() {
        let mut p = proc(300, 1, "/opt/cuda", GIB, 120 * GIB, 0, SCOPE);
        p.nvidia_maps = true;
        p.uvm_vsize = 100 * GIB;
        let table = ProcTable::from_procs(0, vec![p], 0);
        let snapshot = NvmlSnapshot {
            valid: true,
            t_ns: 1_000_000_000,
            procs: vec![],
        };
        let r = run(&table, &snapshot, &vcfg(), &History::default());
        assert_eq!(r.cands[0].footprint, GIB);
    }

    #[test]
    fn stale_nvml_does_not_override_oom_immunity() {
        let table = ProcTable::from_procs(
            0,
            vec![proc(300, 1, "/opt/cuda", GIB, 120 * GIB, -1000, SCOPE)],
            0,
        );
        let snapshot = NvmlSnapshot {
            valid: true,
            t_ns: 0,
            procs: vec![GpuProc {
                pid: 300,
                bytes: 100 * GIB,
            }],
        };
        assert!(run(&table, &snapshot, &vcfg(), &History::default())
            .cands
            .is_empty());
    }

    #[test]
    fn reused_pid_does_not_inherit_growth() {
        let table = ProcTable::from_procs(
            0,
            vec![proc(300, 1, "/opt/job", 20 * GIB, 30 * GIB, 0, SCOPE)],
            0,
        );
        let mut history = History::default();
        history.update(
            &[Candidate {
                pid: 300,
                starttime: 1,
                tree_footprint: GIB,
                ..dummy()
            }],
            0,
        );
        let r = run(&table, &NvmlSnapshot::default(), &vcfg(), &history);
        assert_eq!(r.cands[0].growth, 0.0);
    }

    fn dummy() -> Candidate {
        Candidate {
            pid: 0,
            ppid: 0,
            uid: 0,
            comm: String::new(),
            exe: String::new(),
            cgroup: String::new(),
            state: b'S',
            oom_score_adj: 0,
            cuda: false,
            vidmem: 0,
            vidmem_est: false,
            rss_anon: 0,
            rss_shmem: 0,
            vm_swap: 0,
            uvm: 0,
            vm_size: 0,
            footprint: 0,
            tree_footprint: 0,
            descendants: 0,
            growth: 0.0,
            tier: Tier::Normal,
            weight: 1.0,
            score: 0.0,
            starttime: 0,
        }
    }
}
