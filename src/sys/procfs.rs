//! `/proc/<pid>` readers and the process table used for victim selection.
//!
//! Only lockless files are read in the periodic scan (`status`, `stat`, `cgroup`, `exe` link,
//! `oom_score_adj`). NVIDIA descriptors are detected via fd symlinks. `maps` and `cmdline`
//! are never read because they can block on the target's mmap_lock.

use std::collections::{HashMap, HashSet};

use super::meminfo::parse_u64_prefix;

/// A PID is not an identity: Linux can reuse it after a process exits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub starttime: u64,
}

impl ProcessIdentity {
    pub fn read(pid: u32) -> Option<Self> {
        Some(Self {
            pid,
            starttime: starttime(pid)?,
        })
    }

    pub fn alive(self) -> bool {
        starttime(self.pid) == Some(self.starttime) && alive(self.pid)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub starttime: u64,
    pub state: u8,
    pub kthread: bool,
    pub comm: String,
    pub exe: String,
    pub cgroup: String,
    pub vm_size: u64,
    pub rss_anon: u64,
    pub rss_file: u64,
    pub rss_shmem: u64,
    pub vm_swap: u64,
    pub oom_score_adj: i32,
    pub nspid_depth: u8,
    pub threads: u32,
    /// Process has an open /dev/nvidia* descriptor. Only checked when requested.
    pub nvidia_maps: bool,
    pub nvidia_checked: bool,
    /// Legacy snapshot field: virtual UVM size is not measured or added to resident usage.
    pub uvm_vsize: u64,
}

impl ProcInfo {
    pub fn identity(&self) -> ProcessIdentity {
        ProcessIdentity {
            pid: self.pid,
            starttime: self.starttime,
        }
    }
    pub fn exe_base(&self) -> &str {
        crate::config::basename(&self.exe)
    }
    pub fn is_zombie(&self) -> bool {
        self.state == b'Z' || self.state == b'X'
    }
}

#[derive(Default)]
pub struct ProcTable {
    pub t_ns: u64,
    pub procs: Vec<ProcInfo>,
    index: HashMap<u32, usize>,
    children: HashMap<u32, Vec<u32>>,
    pub scan_us: u64,
}

impl ProcTable {
    pub fn from_procs(t_ns: u64, procs: Vec<ProcInfo>, scan_us: u64) -> Self {
        let mut index = HashMap::with_capacity(procs.len());
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        for (i, p) in procs.iter().enumerate() {
            index.insert(p.pid, i);
            if p.ppid != 0 {
                children.entry(p.ppid).or_default().push(p.pid);
            }
        }
        ProcTable {
            t_ns,
            procs,
            index,
            children,
            scan_us,
        }
    }

    pub fn get(&self, pid: u32) -> Option<&ProcInfo> {
        self.index.get(&pid).map(|i| &self.procs[*i])
    }

    pub fn children_of(&self, pid: u32) -> &[u32] {
        self.children.get(&pid).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// All descendants of `pid` (not including `pid`), deepest first (safe kill order).
    pub fn descendants(&self, pid: u32) -> Vec<u32> {
        let mut out = Vec::new();
        let mut stack = vec![pid];
        let mut seen = HashSet::from([pid]);
        while let Some(p) = stack.pop() {
            for c in self.children_of(p) {
                if seen.insert(*c) {
                    out.push(*c);
                    stack.push(*c);
                }
            }
        }
        out.reverse();
        out
    }

    pub fn len(&self) -> usize {
        self.procs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.procs.is_empty()
    }
}

fn read_small(path: &str, cap: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = Vec::with_capacity(cap);
    f.read_to_end(&mut buf).ok()?;
    Some(buf)
}

fn kb_value(rest: &[u8]) -> u64 {
    let (v, tail) = parse_u64_prefix(rest);
    if tail.windows(2).any(|w| w == b"kB") {
        v.saturating_mul(1024)
    } else {
        v
    }
}

/// Parse /proc/<pid>/status text into the relevant fields.
pub fn parse_status(buf: &[u8], p: &mut ProcInfo) {
    let mut saw_vmsize = false;
    for line in buf.split(|b| *b == b'\n') {
        let colon = match line.iter().position(|b| *b == b':') {
            Some(c) => c,
            None => continue,
        };
        let key = &line[..colon];
        let rest = &line[colon + 1..];
        match key {
            b"Name" => p.comm = String::from_utf8_lossy(rest).trim().to_string(),
            b"State" => {
                p.state = rest
                    .iter()
                    .copied()
                    .find(|b| !b.is_ascii_whitespace())
                    .unwrap_or(b'?')
            }
            b"PPid" => p.ppid = parse_u64_prefix(rest).0 as u32,
            b"Uid" => p.uid = parse_u64_prefix(rest).0 as u32,
            b"NSpid" => {
                p.nspid_depth = rest
                    .split(|b| *b == b'\t' || *b == b' ')
                    .filter(|s| !s.is_empty())
                    .count() as u8
            }
            b"VmSize" => {
                p.vm_size = kb_value(rest);
                saw_vmsize = true;
            }
            b"RssAnon" => p.rss_anon = kb_value(rest),
            b"RssFile" => p.rss_file = kb_value(rest),
            b"RssShmem" => p.rss_shmem = kb_value(rest),
            b"VmSwap" => p.vm_swap = kb_value(rest),
            b"Threads" => p.threads = parse_u64_prefix(rest).0 as u32,
            b"Kthread" => p.kthread = parse_u64_prefix(rest).0 == 1,
            _ => {}
        }
    }
    if !saw_vmsize && !p.is_zombie() {
        // kernels without the Kthread field: kernel threads have no address space
        p.kthread = true;
    }
}

/// Parse /proc/<pid>/stat: returns (state, ppid, starttime, utime+stime in ticks).
pub fn parse_stat(buf: &[u8]) -> Option<(u8, u32, u64, u64)> {
    let close = buf.iter().rposition(|b| *b == b')')?;
    let rest = &buf[close + 1..];
    let fields: Vec<&[u8]> = rest
        .split(|b| *b == b' ')
        .filter(|s| !s.is_empty())
        .collect();
    // fields[0]=state, [1]=ppid, [11]=utime, [12]=stime, [19]=starttime
    if fields.len() < 20 {
        return None;
    }
    let state = fields[0].first().copied().unwrap_or(b'?');
    let ppid = parse_u64_prefix(fields[1]).0 as u32;
    let utime = parse_u64_prefix(fields[11]).0;
    let stime = parse_u64_prefix(fields[12]).0;
    let start = parse_u64_prefix(fields[19]).0;
    Some((state, ppid, start, utime + stime))
}

pub fn starttime(pid: u32) -> Option<u64> {
    let buf = read_small(&format!("/proc/{pid}/stat"), 512)?;
    parse_stat(&buf).map(|t| t.2)
}

pub fn state(pid: u32) -> Option<u8> {
    let buf = read_small(&format!("/proc/{pid}/stat"), 512)?;
    parse_stat(&buf).map(|t| t.0)
}

/// True if the pid exists and is not a zombie.
pub fn alive(pid: u32) -> bool {
    matches!(state(pid), Some(s) if s != b'Z' && s != b'X')
}

pub fn pid_cgroup(pid: u32) -> Option<String> {
    let buf = read_small(&format!("/proc/{pid}/cgroup"), 512)?;
    for line in buf.split(|b| *b == b'\n') {
        if let Some(rest) = line.strip_prefix(b"0::") {
            return Some(String::from_utf8_lossy(rest).trim().to_string());
        }
    }
    None
}

/// Detect NVIDIA device descriptors without reading maps, which can block on mmap_lock.
/// Virtual mappings are not resident memory and are never added to the footprint.
pub fn nvidia_maps(pid: u32) -> Option<(bool, u64)> {
    let entries = std::fs::read_dir(format!("/proc/{pid}/fd")).ok()?;
    let any = entries.flatten().any(|e| {
        std::fs::read_link(e.path()).is_ok_and(|p| p.to_string_lossy().starts_with("/dev/nvidia"))
    });
    Some((any, 0))
}

/// Read one process. Returns None if it vanished.
pub fn read_proc(pid: u32) -> Option<ProcInfo> {
    let mut p = read_proc_basic(pid)?;
    fill_details(&mut p);
    (starttime(pid) == Some(p.starttime)).then_some(p)
}

/// Read oom_score_adj, cgroup and exe (only needed for processes that can become victims).
pub fn fill_details(p: &mut ProcInfo) {
    let pid = p.pid;
    if let Some(adj) = read_small(&format!("/proc/{pid}/oom_score_adj"), 32) {
        let s = String::from_utf8_lossy(&adj);
        p.oom_score_adj = s.trim().parse().unwrap_or(0);
    }
    p.cgroup = pid_cgroup(pid).unwrap_or_default();
    if !p.kthread {
        if let Ok(link) = std::fs::read_link(format!("/proc/{pid}/exe")) {
            p.exe = link.to_string_lossy().into_owned();
        }
    }
}

/// status + stat only (cheap). Returns None if the process vanished.
pub fn read_proc_basic(pid: u32) -> Option<ProcInfo> {
    let stat = read_small(&format!("/proc/{pid}/stat"), 512)?;
    let (_, _, start, _) = parse_stat(&stat)?;
    let status = read_small(&format!("/proc/{pid}/status"), 2048)?;
    let mut p = ProcInfo {
        pid,
        starttime: start,
        ..Default::default()
    };
    parse_status(&status, &mut p);
    Some(p)
}

pub struct ScanOptions<'a> {
    /// PIDs whose /dev/nvidia maps should be inspected (e.g. NVML-listed processes).
    pub maps_for: &'a [u32],
    /// Retained for source compatibility; every process now needs protection details.
    pub detail_min: u64,
    /// Also inspect maps for any process with VmSize >= this (0 disables). Big VmSize without
    /// NVML presence is how a brand-new CUDA hog looks while NVML is blocked.
    pub maps_min_vmsize: u64,
}

/// Enumerate /proc and build a table. Never panics; unreadable processes are skipped.
pub fn scan(opts: &ScanOptions<'_>) -> ProcTable {
    let t0 = crate::mono_ns();
    let mut procs = Vec::with_capacity(1024);
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for ent in rd.flatten() {
            let name = ent.file_name();
            let s = match name.to_str() {
                Some(s) => s,
                None => continue,
            };
            if !s.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let pid: u32 = match s.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            if let Some(mut p) = read_proc_basic(pid) {
                let big = opts.maps_for.contains(&pid)
                    || (opts.maps_min_vmsize > 0 && p.vm_size >= opts.maps_min_vmsize);
                // Small descendants still need protection and identity checks before tree kills.
                if !p.kthread {
                    fill_details(&mut p);
                }
                let want_maps = !p.kthread && !p.is_zombie() && big;
                if want_maps {
                    if let Some((any, uvm)) = nvidia_maps(pid) {
                        p.nvidia_maps = any;
                        p.uvm_vsize = uvm;
                        p.nvidia_checked = true;
                    }
                }
                if starttime(pid) == Some(p.starttime) {
                    procs.push(p);
                }
            }
        }
    }
    let t1 = crate::mono_ns();
    ProcTable::from_procs(t1, procs, (t1 - t0) / 1000)
}

/// Depth of our own PID namespace nesting (1 = host).
pub fn self_nspid_depth() -> u8 {
    read_proc(std::process::id())
        .map(|p| p.nspid_depth)
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_status_fields() {
        let txt = b"Name:\tpython3\nState:\tR (running)\nTgid:\t42\nPid:\t42\nPPid:\t7\nUid:\t1001\t1001\t1001\t1001\nNSpid:\t42\nVmSize:\t 284990296 kB\nRssAnon:\t 0 kB\nRssFile:\t 28132 kB\nRssShmem:\t 540 kB\nVmSwap:\t 2048 kB\nThreads:\t12\nKthread:\t0\n";
        let mut p = ProcInfo::default();
        parse_status(txt, &mut p);
        assert_eq!(p.comm, "python3");
        assert_eq!(p.state, b'R');
        assert_eq!(p.ppid, 7);
        assert_eq!(p.uid, 1001);
        assert_eq!(p.vm_size, 284990296 * 1024);
        assert_eq!(p.rss_file, 28132 * 1024);
        assert_eq!(p.vm_swap, 2048 * 1024);
        assert_eq!(p.threads, 12);
        assert!(!p.kthread);
        assert_eq!(p.nspid_depth, 1);
        let mut k = ProcInfo::default();
        parse_status(
            b"Name:\tkworker/0:1\nState:\tI (idle)\nPPid:\t2\nThreads:\t1\n",
            &mut k,
        );
        assert!(k.kthread);
    }

    #[test]
    fn parse_stat_fields() {
        let txt = b"1234 (pt main (x)) S 7 1234 1234 0 -1 4194560 100 0 0 0 55 66 0 0 20 0 12 0 987654 1000 500 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0";
        let (st, ppid, start, cpu) = parse_stat(txt).unwrap();
        assert_eq!(st, b'S');
        assert_eq!(ppid, 7);
        assert_eq!(start, 987654);
        assert_eq!(cpu, 121);
        assert!(parse_stat(b"bad").is_none());
    }

    #[test]
    fn live_scan_contains_self() {
        let t = scan(&ScanOptions {
            maps_for: &[],
            maps_min_vmsize: 0,
            detail_min: 0,
        });
        let me = t.get(std::process::id()).expect("self in table");
        assert!(!me.kthread);
        assert!(me.vm_size > 0);
        assert!(me.starttime > 0);
        assert!(!me.cgroup.is_empty());
        assert!(t.get(1).is_some());
        assert!(starttime(std::process::id()).is_some());
        assert!(alive(std::process::id()));
        assert!(!alive(u32::MAX - 1));
    }

    #[test]
    fn descendants_order() {
        let mk = |pid, ppid| ProcInfo {
            pid,
            ppid,
            ..Default::default()
        };
        let t = ProcTable::from_procs(
            0,
            vec![mk(1, 0), mk(10, 1), mk(11, 10), mk(12, 11), mk(20, 1)],
            0,
        );
        let d = t.descendants(10);
        assert_eq!(d, vec![12, 11]);
        assert!(t.descendants(20).is_empty());
    }
}
