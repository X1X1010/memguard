//! cgroup v2 helpers: paths, memory stats/events, process lists, `cgroup.kill`, root
//! `memory.reclaim`, and unit classification for the kill allow-list.

use std::io;
use std::path::PathBuf;

use super::meminfo::parse_u64_prefix;
use super::psi::Psi;

pub const ROOT: &str = "/sys/fs/cgroup";

pub fn contains(parent: &str, child: &str) -> bool {
    (parent == "/" && child.starts_with('/'))
        || (!parent.is_empty()
            && (child == parent
                || child
                    .strip_prefix(parent)
                    .is_some_and(|s| s.starts_with('/'))))
}

pub fn fs_path(rel: &str) -> PathBuf {
    let mut p = PathBuf::from(ROOT);
    let rel = rel.trim_start_matches('/');
    if !rel.is_empty() {
        p.push(rel);
    }
    p
}

pub fn exists(rel: &str) -> bool {
    fs_path(rel).join("cgroup.procs").exists()
}

pub fn self_cgroup() -> Option<String> {
    super::procfs::pid_cgroup(std::process::id())
}

fn read_text(rel: &str, file: &str) -> io::Result<String> {
    std::fs::read_to_string(fs_path(rel).join(file))
}

/// Read a single integer file; "max" maps to u64::MAX.
pub fn read_u64(rel: &str, file: &str) -> io::Result<u64> {
    let t = read_text(rel, file)?;
    let t = t.trim();
    if t == "max" {
        return Ok(u64::MAX);
    }
    t.parse::<u64>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("{file}: '{t}'")))
}

pub fn write_file(rel: &str, file: &str, content: &str) -> io::Result<()> {
    std::fs::write(fs_path(rel).join(file), content)
}

#[derive(Default, Clone, Copy, Debug, PartialEq)]
pub struct MemStat {
    pub anon: u64,
    pub file: u64,
    pub kernel: u64,
    pub shmem: u64,
    pub file_mapped: u64,
    pub unevictable: u64,
    pub slab: u64,
    pub pagetables: u64,
}

pub fn parse_memstat(text: &str) -> MemStat {
    let mut m = MemStat::default();
    for line in text.lines() {
        let (k, v) = match line.split_once(' ') {
            Some(kv) => kv,
            None => continue,
        };
        let val = parse_u64_prefix(v.as_bytes()).0;
        match k {
            "anon" => m.anon = val,
            "file" => m.file = val,
            "kernel" => m.kernel = val,
            "shmem" => m.shmem = val,
            "file_mapped" => m.file_mapped = val,
            "unevictable" => m.unevictable = val,
            "slab" => m.slab = val,
            "pagetables" => m.pagetables = val,
            _ => {}
        }
    }
    m
}

pub fn read_memstat(rel: &str) -> io::Result<MemStat> {
    Ok(parse_memstat(&read_text(rel, "memory.stat")?))
}

#[derive(Default, Clone, Copy, Debug, PartialEq)]
pub struct MemEvents {
    pub low: u64,
    pub high: u64,
    pub max: u64,
    pub oom: u64,
    pub oom_kill: u64,
    pub oom_group_kill: u64,
}

pub fn parse_events(text: &str) -> MemEvents {
    let mut e = MemEvents::default();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(' ') {
            let val = parse_u64_prefix(v.as_bytes()).0;
            match k {
                "low" => e.low = val,
                "high" => e.high = val,
                "max" => e.max = val,
                "oom" => e.oom = val,
                "oom_kill" => e.oom_kill = val,
                "oom_group_kill" => e.oom_group_kill = val,
                _ => {}
            }
        }
    }
    e
}

pub fn read_events(rel: &str) -> io::Result<MemEvents> {
    Ok(parse_events(&read_text(rel, "memory.events")?))
}

pub fn read_procs(rel: &str, out: &mut Vec<u32>) -> io::Result<()> {
    out.clear();
    let t = read_text(rel, "cgroup.procs")?;
    for line in t.lines() {
        if let Ok(p) = line.trim().parse::<u32>() {
            out.push(p);
        }
    }
    Ok(())
}

/// Cgroup memory counters include descendants; GPU accounting must use the same membership.
pub fn read_procs_recursive(rel: &str, out: &mut Vec<u32>) -> io::Result<()> {
    out.clear();
    let mut dirs = vec![fs_path(rel)];
    while let Some(dir) = dirs.pop() {
        let text = match std::fs::read_to_string(dir.join("cgroup.procs")) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound && dir != fs_path(rel) => continue,
            Err(e) => return Err(e),
        };
        out.extend(
            text.lines()
                .filter_map(|s| s.trim().parse::<u32>().ok())
                .filter(|p| *p > 1),
        );
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                dirs.push(entry.path());
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(())
}

pub fn read_pressure(rel: &str) -> io::Result<Psi> {
    let t = read_text(rel, "memory.pressure")?;
    super::psi::parse(t.as_bytes()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// SIGKILL every process in the cgroup (kernel >= 5.14).
pub fn kill(rel: &str) -> io::Result<()> {
    write_file(rel, "cgroup.kill", "1")
}

pub fn set_oom_group(rel: &str) -> io::Result<()> {
    write_file(rel, "memory.oom.group", "1")
}

/// Proactively reclaim `bytes` from the whole system via the root cgroup. With `file_only`
/// the kernel is told `swappiness=0` (6.6+), so nothing is swapped out. EAGAIN (partial
/// reclaim) counts as success.
pub fn reclaim_root(bytes: u64, file_only: bool) -> io::Result<()> {
    let content = if file_only {
        format!("{bytes} swappiness=0")
    } else {
        bytes.to_string()
    };
    match std::fs::write(fs_path("").join("memory.reclaim"), content) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => Ok(()),
        Err(e) => Err(e),
    }
}

pub fn root_reclaim_available() -> bool {
    fs_path("").join("memory.reclaim").exists()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Root,
    Slice,
    InitScope,
    UserManager,
    SessionScope,
    Service,
    Scope,
    Other,
}

pub fn unit_name(rel: &str) -> Option<&str> {
    let t = rel.trim_end_matches('/');
    if t.is_empty() {
        return None;
    }
    t.rsplit('/').next().filter(|s| !s.is_empty())
}

pub fn classify(rel: &str) -> Kind {
    let unit = match unit_name(rel) {
        Some(u) => u,
        None => return Kind::Root,
    };
    if unit.ends_with(".slice") {
        Kind::Slice
    } else if unit == "init.scope" {
        Kind::InitScope
    } else if unit.starts_with("user@") && unit.ends_with(".service") {
        Kind::UserManager
    } else if unit.starts_with("session-") && unit.ends_with(".scope") {
        Kind::SessionScope
    } else if unit.ends_with(".service") {
        Kind::Service
    } else if unit.ends_with(".scope") {
        Kind::Scope
    } else {
        Kind::Other
    }
}

/// `cgroup.kill` is permitted only for services/scopes whose unit name matches the allow-list.
pub fn kill_allowed(rel: &str, patterns: &[String]) -> bool {
    match classify(rel) {
        Kind::Service | Kind::Scope => {}
        _ => return false,
    }
    let unit = match unit_name(rel) {
        Some(u) => u,
        None => return false,
    };
    patterns.iter().any(|p| crate::config::glob_match(p, unit))
}

/// If the cgroup is a system service (`/system.slice/<unit>.service`, possibly nested in slices),
/// return the unit name so the daemon can `systemctl stop` it after a kill.
pub fn system_service_unit(rel: &str) -> Option<&str> {
    if !rel.starts_with("/system.slice/") {
        return None;
    }
    match classify(rel) {
        Kind::Service => unit_name(rel),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification() {
        assert_eq!(classify("/"), Kind::Root);
        assert_eq!(classify(""), Kind::Root);
        assert_eq!(classify("/user.slice"), Kind::Slice);
        assert_eq!(classify("/init.scope"), Kind::InitScope);
        assert_eq!(
            classify("/user.slice/user-1001.slice/user@1001.service"),
            Kind::UserManager
        );
        assert_eq!(
            classify("/user.slice/user-1001.slice/session-3.scope"),
            Kind::SessionScope
        );
        assert_eq!(classify("/system.slice/docker-abc.scope"), Kind::Scope);
        assert_eq!(classify("/system.slice/ollama.service"), Kind::Service);
        assert_eq!(
            classify("/user.slice/user-1001.slice/user@1001.service/tmux-spawn-x.scope"),
            Kind::Scope
        );
        let pats = vec!["docker-*.scope".to_string(), "memguard-*.scope".to_string()];
        assert!(kill_allowed("/system.slice/docker-abc.scope", &pats));
        assert!(kill_allowed(
            "/user.slice/user-1001.slice/user@1001.service/app.slice/memguard-x-1f.scope",
            &pats
        ));
        assert!(!kill_allowed(
            "/user.slice/user-1001.slice/user@1001.service/tmux-spawn-x.scope",
            &pats
        ));
        assert!(!kill_allowed(
            "/user.slice/user-1001.slice/session-3.scope",
            &pats
        ));
        assert!(!kill_allowed("/system.slice", &pats));
        assert_eq!(
            system_service_unit("/system.slice/ollama.service"),
            Some("ollama.service")
        );
        assert_eq!(system_service_unit("/system.slice/docker-abc.scope"), None);
        assert_eq!(
            system_service_unit(
                "/user.slice/user-1001.slice/user@1001.service/app.slice/x.service"
            ),
            None
        );
    }

    #[test]
    fn parse_stats() {
        let m = parse_memstat(
            "anon 2607751168\nfile 5623820288\nkernel 322850816\nshmem 25538560\nslab 1\n",
        );
        assert_eq!(m.anon, 2607751168);
        assert_eq!(m.kernel, 322850816);
        let e = parse_events("low 0\nhigh 0\nmax 2\noom 1\noom_kill 1\noom_group_kill 0\n");
        assert_eq!(e.oom_kill, 1);
        assert_eq!(e.max, 2);
    }

    #[test]
    fn live_root() {
        assert!(exists("/"));
        // memory.reclaim is optional on older supported kernels.
        let me = self_cgroup().unwrap();
        assert!(me.starts_with('/'));
        let mut pids = Vec::new();
        read_procs(&me, &mut pids).unwrap();
        assert!(pids.contains(&std::process::id()));
    }
}
