//! Killing: pidfd-based signalling with PID-reuse protection, tree and cgroup kills,
//! `process_mrelease`, and `systemctl stop` for restart-looping services.

use std::os::unix::io::RawFd;

use crate::config::KillSignal;
use crate::sys::procfs::ProcessIdentity;
use crate::sys::{cgroup, procfs};
use crate::victim::KillPlan;

// asm-generic syscall numbers (identical on aarch64 and x86_64)
const SYS_PIDFD_SEND_SIGNAL: libc::c_long = 424;
const SYS_PIDFD_OPEN: libc::c_long = 434;
const SYS_PROCESS_MRELEASE: libc::c_long = 448;

pub fn pidfd_open(pid: u32) -> std::io::Result<RawFd> {
    // SAFETY: raw syscall with integer arguments.
    let r = unsafe { libc::syscall(SYS_PIDFD_OPEN, pid as libc::c_long, 0 as libc::c_long) };
    if r < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(r as RawFd)
}

pub fn pidfd_send_signal(fd: RawFd, sig: libc::c_int) -> std::io::Result<()> {
    // SAFETY: raw syscall; null siginfo means a kernel-generated one.
    let r = unsafe {
        libc::syscall(
            SYS_PIDFD_SEND_SIGNAL,
            fd as libc::c_long,
            sig as libc::c_long,
            0 as libc::c_long,
            0 as libc::c_long,
        )
    };
    if r < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Reclaim the victim's anonymous memory from our context (5.15+). Best effort.
pub fn process_mrelease(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: raw syscall on a pidfd.
    let r = unsafe { libc::syscall(SYS_PROCESS_MRELEASE, fd as libc::c_long, 0 as libc::c_long) };
    if r < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub fn close_fd(fd: RawFd) {
    // SAFETY: closing an fd we opened.
    unsafe {
        libc::close(fd);
    }
}

fn signo(sig: KillSignal) -> libc::c_int {
    match sig {
        KillSignal::Kill => libc::SIGKILL,
        KillSignal::Term => libc::SIGTERM,
    }
}

#[derive(Debug, Default)]
pub struct KillOutcome {
    pub method: &'static str,
    pub signaled: Vec<u32>,
    pub failed: Vec<(u32, String)>,
    /// The root process changed identity between selection and kill: nothing was sent.
    pub aborted_pid_reuse: bool,
    pub mrelease: Option<bool>,
    pub cgroup_error: Option<String>,
}

/// Execute a kill plan. `expected_start` is the victim's /proc starttime at selection time.
/// For `signal=TERM` only the signal changes; escalation to SIGKILL is the caller's job.
pub fn execute(
    plan: &KillPlan,
    root_pid: u32,
    expected_start: u64,
    targets: &[ProcessIdentity],
    sig: KillSignal,
    dry_run: bool,
) -> KillOutcome {
    let mut out = KillOutcome::default();
    // Open first, validate second: validating before pidfd_open leaves a PID-reuse race.
    let root = ProcessIdentity {
        pid: root_pid,
        starttime: expected_start,
    };
    let root_fd = match open_verified(root) {
        Ok(fd) => fd,
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
            out.aborted_pid_reuse = true;
            return out;
        }
        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {
            out.method = "gone";
            return out;
        }
        Err(e) => {
            out.failed.push((root_pid, e.to_string()));
            return out;
        }
    };
    if dry_run {
        out.method = "dry-run";
        close_fd(root_fd);
        return out;
    }
    let s = signo(sig);
    match plan {
        KillPlan::Cgroup(path) => {
            // cgroup.kill always sends SIGKILL. TERM must use the identity-checked targets.
            // Never broaden a stale plan to newly arrived or protected processes.
            let mut current = Vec::new();
            let unchanged = cgroup::read_procs_recursive(path, &mut current).is_ok()
                && procfs::pid_cgroup(root_pid).as_deref() == Some(path.as_str())
                && current.iter().all(|pid| {
                    targets
                        .iter()
                        .any(|t| t.pid == *pid && procfs::starttime(*pid) == Some(t.starttime))
                });
            out.method = "cgroup-targets";
            if sig == KillSignal::Kill && unchanged {
                match cgroup::kill(path) {
                    Ok(()) => {
                        out.method = "cgroup.kill";
                        out.signaled.push(root_pid);
                        close_fd(root_fd);
                        return out;
                    }
                    Err(e) => {
                        out.cgroup_error = Some(e.to_string());
                        out.method = "cgroup.kill-failed+targets";
                    }
                }
            }
            for target in targets {
                signal_target(*target, s, &mut out);
            }
        }
        KillPlan::Process(pid) => {
            out.method = "process";
            if let Some(target) = targets.iter().find(|t| t.pid == *pid) {
                signal_target(*target, s, &mut out);
            }
        }
        KillPlan::Tree(pids) => {
            out.method = "tree";
            for pid in pids {
                if let Some(target) = targets.iter().find(|t| t.pid == *pid) {
                    signal_target(*target, s, &mut out);
                }
            }
        }
    }
    close_fd(root_fd);
    out
}

fn open_verified(target: ProcessIdentity) -> std::io::Result<RawFd> {
    if target.pid <= 1 || target.pid > i32::MAX as u32 || target.starttime == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid process identity",
        ));
    }
    let fd = pidfd_open(target.pid)?;
    if procfs::starttime(target.pid) != Some(target.starttime) {
        close_fd(fd);
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "process identity changed",
        ));
    }
    Ok(fd)
}

fn signal_target(target: ProcessIdentity, s: libc::c_int, out: &mut KillOutcome) {
    let pid = target.pid;
    match open_verified(target) {
        Ok(fd) => {
            match pidfd_send_signal(fd, s) {
                Ok(()) => {
                    out.signaled.push(pid);
                    // process_mrelease can block on the victim's mmap_lock. Kernel exit
                    // teardown reclaims its memory without stalling our decision loop.
                }
                Err(e) => out.failed.push((pid, e.to_string())),
            }
            close_fd(fd);
        }
        Err(e) => {
            if e.raw_os_error() == Some(libc::ESRCH) {
                return;
            }
            out.failed.push((pid, e.to_string()));
        }
    }
}

/// Send `sig` to a list of pids (used for TERM->KILL escalation and signal forwarding).
pub fn signal_pids(pids: &[ProcessIdentity], sig: libc::c_int) -> usize {
    let mut out = KillOutcome::default();
    for target in pids {
        signal_target(*target, sig, &mut out);
    }
    out.signaled.len()
}

/// `systemctl stop --no-block <unit>` in a detached thread (never blocks the caller).
pub fn stop_unit_async(unit: &str) {
    let unit = unit.to_string();
    let _ = std::thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn(move || {
            crate::sampler::drop_realtime();
            let _ = std::process::Command::new("systemctl")
                .args(["stop", "--no-block", &unit])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        });
}

/// True if `systemctl is-active` reports the unit as active.
pub fn unit_active(unit: &str) -> bool {
    std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_descendant_identity_is_never_signaled() {
        let mut root = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let mut unrelated = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let identity = ProcessIdentity::read(root.id()).unwrap();
        let stale = ProcessIdentity {
            pid: unrelated.id(),
            starttime: procfs::starttime(unrelated.id()).unwrap() + 1,
        };
        let out = execute(
            &KillPlan::Tree(vec![stale.pid, identity.pid]),
            identity.pid,
            identity.starttime,
            &[stale, identity],
            KillSignal::Kill,
            false,
        );
        assert_eq!(out.signaled, vec![identity.pid]);
        root.wait().unwrap();
        assert!(unrelated.try_wait().unwrap().is_none());
        unrelated.kill().unwrap();
        unrelated.wait().unwrap();
    }

    #[test]
    fn cgroup_term_and_failed_kill_use_all_verified_targets() {
        for sig in [KillSignal::Term, KillSignal::Kill] {
            let mut a = std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .unwrap();
            let mut b = std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .unwrap();
            let first = ProcessIdentity::read(a.id()).unwrap();
            let second = ProcessIdentity::read(b.id()).unwrap();
            let out = execute(
                &KillPlan::Cgroup("/nonexistent-memguard-test".into()),
                first.pid,
                first.starttime,
                &[first, second],
                sig,
                false,
            );
            assert_eq!(out.signaled, vec![first.pid, second.pid]);
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(a.wait().unwrap().signal(), Some(signo(sig)));
            assert_eq!(b.wait().unwrap().signal(), Some(signo(sig)));
        }
    }

    #[test]
    fn unsafe_pid_values_and_missing_identity_are_rejected() {
        for pid in [0, 1, u32::MAX] {
            assert!(open_verified(ProcessIdentity { pid, starttime: 1 }).is_err());
        }
        assert!(open_verified(ProcessIdentity {
            pid: std::process::id(),
            starttime: 0
        })
        .is_err());
    }

    #[test]
    fn pidfd_on_self_and_child() {
        let fd = pidfd_open(std::process::id()).unwrap();
        close_fd(fd);
        assert!(pidfd_open(u32::MAX - 7).is_err());
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id();
        let start = procfs::starttime(pid).unwrap();
        let targets = [ProcessIdentity {
            pid,
            starttime: start,
        }];
        // wrong starttime -> aborted, child untouched
        let out = execute(
            &KillPlan::Process(pid),
            pid,
            start + 1,
            &targets,
            KillSignal::Kill,
            false,
        );
        assert!(out.aborted_pid_reuse);
        assert!(child.try_wait().unwrap().is_none());
        // dry-run -> nothing sent
        let out = execute(
            &KillPlan::Process(pid),
            pid,
            start,
            &targets,
            KillSignal::Kill,
            true,
        );
        assert_eq!(out.method, "dry-run");
        assert!(child.try_wait().unwrap().is_none());
        // real kill
        let out = execute(
            &KillPlan::Tree(vec![pid]),
            pid,
            start,
            &targets,
            KillSignal::Kill,
            false,
        );
        assert_eq!(out.signaled, vec![pid]);
        let st = child.wait().unwrap();
        assert!(!st.success());
    }
}
