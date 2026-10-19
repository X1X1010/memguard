//! NVML runs in a separate helper *process* because its queries block behind another process's
//! allocation ioctl (measured up to 715 ms) and a stuck ioctl is uninterruptible. The daemon only
//! ever reads the latest snapshot from a pipe and tracks its age; if the helper goes silent it is
//! terminated and replaced after it exits, without accumulating stuck helper processes.
//!
//! Wire format (native endian, same machine): header 32 bytes
//! `magic "NVM1" | status i32 | seq u64 | ts_ns u64 | count u32 | reserved u32`, then `count`
//! entries of 16 bytes `pid u32 | pad u32 | bytes u64`.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};

use crate::sys::nvml::{GpuProc, Nvml};
use crate::victim::NvmlSnapshot;

const MAGIC: &[u8; 4] = b"NVM1";
const HDR: usize = 32;
const ENTRY: usize = 16;

pub const STATUS_OK: i32 = 0;
pub const STATUS_NO_NVML: i32 = 1;
pub const STATUS_QUERY_FAILED: i32 = 2;

fn encode(out: &mut Vec<u8>, status: i32, seq: u64, ts_ns: u64, procs: &[GpuProc]) {
    out.clear();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&status.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&ts_ns.to_ne_bytes());
    out.extend_from_slice(&(procs.len() as u32).to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    for p in procs {
        out.extend_from_slice(&p.pid.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out.extend_from_slice(&p.bytes.to_ne_bytes());
    }
}

/// Parse one record from the front of `buf`. Returns (consumed, status, seq, ts, procs) or None
/// if incomplete. Garbage resyncs by skipping a byte.
fn decode(buf: &[u8], procs: &mut Vec<GpuProc>) -> Option<(usize, i32, u64, u64)> {
    if buf.len() < HDR {
        return None;
    }
    if &buf[0..4] != MAGIC {
        return Some((1, -1, 0, 0));
    }
    let status = i32::from_ne_bytes(buf[4..8].try_into().unwrap());
    let seq = u64::from_ne_bytes(buf[8..16].try_into().unwrap());
    let ts = u64::from_ne_bytes(buf[16..24].try_into().unwrap());
    let count = u32::from_ne_bytes(buf[24..28].try_into().unwrap()) as usize;
    if count > 65536 {
        return Some((1, -1, 0, 0));
    }
    let need = HDR + count * ENTRY;
    if buf.len() < need {
        return None;
    }
    procs.clear();
    for i in 0..count {
        let off = HDR + i * ENTRY;
        let pid = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap());
        let bytes = u64::from_ne_bytes(buf[off + 8..off + 16].try_into().unwrap());
        procs.push(GpuProc { pid, bytes });
    }
    Some((need, status, seq, ts))
}

/// Poll stdin: (daemon went away, last command byte). Commands: b'F' fast, b'S' slow.
fn stdin_poll() -> (bool, Option<u8>) {
    let mut pfd = libc::pollfd {
        fd: 0,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd, zero timeout.
    let n = unsafe { libc::poll(&mut pfd, 1, 0) };
    if n <= 0 {
        return (false, None);
    }
    if (pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)) != 0
        && (pfd.revents & libc::POLLIN) == 0
    {
        return (true, None);
    }
    let mut buf = [0u8; 64];
    // SAFETY: reading into a stack buffer.
    let r = unsafe { libc::read(0, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if r == 0 {
        return (true, None);
    }
    if r < 0 {
        return (false, None);
    }
    (false, Some(buf[r as usize - 1]))
}

/// Entry point of `memguard nvml-helper <interval_ms>`.
pub fn helper_main(interval_ms: u64) -> i32 {
    let fast = std::time::Duration::from_millis(interval_ms.max(10));
    let slow = std::time::Duration::from_millis(interval_ms.max(10) * 4);
    let mut interval = fast;
    // SAFETY: fcntl on stdin.
    unsafe {
        let fl = libc::fcntl(0, libc::F_GETFL);
        if fl >= 0 {
            libc::fcntl(0, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
    }
    let mut out = std::io::stdout().lock();
    let mut buf = Vec::with_capacity(4096);
    let mut procs: Vec<GpuProc> = Vec::with_capacity(64);
    let mut seq = 0u64;
    let mut nvml: Option<Nvml> = None;
    let mut last_load_attempt = 0u64;
    let mut last_err = String::new();
    loop {
        let (closed, cmd) = stdin_poll();
        if closed {
            return 0;
        }
        match cmd {
            Some(b'F') => interval = fast,
            Some(b'S') => interval = slow,
            _ => {}
        }
        let now = crate::mono_ns();
        if nvml.is_none() && now.saturating_sub(last_load_attempt) >= 5_000_000_000 {
            last_load_attempt = now;
            match Nvml::load() {
                Ok(n) => {
                    crate::debug!(
                        "nvml-helper: NVML ready, driver {} ({} device(s))",
                        n.driver_version(),
                        n.device_count()
                    );
                    nvml = Some(n);
                }
                Err(e) => {
                    if e != last_err {
                        crate::warn!("nvml-helper: {e}; retrying every 5 s");
                        last_err = e;
                    }
                }
            }
        }
        seq += 1;
        let status = match nvml.as_mut() {
            None => {
                procs.clear();
                STATUS_NO_NVML
            }
            Some(n) => match n.processes(&mut procs) {
                Ok(()) => STATUS_OK,
                Err(e) => {
                    if e != last_err {
                        crate::warn!("nvml-helper: query failed: {e}");
                        last_err = e;
                    }
                    n.refresh_devices();
                    procs.clear();
                    STATUS_QUERY_FAILED
                }
            },
        };
        // Age covers the query itself, which may have blocked in the driver.
        encode(&mut buf, status, seq, now, &procs);
        if out.write_all(&buf).and_then(|_| out.flush()).is_err() {
            return 0; // daemon went away
        }
        std::thread::sleep(interval);
    }
}

#[derive(Default)]
pub struct FeedStats {
    pub seq: u64,
    pub records: u64,
    pub status: i32,
    pub spawns: u32,
    pub respawns_silent: u32,
}

/// Daemon-side reader of the helper's pipe.
pub struct NvmlFeed {
    exe: std::path::PathBuf,
    child: Option<Child>,
    fd: RawFd,
    buf: Vec<u8>,
    procs_tmp: Vec<GpuProc>,
    latest: NvmlSnapshot,
    last_rx_ns: u64,
    last_spawn_ns: u64,
    interval_ms: u64,
    pub stats: FeedStats,
    /// Every pid ever reported by NVML (CUDA processes), for stale-snapshot attribution.
    pub cuda_seen: HashSet<u32>,
    want_fast: bool,
    sent_fast: Option<bool>,
    terminating: bool,
    identities: std::collections::HashMap<u32, u64>,
}

impl NvmlFeed {
    pub fn spawn(interval_ms: u64) -> std::io::Result<NvmlFeed> {
        let exe = std::env::current_exe()?;
        Self::spawn_with_exe(exe, interval_ms)
    }

    /// Spawn using an explicit memguard binary (tests, or when current_exe is not memguard).
    pub fn spawn_with_exe(exe: std::path::PathBuf, interval_ms: u64) -> std::io::Result<NvmlFeed> {
        let mut f = NvmlFeed {
            exe,
            child: None,
            fd: -1,
            buf: Vec::with_capacity(1 << 16),
            procs_tmp: Vec::with_capacity(64),
            latest: NvmlSnapshot::default(),
            last_rx_ns: 0,
            last_spawn_ns: 0,
            interval_ms,
            stats: FeedStats::default(),
            cuda_seen: HashSet::new(),
            want_fast: true,
            sent_fast: None,
            terminating: false,
            identities: std::collections::HashMap::new(),
        };
        f.start_child()?;
        Ok(f)
    }

    fn start_child(&mut self) -> std::io::Result<()> {
        self.last_spawn_ns = crate::mono_ns();
        let mut cmd = Command::new(&self.exe);
        cmd.arg("nvml-helper")
            .arg(self.interval_ms.to_string())
            .env_remove("NOTIFY_SOCKET")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        // SAFETY: only async-signal-safe calls in the forked child.
        unsafe {
            cmd.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                let param = libc::sched_param { sched_priority: 0 };
                libc::sched_setscheduler(0, libc::SCHED_OTHER, &param);
                libc::setpriority(libc::PRIO_PROCESS, 0, 5);
                Ok(())
            });
        }
        let mut child = cmd.spawn()?;
        let stdout = child.stdout.take().expect("piped stdout");
        let fd = stdout.as_raw_fd();
        // SAFETY: fcntl on a valid fd we own via `stdout`, which we deliberately leak into `fd`.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        std::mem::forget(stdout);
        if self.fd >= 0 {
            // SAFETY: closing the previous pipe fd we own.
            unsafe {
                libc::close(self.fd);
            }
        }
        self.fd = fd;
        if let Some(stdin) = child.stdin.as_ref() {
            let wfd = stdin.as_raw_fd();
            // SAFETY: fcntl on the pipe write end we own.
            unsafe {
                let fl = libc::fcntl(wfd, libc::F_GETFL);
                if fl >= 0 {
                    libc::fcntl(wfd, libc::F_SETFL, fl | libc::O_NONBLOCK);
                }
            }
        }
        self.child = Some(child);
        self.terminating = false;
        self.latest.valid = false;
        self.sent_fast = None;
        self.buf.clear();
        self.last_spawn_ns = crate::mono_ns();
        self.stats.spawns += 1;
        Ok(())
    }

    /// Ask the helper to poll at the tick interval (fast) or 4x slower (idle).
    pub fn set_fast(&mut self, fast: bool) {
        self.want_fast = fast;
    }

    fn sync_mode(&mut self) {
        if self.sent_fast == Some(self.want_fast) {
            return;
        }
        let byte: [u8; 1] = [if self.want_fast { b'F' } else { b'S' }];
        if let Some(stdin) = self.child.as_mut().and_then(|c| c.stdin.as_mut()) {
            if stdin.write_all(&byte).is_ok() {
                self.sent_fast = Some(self.want_fast);
            }
        }
    }

    pub fn helper_pid(&self) -> Option<u32> {
        self.child.as_ref().map(|c| c.id())
    }

    /// Non-blocking: drain the pipe, keep the newest record, supervise the child.
    pub fn poll(&mut self, now_ns: u64) {
        let mut tmp = [0u8; 16384];
        loop {
            // SAFETY: reading into a stack buffer of the stated length.
            let n =
                unsafe { libc::read(self.fd, tmp.as_mut_ptr() as *mut libc::c_void, tmp.len()) };
            if n > 0 {
                self.buf.extend_from_slice(&tmp[..n as usize]);
                if self.buf.len() > (1 << 20) {
                    self.buf.clear(); // runaway garbage
                }
                continue;
            }
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
            }
            break; // EAGAIN (no more data), EOF, or error
        }
        let mut consumed_total = 0usize;
        loop {
            let slice = &self.buf[consumed_total..];
            match decode(slice, &mut self.procs_tmp) {
                None => break,
                Some((n, status, seq, ts)) => {
                    consumed_total += n;
                    if status < 0 {
                        continue; // resync byte
                    }
                    self.stats.records += 1;
                    self.stats.seq = seq;
                    self.stats.status = status;
                    self.last_rx_ns = now_ns;
                    if status == STATUS_OK {
                        self.latest.procs.clear();
                        self.latest.procs.extend_from_slice(&self.procs_tmp);
                        self.latest.t_ns = ts;
                        self.latest.valid = true;
                        self.identities.clear();
                        self.cuda_seen.clear();
                        for p in &self.procs_tmp {
                            if let Some(start) = crate::sys::procfs::starttime(p.pid) {
                                self.identities.insert(p.pid, start);
                                self.cuda_seen.insert(p.pid);
                            }
                        }
                    } else {
                        self.latest.valid = false;
                    }
                }
            }
        }
        if consumed_total > 0 {
            self.buf.drain(..consumed_total);
        }

        self.sync_mode();
        self.identities
            .retain(|pid, start| crate::sys::procfs::starttime(*pid) == Some(*start));
        self.latest
            .procs
            .retain(|p| self.identities.contains_key(&p.pid));
        self.cuda_seen
            .retain(|pid| self.identities.contains_key(pid));

        // supervise
        let exited = match self.child.as_mut() {
            Some(c) => matches!(c.try_wait(), Ok(Some(_))),
            None => true,
        };
        let silent = self.last_rx_ns.max(self.last_spawn_ns) + 10_000_000_000 < now_ns;
        if exited {
            if now_ns.saturating_sub(self.last_spawn_ns) >= 1_000_000_000 {
                crate::warn!("nvml-helper exited; respawning");
                if let Err(e) = self.start_child() {
                    crate::error!("cannot respawn nvml-helper: {e}");
                }
            }
        } else if silent && !self.terminating {
            crate::warn!(
                "nvml-helper silent for 10 s; terminating it (replacement waits for exit)"
            );
            self.stats.respawns_silent += 1;
            self.terminating = true;
            self.latest.valid = false;
            if let Some(c) = self.child.as_mut() {
                let _ = c.kill();
            }
        }
    }

    pub fn snapshot(&self) -> &NvmlSnapshot {
        &self.latest
    }

    pub fn age_ns(&self, now_ns: u64) -> u64 {
        if self.latest.valid {
            now_ns.saturating_sub(self.latest.t_ns)
        } else {
            u64::MAX
        }
    }

    pub fn describe(&self, now_ns: u64) -> String {
        if !self.latest.valid {
            return match self.stats.status {
                STATUS_NO_NVML => "unavailable (library/driver not loaded)".into(),
                STATUS_QUERY_FAILED => "query failing".into(),
                _ => "no data yet".into(),
            };
        }
        format!(
            "{} process(es), age {} ms",
            self.latest.procs.len(),
            self.age_ns(now_ns) / 1_000_000
        )
    }

    pub fn shutdown(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            for _ in 0..10 {
                if !matches!(c.try_wait(), Ok(None)) {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            // A driver task may remain in D state indefinitely. Do not hold up shutdown.
            let _ = std::thread::Builder::new()
                .stack_size(64 * 1024)
                .spawn(move || {
                    let param = libc::sched_param { sched_priority: 0 };
                    unsafe {
                        libc::sched_setscheduler(0, libc::SCHED_OTHER, &param);
                    }
                    let _ = c.wait();
                });
        }
    }
}

impl Drop for NvmlFeed {
    fn drop(&mut self) {
        self.shutdown();
        if self.fd >= 0 {
            // SAFETY: fd owned.
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

/// Bounded query for status/ps/doctor; diagnostic commands must also survive a stuck driver.
pub fn query_direct() -> Result<(Vec<GpuProc>, String), String> {
    let mut feed = NvmlFeed::spawn(50).map_err(|e| e.to_string())?;
    let deadline = crate::mono_ns() + 2_000_000_000;
    loop {
        let now = crate::mono_ns();
        feed.poll(now);
        if feed.snapshot().valid && feed.age_ns(now) <= 1_000_000_000 {
            return Ok((
                feed.snapshot().procs.clone(),
                crate::sys::nvml::driver_version_from_proc().unwrap_or_default(),
            ));
        }
        if now >= deadline || (feed.stats.records > 0 && feed.stats.status != STATUS_OK) {
            return Err(format!("NVML query unavailable: {}", feed.describe(now)));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// Read a helper record stream synchronously (used by tests).
pub fn read_one_record(r: &mut impl Read) -> Option<(i32, u64, Vec<GpuProc>)> {
    let mut hdr = [0u8; HDR];
    r.read_exact(&mut hdr).ok()?;
    let count = u32::from_ne_bytes(hdr[24..28].try_into().unwrap()) as usize;
    if &hdr[..4] != MAGIC || count > 65536 {
        return None;
    }
    let mut body = vec![0u8; count * ENTRY];
    r.read_exact(&mut body).ok()?;
    let mut all = hdr.to_vec();
    all.extend_from_slice(&body);
    let mut procs = Vec::new();
    let (_, status, seq, _) = decode(&all, &mut procs)?;
    Some((status, seq, procs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut buf = Vec::new();
        let procs = vec![
            GpuProc {
                pid: 42,
                bytes: 8 << 30,
            },
            GpuProc { pid: 7, bytes: 1 },
        ];
        encode(&mut buf, STATUS_OK, 9, 123, &procs);
        assert_eq!(buf.len(), HDR + 2 * ENTRY);
        let mut out = Vec::new();
        let (n, status, seq, ts) = decode(&buf, &mut out).unwrap();
        assert_eq!((n, status, seq, ts), (buf.len(), STATUS_OK, 9, 123));
        assert_eq!(out, procs);
        // truncated -> None; garbage prefix -> resync
        assert!(decode(&buf[..buf.len() - 1], &mut out).is_none());
        let mut g = vec![0xffu8];
        g.extend_from_slice(&buf);
        assert_eq!(decode(&g, &mut out).unwrap().0, 1);
    }
}
