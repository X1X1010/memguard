//! Hot sampler (cached fds, no `open()` per tick), the /proc scan thread and the reclaim thread.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;

use crate::engine::Sample;
use crate::sys::cgroup;
use crate::sys::meminfo::{page_size, CachedFile, MemInfo, VmStat};
use crate::sys::procfs::{self, ProcTable, ScanOptions};
use crate::sys::psi::{self, Psi};

/// Background threads must not inherit the daemon's SCHED_FIFO: only the decision loop needs it.
pub(crate) fn drop_realtime() {
    let param = libc::sched_param { sched_priority: 0 };
    // SAFETY: lowering our own thread to SCHED_OTHER is always permitted.
    unsafe {
        libc::sched_setscheduler(0, libc::SCHED_OTHER, &param);
    }
}

pub struct HotSampler {
    meminfo: CachedFile,
    vmstat: Option<CachedFile>,
    psi: Option<CachedFile>,
    buf_m: Vec<u8>,
    buf_v: Vec<u8>,
    buf_p: Vec<u8>,
    page: u64,
    pub last_meminfo: MemInfo,
    pub last_vmstat: VmStat,
    pub last_psi: Psi,
    pub psi_available: bool,
    pub free2m_available: bool,
    ticks: u64,
}

impl HotSampler {
    pub fn open() -> Result<Self, String> {
        let meminfo =
            CachedFile::open("/proc/meminfo").map_err(|e| format!("/proc/meminfo: {e}"))?;
        let vmstat = CachedFile::open("/proc/vmstat").ok();
        let psi = CachedFile::open("/proc/pressure/memory").ok();
        let mut s = HotSampler {
            meminfo,
            vmstat,
            psi_available: psi.is_some(),
            psi,
            buf_m: Vec::with_capacity(8192),
            buf_v: Vec::with_capacity(32768),
            buf_p: Vec::with_capacity(1024),
            page: page_size(),
            last_meminfo: MemInfo::default(),
            last_vmstat: VmStat::default(),
            last_psi: Psi::default(),
            free2m_available: false,
            ticks: 0,
        };
        let probe = s.sample(crate::mono_ns())?;
        s.free2m_available = s.last_vmstat.has_free_pages_blocks;
        let _ = probe;
        Ok(s)
    }

    pub fn sample(&mut self, now_ns: u64) -> Result<Sample, String> {
        self.meminfo
            .read(&mut self.buf_m)
            .map_err(|e| format!("read meminfo: {e}"))?;
        let m = MemInfo::parse(&self.buf_m)?;
        self.last_meminfo = m;
        // vmstat feeds free2m and swap counters only: every 4th tick is plenty
        if self.ticks.is_multiple_of(4) {
            if let Some(v) = &self.vmstat {
                if v.read(&mut self.buf_v).is_ok() {
                    self.last_vmstat = VmStat::parse(&self.buf_v);
                }
            }
        }
        self.ticks += 1;
        if let Some(p) = &self.psi {
            if p.read(&mut self.buf_p).is_ok() {
                if let Ok(ps) = psi::parse(&self.buf_p) {
                    self.last_psi = ps;
                }
            }
        }
        let free2m = if self.last_vmstat.has_free_pages_blocks {
            self.last_vmstat
                .nr_free_pages_blocks
                .saturating_mul(self.page)
        } else {
            m.free
        };
        Ok(Sample {
            t_ns: now_ns,
            total: m.total,
            free: m.free,
            avail: m.available,
            free2m,
            swap_total: m.swap_total,
            swap_free: m.swap_free,
            psi_some_us: self.last_psi.some_total_us,
            psi_full_us: self.last_psi.full_total_us,
        })
    }
}

struct ScanShared {
    table: Mutex<Arc<ProcTable>>,
    fast: AtomicBool,
    stop: AtomicBool,
    maps_for: Mutex<Vec<u32>>,
    scans: AtomicU64,
    normal_ms: u64,
    fast_ms: u64,
    maps_min_vmsize: u64,
    detail_min: u64,
}

/// Background /proc scanner publishing immutable snapshots.
pub struct Scanner {
    shared: Arc<ScanShared>,
    handle: Option<JoinHandle<()>>,
}

impl Scanner {
    pub fn start(normal_ms: u64, fast_ms: u64, maps_min_vmsize: u64, detail_min: u64) -> Scanner {
        let shared = Arc::new(ScanShared {
            table: Mutex::new(Arc::new(ProcTable::default())),
            fast: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            maps_for: Mutex::new(Vec::new()),
            scans: AtomicU64::new(0),
            normal_ms: normal_ms.max(100),
            fast_ms: fast_ms.max(50),
            maps_min_vmsize,
            detail_min,
        });
        let sh = shared.clone();
        let handle = std::thread::Builder::new()
            .name("memguard-scan".into())
            .stack_size(512 * 1024)
            .spawn(move || {
                drop_realtime();
                loop {
                    if sh.stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let maps_for = sh.maps_for.lock().map(|v| v.clone()).unwrap_or_default();
                    let t = procfs::scan(&ScanOptions {
                        maps_for: &maps_for,
                        maps_min_vmsize: sh.maps_min_vmsize,
                        detail_min: sh.detail_min,
                    });
                    if let Ok(mut g) = sh.table.lock() {
                        *g = Arc::new(t);
                    }
                    sh.scans.fetch_add(1, Ordering::Relaxed);
                    let interval = if sh.fast.load(Ordering::Relaxed) {
                        sh.fast_ms
                    } else {
                        sh.normal_ms
                    };
                    let mut slept = 0;
                    while slept < interval && !sh.stop.load(Ordering::Relaxed) {
                        std::thread::sleep(std::time::Duration::from_millis(25));
                        slept += 25;
                        if sh.fast.load(Ordering::Relaxed) && slept >= sh.fast_ms {
                            break;
                        }
                    }
                }
            })
            .expect("spawn scan thread");
        Scanner {
            shared,
            handle: Some(handle),
        }
    }

    pub fn table(&self) -> Arc<ProcTable> {
        self.shared
            .table
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    pub fn set_fast(&self, fast: bool) {
        self.shared.fast.store(fast, Ordering::Relaxed);
    }

    pub fn set_maps_for(&self, pids: &[u32]) {
        if let Ok(mut g) = self.shared.maps_for.lock() {
            g.clear();
            g.extend_from_slice(pids);
        }
    }

    pub fn scans(&self) -> u64 {
        self.shared.scans.load(Ordering::Relaxed)
    }

    /// Block until the first scan has been published (bounded).
    pub fn wait_first(&self, timeout_ms: u64) -> bool {
        let start = crate::mono_ns();
        while self.scans() == 0 {
            if crate::mono_ns() - start > timeout_ms * 1_000_000 {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        true
    }

    pub fn stop(mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            if h.is_finished() {
                let _ = h.join();
            }
        }
    }
}

#[derive(Default, Clone, Debug)]
pub struct ReclaimStats {
    pub requested: u64,
    pub done: u64,
    pub failed: u64,
    pub bytes_total: u64,
    pub disabled: bool,
    pub last_error: String,
    pub last_duration_us: u64,
    pub busy: bool,
}

struct ReclaimState {
    pending: Option<u64>,
    stop: bool,
    stats: ReclaimStats,
}

/// Dedicated thread for the (potentially slow, synchronous) root `memory.reclaim` write.
pub struct Reclaimer {
    shared: Arc<(Mutex<ReclaimState>, Condvar)>,
    handle: Option<JoinHandle<()>>,
}

impl Reclaimer {
    pub fn start(file_only: bool) -> Reclaimer {
        let shared = Arc::new((
            Mutex::new(ReclaimState {
                pending: None,
                stop: false,
                stats: ReclaimStats::default(),
            }),
            Condvar::new(),
        ));
        let sh = shared.clone();
        let handle = std::thread::Builder::new()
            .name("memguard-reclaim".into())
            .stack_size(256 * 1024)
            .spawn(move || {
                drop_realtime();
                let (lock, cv) = &*sh;
                loop {
                    let bytes = {
                        let mut g = match lock.lock() {
                            Ok(g) => g,
                            Err(_) => return,
                        };
                        while g.pending.is_none() && !g.stop {
                            g = match cv.wait(g) {
                                Ok(g) => g,
                                Err(_) => return,
                            };
                        }
                        if g.stop {
                            return;
                        }
                        g.stats.busy = true;
                        g.pending.take().unwrap_or(0)
                    };
                    let t0 = crate::mono_ns();
                    let res = cgroup::reclaim_root(bytes, file_only);
                    let dur = (crate::mono_ns() - t0) / 1000;
                    if let Ok(mut g) = lock.lock() {
                        g.stats.busy = false;
                        g.stats.last_duration_us = dur;
                        match res {
                            Ok(()) => {
                                g.stats.done += 1;
                                g.stats.bytes_total += bytes;
                            }
                            Err(e) => {
                                g.stats.failed += 1;
                                g.stats.last_error = e.to_string();
                                // EINVAL with swappiness= means an old kernel: never reclaim
                                // without the file-only guarantee.
                                if file_only && e.raw_os_error() == Some(libc::EINVAL) {
                                    g.stats.disabled = true;
                                }
                                if e.kind() == std::io::ErrorKind::PermissionDenied {
                                    g.stats.disabled = true;
                                }
                            }
                        }
                    }
                }
            })
            .expect("spawn reclaim thread");
        Reclaimer {
            shared,
            handle: Some(handle),
        }
    }

    /// Queue a reclaim; returns false if one is already pending/running or the feature is disabled.
    pub fn request(&self, bytes: u64) -> bool {
        let (lock, cv) = &*self.shared;
        if let Ok(mut g) = lock.lock() {
            if g.stats.disabled || g.stats.busy || g.pending.is_some() {
                return false;
            }
            g.stats.requested += 1;
            g.pending = Some(bytes);
            cv.notify_one();
            return true;
        }
        false
    }

    pub fn stats(&self) -> ReclaimStats {
        self.shared
            .0
            .lock()
            .map(|g| g.stats.clone())
            .unwrap_or_default()
    }

    pub fn stop(mut self) {
        let (lock, cv) = &*self.shared;
        if let Ok(mut g) = lock.lock() {
            g.stop = true;
            cv.notify_all();
        }
        if let Some(h) = self.handle.take() {
            // the thread may be inside a long reclaim write; do not block shutdown on it
            if self.shared.0.lock().map(|g| !g.stats.busy).unwrap_or(true) {
                let _ = h.join();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hot_sampler_live() {
        let mut s = HotSampler::open().unwrap();
        let a = s.sample(crate::mono_ns()).unwrap();
        assert!(a.total > 0 && a.avail > 0 && a.avail <= a.total);
        assert!(a.free2m <= a.total);
        let b = s.sample(crate::mono_ns()).unwrap();
        assert_eq!(a.total, b.total);
    }

    #[test]
    fn scanner_publishes() {
        let sc = Scanner::start(200, 100, 0, 0);
        assert!(sc.wait_first(5000));
        let t = sc.table();
        assert!(t.get(std::process::id()).is_some());
        sc.stop();
    }
}
