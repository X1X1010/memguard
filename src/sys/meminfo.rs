//! `/proc/meminfo` and `/proc/vmstat` readers with a cached file descriptor (`pread`, no `open()`
//! in the hot loop) and allocation-free parsers.

use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;

/// A file opened once and re-read with `pread` at offset 0 (works for procfs seq files).
pub struct CachedFile {
    fd: RawFd,
    pub path: String,
}

impl CachedFile {
    pub fn open(path: &str) -> io::Result<Self> {
        let c = CString::new(path)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in path"))?;
        // SAFETY: valid C string; flags are plain constants.
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(CachedFile {
            fd,
            path: path.to_string(),
        })
    }

    /// Read the whole file into `buf` (cleared first). Grows `buf` only if the file outgrows it.
    pub fn read(&self, buf: &mut Vec<u8>) -> io::Result<()> {
        buf.clear();
        loop {
            if buf.capacity() - buf.len() < 4096 {
                buf.reserve(16384);
            }
            let spare = buf.capacity() - buf.len();
            // SAFETY: writing into the spare capacity of the vector, then set_len by bytes read.
            let n = unsafe {
                libc::pread(
                    self.fd,
                    buf.as_mut_ptr().add(buf.len()) as *mut libc::c_void,
                    spare,
                    buf.len() as libc::off_t,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(e);
            }
            if n == 0 {
                return Ok(());
            }
            // SAFETY: pread wrote exactly n bytes into the spare capacity.
            unsafe { buf.set_len(buf.len() + n as usize) };
        }
    }
}

impl Drop for CachedFile {
    fn drop(&mut self) {
        // SAFETY: fd owned by this struct.
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Parse leading decimal digits of `s` (after optional spaces). Returns (value, rest).
pub fn parse_u64_prefix(s: &[u8]) -> (u64, &[u8]) {
    let mut i = 0;
    while i < s.len() && (s[i] == b' ' || s[i] == b'\t') {
        i += 1;
    }
    let mut v: u64 = 0;
    let mut any = false;
    while i < s.len() && s[i].is_ascii_digit() {
        v = v.saturating_mul(10).saturating_add((s[i] - b'0') as u64);
        i += 1;
        any = true;
    }
    if !any {
        return (0, &s[i..]);
    }
    (v, &s[i..])
}

#[derive(Default, Clone, Copy, Debug, PartialEq)]
pub struct MemInfo {
    pub total: u64,
    pub free: u64,
    pub available: u64,
    pub buffers: u64,
    pub cached: u64,
    pub swap_cached: u64,
    pub unevictable: u64,
    pub mlocked: u64,
    pub swap_total: u64,
    pub swap_free: u64,
    pub dirty: u64,
    pub writeback: u64,
    pub anon_pages: u64,
    pub mapped: u64,
    pub shmem: u64,
    pub kreclaimable: u64,
    pub slab: u64,
    pub sreclaimable: u64,
    pub sunreclaim: u64,
    pub kernel_stack: u64,
    pub page_tables: u64,
    pub sec_page_tables: u64,
    pub commit_limit: u64,
    pub committed_as: u64,
    pub vmalloc_used: u64,
    pub percpu: u64,
    pub hugetlb: u64,
    pub hugepages_total: u64,
    pub hugepagesize: u64,
}

impl MemInfo {
    /// Parse the text of /proc/meminfo. Values are converted to bytes.
    pub fn parse(buf: &[u8]) -> Result<MemInfo, String> {
        let mut m = MemInfo::default();
        let mut have_available = false;
        for line in buf.split(|b| *b == b'\n') {
            if line.is_empty() {
                continue;
            }
            let colon = match line.iter().position(|b| *b == b':') {
                Some(c) => c,
                None => continue,
            };
            let key = &line[..colon];
            let (v, rest) = parse_u64_prefix(&line[colon + 1..]);
            let is_kb = rest.windows(2).any(|w| w == b"kB");
            let val = if is_kb { v.saturating_mul(1024) } else { v };
            match key {
                b"MemTotal" => m.total = val,
                b"MemFree" => m.free = val,
                b"MemAvailable" => {
                    m.available = val;
                    have_available = true;
                }
                b"Buffers" => m.buffers = val,
                b"Cached" => m.cached = val,
                b"SwapCached" => m.swap_cached = val,
                b"Unevictable" => m.unevictable = val,
                b"Mlocked" => m.mlocked = val,
                b"SwapTotal" => m.swap_total = val,
                b"SwapFree" => m.swap_free = val,
                b"Dirty" => m.dirty = val,
                b"Writeback" => m.writeback = val,
                b"AnonPages" => m.anon_pages = val,
                b"Mapped" => m.mapped = val,
                b"Shmem" => m.shmem = val,
                b"KReclaimable" => m.kreclaimable = val,
                b"Slab" => m.slab = val,
                b"SReclaimable" => m.sreclaimable = val,
                b"SUnreclaim" => m.sunreclaim = val,
                b"KernelStack" => m.kernel_stack = val,
                b"PageTables" => m.page_tables = val,
                b"SecPageTables" => m.sec_page_tables = val,
                b"CommitLimit" => m.commit_limit = val,
                b"Committed_AS" => m.committed_as = val,
                b"VmallocUsed" => m.vmalloc_used = val,
                b"Percpu" => m.percpu = val,
                b"Hugetlb" => m.hugetlb = val,
                b"HugePages_Total" => m.hugepages_total = val,
                b"Hugepagesize" => m.hugepagesize = val,
                _ => {}
            }
        }
        if m.total == 0 || !have_available {
            return Err("meminfo missing MemTotal/MemAvailable".into());
        }
        Ok(m)
    }

    pub fn swap_used(&self) -> u64 {
        self.swap_total.saturating_sub(self.swap_free)
    }

    /// Memory that no /proc/meminfo category accounts for. On GB10 this is essentially GPU memory
    /// held by the NVIDIA driver (cudaMalloc), which is invisible to RSS and memcg.
    pub fn other_estimate(&self) -> u64 {
        let hugetlb = if self.hugetlb > 0 {
            self.hugetlb
        } else {
            self.hugepages_total.saturating_mul(self.hugepagesize)
        };
        let accounted = self
            .free
            .saturating_add(self.buffers)
            .saturating_add(self.cached)
            .saturating_add(self.swap_cached)
            .saturating_add(self.anon_pages)
            .saturating_add(self.slab)
            .saturating_add(self.kernel_stack)
            .saturating_add(self.page_tables)
            .saturating_add(self.sec_page_tables)
            .saturating_add(self.percpu)
            .saturating_add(self.vmalloc_used)
            .saturating_add(hugetlb);
        self.total.saturating_sub(accounted)
    }
}

#[derive(Default, Clone, Copy, Debug, PartialEq)]
pub struct VmStat {
    pub nr_free_pages: u64,
    /// Free pages that sit in whole free blocks of >= pageblock order (2 MiB): what a large
    /// driver allocation can take immediately. Zero when the kernel lacks the counter.
    pub nr_free_pages_blocks: u64,
    pub has_free_pages_blocks: bool,
    pub pswpin: u64,
    pub pswpout: u64,
    pub pgscan_direct: u64,
    pub pgsteal_direct: u64,
    pub allocstall: u64,
    pub compact_stall: u64,
    pub oom_kill: u64,
}

impl VmStat {
    pub fn parse(buf: &[u8]) -> VmStat {
        let mut v = VmStat::default();
        for line in buf.split(|b| *b == b'\n') {
            let sp = match line.iter().position(|b| *b == b' ') {
                Some(s) => s,
                None => continue,
            };
            let key = &line[..sp];
            let (val, _) = parse_u64_prefix(&line[sp + 1..]);
            match key {
                b"nr_free_pages" => v.nr_free_pages = val,
                b"nr_free_pages_blocks" => {
                    v.nr_free_pages_blocks = val;
                    v.has_free_pages_blocks = true;
                }
                b"pswpin" => v.pswpin = val,
                b"pswpout" => v.pswpout = val,
                b"pgscan_direct" => v.pgscan_direct = val,
                b"pgsteal_direct" => v.pgsteal_direct = val,
                b"allocstall_normal"
                | b"allocstall_movable"
                | b"allocstall_dma"
                | b"allocstall_dma32" => v.allocstall = v.allocstall.saturating_add(val),
                b"compact_stall" => v.compact_stall = val,
                b"oom_kill" => v.oom_kill = val,
                _ => {}
            }
        }
        v
    }
}

pub fn page_size() -> u64 {
    // SAFETY: sysconf is always safe to call.
    let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if p <= 0 {
        4096
    } else {
        p as u64
    }
}

/// One-shot convenience readers (not for the hot loop).
pub fn read_meminfo() -> Result<MemInfo, String> {
    let text = std::fs::read("/proc/meminfo").map_err(|e| format!("/proc/meminfo: {e}"))?;
    MemInfo::parse(&text)
}

pub fn read_vmstat() -> Result<VmStat, String> {
    let text = std::fs::read("/proc/vmstat").map_err(|e| format!("/proc/vmstat: {e}"))?;
    Ok(VmStat::parse(&text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_available_is_valid_and_triggers_emergency() {
        let m =
            MemInfo::parse(b"MemTotal: 125829120 kB\nMemFree: 0 kB\nMemAvailable: 0 kB\n").unwrap();
        let mut engine = crate::engine::Engine::new(crate::engine::EngineConfig::from_config(
            &crate::config::Config::default(),
            m.total,
        ));
        let assessment = engine.step(&crate::engine::Sample {
            total: m.total,
            avail: m.available,
            ..Default::default()
        });
        assert!(assessment.emergency && assessment.may_kill);
        assert!(MemInfo::parse(b"MemTotal: 125829120 kB\nMemFree: 0 kB\n").is_err());
    }

    const SAMPLE: &str = "MemTotal:       125505568 kB\nMemFree:        114796920 kB\nMemAvailable:   119433156 kB\nBuffers:          403300 kB\nCached:          5088708 kB\nSwapCached:            0 kB\nUnevictable:       41804 kB\nSwapTotal:      16777212 kB\nSwapFree:       16777212 kB\nAnonPages:       2544120 kB\nShmem:             24940 kB\nSlab:             680028 kB\nKernelStack:       18464 kB\nPageTables:        52976 kB\nSecPageTables:      6092 kB\nVmallocUsed:      117832 kB\nPercpu:            24080 kB\nHugePages_Total:       0\nHugepagesize:       2048 kB\n";

    #[test]
    fn parse_meminfo() {
        let m = MemInfo::parse(SAMPLE.as_bytes()).unwrap();
        assert_eq!(m.total, 125505568 * 1024);
        assert_eq!(m.available, 119433156 * 1024);
        assert_eq!(m.swap_total, 16777212 * 1024);
        assert_eq!(m.hugepages_total, 0);
        assert_eq!(m.hugepagesize, 2048 * 1024);
        // other_estimate ~ 1.7 GiB of unaccounted on an idle box
        let other = m.other_estimate();
        assert!(other < 4 << 30, "other={other}");
        assert!(MemInfo::parse(b"garbage").is_err());
    }

    #[test]
    fn parse_vmstat() {
        let v = VmStat::parse(b"nr_free_pages 28603491\nnr_free_pages_blocks 28412416\npswpout 12\nallocstall_normal 3\nallocstall_movable 4\n");
        assert_eq!(v.nr_free_pages, 28603491);
        assert_eq!(v.nr_free_pages_blocks, 28412416);
        assert!(v.has_free_pages_blocks);
        assert_eq!(v.pswpout, 12);
        assert_eq!(v.allocstall, 7);
    }

    #[test]
    fn cached_file_reads_live_meminfo() {
        let f = CachedFile::open("/proc/meminfo").unwrap();
        let mut buf = Vec::new();
        f.read(&mut buf).unwrap();
        let m1 = MemInfo::parse(&buf).unwrap();
        f.read(&mut buf).unwrap();
        let m2 = MemInfo::parse(&buf).unwrap();
        assert_eq!(m1.total, m2.total);
        assert!(m1.total > 0);
    }
}
