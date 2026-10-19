//! PSI (`/proc/pressure/memory`, cgroup `memory.pressure`) parsing and a sliding-window stall
//! fraction computed from the monotonically increasing `total` counters (avg10 lags too much).

use super::meminfo::parse_u64_prefix;

#[derive(Default, Clone, Copy, Debug, PartialEq)]
pub struct Psi {
    pub some_avg10: f64,
    pub some_avg60: f64,
    pub some_avg300: f64,
    pub some_total_us: u64,
    pub full_avg10: f64,
    pub full_avg60: f64,
    pub full_avg300: f64,
    pub full_total_us: u64,
}

fn parse_f64_field(line: &[u8], key: &[u8]) -> f64 {
    if let Some(pos) = line.windows(key.len()).position(|w| w == key) {
        let rest = &line[pos + key.len()..];
        let end = rest.iter().position(|b| *b == b' ').unwrap_or(rest.len());
        std::str::from_utf8(&rest[..end])
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0)
    } else {
        0.0
    }
}

pub fn parse(buf: &[u8]) -> Result<Psi, String> {
    let mut p = Psi::default();
    let mut seen = 0;
    for line in buf.split(|b| *b == b'\n') {
        let (is_some, is_full) = (line.starts_with(b"some "), line.starts_with(b"full "));
        if !is_some && !is_full {
            continue;
        }
        seen += 1;
        let total = line
            .windows(6)
            .position(|w| w == b"total=")
            .map(|pos| parse_u64_prefix(&line[pos + 6..]).0)
            .unwrap_or(0);
        let a10 = parse_f64_field(line, b"avg10=");
        let a60 = parse_f64_field(line, b"avg60=");
        let a300 = parse_f64_field(line, b"avg300=");
        if is_some {
            p.some_avg10 = a10;
            p.some_avg60 = a60;
            p.some_avg300 = a300;
            p.some_total_us = total;
        } else {
            p.full_avg10 = a10;
            p.full_avg60 = a60;
            p.full_avg300 = a300;
            p.full_total_us = total;
        }
    }
    if seen == 0 {
        return Err("no PSI lines".into());
    }
    Ok(p)
}

pub fn read_system_memory() -> Result<Psi, String> {
    let text = std::fs::read("/proc/pressure/memory")
        .map_err(|e| format!("/proc/pressure/memory: {e}"))?;
    parse(&text)
}

const CAP: usize = 256;

/// Fixed-size ring of (time, some_total, full_total) samples; no heap allocation after creation.
pub struct PsiRing {
    t: [u64; CAP],
    some: [u64; CAP],
    full: [u64; CAP],
    head: usize,
    len: usize,
}

impl Default for PsiRing {
    fn default() -> Self {
        Self::new()
    }
}

impl PsiRing {
    pub fn new() -> Self {
        PsiRing {
            t: [0; CAP],
            some: [0; CAP],
            full: [0; CAP],
            head: 0,
            len: 0,
        }
    }

    pub fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }

    pub fn push(&mut self, t_ns: u64, some_us: u64, full_us: u64) {
        let idx = (self.head + self.len) % CAP;
        self.t[idx] = t_ns;
        self.some[idx] = some_us;
        self.full[idx] = full_us;
        if self.len < CAP {
            self.len += 1;
        } else {
            self.head = (self.head + 1) % CAP;
        }
    }

    fn at(&self, i: usize) -> (u64, u64, u64) {
        let idx = (self.head + i) % CAP;
        (self.t[idx], self.some[idx], self.full[idx])
    }

    /// Stall fractions (some, full) over roughly `window_ns` ending at the newest sample.
    /// Uses the newest sample that is at least `window_ns` old, or the oldest sample if the ring
    /// does not yet span the window (requires >= 200 ms of history). None if insufficient data.
    pub fn fractions(&self, window_ns: u64) -> Option<(f64, f64, u64)> {
        if self.len < 2 {
            return None;
        }
        let (tn, sn, fnl) = self.at(self.len - 1);
        let mut base = self.at(0);
        for i in (0..self.len - 1).rev() {
            let s = self.at(i);
            if tn.saturating_sub(s.0) >= window_ns {
                base = s;
                break;
            }
        }
        let span = tn.saturating_sub(base.0);
        if span < 200_000_000 {
            return None;
        }
        let some = (sn.saturating_sub(base.1) as f64 * 1000.0 / span as f64).min(1.0);
        let full = (fnl.saturating_sub(base.2) as f64 * 1000.0 / span as f64).min(1.0);
        Some((some, full, span))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_psi() {
        let p = parse(b"some avg10=1.50 avg60=0.20 avg300=0.06 total=39628839\nfull avg10=0.00 avg60=0.00 avg300=0.06 total=39405412\n").unwrap();
        assert_eq!(p.some_total_us, 39628839);
        assert_eq!(p.full_total_us, 39405412);
        assert!((p.some_avg10 - 1.5).abs() < 1e-9);
        assert!(parse(b"nothing").is_err());
    }

    #[test]
    fn ring_fractions() {
        let mut r = PsiRing::new();
        // 50 ms ticks, full stall grows 25 ms per tick (50%), some grows 50 ms per tick (100%)
        for i in 0..40u64 {
            r.push(i * 50_000_000, i * 50_000, i * 25_000);
        }
        let (some, full, span) = r.fractions(1_000_000_000).unwrap();
        assert!((some - 1.0).abs() < 1e-6, "some={some}");
        assert!((full - 0.5).abs() < 1e-6, "full={full}");
        assert!(span >= 1_000_000_000);
        let mut short = PsiRing::new();
        short.push(0, 0, 0);
        short.push(100_000_000, 0, 0);
        assert!(short.fractions(1_000_000_000).is_none());
        short.push(300_000_000, 0, 0);
        assert!(short.fractions(1_000_000_000).is_some());
    }

    #[test]
    fn ring_wraps() {
        let mut r = PsiRing::new();
        for i in 0..(CAP as u64 * 3) {
            r.push(i * 50_000_000, i * 10_000, 0);
        }
        let (some, full, _) = r.fractions(1_000_000_000).unwrap();
        assert!((some - 0.2).abs() < 1e-6);
        assert_eq!(full, 0.0);
    }
}
