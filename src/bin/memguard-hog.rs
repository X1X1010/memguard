//! memguard-hog: a controllable memory load generator for testing memguard SAFELY.
//!
//! It refuses to allocate below `--min-avail` (default 32 GiB of MemAvailable) and caps the
//! total at `--max` (default 40 GiB), so no test can exhaust the machine even if memguard fails.
//! It sets its own oom_score_adj to 1000 so it is the preferred victim for every OOM killer.

use std::sync::atomic::{AtomicBool, Ordering};

use memguard::sys::cuda::Cuda;
use memguard::sys::meminfo::read_meminfo;
use memguard::units::{fmt_bytes, parse_size};

const GIB: u64 = 1 << 30;

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_term(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

struct Opts {
    vidmem: u64,
    managed: u64,
    pinned: u64,
    anon: u64,
    step: u64,
    rate_gibs: f64,
    hold_s: f64,
    children: u32,
    ignore_term: bool,
    min_avail: u64,
    max: u64,
    touch: bool,
    quiet: bool,
}

const USAGE: &str =
    "memguard-hog [--vidmem SZ] [--managed SZ] [--pinned SZ] [--anon SZ] [--step SZ=1G]
             [--rate GiB/s (0=max)] [--hold SECS=10] [--children N] [--ignore-term]
             [--min-avail SZ=32G] [--max SZ=40G] [--touch] [--quiet]
Allocates memory of the requested kinds in --step chunks, then holds it for --hold seconds.
Stops (exit 3) when MemAvailable would drop below --min-avail. Exit 0 on normal completion.
";

fn parse(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts {
        vidmem: 0,
        managed: 0,
        pinned: 0,
        anon: 0,
        step: GIB,
        rate_gibs: 0.0,
        hold_s: 10.0,
        children: 0,
        ignore_term: false,
        min_avail: 32 * GIB,
        max: 40 * GIB,
        touch: false,
        quiet: false,
    };
    let mut i = 0;
    let val = |i: &mut usize| -> Result<String, String> {
        *i += 1;
        args.get(*i)
            .cloned()
            .ok_or_else(|| format!("{} needs a value", args[*i - 1]))
    };
    while i < args.len() {
        match args[i].as_str() {
            "--vidmem" => o.vidmem = parse_size(&val(&mut i)?)?,
            "--managed" => o.managed = parse_size(&val(&mut i)?)?,
            "--pinned" => o.pinned = parse_size(&val(&mut i)?)?,
            "--anon" => o.anon = parse_size(&val(&mut i)?)?,
            "--step" => o.step = parse_size(&val(&mut i)?)?.max(1 << 20),
            "--rate" => o.rate_gibs = val(&mut i)?.parse().map_err(|_| "bad --rate")?,
            "--hold" => o.hold_s = val(&mut i)?.parse().map_err(|_| "bad --hold")?,
            "--children" => o.children = val(&mut i)?.parse().map_err(|_| "bad --children")?,
            "--min-avail" => o.min_avail = parse_size(&val(&mut i)?)?,
            "--max" => o.max = parse_size(&val(&mut i)?)?,
            "--ignore-term" => o.ignore_term = true,
            "--touch" => o.touch = true,
            "--quiet" => o.quiet = true,
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument '{other}'")),
        }
        i += 1;
    }
    let total = [o.vidmem, o.managed, o.pinned, o.anon]
        .into_iter()
        .try_fold(0u64, |sum, v| sum.checked_add(v))
        .ok_or("allocation total overflows")?;
    if !o.rate_gibs.is_finite()
        || o.rate_gibs < 0.0
        || !o.hold_s.is_finite()
        || !(0.0..=86_400.0).contains(&o.hold_s)
    {
        return Err("--rate must be finite and nonnegative; --hold must be within 0..86400".into());
    }
    if o.children > 32 {
        return Err("--children must be within 0..32".into());
    }
    if total == 0 {
        return Err("nothing to allocate (use --vidmem/--managed/--pinned/--anon)".into());
    }
    if total > o.max {
        return Err(format!(
            "requested {} exceeds --max {} (raise --max deliberately if you really mean it)",
            fmt_bytes(total),
            fmt_bytes(o.max)
        ));
    }
    Ok(o)
}

fn avail() -> u64 {
    read_meminfo().map(|m| m.available).unwrap_or(0)
}

struct Holder {
    cuda: Option<Cuda>,
    dev: Vec<u64>,
    managed: Vec<u64>,
    host: Vec<(*mut u8, usize)>,
    anon: Vec<Vec<u8>>,
}

impl Holder {
    fn free_all(&mut self) {
        if let Some(c) = &self.cuda {
            for p in self.dev.drain(..).chain(self.managed.drain(..)) {
                c.mem_free(p);
            }
            for (p, _) in self.host.drain(..) {
                c.mem_free_host(p);
            }
        }
        self.anon.clear();
    }
}

fn run_one(o: &Opts, label: &str) -> i32 {
    let pid = std::process::id();
    let log = |msg: String| {
        if !o.quiet {
            eprintln!("hog[{pid}{label}]: {msg}");
        }
    };
    let need_cuda = o.vidmem + o.managed + o.pinned > 0;
    let cuda = if need_cuda {
        match Cuda::load().and_then(|c| c.init_primary().map(|_| c)) {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("hog: CUDA unavailable: {e}");
                return 2;
            }
        }
    } else {
        None
    };
    let mut h = Holder {
        cuda,
        dev: Vec::new(),
        managed: Vec::new(),
        host: Vec::new(),
        anon: Vec::new(),
    };
    let t0 = std::time::Instant::now();
    let mut allocated = 0u64;
    let mut guard_hit = false;
    let mut allocation_failed = false;
    let plan: [(&str, u64); 4] = [
        ("vidmem", o.vidmem),
        ("managed", o.managed),
        ("pinned", o.pinned),
        ("anon", o.anon),
    ];
    'outer: for (kind, size) in plan {
        let mut done = 0u64;
        while done < size {
            if STOP.load(Ordering::SeqCst) {
                break 'outer;
            }
            let step = o.step.min(size - done) as usize;
            let a = avail();
            let in_flight = (step as u64).saturating_mul(o.children.max(1) as u64);
            if a < o.min_avail.saturating_add(in_flight) {
                log(format!(
                    "GUARD: MemAvailable {} would drop below --min-avail {}; stopping allocation",
                    fmt_bytes(a),
                    fmt_bytes(o.min_avail)
                ));
                guard_hit = true;
                break 'outer;
            }
            let res: Result<(), String> = match kind {
                "vidmem" => {
                    let c = h.cuda.as_ref().unwrap();
                    c.mem_alloc(step).and_then(|p| {
                        h.dev.push(p);
                        if o.touch {
                            c.memset_d8(p, 1, step)?;
                            c.sync()?;
                        }
                        Ok(())
                    })
                }
                "managed" => {
                    let c = h.cuda.as_ref().unwrap();
                    c.mem_alloc_managed(step).and_then(|p| {
                        h.managed.push(p);
                        // GPU touch populates managed pages (ATS): this is what costs RAM
                        c.memset_d8(p, 1, step)?;
                        c.sync()
                    })
                }
                "pinned" => {
                    let c = h.cuda.as_ref().unwrap();
                    c.mem_alloc_host(step).map(|p| {
                        // SAFETY: freshly allocated host buffer of `step` bytes.
                        unsafe { std::ptr::write_bytes(p, 1, step) };
                        h.host.push((p, step));
                    })
                }
                _ => {
                    h.anon.push(vec![1u8; step]);
                    Ok(())
                }
            };
            if let Err(e) = res {
                allocation_failed = true;
                log(format!(
                    "{kind} allocation failed after {}: {e}",
                    fmt_bytes(allocated)
                ));
                break 'outer;
            }
            done += step as u64;
            allocated += step as u64;
            let el = t0.elapsed().as_secs_f64();
            log(format!(
                "{kind} {}/{} total {} elapsed {el:.2}s",
                fmt_bytes(done),
                fmt_bytes(size),
                fmt_bytes(allocated)
            ));
            if o.rate_gibs > 0.0 {
                let target = allocated as f64 / GIB as f64 / o.rate_gibs;
                if target > el {
                    std::thread::sleep(std::time::Duration::from_secs_f64(target - el));
                }
            }
        }
    }
    log(format!(
        "holding {} for {:.1}s",
        fmt_bytes(allocated),
        o.hold_s
    ));
    let hold_until = std::time::Instant::now()
        + std::time::Duration::from_secs_f64(if allocation_failed { 0.0 } else { o.hold_s });
    while std::time::Instant::now() < hold_until && !STOP.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    h.free_all();
    log("released everything".into());
    if allocation_failed {
        2
    } else if guard_hit {
        3
    } else {
        0
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let o = match parse(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("memguard-hog: {e}\n{USAGE}");
            std::process::exit(2);
        }
    };
    let _ = std::fs::write("/proc/self/oom_score_adj", "1000");
    // SAFETY: installing simple signal dispositions.
    unsafe {
        if o.ignore_term {
            libc::signal(libc::SIGTERM, libc::SIG_IGN);
        } else {
            libc::signal(
                libc::SIGTERM,
                on_term as extern "C" fn(libc::c_int) as *const () as usize,
            );
        }
        libc::signal(
            libc::SIGINT,
            on_term as extern "C" fn(libc::c_int) as *const () as usize,
        );
    }
    if o.children == 0 {
        std::process::exit(run_one(&o, ""));
    }
    // fork N children, each allocating an equal share
    let n = o.children as u64;
    let child_opts = Opts {
        vidmem: o.vidmem / n,
        managed: o.managed / n,
        pinned: o.pinned / n,
        anon: o.anon / n,
        ..o
    };
    let mut pids = Vec::new();
    for i in 0..o.children {
        // SAFETY: fork; the child only runs run_one and exits.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            std::process::exit(run_one(&child_opts, &format!(" c{i}")));
        } else if pid > 0 {
            pids.push(pid);
        } else {
            eprintln!("hog: fork failed: {}", std::io::Error::last_os_error());
            STOP.store(true, Ordering::SeqCst);
            break;
        }
    }
    let mut worst = if pids.len() < o.children as usize {
        2
    } else {
        0
    };
    for (index, pid) in pids.iter().enumerate() {
        let mut st = 0;
        loop {
            if STOP.load(Ordering::SeqCst) {
                for child in &pids[index..] {
                    // SAFETY: these are our unreaped child PIDs.
                    unsafe {
                        libc::kill(*child, libc::SIGKILL);
                    }
                }
            }
            // SAFETY: waiting on our own child.
            let r = unsafe { libc::waitpid(*pid, &mut st, 0) };
            if r >= 0 {
                break;
            }
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                worst = worst.max(2);
                break;
            }
        }
        let code = if libc::WIFEXITED(st) {
            libc::WEXITSTATUS(st)
        } else {
            128 + libc::WTERMSIG(st)
        };
        worst = worst.max(code);
    }
    std::process::exit(worst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_numeric_inputs_are_rejected() {
        for options in [
            vec!["--anon", "1M", "--hold", "NaN"],
            vec!["--anon", "1M", "--rate", "inf"],
            vec!["--anon", "1M", "--children", "100000"],
            vec![
                "--anon",
                "9000000000000000000",
                "--vidmem",
                "10000000000000000000",
                "--max",
                "18000000000000000000",
            ],
        ] {
            assert!(parse(&options.iter().map(|s| s.to_string()).collect::<Vec<_>>()).is_err());
        }
    }
}
