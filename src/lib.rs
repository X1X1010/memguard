//! memguard: a memory watchdog for NVIDIA GB10 (DGX Spark) unified-memory machines.
//!
//! On GB10 every `cudaMalloc` is ordinary system RAM that the kernel cannot attribute to a process
//! (no RSS, no memcg charge, no oom_score). memguard watches system-wide memory, PSI and the
//! NVIDIA per-process GPU memory list, and terminates the offending job before the box freezes.

pub mod actuator;
pub mod cli;
pub mod config;
pub mod daemon;
pub mod doctor;
pub mod engine;
pub mod helper;
pub mod log;
pub mod replay;
pub mod runner;
pub mod sampler;
pub mod sdnotify;
pub mod status;
pub mod sys;
pub mod units;
pub mod victim;

/// Monotonic clock in nanoseconds (CLOCK_MONOTONIC).
pub fn mono_ns() -> u64 {
    clock_ns(libc::CLOCK_MONOTONIC)
}

/// Boot-time clock in nanoseconds (CLOCK_BOOTTIME, advances across suspend).
pub fn boot_ns() -> u64 {
    clock_ns(libc::CLOCK_BOOTTIME)
}

/// Wall clock seconds since the epoch.
pub fn unix_secs() -> u64 {
    clock_ns(libc::CLOCK_REALTIME) / 1_000_000_000
}

fn clock_ns(clock: libc::clockid_t) -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime only writes into the provided timespec.
    unsafe {
        libc::clock_gettime(clock, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

/// Sleep until an absolute CLOCK_MONOTONIC deadline (nanoseconds). Returns early on EINTR.
pub fn sleep_until_mono(deadline_ns: u64) {
    let ts = libc::timespec {
        tv_sec: (deadline_ns / 1_000_000_000) as libc::time_t,
        tv_nsec: (deadline_ns % 1_000_000_000) as libc::c_long,
    };
    // SAFETY: plain syscall with a valid timespec; remaining-time pointer may be null with TIMER_ABSTIME.
    unsafe {
        libc::clock_nanosleep(
            libc::CLOCK_MONOTONIC,
            libc::TIMER_ABSTIME,
            &ts,
            std::ptr::null_mut(),
        );
    }
}
