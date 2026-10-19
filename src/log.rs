//! Minimal logger: level filter, ISO timestamp when not under journald, non-blocking stderr.
//!
//! The daemon sets stderr to O_NONBLOCK so a stalled journald can never block the decision loop;
//! dropped lines are counted and reported in the status output.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

static LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);
static TIMESTAMPS: AtomicBool = AtomicBool::new(true);
static DROPPED: AtomicU64 = AtomicU64::new(0);
static PLAIN: AtomicBool = AtomicBool::new(false);

pub fn set_level(l: Level) {
    LEVEL.store(l as u8, Ordering::Relaxed);
}

pub fn set_level_str(s: &str) {
    set_level(match s {
        "error" => Level::Error,
        "warn" => Level::Warn,
        "debug" => Level::Debug,
        _ => Level::Info,
    });
}

pub fn level() -> Level {
    match LEVEL.load(Ordering::Relaxed) {
        0 => Level::Error,
        1 => Level::Warn,
        2 => Level::Info,
        _ => Level::Debug,
    }
}

pub fn enabled(l: Level) -> bool {
    (l as u8) <= LEVEL.load(Ordering::Relaxed)
}

/// Under systemd (JOURNAL_STREAM set) journald adds timestamps; skip ours.
pub fn init_from_env() {
    if std::env::var_os("JOURNAL_STREAM").is_some() {
        TIMESTAMPS.store(false, Ordering::Relaxed);
    }
}

pub fn set_timestamps(on: bool) {
    TIMESTAMPS.store(on, Ordering::Relaxed);
}

/// Interactive commands: `memguard: LEVEL message`, no timestamps or journald prefixes.
pub fn set_plain(on: bool) {
    PLAIN.store(on, Ordering::Relaxed);
}

/// Make stderr non-blocking so logging can never stall the hot loop.
pub fn set_nonblocking_stderr() {
    // SAFETY: fcntl on fd 2 with valid flags.
    unsafe {
        let flags = libc::fcntl(2, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(2, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}

pub fn dropped_lines() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}

pub(crate) fn record_drop() {
    DROPPED.fetch_add(1, Ordering::Relaxed);
}

fn timestamp() -> String {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: clock_gettime/localtime_r write only into the provided structs.
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        libc::localtime_r(&ts.tv_sec, &mut tm);
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        ts.tv_nsec / 1_000_000
    )
}

/// Write a line to stderr; on EAGAIN (non-blocking, full pipe) drop it and count.
pub fn write_stderr(line: &str) {
    let bytes = line.as_bytes();
    let mut off = 0usize;
    while off < bytes.len() {
        // SAFETY: valid pointer/length into a live slice.
        let n = unsafe {
            libc::write(
                2,
                bytes[off..].as_ptr() as *const libc::c_void,
                bytes.len() - off,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                _ => {
                    DROPPED.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        }
        if n == 0 {
            record_drop();
            return;
        }
        off += n as usize;
    }
}

pub fn log(l: Level, args: fmt::Arguments<'_>) {
    if !enabled(l) {
        return;
    }
    let tag = match l {
        Level::Error => "ERROR",
        Level::Warn => "WARN ",
        Level::Info => "INFO ",
        Level::Debug => "DEBUG",
    };
    let line = if PLAIN.load(Ordering::Relaxed) {
        format!("memguard: {} {}\n", tag.trim(), args)
    } else if TIMESTAMPS.load(Ordering::Relaxed) {
        format!("{} {} {}\n", timestamp(), tag, args)
    } else {
        // journald priority prefix (<3>=err, <4>=warning, <6>=info, <7>=debug)
        let prio = match l {
            Level::Error => 3,
            Level::Warn => 4,
            Level::Info => 6,
            Level::Debug => 7,
        };
        format!("<{}>{} {}\n", prio, tag, args)
    };
    write_stderr(&line);
}

#[macro_export]
macro_rules! error { ($($arg:tt)*) => { $crate::log::log($crate::log::Level::Error, format_args!($($arg)*)) }; }
#[macro_export]
macro_rules! warn { ($($arg:tt)*) => { $crate::log::log($crate::log::Level::Warn, format_args!($($arg)*)) }; }
#[macro_export]
macro_rules! info { ($($arg:tt)*) => { $crate::log::log($crate::log::Level::Info, format_args!($($arg)*)) }; }
#[macro_export]
macro_rules! debug { ($($arg:tt)*) => { $crate::log::log($crate::log::Level::Debug, format_args!($($arg)*)) }; }
