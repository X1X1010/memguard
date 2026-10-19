//! Command-line dispatch and a tiny argv parser (no external crates).

use std::collections::{HashMap, HashSet};

use crate::{daemon, doctor, helper, replay, runner, status};

pub struct Parsed {
    pub flags: HashSet<String>,
    pub opts: HashMap<String, String>,
    pub multi: HashMap<String, Vec<String>>,
    pub positional: Vec<String>,
    /// Everything after `--`.
    pub rest: Vec<String>,
}

impl Parsed {
    pub fn flag(&self, name: &str) -> bool {
        self.flags.contains(name)
    }
    pub fn opt(&self, name: &str) -> Option<&str> {
        self.opts.get(name).map(|s| s.as_str())
    }
    pub fn multi(&self, name: &str) -> &[String] {
        self.multi.get(name).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

/// Parse `--key value`, `--key=value`, `-k value`, repeatable options (`multi`), flags and `--`.
pub fn parse(
    args: &[String],
    takes_value: &[&str],
    multi_value: &[&str],
    flags: &[&str],
) -> Result<Parsed, String> {
    let mut p = Parsed {
        flags: HashSet::new(),
        opts: HashMap::new(),
        multi: HashMap::new(),
        positional: Vec::new(),
        rest: Vec::new(),
    };
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            p.rest = args[i + 1..].to_vec();
            break;
        }
        if let Some(stripped) = a.strip_prefix('-') {
            let body = stripped.trim_start_matches('-');
            let (name, inline) = match body.split_once('=') {
                Some((n, v)) => (n.to_string(), Some(v.to_string())),
                None => (body.to_string(), None),
            };
            if flags.contains(&name.as_str()) {
                if inline.is_some() {
                    return Err(format!("flag --{name} takes no value"));
                }
                p.flags.insert(name);
            } else if takes_value.contains(&name.as_str()) || multi_value.contains(&name.as_str()) {
                let v = match inline {
                    Some(v) => v,
                    None => {
                        i += 1;
                        args.get(i)
                            .cloned()
                            .ok_or_else(|| format!("--{name} needs a value"))?
                    }
                };
                if multi_value.contains(&name.as_str()) {
                    p.multi.entry(name).or_default().push(v);
                } else {
                    p.opts.insert(name, v);
                }
            } else {
                return Err(format!("unknown option '{a}'"));
            }
        } else {
            p.positional.push(a.clone());
        }
        i += 1;
    }
    Ok(p)
}

pub const USAGE: &str = "memguard - memory watchdog for NVIDIA GB10 (DGX Spark) unified memory

USAGE
  memguard daemon  [--config F] [--dry-run] [--only-kill-exe PATH] [--record F] [-o key=value]... [-v]
  memguard run     [--gpu SZ] [--mem SZ] [--total SZ] [--swap SZ|max] [--floor SZ]
                   [--prefer-kill | --oom-adj N] [--unit NAME] [--no-scope] [--dry-run] [-v] -- CMD ARGS...
  memguard status  [--json] [--top N]
  memguard ps      [--sort footprint|vidmem|rss|swap|vmsize] [-n N] [--all]
  memguard doctor  [--probe]
  memguard check-config [--config F] [-o key=value]...
  memguard replay  TRACE [--config F] [-o key=value]... [-v]
  memguard version

Sizes accept 8G, 512M, 5%; durations 150ms, 2s. Default config: /etc/memguard/memguard.conf.
";

pub fn main() -> i32 {
    crate::log::init_from_env();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        None | Some("-h") | Some("--help") | Some("help") => {
            print!("{USAGE}");
            0
        }
        Some("version") | Some("--version") | Some("-V") => {
            println!("memguard {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Some("daemon") => daemon::main(&args[1..]),
        Some("run") => runner::main(&args[1..]),
        Some("status") => status::status_main(&args[1..]),
        Some("ps") => status::ps_main(&args[1..]),
        Some("doctor") => doctor::doctor_main(&args[1..]),
        Some("check-config") => doctor::check_config_main(&args[1..]),
        Some("replay") => replay::main(&args[1..]),
        Some("nvml-helper") => {
            helper::helper_main(args.get(1).and_then(|s| s.parse().ok()).unwrap_or(50))
        }
        Some("probe-child") => doctor::probe_child_main(),
        Some(other) => {
            eprintln!("memguard: unknown command '{other}'\n");
            eprint!("{USAGE}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args() {
        let a: Vec<String> = [
            "--gpu",
            "8G",
            "--mem=2G",
            "-o",
            "floor=1G",
            "-o",
            "warn=2G",
            "--dry-run",
            "pos",
            "--",
            "cmd",
            "--x",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let p = parse(&a, &["gpu", "mem"], &["o"], &["dry-run"]).unwrap();
        assert_eq!(p.opt("gpu"), Some("8G"));
        assert_eq!(p.opt("mem"), Some("2G"));
        assert_eq!(
            p.multi("o"),
            &["floor=1G".to_string(), "warn=2G".to_string()]
        );
        assert!(p.flag("dry-run"));
        assert_eq!(p.positional, vec!["pos"]);
        assert_eq!(p.rest, vec!["cmd", "--x"]);
        assert!(parse(&["--bogus".to_string()], &[], &[], &[]).is_err());
        assert!(parse(&["--gpu".to_string()], &["gpu"], &[], &[]).is_err());
    }
}
