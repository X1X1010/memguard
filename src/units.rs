//! Parsing and formatting of sizes ("8G", "5%"), durations ("150ms", "2s"), fractions and booleans.

const KIB: f64 = 1024.0;

/// A size that is either absolute or a percentage of total RAM (resolved later).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SizeSpec {
    Bytes(u64),
    Percent(f64),
}

impl SizeSpec {
    pub fn resolve(self, total: u64) -> u64 {
        match self {
            SizeSpec::Bytes(b) => b,
            SizeSpec::Percent(p) => ((total as f64) * p / 100.0).round().max(0.0) as u64,
        }
    }
}

impl std::fmt::Display for SizeSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SizeSpec::Bytes(b) => write!(f, "{}", fmt_bytes(*b)),
            SizeSpec::Percent(p) => write!(f, "{p}%"),
        }
    }
}

fn split_num_suffix(s: &str) -> Result<(f64, &str), String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty value".into());
    }
    let idx = s
        .char_indices()
        .find(|(_, c)| !(c.is_ascii_digit() || *c == '.' || *c == '_'))
        .map(|(i, _)| i)
        .unwrap_or(s.len());
    let (num, suffix) = s.split_at(idx);
    let num = num.replace('_', "");
    let v: f64 = num
        .parse()
        .map_err(|_| format!("invalid number in '{s}'"))?;
    if v < 0.0 || !v.is_finite() {
        return Err(format!("negative or non-finite value '{s}'"));
    }
    Ok((v, suffix.trim()))
}

/// Parse "8G", "512M", "1.5T", "4096", "8GiB", "8gb" (binary units) or "5%".
pub fn parse_size_spec(s: &str) -> Result<SizeSpec, String> {
    let (v, suffix) = split_num_suffix(s)?;
    if suffix == "%" {
        if v > 100.0 {
            return Err(format!("percentage above 100 in '{s}'"));
        }
        return Ok(SizeSpec::Percent(v));
    }
    let mult = match suffix.to_ascii_lowercase().as_str() {
        "" | "b" => 1.0,
        "k" | "kb" | "kib" => KIB,
        "m" | "mb" | "mib" => KIB * KIB,
        "g" | "gb" | "gib" => KIB * KIB * KIB,
        "t" | "tb" | "tib" => KIB * KIB * KIB * KIB,
        other => return Err(format!("unknown size suffix '{other}' in '{s}'")),
    };
    let bytes = (v * mult).round();
    if !bytes.is_finite() || bytes >= u64::MAX as f64 {
        return Err(format!("size too large: '{s}'"));
    }
    Ok(SizeSpec::Bytes(bytes as u64))
}

/// Parse an absolute size (percentages rejected).
pub fn parse_size(s: &str) -> Result<u64, String> {
    match parse_size_spec(s)? {
        SizeSpec::Bytes(b) => Ok(b),
        SizeSpec::Percent(_) => Err(format!("percentage not allowed here: '{s}'")),
    }
}

/// Parse "150ms", "2s", "1.5s", "3m", or a bare number of milliseconds.
pub fn parse_duration_ms(s: &str) -> Result<u64, String> {
    let (v, suffix) = split_num_suffix(s)?;
    let ms = match suffix.to_ascii_lowercase().as_str() {
        "" | "ms" => v,
        "s" | "sec" => v * 1000.0,
        "m" | "min" => v * 60_000.0,
        "h" => v * 3_600_000.0,
        other => return Err(format!("unknown duration suffix '{other}' in '{s}'")),
    };
    if !ms.is_finite() || ms.round() >= u64::MAX as f64 {
        return Err(format!("duration too large: '{s}'"));
    }
    Ok(ms.round() as u64)
}

/// Parse "0.30" or "30%" into a fraction in [0, 1].
pub fn parse_fraction(s: &str) -> Result<f64, String> {
    let (v, suffix) = split_num_suffix(s)?;
    let f = match suffix {
        "%" => v / 100.0,
        "" => v,
        other => return Err(format!("unexpected suffix '{other}' in '{s}'")),
    };
    if !(0.0..=1.0).contains(&f) {
        return Err(format!("fraction out of range in '{s}'"));
    }
    Ok(f)
}

pub fn parse_bool(s: &str) -> Result<bool, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(format!("invalid boolean '{other}'")),
    }
}

/// Human-readable binary size: "8.0G", "512M", "3.2T", "0".
pub fn fmt_bytes(b: u64) -> String {
    let f = b as f64;
    if f >= KIB * KIB * KIB * KIB {
        format!("{:.2}T", f / (KIB * KIB * KIB * KIB))
    } else if f >= KIB * KIB * KIB {
        format!("{:.1}G", f / (KIB * KIB * KIB))
    } else if f >= KIB * KIB {
        format!("{:.0}M", f / (KIB * KIB))
    } else if f >= KIB {
        format!("{:.0}K", f / KIB)
    } else {
        format!("{b}")
    }
}

/// Human-readable rate in bytes per second: "34.1G/s".
pub fn fmt_rate(bps: f64) -> String {
    if !bps.is_finite() {
        return "inf".into();
    }
    let sign = if bps < 0.0 { "-" } else { "" };
    format!("{sign}{}/s", fmt_bytes(bps.abs().round() as u64))
}

pub fn fmt_dur_ms(ms: u64) -> String {
    if ms >= 60_000 {
        format!("{:.1}m", ms as f64 / 60_000.0)
    } else if ms >= 1000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        format!("{ms}ms")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(parse_size("8G").unwrap(), 8 << 30);
        assert_eq!(parse_size("8GiB").unwrap(), 8 << 30);
        assert_eq!(parse_size("512m").unwrap(), 512 << 20);
        assert_eq!(parse_size("1.5T").unwrap(), 3 << 39);
        assert_eq!(parse_size("4096").unwrap(), 4096);
        assert_eq!(parse_size("1_000").unwrap(), 1000);
        assert_eq!(parse_size_spec("5%").unwrap(), SizeSpec::Percent(5.0));
        assert_eq!(SizeSpec::Percent(5.0).resolve(1000), 50);
        assert!(parse_size("5%").is_err());
        assert!(parse_size("8X").is_err());
        assert!(parse_size("-1G").is_err());
        assert!(parse_size_spec("150%").is_err());
    }

    #[test]
    fn durations_fractions_bools() {
        assert_eq!(parse_duration_ms("150ms").unwrap(), 150);
        assert_eq!(parse_duration_ms("2s").unwrap(), 2000);
        assert_eq!(parse_duration_ms("1.5s").unwrap(), 1500);
        assert_eq!(parse_duration_ms("500").unwrap(), 500);
        assert_eq!(parse_fraction("30%").unwrap(), 0.3);
        assert_eq!(parse_fraction("0.25").unwrap(), 0.25);
        assert!(parse_fraction("1.5").is_err());
        assert!(parse_bool("yes").unwrap());
        assert!(!parse_bool("off").unwrap());
        assert!(parse_bool("maybe").is_err());
    }

    #[test]
    fn formatting() {
        assert_eq!(fmt_bytes(8 << 30), "8.0G");
        assert_eq!(fmt_bytes(512 << 20), "512M");
        assert_eq!(fmt_bytes(0), "0");
        assert_eq!(fmt_rate(34.0 * (1u64 << 30) as f64), "34.0G/s");
        assert_eq!(fmt_dur_ms(1500), "1.5s");
    }
}
