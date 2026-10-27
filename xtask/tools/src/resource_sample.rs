//! `resource-sample`: measure one running validator (
//! item 10). It reads `/proc` and the data directory of a live process and
//! prints CPU, memory, disk and network figures. It writes no number of its
//! own: every row comes from the process it watched, so the table in the
//! docs can only be filled from a real run.
//!
//! ```text
//! resource-sample --pid P --data-dir D [--seconds N]
//! ```

use std::path::Path;
use std::time::{Duration, Instant};

fn read(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))
}

/// User plus system CPU ticks of a process (`/proc/P/stat` fields 14, 15).
fn cpu_ticks(pid: u32) -> Result<u64, String> {
    let stat = read(&format!("/proc/{pid}/stat"))?;
    let after = stat
        .rsplit_once(')')
        .map(|(_, rest)| rest)
        .ok_or("bad stat")?;
    let fields: Vec<&str> = after.split_whitespace().collect();
    let utime: u64 = fields
        .get(11)
        .and_then(|v| v.parse().ok())
        .ok_or("bad utime")?;
    let stime: u64 = fields
        .get(12)
        .and_then(|v| v.parse().ok())
        .ok_or("bad stime")?;
    Ok(utime + stime)
}

/// Resident set size in KiB (`VmRSS`).
fn rss_kib(pid: u32) -> Result<u64, String> {
    read(&format!("/proc/{pid}/status"))?
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|rest| rest.split_whitespace().next()?.parse().ok())
        .ok_or_else(|| "no VmRSS".to_string())
}

/// Received plus sent bytes over every interface but loopback, as the
/// process's network namespace sees them (`/proc/P/net/dev`).
fn net_bytes(pid: u32) -> Result<u64, String> {
    let mut total = 0u64;
    for line in read(&format!("/proc/{pid}/net/dev"))?.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        if name.trim() == "lo" {
            continue;
        }
        let fields: Vec<u64> = rest
            .split_whitespace()
            .filter_map(|v| v.parse().ok())
            .collect();
        total += fields.first().copied().unwrap_or(0) + fields.get(8).copied().unwrap_or(0);
    }
    Ok(total)
}

fn dir_bytes(path: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    entries
        .flatten()
        .map(|entry| match entry.metadata() {
            Ok(meta) if meta.is_dir() => dir_bytes(&entry.path()),
            Ok(meta) => meta.len(),
            Err(_) => 0,
        })
        .sum()
}

/// Run the sampler.
///
/// # Errors
///
/// Missing arguments or an unreadable process.
pub fn run(args: &[&str]) -> Result<String, String> {
    let mut pid = None;
    let mut data_dir = None;
    let mut seconds = 60u64;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match *arg {
            "--pid" => pid = it.next().and_then(|v| v.parse::<u32>().ok()),
            "--data-dir" => data_dir = it.next().copied(),
            "--seconds" => seconds = it.next().and_then(|v| v.parse().ok()).unwrap_or(60),
            other => return Err(format!("resource-sample: unknown argument `{other}`")),
        }
    }
    let pid = pid.ok_or("resource-sample: --pid is required")?;
    let data_dir = Path::new(data_dir.ok_or("resource-sample: --data-dir is required")?);
    let ticks_per_second = 100u64; // USER_HZ on Linux
    let start = Instant::now();
    let cpu0 = cpu_ticks(pid)?;
    let net0 = net_bytes(pid)?;
    let disk0 = dir_bytes(data_dir);
    let mut peak_rss = rss_kib(pid)?;
    while start.elapsed() < Duration::from_secs(seconds) {
        std::thread::sleep(Duration::from_secs(1));
        peak_rss = peak_rss.max(rss_kib(pid)?);
    }
    let elapsed = start.elapsed().as_secs().max(1);
    let cpu = cpu_ticks(pid)?.saturating_sub(cpu0);
    let net = net_bytes(pid)?.saturating_sub(net0);
    let disk1 = dir_bytes(data_dir);
    Ok(format!(
        "| Measure | Value |\n|---|---|\n\
         | Window | {elapsed} s |\n\
         | CPU (mean, one core = 100%) | {} % |\n\
         | Peak RSS | {} MiB |\n\
         | Data directory | {} MiB (grew {} KiB) |\n\
         | Network (rx + tx, mean) | {} KiB/s |\n",
        cpu * 100 / ticks_per_second / elapsed,
        peak_rss / 1024,
        disk1 / (1024 * 1024),
        disk1.saturating_sub(disk0) / 1024,
        net / 1024 / elapsed,
    ))
}

/// The canary: this process can be read.
///
/// # Errors
///
/// `/proc` is unreadable.
pub fn self_test() -> Result<String, String> {
    let pid = std::process::id();
    cpu_ticks(pid)?;
    rss_kib(pid)?;
    Ok("resource-sample: /proc of a live process reads".into())
}
