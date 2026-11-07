//! budlum-mobile-log-analyzer (WP-37).
//!
//! Reads the duty log produced on the device by the Budlum validator app
//! (`noBackupFilesDir/duty.log`) and prints a deterministic report.
//!
//! Log line formats (one per line, `<millis> <KIND> [args...]`):
//!   <millis> RUN | PAUSED_THERMAL | PAUSED_NETWORK | PAUSED_POWER
//!   <millis> AUDIT pass|fail
//!   <millis> BATTERY <percent>
//!
//! Usage: budlum-mobile-log-analyzer <duty.log>

use std::env;
use std::fs;
use std::process::ExitCode;

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Report {
    pub run: u64,
    pub paused_thermal: u64,
    pub paused_network: u64,
    pub paused_power: u64,
    pub audits_passed: u64,
    pub audits_failed: u64,
    pub battery_first: Option<u8>,
    pub battery_last: Option<u8>,
}

impl Report {
    pub fn total_decisions(&self) -> u64 {
        self.run + self.paused_thermal + self.paused_network + self.paused_power
    }

    pub fn run_ratio(&self) -> f64 {
        let total = self.total_decisions();
        if total == 0 {
            0.0
        } else {
            self.run as f64 / total as f64
        }
    }

    pub fn audit_pass_rate(&self) -> f64 {
        let total = self.audits_passed + self.audits_failed;
        if total == 0 {
            0.0
        } else {
            self.audits_passed as f64 / total as f64
        }
    }

    pub fn battery_drain(&self) -> Option<i16> {
        match (self.battery_first, self.battery_last) {
            (Some(first), Some(last)) => Some(last as i16 - first as i16),
            _ => None,
        }
    }
}

/// Parse the log text into a [Report]. Unknown lines are ignored but counted.
pub fn parse_report(log: &str) -> (Report, u64) {
    let mut report = Report::default();
    let mut unknown = 0u64;
    for line in log.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let _millis = match parts.next() {
            Some(m) if m.chars().all(|c| c.is_ascii_digit()) => m,
            _ => {
                unknown += 1;
                continue;
            }
        };
        match parts.next() {
            Some("RUN") => report.run += 1,
            Some("PAUSED_THERMAL") => report.paused_thermal += 1,
            Some("PAUSED_NETWORK") => report.paused_network += 1,
            Some("PAUSED_POWER") => report.paused_power += 1,
            Some("AUDIT") => match parts.next() {
                Some("pass") => report.audits_passed += 1,
                Some("fail") => report.audits_failed += 1,
                _ => unknown += 1,
            },
            Some("BATTERY") => match parts.next().and_then(|p| p.parse::<u8>().ok()) {
                Some(pct) => {
                    if report.battery_first.is_none() {
                        report.battery_first = Some(pct);
                    }
                    report.battery_last = Some(pct);
                }
                None => unknown += 1,
            },
            _ => unknown += 1,
        }
    }
    (report, unknown)
}

/// Deterministic text report. Golden-tested by `device_log_analyzer_golden_reports`.
pub fn render_report(report: &Report, unknown: u64) -> String {
    let mut out = String::new();
    out.push_str("budlum mobile duty report\n");
    out.push_str(&format!("decisions.total {}\n", report.total_decisions()));
    out.push_str(&format!("decisions.run {}\n", report.run));
    out.push_str(&format!("decisions.paused_thermal {}\n", report.paused_thermal));
    out.push_str(&format!("decisions.paused_network {}\n", report.paused_network));
    out.push_str(&format!("decisions.paused_power {}\n", report.paused_power));
    out.push_str(&format!("decisions.run_ratio {:.4}\n", report.run_ratio()));
    out.push_str(&format!("audits.passed {}\n", report.audits_passed));
    out.push_str(&format!("audits.failed {}\n", report.audits_failed));
    out.push_str(&format!("audits.pass_rate {:.4}\n", report.audit_pass_rate()));
    match report.battery_drain() {
        Some(drain) => out.push_str(&format!("battery.drain_percent {}\n", drain)),
        None => out.push_str("battery.drain_percent n/a\n"),
    }
    out.push_str(&format!("lines.unknown {}\n", unknown));
    out
}

fn main() -> ExitCode {
    let path = match env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: budlum-mobile-log-analyzer <duty.log>");
            return ExitCode::from(2);
        }
    };
    let log = match fs::read_to_string(&path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot read {}: {}", path, e);
            return ExitCode::from(2);
        }
    };
    let (report, unknown) = parse_report(&log);
    print!("{}", render_report(&report, unknown));
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN_LOG: &str = "\
1700000000000 RUN
1700000900000 AUDIT pass
1700001800000 AUDIT pass
1700002700000 AUDIT fail
1700003600000 PAUSED_THERMAL
1700004500000 RUN
1700005400000 PAUSED_NETWORK
1700006300000 PAUSED_POWER
1700007200000 BATTERY 87
1700008100000 BATTERY 82
garbage line
";

    const GOLDEN_REPORT: &str = "\
budlum mobile duty report
decisions.total 6
decisions.run 2
decisions.paused_thermal 1
decisions.paused_network 1
decisions.paused_power 1
decisions.run_ratio 0.3333
audits.passed 2
audits.failed 1
audits.pass_rate 0.6667
battery.drain_percent -5
lines.unknown 1
";

    #[test]
    fn device_log_analyzer_golden_reports() {
        let (report, unknown) = parse_report(GOLDEN_LOG);
        assert_eq!(report.run, 2);
        assert_eq!(report.paused_thermal, 1);
        assert_eq!(report.audits_passed, 2);
        assert_eq!(report.audits_failed, 1);
        assert_eq!(report.battery_drain(), Some(-5));
        assert_eq!(unknown, 1);
        assert_eq!(render_report(&report, unknown), GOLDEN_REPORT);
    }

    #[test]
    fn empty_log_reports_zeros() {
        let (report, unknown) = parse_report("");
        assert_eq!(report, Report::default());
        assert_eq!(unknown, 0);
        assert!(render_report(&report, unknown).contains("decisions.total 0"));
    }
}
