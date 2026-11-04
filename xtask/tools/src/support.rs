//! Small helpers the smoke and report tools share.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// The current time as `2026-10-07T12:30:00Z`, the format `date -u` printed.
#[must_use]
pub fn utc_timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    format_utc(secs)
}

/// Format seconds since the Unix epoch as an ISO 8601 UTC timestamp.
#[must_use]
pub fn format_utc(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    // Civil date from a day count (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// `git rev-parse --short HEAD`, or `unknown` when git cannot say.
#[must_use]
pub fn git_short_head(root: &Path) -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(root)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// The last `count` lines of `text`, like `tail -n`.
#[must_use]
pub fn tail_lines(text: &str, count: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(count)..].join("\n")
}

/// The first `count` lines of `text`, like `head -n`.
#[must_use]
pub fn head_lines(text: &str, count: usize) -> String {
    text.lines().take(count).collect::<Vec<_>>().join("\n")
}

/// Create a fresh, empty directory under the system temp directory.
///
/// `create_dir` fails when the name exists, so nobody could have named it in
/// advance; that is the property `mktemp -d` gave.
///
/// # Errors
///
/// If no free name could be created.
pub fn make_temp_dir(prefix: &str) -> Result<PathBuf, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    for attempt in 0..100u32 {
        let candidate =
            std::env::temp_dir().join(format!("{prefix}.{}-{nanos}-{attempt}", std::process::id()));
        if std::fs::create_dir(&candidate).is_ok() {
            return Ok(candidate);
        }
    }
    Err(format!(
        "could not create a temporary directory for {prefix}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_instants() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(format_utc(1_791_373_845), "2026-10-07T11:50:45Z");
        assert_eq!(format_utc(1_709_251_199), "2024-02-29T23:59:59Z");
    }

    #[test]
    fn head_and_tail_cut_lines() {
        let text = "a\nb\nc\nd";
        assert_eq!(head_lines(text, 2), "a\nb");
        assert_eq!(tail_lines(text, 2), "c\nd");
        assert_eq!(tail_lines(text, 99), text);
        assert_eq!(head_lines("", 5), "");
    }

    #[test]
    fn temp_dirs_are_distinct_and_empty() {
        let a = make_temp_dir("budlum-support-test").expect("dir");
        let b = make_temp_dir("budlum-support-test").expect("dir");
        assert_ne!(a, b);
        assert_eq!(std::fs::read_dir(&a).expect("readable").count(), 0);
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }
}
