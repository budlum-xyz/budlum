//! Structured log parsing: dependency-free line parsing of operator logs, both
//! Nginx access logs and syslog.
//!
//! WIRING: unwired. `main.rs` declares this module with `mod logparse;` but no
//! command calls it, and since `agent-ops` is a binary crate it cannot be
//! called from outside either. It has 238 lines and 5 tests, and the tests
//! pass. The situation had gone unseen because the tree was never compiled in
//! CI. The module was not deleted: wiring it to a `logs` command is a separate
//! decision. Until it is wired, `dead_code` is silenced, or the build would
//! stop under `-D warnings`.
//!
//! Scope: the Nginx access line, syslog PRI decoding into facility and
//! severity, and severity inference from common event keywords. No regex or
//! chrono dependency is added; the parsing is manual, bounded and
//! deterministic.

// Required by the WIRING note above: dead code warnings must not stop the build
// until the module is wired. This line is removed once it is.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// A line of an Nginx access log, in the combined format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NginxAccessLine {
    pub remote_addr: String,
    pub timestamp: String,
    pub request: String,
    pub status: u16,
    pub bytes: u64,
}

/// Parses an Nginx access line.
///
/// An example of the combined format:
/// `127.0.0.1 - - [14/Nov/2025:20:01:23 +0300] "GET /index.html HTTP/1.1" 200 1024`
///
/// # Errors
///
/// If the format is not the expected shape: the address, the brackets, the
/// quotes, the status or the byte count.
pub fn parse_nginx_line(line: &str) -> Result<NginxAccessLine, String> {
    // 1) The remote address, up to the first space.
    let (remote_addr, rest) = line
        .split_once(' ')
        .ok_or_else(|| "no remote address".to_string())?;

    // 2) The timestamp, between the first '[' and ']'.
    let open = rest
        .find('[')
        .ok_or_else(|| "no time bracket".to_string())?;
    let close_rel = rest[open + 1..]
        .find(']')
        .ok_or_else(|| "the time bracket does not close".to_string())?;
    let close = open + 1 + close_rel;
    let timestamp = rest[open + 1..close].to_string();
    let after_ts = &rest[close + 1..];

    // 3) The request, inside quotes.
    let q1 = after_ts
        .find('"')
        .ok_or_else(|| "no request quote".to_string())?;
    let q2_rel = after_ts[q1 + 1..]
        .find('"')
        .ok_or_else(|| "the request quote does not close".to_string())?;
    let q2 = q1 + 1 + q2_rel;
    let request = after_ts[q1 + 1..q2].to_string();
    let after_req = after_ts[q2 + 1..].trim();

    // 4) The status and the byte count: the last two space-separated numbers.
    let mut parts = after_req.split_whitespace();
    let status = parts
        .next()
        .ok_or_else(|| "no status".to_string())?
        .parse::<u16>()
        .map_err(|e| format!("the status is not a number: {e}"))?;
    let bytes = parts
        .next()
        .ok_or_else(|| "no byte count".to_string())?
        .parse::<u64>()
        .map_err(|e| format!("the byte count is not a number: {e}"))?;

    Ok(NginxAccessLine {
        remote_addr: remote_addr.to_string(),
        timestamp,
        request,
        status,
        bytes,
    })
}

/// The facility, the top 3 bits, and the severity, the low 3 bits, from a
/// syslog PRI value.
#[must_use]
pub fn pri_facility_severity(pri: u8) -> (u8, u8) {
    (pri >> 3, pri & 0x7)
}

/// Inferring the facility from the application name, by the common rules.
#[must_use]
pub fn infer_facility(appname: Option<&str>) -> Option<u8> {
    let a = appname?.to_ascii_lowercase();
    if a.contains("sshd") || a.contains("sudo") || a.contains("pam") || a.contains("login") {
        Some(4) // security/auth
    } else if a.contains("cron") {
        Some(9) // cron
    } else {
        None
    }
}

/// Inferring the severity from the message body, by the common keywords.
#[must_use]
pub fn infer_severity(msg: &str) -> Option<u8> {
    let m = msg.to_ascii_lowercase();
    if m.contains("panic") || m.contains("emerg") {
        Some(0)
    } else if m.contains("alert") {
        Some(1)
    } else if m.contains("crit") {
        Some(2)
    } else if m.contains("fail")
        || m.contains("failed")
        || m.contains("error")
        || m.contains("denied")
    {
        Some(3)
    } else if m.contains("warn") || m.contains("warning") {
        Some(4)
    } else if m.contains("notice") {
        Some(5)
    } else if m.contains("info")
        || m.contains("started")
        || m.contains("finished")
        || m.contains("accepted")
    {
        Some(6)
    } else if m.contains("debug") {
        Some(7)
    } else {
        None
    }
}

/// The name of a severity number.
#[must_use]
pub fn severity_name(severity: u8) -> &'static str {
    match severity {
        0 => "emerg",
        1 => "alert",
        2 => "crit",
        3 => "err",
        4 => "warning",
        5 => "notice",
        6 => "info",
        7 => "debug",
        _ => "unknown",
    }
}

/// A parsed syslog event, a lightweight model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyslogEvent {
    pub facility: Option<u8>,
    pub severity: Option<u8>,
    pub appname: Option<String>,
    pub message: String,
}

/// Parses a syslog line carrying a PRI prefix.
///
/// For example: `<34>Oct 11 22:14:15 mymachine su[123]: 'su root' failed`
///
/// # Errors
///
/// If the PRI prefix is absent or malformed.
pub fn parse_syslog_line(line: &str) -> Result<SyslogEvent, String> {
    let trimmed = line.trim_start();
    if !trimmed.starts_with('<') {
        return Err("no PRI prefix".to_string());
    }
    let close = trimmed
        .find('>')
        .ok_or_else(|| "the PRI does not close".to_string())?;
    let pri: u8 = trimmed[1..close]
        .parse()
        .map_err(|e| format!("the PRI is not a number: {e}"))?;
    let (facility, severity) = pri_facility_severity(pri);
    let body = trimmed[close + 1..].trim();

    // The application name: the first word ending in a colon, which is
    // optional.
    let (appname, message) = match body.split_once(':') {
        Some((app, msg)) if !app.contains(' ') && !app.is_empty() => {
            (Some(app.trim().to_string()), msg.trim().to_string())
        }
        _ => (None, body.to_string()),
    };

    Ok(SyslogEvent {
        facility: Some(facility),
        severity: Some(severity),
        appname,
        message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nginx_combined_line() {
        let line =
            r#"127.0.0.1 - - [14/Nov/2025:20:01:23 +0300] "GET /index.html HTTP/1.1" 200 1024"#;
        let parsed = parse_nginx_line(line).unwrap();
        assert_eq!(parsed.remote_addr, "127.0.0.1");
        assert_eq!(parsed.timestamp, "14/Nov/2025:20:01:23 +0300");
        assert_eq!(parsed.request, "GET /index.html HTTP/1.1");
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.bytes, 1024);
    }

    #[test]
    fn rejects_malformed_nginx() {
        assert!(parse_nginx_line("not a log").is_err());
        assert!(parse_nginx_line(r#"1.2.3.4 - - no-bracket "GET /" 200 5"#).is_err());
    }

    #[test]
    fn pri_decoding_and_inference() {
        assert_eq!(pri_facility_severity(34), (4, 2)); // auth.crit
        assert_eq!(infer_facility(Some("sshd")), Some(4));
        assert_eq!(infer_facility(Some("cron")), Some(9));
        assert_eq!(infer_facility(None), None);
        assert_eq!(infer_severity("connection denied"), Some(3));
        assert_eq!(infer_severity("started ok"), Some(6));
        assert_eq!(infer_severity("panic in kernel"), Some(0));
    }

    #[test]
    fn parses_syslog_pri() {
        let ev =
            parse_syslog_line("<34>Oct 11 22:14:15 mymachine su[123]: 'su root' failed").unwrap();
        assert_eq!(ev.facility, Some(4));
        assert_eq!(ev.severity, Some(2));
        assert!(ev.message.contains("failed"));
    }

    #[test]
    fn syslog_without_pri_rejected() {
        assert!(parse_syslog_line("no pri here").is_err());
    }
}
