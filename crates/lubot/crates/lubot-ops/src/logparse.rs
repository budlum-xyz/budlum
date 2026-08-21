//! Yapılandırılmış log ayrıştırma - operatör loglarının (Nginx erişim,
//! Syslog) bağımlılıksız satır ayrıştırması.
//!
//! Kapsam: Nginx erişim satırı, Syslog PRI çözümü (facility/severity) ve
//! yaygın olay anahtar sözcüklerinden severity çıkarımı. Regex ve chrono
//! bağımlılığı eklenmez; ayrıştırma elle, sınırlı ve deterministiktir.

use serde::{Deserialize, Serialize};

/// Nginx erişim logu satırı (birleşik biçim).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NginxAccessLine {
    pub remote_addr: String,
    pub timestamp: String,
    pub request: String,
    pub status: u16,
    pub bytes: u64,
}

/// Nginx erişim satırını ayrıştırır.
///
/// Birleşik biçim örneği:
/// `127.0.0.1 - - [14/Nov/2025:20:01:23 +0300] "GET /index.html HTTP/1.1" 200 1024`
///
/// # Errors
///
/// Biçim beklenen yapıda değilse (ip, parantez, tırnak, durum, bayt).
pub fn parse_nginx_line(line: &str) -> Result<NginxAccessLine, String> {
    // 1) uzak adres: ilk boşluğa kadar.
    let (remote_addr, rest) = line
        .split_once(' ')
        .ok_or_else(|| "uzak adres yok".to_string())?;

    // 2) zaman damgası: ilk '[' ile ']' arası.
    let open = rest
        .find('[')
        .ok_or_else(|| "zaman parantezi yok".to_string())?;
    let close_rel = rest[open + 1..]
        .find(']')
        .ok_or_else(|| "zaman parantezi kapanmıyor".to_string())?;
    let close = open + 1 + close_rel;
    let timestamp = rest[open + 1..close].to_string();
    let after_ts = &rest[close + 1..];

    // 3) istek: tırnak içinde.
    let q1 = after_ts
        .find('"')
        .ok_or_else(|| "istek tirnagi yok".to_string())?;
    let q2_rel = after_ts[q1 + 1..]
        .find('"')
        .ok_or_else(|| "istek tirnagi kapanmiyor".to_string())?;
    let q2 = q1 + 1 + q2_rel;
    let request = after_ts[q1 + 1..q2].to_string();
    let after_req = after_ts[q2 + 1..].trim();

    // 4) durum + bayt: son iki boşlukla ayrılmış sayı.
    let mut parts = after_req.split_whitespace();
    let status = parts
        .next()
        .ok_or_else(|| "durum yok".to_string())?
        .parse::<u16>()
        .map_err(|e| format!("durum sayı değil: {e}"))?;
    let bytes = parts
        .next()
        .ok_or_else(|| "bayt yok".to_string())?
        .parse::<u64>()
        .map_err(|e| format!("bayt sayı değil: {e}"))?;

    Ok(NginxAccessLine {
        remote_addr: remote_addr.to_string(),
        timestamp,
        request,
        status,
        bytes,
    })
}

/// Syslog PRI değerinden facility (üst 3 bit) ve severity (alt 3 bit).
#[must_use]
pub fn pri_facility_severity(pri: u8) -> (u8, u8) {
    (pri >> 3, pri & 0x7)
}

/// Uygulama adından facility tahmini (ortak kurallar).
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

/// İleti içeriğinden severity tahmini (ortak anahtar sözcükler).
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

/// Severity numarasının adı.
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

/// Ayrıştırılmış Syslog olayı (hafif model).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyslogEvent {
    pub facility: Option<u8>,
    pub severity: Option<u8>,
    pub appname: Option<String>,
    pub message: String,
}

/// Syslog satırını (PRI önekli) ayrıştırır.
///
/// Örnek: `<34>Oct 11 22:14:15 mymachine su[123]: 'su root' failed`
///
/// # Errors
///
/// PRI öneki yoksa veya bozuksa.
pub fn parse_syslog_line(line: &str) -> Result<SyslogEvent, String> {
    let trimmed = line.trim_start();
    if !trimmed.starts_with('<') {
        return Err("PRI öneki yok".to_string());
    }
    let close = trimmed
        .find('>')
        .ok_or_else(|| "PRI kapanmıyor".to_string())?;
    let pri: u8 = trimmed[1..close]
        .parse()
        .map_err(|e| format!("PRI sayı değil: {e}"))?;
    let (facility, severity) = pri_facility_severity(pri);
    let body = trimmed[close + 1..].trim();

    // Uygulama adı: iki nokta üst üste ile biten ilk sözcük (opsiyonel).
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
