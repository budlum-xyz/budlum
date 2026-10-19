//! A minimal HTTP/1.1 client for the local node.
//!
//! It replaces the `curl` calls of the smoke scripts. It speaks plain `http`
//! to `127.0.0.1` only: the port is the sole address input, so a typo cannot
//! point it at a remote host, and there is no TLS to get wrong. A reply is
//! read until the server closes the connection (`Connection: close`), and
//! `Content-Length` and chunked bodies are both understood.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use crate::json;

/// What came back from the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    pub body: String,
}

impl Reply {
    /// `curl -f` semantics: any status below 400 counts as success.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.status < 400
    }

    /// A 2xx status.
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Send one request to `127.0.0.1:port` and read the whole reply.
///
/// # Errors
///
/// If the connection, the write or the read fails, the deadline passes, or the
/// reply is not HTTP.
pub fn request(
    method: &str,
    port: u16,
    path: &str,
    json_body: Option<&str>,
    max_time: Duration,
) -> Result<Reply, String> {
    let deadline = Instant::now() + max_time;
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&addr, max_time)
        .map_err(|e| format!("connect to {addr} failed: {e}"))?;
    let message = build_request(method, port, path, json_body);
    stream
        .set_write_timeout(Some(max_time))
        .map_err(|e| format!("socket setup failed: {e}"))?;
    stream
        .write_all(message.as_bytes())
        .map_err(|e| format!("write to {addr} failed: {e}"))?;

    let mut raw: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(format!("{addr} did not finish the reply in time"));
        }
        stream
            .set_read_timeout(Some(left))
            .map_err(|e| format!("socket setup failed: {e}"))?;
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(e) => return Err(format!("read from {addr} failed: {e}")),
        }
    }
    parse_reply(&raw)
}

/// POST one JSON-RPC call and return the reply body.
///
/// # Errors
///
/// If the request fails or the status is 400 or above.
pub fn call(port: u16, method: &str, params: &str, max_time: Duration) -> Result<String, String> {
    let body = format!(r#"{{"jsonrpc":"2.0","method":"{method}","params":{params},"id":1}}"#);
    let reply = request("POST", port, "/", Some(&body), max_time)?;
    if reply.is_ok() {
        Ok(reply.body)
    } else {
        Err(format!("{method} answered HTTP {}", reply.status))
    }
}

/// The `result` member of a JSON-RPC reply, when it is a string.
#[must_use]
pub fn result_string(body: &str) -> Option<String> {
    json::parse(body)
        .ok()?
        .get("result")
        .and_then(json::Value::as_str)
        .map(str::to_string)
}

/// Read a `0x` quantity such as `0x3b`. Anything else is `None`.
#[must_use]
pub fn parse_hex_quantity(text: &str) -> Option<u64> {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))?;
    u64::from_str_radix(digits, 16).ok()
}

fn build_request(method: &str, port: u16, path: &str, json_body: Option<&str>) -> String {
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nAccept: */*\r\n");
    match json_body {
        Some(body) => {
            let _ = write!(
                head,
                "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
        }
        None => head.push_str("\r\n"),
    }
    head
}

fn parse_reply(raw: &[u8]) -> Result<Reply, String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "the reply has no header end".to_string())?;
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let body_raw = &raw[split + 4..];
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.split_whitespace();
    if !parts.next().is_some_and(|v| v.starts_with("HTTP/1.")) {
        return Err(format!("not an HTTP reply: {status_line:?}"));
    }
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("no status code in {status_line:?}"))?;
    let chunked = lines.any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });
    let bytes = if chunked {
        dechunk(body_raw)?
    } else {
        body_raw.to_vec()
    };
    Ok(Reply {
        status,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    })
}

fn dechunk(mut rest: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let eol = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "a chunk header was cut off".to_string())?;
        let size_text = String::from_utf8_lossy(&rest[..eol]).into_owned();
        let size_hex = size_text.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| format!("bad chunk size {size_hex:?}"))?;
        rest = &rest[eol + 2..];
        if size == 0 {
            return Ok(out);
        }
        if rest.len() < size {
            return Err("a chunk was cut off".to_string());
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size..];
        rest = rest.strip_prefix(b"\r\n").unwrap_or(rest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_plain_reply() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        let r = parse_reply(raw).expect("valid");
        assert_eq!(r.status, 200);
        assert_eq!(r.body, "{}");
        assert!(r.is_ok() && r.is_success());
    }

    #[test]
    fn parses_a_chunked_reply() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;x=1\r\n world\r\n0\r\n\r\n";
        assert_eq!(parse_reply(raw).expect("valid").body, "hello world");
    }

    #[test]
    fn an_error_status_is_not_ok() {
        let raw = b"HTTP/1.1 401 Unauthorized\r\n\r\nno";
        let r = parse_reply(raw).expect("valid");
        assert!(!r.is_ok() && !r.is_success());
    }

    #[test]
    fn a_redirect_is_ok_for_curl_f_but_not_a_success() {
        let raw = b"HTTP/1.1 302 Found\r\n\r\n";
        let r = parse_reply(raw).expect("valid");
        assert!(r.is_ok() && !r.is_success());
    }

    #[test]
    fn rejects_garbage_and_cut_off_chunks() {
        assert!(parse_reply(b"hello").is_err());
        assert!(parse_reply(b"SSH-2.0 x\r\n\r\n").is_err());
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\nshort";
        assert!(parse_reply(raw).is_err());
    }

    #[test]
    fn builds_a_post_with_a_length() {
        let m = build_request("POST", 8545, "/", Some("{}"));
        assert!(m.starts_with("POST / HTTP/1.1\r\n"));
        assert!(m.contains("Content-Length: 2\r\n\r\n{}"));
        assert!(m.contains("Host: 127.0.0.1:8545"));
    }

    #[test]
    fn reads_hex_quantities_and_results() {
        assert_eq!(parse_hex_quantity("0x3"), Some(3));
        assert_eq!(parse_hex_quantity("0xb0ce"), Some(0xb0ce));
        assert_eq!(parse_hex_quantity("3"), None);
        assert_eq!(parse_hex_quantity("0xzz"), None);
        assert_eq!(
            result_string(r#"{"jsonrpc":"2.0","result":"0xb0ce","id":1}"#).as_deref(),
            Some("0xb0ce")
        );
        assert_eq!(result_string(r#"{"result":true}"#), None);
        assert_eq!(result_string("not json"), None);
    }

    #[test]
    fn a_closed_port_is_an_error() {
        // Port 1 is reserved and nothing listens there in a test run.
        assert!(request("GET", 1, "/", None, Duration::from_millis(500)).is_err());
    }
}
