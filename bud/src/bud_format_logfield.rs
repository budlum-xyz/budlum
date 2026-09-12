//! B.U.D. 2.0 - Field-Aware Template Columnisation for LOGs (2026-08-16)
//!
//! The logsentinel-parser pattern (K88-3) synthesised with ideas.md F21/F53: in
//! KNOWN log formats (nginx access, syslog) lines are parsed field by field, and
//! fields such as ip/status/size go into separate columns. Because the field
//! types are known, numeric fields are turned into BINARY (the Parquet idea),
//! giving a much higher ratio than generic template columnisation (measured:
//! generic LOG 6.17x; field-aware plus binary is expected at 10x or more).
//!
//! The nginx access log format:
//!   $remote_addr - $remote_user [$time_local] "$method $path $proto" $status $body_bytes
//!   for example: 127.0.0.1 - - [14/Nov/2025:20:01:23 +0300] "GET /index.html HTTP/1.1" 200 1024
//!
//! Output: a template (the fixed pieces plus placeholders) plus columns (binary
//! or string, depending on the field type). Lossless: the lines are rebuilt
//! EXACTLY from the template and the columns.
//!
//! Code: `#![forbid(unsafe_code)]`, deterministic, panic free.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const LOGFIELD_MAGIC: [u8; 8] = *b"\xB5LGFD\0\0\0";
pub const LOGFIELD_VERSION: u8 = 1;
pub const MAX_LINES: usize = 10_000_000;

/// The nginx access log fields (the parse order is fixed - determinism).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NginxField {
    RemoteAddr,
    TimeLocal, // "[14/Nov/2025:20:01:23 +0300]"
    Method,
    Path,
    Proto,
    Status,    // u16 → binary
    BodyBytes, // u64 → binary
}

pub const NGINX_FIELDS: [NginxField; 7] = [
    NginxField::RemoteAddr,
    NginxField::TimeLocal,
    NginxField::Method,
    NginxField::Path,
    NginxField::Proto,
    NginxField::Status,
    NginxField::BodyBytes,
];

/// Extract the fields from an nginx access log line (a known format - lossless
/// parsing). Returns: (the fixed template pieces [7+1], the field values [7]).
/// The template pieces are the fixed parts BETWEEN the fields of the line.
pub fn parse_nginx_line(line: &[u8]) -> Option<(Vec<&[u8]>, Vec<Vec<u8>>)> {
    let s = std::str::from_utf8(line).ok()?;
    // 127.0.0.1 - - [ts] "METHOD path PROTO" status size
    let mut parts: Vec<&str> = Vec::new();
    let mut rest = s;
    // remote_addr: up to the first space
    let sp = rest.find(' ')?;
    let remote = &rest[..sp];
    rest = &rest[sp + 1..];
    // " - - " sabit
    if !rest.starts_with("- - ") {
        return None;
    }
    rest = &rest[4..];
    // [ts]
    if !rest.starts_with('[') {
        return None;
    }
    let rb = rest.find(']')?;
    let time = &rest[1..rb];
    rest = &rest[rb + 1..];
    // "METHOD path proto"
    let q1 = rest.find('"')?;
    rest = &rest[q1 + 1..];
    let q2 = rest.find('"')?;
    let req = &rest[..q2];
    rest = &rest[q2 + 1..];
    // inside req: method path proto (space separated)
    let mut reqparts = req.splitn(3, ' ');
    let method = reqparts.next()?;
    let path = reqparts.next()?;
    let proto = reqparts.next()?;
    // status size
    rest = rest.trim_start();
    let mut tail = rest.split_whitespace();
    let status = tail.next()?;
    let size = tail.next()?;
    parts.push(remote);
    parts.push(time);
    parts.push(method);
    parts.push(path);
    parts.push(proto);
    parts.push(status);
    parts.push(size);
    let _ = parts;
    // Lossless means the rebuild is byte-identical. The reader accepted
    // lines the writer cannot reproduce: a trailing referer or user agent,
    // doubled spaces, a status or size with leading zeros, a missing final
    // newline. Such a line is refused here, so the caller falls back to the
    // raw bytes instead of silently storing a different log.
    let status_num: u16 = status.parse().ok()?;
    let size_num: u64 = size.parse().ok()?;
    let rebuilt =
        format!("{remote} - - [{time}] \"{method} {path} {proto}\" {status_num} {size_num}\n");
    if rebuilt.as_bytes() != line {
        return None;
    }
    // the fixed template pieces (between the fields):
    // "" - - "[" "]" "\"" " " "\"" " " "\n"
    let fixed: Vec<&[u8]> = vec![b" - - [", b"] \"", b" ", b" ", b"\" ", b" ", b"\n"];
    let values: Vec<Vec<u8>> = vec![
        remote.as_bytes().to_vec(),
        time.as_bytes().to_vec(),
        method.as_bytes().to_vec(),
        path.as_bytes().to_vec(),
        proto.as_bytes().to_vec(),
        status.as_bytes().to_vec(),
        size.as_bytes().to_vec(),
    ];
    Some((fixed, values))
}

/// The field-aware transform: log lines -> a template plus columns (numbers in binary).
#[derive(Debug, Clone)]
pub struct LogFieldColumnar {
    pub lines: usize,
    pub fixed_template: Vec<u8>, // the fixed pieces joined together (from the first line)
    pub columns: Vec<Vec<Vec<u8>>>, // 7 columns; the numeric fields are binary
}

impl LogFieldColumnar {
    /// Split log text into field-aware columns (the lines must share one format).
    pub fn encode(data: &[u8]) -> Option<Self> {
        let mut lines: Vec<Vec<u8>> = Vec::new();
        for line in data.split_inclusive(|&b| b == b'\n') {
            lines.push(line.to_vec());
        }
        if lines.is_empty() || lines.len() > MAX_LINES {
            return None;
        }
        // extract the template from the first line (the fixed pieces)
        let first = parse_nginx_line(&lines[0])?;
        let fixed_template = first.0.concat();
        // `vec![Vec::with_capacity(n); 7]` builds only the FIRST vector with a
        // capacity of n; the remaining six are clones of it, and a clone does
        // not carry the capacity (a cloned empty Vec is born without one). So
        // the intent to preallocate silently vanished for 6 of the 7 columns.
        // Building each column one by one makes the intent real
        // (clippy::repeat_vec_with_capacity).
        let mut columns: Vec<Vec<Vec<u8>>> =
            (0..7).map(|_| Vec::with_capacity(lines.len())).collect();
        for line in &lines {
            let (_, values) = parse_nginx_line(line)?;
            for (ci, v) in values.iter().enumerate() {
                columns[ci].push(v.clone());
            }
        }
        // turn the numeric columns into binary (status u16, size u64) - lossless
        let mut out_cols = columns;
        if let Some(col) = out_cols.get_mut(5) {
            for v in col.iter_mut() {
                let n: u16 = std::str::from_utf8(v).ok()?.parse().ok()?;
                *v = n.to_le_bytes().to_vec();
            }
        }
        if let Some(col) = out_cols.get_mut(6) {
            for v in col.iter_mut() {
                let n: u64 = std::str::from_utf8(v).ok()?.parse().ok()?;
                *v = n.to_le_bytes().to_vec();
            }
        }
        Some(LogFieldColumnar {
            lines: lines.len(),
            fixed_template,
            columns: out_cols,
        })
    }

    /// Rebuild the original lines from the columns (the losslessness proof).
    pub fn decode(&self) -> Option<Vec<u8>> {
        let n = self.columns.first().map(|c| c.len()).unwrap_or(0);
        if n == 0 {
            return None;
        }
        let mut out = Vec::with_capacity(n * 80);
        for r in 0..n {
            // turn the field values back into text
            let remote = str_of(&self.columns[0][r])?;
            let time = str_of(&self.columns[1][r])?;
            let method = str_of(&self.columns[2][r])?;
            let path = str_of(&self.columns[3][r])?;
            let proto = str_of(&self.columns[4][r])?;
            let status =
                u16::from_le_bytes(self.columns[5][r].as_slice().try_into().ok()?).to_string();
            let size =
                u64::from_le_bytes(self.columns[6][r].as_slice().try_into().ok()?).to_string();
            // rebuild from the template: "remote - - [time] \"method path proto\" status size\n"
            out.extend_from_slice(remote.as_bytes());
            out.extend_from_slice(b" - - [");
            out.extend_from_slice(time.as_bytes());
            out.extend_from_slice(b"] \"");
            out.extend_from_slice(method.as_bytes());
            out.extend_from_slice(b" ");
            out.extend_from_slice(path.as_bytes());
            out.extend_from_slice(b" ");
            out.extend_from_slice(proto.as_bytes());
            out.extend_from_slice(b"\" ");
            out.extend_from_slice(status.as_bytes());
            out.extend_from_slice(b" ");
            out.extend_from_slice(size.as_bytes());
            out.extend_from_slice(b"\n");
        }
        Some(out)
    }
}

fn str_of(v: &[u8]) -> Option<String> {
    Some(std::str::from_utf8(v).ok()?.to_string())
}

/// A deterministic blob: magic + line count + template + columns (len-prefixed) + digest.
impl LogFieldColumnar {
    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&LOGFIELD_MAGIC);
        out.push(LOGFIELD_VERSION);
        out.extend_from_slice(&(self.lines as u32).to_le_bytes());
        push_bytes(&mut out, &self.fixed_template);
        for col in &self.columns {
            out.extend_from_slice(&(col.len() as u32).to_le_bytes());
            for v in col {
                push_bytes(&mut out, v);
            }
        }
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_LOGFIELD_V1");
        h.update(&out);
        let d: [u8; 32] = h.finalize().into();
        out.extend_from_slice(&d);
        out
    }

    pub fn from_blob(bytes: &[u8]) -> Option<Self> {
        const HDR: usize = 8 + 1 + 4;
        if bytes.len() < HDR + 32 || bytes[0..8] != LOGFIELD_MAGIC || bytes[8] != LOGFIELD_VERSION {
            return None;
        }
        let payload_len = bytes.len() - 32;
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_LOGFIELD_V1");
        h.update(&bytes[..payload_len]);
        let d: [u8; 32] = h.finalize().into();
        if d != bytes[payload_len..] {
            return None;
        }
        let lines = u32::from_le_bytes(bytes[9..13].try_into().ok()?) as usize;
        // The header count is bound the same way `encode` bounds its input:
        // no empty container, nothing above `MAX_LINES`. `decode` indexes
        // every column by the first column's length, so each column below
        // has to hold exactly `lines` entries or a short one panics there.
        if lines == 0 || lines > MAX_LINES {
            return None;
        }
        let mut pos = HDR;
        let fixed_template = read_bytes(bytes, &mut pos)?;
        let mut columns = Vec::with_capacity(7);
        for _ in 0..7 {
            if bytes.len() < pos + 4 {
                return None;
            }
            let n = u32::from_le_bytes(bytes[pos..pos + 4].try_into().ok()?) as usize;
            pos += 4;
            // Every entry carries at least its 4-byte length prefix, so the
            // bytes left bound the count. A count that the input cannot hold
            // is refused before it is allocated: `Vec::with_capacity` from a
            // header-supplied number is an allocation bomb, and under
            // `panic = "abort"` an allocation failure takes the process down.
            if n != lines || n > payload_len.saturating_sub(pos) / 4 {
                return None;
            }
            let mut col = Vec::with_capacity(n);
            for _ in 0..n {
                let v = read_bytes(bytes, &mut pos)?;
                col.push(v);
            }
            columns.push(col);
        }
        if pos != payload_len {
            return None;
        }
        Some(LogFieldColumnar {
            lines,
            fixed_template,
            columns,
        })
    }
}

fn push_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

fn read_bytes(bytes: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    if bytes.len() < *pos + 4 {
        return None;
    }
    let len = u32::from_le_bytes(bytes[*pos..*pos + 4].try_into().ok()?) as usize;
    *pos += 4;
    if bytes.len() < *pos + len {
        return None;
    }
    let v = bytes[*pos..*pos + len].to_vec();
    *pos += len;
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_log(n: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for i in 0..n {
            let ip = format!("10.0.{}.{}", i % 4, i % 255);
            let method = ["GET", "POST", "PUT"][i % 3];
            let path = ["/api/a", "/api/b", "/index.html"][i % 3];
            let status = [200, 200, 404, 500][i % 4];
            let size = i * 137 % 100000;
            out.extend_from_slice(
                format!("{ip} - - [14/Nov/2025:20:01:23 +0300] \"{method} {path} HTTP/1.1\" {status} {size}\n")
                    .as_bytes(),
            );
        }
        out
    }

    #[test]
    fn parse_nginx_line_works() {
        let line =
            b"127.0.0.1 - - [14/Nov/2025:20:01:23 +0300] \"GET /index.html HTTP/1.1\" 200 1024\n";
        let (fixed, values) = parse_nginx_line(line).expect("the nginx line parses");
        assert_eq!(fixed.len(), 7);
        assert_eq!(values[0], b"127.0.0.1");
        assert_eq!(values[2], b"GET");
        assert_eq!(values[3], b"/index.html");
        assert_eq!(values[5], b"200");
        assert_eq!(values[6], b"1024");
    }

    /// A blob whose header claims a column count the body cannot hold used
    /// to reach `Vec::with_capacity(n)` before any body byte was read; with
    /// `lines` set to match, a few dozen bytes asked for gigabytes. The digest
    /// is recomputed so only the count check can be what refuses it.
    #[test]
    fn a_column_count_the_body_cannot_hold_is_refused_before_allocation() {
        let claimed = (MAX_LINES / 2) as u32;
        let mut out = Vec::new();
        out.extend_from_slice(&LOGFIELD_MAGIC);
        out.push(LOGFIELD_VERSION);
        out.extend_from_slice(&claimed.to_le_bytes()); // lines, within MAX_LINES
        push_bytes(&mut out, b"tpl");
        out.extend_from_slice(&claimed.to_le_bytes()); // first column count
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_LOGFIELD_V1");
        h.update(&out);
        let d: [u8; 32] = h.finalize().into();
        out.extend_from_slice(&d);
        assert!(LogFieldColumnar::from_blob(&out).is_none());
    }

    /// A header line count outside what `encode` can produce (zero or above
    /// `MAX_LINES`) is refused, and so is a blob whose columns do not all
    /// hold exactly that many entries: `decode` walks every column by the
    /// first column's length, so a shorter column used to panic there.
    #[test]
    fn column_lengths_must_match_the_header_line_count() {
        let seal = |mut out: Vec<u8>| {
            let mut h = Sha3_256::new();
            h.update(b"BDLM_BUD_LOGFIELD_V1");
            h.update(&out);
            let d: [u8; 32] = h.finalize().into();
            out.extend_from_slice(&d);
            out
        };
        let header = |lines: u32| {
            let mut out = Vec::new();
            out.extend_from_slice(&LOGFIELD_MAGIC);
            out.push(LOGFIELD_VERSION);
            out.extend_from_slice(&lines.to_le_bytes());
            push_bytes(&mut out, b"tpl");
            out
        };
        for lines in [0u32, (MAX_LINES + 1) as u32, u32::MAX] {
            let mut out = header(lines);
            for _ in 0..7 {
                out.extend_from_slice(&0u32.to_le_bytes());
            }
            assert!(
                LogFieldColumnar::from_blob(&seal(out)).is_none(),
                "lines={lines} must be refused"
            );
        }
        // Two lines claimed; column 5 carries a single entry.
        let mut out = header(2);
        for ci in 0..7 {
            let n: u32 = if ci == 5 { 1 } else { 2 };
            out.extend_from_slice(&n.to_le_bytes());
            for _ in 0..n {
                push_bytes(&mut out, b"x");
            }
        }
        assert!(LogFieldColumnar::from_blob(&seal(out)).is_none());
        // The same layout with every column at two entries parses.
        let mut out = header(2);
        for _ in 0..7 {
            out.extend_from_slice(&2u32.to_le_bytes());
            push_bytes(&mut out, b"x");
            push_bytes(&mut out, b"x");
        }
        let parsed = LogFieldColumnar::from_blob(&seal(out)).expect("well formed blob");
        assert_eq!(parsed.lines, 2);
        assert!(parsed.columns.iter().all(|c| c.len() == 2));
    }

    #[test]
    fn roundtrip_lossless() {
        // K38: encode -> decode = the original (lossless)
        let log = sample_log(500);
        let col = LogFieldColumnar::encode(&log).expect("field-aware encode");
        assert_eq!(col.lines, 500);
        let back = col.decode().expect("decode");
        assert_eq!(back, log, "field-aware template columnisation is lossless");
        // blob roundtrip
        let blob = col.to_blob();
        let col2 = LogFieldColumnar::from_blob(&blob).expect("the blob reads back");
        assert_eq!(col2.decode().unwrap(), log);
        // kurcalama red
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(LogFieldColumnar::from_blob(&bad).is_none());
    }

    #[test]
    fn numeric_columns_are_binary() {
        let log = sample_log(50);
        let col = LogFieldColumnar::encode(&log).unwrap();
        // the status column (5) is 2 bytes, the size column (6) is 8 bytes - binary
        assert_eq!(col.columns[5][0].len(), 2, "status u16 binary");
        assert_eq!(col.columns[6][0].len(), 8, "size u64 binary");
        // the string columns stay as text
        assert!(col.columns[0][0].len() >= 5, "ip string");
    }

    #[test]
    fn irregular_line_falls_back() {
        // a different format -> None (losslessness is preserved, the caller falls back to raw)
        assert!(parse_nginx_line(b"broken line").is_none());
        assert!(LogFieldColumnar::encode(b"broken line\nsecond line\n").is_none());
        assert!(LogFieldColumnar::encode(b"").is_none());
    }

    /// Lines the old parser accepted and the writer rebuilt differently.
    /// Each is refused now, so no log is stored as a different log.
    #[test]
    fn a_line_the_rebuild_cannot_reproduce_is_refused() {
        let good = b"10.0.0.1 - - [01/Jan/2026:00:00:00 +0000] \"GET /a HTTP/1.1\" 200 512\n";
        assert!(parse_nginx_line(good).is_some());
        let lossy: [&[u8]; 4] = [
            // combined format: referer and user agent after the size
            b"10.0.0.1 - - [01/Jan/2026:00:00:00 +0000] \"GET /a HTTP/1.1\" 200 512 \"-\" \"curl\"\n",
            // doubled space before the status
            b"10.0.0.1 - - [01/Jan/2026:00:00:00 +0000] \"GET /a HTTP/1.1\"  200 512\n",
            // leading zero in the size
            b"10.0.0.1 - - [01/Jan/2026:00:00:00 +0000] \"GET /a HTTP/1.1\" 200 0512\n",
            // no final newline
            b"10.0.0.1 - - [01/Jan/2026:00:00:00 +0000] \"GET /a HTTP/1.1\" 200 512",
        ];
        for line in lossy {
            assert!(
                parse_nginx_line(line).is_none(),
                "refused: {}",
                String::from_utf8_lossy(line)
            );
        }
        let mut text = good.to_vec();
        text.extend_from_slice(lossy[0]);
        assert!(LogFieldColumnar::encode(&text).is_none());
    }

    #[test]
    fn field_aware_ratio_beats_plain_zstd() {
        // MEASUREMENT: generic LOG zstd19 gives 6.17x; field-aware plus binary
        // columns plus zstd must do much better (a numeric field goes from a 10
        // digit string to 2 or 8 binary bytes)
        let log = sample_log(8000);
        let col = LogFieldColumnar::encode(&log).expect("encode");
        let blob = col.to_blob();
        let comp = zstd::bulk::compress(&blob, 19).expect("zstd");
        let plain = zstd::bulk::compress(&log, 19).expect("plain zstd");
        let field_ratio = log.len() as f64 / comp.len() as f64;
        let plain_ratio = log.len() as f64 / plain.len() as f64;
        assert!(
            field_ratio > plain_ratio * 1.2,
            "field-aware is better: field {field_ratio:.2}x vs plain {plain_ratio:.2}x"
        );
        // losslessness: blob -> decode = the original
        assert_eq!(col.decode().unwrap(), log);
    }
    #[test]
    fn blob_never_panics() {
        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                self.0 = x;
                x.wrapping_mul(0x2545_F491_4F6C_DD1D)
            }
            fn byte(&mut self) -> u8 {
                (self.next() & 0xff) as u8
            }
        }
        let mut rng = Rng(0x4C47_4644_2026_0816);
        let mut buf = [0u8; 128];
        for _ in 0..2000 {
            let len = (rng.next() % 128) as usize;
            for b in &mut buf[..len] {
                *b = rng.byte();
            }
            let _ = LogFieldColumnar::from_blob(&buf[..len]);
        }
    }
}
