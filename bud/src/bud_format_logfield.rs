//! B.U.D. 2.0 - LOG Alan-Tanımlı Şablon Sütunlama (2026-08-16)
//!
//! logsentinel-parser deseni (K88-3) + fikirler.md F21/F53 sentezi: BİLİNEN log
//! formatlarında (nginx access, syslog) satırlar alan bazında ayrıştırılır -
//! ip/status/size gibi alanlar ayrı sütunlara gider. Alan tipleri bilindiği için
//! sayısal alanlar BINARY'ye çevrilir (Parquet mantığı) → genel şablon sütunlamadan
//! çok daha yüksek oran (ölçüm: genel LOG 6.17x; alan-tanımlı + binary 10x+ beklenir).
//!
//! Nginx access log formatı:
//!   $remote_addr - $remote_user [$time_local] "$method $path $proto" $status $body_bytes
//!   ör: 127.0.0.1 - - [14/Nov/2025:20:01:23 +0300] "GET /index.html HTTP/1.1" 200 1024
//!
//! Çıktı: şablon (sabit parçalar + yer tutucular) + sütunlar (alan tipine göre binary
//! veya string). Kayıpsız: satırlar şablondan + sütunlardan BİREBİR yeniden kurulur.
//!
//! Kod: `#![forbid(unsafe_code)]`, deterministik, panik'siz.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const LOGFIELD_MAGIC: [u8; 8] = *b"\xB5LGFD\0\0\0";
pub const LOGFIELD_VERSION: u8 = 1;
pub const MAX_LINES: usize = 10_000_000;

/// Nginx access log alanları (ayrıştırma sırası sabit - determinizm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NginxField {
    RemoteAddr,
    TimeLocal,  // "[14/Nov/2025:20:01:23 +0300]"
    Method,
    Path,
    Proto,
    Status,     // u16 → binary
    BodyBytes,  // u64 → binary
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

/// Nginx access log satırından alanları çıkar (bilinen format - kayıpsız ayrıştırma).
/// Dönüş: (sabit şablon parçaları [7+1], alan değerleri [7]).
/// Şablon parçaları: satırın alanlar ARASI sabit kısımları.
pub fn parse_nginx_line(line: &[u8]) -> Option<(Vec<&[u8]>, Vec<Vec<u8>>)> {
    let s = std::str::from_utf8(line).ok()?;
    // 127.0.0.1 - - [ts] "METHOD path PROTO" status size
    let mut parts: Vec<&str> = Vec::new();
    let mut rest = s;
    // remote_addr: ilk boşluğa kadar
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
    // req içinde method path proto (boşlukla)
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
    // sabit şablon parçaları (alanlar arası): 
    // "" - - "[" "]" "\"" " " "\"" " " "\n"
    let fixed: Vec<&[u8]> = vec![
        b" - - [",
        b"] \"",
        b" ",
        b" ",
        b"\" ",
        b" ",
        b"\n",
    ];
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

/// Alan-tanımlı transform: log satırları → şablon + sütunlar (binary sayılar).
#[derive(Debug, Clone)]
pub struct LogFieldColumnar {
    pub lines: usize,
    pub fixed_template: Vec<u8>,      // sabit parçaların birleşimi (ilk satırdan)
    pub columns: Vec<Vec<Vec<u8>>>,   // 7 sütun; sayısal alanlar binary
}

impl LogFieldColumnar {
    /// Log metnini alan-tanımlı sütunlara ayır (satırlar aynı formatta olmalı).
    pub fn encode(data: &[u8]) -> Option<Self> {
        let mut lines: Vec<Vec<u8>> = Vec::new();
        for line in data.split_inclusive(|&b| b == b'\n') {
            lines.push(line.to_vec());
        }
        if lines.is_empty() || lines.len() > MAX_LINES {
            return None;
        }
        // ilk satırdan şablon çıkar (sabit parçalar)
        let first = parse_nginx_line(&lines[0])?;
        let fixed_template = first.0.concat();
        // `vec![Vec::with_capacity(n); 7]` yalnız İLK vektörü n kapasiteli
        // kurar; kalan altısı onun klonudur ve klon kapasiteyi taşımaz (boş
        // Vec klonu kapasitesiz doğar). Yani ayırma amacı 7 sütunun 6'sında
        // sessizce kayboluyordu. Her sütunu tek tek kurmak amacı gerçekten
        // uygular (clippy::repeat_vec_with_capacity).
        let mut columns: Vec<Vec<Vec<u8>>> =
            (0..7).map(|_| Vec::with_capacity(lines.len())).collect();
        for line in &lines {
            let (_, values) = parse_nginx_line(line)?;
            for (ci, v) in values.iter().enumerate() {
                columns[ci].push(v.clone());
            }
        }
        // sayısal sütunları binary'ye çevir (status u16, size u64) - kayıpsız
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
        Some(LogFieldColumnar { lines: lines.len(), fixed_template, columns: out_cols })
    }

    /// Sütunlardan orijinal satırları yeniden kur (kayıpsızlık kanıtı).
    pub fn decode(&self) -> Option<Vec<u8>> {
        let n = self.columns.first().map(|c| c.len()).unwrap_or(0);
        if n == 0 {
            return None;
        }
        let mut out = Vec::with_capacity(n * 80);
        for r in 0..n {
            // alan değerlerini metne geri çevir
            let remote = str_of(&self.columns[0][r])?;
            let time = str_of(&self.columns[1][r])?;
            let method = str_of(&self.columns[2][r])?;
            let path = str_of(&self.columns[3][r])?;
            let proto = str_of(&self.columns[4][r])?;
            let status = u16::from_le_bytes(self.columns[5][r].as_slice().try_into().ok()?).to_string();
            let size = u64::from_le_bytes(self.columns[6][r].as_slice().try_into().ok()?).to_string();
            // şablondan yeniden kur: "remote - - [time] \"method path proto\" status size\n"
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

/// Deterministik blob: magic + satır sayısı + şablon + sütunlar (len-prefix) + digest.
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
        let mut pos = HDR;
        let fixed_template = read_bytes(bytes, &mut pos)?;
        let mut columns = Vec::with_capacity(7);
        for _ in 0..7 {
            if bytes.len() < pos + 4 {
                return None;
            }
            let n = u32::from_le_bytes(bytes[pos..pos + 4].try_into().ok()?) as usize;
            pos += 4;
            if n > lines {
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
        Some(LogFieldColumnar { lines, fixed_template, columns })
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
        let line = b"127.0.0.1 - - [14/Nov/2025:20:01:23 +0300] \"GET /index.html HTTP/1.1\" 200 1024\n";
        let (fixed, values) = parse_nginx_line(line).expect("nginx satırı ayrışır");
        assert_eq!(fixed.len(), 7);
        assert_eq!(values[0], b"127.0.0.1");
        assert_eq!(values[2], b"GET");
        assert_eq!(values[3], b"/index.html");
        assert_eq!(values[5], b"200");
        assert_eq!(values[6], b"1024");
    }

    #[test]
    fn roundtrip_lossless() {
        // K38: encode → decode = orijinal (kayıpsız)
        let log = sample_log(500);
        let col = LogFieldColumnar::encode(&log).expect("alan-tanımlı encode");
        assert_eq!(col.lines, 500);
        let back = col.decode().expect("decode");
        assert_eq!(back, log, "alan-tanımlı şablon sütunlama kayıpsız");
        // blob roundtrip
        let blob = col.to_blob();
        let col2 = LogFieldColumnar::from_blob(&blob).expect("blob okunur");
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
        // status sütunu (5) 2 bayt, size sütunu (6) 8 bayt - binary
        assert_eq!(col.columns[5][0].len(), 2, "status u16 binary");
        assert_eq!(col.columns[6][0].len(), 8, "size u64 binary");
        // string sütunlar metin
        assert!(col.columns[0][0].len() >= 5, "ip string");
    }

    #[test]
    fn irregular_line_falls_back() {
        // farklı format → None (kayıpsızlık korunur, çağıran ham yola düşer)
        assert!(parse_nginx_line(b"bozuk satir").is_none());
        assert!(LogFieldColumnar::encode(b"bozuk satir\nikinci satir\n").is_none());
        assert!(LogFieldColumnar::encode(b"").is_none());
    }


    #[test]
    fn field_aware_ratio_beats_plain_zstd() {
        // ÖLÇÜM: genel LOG zstd19 6.17x; alan-tanımlı + binary sütunlar + zstd
        // çok daha iyi olmalı (sayısal alanlar 10 haneli string → 2/8 bayt binary)
        let log = sample_log(8000);
        let col = LogFieldColumnar::encode(&log).expect("encode");
        let blob = col.to_blob();
        let comp = zstd::bulk::compress(&blob, 19).expect("zstd");
        let plain = zstd::bulk::compress(&log, 19).expect("plain zstd");
        let field_ratio = log.len() as f64 / comp.len() as f64;
        let plain_ratio = log.len() as f64 / plain.len() as f64;
        assert!(
            field_ratio > plain_ratio * 1.2,
            "alan-tanımlı daha iyi: field {field_ratio:.2}x vs plain {plain_ratio:.2}x"
        );
        // kayıpsızlık: blob -> decode = orijinal
        assert_eq!(col.decode().unwrap(), log);
    }
    #[test]
    fn blob_never_panics() {
        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
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
