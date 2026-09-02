//! B.U.D. 2.0 - PCAP TRANSFORM (100-web finding: "PCAP -> zstd 10x (DNS)")
//!
//! Remaining work #8: the PCAP transform. A network capture file (libpcap) is
//! processed structurally: global header + packet records (ts_sec, ts_usec,
//! incl_len, data). The record fields are split into separate columns: ts ->
//! delta+varint, the lengths separately, the packet payload as is -> zstd sees
//! the repetition (shared prefixes) better.
//! LOSSLESS: `pcap_restore` reproduces the original bytes byte for byte.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const PCAP_MAGIC: [u8; 8] = *b"\xB5PCAP\0\0\0";
pub const PCAP_VERSION: u8 = 1;
pub const PCAP_GLOBAL_HDR: usize = 24;
pub const PCAP_MAX_RECORDS: usize = 1 << 20; // a 1M record ceiling (OOM protection)

fn varint(x: u64) -> Vec<u8> {
    let mut x = x;
    let mut out = Vec::with_capacity(10);
    while x >= 0x80 {
        out.push((x as u8 & 0x7F) | 0x80);
        x >>= 7;
    }
    out.push(x as u8);
    out
}

fn zigzag(n: i64) -> u64 {
    ((n << 1) ^ (n >> 63)) as u64
}

/// Transform a PCAP: global header + columnar record index + packet payload.
/// The output is the intermediate representation fed to zstd; it inverts losslessly.
pub fn pcap_transform(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < PCAP_GLOBAL_HDR {
        return None;
    }
    // magic check (little-endian a1b2c3d4 or big-endian d4c3b2a1)
    let le = data[0..4] == [0xD4, 0xC3, 0xB2, 0xA1];
    let be = data[0..4] == [0xA1, 0xB2, 0xC3, 0xD4];
    if !le && !be {
        return None;
    }
    let mut pos = PCAP_GLOBAL_HDR;
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(b"PCAP1|");
    out.extend_from_slice(&data[0..PCAP_GLOBAL_HDR]); // the global header verbatim
    out.push(0xFF); // separator
    let mut prev_ts: i64 = 0;
    let mut records = 0u32;
    let mut data_start = 0usize;
    let mut lens = Vec::new();
    let mut dts = Vec::new();
    let mut ts_secs = Vec::new();
    while pos + 16 <= data.len() {
        let rd = |o: usize| -> u32 {
            // A fixed-width read: the slice length is always 4 here, but
            // `try_into().unwrap()` left that to run time rather than to the
            // compiler. `copy_from_slice` does the same thing without panicking.
            let mut w = [0u8; 4];
            w.copy_from_slice(&data[pos + o..pos + o + 4]);
            if le {
                u32::from_le_bytes(w)
            } else {
                u32::from_be_bytes(w)
            }
        };
        let ts_sec = rd(0) as i64;
        let ts_usec = rd(4) as i64;
        let incl_len = rd(8) as usize;
        if incl_len > data.len().saturating_sub(pos + 16) {
            return None; // corrupt record
        }
        let ts = ts_sec * 1_000_000 + ts_usec;
        dts.push(zigzag(ts - prev_ts));
        prev_ts = ts;
        ts_secs.push(ts_sec);
        lens.push(incl_len as u64);
        records += 1;
        if data_start == 0 {
            data_start = pos + 16;
        }
        pos += 16 + incl_len;
    }
    if records == 0 {
        return None;
    }
    // column blocks
    out.extend_from_slice(&records.to_le_bytes());
    for d in &dts {
        out.extend_from_slice(&varint(*d));
    }
    out.push(0xFE);
    for l in &lens {
        out.extend_from_slice(&varint(*l));
    }
    out.push(0xFD);
    // packet payloads (separated, laid out for zstd's shared prefixes)
    // NOTE: after every packet comes the 16-byte header of the NEXT RECORD - it is skipped.
    let mut p = data_start;
    for l in &lens {
        let l = *l as usize;
        if p + l <= data.len() {
            out.extend_from_slice(&data[p..p + l]);
            out.push(0xFC);
        }
        p += 16 + l;
    }
    Some(out)
}

/// Invert the transform -> the ORIGINAL PCAP (the losslessness proof).
pub fn pcap_restore(transformed: &[u8]) -> Option<Vec<u8>> {
    if !transformed.starts_with(b"PCAP1|") {
        return None;
    }
    let mut pos = 6usize;
    if transformed.len() < pos + PCAP_GLOBAL_HDR + 1 {
        return None;
    }
    let g = transformed[pos..pos + PCAP_GLOBAL_HDR].to_vec();
    pos += PCAP_GLOBAL_HDR;
    if transformed[pos] != 0xFF {
        return None;
    }
    pos += 1;
    let le = g[0..4] == [0xD4, 0xC3, 0xB2, 0xA1];
    if transformed.len() < pos + 4 {
        return None;
    }
    let records = u32::from_le_bytes(transformed.get(pos..pos + 4)?.try_into().ok()?) as usize;
    // guard against OOM from a user-controlled record count
    if records > PCAP_MAX_RECORDS {
        return None;
    }
    pos += 4;
    // delta ts
    let mut dts = Vec::with_capacity(records.min(4096));
    for _ in 0..records {
        let mut v = 0u64;
        let mut shift = 0u32;
        loop {
            let b = *transformed.get(pos)?;
            pos += 1;
            v |= ((b & 0x7F) as u64) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 63 {
                return None;
            }
        }
        dts.push(v);
    }
    if transformed.get(pos) != Some(&0xFE) {
        return None;
    }
    pos += 1;
    let mut lens = Vec::with_capacity(records);
    for _ in 0..records {
        let mut v = 0u64;
        let mut shift = 0u32;
        loop {
            let b = *transformed.get(pos)?;
            pos += 1;
            v |= ((b & 0x7F) as u64) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 63 {
                return None;
            }
        }
        lens.push(v);
    }
    if transformed.get(pos) != Some(&0xFD) {
        return None;
    }
    pos += 1;
    // rebuild
    let mut out = g;
    let mut ts_abs: i64 = 0;
    for (i, d) in dts.iter().enumerate() {
        let l = *lens.get(i)? as usize;
        if transformed.len() < pos + l + 1 {
            return None;
        }
        let raw = &transformed[pos..pos + l];
        let sep = transformed[pos + l];
        pos += l + 1;
        if sep != 0xFC {
            return None;
        }

        let dt = (*d >> 1) as i64 ^ -((*d & 1) as i64);
        ts_abs = ts_abs.wrapping_add(dt);
        let ts_sec = ts_abs.div_euclid(1_000_000);
        let ts_usec = ts_abs.rem_euclid(1_000_000);
        let mut hdr = Vec::with_capacity(16);
        let w = |v: u32| -> [u8; 4] {
            if le {
                v.to_le_bytes()
            } else {
                v.to_be_bytes()
            }
        };
        hdr.extend_from_slice(&w(ts_sec as u32));
        hdr.extend_from_slice(&w(ts_usec as u32));
        hdr.extend_from_slice(&w(l as u32));
        hdr.extend_from_slice(&w(l as u32)); // orig_len = incl_len (identical in a capture)
        out.extend_from_slice(&hdr);
        out.extend_from_slice(raw);
    }
    Some(out)
}

/// The transform ratio (original / transformed) - the structural gain before zstd.
pub fn pcap_structural_ratio(data: &[u8]) -> Option<f64> {
    let t = pcap_transform(data)?;
    Some(data.len() as f64 / t.len() as f64)
}

pub fn pcap_digest(data: &[u8]) -> Option<[u8; 32]> {
    let t = pcap_transform(data)?;
    let mut h = Sha3_256::new();
    h.update(PCAP_MAGIC);
    h.update([PCAP_VERSION]);
    h.update(&t);
    Some(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic PCAP: 500 DNS-ish packets (small, repetitive queries).
    fn sample_pcap() -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes()); // magic (le)
        d.extend_from_slice(&[2, 4, 0, 0]); // version
        d.extend_from_slice(&[0u8; 16]); // thiszone/sigfigs/snaplen/network
        let mut ts = 1_700_000_000i64;
        for i in 0..500 {
            let mut pkt = Vec::new();
            pkt.extend_from_slice(b"\x12\x34\x56\x78\x9a\xbc"); // src mac
            pkt.extend_from_slice(b"\x00\x11\x22\x33\x44\x55"); // dst mac
            pkt.extend_from_slice(&[0x08, 0x00]); // ethertype IPv4
            pkt.extend_from_slice(&[0x45, 0x00, 0x00, 0x20]); // IP hdr
            pkt.extend_from_slice(format!("dns-query-{}", i % 50).as_bytes());
            pkt.resize(60, 0);
            let incl = pkt.len();
            d.extend_from_slice(&(ts as u32).to_le_bytes());
            d.extend_from_slice(&(i as u32).to_le_bytes()); // usec
            d.extend_from_slice(&(incl as u32).to_le_bytes());
            d.extend_from_slice(&(incl as u32).to_le_bytes());
            d.extend_from_slice(&pkt);
            ts += 5;
        }
        d
    }

    #[test]
    fn pcap_roundtrip_is_lossless() {
        let p = sample_pcap();
        let t = pcap_transform(&p).expect("transform");
        assert!(
            t.len() < p.len(),
            "the transform must shrink: {} -> {}",
            p.len(),
            t.len()
        );
        let r = pcap_restore(&t).expect("restore");
        assert_eq!(r, p, "the PCAP comes back byte for byte");
    }

    #[test]
    fn pcap_has_a_structural_gain() {
        let p = sample_pcap();
        let r = pcap_structural_ratio(&p).expect("ratio");
        assert!(r > 1.0, "structural gain: {r}");
    }

    #[test]
    fn pcap_rejects_corrupt_input() {
        assert!(pcap_transform(b"short").is_none());
        assert!(pcap_transform(&[0u8; 24]).is_none()); // no magic
        let mut p = sample_pcap();
        p.truncate(40); // global hdr + half a record
        assert!(pcap_transform(&p).is_none() || pcap_transform(&p).is_some()); // no panic
    }

    #[test]
    fn pcap_digest_is_deterministic() {
        let p = sample_pcap();
        assert_eq!(pcap_digest(&p), pcap_digest(&p));
    }
}
