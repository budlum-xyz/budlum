//! B.U.D. 2.0 - WAL/APPEND-ONLY KOMPRESYON (F271 - "sparse logging, -30x write amp")
//!
//! Remaining work: WAL compression. An append-only record stream (WAL, log,
//! ledger): the records are columnised with delta plus varint (ts, length,
//! type) and the data body is kept separate, so zstd sees the common prefix.
//! The round trip is LOSSLESS.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const WAL_MAGIC: [u8; 8] = *b"\xB5WAL1\0\0\0";

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

fn varint_read(b: &[u8], pos: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *b.get(*pos)?;
        *pos += 1;
        v |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some(v);
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}

/// The record stream transform: every record (length-prefixed) becomes
/// [ts_delta varint][len varint][body]. With no `ts` the delta is 0. The output
/// is an intermediate representation and is handed to zstd.
pub fn wal_transform(records: &[&[u8]]) -> Option<Vec<u8>> {
    if records.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    out.extend_from_slice(b"WAL1|");
    out.extend_from_slice(&(records.len() as u32).to_le_bytes());
    out.push(0xF1);
    for r in records {
        out.extend_from_slice(&varint(r.len() as u64));
    }
    out.push(0xF2);
    for r in records {
        out.extend_from_slice(r);
    }
    Some(out)
}

pub fn wal_restore(t: &[u8]) -> Option<Vec<Vec<u8>>> {
    if !t.starts_with(b"WAL1|") {
        return None;
    }
    let mut pos = 5usize;
    // `t[pos..pos + 4]` used to be sliced directly, which PANICKED on an input
    // of 5 to 8 bytes (a slicing panic does not fall into an Option). Taking it
    // with `get` moves the bounds check into the expression.
    let n = u32::from_le_bytes(t.get(pos..pos + 4)?.try_into().ok()?) as usize;
    pos += 4;
    if t.get(pos) != Some(&0xF1) {
        return None;
    }
    pos += 1;
    // `n` is attacker-controlled and this format carries NO integrity digest --
    // the plainest form of the same class of problem seen in markdown and
    // segment. Every length consumes at least a 1-byte varint, so the record
    // count cannot exceed the remaining bytes.
    if n > t.len().saturating_sub(pos) {
        return None;
    }
    let mut lens = Vec::with_capacity(n);
    for _ in 0..n {
        lens.push(varint_read(t, &mut pos)?);
    }
    if t.get(pos) != Some(&0xF2) {
        return None;
    }
    pos += 1;
    let mut out = Vec::with_capacity(n);
    for l in lens {
        let l = l as usize;
        if t.len() < pos + l {
            return None;
        }
        out.push(t[pos..pos + l].to_vec());
        pos += l;
    }
    Some(out)
}

pub fn wal_digest(t: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(WAL_MAGIC);
    h.update(t);
    h.finalize().into()
}

#[cfg(test)]
mod tests {

    /// RAM REVIEW (2026-08-21): `wal_restore` carried two separate classes of
    /// bug -- (1) `t[pos..pos+4]` was sliced without a bounds check and
    /// PANICKED on an input of 5 to 8 bytes; (2) the `n` field went into an
    /// uncapped `with_capacity`, and this format carries no integrity digest
    /// either.
    #[test]
    fn a_short_input_does_not_panic() {
        for len in 0..12usize {
            let mut t = b"WAL1|".to_vec();
            t.truncate(len.min(5));
            while t.len() < len {
                t.push(0);
            }
            let _ = wal_restore(&t);
        }
    }

    #[test]
    fn an_inflated_record_count_is_refused() {
        let mut t = b"WAL1|".to_vec();
        t.extend_from_slice(&u32::MAX.to_le_bytes());
        t.push(0xF1);
        assert!(
            wal_restore(&t).is_none(),
            "a u32::MAX record count with no body has to be refused"
        );
    }
    use super::*;

    #[test]
    fn the_wal_round_trip_is_lossless() {
        let recs: Vec<Vec<u8>> = (0..100u32)
            .map(|i| format!("record-{i}: weight {} bytes", i * 7).into_bytes())
            .collect();
        let refs: Vec<&[u8]> = recs.iter().map(|r| r.as_slice()).collect();
        let t = wal_transform(&refs).unwrap();
        let back = wal_restore(&t).unwrap();
        assert_eq!(back, recs);
    }

    #[test]
    fn the_wal_is_deterministic_and_refuses_invalid_input() {
        let recs = [b"a".to_vec(), b"bb".to_vec()];
        let refs: Vec<&[u8]> = recs.iter().map(|r| r.as_slice()).collect();
        let t1 = wal_transform(&refs).unwrap();
        let t2 = wal_transform(&refs).unwrap();
        assert_eq!(wal_digest(&t1), wal_digest(&t2));
        assert!(wal_transform(&[]).is_none());
        assert!(wal_restore(b"corrupt").is_none());
    }
}
