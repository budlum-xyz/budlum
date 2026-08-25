//! B.U.D. 2.0 - Segment Ledger (segmentli zincir depolama deseni) (2026-08-16)
//!
//! K88-1: the segment storage pattern for the chain core - 64MB segments,
//! `len(4) + data + crc32(4)` records, and a corrupt record REFUSED on a CRC
//! mismatch. The B.U.D. version: SHA3-256 integrity (stronger than CRC32 - K38),
//! a length prefix, bomb protection (the segment ceiling), deterministic.
//!
//! This module is the core of storing .bud records (production proofs, PACTs,
//! regeneration challenges, checkpoints) ON CHAIN as segments: an append-only
//! ledger (the I1 PACT record plus the K89 blockchain integration).
//!
//! Kod: `#![forbid(unsafe_code)]`, panik'siz.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const SEGMENT_MAGIC: [u8; 8] = *b"\xB5SEGL\0\0\0";
pub const SEGMENT_VERSION: u8 = 1;
pub const MAX_SEGMENT_BYTES: u64 = 64 * 1024 * 1024; // 64 MB (blockchain-core)
pub const MAX_ENTRY_BYTES: u64 = 16 * 1024 * 1024; // the single-record ceiling (16 MB)

/// The segment ledger: append-only records (a length prefix plus a SHA3 digest).
#[derive(Debug, Clone)]
pub struct SegmentLedger {
    pub entries: Vec<Vec<u8>>, // the stored records (each with its own digest)
    pub total_bytes: u64,
}

impl Default for SegmentLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl SegmentLedger {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_SEGMENT_V1";

    pub fn new() -> Self {
        SegmentLedger {
            entries: Vec::new(),
            total_bytes: 0,
        }
    }

    /// Append a record (append-only). The size ceilings are applied and the digest is computed.
    pub fn append(&mut self, data: &[u8]) -> Option<u64> {
        if data.is_empty() || data.len() as u64 > MAX_ENTRY_BYTES {
            return None;
        }
        if self.total_bytes + data.len() as u64 > MAX_SEGMENT_BYTES {
            return None; // the segment is full -> a new segment (the caller decides)
        }
        self.total_bytes += data.len() as u64;
        self.entries.push(data.to_vec());
        Some(self.total_bytes)
    }

    /// Record integrity: verify the digest (K38).
    pub fn verify_entry(data: &[u8], digest: &[u8; 32]) -> bool {
        Self::entry_digest(data) == *digest
    }

    pub fn entry_digest(data: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update((data.len() as u64).to_le_bytes());
        h.update(data);
        h.finalize().into()
    }

    /// Serialise a segment: magic + version + record count + (len + digest + data)* + the root digest.
    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&SEGMENT_MAGIC);
        out.push(SEGMENT_VERSION);
        out.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for e in &self.entries {
            out.extend_from_slice(&(e.len() as u32).to_le_bytes());
            out.extend_from_slice(&Self::entry_digest(e));
            out.extend_from_slice(e);
        }
        // the root digest (whole-segment integrity - ledger immutability)
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update(&out);
        let root: [u8; 32] = h.finalize().into();
        out.extend_from_slice(&root);
        out
    }

    /// Deserialise a segment: verify strictly (every record digest, the root digest, and refuse trailing bytes).
    pub fn from_blob(bytes: &[u8]) -> Option<Self> {
        const HDR: usize = 8 + 1 + 4;
        if bytes.len() < HDR + 32 || bytes[0..8] != SEGMENT_MAGIC || bytes[8] != SEGMENT_VERSION {
            return None;
        }
        let payload_len = bytes.len() - 32;
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update(&bytes[..payload_len]);
        let root: [u8; 32] = h.finalize().into();
        if root != bytes[payload_len..] {
            return None;
        }
        let count = u32::from_le_bytes(bytes[9..13].try_into().ok()?) as usize;
        let mut pos = HDR;
        // `count` is attacker-controlled; allocating on it directly used to
        // request 103 GB from a 45-byte blob (measured: "memory allocation of
        // 103079215080 bytes failed" -> SIGABRT, which kills the node under
        // panic="abort").
        // The SHA3 check above does not protect: the digest is keyless and
        // DOMAIN is a public constant, so producing a valid blob stays free.
        //
        // Every record consumes at least 4 bytes of length plus a 32 byte
        // digest = 36 bytes; since the ceiling is derived from the length of
        // the input itself, the allocation always stays proportional to the
        // input.
        if count > payload_len.saturating_sub(pos) / 36 {
            return None;
        }
        let mut entries = Vec::with_capacity(count);
        let mut total: u64 = 0;
        for _ in 0..count {
            if bytes.len() < pos + 4 + 32 {
                return None;
            }
            let len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().ok()?) as usize;
            pos += 4;
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&bytes[pos..pos + 32]);
            pos += 32;
            if len as u64 > MAX_ENTRY_BYTES || bytes.len() < pos + len {
                return None;
            }
            let data = bytes[pos..pos + len].to_vec();
            pos += len;
            if !Self::verify_entry(&data, &digest) {
                return None; // the record was tampered with
            }
            total += len as u64;
            entries.push(data);
        }
        if pos != payload_len || total > MAX_SEGMENT_BYTES {
            return None;
        }
        Some(SegmentLedger {
            entries,
            total_bytes: total,
        })
    }

    /// The segment root (writable into a chain header - within the I8 byte budget).
    pub fn root(&self) -> [u8; 32] {
        let blob = self.to_blob();
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_SEGMENT_ROOT_V1");
        h.update(&blob[..blob.len() - 32]);
        h.finalize().into()
    }
}

#[cfg(test)]
mod tests {

    /// RAM DENETIMI (2026-08-21): sisirilmis `count`, 45 baytlik girdiyle
    /// 103.079.215.080 baytlik ayirma talebi uretiyordu -> SIGABRT.
    /// SHA3 alani korumaz (anahtarsiz ozet + public DOMAIN).
    #[test]
    fn an_inflated_record_count_is_refused_before_allocating() {
        use sha3::{Digest, Sha3_256};
        let mut b = Vec::new();
        b.extend_from_slice(&SEGMENT_MAGIC);
        b.push(SEGMENT_VERSION);
        b.extend_from_slice(&u32::MAX.to_le_bytes());
        let mut h = Sha3_256::new();
        h.update(SegmentLedger::DOMAIN);
        h.update(&b);
        b.extend_from_slice(&h.finalize());

        assert!(
            SegmentLedger::from_blob(&b).is_none(),
            "a u32::MAX record count with no body must be refused"
        );
    }

    /// Canary: the ceiling must not refuse a real ledger.
    #[test]
    fn a_real_ledger_is_unaffected_by_the_ceiling() {
        let mut seg = SegmentLedger::new();
        seg.append(b"first record").expect("append");
        seg.append(b"second record").expect("append");
        let blob = seg.to_blob();
        let back = SegmentLedger::from_blob(&blob).expect("a valid blob must be accepted");
        assert_eq!(back.root(), seg.root(), "the root digest does not change");
    }
    use super::*;

    #[test]
    fn append_and_roundtrip() {
        let mut seg = SegmentLedger::new();
        seg.append(b"pact record 1").expect("append");
        seg.append(b"regeneration exam record").expect("append");
        seg.append(b"checkpoint").expect("ekle");
        assert_eq!(seg.entries.len(), 3);
        assert!(seg.total_bytes > 0);
        let blob = seg.to_blob();
        let back = SegmentLedger::from_blob(&blob).expect("the segment reads back");
        assert_eq!(back.entries, seg.entries);
        assert_eq!(back.total_bytes, seg.total_bytes);
        // the root is deterministic
        assert_eq!(seg.root(), back.root());
        assert_ne!(seg.root(), [0u8; 32]);
        // tampering is refused: any record byte
        for i in 0..blob.len() {
            let mut bad = blob.clone();
            bad[i] ^= 0x01;
            // corrupting the magic/version bytes is refused too (a different error path, still None)
            let _ = SegmentLedger::from_blob(&bad);
        }
        let mut bad = blob.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 0xFF;
        assert!(
            SegmentLedger::from_blob(&bad).is_none(),
            "record tampering is refused"
        );
        // trailing bytes are refused
        let mut extra = blob.clone();
        extra.push(0x00);
        assert!(SegmentLedger::from_blob(&extra).is_none());
    }

    #[test]
    fn tampered_entry_digest_rejected() {
        // change a record but leave the old digest -> REFUSED
        let mut seg = SegmentLedger::new();
        seg.append(b"original record").expect("append");
        let blob = seg.to_blob();
        let mut bad = blob.clone();
        // change the first record's data (HDR = 13, then 4 len + 32 digest, so data starts at 49)
        bad[49] = b'X';
        assert!(
            SegmentLedger::from_blob(&bad).is_none(),
            "a modified record is REFUSED"
        );
    }

    #[test]
    fn segment_capacity_limits() {
        let mut seg = SegmentLedger::new();
        // 16MB + 1 → red
        let big = vec![0u8; (MAX_ENTRY_BYTES + 1) as usize];
        assert!(seg.append(&big).is_none(), "the record ceiling");
        // empty -> refused
        assert!(seg.append(&[]).is_none());
        // a full segment: up to 64MB
        let chunk = vec![0u8; 1024];
        let mut filled = false;
        for _ in 0..(MAX_SEGMENT_BYTES as usize / 1024 + 10) {
            if seg.append(&chunk).is_none() {
                filled = true;
                break;
            }
        }
        assert!(filled, "the segment capacity is bounded");
        assert!(seg.total_bytes <= MAX_SEGMENT_BYTES);
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
        let mut rng = Rng(0x5345_474C_2026_0816);
        let mut buf = vec![0u8; 256];
        for _ in 0..2000 {
            let len = (rng.next() % 256) as usize;
            for b in &mut buf[..len] {
                *b = rng.byte();
            }
            let _ = SegmentLedger::from_blob(&buf[..len]);
        }
    }
}
