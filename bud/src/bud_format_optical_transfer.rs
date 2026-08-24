//! B.U.D. 2.0 - THE OPTICAL TRANSFER LAYER: screen-to-camera data transfer.
//!
//! The pattern taken over, 2026-08-16: a screen and a camera carry data over
//! light as a stream of codes. The measurement was 418.5 KB/s sustained, or
//! 1.0 MB in 2.5 seconds. For B.U.D. this is the **on-device open** transport
//! of `.bud` content: offline, without a network.
//!
//! - The `.bud` is split into segments, each shown on screen as one code.
//! - The receiving camera reads the codes, joins the segments and rebuilds the
//!   `.bud` losslessly.
//!
//! What B.U.D. adds: lossless, deterministic segmentation, with a content id
//! per segment, resilience to arriving out of order, through the sequence
//! number and the total, and verified joining, through a SHA3-256 digest. This
//! is the transport leg of the "on-device open or closed" user condition.

use sha3::{Digest, Sha3_256};

pub const OPTX_MAGIC: [u8; 8] = *b"\xB5OPTX\0\0\0";
pub const OPTX_VERSION: u8 = 1;

/// An optical segment, one per code shown on screen.
#[derive(Debug, Clone)]
pub struct OptSegment {
    pub index: u32,       // the sequence number, zero-based
    pub total: u32,       // the total number of segments
    pub data: Vec<u8>,    // the raw byte slice, the body of the code
    pub digest: [u8; 32], // SHA3-256(domain || index || total || data)
}

impl OptSegment {
    fn digest(index: u32, total: u32, data: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"BDLM_OPTX_SEG_V1");
        h.update(index.to_le_bytes());
        h.update(total.to_le_bytes());
        h.update((data.len() as u64).to_le_bytes());
        h.update(data);
        h.finalize().into()
    }

    /// Verify; a corrupt code is REFUSED.
    pub fn verify(&self) -> bool {
        Self::digest(self.index, self.total, &self.data) == self.digest
    }
}

/// Splits `.bud` content into optical segments, deterministically;
/// `seg_capacity` is the bytes per code.
pub fn split_optical(data: &[u8], seg_capacity: usize) -> Option<Vec<OptSegment>> {
    if data.is_empty() || seg_capacity == 0 {
        return None;
    }
    let total = data.len().div_ceil(seg_capacity) as u32;
    let mut segs = Vec::with_capacity(total as usize);
    for (i, chunk) in data.chunks(seg_capacity).enumerate() {
        let d = chunk.to_vec();
        segs.push(OptSegment {
            index: i as u32,
            total,
            digest: OptSegment::digest(i as u32, total, &d),
            data: d,
        });
    }
    Some(segs)
}

/// Joins the segments back into the original `.bud`, which is the proof of
/// losslessness.
///
/// It is resilient to arriving out of order, sorting by index; a missing,
/// duplicated or corrupt segment is REFUSED.
pub fn join_optical(segs: &[OptSegment]) -> Option<Vec<u8>> {
    if segs.is_empty() {
        return None;
    }
    let total = segs[0].total;
    if total == 0 || total > 1_000_000 {
        return None;
    }
    // Every segment must report the same total.
    if !segs.iter().all(|s| s.total == total) {
        return None;
    }
    // Verify and order them.
    let mut by_index: Vec<Option<&OptSegment>> = vec![None; total as usize];
    for s in segs {
        if !s.verify() {
            return None;
        }
        if (s.index as usize) >= total as usize {
            return None;
        }
        if by_index[s.index as usize].is_some() {
            return None; // a duplicated segment is refused
        }
        by_index[s.index as usize] = Some(s);
    }
    if by_index.iter().any(|o| o.is_none()) {
        return None; // a missing segment is refused
    }
    let mut out = Vec::new();
    for o in by_index.into_iter().flatten() {
        out.extend_from_slice(&o.data);
    }
    Some(out)
}

/// The split-then-join losslessness check, and its error tolerance.
pub fn roundtrip_lossless(data: &[u8], seg_capacity: usize) -> bool {
    match split_optical(data, seg_capacity) {
        Some(segs) => join_optical(&segs) == Some(data.to_vec()),
        None => false,
    }
}

/// The measurement: the segment count and the payload per code, which estimates
/// the screen-to-camera bandwidth.
pub fn optical_stats(data: &[u8], seg_capacity: usize) -> Option<(usize, usize)> {
    let segs = split_optical(data, seg_capacity)?;
    Some((segs.len(), seg_capacity))
}

pub fn optx_digest(segs: &[OptSegment]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(OPTX_MAGIC);
    h.update([OPTX_VERSION]);
    for s in segs {
        h.update(s.index.to_le_bytes());
        h.update(s.total.to_le_bytes());
        h.update(s.digest);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_optical_round_trip_is_lossless() {
        let data: Vec<u8> = (0u8..=255).cycle().take(50_000).collect();
        assert!(
            roundtrip_lossless(&data, 1024),
            "a large .bud stays lossless"
        );
        assert!(roundtrip_lossless(b"short content", 512));
        // A corrupt code is refused.
        let segs = split_optical(&data, 1024).unwrap();
        let mut corrupt = segs.clone();
        corrupt[3].data[0] ^= 0xFF;
        assert!(
            join_optical(&corrupt).is_none(),
            "a corrupt segment is refused"
        );
    }

    #[test]
    fn it_is_resilient_to_arriving_out_of_order() {
        let data = b"order-independent joining test".to_vec();
        let mut segs = split_optical(&data, 8).unwrap();
        segs.reverse(); // break the order
        assert_eq!(
            join_optical(&segs).unwrap(),
            data,
            "out of order, it still joins"
        );
    }

    #[test]
    fn a_missing_or_duplicated_segment_is_refused() {
        let data = b"missing segment test".to_vec();
        let segs = split_optical(&data, 8).unwrap();
        // Missing: drop the middle one.
        let mut missing = segs.clone();
        missing.remove(1);
        assert!(
            join_optical(&missing).is_none(),
            "a missing segment is refused"
        );
        // Duplicated: repeat one of them.
        let mut duplicated = segs.clone();
        duplicated.push(segs[0].clone());
        assert!(
            join_optical(&duplicated).is_none(),
            "a duplicated segment is refused"
        );
    }

    #[test]
    fn the_measurement_statistics() {
        let (n, cap) = optical_stats(&vec![0u8; 10_000], 500).unwrap();
        assert_eq!(n, 20);
        assert_eq!(cap, 500);
        assert!(optical_stats(b"", 10).is_none());
    }

    #[test]
    fn the_digest_is_deterministic() {
        let segs = split_optical(b"optical determinism", 4).unwrap();
        assert_eq!(optx_digest(&segs), optx_digest(&segs));
        // A different split gives a different digest, because the content changed.
        let segs2 = split_optical(b"optical determinism!", 4).unwrap();
        assert_ne!(optx_digest(&segs), optx_digest(&segs2));
    }
}
