//! B.U.D. 2.0 - THE DB PAGE DELTA (F263/F264 - InnoDB and TOAST page
//! compression).
//!
//! Remaining work: DB page compression. For a page-structured database file
//! (SQLite or FDB): an XOR delta between consecutive pages, then zstd (under an
//! append-heavy workload neighbouring pages
//! is similar). LOSSLESS: the original pages are restored byte for byte.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const DBD_MAGIC: [u8; 8] = *b"\xB5DBD1\0\0\0";

/// Turns a page stream into a delta: page 0 stays raw and each later page is
/// XORed with the one before it.
pub fn page_delta_encode(pages: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    if pages.is_empty() {
        return None;
    }
    let plen = pages[0].len();
    if pages.iter().any(|p| p.len() != plen) {
        return None;
    }
    let mut out = Vec::with_capacity(pages.len());
    let mut prev = vec![0u8; plen];
    for p in pages {
        let d: Vec<u8> = p.iter().zip(prev.iter()).map(|(a, b)| a ^ b).collect();
        out.push(d);
        prev = p.clone();
    }
    Some(out)
}

pub fn page_delta_decode(deltas: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    if deltas.is_empty() {
        return None;
    }
    let plen = deltas[0].len();
    let mut out = Vec::with_capacity(deltas.len());
    let mut prev = vec![0u8; plen];
    for d in deltas {
        if d.len() != plen {
            return None;
        }
        let p: Vec<u8> = d.iter().zip(prev.iter()).map(|(a, b)| a ^ b).collect();
        out.push(p.clone());
        prev = p;
    }
    Some(out)
}

pub fn dbd_digest(deltas: &[Vec<u8>]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DBD_MAGIC);
    for d in deltas {
        h.update(d);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_delta_is_lossless() {
        // Append-heavy: every page closely resembles the one before it.
        let mut pages: Vec<Vec<u8>> = Vec::new();
        let mut cur = vec![0u8; 256];
        for i in 0..50u8 {
            pages.push(cur.clone());
            cur[i as usize % 256] = i; // a small change
        }
        let d = page_delta_encode(&pages).unwrap();
        let back = page_delta_decode(&d).unwrap();
        assert_eq!(back, pages);
        // The delta has low entropy, so zstd compresses it better - a
        // structural gain.
        let ham: usize = d
            .iter()
            .map(|p| p.iter().filter(|&&b| b != 0).count())
            .sum();
        assert!(ham < 256, "delta seyrek: {ham}");
    }

    #[test]
    fn different_page_sizes_are_refused() {
        assert!(page_delta_encode(&[vec![0u8; 8], vec![0u8; 9]]).is_none());
        assert!(page_delta_encode(&[]).is_none());
    }

    #[test]
    fn dbd_deterministik() {
        let pages = vec![vec![1u8; 16], vec![2u8; 16]];
        let d1 = page_delta_encode(&pages).unwrap();
        let d2 = page_delta_encode(&pages).unwrap();
        assert_eq!(dbd_digest(&d1), dbd_digest(&d2));
    }
}
