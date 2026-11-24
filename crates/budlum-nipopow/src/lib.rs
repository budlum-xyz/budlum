//! NIPoPoW succinct proof-of-work finality verification adapter for Budlum.
//!
//! Budlum is a Universal Settlement Layer: it ingests the finality proofs of
//! many external consensus domains and records them in a single
//! `GlobalBlockHeader`. For Nakamoto/PoW-style chains the canonical succinct
//! client is **NIPoPoW** (Non-Interactive Proofs of Proof-of-Work,
//! Kiayias et al. 2017): instead of shipping the whole header chain, a prover
//! sends a short interlink-structured proof that a superchain of a given
//! cumulative work exists.
//!
//! This crate implements the *verification* half of that protocol in a
//! hash-agnostic, dependency-light way (SHA-256 is used as the production
//! digest). It is the historical-line culmination of `bitcoin_spv.rs`
//! (Chaum → hashcash/b-money → Nakamoto → Bitcoin SPV): SPV proves payment
//! inclusion; NIPoPoW proves *chain superiority* succinctly, which is what a
//! settlement layer needs to admit a PoW domain's finality.
//!
//! # Security assumption (see `mimari/NIHAI_SISTEM_SINIRLARI.md`)
//!
//! Verification is **fail-closed**: any structurally invalid proof is rejected.
//! The *economic* guarantee — that an adversary with strictly less than 50%
//! hash-power cannot forge a proof preferred over the honest one — relies on
//! the honest-chain / <½-PoW assumption. That assumption is an open research
//! boundary for NIPoPoW-class proofs and is documented, not claimed solved.

pub mod envelope;

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Fixed 32-byte digest used for block identity, interlink anchors and PoW.
pub type Hash32 = [u8; 32];

/// A single proof-of-work header in a NIPoPoW chain.
#[derive(Clone, Debug)]
pub struct PowHeader {
    /// `SHA256(parent || height || nonce || level)` — the PoW commitment.
    pub id: Hash32,
    /// Parent header id (the trusted checkpoint for height 0).
    pub parent: Hash32,
    /// Chain height (genesis-of-proof = 0).
    pub height: u64,
    /// Nonce that makes `id` carry `level` leading zero bits.
    pub nonce: u64,
    /// PoW difficulty level: number of leading zero bits required.
    pub level: u8,
    /// Interlink: `interlink[k]` (k in `0..level`) is the id of the closest
    /// *proper* ancestor whose level is `>= k + 1`.
    pub interlink: Vec<Hash32>,
}

/// A NIPoPoW succinct proof: a contiguous prefix tail plus an interlink
/// (velvet) suffix that descends to the trusted `anchor`.
#[derive(Clone, Debug)]
pub struct NipopowProof {
    /// Contiguous recent headers (ascending height), ending at the head.
    pub prefix: Vec<PowHeader>,
    /// Interlink-descent path from just below the prefix down to the anchor.
    pub suffix: Vec<PowHeader>,
    /// Trusted checkpoint the proof must connect to.
    pub anchor: Hash32,
}

impl NipopowProof {
    /// Fail-closed verification of a NIPoPoW proof.
    ///
    /// `m` is the goodness bound (minimum number of level-≥1 blocks the proof
    /// must exhibit) and `max_level` the highest difficulty level in the proof.
    /// Returns `true` only when the proof is (a) internally consistent, (b)
    /// every header carries valid PoW, (c) the interlink/suffix descends
    /// without gaps to `anchor`, and (d) it satisfies the goodness bound.
    pub fn verify(&self, m: usize, max_level: u8) -> bool {
        let mut all: Vec<&PowHeader> = Vec::new();
        all.extend(self.prefix.iter());
        all.extend(self.suffix.iter());
        if all.is_empty() {
            return false;
        }
        // The contiguous head is the proof: without it there is nothing to
        // anchor a suffix descent to, and the prefix/suffix junction logic
        // below indexes prefix[0]. Reject instead of panicking.
        if self.prefix.is_empty() {
            return false;
        }

        // (a) PoW validity for every header.
        for h in &all {
            if h.level == 0 || h.level > max_level {
                return false;
            }
            if leading_zero_bits(&h.id) < h.level as u32 {
                return false;
            }
            if hash_block(&h.parent, h.height, h.nonce, h.level) != h.id {
                return false;
            }
            // Interlink length must cover the declared level.
            if h.interlink.len() != h.level as usize {
                return false;
            }
        }

        // (b) prefix contiguity.
        for w in 1..self.prefix.len() {
            let prev = &self.prefix[w - 1];
            let cur = &self.prefix[w];
            if cur.height != prev.height + 1 {
                return false;
            }
            if cur.parent != prev.id {
                return false;
            }
        }

        // (c) junction between prefix and suffix.
        if self.suffix.is_empty() {
            // The whole chain is the proof: must start at the anchor.
            if self.prefix[0].parent != self.anchor {
                return false;
            }
        } else {
            if self.prefix[0].parent != self.suffix[0].id {
                return false;
            }
            if self.prefix[0].height != self.suffix[0].height + 1 {
                return false;
            }
        }

        // (d) suffix descent: each step is either contiguous or a valid
        //     interlink jump to a strictly lower, sufficiently-levelled ancestor.
        for w in 1..self.suffix.len() {
            let up = &self.suffix[w - 1];
            let down = &self.suffix[w];
            if down.height >= up.height {
                return false;
            }
            let contiguous = down.id == up.parent;
            let mut interlink_ok = false;
            for (k, ptr) in up.interlink.iter().enumerate() {
                if *ptr == down.id {
                    // The pointed ancestor must satisfy the interlink contract:
                    // strictly lower and levelled >= k+1. A forged pointer to a
                    // header not carried in the proof cannot satisfy this because
                    // `down` is an actual proof header, so any mismatch fails
                    // closed (it would also fail the contiguous check).
                    if down.level as usize > k && down.height < up.height {
                        interlink_ok = true;
                        break;
                    }
                }
            }
            if !contiguous && !interlink_ok {
                return false;
            }
        }

        // (e) the descent must reach the trusted anchor.
        if let Some(bottom) = self.suffix.last() {
            if bottom.parent != self.anchor {
                return false;
            }
        } else if self.prefix[0].parent != self.anchor {
            return false;
        }

        // (f) goodness bound: enough level-≥1 blocks to defeat an adversary
        //     with strictly less than 50% hash-power (NIPoPoW security).
        let level1 = all.iter().filter(|h| h.level >= 1).count();
        level1 >= m
    }
}

/// Count leading zero bits of a 32-byte digest (from the MSB).
pub fn leading_zero_bits(h: &Hash32) -> u32 {
    let mut bits = 0u32;
    for &byte in h {
        if byte == 0 {
            bits += 8;
            continue;
        }
        bits += byte.leading_zeros();
        break;
    }
    bits
}

/// `SHA256(parent || height(LE u64) || nonce(LE u64) || level(u8))`.
pub fn hash_block(parent: &Hash32, height: u64, nonce: u64, level: u8) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(parent);
    hasher.update(height.to_le_bytes());
    hasher.update(nonce.to_le_bytes());
    hasher.update([level]);
    let out = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&out);
    id
}

/// Mine a header at `level` (requires `level` leading zero bits) atop `parent`.
fn mine(parent: &Hash32, height: u64, level: u8) -> PowHeader {
    let mut nonce: u64 = 0;
    loop {
        let id = hash_block(parent, height, nonce, level);
        if leading_zero_bits(&id) >= level as u32 {
            // Interlink is filled in by the builder once the ancestor map exists.
            return PowHeader {
                id,
                parent: *parent,
                height,
                nonce,
                level,
                interlink: vec![[0u8; 32]; level as usize],
            };
        }
        nonce = nonce.wrapping_add(1);
    }
}

/// Incremental builder of a NIPoPoW chain used by tests and (in production)
/// by the prover side.
pub struct ChainBuilder {
    anchor: Hash32,
    headers: Vec<PowHeader>,
    /// Most recent header id seen at each level (1-indexed by level).
    last_at_level: BTreeMap<u8, Hash32>,
}

impl ChainBuilder {
    pub fn new(anchor: Hash32) -> Self {
        Self {
            anchor,
            headers: Vec::new(),
            last_at_level: BTreeMap::new(),
        }
    }

    /// Append a mined header at `level`. Returns its id.
    pub fn push(&mut self, level: u8) -> Hash32 {
        let height = self.headers.len() as u64;
        let parent = if self.headers.is_empty() {
            self.anchor
        } else {
            self.headers[height as usize - 1].id
        };
        let mut header = mine(&parent, height, level);

        // Fill the interlink: for each k in 0..level, point to the closest
        // proper ancestor with level >= k+1 (the value before we update it).
        for k in 0..level as usize {
            let mu = (k + 1) as u8;
            if let Some(&aid) = self.last_at_level.get(&mu) {
                header.interlink[k] = aid;
            } else {
                header.interlink[k] = [0u8; 32];
            }
        }
        let id = header.id;
        self.last_at_level.insert(level, id);
        self.headers.push(header);
        id
    }

    pub fn headers(&self) -> &[PowHeader] {
        &self.headers
    }

    pub fn head(&self) -> Hash32 {
        self.headers.last().map(|h| h.id).unwrap_or(self.anchor)
    }

    pub fn anchor(&self) -> Hash32 {
        self.anchor
    }

    /// Build a succinct proof of `m` goodness from the current head.
    pub fn build_proof(&self, m: usize) -> NipopowProof {
        let total = self.headers.len();
        let k = (3 * m).min(total);
        let prefix_start = total - k;
        let prefix: Vec<PowHeader> = self.headers[prefix_start..].to_vec();

        let by_id: BTreeMap<Hash32, &PowHeader> = self.headers.iter().map(|h| (h.id, h)).collect();

        let mut suffix: Vec<PowHeader> = Vec::new();
        if prefix_start > 0 {
            let mut cur = &self.headers[prefix_start - 1];
            loop {
                suffix.push(cur.clone());
                if cur.height == 0 {
                    break;
                }
                // Follow the highest available interlink level (velvet descent).
                let mut next: Option<&PowHeader> = None;
                for lvl in (1..=cur.level as usize).rev() {
                    let idx = lvl - 1;
                    if idx < cur.interlink.len() {
                        if let Some(n) = by_id.get(&cur.interlink[idx]) {
                            if n.height < cur.height {
                                next = Some(n);
                                break;
                            }
                        }
                    }
                }
                match next {
                    Some(n) => cur = n,
                    None => {
                        if let Some(p) = by_id.get(&cur.parent) {
                            cur = p;
                        } else {
                            break;
                        }
                    }
                }
            }
        }

        NipopowProof {
            prefix,
            suffix,
            anchor: self.anchor,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mined_header_carries_requested_level() {
        let mut b = ChainBuilder::new([0u8; 32]);
        let id = b.push(3);
        let h = &b.headers()[0];
        assert_eq!(h.level, 3);
        assert_eq!(h.id, id);
        // Mining requires `>= level` leading zero bits, so the digest may carry
        // more than exactly `level` (a higher-difficulty block still satisfies
        // a lower level) — assert the bound, not an exact count.
        assert!(leading_zero_bits(&h.id) >= 3);
    }

    #[test]
    fn interlink_points_to_closest_higher_ancestor() {
        let mut b = ChainBuilder::new([0u8; 32]);
        // levels: 1,2,1,3 -> index 3 is level 3.
        b.push(1);
        b.push(2);
        b.push(1);
        b.push(3);
        let h3 = &b.headers()[3];
        // interlink[2] (mu=3) must point to the closest level>=3 ancestor: none
        // before it, so it is zero; interlink[1] (mu=2) points to header index 1
        // (the level-2 ancestor); interlink[0] (mu=1) points to header index 2.
        assert_eq!(h3.interlink[2], [0u8; 32]);
        assert_eq!(h3.interlink[1], b.headers()[1].id);
        assert_eq!(h3.interlink[0], b.headers()[2].id);
    }
}
