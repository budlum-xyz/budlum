//! NIPoPoW succinct proof-of-work finality verification adapter for Budlum.
//!
//! Budlum is a Universal Settlement Layer: it ingests the finality proofs of
//! many external consensus domains and records them in a single
//! `GlobalBlockHeader`. For Nakamoto/PoW-style chains the canonical succinct
//! client is NIPoPoW (Non-Interactive Proofs of Proof-of-Work, Kiayias et al.
//! 2017): instead of shipping the whole header chain, a prover sends a short
//! interlink-structured proof that a superchain of a given cumulative work
//! exists.
//!
//! This crate implements the verification half of that protocol in a
//! hash-agnostic, dependency-light way (SHA-256 is used as the production
//! digest). It is the historical-line culmination of `bitcoin_spv.rs`
//! (Chaum, hashcash and b-money, Nakamoto, Bitcoin SPV): SPV proves payment
//! inclusion; NIPoPoW proves chain superiority succinctly, which is what a
//! settlement layer needs to admit a PoW domain's finality.
//!
//! # What a proof is allowed to claim
//!
//! A verifier is only as strong as the fields its proof cannot choose. This
//! crate binds three of them, and each binding was added because a working
//! adversarial test could break the verifier without it:
//!
//! 1. *The interlink is part of the proof of work.* `hash_block` digests the
//!    interlink together with the parent, the height, the nonce and the level,
//!    so a pointer that no miner committed to cannot direct a descent.
//!    Without this an adversary splices a jump into any valid-PoW fork of its
//!    own making, at a cost of a handful of hashes.
//! 2. *The trusted anchor is an id and a height.* An anchor that is only an id
//!    is satisfied by any header that names it as its parent, so one level-1
//!    header could claim a height of two to the fortieth for two hashes of
//!    work. `TrustedAnchor` carries both, and the oldest header in the proof
//!    must be the anchor's immediate child.
//! 3. *Goodness counts superblocks.* Every accepted header has level at least
//!    one, so counting level-at-least-one blocks counted the proof's own
//!    length and made the security parameter vacuous. Goodness is now the
//!    number of headers at or above `SecurityParams::superblock_level`, and a
//!    proof may not repeat a header to inflate it.
//!
//! # Security assumption
//!
//! Verification is fail-closed: any structurally invalid proof is rejected, and
//! so is any proof that does not satisfy the parameters it is checked against.
//! The economic guarantee - that an adversary with strictly less than half the
//! hash power cannot forge a proof preferred over the honest one - rests on the
//! honest-chain and majority-hash-power assumption. That assumption is an open
//! research boundary for NIPoPoW-class proofs; it is stated, not claimed solved.
//!
//! WIRING: unwired - the crate is the verification half of the NIPoPoW family.
//! It reaches the network through `src/cross_domain/external/nipopow.rs`, which
//! is to call these types from an `ExternalFinalityAdapter` implementation.
//! Until that adapter depends on the crate, every public item here is named
//! only by this crate's own tests, and `EvidenceEnvelope` carries the family
//! attestation across the boundary.

pub mod envelope;

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Fixed 32-byte digest used for block identity, interlink anchors and PoW.
pub type Hash32 = [u8; 32];

/// Highest difficulty level a header may declare.
///
/// A level is a count of leading zero bits over a 32-byte digest, so 256 is the
/// arithmetic ceiling; the bound is deliberately far below it so that a proof
/// cannot demand a level no fixture and no caller can produce, and so that the
/// level fits comfortably inside the interlink vector a header carries.
pub const MAX_LEVEL: u8 = 32;

/// The block a verifier already trusts, identified by digest *and* height.
///
/// The height is not decoration: without it the anchor is a 32-byte string that
/// any freshly mined header can name as its parent, which makes a claimed
/// height worthless.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedAnchor {
    /// Digest of the trusted block.
    pub id: Hash32,
    /// Height of the trusted block.
    pub height: u64,
}

impl TrustedAnchor {
    /// The chain genesis, whose height is zero by definition.
    #[must_use]
    pub const fn genesis(id: Hash32) -> Self {
        Self { id, height: 0 }
    }
}

/// The parameters a proof is checked against.
///
/// `m` is the goodness bound: how many superblocks the proof must exhibit at or
/// above `superblock_level`. The three values are related, and the constructor
/// refuses every combination that would make the bound vacuous.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecurityParams {
    m: usize,
    superblock_level: u8,
    max_level: u8,
}

impl SecurityParams {
    /// Build parameters, or `None` when the combination cannot bound anything.
    ///
    /// A level-1 header costs two hashes on average, so a superblock level of 1
    /// would make goodness the proof's length. `m` of zero would be satisfied
    /// by no proof at all, and `max_level` below the superblock level would make
    /// the bound unreachable. All three are refused here rather than checked
    /// again at every call site.
    #[must_use]
    pub const fn new(m: usize, superblock_level: u8, max_level: u8) -> Option<Self> {
        if m == 0 || superblock_level < 2 || superblock_level > max_level || max_level < 2 {
            return None;
        }
        if max_level > MAX_LEVEL {
            return None;
        }
        Some(Self {
            m,
            superblock_level,
            max_level,
        })
    }

    /// Superblocks the proof must carry.
    #[must_use]
    pub const fn m(self) -> usize {
        self.m
    }

    /// Level at which a header counts as a superblock.
    ///
    /// This is the one parameter that decides what a forgery costs: an
    /// adversary must mine `m` headers with at least this many leading zero
    /// bits, so the price of the proof is `m * 2^superblock_level` hash
    /// evaluations. It is therefore the adapter's job to pin it to the target
    /// chain's real difficulty, not the prover's.
    #[must_use]
    pub const fn superblock_level(self) -> u8 {
        self.superblock_level
    }

    /// Highest level any header in the proof may declare.
    #[must_use]
    pub const fn max_level(self) -> u8 {
        self.max_level
    }
}

/// A single proof-of-work header in a NIPoPoW chain.
#[derive(Clone, Debug)]
pub struct PowHeader {
    /// The proof-of-work commitment over every other field, interlink included.
    pub id: Hash32,
    /// Parent header id (the trusted anchor for the oldest header).
    pub parent: Hash32,
    /// Chain height.
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
    /// Digest of the trusted block the descent must reach.
    pub anchor: Hash32,
}

impl NipopowProof {
    /// Fail-closed verification of a NIPoPoW proof against a trusted anchor.
    ///
    /// Returns `true` only when every header is committed by its own proof of
    /// work (interlink included), the prefix is contiguous, the suffix descends
    /// without gaps, the descent reaches the anchor's immediate child at the
    /// anchor's height plus one, no header is repeated, and the proof carries at
    /// least `params.m` superblocks.
    #[must_use]
    pub fn verify(&self, anchor: &TrustedAnchor, params: &SecurityParams) -> bool {
        // The head is what a settlement claim is about: a proof with no prefix
        // describes no head, and the junction logic below indexes prefix[0].
        if self.prefix.is_empty() {
            return false;
        }

        let mut all: Vec<&PowHeader> = Vec::with_capacity(self.prefix.len() + self.suffix.len());
        all.extend(self.prefix.iter());
        all.extend(self.suffix.iter());

        // (a) Every header is committed by its own proof of work. The digest
        //     covers the interlink, so a spliced pointer is not a free parameter.
        let mut seen: BTreeMap<Hash32, ()> = BTreeMap::new();
        for h in &all {
            if h.level == 0 || h.level > params.max_level {
                return false;
            }
            if h.interlink.len() != h.level as usize {
                return false;
            }
            if leading_zero_bits(&h.id) < u32::from(h.level) {
                return false;
            }
            if hash_header(h) != h.id {
                return false;
            }
            // A chain cannot contain the same block twice, and a repeated
            // superblock would otherwise pay for goodness more than once.
            if seen.insert(h.id, ()).is_some() {
                return false;
            }
        }

        // (b) Prefix contiguity.
        for w in 1..self.prefix.len() {
            let prev = &self.prefix[w - 1];
            let cur = &self.prefix[w];
            // `+ 1` on a u64 height is attacker input: at `u64::MAX` it panics in
            // a build with overflow checks on, and the release profile turns
            // that panic into an abort.
            let expected = match prev.height.checked_add(1) {
                Some(expected) => expected,
                None => return false,
            };
            if cur.height != expected || cur.parent != prev.id {
                return false;
            }
        }

        // (c) Junction between prefix and suffix.
        if let Some(first_suffix) = self.suffix.first() {
            let expected = match first_suffix.height.checked_add(1) {
                Some(expected) => expected,
                None => return false,
            };
            if self.prefix[0].parent != first_suffix.id || self.prefix[0].height != expected {
                return false;
            }
        }

        // (d) Suffix descent: each step is either the contiguous parent or an
        //     interlink pointer this header's own digest committed to.
        for w in 1..self.suffix.len() {
            let up = &self.suffix[w - 1];
            let down = &self.suffix[w];
            if down.height >= up.height {
                return false;
            }
            let contiguous = down.id == up.parent;
            let mut interlink_ok = false;
            if !contiguous {
                for (k, ptr) in up.interlink.iter().enumerate() {
                    // A zero pointer is "no ancestor at this level", never a
                    // jump target, and the committed level must reach the slot.
                    if *ptr != [0u8; 32] && *ptr == down.id && down.level as usize > k {
                        interlink_ok = true;
                        break;
                    }
                }
            }
            if !contiguous && !interlink_ok {
                return false;
            }
        }

        // (e) The descent reaches the anchor: the oldest header in the proof is
        //     the anchor's immediate child, at the anchor's height plus one.
        let oldest = self.suffix.last().unwrap_or(&self.prefix[0]);
        if oldest.parent != anchor.id {
            return false;
        }
        // `saturating_add` would let a `u64::MAX` anchor accept a `u64::MAX`
        // child, which is exactly the binding this check exists to make.
        let expected = match anchor.height.checked_add(1) {
            Some(expected) => expected,
            None => return false,
        };
        if oldest.height != expected {
            return false;
        }

        // (f) Goodness: superblocks the proof actually exhibits.
        let superblocks = all
            .iter()
            .filter(|h| h.level >= params.superblock_level)
            .count();
        superblocks >= params.m
    }
}

/// Count leading zero bits of a 32-byte digest (from the MSB).
#[must_use]
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

/// `SHA256(parent || height || nonce || level || interlink_len || interlink)`.
///
/// Integers are little-endian and the interlink is length-prefixed, so the
/// encoding is unambiguous: an empty interlink and a one-element interlink of
/// zeros digest differently.
#[must_use]
pub fn hash_block(
    parent: &Hash32,
    height: u64,
    nonce: u64,
    level: u8,
    interlink: &[Hash32],
) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(parent);
    hasher.update(height.to_le_bytes());
    hasher.update(nonce.to_le_bytes());
    hasher.update([level]);
    let count = u32::try_from(interlink.len()).unwrap_or(u32::MAX);
    hasher.update(count.to_le_bytes());
    for pointer in interlink {
        hasher.update(pointer);
    }
    let out = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&out);
    id
}

/// The proof-of-work commitment of a whole header.
fn hash_header(header: &PowHeader) -> Hash32 {
    hash_block(
        &header.parent,
        header.height,
        header.nonce,
        header.level,
        &header.interlink,
    )
}

/// Mine a header at `level` (requires `level` leading zero bits) atop `parent`,
/// committing to the given interlink.
///
/// The interlink must be known before mining: it is part of what the work
/// commits to, which is the whole reason a descent cannot be redirected.
fn mine_header(parent: &Hash32, height: u64, level: u8, interlink: Vec<Hash32>) -> PowHeader {
    let mut nonce: u64 = 0;
    loop {
        let id = hash_block(parent, height, nonce, level, &interlink);
        if leading_zero_bits(&id) >= u32::from(level) {
            return PowHeader {
                id,
                parent: *parent,
                height,
                nonce,
                level,
                interlink,
            };
        }
        nonce = nonce.wrapping_add(1);
    }
}

/// Incremental builder of a NIPoPoW chain used by tests and by the prover side.
///
/// The anchor is the genesis the chain is built on: the first header is at
/// height one and names the anchor as its parent, which is exactly the shape
/// [`NipopowProof::verify`] requires.
pub struct ChainBuilder {
    anchor: Hash32,
    headers: Vec<PowHeader>,
    /// Most recent header id seen at each level (1-indexed by level).
    last_at_level: BTreeMap<u8, Hash32>,
}

impl ChainBuilder {
    /// A builder whose genesis is `anchor` at height zero.
    #[must_use]
    pub fn new(anchor: Hash32) -> Self {
        Self {
            anchor,
            headers: Vec::new(),
            last_at_level: BTreeMap::new(),
        }
    }

    /// Append a mined header at `level`. Returns its id.
    pub fn push(&mut self, level: u8) -> Hash32 {
        let height = self.headers.len() as u64 + 1;
        let parent = self.headers.last().map_or(self.anchor, |header| header.id);

        // The interlink contract says "closest proper ancestor at level k+1",
        // so a level-3 header fills the level-1 and level-2 slots as well. Using
        // the exact-level map only would leave holes a descent must then cross
        // one parent link at a time, which is what made honest proofs long.
        let mut interlink = vec![[0u8; 32]; usize::from(level)];
        for (k, slot) in interlink.iter_mut().enumerate() {
            let mu = u8::try_from(k + 1).unwrap_or(u8::MAX);
            if let Some(ancestor) = self.last_at_level.get(&mu) {
                *slot = *ancestor;
            }
        }

        let header = mine_header(&parent, height, level, interlink);
        let id = header.id;
        for mu in 1..=level {
            self.last_at_level.insert(mu, id);
        }
        self.headers.push(header);
        id
    }

    /// The headers mined so far, ascending by height.
    #[must_use]
    pub fn headers(&self) -> &[PowHeader] {
        &self.headers
    }

    /// Digest of the head, or the anchor when nothing is mined yet.
    #[must_use]
    pub fn head(&self) -> Hash32 {
        self.headers.last().map_or(self.anchor, |header| header.id)
    }

    /// Digest of the genesis the chain was built on.
    #[must_use]
    pub fn anchor(&self) -> Hash32 {
        self.anchor
    }

    /// The trusted anchor this chain is verified against.
    #[must_use]
    pub fn trusted_anchor(&self) -> TrustedAnchor {
        TrustedAnchor::genesis(self.anchor)
    }

    /// Build a succinct proof of `m` goodness from the current head.
    #[must_use]
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
                if cur.height == 1 {
                    break;
                }
                // Follow the highest available interlink level (velvet descent).
                let mut next: Option<&PowHeader> = None;
                for lvl in (1..=cur.level as usize).rev() {
                    if let Some(n) = by_id.get(&cur.interlink[lvl - 1]) {
                        if n.height < cur.height {
                            next = Some(n);
                            break;
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
        let mut builder = ChainBuilder::new([0u8; 32]);
        let id = builder.push(3);
        let header = &builder.headers()[0];
        assert_eq!(header.level, 3);
        assert_eq!(header.id, id);
        assert!(leading_zero_bits(&header.id) >= 3);
        assert_eq!(header.height, 1);
    }

    #[test]
    fn interlink_points_to_closest_higher_ancestor() {
        let mut builder = ChainBuilder::new([0u8; 32]);
        // Levels 1, 2, 1, 3: the level-3 header at index 3 must fill every slot
        // with the closest ancestor that reaches that level.
        builder.push(1);
        builder.push(2);
        builder.push(1);
        builder.push(3);
        let header = &builder.headers()[3];
        assert_eq!(header.interlink[2], [0u8; 32]);
        assert_eq!(header.interlink[1], builder.headers()[1].id);
        assert_eq!(header.interlink[0], builder.headers()[2].id);
    }

    #[test]
    fn hash_commits_to_the_interlink() {
        let parent = [3u8; 32];
        let empty = hash_block(&parent, 4, 9, 1, &[]);
        let zero_pointer = hash_block(&parent, 4, 9, 1, &[[0u8; 32]]);
        let real_pointer = hash_block(&parent, 4, 9, 1, &[[7u8; 32]]);
        assert_ne!(empty, zero_pointer);
        assert_ne!(zero_pointer, real_pointer);
    }

    #[test]
    fn vacuous_parameters_are_refused() {
        assert!(SecurityParams::new(0, 2, 8).is_none());
        assert!(SecurityParams::new(4, 1, 8).is_none());
        assert!(SecurityParams::new(4, 5, 4).is_none());
        assert!(SecurityParams::new(4, 2, 33).is_none());
        match SecurityParams::new(4, 2, 8) {
            Some(params) => {
                assert_eq!(params.m(), 4);
                assert_eq!(params.superblock_level(), 2);
                assert_eq!(params.max_level(), 8);
            }
            None => panic!("(4, 2, 8) is a valid parameter set"),
        }
    }
}
