//! Custody proofs: the sub-block tree, the audit draw and proof checking.
//!
//! * A symbol is cut into 64-byte sub-blocks; the last one is zero-padded.
//! * Symbol leaf: the Merkle root over the sub-blocks (tag
//!   `BDLM_BUD3_SYMBOL_V1`).
//! * Symbol root of a segment: the Merkle root over the symbol leaves of the
//!   placement, in ESI order (tag `BDLM_BUD3_SYMBOLS_V1`). The object record
//!   holds it for the upload symbols and every repair record holds one for the
//!   new symbols.
//!
//! Each epoch the audit seed picks at most one audit per custody share, with a
//! per-class probability in parts per million. An audit names one symbol of
//! the share and one sub-block of it. The holder answers with the sub-block
//! bytes and two Merkle paths; block execution checks them against the symbol
//! root it already holds. The draw uses no floating point and no wall clock.
//!
//! The Merkle trees here hash an odd node up unchanged and bind the leaf count
//! into the root, the same rule as the object commitment.

use crate::core::hash::hash_fields_bytes;

/// Sub-block size in bytes.
pub const SUB_BLOCK: usize = 64;
/// Symbol leaf tag.
pub const SYMBOL_TAG: &[u8] = b"BDLM_BUD3_SYMBOL_V1";
/// Symbol root tag.
pub const SYMBOLS_TAG: &[u8] = b"BDLM_BUD3_SYMBOLS_V1";
/// Audit draw tag.
pub const AUDIT_TAG: &[u8] = b"BDLM_BUD3_AUDIT_V1";

/// Parts per million.
pub const PPM: u32 = 1_000_000;

/// The longest Merkle path a proof may carry (2^32 leaves).
pub const MAX_PATH: usize = 32;

fn leaf_hash(tag: &[u8], index: u64, bytes: &[u8]) -> [u8; 32] {
    hash_fields_bytes(&[tag, &[0x00], &index.to_le_bytes(), bytes])
}

fn node_hash(tag: &[u8], left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hash_fields_bytes(&[tag, &[0x01], left, right])
}

fn root_hash(tag: &[u8], count: u64, root: &[u8; 32]) -> [u8; 32] {
    hash_fields_bytes(&[tag, &[0x02], &count.to_le_bytes(), root])
}

/// One step of a Merkle path: the sibling, or `None` where the node had no
/// sibling and moved up unchanged.
pub type PathStep = Option<[u8; 32]>;

/// Merkle root and the path of every leaf would be costly; this builds the
/// root and, when asked, the path of one leaf.
fn merkle(tag: &[u8], leaves: Vec<[u8; 32]>, want: Option<usize>) -> ([u8; 32], Vec<PathStep>) {
    let count = leaves.len() as u64;
    let mut level = leaves;
    let mut pos = want;
    let mut path = Vec::new();
    while level.len() > 1 {
        if let Some(p) = pos {
            let sibling = if p.is_multiple_of(2) { p + 1 } else { p - 1 };
            path.push(level.get(sibling).copied());
            pos = Some(p / 2);
        }
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [l, r] => node_hash(tag, l, r),
                [one] => *one,
                _ => [0u8; 32],
            })
            .collect();
    }
    let top = level.first().copied().unwrap_or([0u8; 32]);
    (root_hash(tag, count, &top), path)
}

/// Fold a path from a leaf hash up to the root.
fn fold(tag: &[u8], count: u64, index: u64, leaf: [u8; 32], path: &[PathStep]) -> Option<[u8; 32]> {
    if path.len() > MAX_PATH || index >= count {
        return None;
    }
    // Recompute the shape so a path cannot claim a sibling where the tree has
    // none, or skip one where it has one.
    let mut width = count;
    let mut pos = index;
    let mut acc = leaf;
    let mut steps = path.iter();
    while width > 1 {
        let has_sibling = pos % 2 == 1 || pos + 1 < width;
        let step = steps.next()?;
        match (has_sibling, step) {
            (true, Some(s)) => {
                acc = if pos.is_multiple_of(2) {
                    node_hash(tag, &acc, s)
                } else {
                    node_hash(tag, s, &acc)
                };
            }
            (false, None) => {}
            _ => return None,
        }
        pos /= 2;
        width = width.div_ceil(2);
    }
    if steps.next().is_some() {
        return None;
    }
    Some(root_hash(tag, count, &acc))
}

/// The sub-blocks of a symbol, the last one zero-padded.
fn sub_blocks(symbol: &[u8]) -> Vec<[u8; SUB_BLOCK]> {
    let mut out: Vec<[u8; SUB_BLOCK]> = symbol
        .chunks(SUB_BLOCK)
        .map(|c| {
            let mut b = [0u8; SUB_BLOCK];
            for (d, s) in b.iter_mut().zip(c) {
                *d = *s;
            }
            b
        })
        .collect();
    if out.is_empty() {
        out.push([0u8; SUB_BLOCK]);
    }
    out
}

/// The number of sub-blocks of a symbol of `symbol_size` bytes.
#[must_use]
pub const fn sub_block_count(symbol_size: usize) -> u64 {
    let n = symbol_size.div_ceil(SUB_BLOCK) as u64;
    if n == 0 {
        1
    } else {
        n
    }
}

fn sub_leaves(symbol: &[u8]) -> Vec<[u8; 32]> {
    sub_blocks(symbol)
        .iter()
        .enumerate()
        .map(|(i, b)| leaf_hash(SYMBOL_TAG, i as u64, b))
        .collect()
}

/// The leaf of one symbol: the root over its sub-blocks.
#[must_use]
pub fn symbol_leaf(symbol: &[u8]) -> [u8; 32] {
    merkle(SYMBOL_TAG, sub_leaves(symbol), None).0
}

fn symbol_root_leaves(leaves: &[(u32, [u8; 32])]) -> Vec<[u8; 32]> {
    leaves
        .iter()
        .map(|(esi, leaf)| leaf_hash(SYMBOLS_TAG, u64::from(*esi), leaf))
        .collect()
}

/// The symbol root over `(esi, symbol_leaf)` pairs in ESI order.
#[must_use]
pub fn symbol_root(leaves: &[(u32, [u8; 32])]) -> [u8; 32] {
    merkle(SYMBOLS_TAG, symbol_root_leaves(leaves), None).0
}

/// Serde for a 64-byte sub-block (serde derives arrays only up to 32).
mod sub_block_serde {
    use super::SUB_BLOCK;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8; SUB_BLOCK], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(b)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; SUB_BLOCK], D::Error> {
        let v: Vec<u8> = Vec::deserialize(d)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("a sub-block is 64 bytes"))
    }
}

/// One custody proof: a sub-block of a symbol and its two paths.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CustodyProof {
    /// Segment index.
    pub segment: u64,
    /// The symbol's ESI.
    pub esi: u32,
    /// Position of the symbol in the symbol root.
    pub position: u64,
    /// The sub-block index inside the symbol.
    pub sub_block: u64,
    /// The sub-block bytes.
    #[serde(with = "sub_block_serde")]
    pub bytes: [u8; SUB_BLOCK],
    /// Path from the sub-block to the symbol leaf.
    pub symbol_path: Vec<PathStep>,
    /// Path from the symbol leaf to the symbol root.
    pub root_path: Vec<PathStep>,
}

/// Build the proof a holder sends. `placed` is every `(esi, symbol_leaf)` of
/// the symbol root in ESI order; `position` is the audited symbol in it.
#[must_use]
pub fn prove(
    segment: u64,
    placed: &[(u32, [u8; 32])],
    position: usize,
    symbol: &[u8],
    sub_block: usize,
) -> Option<CustodyProof> {
    let (esi, _) = *placed.get(position)?;
    let blocks = sub_blocks(symbol);
    let bytes = *blocks.get(sub_block)?;
    let (_, symbol_path) = merkle(SYMBOL_TAG, sub_leaves(symbol), Some(sub_block));
    let (_, root_path) = merkle(SYMBOLS_TAG, symbol_root_leaves(placed), Some(position));
    Some(CustodyProof {
        segment,
        esi,
        position: position as u64,
        sub_block: sub_block as u64,
        bytes,
        symbol_path,
        root_path,
    })
}

/// Why a proof failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofError {
    /// The proof answers another audit.
    WrongChallenge,
    /// A path does not lead to the symbol root.
    BadPath,
}

/// What block execution knows when it checks a proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofContext {
    /// The symbol root of the segment.
    pub symbol_root: [u8; 32],
    /// Number of symbols under the root.
    pub symbol_count: u64,
    /// Sub-blocks per symbol.
    pub sub_blocks: u64,
}

impl CustodyProof {
    /// Check the proof against the audit and the stored symbol root.
    ///
    /// # Errors
    ///
    /// [`ProofError::WrongChallenge`] when it answers another audit,
    /// [`ProofError::BadPath`] when it does not hash to the root.
    pub fn verify(&self, audit: &Audit, ctx: &ProofContext) -> Result<(), ProofError> {
        if self.segment != audit.segment
            || self.position != audit.position
            || self.sub_block != audit.sub_block
        {
            return Err(ProofError::WrongChallenge);
        }
        let leaf = leaf_hash(SYMBOL_TAG, self.sub_block, &self.bytes);
        let symbol = fold(
            SYMBOL_TAG,
            ctx.sub_blocks,
            self.sub_block,
            leaf,
            &self.symbol_path,
        )
        .ok_or(ProofError::BadPath)?;
        let entry = leaf_hash(SYMBOLS_TAG, u64::from(self.esi), &symbol);
        let root = fold(
            SYMBOLS_TAG,
            ctx.symbol_count,
            self.position,
            entry,
            &self.root_path,
        )
        .ok_or(ProofError::BadPath)?;
        if root != ctx.symbol_root {
            return Err(ProofError::BadPath);
        }
        Ok(())
    }
}

/// One audit of one custody share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Audit {
    /// Segment index.
    pub segment: u64,
    /// Position of the audited symbol in the symbol root.
    pub position: u64,
    /// Sub-block index.
    pub sub_block: u64,
}

/// A custody share as the audit draw sees it: the positions it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareRef {
    /// Segment index.
    pub segment: u64,
    /// The holder.
    pub holder: [u8; 32],
    /// First position in the symbol root.
    pub first_position: u64,
    /// Number of symbols held.
    pub symbols: u64,
}

fn draw(seed: &[u8; 32], share: &ShareRef, what: u8) -> u64 {
    let h = hash_fields_bytes(&[
        AUDIT_TAG,
        seed,
        &share.segment.to_le_bytes(),
        &share.holder,
        &[what],
    ]);
    let mut b = [0u8; 8];
    b.copy_from_slice(h.get(..8).unwrap_or(&[0u8; 8]));
    u64::from_le_bytes(b)
}

/// The audit of `share` this epoch, if the draw selects it. `probability_ppm`
/// is the class parameter (Full 20 000, Mobile 10 000 at testnet default).
#[must_use]
pub fn audit_for(
    seed: &[u8; 32],
    share: &ShareRef,
    probability_ppm: u32,
    sub_blocks: u64,
) -> Option<Audit> {
    if share.symbols == 0 || sub_blocks == 0 {
        return None;
    }
    if draw(seed, share, 0) % u64::from(PPM) >= u64::from(probability_ppm.min(PPM)) {
        return None;
    }
    Some(Audit {
        segment: share.segment,
        position: share.first_position + draw(seed, share, 1) % share.symbols,
        sub_block: draw(seed, share, 2) % sub_blocks,
    })
}

/// The testnet audit probability of a Full share, in ppm.
pub const FULL_AUDIT_PPM: u32 = 20_000;
/// The testnet audit probability of a Mobile share, in ppm.
pub const MOBILE_AUDIT_PPM: u32 = 10_000;

#[cfg(test)]
mod tests {
    use super::*;

    fn symbols(n: u32, size: usize) -> Vec<(u32, Vec<u8>)> {
        (0..n)
            .map(|esi| {
                (
                    esi * 3 + 1,
                    (0..size).map(|i| (i as u32 ^ esi) as u8).collect(),
                )
            })
            .collect()
    }

    type Setup = (Vec<(u32, Vec<u8>)>, Vec<(u32, [u8; 32])>, ProofContext);

    fn setup(n: u32, size: usize) -> Setup {
        let syms = symbols(n, size);
        let leaves: Vec<(u32, [u8; 32])> = syms.iter().map(|(e, s)| (*e, symbol_leaf(s))).collect();
        let ctx = ProofContext {
            symbol_root: symbol_root(&leaves),
            symbol_count: u64::from(n),
            sub_blocks: sub_block_count(size),
        };
        (syms, leaves, ctx)
    }

    #[test]
    fn every_position_and_sub_block_proves() {
        // 7 symbols (odd tree) of 2911 bytes (46 sub-blocks, last padded).
        let (syms, leaves, ctx) = setup(7, 2911);
        assert_eq!(ctx.sub_blocks, 46);
        for (pos, (_, symbol)) in syms.iter().enumerate() {
            for sb in [0usize, 1, 44, 45] {
                let proof = prove(3, &leaves, pos, symbol, sb).unwrap();
                let audit = Audit {
                    segment: 3,
                    position: pos as u64,
                    sub_block: sb as u64,
                };
                assert_eq!(proof.verify(&audit, &ctx), Ok(()), "pos {pos} sb {sb}");
            }
        }
    }

    #[test]
    fn a_wrong_byte_or_path_fails() {
        let (syms, leaves, ctx) = setup(5, 300);
        let audit = Audit {
            segment: 0,
            position: 2,
            sub_block: 1,
        };
        let good = prove(0, &leaves, 2, &syms[2].1, 1).unwrap();

        let mut p = good.clone();
        p.bytes[0] ^= 1;
        assert_eq!(p.verify(&audit, &ctx), Err(ProofError::BadPath));

        let mut p = good.clone();
        p.esi += 1;
        assert_eq!(p.verify(&audit, &ctx), Err(ProofError::BadPath));

        let mut p = good.clone();
        p.root_path.pop();
        assert_eq!(p.verify(&audit, &ctx), Err(ProofError::BadPath));

        let mut p = good.clone();
        p.root_path.push(None);
        assert_eq!(p.verify(&audit, &ctx), Err(ProofError::BadPath));

        let other = Audit {
            segment: 0,
            position: 3,
            sub_block: 1,
        };
        assert_eq!(good.verify(&other, &ctx), Err(ProofError::WrongChallenge));

        // The bytes of another symbol at the same position do not prove.
        let forged = prove(0, &leaves, 2, &syms[3].1, 1).unwrap();
        assert_eq!(forged.verify(&audit, &ctx), Err(ProofError::BadPath));
    }

    #[test]
    fn a_proof_is_about_640_bytes() {
        let (syms, leaves, ctx) = setup(4096, 64);
        let p = prove(0, &leaves, 1234, &syms[1234].1, 0).unwrap();
        let _ = ctx;
        let size = 8 + 4 + 8 + 8 + SUB_BLOCK + 33 * (p.symbol_path.len() + p.root_path.len());
        assert!(size < 700, "{size}");
    }

    #[test]
    fn the_audit_draw_is_deterministic_and_near_its_rate() {
        let seed = [9u8; 32];
        let mut hits = 0u32;
        for i in 0..20_000u64 {
            let mut holder = [0u8; 32];
            holder[..8].copy_from_slice(&i.to_le_bytes());
            let share = ShareRef {
                segment: i % 17,
                holder,
                first_position: 10,
                symbols: 5,
            };
            let a = audit_for(&seed, &share, FULL_AUDIT_PPM, 46);
            assert_eq!(a, audit_for(&seed, &share, FULL_AUDIT_PPM, 46));
            if let Some(a) = a {
                hits += 1;
                assert!((10..15).contains(&a.position));
                assert!(a.sub_block < 46);
            }
        }
        // 2 % of 20 000 = 400.
        assert!((300..500).contains(&hits), "{hits}");
        let share = ShareRef {
            segment: 0,
            holder: [1; 32],
            first_position: 0,
            symbols: 1,
        };
        assert_eq!(audit_for(&seed, &share, 0, 46), None);
        assert!(audit_for(&seed, &share, PPM, 46).is_some());
        assert_eq!(
            audit_for(
                &seed,
                &ShareRef {
                    symbols: 0,
                    ..share
                },
                PPM,
                46
            ),
            None
        );
    }
}
