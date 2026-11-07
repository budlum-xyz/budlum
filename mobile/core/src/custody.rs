//! Custody proofs: the same Merkle rule as `src/storage/bud3/custody.rs`.
//!
//! `crates/budlum-types` will own these types once that crate lands.

use crate::hash::hash_fields_bytes;

/// Sub-block size in bytes.
pub const SUB_BLOCK: usize = 64;
/// Symbol leaf tag. Must equal `src/storage/bud3/custody.rs`.
pub const SYMBOL_TAG: &[u8] = b"BDLM_BUD3_SYMBOL_V1";
/// Symbol root tag. Must equal `src/storage/bud3/custody.rs`.
pub const SYMBOLS_TAG: &[u8] = b"BDLM_BUD3_SYMBOLS_V1";
/// The longest Merkle path a proof may carry (2^32 leaves).
pub const MAX_PATH: usize = 32;

/// One step of a Merkle path: the sibling, or `None` where the node had no
/// sibling and moved up unchanged.
pub type PathStep = Option<[u8; 32]>;

fn leaf_hash(tag: &[u8], index: u64, bytes: &[u8]) -> [u8; 32] {
    hash_fields_bytes(&[tag, &[0x00], &index.to_le_bytes(), bytes])
}

fn node_hash(tag: &[u8], left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hash_fields_bytes(&[tag, &[0x01], left, right])
}

fn root_hash(tag: &[u8], count: u64, root: &[u8; 32]) -> [u8; 32] {
    hash_fields_bytes(&[tag, &[0x02], &count.to_le_bytes(), root])
}

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

fn fold(tag: &[u8], count: u64, index: u64, leaf: [u8; 32], path: &[PathStep]) -> Option<[u8; 32]> {
    if path.len() > MAX_PATH || index >= count {
        return None;
    }
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

/// One custody proof: a sub-block of a symbol and its two paths.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub bytes: [u8; SUB_BLOCK],
    /// Path from the sub-block to the symbol leaf.
    pub symbol_path: Vec<PathStep>,
    /// Path from the symbol leaf to the symbol root.
    pub root_path: Vec<PathStep>,
}

/// Build the proof a holder sends.
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

/// What the checker knows when it checks a proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofContext {
    /// The symbol root of the segment.
    pub symbol_root: [u8; 32],
    /// Number of symbols under the root.
    pub symbol_count: u64,
    /// Sub-blocks per symbol.
    pub sub_blocks: u64,
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

/// A batch of custody proofs, the duty-lane transaction payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyProofBatch {
    /// Proofs in this batch.
    pub proofs: Vec<CustodyProof>,
}
