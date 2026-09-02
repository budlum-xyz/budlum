//! Light client: knowing which state root is valid.
//!
//! A browser asks a node, and the node can lie. Three separate questions have
//! three separate answers, and this module is about the third.
//!
//! * **Content bytes** cannot lie: if the hash does not match, the bytes are
//!   thrown away ([`crate::fetch`]).
//! * **BNS resolution** can lie: a node that returns the attacker's manifest ID
//!   shows a page that is *verified and wrong*. Resolution has to be bound to a
//!   state proof ([`crate::bns_proof`]).
//! * **Chain headers**: knowing which state root is valid means following a
//!   header chain. That is this module.
//!
//! # Measured: following every header is expensive
//!
//! Adding up the `BlockHeader` fields in `src/core/block.rs` gives roughly 603
//! bytes per header. The hash fields are `String` written with `hex::encode`,
//! so every thirty-two byte root occupies sixty-four characters.
//!
//! | following           | 1s blocks | 6s blocks  | 12s blocks |
//! |---------------------|-----------|------------|------------|
//! | every header        | 1.5 GB/mo | 248 MB/mo  | 124 MB/mo  |
//! | epoch boundaries    | 149 MB/mo | 24.8 MB/mo | 12.4 MB/mo |
//!
//! Hence the decision: **the browser does not follow every header, only
//! finalized epoch boundaries.** `EPOCH_LENGTH = 10`
//! (`src/chain/blockchain.rs:54`), so one in ten. Verifying a state proof needs
//! exactly one thing, that the root the proof binds to sits in a finalized
//! header; the nine headers in between answer nothing about that.
//!
//! # What is not verified, stated plainly
//!
//! This module does not prove on its own that a header is **final**. Budlum
//! carries multiple consensus kinds and finality is produced seven different
//! ways behind `DomainFinalityAdapter` (`PoW` header-chain, `PoS`, `PoA`, BFT,
//! ZK, storage attestation, AI inference). A browser verifying all seven is a
//! separate piece of work and it **has not been done**. Until it is, header
//! following asks a `FinalitySource`, and when that source is merely asserting
//! something the result is labelled
//! [`crate::evidence::Strength::RpcClaimOnly`].
//!
//! Presenting this as "there is a light client" would be selling a guarantee
//! that does not exist.

use crate::evidence::{Claim, Evidence, Strength};
use sha2::{Digest, Sha256};

/// Must match `src/chain/blockchain.rs:54`. If they diverge, epoch boundaries
/// shift out from under everything that follows them.
pub const EPOCH_LENGTH: u64 = 10;

/// A followed header.
///
/// `state_root` and `hash` are hex `String`s on the chain, and are kept that
/// way here, because the comparison has to be made in the form the chain
/// writes. Converting to raw bytes would take a header from 603 to 443 bytes,
/// a 26 percent saving, but that is a consensus surface change and is not made
/// here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedHeader {
    pub index: u64,
    pub epoch: u64,
    pub state_root: String,
    pub hash: String,
}

impl TrackedHeader {
    /// Is this header an epoch boundary?
    #[must_use]
    pub fn is_epoch_boundary(&self) -> bool {
        self.index.is_multiple_of(EPOCH_LENGTH)
    }
}

/// Who speaks about finality.
pub trait FinalitySource {
    /// Is this header final, and **how** do we know?
    ///
    /// The returned `Claim` is the source declaring its own strength. A source
    /// that wants to say `Verified` must have verified a proof; "the RPC said
    /// so" is `RpcClaimOnly`.
    fn finality_of(&self, header: &TrackedHeader) -> Claim;
}

/// A store of finalized epoch boundaries.
///
/// Only epoch boundaries are kept, and the store is bounded: a browser cannot
/// hold an unbounded chain. At the limit the **oldest** header is dropped,
/// because a state proof always binds to a recent root.
#[derive(Debug, Clone)]
pub struct HeaderStore {
    headers: Vec<TrackedHeader>,
    capacity: usize,
}

impl HeaderStore {
    /// Default capacity: 1024 epoch boundaries.
    ///
    /// At six-second blocks an epoch is sixty seconds, so 1024 epochs is about
    /// seventeen hours. The root a proof binds to is expected to fall inside
    /// that window; if it does not, the proof is stale and belongs rejected.
    pub const DEFAULT_CAPACITY: usize = 1024;

    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(Self::DEFAULT_CAPACITY)
    }

    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            headers: Vec::new(),
            capacity: capacity.max(1),
        }
    }

    /// Accepts a header.
    ///
    /// # Errors
    ///
    /// A header that is not an epoch boundary, an index that moves backwards,
    /// or a different hash at an index already held. The last is a sign of a
    /// fork, and is never quietly overwritten.
    pub fn accept(&mut self, header: TrackedHeader) -> Result<(), String> {
        if !header.is_epoch_boundary() {
            return Err(format!(
                "header {} is not an epoch boundary (EPOCH_LENGTH={EPOCH_LENGTH}); \
                 the browser does not follow the headers in between",
                header.index
            ));
        }
        if let Some(last) = self.headers.last() {
            if header.index == last.index {
                if header.hash != last.hash {
                    return Err(format!(
                        "two different hashes appeared for index {} ({} and {}); \
                         that is a sign of a fork and is not resolved silently",
                        header.index, last.hash, header.hash
                    ));
                }
                return Ok(());
            }
            if header.index < last.index {
                return Err(format!(
                    "header {} is behind {}, which was already seen; a chain that \
                     moves backwards is not accepted",
                    header.index, last.index
                ));
            }
        }
        self.headers.push(header);
        if self.headers.len() > self.capacity {
            self.headers.remove(0);
        }
        Ok(())
    }

    /// The most recent finalized root.
    #[must_use]
    pub fn tip(&self) -> Option<&TrackedHeader> {
        self.headers.last()
    }

    /// Is this state root in a followed header?
    #[must_use]
    pub fn knows_state_root(&self, state_root: &str) -> bool {
        self.headers.iter().any(|h| h.state_root == state_root)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// How strongly a state root can be trusted.
    ///
    /// All three are required: the root must sit in a known header, that header
    /// must be final, and the result cannot be stronger than the strength of
    /// whatever source asserted that finality.
    pub fn strength_of<S: FinalitySource>(&self, source: &S, state_root: &str) -> Evidence {
        let Some(header) = self.headers.iter().find(|h| h.state_root == state_root) else {
            return Evidence::new().with(Claim::new(
                "light-client",
                Strength::Refused,
                "the state root is in no followed finalized header",
            ));
        };
        Evidence::new().with(source.finality_of(header))
    }
}

impl Default for HeaderStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Sparse Merkle trie proof: the same rule as `src/storage/merkle_trie.rs`.
// ---------------------------------------------------------------------------

const TRIE_DEPTH: usize = 256;
const DOMAIN_PREFIX: &[u8] = b"BDLM_MERKLE_TRIE_V1";

/// A state proof for one address.
///
/// The same shape as the proof `src/storage/merkle_trie.rs` produces. That
/// module is **not wired** today - its own file says so: account state is still
/// hashed through the old root - so this verifier does not run against the live
/// chain yet. It is here so that the browser side is ready the day the trie is
/// wired, and the rule does not get reinvented that day.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    pub address: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
    pub directions: Vec<bool>,
    pub leaf_hash: [u8; 32],
}

fn get_bit(bytes: &[u8; 32], index: usize) -> bool {
    let byte = bytes[index / 8];
    let bit = 7 - (index % 8);
    (byte >> bit) & 1 == 1
}

fn hash_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Two empty children collapse to empty: zero, not `H(0||0)`.
fn combine_nodes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    if *left == [0u8; 32] && *right == [0u8; 32] {
        return [0u8; 32];
    }
    hash_internal(left, right)
}

fn finalize_root(raw: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN_PREFIX);
    h.update(raw);
    h.finalize().into()
}

/// A leaf hash: `SHA-256(0x01 || address || balance_le || nonce_le)`.
#[must_use]
pub fn hash_leaf(address: &[u8; 32], balance: u64, nonce: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(address);
    h.update(balance.to_le_bytes());
    h.update(nonce.to_le_bytes());
    h.finalize().into()
}

impl MerkleProof {
    /// Does this proof bind to that root?
    ///
    /// The direction bits are **derived from the address and compared**.
    /// Without the comparison a valid proof could be labelled as a proof for a
    /// different address, which is exactly what the LOW (CWE-345) finding
    /// closed in `merkle_trie.rs`. It has to stay closed here too: leaving the
    /// verifier side open makes the proof meaningless.
    #[must_use]
    pub fn verify(&self, expected_root: &[u8; 32]) -> bool {
        if self.siblings.len() != TRIE_DEPTH || self.directions.len() != TRIE_DEPTH {
            return false;
        }
        let mut current = self.leaf_hash;
        for i in 0..TRIE_DEPTH {
            let expected_direction = get_bit(&self.address, TRIE_DEPTH - 1 - i);
            if self.directions[i] != expected_direction {
                return false;
            }
            let (left, right) = if self.directions[i] {
                (self.siblings[i], current)
            } else {
                (current, self.siblings[i])
            };
            current = combine_nodes(&left, &right);
        }
        &finalize_root(&current) == expected_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct HonestChain;
    impl FinalitySource for HonestChain {
        fn finality_of(&self, header: &TrackedHeader) -> Claim {
            Claim::new(
                "finality",
                Strength::RpcClaimOnly,
                &format!(
                    "finality for epoch {} is an RPC assertion; the seven \
                     DomainFinalityAdapter forms are not verified in the browser",
                    header.epoch
                ),
            )
        }
    }

    fn header(index: u64) -> TrackedHeader {
        TrackedHeader {
            index,
            epoch: index / EPOCH_LENGTH,
            state_root: format!("root{index}"),
            hash: format!("hash{index}"),
        }
    }

    #[test]
    fn only_epoch_boundaries_are_accepted() {
        let mut store = HeaderStore::new();
        assert!(store.accept(header(10)).is_ok());
        let err = store.accept(header(13)).unwrap_err();
        assert!(err.contains("is not an epoch boundary"), "{err}");
    }

    #[test]
    fn a_second_hash_at_one_index_is_a_fork_not_an_update() {
        let mut store = HeaderStore::new();
        store.accept(header(10)).unwrap();
        let mut twin = header(10);
        twin.hash = String::from("different");
        let err = store.accept(twin).unwrap_err();
        assert!(err.contains("a sign of a fork"), "{err}");
    }

    #[test]
    fn the_chain_does_not_go_backwards() {
        let mut store = HeaderStore::new();
        store.accept(header(20)).unwrap();
        assert!(store.accept(header(10)).is_err());
    }

    #[test]
    fn capacity_drops_the_oldest_not_the_newest() {
        let mut store = HeaderStore::with_capacity(2);
        store.accept(header(10)).unwrap();
        store.accept(header(20)).unwrap();
        store.accept(header(30)).unwrap();
        assert_eq!(store.len(), 2);
        assert!(!store.knows_state_root("root10"));
        assert!(store.knows_state_root("root30"));
        assert_eq!(store.tip().unwrap().index, 30);
    }

    #[test]
    fn an_unknown_state_root_is_refused_not_assumed() {
        let store = HeaderStore::new();
        let e = store.strength_of(&HonestChain, "root10");
        assert_eq!(e.weakest(), Strength::Refused);
    }

    #[test]
    fn a_known_root_is_only_as_strong_as_the_finality_source() {
        let mut store = HeaderStore::new();
        store.accept(header(10)).unwrap();
        let e = store.strength_of(&HonestChain, "root10");
        assert_eq!(e.weakest(), Strength::RpcClaimOnly);
        assert!(e.badge().contains("DomainFinalityAdapter"));
    }

    #[test]
    fn a_merkle_proof_verifies_only_against_its_own_root() {
        // A single-leaf trie: every sibling is empty.
        let address = [0xAAu8; 32];
        let leaf = hash_leaf(&address, 100, 3);
        let mut current = leaf;
        let mut directions = Vec::with_capacity(TRIE_DEPTH);
        for i in 0..TRIE_DEPTH {
            let bit = get_bit(&address, TRIE_DEPTH - 1 - i);
            directions.push(bit);
            let (l, r) = if bit {
                ([0u8; 32], current)
            } else {
                (current, [0u8; 32])
            };
            current = combine_nodes(&l, &r);
        }
        let root = finalize_root(&current);
        let proof = MerkleProof {
            address,
            siblings: vec![[0u8; 32]; TRIE_DEPTH],
            directions,
            leaf_hash: leaf,
        };
        assert!(proof.verify(&root));
        assert!(!proof.verify(&[0u8; 32]));
    }

    #[test]
    fn a_proof_relabelled_to_another_address_does_not_verify() {
        let address = [0xAAu8; 32];
        let leaf = hash_leaf(&address, 100, 3);
        let mut current = leaf;
        let mut directions = Vec::with_capacity(TRIE_DEPTH);
        for i in 0..TRIE_DEPTH {
            let bit = get_bit(&address, TRIE_DEPTH - 1 - i);
            directions.push(bit);
            let (l, r) = if bit {
                ([0u8; 32], current)
            } else {
                (current, [0u8; 32])
            };
            current = combine_nodes(&l, &r);
        }
        let root = finalize_root(&current);
        let forged = MerkleProof {
            address: [0xBBu8; 32],
            siblings: vec![[0u8; 32]; TRIE_DEPTH],
            directions,
            leaf_hash: leaf,
        };
        assert!(
            !forged.verify(&root),
            "a proof with a relabelled address must not pass"
        );
    }

    #[test]
    fn a_short_proof_is_refused() {
        let proof = MerkleProof {
            address: [1u8; 32],
            siblings: vec![[0u8; 32]; 4],
            directions: vec![false; 4],
            leaf_hash: [2u8; 32],
        };
        assert!(!proof.verify(&[0u8; 32]));
    }
}
