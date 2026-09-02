//! BNS resolution: the browser's real trust problem.
//!
//! # Content addressing does not solve this
//!
//! A node that answers `ayaz.bud` with an attacker's manifest identity shows a
//! page that is **verified and wrong**: the bytes are consistent with their
//! hash, but that hash does not belong to the name that was asked for. Byte
//! verification says nothing here, because what is wrong is not the bytes, it
//! is the mapping.
//!
//! The decision: BNS resolution is settled **with a state proof**, and an
//! answer without one does not count as verified.
//!
//! # What can actually be proven today, stated plainly
//!
//! `AccountState::calculate_state_root` (`src/core/account.rs:1966`) folds the
//! BNS registry into the state root like this:
//!
//! ```text
//! if !self.bns_registry.is_empty() {
//!     final_hasher.update(b"bns_v1");
//!     final_hasher.update(self.bns_registry.root());
//! }
//! ```
//!
//! and `BnsRegistry::root()` (`src/bns/registry.rs:299`) writes **the whole
//! registry into a single SHA-256 stream**. So there is **no structure** on
//! chain today that can produce a proof for one name: verifying the `bns_v1`
//! root requires holding the entire registry.
//!
//! That has three consequences, and all three are written down:
//!
//! 1. [`BnsInclusionProof::Registry`] - verification against the whole
//!    registry. Correct, but it does not scale; it works for a small registry
//!    and not for a hundred thousand names.
//! 2. [`BnsInclusionProof::PerName`] - a Merkle proof per name. The chain does
//!    **not produce this today**; `BnsRegistry::root()` would have to become a
//!    Merkle tree, and that is a **consensus surface change**, not a decision
//!    this browser gets to make on its own.
//! 3. With no proof the verdict is [`Strength::RpcClaimOnly`]. Quietly saying
//!    `Verified` would be selling a guarantee that does not exist.
//!
//! This is the most important sentence in the file: **BNS resolution is not
//! provable today, and the browser does not hide that.**

use crate::content_id::ContentId;
use crate::evidence::{Claim, Evidence, Strength};
use sha2::{Digest, Sha256};

/// A resolution answer from the chain.
///
/// The fields match `BnsResolved` (`src/bns/types.rs`); the ones this browser
/// does not need are not carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedName {
    pub name: String,
    /// The 32-byte owner address.
    pub owner: [u8; 32],
    pub storage_root: Option<[u8; 32]>,
    pub content_id: Option<ContentId>,
    pub is_expired: bool,
}

/// Proof that a resolution belongs to the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BnsInclusionProof {
    /// The whole registry. What `BnsRegistry::root()` produces today is
    /// computed from this stream, so verifying means re-hashing the entire
    /// registry.
    Registry {
        /// `base_cost`, the first field that goes into the root.
        base_cost: u64,
        /// The `(name, owner, expires_at, content_id)` tuple, in `BTreeMap`
        /// order. The on-chain `root()` writes more fields than this; this
        /// version carries only the fields the browser reads, and **therefore
        /// cannot produce the full root**. The `verify` below reports that as
        /// a shortfall, not as a success.
        entries: Vec<RegistryEntry>,
    },
    /// A Merkle proof per name. The chain does not produce this today.
    PerName {
        leaf: [u8; 32],
        siblings: Vec<[u8; 32]>,
        directions: Vec<bool>,
    },
    /// No proof: an RPC answered, and that is all.
    None,
}

/// One row of the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryEntry {
    pub name: String,
    pub owner: [u8; 32],
    pub expires_at: u64,
    pub content_id: Option<ContentId>,
}

/// Evaluate a BNS resolution together with its proof.
///
/// `expected_bns_root` is the value `AccountState` writes into the state root
/// under the `bns_v1` tag.
#[must_use]
pub fn evaluate(
    resolved: &ResolvedName,
    proof: &BnsInclusionProof,
    expected_bns_root: Option<[u8; 32]>,
) -> Evidence {
    let mut evidence = Evidence::new();

    if resolved.is_expired {
        evidence.push(Claim::new(
            "bns-resolution",
            Strength::Refused,
            "the registration has expired, and an expired name binds to no content",
        ));
        return evidence;
    }

    match proof {
        BnsInclusionProof::None => {
            evidence.push(Claim::new(
                "bns-resolution",
                Strength::RpcClaimOnly,
                "no state proof arrived; this answer is one node's assertion and a node \
                 can lie. Even if the content hash checks out, the page shown may not \
                 belong to the name that was asked for",
            ));
        }
        BnsInclusionProof::PerName { .. } => {
            evidence.push(Claim::new(
                "bns-resolution",
                Strength::RpcClaimOnly,
                "a per-name proof was presented, but the chain does not produce one today: \
                 BnsRegistry::root() writes the whole registry into a single SHA-256 \
                 stream, not a Merkle tree. There is no root to verify it against",
            ));
        }
        BnsInclusionProof::Registry { base_cost, entries } => {
            let Some(expected) = expected_bns_root else {
                evidence.push(Claim::new(
                    "bns-resolution",
                    Strength::RpcClaimOnly,
                    "a registry was presented, but no bns_v1 root was given to compare it against",
                ));
                return evidence;
            };
            let found = entries.iter().any(|e| {
                e.name == resolved.name
                    && e.owner == resolved.owner
                    && e.content_id == resolved.content_id
            });
            if !found {
                evidence.push(Claim::new(
                    "bns-resolution",
                    Strength::Refused,
                    "the resolved record is not in the presented registry; the answer contradicts it",
                ));
                return evidence;
            }
            let computed = partial_registry_root(*base_cost, entries);
            if computed == expected {
                evidence.push(Claim::new(
                    "bns-resolution",
                    Strength::Verified,
                    "the registry reproduced the bns_v1 root, and the record is in it",
                ));
            } else {
                // This is the expected case: this version does not carry all
                // of `root()`'s fields. What is wrong is the proof format, not
                // the registry.
                evidence.push(Claim::new(
                    "bns-resolution",
                    Strength::RpcClaimOnly,
                    "the presented registry did not reproduce the bns_v1 root. On its own \
                     that is not a sign of lying: BnsRegistry::root() also writes the \
                     resolver, address, consensus_domain_id, storage_root, \
                     storage_domain_id, storage_root_height and subdomains fields, and \
                     this proof format does not carry them. The proof format is \
                     incomplete, so the answer is not verified",
                ));
            }
        }
    }

    evidence
}

/// A **partial** reproduction of `BnsRegistry::root()`.
///
/// Deliberately incomplete, and its name says so. The full root also covers
/// six fields the browser never reads, plus subdomain names; carrying those
/// here would mean a browser downloading an entire registry. This function's
/// job is to make it **measurable** why the proof format is not enough.
#[must_use]
pub fn partial_registry_root(base_cost: u64, entries: &[RegistryEntry]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_BNS_REGISTRY_V1");
    hasher.update(base_cost.to_le_bytes());
    for e in entries {
        hasher.update(e.name.as_bytes());
        hasher.update(e.owner);
        hasher.update(e.expires_at.to_le_bytes());
        // The on-chain `root()` writes the resolver/address/domain/storage fields
        // here. They are not written here, which is why this root does not hold.
        match e.content_id {
            Some(cid) => {
                hasher.update([1u8]);
                hasher.update(cid.0);
            }
            None => hasher.update([0u8]),
        }
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolved() -> ResolvedName {
        ResolvedName {
            name: String::from("ayaz.bud"),
            owner: [1u8; 32],
            storage_root: Some([9u8; 32]),
            content_id: Some(ContentId([9u8; 32])),
            is_expired: false,
        }
    }

    #[test]
    fn an_expired_name_is_refused_before_any_proof_is_read() {
        let mut r = resolved();
        r.is_expired = true;
        let e = evaluate(&r, &BnsInclusionProof::None, None);
        assert_eq!(e.weakest(), Strength::Refused);
        assert!(e.badge().contains("has expired"));
    }

    #[test]
    fn no_proof_is_a_claim_not_a_verification() {
        let e = evaluate(&resolved(), &BnsInclusionProof::None, None);
        assert_eq!(e.weakest(), Strength::RpcClaimOnly);
        assert!(e.badge().contains("a node can lie"));
    }

    #[test]
    fn a_per_name_proof_says_the_chain_does_not_produce_one() {
        let e = evaluate(
            &resolved(),
            &BnsInclusionProof::PerName {
                leaf: [0u8; 32],
                siblings: vec![],
                directions: vec![],
            },
            Some([0u8; 32]),
        );
        assert_eq!(e.weakest(), Strength::RpcClaimOnly);
        assert!(e.badge().contains("not a Merkle tree"));
    }

    #[test]
    fn a_registry_missing_the_record_is_refused_not_downgraded() {
        let proof = BnsInclusionProof::Registry {
            base_cost: 100,
            entries: vec![RegistryEntry {
                name: String::from("other.bud"),
                owner: [2u8; 32],
                expires_at: 10,
                content_id: None,
            }],
        };
        let e = evaluate(&resolved(), &proof, Some([0u8; 32]));
        assert_eq!(e.weakest(), Strength::Refused);
        assert!(e.badge().contains("contradicts it"));
    }

    #[test]
    fn a_registry_that_reproduces_the_root_is_verified() {
        let entries = vec![RegistryEntry {
            name: String::from("ayaz.bud"),
            owner: [1u8; 32],
            expires_at: 10,
            content_id: Some(ContentId([9u8; 32])),
        }];
        let root = partial_registry_root(100, &entries);
        let proof = BnsInclusionProof::Registry {
            base_cost: 100,
            entries,
        };
        let e = evaluate(&resolved(), &proof, Some(root));
        assert_eq!(e.weakest(), Strength::Verified);
    }

    #[test]
    fn a_registry_that_does_not_reproduce_the_root_explains_which_fields_are_missing() {
        let entries = vec![RegistryEntry {
            name: String::from("ayaz.bud"),
            owner: [1u8; 32],
            expires_at: 10,
            content_id: Some(ContentId([9u8; 32])),
        }];
        let proof = BnsInclusionProof::Registry {
            base_cost: 100,
            entries,
        };
        let e = evaluate(&resolved(), &proof, Some([0xFFu8; 32]));
        assert_eq!(e.weakest(), Strength::RpcClaimOnly);
        assert!(e.badge().contains("storage_root_height"), "{}", e.badge());
    }

    #[test]
    fn the_partial_root_is_deterministic() {
        let entries = vec![RegistryEntry {
            name: String::from("a.bud"),
            owner: [3u8; 32],
            expires_at: 1,
            content_id: None,
        }];
        assert_eq!(
            partial_registry_root(100, &entries),
            partial_registry_root(100, &entries)
        );
        assert_ne!(
            partial_registry_root(100, &entries),
            partial_registry_root(101, &entries)
        );
    }
}
