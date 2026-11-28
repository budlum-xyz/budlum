//! Cross-slot falsity: refuting an accepted attestation with its successor.
//!
//! # The gap this closes
//!
//! [`crate::cross_domain::external::intake::IntakeState::slash_on_contradiction`]
//! refutes an accepted attestation only inside its own slot: the challenger has
//! to produce a second, independently verified proof for the *same* external
//! `(height, evidence_version)` with a different committed root. That covers
//! fabricated evidence and a chain that signs two different blocks at one
//! height. It does not cover the case that actually costs money: a proof that
//! was authentic when it was accepted and whose slot can never be re-proved,
//! because the chain moved to a different branch and left it behind. The record
//! then keeps a lie forever, its carrier keeps the bond, and a consumer reading
//! that slot's root reads a state that its own chain abandoned.
//!
//! The successor is the missing witness. A later proof from the same adapter
//! binds, as part of its own verification, the parent block digest it descends
//! from. If accepted slot `h` claims block `B` and the accepted proof at `h + 1`
//! descends from `P != B`, then slot `h` is false, the successor is the proof of
//! it, and the carrier of `h` is the account that is answerable.
//!
//! # What this module refuses to do
//!
//! - It does not slash on a *tie*. Two accepted slots at the same height with
//!   different roots and no ancestry between them are the external chain's own
//!   equivocation; neither carrier is provably the liar, so the verdict freezes
//!   the domain and slashes nobody.
//! - It does not infer a parent hash. If the adapter does not bind one, the
//!   witness is refused (`Refusal::NoParentBinding`) rather than guessed: a
//!   slash built on an inferred ancestry is an unprovable claim.
//! - It does not repeat a ruling. The same `(refuted, refuter)` evidence-digest
//!   pair decides once; a second adjudication is refused, so a bond cannot be
//!   drained twice by replaying one honest witness.
//!
//! Everything here is a pure function of two records and a challenger address:
//! no clock, no I/O, no floating point, so two nodes cannot disagree.

use std::collections::BTreeSet;

use crate::core::address::Address;
use crate::cross_domain::external::spec::{AdapterId, DomainKey};

/// One accepted slot of an external domain's attestation book.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BookSlot {
    pub domain: DomainKey,
    pub adapter: AdapterId,
    /// Height in the external system's own numbering.
    pub height: u64,
    pub evidence_version: u32,
    /// The evidence digest the book keyed this attestation under.
    pub evidence_digest: [u8; 32],
    /// The account that carried the evidence in and escrowed the bond.
    pub carrier: Address,
    /// The block digest this attestation committed to, where the adapter
    /// attests one. `None` means the accepted claim said nothing about a block,
    /// so nothing can be contradicted at the block level.
    pub attested_block_hash: Option<[u8; 32]>,
}

/// What a *successor* proof says, after its own adapter accepted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuccessorView {
    pub domain: DomainKey,
    pub adapter: AdapterId,
    pub height: u64,
    pub evidence_version: u32,
    pub evidence_digest: [u8; 32],
    /// The account carrying the successor evidence.
    pub carrier: Address,
    /// The parent block digest the successor's own verification bound.
    pub attested_parent: Option<[u8; 32]>,
}

/// The ruling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ruling {
    /// The predecessor is provably false: its carrier is answerable.
    Refuted {
        refuted: [u8; 32],
        refuter: [u8; 32],
        carrier: Address,
        /// The challenge key this ruling is recorded under.
        adjudication_key: [u8; 32],
    },
    /// Nothing follows; the state must not move.
    Refused(Refusal),
}

/// Why a witness did not decide anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The two records are about different domains.
    CrossDomain,
    /// The two records are from different adapters.
    CrossAdapter,
    /// Evidence-format versions differ; each version is its own rule set.
    VersionMismatch,
    /// The successor is not the immediate successor, so no parent is bound.
    NotAdjacent { successor: u64, predecessor: u64 },
    /// The adapter binds no parent digest, so ancestry cannot be proved.
    NoParentBinding,
    /// The predecessor attested no block digest.
    NoBlockBinding,
    /// The successor's parent equals the predecessor's block: no contradiction.
    NoContradiction,
    /// The carrier would be challenging itself.
    SelfChallenge,
    /// This pair already decided once.
    AlreadyAdjudicated,
    /// The challenger is the zero address; an anonymous slash has no payer of
    /// record and no reward to pay.
    AnonymousChallenger,
}

impl Refusal {
    /// A stable, human-readable reason. Stable because it is folded into log
    /// lines and refusal counters that operators query over time.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::CrossDomain => "records belong to different domains",
            Self::CrossAdapter => "records come from different adapters",
            Self::VersionMismatch => "evidence format versions differ",
            Self::NotAdjacent { .. } => "successor is not the immediate next height",
            Self::NoParentBinding => "adapter binds no parent digest",
            Self::NoBlockBinding => "predecessor attested no block digest",
            Self::NoContradiction => "successor descends from the attested block",
            Self::SelfChallenge => "a carrier cannot challenge itself",
            Self::AlreadyAdjudicated => "this witness pair already decided",
            Self::AnonymousChallenger => "challenger cannot be the zero address",
        }
    }
}

/// Domain-separated key a ruling is recorded under, so replaying one honest
/// witness cannot slash the same bond twice.
#[must_use]
fn adjudication_key(refuted: &[u8; 32], refuter: &[u8; 32]) -> [u8; 32] {
    // Sorted, so `(a, b)` and `(b, a)` are the same key: a challenger must not
    // be able to present the same witness in the other order and slash again.
    let (first, second) = if refuted <= refuter {
        (refuted, refuter)
    } else {
        (refuter, refuted)
    };
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_EXT_ANCESTRY_ADJUDICATION_V1",
        first.as_slice(),
        second.as_slice(),
    ])
}

/// Rule on a successor witness against the accepted slot it descends from.
///
/// `already_decided` holds the adjudication keys this domain has ruled on.
/// Passing it in keeps this function pure; the state layer owns the set.
#[must_use]
pub fn adjudicate(
    successor: &SuccessorView,
    predecessor: &BookSlot,
    challenger: Address,
    already_decided: &BTreeSet<[u8; 32]>,
) -> Ruling {
    if challenger == Address::zero() {
        return Ruling::Refused(Refusal::AnonymousChallenger);
    }
    if successor.domain != predecessor.domain {
        return Ruling::Refused(Refusal::CrossDomain);
    }
    if successor.adapter != predecessor.adapter {
        return Ruling::Refused(Refusal::CrossAdapter);
    }
    if successor.evidence_version != predecessor.evidence_version {
        return Ruling::Refused(Refusal::VersionMismatch);
    }
    // `checked_add`, not `saturating_add`: a predecessor at `u64::MAX` has no
    // successor at all, and saturating would make one at `u64::MAX` look
    // adjacent to it. A witness that only exists because arithmetic wrapped is
    // not a witness.
    if predecessor.height.checked_add(1) != Some(successor.height) {
        return Ruling::Refused(Refusal::NotAdjacent {
            successor: successor.height,
            predecessor: predecessor.height,
        });
    }
    if successor.carrier == predecessor.carrier {
        return Ruling::Refused(Refusal::SelfChallenge);
    }
    let key = adjudication_key(&predecessor.evidence_digest, &successor.evidence_digest);
    if already_decided.contains(&key) {
        return Ruling::Refused(Refusal::AlreadyAdjudicated);
    }
    let Some(parent) = successor.attested_parent else {
        return Ruling::Refused(Refusal::NoParentBinding);
    };
    let Some(block) = predecessor.attested_block_hash else {
        return Ruling::Refused(Refusal::NoBlockBinding);
    };
    if parent == block {
        return Ruling::Refused(Refusal::NoContradiction);
    }
    Ruling::Refuted {
        refuted: predecessor.evidence_digest,
        refuter: successor.evidence_digest,
        carrier: predecessor.carrier,
        adjudication_key: key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::from([byte; 32])
    }

    fn slot(height: u64, digest: u8, block: u8) -> BookSlot {
        BookSlot {
            domain: DomainKey([7u8; 32]),
            adapter: AdapterId([9u8; 32]),
            height,
            evidence_version: 2,
            evidence_digest: [digest; 32],
            carrier: addr(0x11),
            attested_block_hash: Some([block; 32]),
        }
    }

    fn successor(height: u64, digest: u8, parent: u8) -> SuccessorView {
        SuccessorView {
            domain: DomainKey([7u8; 32]),
            adapter: AdapterId([9u8; 32]),
            height,
            evidence_version: 2,
            evidence_digest: [digest; 32],
            carrier: addr(0x22),
            attested_parent: Some([parent; 32]),
        }
    }

    /// The slice's reason to exist: a slot left behind by a deeper branch is
    /// refutable from the record, and the carrier of that slot is named.
    #[test]
    fn ancestry_refutes_abandoned_branch_attestation() {
        let decided = BTreeSet::new();
        let earlier = slot(100, 0xAA, 0xB1);
        let later = successor(101, 0xBB, 0xB2);
        let ruling = adjudicate(&later, &earlier, addr(0x42), &decided);
        let Ruling::Refuted {
            refuted,
            refuter,
            carrier,
            adjudication_key: key,
        } = ruling
        else {
            panic!("abandoned branch must be refuted, got {ruling:?}");
        };
        assert_eq!(refuted, [0xAA; 32]);
        assert_eq!(refuter, [0xBB; 32]);
        assert_eq!(carrier, addr(0x11));
        assert_eq!(key, adjudication_key(&[0xAA; 32], &[0xBB; 32]));
    }

    /// The rule that protects honest carriers: a successor that descends from
    /// the attested block proves nothing, and must not move state.
    #[test]
    fn ancestry_equal_parent_is_no_contradiction() {
        let earlier = slot(100, 0xAA, 0xB1);
        let later = successor(101, 0xBB, 0xB1);
        assert_eq!(
            adjudicate(&later, &earlier, addr(0x42), &BTreeSet::new()),
            Ruling::Refused(Refusal::NoContradiction)
        );
    }

    /// A witness from any other height is not a parent witness.
    #[test]
    fn ancestry_refuses_non_adjacent_successor() {
        let earlier = slot(100, 0xAA, 0xB1);
        let far = successor(140, 0xBB, 0xB2);
        assert_eq!(
            adjudicate(&far, &earlier, addr(0x42), &BTreeSet::new()),
            Ruling::Refused(Refusal::NotAdjacent {
                successor: 140,
                predecessor: 100
            })
        );
        let same = successor(100, 0xBB, 0xB2);
        assert_eq!(
            adjudicate(&same, &earlier, addr(0x42), &BTreeSet::new()),
            Ruling::Refused(Refusal::NotAdjacent {
                successor: 100,
                predecessor: 100
            })
        );
    }

    /// No parent binding means no ancestry claim. Refusing here is the whole
    /// difference between a proof and an inference.
    #[test]
    fn ancestry_refuses_missing_parent_binding() {
        let earlier = slot(100, 0xAA, 0xB1);
        let mut later = successor(101, 0xBB, 0xB2);
        later.attested_parent = None;
        assert_eq!(
            adjudicate(&later, &earlier, addr(0x42), &BTreeSet::new()),
            Ruling::Refused(Refusal::NoParentBinding)
        );
        let mut no_block = slot(100, 0xAA, 0xB1);
        no_block.attested_block_hash = None;
        assert_eq!(
            adjudicate(
                &successor(101, 0xBB, 0xB2),
                &no_block,
                addr(0x42),
                &BTreeSet::new()
            ),
            Ruling::Refused(Refusal::NoBlockBinding)
        );
    }

    /// Domain, adapter and format version are all part of the rule set; a
    /// witness from one of them says nothing about another.
    #[test]
    fn ancestry_refuses_cross_domain_adapter_and_version() {
        let earlier = slot(100, 0xAA, 0xB1);
        let mut other_domain = successor(101, 0xBB, 0xB2);
        other_domain.domain = DomainKey([8u8; 32]);
        assert_eq!(
            adjudicate(&other_domain, &earlier, addr(0x42), &BTreeSet::new()),
            Ruling::Refused(Refusal::CrossDomain)
        );
        let mut other_adapter = successor(101, 0xBB, 0xB2);
        other_adapter.adapter = AdapterId([0x0A; 32]);
        assert_eq!(
            adjudicate(&other_adapter, &earlier, addr(0x42), &BTreeSet::new()),
            Ruling::Refused(Refusal::CrossAdapter)
        );
        let mut other_version = successor(101, 0xBB, 0xB2);
        other_version.evidence_version = 3;
        assert_eq!(
            adjudicate(&other_version, &earlier, addr(0x42), &BTreeSet::new()),
            Ruling::Refused(Refusal::VersionMismatch)
        );
    }

    /// A carrier cannot refute itself, and an anonymous challenger cannot
    /// collect a reward.
    #[test]
    fn ancestry_refuses_self_and_anonymous_challenges() {
        let earlier = slot(100, 0xAA, 0xB1);
        let mut later = successor(101, 0xBB, 0xB2);
        later.carrier = addr(0x11);
        assert_eq!(
            adjudicate(&later, &earlier, addr(0x42), &BTreeSet::new()),
            Ruling::Refused(Refusal::SelfChallenge)
        );
        assert_eq!(
            adjudicate(
                &successor(101, 0xBB, 0xB2),
                &earlier,
                Address::zero(),
                &BTreeSet::new()
            ),
            Ruling::Refused(Refusal::AnonymousChallenger)
        );
    }

    /// One witness pair decides once, in either order, so a bond cannot be
    /// drained by replaying the same honest witness.
    #[test]
    fn ancestry_adjudication_is_idempotent_in_both_orders() {
        let mut decided = BTreeSet::new();
        let earlier = slot(100, 0xAA, 0xB1);
        let later = successor(101, 0xBB, 0xB2);
        let first = adjudicate(&later, &earlier, addr(0x42), &decided);
        let Ruling::Refuted {
            adjudication_key: key,
            ..
        } = first
        else {
            panic!("first witness must refute");
        };
        assert_eq!(key, adjudication_key(&[0xBB; 32], &[0xAA; 32]));
        decided.insert(key);
        assert_eq!(
            adjudicate(&later, &earlier, addr(0x43), &decided),
            Ruling::Refused(Refusal::AlreadyAdjudicated)
        );
        // The key is order-independent: presenting the pair the other way
        // round must not decide it a second time.
        assert_eq!(
            adjudication_key(&[0xAA; 32], &[0xBB; 32]),
            adjudication_key(&[0xBB; 32], &[0xAA; 32])
        );
    }

    /// Heights near the integer edges must refuse, not wrap into adjacency.
    #[test]
    fn ancestry_height_arithmetic_never_wraps() {
        let mut edge = slot(u64::MAX, 0xAA, 0xB1);
        edge.height = u64::MAX - 1;
        let later = successor(u64::MAX, 0xBB, 0xB2);
        assert!(matches!(
            adjudicate(&later, &edge, addr(0x42), &BTreeSet::new()),
            Ruling::Refuted { .. }
        ));
        // A predecessor at the maximum height has no successor at all.
        let top = slot(u64::MAX, 0xAA, 0xB1);
        assert!(matches!(
            adjudicate(&later, &top, addr(0x42), &BTreeSet::new()),
            Ruling::Refused(Refusal::NotAdjacent { .. })
        ));
    }
}
