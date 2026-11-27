//! Bundles: one atomic ask across several chains, instead of one intent per chain.
//!
//! # Why this exists
//!
//! A [`UserIntent`] names exactly one `source_domain` and one `target_domain`.
//! That is the right shape for "move my money from A to B", and it is the wrong
//! shape for almost everything a user actually wants to do across a portfolio:
//!
//! - "Sell this on A **and** buy that on B, or do neither."
//! - "Pay on three chains inside one budget."
//! - "Rebalance: this much off C, this much onto D, one fee for both."
//!
//! Today each of those is N separate intents, each with its own escrow, its own
//! deadline and its own settlement. They can land in any order, half of them can
//! fill and half expire, and the user carries the risk of the gap. The
//! directive calls this out directly: `docs` and `settlement/domains.rs` both
//! describe `RelayerIntent` as per-chain, and the "single trade, many chains"
//! leg of the unification has nowhere to live.
//!
//! A bundle is that nowhere. It is a set of legs that are **all or nothing**:
//! they settle together or they refund together, and a solver that fills one
//! leg is paid only when the whole bundle completes.
//!
//! # What makes it atomic without a coordinator
//!
//! The bundle commits to every leg's `intent_id` before any leg moves, so the
//! id of the bundle is a function of decisions the owner already froze. Every
//! leg is escrowed at `Open`, the bundle's completion is a single condition
//! over the legs' settlement records, and refund is the same condition negated.
//! There is no window in which one leg is settled and another is refunded,
//! because neither transition is available until the whole set is decided.
//!
//! This is deliberately *not* a new consensus mechanism. It is a bookkeeping
//! rule over intents the chain already knows how to settle, which is why it can
//! be checked by any node from state alone.
//!
//! # What this is not
//!
//! It is not a solver. It does not price anything, and it does not decide which
//! chain a leg runs on beyond what the legs themselves said. It is the
//! *container* that makes "one trade across many chains" expressible; the
//! pricing question stays with the existing per-leg auction.

use crate::core::address::Address;
use crate::relayer::policy::UserIntent;
use sha2::{Digest, Sha256};

/// Domain tag of a bundle id.
pub const BUNDLE_DOMAIN: &[u8] = b"BDLM_INTENT_BUNDLE_V1";

/// Most legs one bundle may carry.
///
/// A bundle is escrowed and settled as a unit, so this is a bound on the work
/// one transaction can ask the chain to do - not on how many chains a user may
/// ever touch. Sixteen is the same order as the claim-reference ceiling and is
/// well past what any real rebalance needs.
pub const MAX_BUNDLE_LEGS: usize = 16;

/// Why a bundle was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BundleError {
    /// A bundle with no legs would settle vacuously.
    #[error("a bundle must carry at least one leg")]
    Empty,
    /// More legs than the ceiling.
    #[error("a bundle carries {0} legs, more than {MAX_BUNDLE_LEGS}")]
    TooManyLegs(usize),
    /// Two legs with the same id would make "all settled" ambiguous.
    #[error("two legs name the same intent id")]
    DuplicateLeg,
    /// The legs do not all belong to the bundle's owner.
    #[error("leg {index} is owned by another account")]
    NotTheOwner {
        /// Index of the offending leg.
        index: usize,
    },
    /// Two legs touch the same domain pair with the same action, so the bundle
    /// could be satisfied by settling one of them twice.
    #[error("legs {a} and {b} are interchangeable")]
    AmbiguousLegs {
        /// First leg index.
        a: usize,
        /// Second leg index.
        b: usize,
    },
    /// The bundle id does not match its contents.
    #[error("bundle id does not match its legs")]
    IdMismatch,
}

/// Canonical bytes of an action, for comparing two legs.
///
/// The action is compared by its encoding rather than by `==` because it
/// carries a `String` target address and the chain compares actions by their
/// canonical bytes everywhere else (see `encode_action`). Reusing the same
/// field order here is what keeps the two comparisons from disagreeing.
fn action_bytes(action: &crate::relayer::policy::RelayerActionKind) -> [u8; 32] {
    use crate::relayer::policy::RelayerActionKind;
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_RELAYER_ACTION_CMP_V1");
    match action {
        RelayerActionKind::ExternalTransaction {
            chain,
            target_address,
            payload_hash,
        } => {
            hasher.update([0u8]);
            hasher.update(format!("{chain:?}").as_bytes());
            hasher.update((target_address.len() as u64).to_le_bytes());
            hasher.update(target_address.as_bytes());
            hasher.update(payload_hash);
        }
        RelayerActionKind::DwebResolve { name } => {
            hasher.update([1u8]);
            hasher.update((name.len() as u64).to_le_bytes());
            hasher.update(name.as_bytes());
        }
        RelayerActionKind::PollenRead { asset_id, grant_id } => {
            hasher.update([2u8]);
            hasher.update(asset_id.0);
            hasher.update(grant_id.0);
        }
    }
    hasher.finalize().into()
}

/// A set of intents that settle together or refund together.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IntentBundle {
    /// The account that owns every leg.
    pub owner: Address,
    /// The legs, in the order the owner wrote them. Order is not semantic; it
    /// is part of the id so a bundle cannot be reordered under its owner.
    pub legs: Vec<UserIntent>,
    /// Block after which the whole bundle expires.
    ///
    /// A bundle's deadline is its own, not the minimum of its legs': a leg
    /// that expires early would otherwise silently shorten a bundle the owner
    /// gave more time to.
    pub deadline_block: u64,
    /// Ceiling on the sum of every leg's `max_fee`, in attoBUD.
    ///
    /// This is the number the owner actually budgets. It is separate from the
    /// legs' individual fees because a solver's total take is what the owner
    /// cares about, and summing per-leg fees at settlement time is the only
    /// place it can be enforced atomically.
    pub max_total_fee: u64,
    /// The bundle's identifier, a function of everything above.
    pub bundle_id: [u8; 32],
}

impl IntentBundle {
    /// Builds a bundle and computes its id.
    ///
    /// Validation is deliberately not part of construction: a bundle assembled
    /// here may be malformed on purpose (a test, a diagnostic), and the checks
    /// that matter run at the door. What construction *does* guarantee is that
    /// the id commits to the legs that were passed.
    #[must_use]
    pub fn new(
        owner: Address,
        legs: Vec<UserIntent>,
        deadline_block: u64,
        max_total_fee: u64,
    ) -> Self {
        let mut bundle = Self {
            owner,
            legs,
            deadline_block,
            max_total_fee,
            bundle_id: [0u8; 32],
        };
        bundle.bundle_id = bundle.calculate_id();
        bundle
    }

    /// The id: owner, deadline, budget, and every leg's id in order.
    ///
    /// Legs contribute their *id*, not their fields, because a leg id already
    /// commits to its own source, target, action, fee, deadline and emitter.
    /// Hashing the id twice would be harmless; rehashing the fields would let
    /// two encodings of the same leg disagree.
    #[must_use]
    pub fn calculate_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(BUNDLE_DOMAIN);
        hasher.update(self.owner.as_bytes());
        hasher.update(self.deadline_block.to_le_bytes());
        hasher.update(self.max_total_fee.to_le_bytes());
        // The leg count goes in before the legs so a bundle of two cannot
        // collide with a bundle of three whose first two legs match.
        hasher.update(
            u32::try_from(self.legs.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        for leg in &self.legs {
            hasher.update(leg.intent_id);
        }
        hasher.finalize().into()
    }

    /// Whether `bundle_id` is the id of these contents.
    #[must_use]
    pub fn verify_id(&self) -> bool {
        self.bundle_id == self.calculate_id()
    }

    /// The bundle's own rules, checked before any leg is looked at.
    ///
    /// These are the failures a bundle can have that no individual leg can:
    /// being empty, being too large, naming the same leg twice, mixing owners,
    /// or carrying two legs that a solver could satisfy interchangeably.
    ///
    /// # Errors
    ///
    /// The first [`BundleError`] that applies.
    pub fn validate_shape(&self) -> Result<(), BundleError> {
        if self.legs.is_empty() {
            return Err(BundleError::Empty);
        }
        if self.legs.len() > MAX_BUNDLE_LEGS {
            return Err(BundleError::TooManyLegs(self.legs.len()));
        }
        if !self.verify_id() {
            return Err(BundleError::IdMismatch);
        }

        for (index, leg) in self.legs.iter().enumerate() {
            if leg.owner != self.owner {
                return Err(BundleError::NotTheOwner { index });
            }
        }

        for (i, a) in self.legs.iter().enumerate() {
            for (j, b) in self.legs.iter().enumerate().skip(i + 1) {
                if a.intent_id == b.intent_id {
                    return Err(BundleError::DuplicateLeg);
                }
                // Two legs with the same source, target and action are
                // interchangeable: a solver that settles one of them twice
                // would satisfy the "all legs settled" condition with work done
                // once. The action is compared through its encoding rather than
                // its `==` because it carries a `String` target address and the
                // chain compares actions by their canonical bytes everywhere
                // else.
                if a.source_domain == b.source_domain
                    && a.target_domain == b.target_domain
                    && action_bytes(&a.action) == action_bytes(&b.action)
                {
                    return Err(BundleError::AmbiguousLegs { a: i, b: j });
                }
            }
        }
        Ok(())
    }

    /// The total fee the owner is on the hook for if every leg fills.
    ///
    /// Saturating: a sum that overflows is larger than any budget, and
    /// `budget_covers_fees` refuses it rather than wrapping to a small number
    /// that would look affordable.
    #[must_use]
    pub fn total_max_fee(&self) -> u64 {
        self.legs
            .iter()
            .fold(0u64, |acc, leg| acc.saturating_add(leg.max_fee))
    }

    /// Whether the legs' fees fit inside the bundle's budget.
    #[must_use]
    pub fn budget_covers_fees(&self) -> bool {
        self.total_max_fee() <= self.max_total_fee
    }

    /// The domains this bundle touches, deduplicated and ordered.
    ///
    /// A caller that wants to know "which chains does this trade need" reads
    /// this; a bundle that touches one domain is legal and means a same-chain
    /// multi-action, which is why the result is not required to be larger than
    /// one.
    #[must_use]
    pub fn domains(&self) -> Vec<u32> {
        let mut domains: Vec<u32> = Vec::new();
        for leg in &self.legs {
            for d in [leg.source_domain, leg.target_domain] {
                if !domains.contains(&d) {
                    domains.push(d);
                }
            }
        }
        domains
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::transaction::ExternalChain;
    use crate::relayer::policy::RelayerActionKind;

    fn owner() -> Address {
        Address::from([0xA1; 32])
    }

    fn intent(src: u32, tgt: u32, amount_hint: u8, fee: u64, owner: Address) -> UserIntent {
        UserIntent::new(
            owner,
            src,
            tgt,
            RelayerActionKind::ExternalTransaction {
                chain: ExternalChain::Ethereum,
                target_address: format!("0x{amount_hint:02x}"),
                payload_hash: [amount_hint; 32],
            },
            fee,
            1_000,
            u64::from(amount_hint),
            [0x11; 32],
            Address::from([0xB2; 32]),
        )
    }

    /// A bundle's id commits to every leg, so reordering or swapping a leg is a
    /// different bundle and the old id no longer verifies.
    #[test]
    fn the_bundle_id_commits_to_every_leg_in_order() {
        let a = intent(1, 2, 0x01, 100, owner());
        let b = intent(2, 3, 0x02, 200, owner());

        let bundle = IntentBundle::new(owner(), vec![a.clone(), b.clone()], 500, 400);
        assert!(bundle.verify_id());

        // Same legs, other order.
        let swapped = IntentBundle::new(owner(), vec![b.clone(), a.clone()], 500, 400);
        assert_ne!(
            bundle.bundle_id, swapped.bundle_id,
            "reordering the legs left the id unchanged"
        );

        // Same legs, a different budget.
        let richer = IntentBundle::new(owner(), vec![a, b], 500, 401);
        assert_ne!(
            bundle.bundle_id, richer.bundle_id,
            "the budget did not enter the bundle id"
        );
    }

    /// Two interchangeable legs would let one piece of work satisfy two slots.
    #[test]
    fn interchangeable_legs_are_refused() {
        let a = intent(1, 2, 0x01, 100, owner());
        // Same source, target, action and fee - the only difference is the
        // replay nonce, which is exactly the shape a solver could fill twice.
        let mut b = intent(1, 2, 0x01, 100, owner());
        b.replay_nonce = 99;
        b.intent_id = b.calculate_id();
        assert_ne!(a.intent_id, b.intent_id, "the fixture legs must differ");

        let bundle = IntentBundle::new(owner(), vec![a, b], 500, 400);
        assert_eq!(
            bundle.validate_shape(),
            Err(BundleError::AmbiguousLegs { a: 0, b: 1 }),
            "two interchangeable legs were accepted"
        );
    }

    /// A leg owned by somebody else cannot ride in another account's bundle.
    #[test]
    fn a_foreign_leg_is_refused() {
        let mine = intent(1, 2, 0x01, 100, owner());
        let theirs = intent(3, 4, 0x02, 100, Address::from([0xC3; 32]));
        let bundle = IntentBundle::new(owner(), vec![mine, theirs], 500, 400);
        assert_eq!(
            bundle.validate_shape(),
            Err(BundleError::NotTheOwner { index: 1 })
        );
    }

    /// The budget rule: the legs' fees either fit inside the owner's ceiling or
    /// the bundle is refused, and an overflowing sum is refused rather than
    /// wrapping to something that looks affordable.
    #[test]
    fn the_budget_is_a_ceiling_on_the_sum_not_a_per_leg_check() {
        let a = intent(1, 2, 0x01, 100, owner());
        let b = intent(2, 3, 0x02, 200, owner());

        let fitting = IntentBundle::new(owner(), vec![a.clone(), b.clone()], 500, 300);
        assert_eq!(fitting.total_max_fee(), 300);
        assert!(fitting.budget_covers_fees());

        let tight = IntentBundle::new(owner(), vec![a.clone(), b.clone()], 500, 299);
        assert!(
            !tight.budget_covers_fees(),
            "a 299 budget covered 300 of legs"
        );

        // Each leg fits on its own; the sum does not. This is the case a
        // per-leg check would wave through.
        let mut huge = intent(4, 5, 0x03, u64::MAX, owner());
        huge.max_fee = u64::MAX;
        huge.intent_id = huge.calculate_id();
        let mut huge2 = intent(6, 7, 0x04, u64::MAX, owner());
        huge2.max_fee = u64::MAX;
        huge2.intent_id = huge2.calculate_id();
        let overflowing = IntentBundle::new(owner(), vec![huge, huge2], 500, u64::MAX);
        assert_eq!(
            overflowing.total_max_fee(),
            u64::MAX,
            "the sum wrapped instead of saturating"
        );
        assert!(
            !overflowing.budget_covers_fees(),
            "an overflowing fee sum fit inside the budget"
        );
    }

    /// The domains a bundle touches are all of them, once each.
    #[test]
    fn the_domains_are_the_union_of_every_leg() {
        let bundle = IntentBundle::new(
            owner(),
            vec![
                intent(1, 2, 0x01, 100, owner()),
                intent(2, 3, 0x02, 100, owner()),
            ],
            500,
            400,
        );
        assert_eq!(bundle.domains(), vec![1, 2, 3]);
    }

    /// Empty and oversized bundles are refused before any leg is read.
    #[test]
    fn the_shape_rules_refuse_empty_and_oversized_bundles() {
        let empty = IntentBundle::new(owner(), Vec::new(), 500, 0);
        assert_eq!(empty.validate_shape(), Err(BundleError::Empty));

        let many: Vec<UserIntent> = (0..=MAX_BUNDLE_LEGS as u8)
            .map(|i| intent(u32::from(i) + 1, u32::from(i) + 2, i, 1, owner()))
            .collect();
        assert!(many.len() > MAX_BUNDLE_LEGS);
        let oversized = IntentBundle::new(owner(), many, 500, 1_000);
        assert!(matches!(
            oversized.validate_shape(),
            Err(BundleError::TooManyLegs(_))
        ));
    }
}

/// What a bundle looks like from the chain's point of view, given its legs.
///
/// A bundle is not a new ledger: its state is a *function of* the legs it binds,
/// which is why this is derived rather than stored. Storing a status would mean
/// two places to disagree - the bundle says "settled" while a leg says "open" -
/// and one of them would eventually be wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleStatus {
    /// At least one leg is still open and none has expired: the bundle is live.
    Open,
    /// Every leg is settled: the bundle completed and its escrow is paid out.
    Complete,
    /// A leg expired before the bundle completed: every leg must refund.
    ///
    /// All-or-nothing means this is not "the settled ones stay settled". If one
    /// leg cannot happen, none of them happened as far as the owner is
    /// concerned, and the bundle is refunded as a unit.
    Refund,
}

/// Decides a bundle's state from the states of its legs.
///
/// `is_settled` and `is_expired` are supplied by the caller because settlement
/// state lives in the relayer policy registry and expiry is a function of the
/// current block; this function is the *rule*, not the lookup.
///
/// The order of the two checks is the whole semantics: **expiry wins**. A bundle
/// with two settled legs and one expired leg refunds, it does not pay out the
/// two. Checking "all settled" first would let a solver fill the easy legs and
/// let the hard one expire - the exact risk the bundle exists to remove.
#[must_use]
pub fn bundle_status<F, G>(bundle: &IntentBundle, is_settled: F, is_expired: G) -> BundleStatus
where
    F: Fn(&[u8; 32]) -> bool,
    G: Fn(&[u8; 32]) -> bool,
{
    if bundle.legs.iter().any(|leg| is_expired(&leg.intent_id)) {
        return BundleStatus::Refund;
    }
    if bundle.legs.iter().all(|leg| is_settled(&leg.intent_id)) {
        return BundleStatus::Complete;
    }
    BundleStatus::Open
}

#[cfg(test)]
mod status_tests {
    use super::*;

    fn owner() -> Address {
        Address::from([0xA1; 32])
    }

    fn leg(tag: u8) -> UserIntent {
        UserIntent::new(
            owner(),
            u32::from(tag),
            u32::from(tag) + 1,
            crate::relayer::policy::RelayerActionKind::DwebResolve {
                name: format!("leg-{tag}"),
            },
            100,
            1_000,
            u64::from(tag),
            [0x11; 32],
            Address::from([0xB2; 32]),
        )
    }

    /// Expiry beats settlement: two settled legs and one expired leg refunds,
    /// it does not pay out the two. This is the incentive the bundle exists to
    /// create - a solver cannot fill the easy legs and let the hard one lapse.
    #[test]
    fn expiry_wins_over_partial_settlement() {
        let (a, b, c) = (leg(1), leg(2), leg(3));
        let bundle = IntentBundle::new(owner(), vec![a.clone(), b.clone(), c.clone()], 500, 400);

        let settled = |id: &[u8; 32]| *id == a.intent_id || *id == b.intent_id;
        let expired = |id: &[u8; 32]| *id == c.intent_id;

        assert_eq!(
            bundle_status(&bundle, settled, expired),
            BundleStatus::Refund,
            "a partially settled bundle with an expired leg paid out"
        );
    }

    /// A bundle completes only when every leg settled; nothing less counts.
    #[test]
    fn a_bundle_completes_only_when_every_leg_settled() {
        let (a, b) = (leg(1), leg(2));
        let bundle = IntentBundle::new(owner(), vec![a.clone(), b.clone()], 500, 400);

        let none = |_: &[u8; 32]| false;
        assert_eq!(
            bundle_status(&bundle, none, none),
            BundleStatus::Open,
            "an untouched bundle was not open"
        );

        let only_a = |id: &[u8; 32]| *id == a.intent_id;
        assert_eq!(
            bundle_status(&bundle, only_a, none),
            BundleStatus::Open,
            "one settled leg completed the bundle"
        );

        let both = |_: &[u8; 32]| true;
        assert_eq!(
            bundle_status(&bundle, both, none),
            BundleStatus::Complete,
            "all legs settled did not complete the bundle"
        );
    }
}
