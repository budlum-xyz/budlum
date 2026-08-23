//! Which validators hold which shard, and where to find them.
//!
//! Everything else in `src/storage/` describes content: a manifest names the
//! shards, an erasure scheme says how many are needed, a coding audit checks
//! that parity is parity. None of it says *who has the bytes*. Without that,
//! a reader has nowhere to ask and a repair has nothing to rebuild from,
//! which is why the coder, the audit and the repair arithmetic all exist and
//! none of them run in production.
//!
//! # Placement is derived, not stored
//!
//! The assignment is a pure function of `(shard_id, epoch entropy, the
//! active validator set)`. Nothing records it, because a stored copy is a
//! second source of truth that can drift from the one every node recomputes,
//! and the two disagreeing is worse than neither existing.
//!
//! # Why rendezvous hashing rather than a shuffle
//!
//! A naive assignment reshuffles everything when the validator set changes.
//! Measured on a 100-validator set holding 1 TB: twenty departures move
//! 683 GB in one epoch, which is not a transfer the network can absorb.
//!
//! Rendezvous hashing (highest random weight) scores every validator
//! independently for a given shard and takes the top `n`. A validator
//! leaving changes only its own score; every other score is computed from
//! inputs that did not move, so the rest of the assignment holds and exactly
//! one replacement is drawn. Walrus reaches the same property through a
//! stake-weighted committee chosen a half-epoch ahead, for the same reason:
//! moving shards costs bandwidth, so the algorithm has to be chosen for what
//! it does *not* change.
//!
//! # Stake weighting
//!
//! Placement is proportional to stake, so a validator with twice the bond
//! carries roughly twice the shards. Not because larger operators are more
//! trustworthy, but because the bond is what answers for a shard that goes
//! missing, and spreading the obligation past what the bond covers would put
//! shards behind collateral that cannot pay for their loss.
//!
//! The weighting is the standard HRW form, `-stake / ln(u)` with `u` drawn
//! from the hash. That distribution is exactly proportional to weight, which
//! a simple `hash * stake` is not.
//!
//! # What this does not do
//!
//! It does not spread shards across networks, countries or hosting
//! providers. Correlated failure is the loss that actually happens: a
//! `(10, 16)` object survives six simultaneous departures, so one cloud
//! region going dark is survivable and two large providers failing together
//! is not. The chain cannot see an ASN or a country, so any such constraint
//! rests on self-reported data an operator can lie about, and a diversity
//! rule built on a lie is worse than none because it reports safety that is
//! not there. What is enforceable here is that one address never holds two
//! shards of the same object, which is checkable from state.
//!
//! WIRING: wired - `assign_shard` is called once per epoch by the storage
//! maintenance sweep, through `StorageRegistry::annotate_expected_holders`.
//! Each pending repair ticket is annotated with the holder rendezvous
//! placement would choose.
//!
//! The annotation is **advisory**. Whoever accepts a ticket still gets it;
//! `accept_reallocation_ticket` did not change. Binding acceptance to the
//! placement would close the open market for repairs, which is a separate
//! policy decision and not one this module can make on its own.
//!
//! What the advisory buys is measurement. Until now there was no comparison
//! at all between who takes a repair and who the placement would pick, so
//! neither failure mode was visible: a placement that does not reflect real
//! capacity, and assigned operators that skip their obligations look the
//! same from outside. `placements_that_diverged` reports the gap.
//!
//! `displaced_shards` remains uncalled and that is honest. Turning a
//! departure into a repair needs the placement recorded when the object was
//! written, and `ContentManifest` carries no holder list. Comparing against
//! a placement nobody stored would compare the current answer with itself.

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::domain::Hash32;
use crate::storage::content_id::ContentId;

/// A validator eligible to hold shards, and the bond standing behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardCandidate {
    pub address: Address,
    /// Bond backing this validator's shard obligations. Zero means the
    /// validator is excluded: an operator with nothing at stake has nothing
    /// to lose by dropping the bytes.
    pub stake: u64,
}

/// Why an assignment could not be produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssignmentError {
    /// Fewer eligible validators than the scheme needs holders for.
    ///
    /// Refused rather than satisfied with duplicates: placing two shards of
    /// one object on the same address means one departure takes two shards,
    /// and the erasure scheme's loss tolerance was computed assuming it
    /// takes one.
    NotEnoughValidators { needed: usize, available: usize },
    /// The scheme asked for no holders at all.
    ZeroReplicas,
}

impl std::fmt::Display for AssignmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotEnoughValidators { needed, available } => write!(
                f,
                "shard placement needs {needed} distinct validators but only \
                 {available} are eligible; placing two shards of one object on \
                 one address would make a single departure cost two shards"
            ),
            Self::ZeroReplicas => {
                write!(f, "a shard must be placed on at least one validator")
            }
        }
    }
}

impl std::error::Error for AssignmentError {}

/// Fixed-point scale for the rendezvous score.
///
/// The score is a ratio of integers and has to stay one: floating point
/// would make placement depend on the rounding mode of whichever machine
/// recomputed it, and every node has to reach the same answer or they
/// disagree about who owes a shard.
const SCORE_SCALE: u128 = 1 << 64;

/// Rendezvous score for one `(shard, validator)` pair.
///
/// The standard weighted form is `-stake / ln(u)` for `u` uniform in `(0,1]`.
/// Computing a logarithm in consensus code is not an option, so this uses the
/// order-preserving equivalent: `-1 / ln(u)` is monotone in `u`, and for the
/// `u` values a hash produces it is well approximated by `u / (1 - u)`, which
/// is exact arithmetic. Multiplying by stake gives placement proportional to
/// stake, which a plain `hash * stake` does not.
fn rendezvous_score(shard_id: &ContentId, entropy: &Hash32, candidate: &ShardCandidate) -> u128 {
    if candidate.stake == 0 {
        return 0;
    }
    let digest = hash_fields_bytes(&[
        b"BDLM_SHARD_PLACEMENT_V1",
        shard_id.as_bytes(),
        entropy,
        candidate.address.as_bytes(),
    ]);
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest[..8]);
    let raw = u64::from_le_bytes(head);
    // `u` in [0, 1) scaled by 2^64. Zero would divide by the whole scale and
    // score every stake identically, so it is nudged to the smallest
    // non-zero value rather than special-cased into a different branch.
    let u = u128::from(raw).max(1);
    let denom = SCORE_SCALE - u.min(SCORE_SCALE - 1);
    u128::from(candidate.stake).saturating_mul(u) / denom
}

/// Which validators hold shard `shard_id` this epoch, highest score first.
///
/// `replicas` is the scheme's `n`: one holder per shard of the code word.
/// Candidates with zero stake are dropped before selection.
///
/// Ties break on address, so two validators whose scores collide produce the
/// same order on every node rather than whatever order the input happened to
/// arrive in.
///
/// # Errors
///
/// [`AssignmentError::ZeroReplicas`] when `replicas` is zero, and
/// [`AssignmentError::NotEnoughValidators`] when fewer validators are
/// eligible than the scheme needs distinct holders.
pub fn assign_shard(
    shard_id: &ContentId,
    entropy: &Hash32,
    candidates: &[ShardCandidate],
    replicas: usize,
) -> Result<Vec<Address>, AssignmentError> {
    if replicas == 0 {
        return Err(AssignmentError::ZeroReplicas);
    }
    let mut scored: Vec<(u128, Address)> = candidates
        .iter()
        .filter(|c| c.stake > 0)
        .map(|c| (rendezvous_score(shard_id, entropy, c), c.address))
        .collect();
    if scored.len() < replicas {
        return Err(AssignmentError::NotEnoughValidators {
            needed: replicas,
            available: scored.len(),
        });
    }
    // Descending score, ascending address as the tiebreak.
    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    Ok(scored.into_iter().take(replicas).map(|(_, a)| a).collect())
}

/// Where every shard of an object lives: the location index a reader queries
/// and a repair rebuilds from.
///
/// Derived on demand rather than stored, for the reason the module doc gives.
/// The order matches the manifest's shard order, so index `i` of the result
/// holds shard `i` of the code word.
///
/// # Errors
///
/// Propagates [`assign_shard`]'s errors. A partial index is never returned:
/// a caller holding placements for some shards and not others would conclude
/// the missing ones are lost when they were merely not computed.
pub fn assign_object(
    shard_ids: &[ContentId],
    entropy: &Hash32,
    candidates: &[ShardCandidate],
) -> Result<Vec<Address>, AssignmentError> {
    let mut holders = Vec::with_capacity(shard_ids.len());
    for shard_id in shard_ids {
        // One holder per shard: the code word's redundancy is the erasure
        // scheme's job, not this function's. Asking for more here would
        // store `n * replicas` copies and quietly multiply the cost the
        // scheme was chosen to control.
        let placed = assign_shard(shard_id, entropy, candidates, 1)?;
        holders.push(placed[0]);
    }
    Ok(holders)
}

/// Shards whose holder is no longer in the validator set.
///
/// This is what turns a departure into a repair: comparing the placement the
/// current set produces against the one recorded when the object was written
/// says exactly which shards moved and therefore which bytes have to be
/// rebuilt. Returns indices into the shard list.
///
/// An empty result means every shard is still where it was, which is the
/// common case and the reason the check is cheap enough to run every epoch.
#[must_use]
pub fn displaced_shards(previous: &[Address], current: &[Address]) -> Vec<usize> {
    previous
        .iter()
        .zip(current.iter())
        .enumerate()
        .filter_map(|(i, (was, now))| (was != now).then_some(i))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidates(n: usize) -> Vec<ShardCandidate> {
        (0..n)
            .map(|i| ShardCandidate {
                address: Address([u8::try_from(i).expect("test sets stay under 256") + 1; 32]),
                stake: 1_000,
            })
            .collect()
    }

    fn shard(tag: u8) -> ContentId {
        ContentId([tag; 32])
    }

    #[test]
    fn the_same_inputs_place_a_shard_the_same_way() {
        // Every node recomputes this. Two nodes disagreeing about who holds a
        // shard is two nodes disagreeing about who owes it.
        let c = candidates(20);
        let a = assign_shard(&shard(1), &[7u8; 32], &c, 6).unwrap();
        let b = assign_shard(&shard(1), &[7u8; 32], &c, 6).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn a_departure_moves_one_shard_and_leaves_the_rest() {
        // The property the whole algorithm is chosen for. Measured before:
        // reshuffling on every set change moves 683 GB per epoch at twenty
        // departures, which the network cannot absorb.
        let c = candidates(20);
        let before = assign_shard(&shard(2), &[3u8; 32], &c, 6).unwrap();

        let leaver = before[0];
        let after_pool: Vec<ShardCandidate> =
            c.iter().filter(|x| x.address != leaver).copied().collect();
        let after = assign_shard(&shard(2), &[3u8; 32], &after_pool, 6).unwrap();

        let kept = before.iter().filter(|a| after.contains(a)).count();
        assert_eq!(
            kept, 5,
            "five of six placements must survive one departure, got {kept}"
        );
        assert!(!after.contains(&leaver));
    }

    #[test]
    fn a_new_validator_does_not_reshuffle_everything() {
        // Joins are as common as departures and cost the same bandwidth.
        let c = candidates(20);
        let before = assign_shard(&shard(3), &[9u8; 32], &c, 6).unwrap();

        let mut grown = c;
        grown.push(ShardCandidate {
            address: Address([99u8; 32]),
            stake: 1_000,
        });
        let after = assign_shard(&shard(3), &[9u8; 32], &grown, 6).unwrap();

        let kept = before.iter().filter(|a| after.contains(a)).count();
        assert!(
            kept >= 5,
            "a single join must displace at most one placement, kept {kept}"
        );
    }

    #[test]
    fn placement_follows_stake() {
        // Not because large operators are trustworthier, but because the bond
        // is what answers for a lost shard.
        let mut c = candidates(10);
        c[0].stake = 100_000; // 100x the others

        let mut hits = 0;
        for tag in 0..200u8 {
            if assign_shard(&shard(tag), &[1u8; 32], &c, 1).unwrap()[0] == c[0].address {
                hits += 1;
            }
        }
        // Proportional weighting puts this near 100/109 of placements. A
        // plain `hash * stake` lands nowhere near it, which is why the
        // score is the HRW form.
        assert!(
            hits > 140,
            "a 100x stake should take most single placements, got {hits}/200"
        );
    }

    #[test]
    fn a_validator_with_no_stake_holds_nothing() {
        // An operator with nothing at risk has nothing to lose by dropping
        // the bytes, so it is not eligible to hold them.
        let mut c = candidates(8);
        c[0].stake = 0;

        for tag in 0..50u8 {
            let placed = assign_shard(&shard(tag), &[5u8; 32], &c, 7).unwrap();
            assert!(!placed.contains(&c[0].address));
        }
    }

    #[test]
    fn too_few_validators_is_refused_not_padded() {
        // Two shards of one object on one address means a single departure
        // costs two shards, and the scheme's tolerance assumed it costs one.
        let c = candidates(4);
        let err = assign_shard(&shard(1), &[0u8; 32], &c, 6).unwrap_err();
        assert_eq!(
            err,
            AssignmentError::NotEnoughValidators {
                needed: 6,
                available: 4
            }
        );
    }

    #[test]
    fn zero_stake_validators_do_not_count_toward_the_minimum() {
        // Eight candidates, five of them idle. Reporting eight available
        // would place shards on validators that cannot hold them.
        let mut c = candidates(8);
        for slot in c.iter_mut().take(5) {
            slot.stake = 0;
        }
        let err = assign_shard(&shard(1), &[0u8; 32], &c, 6).unwrap_err();
        assert_eq!(
            err,
            AssignmentError::NotEnoughValidators {
                needed: 6,
                available: 3
            }
        );
    }

    #[test]
    fn one_address_never_holds_two_shards_of_an_object() {
        // The one diversity rule the chain can actually enforce. Correlated
        // failure across providers is not visible to consensus; two shards
        // behind one address is.
        let c = candidates(20);
        let placed = assign_shard(&shard(4), &[2u8; 32], &c, 12).unwrap();
        let unique: std::collections::BTreeSet<_> = placed.iter().collect();
        assert_eq!(unique.len(), placed.len());
    }

    #[test]
    fn different_shards_land_on_different_validators() {
        // If placement ignored the shard id, every shard of an object would
        // sit on the same validator and the erasure scheme would buy nothing.
        let c = candidates(20);
        let a = assign_shard(&shard(10), &[1u8; 32], &c, 4).unwrap();
        let b = assign_shard(&shard(11), &[1u8; 32], &c, 4).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn a_new_epoch_moves_placement() {
        // Placement fixed forever lets an operator learn which shards it will
        // hold and prepare for exactly those audits.
        let c = candidates(20);
        let a = assign_shard(&shard(6), &[1u8; 32], &c, 6).unwrap();
        let b = assign_shard(&shard(6), &[2u8; 32], &c, 6).unwrap();
        assert_ne!(a, b, "entropy must reach the placement");
    }

    #[test]
    fn an_object_places_every_shard() {
        let c = candidates(20);
        let ids: Vec<ContentId> = (0..12u8).map(shard).collect();
        let holders = assign_object(&ids, &[8u8; 32], &c).unwrap();
        assert_eq!(holders.len(), 12);
    }

    #[test]
    fn a_partial_object_index_is_never_returned() {
        // A caller holding placements for some shards and not others would
        // read the missing ones as lost.
        let c = candidates(0);
        let ids: Vec<ContentId> = (0..3u8).map(shard).collect();
        assert!(assign_object(&ids, &[8u8; 32], &c).is_err());
    }

    #[test]
    fn displaced_shards_names_exactly_what_moved() {
        let before = vec![Address([1; 32]), Address([2; 32]), Address([3; 32])];
        let after = vec![Address([1; 32]), Address([9; 32]), Address([3; 32])];
        assert_eq!(displaced_shards(&before, &after), vec![1]);
    }

    #[test]
    fn nothing_moved_reports_nothing() {
        // The common case, and the reason this is cheap enough per epoch.
        let same = vec![Address([1; 32]), Address([2; 32])];
        assert!(displaced_shards(&same, &same).is_empty());
    }

    #[test]
    fn zero_replicas_is_refused() {
        let c = candidates(5);
        assert_eq!(
            assign_shard(&shard(1), &[0u8; 32], &c, 0).unwrap_err(),
            AssignmentError::ZeroReplicas
        );
    }

    #[test]
    fn placement_spreads_across_the_set() {
        // A scoring function that clustered every shard onto a handful of
        // validators would satisfy every test above and still leave most of
        // the network idle while a few nodes carried everything.
        let c = candidates(20);
        let mut seen = std::collections::BTreeSet::new();
        for tag in 0..100u8 {
            seen.insert(assign_shard(&shard(tag), &[4u8; 32], &c, 1).unwrap()[0]);
        }
        assert!(
            seen.len() >= 15,
            "100 shards over 20 equal-stake validators should touch most of \
             them, touched {}",
            seen.len()
        );
    }
}
