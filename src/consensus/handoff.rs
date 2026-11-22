//! The Handoff Certificate committee and node-side signature binding (K-4, K-G.6).
//!
//! The committee is a function of the validator addresses and the epoch
//! randomness of the Filiz chain (`consensus::filiz::epoch_randomness`), so
//! every node and phone derives the same one.
//!
//! The wire types ([`HandoffMember`], [`HandoffSignature`], [`HandoffCertificate`],
//! [`HandoffError`]), the deterministic Filiz committee seating ([`handoff_committee`],
//! [`handoff_committee_weighted`]), the set digest ([`set_digest`]), and the
//! pure quorum/chain walk ([`follow_handoffs_with`]) are defined once in
//! `budlum_types::handoff` so the mobile core (`budlum-mobile-core`) and the
//! full node run the exact same implementation without linking `budlum-core`.
//!
//! This module re-exports those shared types for Filiz handoff persistence and
//! binds them to the node's [`crate::crypto::scheme::SchemeStatusRegistry`]
//! (`consensus::filiz::epoch_randomness`) and [`crate::crypto::pq::verify_in`]
//! under `BDLM/HANDOFF/V1`.
//! WIRING: consensus surface kept public for the QC, Filiz and handoff wiring; production callers land with it.

pub use budlum_types::handoff::{
    follow_handoffs_with, handoff_committee, handoff_committee_weighted, member_set_is_valid,
    set_digest, HandoffCertificate, HandoffError, HandoffMember, HandoffSignature, COMMITTEE_SIZE,
};

/// Extract the [`HandoffMember`] list from a finality [`crate::chain::finality::ValidatorSetSnapshot`],
/// preserving snapshot order.
#[must_use]
/// WIRING: consensus surface kept public for the QC, Filiz and handoff wiring; production callers land with it.
pub fn from_snapshot(
    snapshot: &crate::chain::finality::ValidatorSetSnapshot,
) -> Vec<HandoffMember> {
    snapshot
        .validators
        .iter()
        .map(|entry| HandoffMember {
            address: entry.address.as_bytes().to_vec(),
            bls_public_key: entry.bls_public_key.clone(),
            pop_signature: entry.pop_signature.clone(),
            pq_public_key: entry.pq_public_key.clone(),
            stake: entry.stake,
        })
        .collect()
}

/// Verify `cert` against `outgoing` and the canonical `epoch_randomness` under
/// the chain's [`crate::crypto::scheme::SchemeStatusRegistry`].
///
/// # Errors
///
/// [`HandoffError`] for a set mismatch, randomness mismatch, non-committee
/// signer, non-ascending order, quorum shortfall, or failed ML-DSA-65 signature.
/// WIRING: consensus surface kept public for the QC, Filiz and handoff wiring; production callers land with it.
pub fn verify_in(
    cert: &HandoffCertificate,
    registry: &crate::crypto::scheme::SchemeStatusRegistry,
    outgoing: &[HandoffMember],
    epoch_randomness: [u8; 32],
) -> Result<(), HandoffError> {
    cert.verify_with(outgoing, epoch_randomness, |pk, message, signature| {
        crate::crypto::pq::verify_in(
            registry,
            crate::crypto::scheme::SchemeId::ML_DSA_65,
            pk,
            message,
            crate::crypto::ctx::HANDOFF_V1,
            signature,
        )
        .map_err(|e| e.to_string())
    })
}

/// Follow a chain of [`HandoffCertificate`] steps from a trusted set of
/// `start_epoch` under `registry`.
///
/// # Errors
///
/// The first step that breaks contiguity, set binding, randomness, quorum, or
/// ML-DSA-65 verification.
/// WIRING: consensus surface kept public for the QC, Filiz and handoff wiring; production callers land with it.
pub fn follow_handoffs<'a>(
    registry: &crate::crypto::scheme::SchemeStatusRegistry,
    chain_id: u64,
    start_epoch: u64,
    trusted: &'a [HandoffMember],
    steps: &'a [(HandoffCertificate, Vec<HandoffMember>)],
    epoch_randomness: &dyn Fn(u64) -> [u8; 32],
) -> Result<(u64, &'a [HandoffMember]), HandoffError> {
    if !member_set_is_valid(trusted) {
        return Err(HandoffError::OutgoingSet);
    }
    let mut epoch = start_epoch;
    let mut current = trusted;
    for (cert, next) in steps {
        if cert.chain_id != chain_id {
            return Err(HandoffError::Chain {
                expected: chain_id,
                got: cert.chain_id,
            });
        }
        if cert.epoch != epoch {
            return Err(HandoffError::Epoch {
                expected: epoch,
                got: cert.epoch,
            });
        }
        verify_in(cert, registry, current, epoch_randomness(epoch))?;
        epoch = epoch.checked_add(1).ok_or(HandoffError::Epoch {
            expected: u64::MAX,
            got: cert.epoch,
        })?;
        if !member_set_is_valid(next) {
            return Err(HandoffError::IncomingSet);
        }
        if cert.incoming_set != set_digest(chain_id, epoch, next) {
            return Err(HandoffError::IncomingSet);
        }
        current = next;
    }
    Ok((epoch, current))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| u32::try_from(i).unwrap_or(u32::MAX).to_be_bytes().to_vec())
            .collect()
    }

    #[test]
    fn a_small_set_signs_whole() {
        assert_eq!(
            handoff_committee(&set(COMMITTEE_SIZE), &[1; 32]).len(),
            COMMITTEE_SIZE
        );
        assert_eq!(handoff_committee(&set(3), &[1; 32]), vec![0, 1, 2]);
    }

    #[test]
    fn a_large_set_seats_exactly_the_committee_size_in_index_order() {
        let seats = handoff_committee(&set(1000), &[7; 32]);
        assert_eq!(seats.len(), COMMITTEE_SIZE);
        assert!(seats.windows(2).all(|w| w[0] < w[1]));
        assert!(seats.iter().all(|&i| i < 1000));
    }

    #[test]
    fn the_committee_is_deterministic_and_follows_the_randomness() {
        let a = handoff_committee(&set(800), &[1; 32]);
        assert_eq!(a, handoff_committee(&set(800), &[1; 32]));
        assert_ne!(a, handoff_committee(&set(800), &[2; 32]));
    }

    fn members(keys: &[crate::crypto::primitives::PqKeyPair]) -> Vec<HandoffMember> {
        keys.iter()
            .enumerate()
            .map(|(i, key)| {
                let tag = u8::try_from(i).unwrap_or(0);
                HandoffMember {
                    address: vec![tag; 32],
                    bls_public_key: vec![tag ^ 0xA5; 48],
                    pop_signature: vec![tag ^ 0x5A; 96],
                    pq_public_key: key.public_key_bytes().to_vec(),
                    stake: 10,
                }
            })
            .collect()
    }

    fn signed(
        keys: &[crate::crypto::primitives::PqKeyPair],
        outgoing: &[HandoffMember],
        incoming: &[HandoffMember],
        signers: &[usize],
    ) -> HandoffCertificate {
        let mut cert = HandoffCertificate::unsigned(7, 4, outgoing, incoming, [3; 32]);
        let message = cert.signing_message();
        for &i in signers {
            let signature = keys[i]
                .sign(crate::crypto::ctx::HANDOFF_V1, &message)
                .expect("signs");
            cert.insert_signature(u32::try_from(i).unwrap(), signature);
        }
        cert
    }

    #[test]
    fn a_two_thirds_committee_hands_over_and_a_light_client_follows() {
        let keys: Vec<_> = (0..4)
            .map(|_| crate::crypto::primitives::PqKeyPair::generate())
            .collect();
        let outgoing = members(&keys);
        let mut incoming = outgoing.clone();
        incoming[0].stake = 20;
        let registry = crate::crypto::scheme::SchemeStatusRegistry::genesis();

        let cert = signed(&keys, &outgoing, &incoming, &[0, 1, 2]);
        assert_eq!(verify_in(&cert, &registry, &outgoing, [3; 32]), Ok(()));
        let steps = vec![(cert.clone(), incoming.clone())];
        let (epoch, reached) =
            follow_handoffs(&registry, 7, 4, &outgoing, &steps, &|_| [3; 32]).expect("follows");
        assert_eq!(epoch, 5);
        assert_eq!(reached, incoming.as_slice());

        // The committee is seated by the certificate's `randomness` field, so a
        // certificate signed by a committee chosen from a randomness of its own
        // choosing must be refused: the chain seated a different one.
        let mut renamed = cert.clone();
        renamed.randomness = [4; 32];
        assert_eq!(
            verify_in(&renamed, &registry, &outgoing, [3; 32]),
            Err(HandoffError::Randomness)
        );

        let short = signed(&keys, &outgoing, &incoming, &[0, 1]);
        assert!(matches!(
            verify_in(&short, &registry, &outgoing, [3; 32]),
            Err(HandoffError::Quorum { .. })
        ));
        let mut swapped = cert.clone();
        swapped.signatures[0].signature = swapped.signatures[1].signature.clone();
        assert!(matches!(
            verify_in(&swapped, &registry, &outgoing, [3; 32]),
            Err(HandoffError::Signature { .. })
        ));
        let mut forged_bls = incoming.clone();
        forged_bls[0].bls_public_key[0] ^= 0xFF;
        assert_eq!(
            follow_handoffs(
                &registry,
                7,
                4,
                &outgoing,
                &[(cert.clone(), forged_bls)],
                &|_| [3; 32]
            ),
            Err(HandoffError::IncomingSet),
            "swapped BLS key must break incoming-set binding"
        );
        let mut forged_set = incoming.clone();
        forged_set[1].stake = 99;
        assert_eq!(
            follow_handoffs(&registry, 7, 4, &outgoing, &[(cert, forged_set)], &|_| [3;
                32]),
            Err(HandoffError::IncomingSet)
        );
    }

    #[test]
    fn seat_majority_without_two_thirds_stake_is_refused() {
        let registry = crate::crypto::scheme::SchemeStatusRegistry::genesis();
        let keys: Vec<_> = (0..4)
            .map(|_| crate::crypto::primitives::PqKeyPair::generate())
            .collect();
        let mut outgoing = members(&keys);
        // Member 3 holds 1_000 stake; members 0..3 hold 1 stake each (3/4 seats, 3/1003 stake).
        outgoing[0].stake = 1;
        outgoing[1].stake = 1;
        outgoing[2].stake = 1;
        outgoing[3].stake = 1_000;
        let incoming = outgoing.clone();

        let low_stake_cert = signed(&keys, &outgoing, &incoming, &[0, 1, 2]);
        assert!(
            matches!(
                low_stake_verify_in(&cert, &registry, &outgoing, [3; 32]),
                Err(HandoffError::Quorum {
                    signed: 3,
                    committee: 4
                })
            ),
            "3 of 4 seats with <2/3 committed stake must not clear handoff quorum"
        );

        let high_stake_cert = signed(&keys, &outgoing, &incoming, &[0, 1, 3]);
        assert!(verify_in(&high_stake_cert, &registry, &outgoing, [3; 32]).is_ok());
    }

    #[test]
    fn follow_handoffs_refuses_invalid_successor_sets() {
        let registry = crate::crypto::scheme::SchemeStatusRegistry::genesis();
        let keys: Vec<_> = (0..3)
            .map(|_| crate::crypto::primitives::PqKeyPair::generate())
            .collect();
        let outgoing = members(&keys);

        let empty_incoming: Vec<HandoffMember> = Vec::new();
        let cert_empty = signed(&keys, &outgoing, &empty_incoming, &[0, 1, 2]);
        assert_eq!(
            follow_handoffs(
                &registry,
                7,
                4,
                &outgoing,
                &[(cert_empty, empty_incoming)],
                &|_| [3; 32]
            ),
            Err(HandoffError::IncomingSet)
        );

        let mut zero_stake = outgoing.clone();
        zero_stake[0].stake = 0;
        let cert_zero = signed(&keys, &outgoing, &zero_stake, &[0, 1, 2]);
        assert_eq!(
            follow_handoffs(
                &registry,
                7,
                4,
                &outgoing,
                &[(cert_zero, zero_stake)],
                &|_| [3; 32]
            ),
            Err(HandoffError::IncomingSet)
        );

        let mut dup = outgoing.clone();
        dup[1].address = dup[0].address.clone();
        let cert_dup = signed(&keys, &outgoing, &dup, &[0, 1, 2]);
        assert_eq!(
            follow_handoffs(&registry, 7, 4, &outgoing, &[(cert_dup, dup)], &|_| [3; 32]),
            Err(HandoffError::IncomingSet)
        );
    }

    #[test]
    fn large_validator_set_verifies_and_resists_minimum_stake_sybils() {
        let registry = crate::crypto::scheme::SchemeStatusRegistry::genesis();
        // Verify stake-weighted committee seating over > COMMITTEE_SIZE (512)
        // validators: 60 heavily bonded validators (stake 10_000_000 each) plus
        // 740 minimum-stake sybils (stake 1 each) = 800 total validators.
        let mut mixed = Vec::with_capacity(800);
        for i in 0u32..800 {
            mixed.push(HandoffMember {
                address: i.to_be_bytes().to_vec(),
                pq_public_key: vec![1u8],
                bls_public_key: Vec::new(),
                pop_signature: Vec::new(),
                stake: if i < 60 { 10_000_000 } else { 1 },
            });
        }
        let seated = handoff_committee_weighted(&mixed, &[0xA5; 32]);
        assert_eq!(seated.len(), COMMITTEE_SIZE);
        let committee_stake: u128 = seated.iter().map(|&idx| u128::from(mixed[idx].stake)).sum();
        let sybil_stake: u128 = seated
            .iter()
            .filter(|&&idx| idx >= 60)
            .map(|&idx| u128::from(mixed[idx].stake))
            .sum();
        let bonded_seated = seated.iter().filter(|&&idx| idx < 60).count();
        assert_eq!(
            bonded_seated, 60,
            "every heavily bonded validator is seated ahead of minimum-stake sybils"
        );
        assert!(
            sybil_stake.saturating_mul(3) <= committee_stake.saturating_mul(2),
            "740 minimum-stake sybils cannot reach 2/3 of committee stake"
        );

        // End-to-end signed verification with real PQ keys: 11 of 16 (> 2/3) pass,
        // 10 of 16 (<= 2/3) are refused with exact InsufficientStake totals.
        let keys: Vec<_> = (0..16)
            .map(|_| crate::crypto::primitives::PqKeyPair::generate())
            .collect();
        let outgoing = members(&keys);
        let incoming = outgoing.clone();
        let committee = handoff_committee_weighted(&outgoing, &[3; 32]);
        assert_eq!(committee.len(), 16);
        let pass_cert = signed(&keys, &outgoing, &incoming, &committee[..11]);
        assert_eq!(verify_in(&pass_cert, &registry, &outgoing, [3; 32]), Ok(()));
        let short_cert = signed(&keys, &outgoing, &incoming, &committee[..10]);
        assert_eq!(
            verify_in(&short_cert, &registry, &outgoing, [3; 32]),
            Err(HandoffError::Quorum {
                signed: 10,
                committee: 16,
            })
        );
    }

    #[test]
    fn node_handoff_types_are_the_shared_budlum_types_definitions() {
        fn same_cert(shared: budlum_types::handoff::HandoffCertificate) -> HandoffCertificate {
            shared
        }
        fn same_member(shared: budlum_types::handoff::HandoffMember) -> HandoffMember {
            shared
        }
        let m = same_member(budlum_types::handoff::HandoffMember {
            address: vec![1; 32],
            bls_public_key: vec![2; 48],
            pop_signature: vec![3; 96],
            pq_public_key: vec![4; 32],
            stake: 10,
        });
        let cert = same_cert(budlum_types::handoff::HandoffCertificate::unsigned(
            45_261,
            1,
            std::slice::from_ref(&m),
            std::slice::from_ref(&m),
            [5; 32],
        ));
        assert_eq!(cert.chain_id, 45_261);
    }
}
