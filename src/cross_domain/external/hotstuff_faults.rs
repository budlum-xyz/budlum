//! WIRING: unwired - `HotStuff` pacemaker timeout-certificate verifier
//! (`verify_hotstuff_timeout_certificate`) awaits its pacemaker view-change intake
//! door; double-vote equivocation (`verify_hotstuff_equivocation`) is wired via
//! `IntakeState::adjudicate_hotstuff_equivocation` and `ExternalDomainTx::SubmitFaultProof`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use super::{
    hotstuff_timeout_sign_bytes, hotstuff_vote_sign_bytes, validate_pinned_committee,
    HotStuffTimeoutCertificate, HotStuffVoteSig, PinnedHotStuffCommittee,
};
use crate::cross_domain::external::spec::AdapterError;

/// Verify a `HotStuffTimeoutCertificate` against `pinned` and return the
/// verified `(max_high_qc_view, signed_stake, all_pq)` tuple.
///
/// # Errors
///
/// Returns [`AdapterError`] if `network` is blank, epoch, view, committee bounds,
/// signer uniqueness, Ed25519 or ML-DSA-65 signatures, `max_high_qc_view`, or
/// the strict 2/3 stake threshold fail.
///
/// Convenience: exposed for `HotStuff` view-change safety auditing and bridges.
pub fn verify_hotstuff_timeout_certificate(
    network: &str,
    pinned: &PinnedHotStuffCommittee,
    tc: &HotStuffTimeoutCertificate,
) -> Result<(u64, u128, bool), AdapterError> {
    if network.trim().is_empty() {
        return Err(AdapterError::ConsensusRule {
            rule: "HotStuff network identifier must not be empty".into(),
        });
    }
    if tc.epoch != pinned.epoch {
        return Err(AdapterError::ConsensusRule {
            rule: "HotStuff TC epoch mismatches pinned committee epoch".into(),
        });
    }
    if tc.view == 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "HotStuff TC view must be non-zero".into(),
        });
    }
    let (member_map, total_stake) = validate_pinned_committee(pinned)?;
    if tc.votes.is_empty() || tc.votes.len() > pinned.members.len() {
        return Err(AdapterError::ConsensusRule {
            rule: "HotStuff TC vote count outside [1, committee.len()]".into(),
        });
    }

    let mut seen = BTreeSet::new();
    let mut signed_stake = 0u128;
    let mut observed_max_high_qc = 0u64;
    let mut all_pq = true;

    for v in &tc.votes {
        if !seen.insert(v.signer_pubkey) {
            return Err(AdapterError::ConsensusRule {
                rule: "duplicate signer in HotStuff TimeoutCertificate".into(),
            });
        }
        if v.high_qc_view >= tc.view {
            return Err(AdapterError::ConsensusRule {
                rule: "HotStuff timeout vote high_qc_view must be strictly below timed-out view"
                    .into(),
            });
        }
        let member =
            member_map
                .get(&v.signer_pubkey)
                .ok_or_else(|| AdapterError::ConsensusRule {
                    rule: "non-committee signer in HotStuff TimeoutCertificate".into(),
                })?;
        let digest = hotstuff_timeout_sign_bytes(network, tc.epoch, tc.view, v.high_qc_view);
        crate::crypto::primitives::verify_signature(&digest, &v.ed25519_sig, &v.signer_pubkey)
            .map_err(|_| AdapterError::Crypto {
                what: "invalid Ed25519 signature in HotStuff TimeoutCertificate".into(),
            })?;
        if member.pq_pubkey.is_empty() {
            all_pq = false;
        } else {
            if v.pq_sig.is_empty() {
                return Err(AdapterError::Crypto {
                    what: "missing mandatory ML-DSA-65 co-signature in HotStuff TC".into(),
                });
            }
            crate::crypto::primitives::PqKeyPair::verify(
                &member.pq_pubkey,
                crate::crypto::ctx::CROSS_DOMAIN_V1,
                &digest,
                &v.pq_sig,
            )
            .map_err(|_| AdapterError::Crypto {
                what: "invalid ML-DSA-65 co-signature in HotStuff TC".into(),
            })?;
        }
        observed_max_high_qc = observed_max_high_qc.max(v.high_qc_view);
        signed_stake = signed_stake
            .checked_add(u128::from(member.voting_weight))
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "HotStuff TC signed stake overflows u128".into(),
            })?;
    }

    if observed_max_high_qc != tc.max_high_qc_view {
        return Err(AdapterError::ConsensusRule {
            rule: "HotStuff TC declared max_high_qc_view mismatches signed votes".into(),
        });
    }
    if signed_stake.saturating_mul(3) <= total_stake.saturating_mul(2) {
        return Err(AdapterError::ConsensusRule {
            rule: "HotStuff TC signed stake does not exceed strict 2/3".into(),
        });
    }
    Ok((observed_max_high_qc, signed_stake, all_pq))
}

/// Cryptographic misbehaviour bundle proving that a `HotStuff` validator signed
/// two distinct blocks in the exact same `(epoch, view)`.
///
/// WIRING: exposed for `HotStuff` double-vote slashing intake surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotStuffEquivocationProof {
    /// Shared epoch of the double-vote.
    pub epoch: u64,
    /// Shared view of the double-vote.
    pub view: u64,
    /// First voted block hash (non-zero, distinct from `block_hash_b`).
    pub block_hash_a: [u8; 32],
    /// Second voted block hash (non-zero, distinct from `block_hash_a`).
    pub block_hash_b: [u8; 32],
    /// Vote signature on `block_hash_a`.
    pub vote_a: HotStuffVoteSig,
    /// Vote signature on `block_hash_b` by the exact same validator.
    pub vote_b: HotStuffVoteSig,
}

/// Verify a `HotStuffEquivocationProof` (including mandatory ML-DSA-65 co-sigs
/// so a classical forgery cannot frame a PQ-enrolled validator) and return the
/// slashable `(validator_pubkey, voting_weight)`.
///
/// # Errors
///
/// Returns [`AdapterError`] if `network` is blank, the committee violates
/// bounds/uniqueness, the proof epoch mismatches `pinned`, block hashes are
/// zero or equal, votes are from different or unknown signers, or any Ed25519
/// or ML-DSA-65 signature check fails.
///
/// Convenience: exposed for `HotStuff` slashing and `ConsensusSentry` freeze hooks.
pub fn verify_hotstuff_equivocation(
    network: &str,
    pinned: &PinnedHotStuffCommittee,
    proof: &HotStuffEquivocationProof,
) -> Result<([u8; 32], u64), AdapterError> {
    if network.trim().is_empty() {
        return Err(AdapterError::ConsensusRule {
            rule: "HotStuff network identifier must not be empty".into(),
        });
    }
    if proof.epoch != pinned.epoch {
        return Err(AdapterError::ConsensusRule {
            rule: "HotStuff equivocation proof epoch mismatches pinned committee".into(),
        });
    }
    if proof.block_hash_a == [0u8; 32] || proof.block_hash_b == [0u8; 32] {
        return Err(AdapterError::ConsensusRule {
            rule: "HotStuff equivocation proof contains zero block_hash".into(),
        });
    }
    if bool::from(proof.block_hash_a.ct_eq(&proof.block_hash_b)) {
        return Err(AdapterError::ConsensusRule {
            rule: "HotStuff equivocation proof names identical block hashes".into(),
        });
    }
    if !bool::from(
        proof
            .vote_a
            .signer_pubkey
            .ct_eq(&proof.vote_b.signer_pubkey),
    ) {
        return Err(AdapterError::ConsensusRule {
            rule: "HotStuff equivocation votes belong to different validators".into(),
        });
    }
    let (member_map, _total_stake) = validate_pinned_committee(pinned)?;
    let member = member_map
        .get(&proof.vote_a.signer_pubkey)
        .copied()
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "HotStuff equivocation signer is not in pinned committee".into(),
        })?;

    for (blk_hash, vote) in [
        (&proof.block_hash_a, &proof.vote_a),
        (&proof.block_hash_b, &proof.vote_b),
    ] {
        let msg = hotstuff_vote_sign_bytes(network, proof.epoch, proof.view, blk_hash);
        crate::crypto::primitives::verify_signature(
            &msg,
            &vote.ed25519_sig,
            &member.ed25519_pubkey,
        )
        .map_err(|_| AdapterError::Crypto {
            what: "invalid Ed25519 signature in HotStuff equivocation proof".into(),
        })?;
        if !member.pq_pubkey.is_empty() {
            if vote.pq_sig.is_empty() {
                return Err(AdapterError::Crypto {
                    what: "missing mandatory ML-DSA-65 co-signature in HotStuff equivocation"
                        .into(),
                });
            }
            crate::crypto::primitives::PqKeyPair::verify(
                &member.pq_pubkey,
                crate::crypto::ctx::CROSS_DOMAIN_V1,
                &msg,
                &vote.pq_sig,
            )
            .map_err(|_| AdapterError::Crypto {
                what: "invalid ML-DSA-65 co-signature in HotStuff equivocation".into(),
            })?;
        }
    }

    Ok((member.ed25519_pubkey, member.voting_weight))
}

#[cfg(test)]
mod tests {
    use super::super::{HotStuffTimeoutVote, HotStuffValidator, MAX_HOTSTUFF_COMMITTEE};
    use super::*;
    use crate::crypto::ctx;
    use crate::crypto::primitives::{KeyPair, PqKeyPair};

    #[test]
    fn hotstuff_faults_reject_duplicate_committee_pubkeys_and_empty_network() {
        let ed = KeyPair::from_seed(&[0x41; 32]).expect("ed");
        let pq = PqKeyPair::generate();
        let pub_ed = ed.public_key_bytes();
        let pub_pq = pq.public_key_bytes().to_vec();

        // Duplicate ed25519_pubkey with classical-only row preceding PQ-enrolled row must be rejected.
        let dup_committee = PinnedHotStuffCommittee {
            epoch: 7,
            members: vec![
                HotStuffValidator {
                    ed25519_pubkey: pub_ed,
                    voting_weight: 100,
                    pq_pubkey: Vec::new(),
                },
                HotStuffValidator {
                    ed25519_pubkey: pub_ed,
                    voting_weight: 100,
                    pq_pubkey: pub_pq.clone(),
                },
            ],
        };
        let ma = hotstuff_vote_sign_bytes("aptos-jolteon-1", 7, 12, &[0xAA; 32]);
        let mb = hotstuff_vote_sign_bytes("aptos-jolteon-1", 7, 12, &[0xBB; 32]);
        let classical_eq = HotStuffEquivocationProof {
            epoch: 7,
            view: 12,
            block_hash_a: [0xAA; 32],
            block_hash_b: [0xBB; 32],
            vote_a: HotStuffVoteSig {
                signer_pubkey: pub_ed,
                ed25519_sig: ed.sign(&ma).to_vec(),
                pq_sig: Vec::new(),
            },
            vote_b: HotStuffVoteSig {
                signer_pubkey: pub_ed,
                ed25519_sig: ed.sign(&mb).to_vec(),
                pq_sig: Vec::new(),
            },
        };
        assert!(matches!(
            verify_hotstuff_equivocation("aptos-jolteon-1", &dup_committee, &classical_eq),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("duplicate")
        ));

        let mtc = hotstuff_timeout_sign_bytes("aptos-jolteon-1", 7, 15, 14);
        let classical_tc = HotStuffTimeoutCertificate {
            epoch: 7,
            view: 15,
            max_high_qc_view: 14,
            votes: vec![HotStuffTimeoutVote {
                signer_pubkey: pub_ed,
                high_qc_view: 14,
                ed25519_sig: ed.sign(&mtc).to_vec(),
                pq_sig: Vec::new(),
            }],
        };
        assert!(matches!(
            verify_hotstuff_timeout_certificate("aptos-jolteon-1", &dup_committee, &classical_tc),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("duplicate")
        ));

        assert_blank_network_and_bad_pq_rejected(&ed, &pq, pub_ed, pub_pq);
        assert_committee_bounds_rejected(&classical_eq, &classical_tc, pub_ed);
        assert_timeout_certificate_acceptance_and_refusals();
        assert_equivocation_acceptance_and_refusals();
    }

    fn assert_timeout_certificate_acceptance_and_refusals() {
        let net = "aptos-jolteon-1";
        let ed1 = KeyPair::from_seed(&[0x51; 32]).expect("ed1");
        let ed2 = KeyPair::from_seed(&[0x52; 32]).expect("ed2");
        let ed3 = KeyPair::from_seed(&[0x53; 32]).expect("ed3");
        let pq1 = PqKeyPair::generate();
        let pq2 = PqKeyPair::generate();
        let pq3 = PqKeyPair::generate();

        // Total stake = 300 (100 + 101 + 99): signers 1+2 hold 201 > 200 (strict > 2/3),
        // while signers 1+3 hold 199, and an exact 2/3 committee (100 + 100 + 100) holds 200.
        let strict_committee = PinnedHotStuffCommittee {
            epoch: 9,
            members: vec![
                HotStuffValidator {
                    ed25519_pubkey: ed1.public_key_bytes(),
                    voting_weight: 100,
                    pq_pubkey: pq1.public_key_bytes().to_vec(),
                },
                HotStuffValidator {
                    ed25519_pubkey: ed2.public_key_bytes(),
                    voting_weight: 101,
                    pq_pubkey: pq2.public_key_bytes().to_vec(),
                },
                HotStuffValidator {
                    ed25519_pubkey: ed3.public_key_bytes(),
                    voting_weight: 99,
                    pq_pubkey: pq3.public_key_bytes().to_vec(),
                },
            ],
        };
        let d1 = hotstuff_timeout_sign_bytes(net, 9, 20, 17);
        let d2 = hotstuff_timeout_sign_bytes(net, 9, 20, 19);
        let v1 = HotStuffTimeoutVote {
            signer_pubkey: ed1.public_key_bytes(),
            high_qc_view: 17,
            ed25519_sig: ed1.sign(&d1).to_vec(),
            pq_sig: pq1.sign(ctx::CROSS_DOMAIN_V1, &d1).expect("pq1"),
        };
        let v2 = HotStuffTimeoutVote {
            signer_pubkey: ed2.public_key_bytes(),
            high_qc_view: 19,
            ed25519_sig: ed2.sign(&d2).to_vec(),
            pq_sig: pq2.sign(ctx::CROSS_DOMAIN_V1, &d2).expect("pq2"),
        };

        // 1. Acceptance: valid >2/3 PQ-enrolled TimeoutCertificate returns (19, 201, true).
        let valid_tc = HotStuffTimeoutCertificate {
            epoch: 9,
            view: 20,
            max_high_qc_view: 19,
            votes: vec![v1.clone(), v2.clone()],
        };
        assert_eq!(
            verify_hotstuff_timeout_certificate(net, &strict_committee, &valid_tc).expect("tc ok"),
            (19, 201, true)
        );

        // 2. Rejection: exact 2/3 stake (200 of 300) fails strict >2/3 rule.
        let equal_committee = PinnedHotStuffCommittee {
            epoch: 9,
            members: vec![
                HotStuffValidator {
                    ed25519_pubkey: ed1.public_key_bytes(),
                    voting_weight: 100,
                    pq_pubkey: pq1.public_key_bytes().to_vec(),
                },
                HotStuffValidator {
                    ed25519_pubkey: ed2.public_key_bytes(),
                    voting_weight: 100,
                    pq_pubkey: pq2.public_key_bytes().to_vec(),
                },
                HotStuffValidator {
                    ed25519_pubkey: ed3.public_key_bytes(),
                    voting_weight: 100,
                    pq_pubkey: pq3.public_key_bytes().to_vec(),
                },
            ],
        };
        assert!(matches!(
            verify_hotstuff_timeout_certificate(net, &equal_committee, &valid_tc),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("2/3")
        ));

        // 3. Rejection: declared max_high_qc_view mismatching observed signed votes.
        let mut wrong_max = valid_tc.clone();
        wrong_max.max_high_qc_view = 18;
        assert!(matches!(
            verify_hotstuff_timeout_certificate(net, &strict_committee, &wrong_max),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("max_high_qc_view")
        ));

        // 4. Rejection: replayed / duplicate timeout vote by the same validator.
        let mut replayed_vote = valid_tc.clone();
        replayed_vote.votes = vec![v2.clone(), v2];
        assert!(matches!(
            verify_hotstuff_timeout_certificate(net, &strict_committee, &replayed_vote),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("duplicate signer")
        ));

        // 5. Rejection: foreign epoch mismatching pinned committee epoch.
        let mut foreign_epoch_tc = valid_tc.clone();
        foreign_epoch_tc.epoch = 10;
        assert!(matches!(
            verify_hotstuff_timeout_certificate(net, &strict_committee, &foreign_epoch_tc),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("epoch")
        ));

        // 6. Rejection: flipped Ed25519 signature byte in TC vote.
        let mut bad_ed_tc = valid_tc.clone();
        bad_ed_tc.votes[0].ed25519_sig[0] ^= 0x01;
        assert!(matches!(
            verify_hotstuff_timeout_certificate(net, &strict_committee, &bad_ed_tc),
            Err(AdapterError::Crypto { .. })
        ));

        // 7. Rejection: stripped ML-DSA-65 PQ co-signature for PQ-enrolled validator.
        let mut stripped_pq_tc = valid_tc;
        stripped_pq_tc.votes[1].pq_sig.clear();
        assert!(matches!(
            verify_hotstuff_timeout_certificate(net, &strict_committee, &stripped_pq_tc),
            Err(AdapterError::Crypto { ref what }) if what.contains("ML-DSA-65")
        ));
    }

    fn assert_equivocation_acceptance_and_refusals() {
        let net = "aptos-jolteon-1";
        let ed1 = KeyPair::from_seed(&[0x61; 32]).expect("ed1");
        let ed2 = KeyPair::from_seed(&[0x62; 32]).expect("ed2");
        let pq1 = PqKeyPair::generate();
        let pq2 = PqKeyPair::generate();

        let committee = PinnedHotStuffCommittee {
            epoch: 11,
            members: vec![
                HotStuffValidator {
                    ed25519_pubkey: ed1.public_key_bytes(),
                    voting_weight: 250,
                    pq_pubkey: pq1.public_key_bytes().to_vec(),
                },
                HotStuffValidator {
                    ed25519_pubkey: ed2.public_key_bytes(),
                    voting_weight: 150,
                    pq_pubkey: pq2.public_key_bytes().to_vec(),
                },
            ],
        };

        let msg_a = hotstuff_vote_sign_bytes(net, 11, 33, &[0x11; 32]);
        let msg_b = hotstuff_vote_sign_bytes(net, 11, 33, &[0x22; 32]);
        let valid_eq = HotStuffEquivocationProof {
            epoch: 11,
            view: 33,
            block_hash_a: [0x11; 32],
            block_hash_b: [0x22; 32],
            vote_a: HotStuffVoteSig {
                signer_pubkey: ed1.public_key_bytes(),
                ed25519_sig: ed1.sign(&msg_a).to_vec(),
                pq_sig: pq1.sign(ctx::CROSS_DOMAIN_V1, &msg_a).expect("pq_a"),
            },
            vote_b: HotStuffVoteSig {
                signer_pubkey: ed1.public_key_bytes(),
                ed25519_sig: ed1.sign(&msg_b).to_vec(),
                pq_sig: pq1.sign(ctx::CROSS_DOMAIN_V1, &msg_b).expect("pq_b"),
            },
        };

        // 8. Acceptance: valid PQ-enrolled equivocation returns (ed1_pubkey, 250).
        assert_eq!(
            verify_hotstuff_equivocation(net, &committee, &valid_eq).expect("equivocation ok"),
            (ed1.public_key_bytes(), 250)
        );

        // 9. Rejection: identical block hashes (`block_hash_a == block_hash_b`) is not equivocation.
        let mut same_block = valid_eq.clone();
        same_block.block_hash_b = same_block.block_hash_a;
        same_block.vote_b = same_block.vote_a.clone();
        assert!(matches!(
            verify_hotstuff_equivocation(net, &committee, &same_block),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("identical")
        ));

        // 10. Rejection: votes signed by two different validators in the same view.
        let mut distinct_signers = valid_eq.clone();
        distinct_signers.vote_b = HotStuffVoteSig {
            signer_pubkey: ed2.public_key_bytes(),
            ed25519_sig: ed2.sign(&msg_b).to_vec(),
            pq_sig: pq2.sign(ctx::CROSS_DOMAIN_V1, &msg_b).expect("pq2_b"),
        };
        assert!(matches!(
            verify_hotstuff_equivocation(net, &committee, &distinct_signers),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("different validators")
        ));

        // Foreign epoch, flipped Ed25519 byte, and stripped ML-DSA-65 co-sig on equivocation:
        let mut foreign_eq = valid_eq.clone();
        foreign_eq.epoch = 12;
        assert!(matches!(
            verify_hotstuff_equivocation(net, &committee, &foreign_eq),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("epoch")
        ));

        let mut bad_ed_eq = valid_eq.clone();
        bad_ed_eq.vote_a.ed25519_sig[3] ^= 0x80;
        assert!(matches!(
            verify_hotstuff_equivocation(net, &committee, &bad_ed_eq),
            Err(AdapterError::Crypto { .. })
        ));

        let mut stripped_pq_eq = valid_eq;
        stripped_pq_eq.vote_b.pq_sig.clear();
        assert!(matches!(
            verify_hotstuff_equivocation(net, &committee, &stripped_pq_eq),
            Err(AdapterError::Crypto { ref what }) if what.contains("ML-DSA-65")
        ));
    }

    fn assert_committee_bounds_rejected(
        classical_eq: &HotStuffEquivocationProof,
        classical_tc: &HotStuffTimeoutCertificate,
        pub_ed: [u8; 32],
    ) {
        let oversized = PinnedHotStuffCommittee {
            epoch: 7,
            members: (0..=MAX_HOTSTUFF_COMMITTEE)
                .map(|i| {
                    let mut pk = [0u8; 32];
                    pk[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
                    HotStuffValidator {
                        ed25519_pubkey: pk,
                        voting_weight: 1,
                        pq_pubkey: Vec::new(),
                    }
                })
                .collect(),
        };
        assert!(verify_hotstuff_equivocation("aptos-jolteon-1", &oversized, classical_eq).is_err());

        let ed2 = KeyPair::from_seed(&[0x42; 32]).expect("ed2");
        let overflow_committee = PinnedHotStuffCommittee {
            epoch: 7,
            members: vec![
                HotStuffValidator {
                    ed25519_pubkey: pub_ed,
                    voting_weight: u64::MAX,
                    pq_pubkey: Vec::new(),
                },
                HotStuffValidator {
                    ed25519_pubkey: ed2.public_key_bytes(),
                    voting_weight: 1,
                    pq_pubkey: Vec::new(),
                },
            ],
        };
        assert!(
            verify_hotstuff_equivocation("aptos-jolteon-1", &overflow_committee, classical_eq)
                .is_ok()
        );

        let zero_weight_committee = PinnedHotStuffCommittee {
            epoch: 7,
            members: vec![HotStuffValidator {
                ed25519_pubkey: pub_ed,
                voting_weight: 0,
                pq_pubkey: Vec::new(),
            }],
        };
        assert!(verify_hotstuff_equivocation(
            "aptos-jolteon-1",
            &zero_weight_committee,
            classical_eq
        )
        .is_err());
        assert!(verify_hotstuff_timeout_certificate(
            "aptos-jolteon-1",
            &zero_weight_committee,
            classical_tc,
        )
        .is_err());
    }

    fn assert_blank_network_and_bad_pq_rejected(
        ed: &KeyPair,
        pq: &PqKeyPair,
        pub_ed: [u8; 32],
        pub_pq: Vec<u8>,
    ) {
        let single = PinnedHotStuffCommittee {
            epoch: 7,
            members: vec![HotStuffValidator {
                ed25519_pubkey: pub_ed,
                voting_weight: 100,
                pq_pubkey: pub_pq,
            }],
        };
        let blank_vote_first = hotstuff_vote_sign_bytes("   ", 7, 12, &[0xAA; 32]);
        let blank_vote_second = hotstuff_vote_sign_bytes("   ", 7, 12, &[0xBB; 32]);
        let blank_eq = HotStuffEquivocationProof {
            epoch: 7,
            view: 12,
            block_hash_a: [0xAA; 32],
            block_hash_b: [0xBB; 32],
            vote_a: HotStuffVoteSig {
                signer_pubkey: pub_ed,
                ed25519_sig: ed.sign(&blank_vote_first).to_vec(),
                pq_sig: pq
                    .sign(ctx::CROSS_DOMAIN_V1, &blank_vote_first)
                    .expect("pq"),
            },
            vote_b: HotStuffVoteSig {
                signer_pubkey: pub_ed,
                ed25519_sig: ed.sign(&blank_vote_second).to_vec(),
                pq_sig: pq
                    .sign(ctx::CROSS_DOMAIN_V1, &blank_vote_second)
                    .expect("pq"),
            },
        };
        assert!(verify_hotstuff_equivocation("   ", &single, &blank_eq).is_err());

        let blank_tc_digest = hotstuff_timeout_sign_bytes("", 7, 15, 14);
        let blank_tc = HotStuffTimeoutCertificate {
            epoch: 7,
            view: 15,
            max_high_qc_view: 14,
            votes: vec![HotStuffTimeoutVote {
                signer_pubkey: pub_ed,
                high_qc_view: 14,
                ed25519_sig: ed.sign(&blank_tc_digest).to_vec(),
                pq_sig: pq.sign(ctx::CROSS_DOMAIN_V1, &blank_tc_digest).expect("pq"),
            }],
        };
        assert!(verify_hotstuff_timeout_certificate("", &single, &blank_tc).is_err());

        let bad_pq_committee = PinnedHotStuffCommittee {
            epoch: 7,
            members: vec![HotStuffValidator {
                ed25519_pubkey: pub_ed,
                voting_weight: 100,
                pq_pubkey: vec![0xAB; 4],
            }],
        };
        assert!(
            verify_hotstuff_equivocation("aptos-jolteon-1", &bad_pq_committee, &blank_eq).is_err()
        );
    }
}
