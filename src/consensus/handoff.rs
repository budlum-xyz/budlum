//! The Handoff Certificate committee.
//!
//! The Handoff Certificate is the one QC blob that stays persistent. When the validator set
//! has more than [`COMMITTEE_SIZE`] members, its PQ part is signed by a committee of exactly
//! that many members instead of the whole set. The committee is a function of the validator
//! addresses and the epoch randomness of the Filiz chain, so every node derives the same one
//! and no validator chooses its own seat: members are ranked by
//! `SHA3-256(tag || randomness || address)` and the lowest ranks sit.
//!
//! [`HandoffCertificate`] is the certificate itself: the outgoing set's
//! committee signs, with ML-DSA-65 under `BDLM/HANDOFF/V1`, the move from the
//! digest of the set of epoch `e` to the digest of the set of epoch `e + 1`.
//! It carries no TTL and is stored for good (`Storage::save_handoff_cert`),
//! so a light client that trusts one set can follow every later set with
//! [`follow_handoffs`] without any classical signature.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// The committee size above which the PQ part of a Handoff Certificate is committee signed.
/// WIRING: consensus surface kept public for the QC, Filiz and handoff wiring; production callers land with it.
pub const COMMITTEE_SIZE: usize = 512;

const COMMITTEE_TAG: &[u8] = b"BDLM_HANDOFF_COMMITTEE_V1";

fn rank(randomness: &[u8; 32], address: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update((COMMITTEE_TAG.len() as u64).to_le_bytes());
    hasher.update(COMMITTEE_TAG);
    hasher.update(randomness);
    hasher.update((address.len() as u64).to_le_bytes());
    hasher.update(address);
    hasher.finalize().into()
}

/// Indices of the members that sign the PQ part of the Handoff Certificate.
///
/// Returned in ascending index order. With [`COMMITTEE_SIZE`] or fewer
/// validators every index is returned so the whole set signs. A duplicate
/// address ranks by its own hash and an index tie-break, keeping the result
/// total and deterministic.
#[must_use]
/// WIRING: consensus surface kept public for the QC, Filiz and handoff wiring; production callers land with it.
pub fn handoff_committee(validators: &[Vec<u8>], randomness: &[u8; 32]) -> Vec<usize> {
    if validators.len() <= COMMITTEE_SIZE {
        return (0..validators.len()).collect();
    }
    let mut ranked: Vec<([u8; 32], usize)> = validators
        .iter()
        .enumerate()
        .map(|(index, address)| (rank(randomness, address), index))
        .collect();
    ranked.sort_unstable();
    let mut seats: Vec<usize> = ranked
        .into_iter()
        .take(COMMITTEE_SIZE)
        .map(|(_, index)| index)
        .collect();
    seats.sort_unstable();
    seats
}

/// Exact 192-bit unsigned product `a * b` as `(hi_128, lo_128)` for
/// platform-independent stake-weighted priority comparison without floats.
const fn mul_128_64(a: u128, b: u64) -> (u128, u128) {
    let mask = u64::MAX as u128;
    let a_lo = a & mask;
    let a_hi = a >> 64;
    let wb = b as u128;
    let lo = a_lo * wb;
    let mid = a_hi * wb + (lo >> 64);
    let out_lo = (lo & mask) | ((mid & mask) << 64);
    let out_hi = mid >> 64;
    (out_hi, out_lo)
}

/// Stake-weighted committee seating over `outgoing` using exact 192-bit
/// cross-multiplication `draw_a * stake_b` vs `draw_b * stake_a`.
///
/// Positive-stake members with higher stake produce proportionally smaller
/// expected `draw / stake` ratios, so minimum-stake sybil accounts cannot
/// capture the fixed [`COMMITTEE_SIZE`]-seat committee while large validator
/// sets (`N > COMMITTEE_SIZE`) still verify cleanly once strictly more than two
/// thirds of committee seats and committee stake sign.
fn handoff_committee_weighted(members: &[HandoffMember], randomness: &[u8; 32]) -> Vec<usize> {
    let positive: Vec<(usize, &HandoffMember)> = members
        .iter()
        .enumerate()
        .filter(|(_, m)| m.stake > 0)
        .collect();
    if positive.len() <= COMMITTEE_SIZE {
        return positive.into_iter().map(|(i, _)| i).collect();
    }
    let mut candidates: Vec<(u128, u64, [u8; 32], usize)> = positive
        .into_iter()
        .map(|(index, member)| {
            let r = rank(randomness, &member.address);
            let mut top = [0u8; 16];
            top.copy_from_slice(&r[..16]);
            // Ensure strictly positive numerator so distinct stakes break ties fairly.
            let draw = u128::from_be_bytes(top) | 1;
            (draw, member.stake, r, index)
        })
        .collect();
    candidates.sort_unstable_by(|a, b| {
        mul_128_64(a.0, b.1)
            .cmp(&mul_128_64(b.0, a.1))
            .then_with(|| a.2.cmp(&b.2))
            .then_with(|| a.3.cmp(&b.3))
    });
    let mut seats: Vec<usize> = candidates
        .into_iter()
        .take(COMMITTEE_SIZE)
        .map(|(_, _, _, index)| index)
        .collect();
    seats.sort_unstable();
    seats
}

const SET_TAG: &[u8] = b"BDLM_HANDOFF_SET_V1";
const CERT_TAG: &[u8] = b"BDLM_HANDOFF_CERT_V1";

fn absorb(hasher: &mut Sha3_256, field: &[u8]) {
    hasher.update((field.len() as u64).to_le_bytes());
    hasher.update(field);
}

/// One validator as the Handoff Certificate sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffMember {
    pub address: Vec<u8>,
    pub bls_public_key: Vec<u8>,
    pub pop_signature: Vec<u8>,
    pub pq_public_key: Vec<u8>,
    pub stake: u64,
}

impl HandoffMember {
    /// The members of a finality validator snapshot, in snapshot order.
    #[must_use]
    pub fn from_snapshot(snapshot: &crate::chain::finality::ValidatorSetSnapshot) -> Vec<Self> {
        snapshot
            .validators
            .iter()
            .map(|entry| Self {
                address: entry.address.as_bytes().to_vec(),
                bls_public_key: entry.bls_public_key.clone(),
                pop_signature: entry.pop_signature.clone(),
                pq_public_key: entry.pq_public_key.clone(),
                stake: entry.stake,
            })
            .collect()
    }
}

/// The digest of the validator set of `epoch` on `chain_id`: every member's
/// address, BLS consensus key, `PoP` signature, ML-DSA-65 key and stake, length
/// prefixed, in set order.
#[must_use]
pub fn set_digest(chain_id: u64, epoch: u64, members: &[HandoffMember]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    absorb(&mut hasher, SET_TAG);
    absorb(&mut hasher, &chain_id.to_le_bytes());
    absorb(&mut hasher, &epoch.to_le_bytes());
    absorb(&mut hasher, &(members.len() as u64).to_le_bytes());
    for member in members {
        absorb(&mut hasher, &member.address);
        absorb(&mut hasher, &member.bls_public_key);
        absorb(&mut hasher, &member.pop_signature);
        absorb(&mut hasher, &member.pq_public_key);
        absorb(&mut hasher, &member.stake.to_le_bytes());
    }
    hasher.finalize().into()
}

/// One committee member's ML-DSA-65 signature.
///
/// `index` is the member's position in the outgoing set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// WIRING: consensus surface kept public for the QC, Filiz and handoff wiring; production callers land with it.
pub struct HandoffSignature {
    pub index: u32,
    pub signature: Vec<u8>,
}

/// The persistent certificate that hands the chain from the set of `epoch`
/// to the set of `epoch + 1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffCertificate {
    pub chain_id: u64,
    pub epoch: u64,
    pub outgoing_set: [u8; 32],
    pub incoming_set: [u8; 32],
    /// The epoch randomness that seats the committee
    /// (`consensus::filiz::epoch_randomness`).
    pub randomness: [u8; 32],
    /// Ascending by index; only committee members.
    pub signatures: Vec<HandoffSignature>,
}

/// Why a Handoff Certificate or a chain of them was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
/// WIRING: consensus surface kept public for the QC, Filiz and handoff wiring; production callers land with it.
pub enum HandoffError {
    #[error("the outgoing set does not match the certificate")]
    OutgoingSet,
    #[error("the incoming set does not match the certificate")]
    IncomingSet,
    #[error("the certificate is for chain {got}, expected {expected}")]
    Chain { expected: u64, got: u64 },
    #[error("the certificate hands over epoch {got}, expected {expected}")]
    Epoch { expected: u64, got: u64 },
    #[error("signature indices are not strictly ascending")]
    Order,
    #[error("index {0} is not a committee seat")]
    NotCommittee(u32),
    #[error("the certificate randomness is not the epoch randomness")]
    Randomness,
    #[error("{signed} of {committee} committee members signed; more than two thirds are required")]
    Quorum { signed: usize, committee: usize },
    #[error("the signature of member {index} does not verify: {reason}")]
    Signature { index: u32, reason: String },
}

impl HandoffCertificate {
    /// The bytes every committee member signs.
    #[must_use]
    pub fn signing_message(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 * 6 + CERT_TAG.len() + 8 + 8 + 96);
        for field in [
            CERT_TAG,
            &self.chain_id.to_le_bytes(),
            &self.epoch.to_le_bytes(),
            &self.outgoing_set,
            &self.incoming_set,
            &self.randomness,
        ] {
            out.extend_from_slice(&(field.len() as u64).to_le_bytes());
            out.extend_from_slice(field);
        }
        out
    }

    /// An unsigned certificate for the move from `outgoing` to `incoming`.
    #[must_use]
    /// WIRING: consensus surface kept public for the QC, Filiz and handoff wiring; production callers land with it.
    pub fn unsigned(
        chain_id: u64,
        epoch: u64,
        outgoing: &[HandoffMember],
        incoming: &[HandoffMember],
        randomness: [u8; 32],
    ) -> Self {
        Self {
            chain_id,
            epoch,
            outgoing_set: set_digest(chain_id, epoch, outgoing),
            incoming_set: set_digest(chain_id, epoch.saturating_add(1), incoming),
            randomness,
            signatures: Vec::new(),
        }
    }

    /// Add one member's signature, keeping the index order.
    /// WIRING: unwired - no caller in this tree yet; kept as a declared surface, and nothing depends on it until one arrives.
    pub fn insert_signature(&mut self, index: u32, signature: Vec<u8>) {
        match self.signatures.binary_search_by_key(&index, |s| s.index) {
            Ok(at) => self.signatures[at].signature = signature,
            Err(at) => self
                .signatures
                .insert(at, HandoffSignature { index, signature }),
        }
    }

    /// Verify the certificate against the outgoing set it names and the
    /// canonical epoch randomness the chain computed for `self.epoch`.
    ///
    /// `epoch_randomness` is the caller's independent knowledge of
    /// `consensus::filiz::epoch_randomness(chain_id, epoch, canonical_reveals)`.
    /// The certificate carries its own `randomness` field, and that field seats
    /// the committee - so a certificate that names its own randomness would
    /// pick its own committee out of the outgoing set and its signatures would
    /// agree with that choice. Comparing the field against the value the
    /// verifier trusts is what turns the committee from the certificate's
    /// claim into the chain's seating.
    ///
    /// # Errors
    ///
    /// [`HandoffError`] for a set mismatch, a randomness that is not the
    /// epoch's, a signer outside the committee, an order violation, two
    /// thirds not reached, or a bad signature.
    pub fn verify_in(
        &self,
        registry: &crate::crypto::scheme::SchemeStatusRegistry,
        outgoing: &[HandoffMember],
        epoch_randomness: [u8; 32],
    ) -> Result<(), HandoffError> {
        if !incoming_set_is_valid(outgoing)
            || set_digest(self.chain_id, self.epoch, outgoing) != self.outgoing_set
        {
            return Err(HandoffError::OutgoingSet);
        }
        if self.randomness != epoch_randomness {
            return Err(HandoffError::Randomness);
        }
        let committee = handoff_committee_weighted(outgoing, &epoch_randomness);
        if !self.signatures.windows(2).all(|w| w[0].index < w[1].index) {
            return Err(HandoffError::Order);
        }
        for entry in &self.signatures {
            if committee.binary_search(&(entry.index as usize)).is_err() {
                return Err(HandoffError::NotCommittee(entry.index));
            }
        }
        let signed = self.signatures.len();
        if committee.is_empty() || signed * 3 <= committee.len() * 2 {
            return Err(HandoffError::Quorum {
                signed,
                committee: committee.len(),
            });
        }
        // Require strictly more than two thirds of the seated committee's
        // bonded stake as well as more than two thirds of its seats; combined
        // with stake-weighted committee selection this stops minimum-stake
        // accounts from outweighing bonded stake without deadlocking networks
        // with more than `COMMITTEE_SIZE` validators.
        let committee_stake: u128 = committee
            .iter()
            .map(|&idx| u128::from(outgoing[idx].stake))
            .sum();
        let signed_stake: u128 = self
            .signatures
            .iter()
            .map(|entry| u128::from(outgoing[entry.index as usize].stake))
            .sum();
        if committee_stake == 0 || signed_stake * 3 <= committee_stake * 2 {
            return Err(HandoffError::Quorum {
                signed,
                committee: committee.len(),
            });
        }
        let message = self.signing_message();
        for entry in &self.signatures {
            let member = &outgoing[entry.index as usize];
            crate::crypto::pq::verify_in(
                registry,
                crate::crypto::scheme::SchemeId::ML_DSA_65,
                &member.pq_public_key,
                &message,
                crate::crypto::ctx::HANDOFF_V1,
                &entry.signature,
            )
            .map_err(|e| HandoffError::Signature {
                index: entry.index,
                reason: e.to_string(),
            })?;
        }
        Ok(())
    }
}

/// Follow a chain of Handoff Certificates from a trusted set of
/// `start_epoch`. Each step is a certificate and the incoming set it names;
/// the result is the last set the chain reaches.
///
/// # Errors
///
/// The first step that does not continue the chain or does not verify.
/// WIRING: consensus surface kept public for the QC, Filiz and handoff wiring; production callers land with it.
pub fn follow_handoffs<'a>(
    registry: &crate::crypto::scheme::SchemeStatusRegistry,
    chain_id: u64,
    start_epoch: u64,
    trusted: &'a [HandoffMember],
    steps: &'a [(HandoffCertificate, Vec<HandoffMember>)],
    epoch_randomness: &dyn Fn(u64) -> [u8; 32],
) -> Result<(u64, &'a [HandoffMember]), HandoffError> {
    if !incoming_set_is_valid(trusted) {
        return Err(HandoffError::OutgoingSet);
    }
    let mut epoch = start_epoch;
    let mut current = trusted;
    for (cert, incoming) in steps {
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
        cert.verify_in(registry, current, epoch_randomness(cert.epoch))?;
        epoch = epoch.checked_add(1).ok_or(HandoffError::Epoch {
            expected: u64::MAX,
            got: cert.epoch,
        })?;
        if !incoming_set_is_valid(incoming) {
            return Err(HandoffError::IncomingSet);
        }
        if set_digest(chain_id, epoch, incoming) != cert.incoming_set {
            return Err(HandoffError::IncomingSet);
        }
        current = incoming;
    }
    Ok((epoch, current))
}

fn incoming_set_is_valid(incoming: &[HandoffMember]) -> bool {
    if incoming.is_empty() {
        return false;
    }
    let mut seen = std::collections::BTreeSet::new();
    for member in incoming {
        if member.address.is_empty()
            || member.pq_public_key.is_empty()
            || member.stake == 0
            || !seen.insert(member.address.as_slice())
        {
            return false;
        }
    }
    true
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
        assert_eq!(cert.verify_in(&registry, &outgoing, [3; 32]), Ok(()));
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
            renamed.verify_in(&registry, &outgoing, [3; 32]),
            Err(HandoffError::Randomness)
        );

        let short = signed(&keys, &outgoing, &incoming, &[0, 1]);
        assert!(matches!(
            short.verify_in(&registry, &outgoing, [3; 32]),
            Err(HandoffError::Quorum { .. })
        ));
        let mut swapped = cert.clone();
        swapped.signatures[0].signature = swapped.signatures[1].signature.clone();
        assert!(matches!(
            swapped.verify_in(&registry, &outgoing, [3; 32]),
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
                low_stake_cert.verify_in(&registry, &outgoing, [3; 32]),
                Err(HandoffError::Quorum {
                    signed: 3,
                    committee: 4
                })
            ),
            "3 of 4 seats with <2/3 committed stake must not clear handoff quorum"
        );

        let high_stake_cert = signed(&keys, &outgoing, &incoming, &[0, 1, 3]);
        assert!(high_stake_cert
            .verify_in(&registry, &outgoing, [3; 32])
            .is_ok());
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
        assert_eq!(pass_cert.verify_in(&registry, &outgoing, [3; 32]), Ok(()));
        let short_cert = signed(&keys, &outgoing, &incoming, &committee[..10]);
        assert_eq!(
            short_cert.verify_in(&registry, &outgoing, [3; 32]),
            Err(HandoffError::Quorum {
                signed: 10,
                committee: 16,
            })
        );
    }
}
