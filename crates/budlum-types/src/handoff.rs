//! The Handoff Certificate committee and wire types, defined once (K-4).
//!
//! The Handoff Certificate is the one QC blob that stays persistent. When the
//! validator set has more than [`COMMITTEE_SIZE`] members, its post-quantum
//! part is signed by a committee of at most [`COMMITTEE_SIZE`] members instead
//! of the whole set. The committee is a pure function of the validator set and
//! the Filiz epoch randomness, so the node and the mobile core derive the
//! exact same seats and neither side carries a copy that could drift.
//!
//! [`HandoffCertificate`] hands the chain from the set of epoch `e` to the set
//! of epoch `e + 1` under ML-DSA-65 (`BDLM/HANDOFF/V1`). Signature verification
//! enters through [`HandoffCertificate::verify_with`] and
//! [`follow_handoffs_with`] so this crate stays free of signature libraries
//! while both `budlum-core` and `budlum-mobile-core` bind the node's own
//! ML-DSA-65 verifier.
//! Convenience: exposed for workspace subcrate consumers, SDK bindings, and integration callers.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeSet;
use std::fmt;

/// The committee size above which the PQ part of a Handoff Certificate is committee signed.
pub const COMMITTEE_SIZE: usize = 512;

/// Domain separation tag for handoff committee rank derivation.
pub const COMMITTEE_TAG: &[u8] = b"BDLM_HANDOFF_COMMITTEE_V1";

/// Domain separation tag for a validator set's handoff digest.
pub const SET_TAG: &[u8] = b"BDLM_HANDOFF_SET_V1";

/// Domain separation tag for [`HandoffCertificate::signing_message`].
pub const CERT_TAG: &[u8] = b"BDLM_HANDOFF_CERT_V1";

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

/// Stake-weighted committee seating over `members` using exact 192-bit
/// cross-multiplication `draw_a * stake_b` vs `draw_b * stake_a`.
///
/// Positive-stake members with higher stake produce proportionally smaller
/// expected `draw / stake` ratios, so minimum-stake sybil accounts cannot
/// capture the fixed [`COMMITTEE_SIZE`]-seat committee while large validator
/// sets (`N > COMMITTEE_SIZE`) still verify cleanly once strictly more than two
/// thirds of committee seats and committee stake sign.
#[must_use]
pub fn handoff_committee_weighted(members: &[HandoffMember], randomness: &[u8; 32]) -> Vec<usize> {
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

/// Whether a validator set satisfies the structural handoff rules: non-empty,
/// positive stake, non-empty address and PQ key, and no duplicate addresses.
#[must_use]
pub fn member_set_is_valid(members: &[HandoffMember]) -> bool {
    if members.is_empty() {
        return false;
    }
    let mut seen = BTreeSet::new();
    for member in members {
        if member.address.is_empty()
            || member.address.iter().all(|&b| b == 0)
            || member.pq_public_key.is_empty()
            || member.pq_public_key.iter().all(|&b| b == 0)
            || member.stake == 0
            || !seen.insert(member.address.as_slice())
        {
            return false;
        }
    }
    true
}

/// One committee member's ML-DSA-65 signature.
///
/// `index` is the member's position in the outgoing set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandoffError {
    OutgoingSet,
    IncomingSet,
    Chain { expected: u64, got: u64 },
    Epoch { expected: u64, got: u64 },
    Order,
    NotCommittee(u32),
    Randomness,
    Quorum { signed: usize, committee: usize },
    Signature { index: u32, reason: String },
}

impl fmt::Display for HandoffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutgoingSet => f.write_str("the outgoing set does not match the certificate"),
            Self::IncomingSet => f.write_str("the incoming set does not match the certificate"),
            Self::Chain { expected, got } => {
                write!(f, "the certificate is for chain {got}, expected {expected}")
            }
            Self::Epoch { expected, got } => {
                write!(f, "the certificate hands over epoch {got}, expected {expected}")
            }
            Self::Order => f.write_str("signature indices are not strictly ascending"),
            Self::NotCommittee(index) => write!(f, "index {index} is not a committee seat"),
            Self::Randomness => f.write_str("the certificate randomness is not the epoch randomness"),
            Self::Quorum { signed, committee } => write!(
                f,
                "{signed} of {committee} committee members signed; more than two thirds are required"
            ),
            Self::Signature { index, reason } => {
                write!(f, "the signature of member {index} does not verify: {reason}")
            }
        }
    }
}

impl std::error::Error for HandoffError {}

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
    pub fn insert_signature(&mut self, index: u32, signature: Vec<u8>) {
        match self.signatures.binary_search_by_key(&index, |s| s.index) {
            Ok(at) => {
                if let Some(slot) = self.signatures.get_mut(at) {
                    slot.signature = signature;
                }
            }
            Err(at) => self
                .signatures
                .insert(at, HandoffSignature { index, signature }),
        }
    }

    /// Verify the certificate against `outgoing` and the canonical
    /// `epoch_randomness`, delegating cryptographic verification of each
    /// member's ML-DSA-65 signature over [`Self::signing_message`] to
    /// `verify_sig(pq_public_key, signing_message, signature)`.
    ///
    /// # Errors
    ///
    /// [`HandoffError`] for a set mismatch, a randomness that is not the
    /// epoch's, a signer outside the committee, an order violation, two
    /// thirds of seats or stake not reached, or a bad signature.
    pub fn verify_with<F>(
        &self,
        outgoing: &[HandoffMember],
        epoch_randomness: [u8; 32],
        mut verify_sig: F,
    ) -> Result<(), HandoffError>
    where
        F: FnMut(&[u8], &[u8], &[u8]) -> Result<(), String>,
    {
        if self.chain_id == 0 {
            return Err(HandoffError::Chain {
                expected: 1,
                got: 0,
            });
        }
        if !member_set_is_valid(outgoing)
            || set_digest(self.chain_id, self.epoch, outgoing) != self.outgoing_set
        {
            return Err(HandoffError::OutgoingSet);
        }
        if self.incoming_set == [0u8; 32] {
            return Err(HandoffError::IncomingSet);
        }
        if self.randomness != epoch_randomness {
            return Err(HandoffError::Randomness);
        }
        let committee = handoff_committee_weighted(outgoing, &epoch_randomness);
        if !self.signatures.windows(2).all(|w| w[0].index < w[1].index) {
            return Err(HandoffError::Order);
        }
        for entry in &self.signatures {
            let Ok(idx) = usize::try_from(entry.index) else {
                return Err(HandoffError::NotCommittee(entry.index));
            };
            if committee.binary_search(&idx).is_err() {
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
        let committee_stake: u128 = committee
            .iter()
            .filter_map(|&idx| outgoing.get(idx))
            .map(|m| u128::from(m.stake))
            .sum();
        let signed_stake: u128 = self
            .signatures
            .iter()
            .filter_map(|entry| {
                usize::try_from(entry.index)
                    .ok()
                    .and_then(|idx| outgoing.get(idx))
            })
            .map(|m| u128::from(m.stake))
            .sum();
        if committee_stake == 0 || signed_stake * 3 <= committee_stake * 2 {
            return Err(HandoffError::Quorum {
                signed,
                committee: committee.len(),
            });
        }
        let message = self.signing_message();
        for entry in &self.signatures {
            let member = usize::try_from(entry.index)
                .ok()
                .and_then(|idx| outgoing.get(idx))
                .ok_or(HandoffError::NotCommittee(entry.index))?;
            verify_sig(&member.pq_public_key, &message, &entry.signature).map_err(|reason| {
                HandoffError::Signature {
                    index: entry.index,
                    reason,
                }
            })?;
        }
        Ok(())
    }
}

/// Follow a chain of Handoff Certificates from a trusted set of
/// `start_epoch`. Each step is a certificate and the incoming set it names;
/// the result is the last `(epoch, members)` the chain reaches.
///
/// # Errors
///
/// The first step that does not continue the chain or does not verify.
pub fn follow_handoffs_with<'a, F>(
    chain_id: u64,
    start_epoch: u64,
    trusted: &'a [HandoffMember],
    steps: &'a [(HandoffCertificate, Vec<HandoffMember>)],
    epoch_randomness: &dyn Fn(u64) -> [u8; 32],
    mut verify_sig: F,
) -> Result<(u64, &'a [HandoffMember]), HandoffError>
where
    F: FnMut(&[u8], &[u8], &[u8]) -> Result<(), String>,
{
    if chain_id == 0 {
        return Err(HandoffError::Chain {
            expected: 1,
            got: 0,
        });
    }
    if !member_set_is_valid(trusted) {
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
        cert.verify_with(current, epoch_randomness(cert.epoch), &mut verify_sig)?;
        epoch = epoch.checked_add(1).ok_or(HandoffError::Epoch {
            expected: u64::MAX,
            got: cert.epoch,
        })?;
        if !member_set_is_valid(incoming) {
            return Err(HandoffError::IncomingSet);
        }
        if set_digest(chain_id, epoch, incoming) != cert.incoming_set {
            return Err(HandoffError::IncomingSet);
        }
        current = incoming;
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
    fn committee_seating_is_deterministic_and_bounded() {
        assert_eq!(handoff_committee(&set(3), &[1; 32]), vec![0, 1, 2]);
        let seats = handoff_committee(&set(800), &[7; 32]);
        assert_eq!(seats.len(), COMMITTEE_SIZE);
        assert!(seats.windows(2).all(|w| w[0] < w[1]));
        assert_ne!(seats, handoff_committee(&set(800), &[8; 32]));
    }

    #[test]
    fn weighted_committee_seats_bonded_members_ahead_of_sybils() {
        let mut mixed = Vec::with_capacity(800);
        for i in 0u32..800 {
            mixed.push(HandoffMember {
                address: i.to_be_bytes().to_vec(),
                bls_public_key: Vec::new(),
                pop_signature: Vec::new(),
                pq_public_key: vec![1u8],
                stake: if i < 60 { 10_000_000 } else { 1 },
            });
        }
        let seated = handoff_committee_weighted(&mixed, &[0xA5; 32]);
        assert_eq!(seated.len(), COMMITTEE_SIZE);
        let bonded_seated = seated.iter().filter(|&&idx| idx < 60).count();
        assert_eq!(bonded_seated, 60);
    }

    #[test]
    fn set_digest_and_signing_message_bind_every_field() {
        let m1 = HandoffMember {
            address: vec![1; 32],
            bls_public_key: vec![2; 48],
            pop_signature: vec![3; 96],
            pq_public_key: vec![4; 32],
            stake: 100,
        };
        let mut m2 = m1.clone();
        m2.stake = 101;
        assert_ne!(
            set_digest(45_261, 1, std::slice::from_ref(&m1)),
            set_digest(45_261, 1, std::slice::from_ref(&m2))
        );
        assert_ne!(
            set_digest(45_261, 1, std::slice::from_ref(&m1)),
            set_digest(45_262, 1, std::slice::from_ref(&m1))
        );
        assert_ne!(
            set_digest(45_261, 1, std::slice::from_ref(&m1)),
            set_digest(45_261, 2, std::slice::from_ref(&m1))
        );

        let c1 = HandoffCertificate::unsigned(
            45_261,
            1,
            std::slice::from_ref(&m1),
            std::slice::from_ref(&m2),
            [9; 32],
        );
        let c2 = HandoffCertificate::unsigned(45_261, 1, &[m1], &[m2], [8; 32]);
        assert_ne!(c1.signing_message(), c2.signing_message());
    }

    #[test]
    fn handoff_rejects_zero_address_zero_chain_id_and_zero_incoming_set() {
        let zero_addr_member = HandoffMember {
            address: vec![0u8; 32],
            bls_public_key: vec![2; 48],
            pop_signature: vec![3; 96],
            pq_public_key: vec![4; 32],
            stake: 100,
        };
        assert!(
            !member_set_is_valid(&[zero_addr_member]),
            "all-zero validator address must be rejected by member_set_is_valid"
        );

        let valid = HandoffMember {
            address: vec![1; 32],
            bls_public_key: vec![2; 48],
            pop_signature: vec![3; 96],
            pq_public_key: vec![4; 32],
            stake: 100,
        };
        let mut cert_zero_chain = HandoffCertificate::unsigned(
            0,
            1,
            std::slice::from_ref(&valid),
            std::slice::from_ref(&valid),
            [9; 32],
        );
        cert_zero_chain.insert_signature(0, vec![0xAA; 64]);
        assert!(
            cert_zero_chain
                .verify_with(std::slice::from_ref(&valid), [9; 32], |_, _, _| Ok(()))
                .is_err(),
            "handoff certificate with chain_id == 0 must be refused"
        );

        let mut cert_zero_incoming = HandoffCertificate::unsigned(
            45_261,
            1,
            std::slice::from_ref(&valid),
            std::slice::from_ref(&valid),
            [9; 32],
        );
        cert_zero_incoming.incoming_set = [0u8; 32];
        cert_zero_incoming.insert_signature(0, vec![0xAA; 64]);
        assert_eq!(
            cert_zero_incoming.verify_with(std::slice::from_ref(&valid), [9; 32], |_, _, _| Ok(())),
            Err(HandoffError::IncomingSet),
            "handoff certificate with all-zero incoming_set digest must be refused"
        );
    }
}
