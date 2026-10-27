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

/// The indices (into `validators`) of the members that sign the PQ part of the Handoff
/// Certificate, in ascending index order. With [`COMMITTEE_SIZE`] or fewer validators every
/// index is returned: the whole set signs. A duplicate address ranks by its own hash and an
/// index tie-break, so the result stays total and deterministic.
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
                pq_public_key: entry.pq_public_key.clone(),
                stake: entry.stake,
            })
            .collect()
    }
}

/// The digest of the validator set of `epoch` on `chain_id`: every member's
/// address, ML-DSA-65 key and stake, length prefixed, in set order.
#[must_use]
pub fn set_digest(chain_id: u64, epoch: u64, members: &[HandoffMember]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    absorb(&mut hasher, SET_TAG);
    absorb(&mut hasher, &chain_id.to_le_bytes());
    absorb(&mut hasher, &epoch.to_le_bytes());
    absorb(&mut hasher, &(members.len() as u64).to_le_bytes());
    for member in members {
        absorb(&mut hasher, &member.address);
        absorb(&mut hasher, &member.pq_public_key);
        absorb(&mut hasher, &member.stake.to_le_bytes());
    }
    hasher.finalize().into()
}

/// One committee member's ML-DSA-65 signature; `index` is the member's
/// position in the outgoing set.
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
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
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
        if set_digest(self.chain_id, self.epoch, outgoing) != self.outgoing_set {
            return Err(HandoffError::OutgoingSet);
        }
        if self.randomness != epoch_randomness {
            return Err(HandoffError::Randomness);
        }
        let addresses: Vec<Vec<u8>> = outgoing.iter().map(|m| m.address.clone()).collect();
        let committee = handoff_committee(&addresses, &epoch_randomness);
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
pub fn follow_handoffs<'a>(
    registry: &crate::crypto::scheme::SchemeStatusRegistry,
    chain_id: u64,
    start_epoch: u64,
    trusted: &'a [HandoffMember],
    steps: &'a [(HandoffCertificate, Vec<HandoffMember>)],
    epoch_randomness: &dyn Fn(u64) -> [u8; 32],
) -> Result<(u64, &'a [HandoffMember]), HandoffError> {
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
        epoch = epoch.saturating_add(1);
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
        (0..n).map(|i| (i as u32).to_be_bytes().to_vec()).collect()
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
            .map(|(i, key)| HandoffMember {
                address: vec![u8::try_from(i).unwrap_or(0); 32],
                pq_public_key: key.public_key_bytes().to_vec(),
                stake: 10,
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
        let (epoch, reached) = follow_handoffs(&registry, 7, 4, &outgoing, &steps, &|_| [3; 32])
            .expect("follows");
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
        let mut forged_set = incoming.clone();
        forged_set[1].stake = 99;
        assert_eq!(
            follow_handoffs(&registry, 7, 4, &outgoing, &[(cert, forged_set)], &|_| [3; 32]),
            Err(HandoffError::IncomingSet)
        );
    }
}
