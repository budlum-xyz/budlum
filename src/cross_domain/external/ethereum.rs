//! The first concrete adapter: an Ethereum-type PoS chain, verified through its
//! Altair sync committee.
//!
//! # What the sync committee gives us, and what it does not
//!
//! A sync committee is 512 validators, resampled every 256 epochs (about 27
//! hours), who sign the recent block header with BLS12-381 keys. Their
//! signatures aggregate into one, so a light client can check "a supermajority
//! of the current committee signed this header" with one pairing instead of
//! 512. That is a real, cheap, widely-deployed proof, and it is what Helios,
//! Telepathy and the SP1 light client all verify.
//!
//! What it does not give us is **slashability**. Altair defines no slashing
//! condition for sync committee messages. A committee that signs a header for a
//! chain that does not exist loses nothing. The honest statement of this
//! adapter's security is therefore "an honest majority of a 512-validator
//! sample, with no economic penalty for dishonesty" - and that is exactly what
//! [`SecurityBacking::SignatureSet`] carries, with `slashable: false`. A
//! consumer who needs slashable finality should look at a proof over the full
//! validator set instead, and can now tell the two apart without reading
//! anybody's prose.
//!
//! # Finality depth
//!
//! Casper FFG finalises a checkpoint once two consecutive epochs justify it,
//! which in practice is around 12.8 minutes at 32 slots per epoch and 12
//! seconds per slot. This adapter requires the *finalized* header, not the
//! attested one, and refuses anything that only reaches justification - a
//! justified checkpoint can still be reverted by a conflicting finalisation.
//!
//! # The BLS dependency
//!
//! Verifying the aggregate signature needs BLS12-381 pairing arithmetic against
//! the beacon chain's domain-separated signing root. This module does not
//! implement that; it takes a [`BlsVerifier`] and refuses with
//! [`AdapterError::Unavailable`] when none is installed. Refusing is the
//! behaviour here, not an approximation: an adapter that skipped the pairing
//! check would accept a committee of one signature, and nothing downstream
//! could tell.

use crate::cross_domain::external::selftest::{BytePatch, ExpectedRefusal, FaultProbe, RefusalKind};
use crate::cross_domain::external::spec::{
    AdapterDescriptor, AdapterError, AdapterId, FinalityAttestation, FinalityKind,
    ProofSystem, RawConsensusEvidence, SecurityBacking, TimeUnit, TrustModel,
    VerificationPolicy,
};
use serde::{Deserialize, Serialize};

/// `SYNC_COMMITTEE_SIZE` in the Altair preset: 2**9.
pub const SYNC_COMMITTEE_SIZE: u64 = 512;
/// `EPOCHS_PER_SYNC_COMMITTEE_PERIOD`: 2**8, about 27 hours.
pub const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64 = 256;
/// `SLOTS_PER_EPOCH` on mainnet.
pub const SLOTS_PER_EPOCH: u64 = 32;
/// The participation bitvector is one bit per committee member.
pub const BITVECTOR_BYTES: usize = (SYNC_COMMITTEE_SIZE / 8) as usize;

/// The 2/3 threshold, written as an inequality rather than a number.
///
/// The spec's rule is `sum(bits) * 3 >= SYNC_COMMITTEE_SIZE * 2`, which for 512
/// means at least 342 signers. Computing `512 * 2 / 3 = 341` and comparing with
/// `>=` would admit 341, which is below the spec's threshold - an off-by-one
/// here is a supermajority that is not one. The inequality is kept in the code
/// so the rounding question never has to be answered.
#[must_use]
pub fn has_supermajority(signers: u64) -> bool {
    signers.saturating_mul(3) >= SYNC_COMMITTEE_SIZE.saturating_mul(2)
}

/// The smallest signer count that satisfies the threshold. Exposed so a test
/// can sit exactly on the boundary instead of near it.
#[must_use]
pub fn minimum_signers() -> u64 {
    (0..=SYNC_COMMITTEE_SIZE)
        .find(|n| has_supermajority(*n))
        .unwrap_or(SYNC_COMMITTEE_SIZE)
}

/// Counts set bits. `u32::count_ones` over each byte; written out rather than
/// using a table because the loop is six lines and a table is a thing to keep
/// in sync.
#[must_use]
pub fn participation(bits: &[u8]) -> u64 {
    bits.iter().map(|b| u64::from(b.count_ones())).sum()
}

/// Slot to epoch.
#[must_use]
pub fn epoch_of_slot(slot: u64) -> u64 {
    slot / SLOTS_PER_EPOCH
}

/// Slot to sync committee period.
#[must_use]
pub fn period_of_slot(slot: u64) -> u64 {
    epoch_of_slot(slot) / EPOCHS_PER_SYNC_COMMITTEE_PERIOD
}

/// The BLS check, injected.
///
/// A trait rather than a direct call so this adapter can be tested without
/// pairing arithmetic, and so a build without the dependency fails loudly at
/// construction instead of quietly at verification.
pub trait BlsVerifier: Send + Sync {
    /// Verifies an aggregate signature against an aggregate public key.
    ///
    /// `signing_root` is the beacon chain's domain-separated signing root;
    /// constructing it is the caller's job and is the part most often got
    /// wrong, which is why it is a parameter and not something this module
    /// derives from a slot number it was handed.
    fn verify_aggregate(
        &self,
        signing_root: &[u8; 32],
        aggregate_pubkey: &[u8],
        signature: &[u8],
        participants: u64,
    ) -> Result<(), String>;
}

/// The payload layout. Fixed offsets, declared as constants, because a parser
/// whose offsets live inline in the code cannot be probed by offset - and
/// probing by offset is the whole admission model.
pub mod layout {
    /// 32 bytes: the finalized header's hash tree root.
    pub const FINALIZED_ROOT: std::ops::Range<usize> = 0..32;
    /// 8 bytes, little endian: the finalized slot.
    pub const FINALIZED_SLOT: std::ops::Range<usize> = 32..40;
    /// 8 bytes, little endian: the attested slot.
    pub const ATTESTED_SLOT: std::ops::Range<usize> = 40..48;
    /// 8 bytes, little endian: the period this update belongs to.
    pub const PERIOD: std::ops::Range<usize> = 48..56;
    /// 32 bytes: the next sync committee's root, so the committee can be
    /// rotated forward without trusting a fresh source.
    pub const NEXT_COMMITTEE_ROOT: std::ops::Range<usize> = 56..88;
    /// 96 bytes: the aggregate public key (BLS12-381 G1).
    pub const AGGREGATE_PUBKEY: std::ops::Range<usize> = 88..184;
    /// 96 bytes: the aggregate signature (BLS12-381 G2).
    pub const SIGNATURE: std::ops::Range<usize> = 184..280;
    /// 64 bytes: one bit per committee member.
    pub const PARTICIPATION_BITS: std::ops::Range<usize> = 280..344;
    /// 32 bytes: the finalized state root - the thing Budlum actually commits
    /// to. Distinct from the header root above: a consumer that wanted the
    /// header root is reading the wrong field.
    pub const STATE_ROOT: std::ops::Range<usize> = 344..376;
    /// Total payload length.
    pub const LEN: usize = 376;
}

/// The parsed update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCommitteeUpdate {
    pub finalized_root: [u8; 32],
    pub finalized_slot: u64,
    pub attested_slot: u64,
    pub period: u64,
    pub next_committee_root: [u8; 32],
    pub aggregate_pubkey: Vec<u8>,
    pub signature: Vec<u8>,
    pub participation_bits: Vec<u8>,
    pub state_root: [u8; 32],
}

impl SyncCommitteeUpdate {
    /// The number of committee members who signed.
    #[must_use]
    pub fn signers(&self) -> u64 {
        participation(&self.participation_bits)
    }
}

/// Reads the fixed-layout payload.
///
/// # Errors
///
/// [`AdapterError::Malformed`] naming the offset, so a truncated or
/// misaligned payload points at where it went wrong.
pub fn parse_update(payload: &[u8]) -> Result<SyncCommitteeUpdate, AdapterError> {
    fn slice<'a>(
        payload: &'a [u8],
        range: std::ops::Range<usize>,
        what: &str,
    ) -> Result<&'a [u8], AdapterError> {
        payload.get(range.clone()).ok_or(AdapterError::Malformed {
            offset: range.start,
            reason: format!("{what} is not present"),
        })
    }
    fn fixed<const N: usize>(
        payload: &[u8],
        range: std::ops::Range<usize>,
        what: &str,
    ) -> Result<[u8; N], AdapterError> {
        let bytes = slice(payload, range, what)?;
        <[u8; N]>::try_from(bytes).map_err(|_| AdapterError::Malformed {
            offset: 0,
            reason: format!("{what} is not {N} bytes"),
        })
    }
    fn u64_at(payload: &[u8], range: std::ops::Range<usize>, what: &str) -> Result<u64, AdapterError> {
        let bytes = slice(payload, range, what)?;
        let arr = <[u8; 8]>::try_from(bytes).map_err(|_| AdapterError::Malformed {
            offset: 0,
            reason: format!("{what} is not 8 bytes"),
        })?;
        Ok(u64::from_le_bytes(arr))
    }

    if payload.len() != layout::LEN {
        return Err(AdapterError::Malformed {
            offset: payload.len(),
            reason: format!("payload is {} bytes, expected {}", payload.len(), layout::LEN),
        });
    }

    Ok(SyncCommitteeUpdate {
        finalized_root: fixed(payload, layout::FINALIZED_ROOT, "finalized_root")?,
        finalized_slot: u64_at(payload, layout::FINALIZED_SLOT, "finalized_slot")?,
        attested_slot: u64_at(payload, layout::ATTESTED_SLOT, "attested_slot")?,
        period: u64_at(payload, layout::PERIOD, "period")?,
        next_committee_root: fixed(payload, layout::NEXT_COMMITTEE_ROOT, "next_committee_root")?,
        aggregate_pubkey: slice(payload, layout::AGGREGATE_PUBKEY, "aggregate_pubkey")?.to_vec(),
        signature: slice(payload, layout::SIGNATURE, "signature")?.to_vec(),
        participation_bits: slice(payload, layout::PARTICIPATION_BITS, "participation_bits")?
            .to_vec(),
        state_root: fixed(payload, layout::STATE_ROOT, "state_root")?,
    })
}

/// The adapter.
pub struct EthereumSyncAdapter {
    descriptor: AdapterDescriptor,
    /// The network this instance serves. Checked on every call: one adapter
    /// binary pointed at a second network must not keep producing
    /// attestations, because the signing root it holds belongs to the first.
    network: String,
    verifier: Option<Box<dyn BlsVerifier>>,
    /// The signing root is supplied per call by the caller that owns the
    /// beacon chain's fork version and genesis validators root. Stored here so
    /// the adapter has one place that says "I need this and cannot derive it".
    signing_root: [u8; 32],
    golden: Option<RawConsensusEvidence>,
}

impl EthereumSyncAdapter {
    /// # Errors
    ///
    /// Nothing: an adapter without a verifier constructs fine and refuses at
    /// verification time. Constructing is not the moment to fail, because the
    /// caller may be building a registry of adapters before installing crypto.
    #[must_use]
    pub fn new(
        network: &str,
        signing_root: [u8; 32],
        verifier: Option<Box<dyn BlsVerifier>>,
    ) -> Self {
        let id = AdapterId::from_name(&format!("ethereum-sync-{network}"));
        Self {
            network: network.to_string(),
            descriptor: AdapterDescriptor {
                id,
                name: format!("ethereum-sync-{network}"),
                adapter_version: 1,
                accepted_evidence_versions: vec![1],
                consensus_kind: "gasper-pos".to_string(),
                finality_kind: FinalityKind::ProtocolFinality,
                // Two epochs of Casper FFG. Declared rather than derived from
                // a slot count, because the depth a consumer relies on should
                // be a number they can read.
                required_depth: 2 * SLOTS_PER_EPOCH,
                time_unit: TimeUnit::Slot,
                trust_model: TrustModel::HonestMajority {
                    set_size: SYNC_COMMITTEE_SIZE,
                },
            },
            verifier,
            signing_root,
            golden: None,
        }
    }

    /// Attaches a golden sample. Separate from `new` because a golden sample
    /// has to be real evidence, and the caller is the one who has a beacon
    /// node.
    #[must_use]
    pub fn with_golden(mut self, golden: RawConsensusEvidence) -> Self {
        self.golden = Some(golden);
        self
    }
}

impl crate::cross_domain::external::spec::ExternalFinalityAdapter for EthereumSyncAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        self.descriptor.clone()
    }

    fn verify(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, AdapterError> {
        if evidence.adapter != self.descriptor.id {
            return Err(AdapterError::WrongAdapter {
                expected: self.descriptor.name.clone(),
                found: "another adapter".to_string(),
            });
        }
        // The signing root held by this instance belongs to one network. An
        // evidence envelope naming another one is refused here rather than
        // verified against the wrong genesis, which would produce a signature
        // check that means nothing.
        if evidence.network != self.network {
            return Err(AdapterError::WrongAdapter {
                expected: self.network.clone(),
                found: evidence.network.clone(),
            });
        }
        if !self
            .descriptor
            .accepted_evidence_versions
            .contains(&evidence.evidence_version)
        {
            return Err(AdapterError::UnsupportedEvidenceVersion {
                version: evidence.evidence_version,
                accepted: "1".to_string(),
            });
        }

        let update = parse_update(&evidence.payload)?;

        // The declared fields must be the derived ones. Without this the
        // envelope's claim and the payload's content can drift, and the
        // network would be indexing one while committing the other.
        if policy.require_declared_match {
            if evidence.declared_height != update.finalized_slot {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if evidence.declared_root != update.state_root {
                return Err(AdapterError::DeclarationMismatch { field: "state_root" });
            }
        }

        // Finalized must not be ahead of attested: the attested header is the
        // one the committee signed, and a finalized header beyond it is a
        // claim about something nobody signed.
        if update.finalized_slot > update.attested_slot {
            return Err(AdapterError::ConsensusRule {
                rule: "finalized slot is ahead of the attested slot".to_string(),
            });
        }

        // The declared period must be the one the slot belongs to. A period
        // taken from the envelope rather than derived would let one committee's
        // signature be presented for another period.
        if update.period != period_of_slot(update.finalized_slot) {
            return Err(AdapterError::ConsensusRule {
                rule: "declared period does not match the finalized slot's period".to_string(),
            });
        }

        // Participation, before the expensive check: a bitvector that does not
        // reach 2/3 is a refusal regardless of whether the signature verifies.
        let signers = update.signers();
        if !has_supermajority(signers) {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "{signers} of {SYNC_COMMITTEE_SIZE} signed; the threshold is {}",
                    minimum_signers()
                ),
            });
        }

        // The pairing check. Refused when no verifier is installed - there is
        // no mode in which this adapter accepts an unchecked signature.
        let Some(verifier) = self.verifier.as_ref() else {
            return Err(AdapterError::Unavailable {
                reason: "no BLS verifier installed; refusing rather than skipping the check"
                    .to_string(),
            });
        };
        verifier
            .verify_aggregate(
                &self.signing_root,
                &update.aggregate_pubkey,
                &update.signature,
                signers,
            )
            .map_err(|e| AdapterError::Crypto { what: e })?;

        // Depth and age, against the caller's policy rather than the
        // adapter's opinion of how deep is deep enough.
        let depth = update.attested_slot.saturating_sub(update.finalized_slot);
        if depth < policy.min_depth {
            return Err(AdapterError::InsufficientDepth {
                observed: depth,
                required: policy.min_depth,
            });
        }
        if policy.max_age > 0 {
            let age = policy.now.saturating_sub(update.finalized_slot);
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        Ok(FinalityAttestation {
            adapter: self.descriptor.id,
            domain: crate::cross_domain::external::spec::DomainKey::from_parts(
                &self.descriptor.id,
                &evidence.network,
            ),
            height: update.finalized_slot,
            state_root: update.state_root,
            finalized_at: epoch_of_slot(update.finalized_slot),
            time_unit: TimeUnit::Epoch,
            security: SecurityBacking::SignatureSet {
                signers,
                required: minimum_signers(),
                total_weight: u128::from(SYNC_COMMITTEE_SIZE),
                // The load-bearing line in this file. Altair defines no
                // slashing condition for sync committee messages, so a
                // dishonest committee loses nothing. Saying otherwise would be
                // the one claim in this adapter that a reader could not check.
                slashable: false,
            },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
        })
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        // Every probe is a byte patch, so any node can apply and replay it.
        // The offsets come from `layout`, which is why the layout is constants
        // rather than inline arithmetic.
        vec![
            FaultProbe {
                name: "a payload that is one byte short is refused, not partially parsed".to_string(),
                patch: BytePatch::TruncatePayload {
                    keep: layout::LEN - 1,
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "an empty payload is refused".to_string(),
                patch: BytePatch::TruncatePayload { keep: 0 },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "a declared height that the payload does not support is refused".to_string(),
                patch: BytePatch::DeclaredHeight { value: u64::MAX },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "a declared root that the payload does not support is refused".to_string(),
                patch: BytePatch::DeclaredRoot { value: [0xff; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "an evidence version this adapter never accepted is refused at the gate".to_string(),
                patch: BytePatch::EvidenceVersion { value: 99 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "a participation bitvector with nobody signing is refused before the pairing check"
                    .to_string(),
                patch: BytePatch::InPayload {
                    offset: layout::PARTICIPATION_BITS.start,
                    bytes: vec![0u8; BITVECTOR_BYTES],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "a participation bitvector one signer below the threshold is refused".to_string(),
                patch: BytePatch::InPayload {
                    offset: layout::PARTICIPATION_BITS.start,
                    // minimum_signers() - 1 bits set: exactly one short.
                    bytes: bits_for(minimum_signers().saturating_sub(1)),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "corrupting the aggregate signature is refused by the crypto door".to_string(),
                patch: BytePatch::InPayload {
                    offset: layout::SIGNATURE.start,
                    bytes: vec![0u8; 96],
                },
                expect: ExpectedRefusal::Any,
            },
            FaultProbe {
                name: "corrupting the aggregate public key is refused by the crypto door".to_string(),
                patch: BytePatch::InPayload {
                    offset: layout::AGGREGATE_PUBKEY.start,
                    bytes: vec![0u8; 96],
                },
                expect: ExpectedRefusal::Any,
            },
            FaultProbe {
                name: "pointing the adapter at a different network is refused".to_string(),
                patch: BytePatch::Network {
                    value: "not-this-network".to_string(),
                },
                expect: ExpectedRefusal::Any,
            },
        ]
    }

    fn golden_evidence(&self) -> Option<RawConsensusEvidence> {
        self.golden.clone()
    }
}

/// Builds a bitvector with the first `count` bits set. Used by the boundary
/// probe, which is the one that catches an off-by-one in the threshold.
#[must_use]
pub fn bits_for(count: u64) -> Vec<u8> {
    let mut out = vec![0u8; BITVECTOR_BYTES];
    let mut remaining = count;
    for byte in &mut out {
        if remaining == 0 {
            break;
        }
        let set = remaining.min(8);
        *byte = u8::MAX >> (8u32.saturating_sub(set as u32));
        remaining = remaining.saturating_sub(set);
    }
    out
}

/// A [`BlsVerifier`] that accepts everything. Exists so the adapter's
/// *structural* rules can be tested without pairing arithmetic - and it is
/// deliberately in the test surface, not in production, because an adapter
/// wired to it accepts any signature.
#[cfg(test)]
pub struct AcceptAllBls;

#[cfg(test)]
impl BlsVerifier for AcceptAllBls {
    fn verify_aggregate(
        &self,
        _signing_root: &[u8; 32],
        _aggregate_pubkey: &[u8],
        _signature: &[u8],
        _participants: u64,
    ) -> Result<(), String> {
        Ok(())
    }
}

/// A [`BlsVerifier`] that refuses everything, for the probe that must not pass
/// by accident.
#[cfg(test)]
pub struct RefuseAllBls;

#[cfg(test)]
impl BlsVerifier for RefuseAllBls {
    fn verify_aggregate(
        &self,
        _signing_root: &[u8; 32],
        _aggregate_pubkey: &[u8],
        _signature: &[u8],
        _participants: u64,
    ) -> Result<(), String> {
        Err("refused by the test verifier".to_string())
    }
}

/// A note on the proof system this adapter would use if the pairing check were
/// moved into a circuit. Exposed as a constant rather than buried in a comment,
/// because the choice is part of the security story: a STARK has a transparent
/// setup, which matters for a component whose whole job is removing trusted
/// parties.
pub const ZK_PROOF_SYSTEM: ProofSystem = ProofSystem::Stark;
