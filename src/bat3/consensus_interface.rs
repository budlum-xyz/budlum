//! Consensus-agnostic fact anchor: binds a `Bat3` journal entry to a
//! verified external finality attestation and re-checks the binding.
//!
//! WIRING: reached through `crate::bat3` (re-exported in `src/bat3/mod.rs`)
//! and called by `crate::explorer_evidence::anchor_bat3_evidence_fact`.

use crate::core::hash::hash_fields_bytes;
use crate::cross_domain::external::spec::{FinalityAttestation, SecurityBacking};
use serde::{Deserialize, Serialize};

use super::journal::Bat3JournalEntry;

/// The backing class a consensus fact was bound under.
///
/// WIRING: carried inside [`ConsensusFact`] and reported to explorer views.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactBackingClass {
    /// A signature-set backing (`> 2/3` of a bounded, bonded committee).
    SignatureSet,
    /// Proof-of-work backing above the anchored height.
    Work,
    /// A validity-proof backing.
    Zk,
    /// A permissioned authority set.
    Authority,
    /// No cryptographic backing this cycle.
    None,
}

/// Why a `Bat3` consensus fact binding or verification was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum Bat3ConsensusError {
    /// The attestation carried no cryptographic backing.
    #[error("Bat3 consensus fact attestation carries no cryptographic backing")]
    UnbackedAttestation(FactBackingClass),
    /// The attestation's field disagrees with the fact's recorded value.
    #[error("Bat3 consensus fact attestation mismatch on {0}")]
    AttestationMismatch(&'static str),
}

/// A `Bat3` journal entry bound to a verified external finality attestation.
///
/// WIRING: produced by [`ConsensusFact::bind_from_attestation`] and verified
/// by [`ConsensusFact::verify_against_attestation`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusFact {
    entry: Bat3JournalEntry,
    backing: FactBackingClass,
    binding: [u8; 32],
}

impl ConsensusFact {
    /// Binds a journal entry to a finality attestation, requiring that the
    /// attestation carries cryptographic backing.
    ///
    /// # Errors
    ///
    /// Returns [`Bat3ConsensusError::UnbackedAttestation`] if the attestation
    /// carries [`SecurityBacking::None`].
    pub fn bind_from_attestation(
        entry: &Bat3JournalEntry,
        attestation: &FinalityAttestation,
    ) -> Result<Self, Bat3ConsensusError> {
        let backing = match &attestation.security {
            SecurityBacking::SignatureSet { .. } => FactBackingClass::SignatureSet,
            SecurityBacking::Work { .. } => FactBackingClass::Work,
            SecurityBacking::Zk { .. } => FactBackingClass::Zk,
            SecurityBacking::Authority { .. } => FactBackingClass::Authority,
            SecurityBacking::None => {
                return Err(Bat3ConsensusError::UnbackedAttestation(
                    FactBackingClass::None,
                ));
            }
        };
        let binding = Self::binding_digest(entry, attestation, backing);
        Ok(Self {
            entry: entry.clone(),
            backing,
            binding,
        })
    }

    /// Re-verifies that the recorded binding still matches the attestation.
    ///
    /// # Errors
    ///
    /// Returns [`Bat3ConsensusError::AttestationMismatch`] if a field the
    /// binding depends on has changed.
    pub fn verify_against_attestation(
        &self,
        entry: &Bat3JournalEntry,
        attestation: &FinalityAttestation,
    ) -> Result<(), Bat3ConsensusError> {
        let backing = match &attestation.security {
            SecurityBacking::SignatureSet { .. } => FactBackingClass::SignatureSet,
            SecurityBacking::Work { .. } => FactBackingClass::Work,
            SecurityBacking::Zk { .. } => FactBackingClass::Zk,
            SecurityBacking::Authority { .. } => FactBackingClass::Authority,
            SecurityBacking::None => {
                return Err(Bat3ConsensusError::UnbackedAttestation(
                    FactBackingClass::None,
                ));
            }
        };
        if self.backing != backing {
            return Err(Bat3ConsensusError::AttestationMismatch("security"));
        }
        if self.entry.sequence() != entry.sequence()
            || self.entry.height() != entry.height()
            || self.entry.digest() != entry.digest()
        {
            return Err(Bat3ConsensusError::AttestationMismatch("entry"));
        }
        let binding = Self::binding_digest(entry, attestation, backing);
        if binding != self.binding {
            return Err(Bat3ConsensusError::AttestationMismatch("state_root"));
        }
        Ok(())
    }

    /// The journal entry this fact was bound to.
    #[must_use]
    pub fn entry(&self) -> &Bat3JournalEntry {
        &self.entry
    }

    /// The backing class this fact was bound under.
    #[must_use]
    pub const fn backing(&self) -> FactBackingClass {
        self.backing
    }

    /// The self-derived binding digest of this fact.
    #[must_use]
    pub const fn binding(&self) -> &[u8; 32] {
        &self.binding
    }

    fn binding_digest(
        entry: &Bat3JournalEntry,
        attestation: &FinalityAttestation,
        backing: FactBackingClass,
    ) -> [u8; 32] {
        let height_le = attestation.height.to_le_bytes();
        let tag: &[u8] = match backing {
            FactBackingClass::SignatureSet => b"BDLM_BAT3_CONSENSUS_FACT_V1/sig",
            FactBackingClass::Work => b"BDLM_BAT3_CONSENSUS_FACT_V1/work",
            FactBackingClass::Zk => b"BDLM_BAT3_CONSENSUS_FACT_V1/zk",
            FactBackingClass::Authority => b"BDLM_BAT3_CONSENSUS_FACT_V1/auth",
            FactBackingClass::None => b"BDLM_BAT3_CONSENSUS_FACT_V1/none",
        };
        hash_fields_bytes(&[
            b"BDLM_BAT3_CONSENSUS_FACT_V1",
            tag,
            &entry.sequence().to_le_bytes(),
            entry.digest(),
            entry.topic().as_bytes(),
            &height_le,
            &attestation.state_root,
            &attestation.evidence_digest,
        ])
    }
}
