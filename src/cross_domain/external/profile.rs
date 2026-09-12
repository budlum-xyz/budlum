//! The objective information profile shown for an external domain.
//!
//! # Why there is no score in here
//!
//! A "trust score" would be a number Budlum computed about somebody else's
//! chain. It would rank a 512-validator sync committee against a
//! million-validator set, weight a bond against a proof system, and collapse
//! assumptions that are not commensurable into a single figure. Every input
//! to that figure would be a judgement, the weighting would be ours, and the
//! output would be quoted back to us as if it were a measurement.
//!
//! So this module computes nothing evaluative. It reads facts off the domain's
//! own registration and presents them with their units attached. A reader who
//! wants to decide whether 40 bonded tokens is enough backing for their use
//! case decides it themselves, with the number in front of them - which is the
//! only arrangement in which that decision is theirs.
//!
//! Every field below answers "what is registered" or "what happened", never
//! "how good is it".

use crate::cross_domain::external::spec::{
    AdapterDescriptor, DomainKey, FinalityKind, SecurityBacking, TrustModel,
};
use serde::{Deserialize, Serialize};

/// The domain's lifecycle. Every transition is recorded, because "was this
/// domain ever refused" is a fact a reader is entitled to and a boolean
/// "active" would hide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainState {
    /// Registered, no attestation accepted yet.
    Registered,
    /// Admission's self-test ran and passed; the domain may be routed through.
    Admitted,
    /// Live and serving attestations.
    Active,
    /// The domain asked to stop. Its history stays readable.
    Retired,
    /// An attestation was refused after admission. Not a judgement about the
    /// chain - a record that the adapter and the evidence disagreed.
    Faulted,
}

impl DomainState {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Admitted => "admitted",
            Self::Active => "active",
            Self::Retired => "retired",
            Self::Faulted => "faulted",
        }
    }

    /// Whether attestations from this domain are currently consumed.
    #[must_use]
    pub fn serves(&self) -> bool {
        matches!(self, Self::Admitted | Self::Active)
    }
}

/// One state change, kept forever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateEvent {
    pub at_height: u64,
    pub from: DomainState,
    pub to: DomainState,
    /// Why, in the words of whoever caused the transition. Stored verbatim;
    /// not interpreted.
    pub reason: String,
}

/// What the profile shows. Constructed by [`profile_of`], which reads only the
/// domain's own record - it takes no argument that represents Budlum's
/// opinion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainProfile {
    pub domain: DomainKey,
    pub state: DomainState,

    // --- From the adapter's own declaration, unchanged ---
    /// The target's consensus, in the target's own words.
    pub consensus_kind: String,
    /// What kind of finality the target offers.
    pub finality_kind: FinalityKind,
    /// How deep the adapter insists on going.
    pub required_depth: u64,
    /// Who must be honest for an attestation to be true.
    pub trust_model: TrustModel,
    /// The evidence versions currently inside their window.
    pub accepted_evidence_versions: Vec<u32>,
    /// Whether the domain has ever forked its evidence format, and how many
    /// times. A fork history is a fact about the target's stability that a
    /// reader may care about; the count is theirs to weigh.
    pub evidence_forks: u32,

    // --- Economic backing, with units ---
    /// The bond currently posted against this domain. In the chain's own
    /// smallest unit, named so it cannot be read as whole tokens.
    pub bond_atoms: u128,
    /// The unit `bond_atoms` is denominated in.
    pub bond_unit: &'static str,
    /// How many distinct addresses posted it. One address posting 1,000 and
    /// fifty posting 20 are different facts about who would have to collude.
    pub bond_posters: u64,

    // --- What happened, not what we think ---
    pub attestations_accepted: u64,
    pub attestations_refused: u64,
    /// The most recent height an attestation was accepted at, in the target's
    /// numbering.
    pub last_accepted_height: Option<u64>,
    /// When the last attestation was verified, in Budlum heights.
    pub last_verified_at: Option<u64>,
    /// The backing of the most recent accepted attestation. Carried so a
    /// reader can see whether the backing has changed shape - a domain that
    /// quietly moved from slashable signatures to an unslashable committee is
    /// visible here.
    pub last_backing: Option<SecurityBacking>,
    /// The full state history.
    pub history: Vec<StateEvent>,
}

impl DomainProfile {
    /// The ratio of refusals to attempts, as a pair rather than a percentage:
    /// a percentage invites a threshold, and any threshold we chose would be
    /// a score with extra steps.
    #[must_use]
    pub fn refusal_ratio(&self) -> (u64, u64) {
        (
            self.attestations_refused,
            self.attestations_accepted.saturating_add(self.attestations_refused),
        )
    }

    /// How stale this domain is, in Budlum heights. `None` if it has never
    /// produced an attestation - which is a different fact from "very stale",
    /// and is reported separately rather than as a large number.
    #[must_use]
    pub fn staleness(&self, now_height: u64) -> Option<u64> {
        self.last_verified_at
            .map(|then| now_height.saturating_sub(then))
    }

    /// A single line for a display surface. Contains no evaluation: it is the
    /// facts, comma-separated, with units.
    #[must_use]
    pub fn summary_line(&self) -> String {
        let (refused, attempts) = self.refusal_ratio();
        format!(
            "{} | consensus={} | finality={:?} | depth>={} | bond={} {} from {} poster(s) | accepted={} refused={}/{} | forks={}",
            self.state.as_str(),
            self.consensus_kind,
            self.finality_kind,
            self.required_depth,
            self.bond_atoms,
            self.bond_unit,
            self.bond_posters,
            self.attestations_accepted,
            refused,
            attempts,
            self.evidence_forks,
        )
    }
}

/// The record a domain's profile is read from. This is what the registry
/// stores; the profile is a view of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainRecord {
    pub domain: DomainKey,
    pub descriptor: AdapterDescriptor,
    pub state: DomainState,
    pub bond_atoms: u128,
    pub bond_posters: u64,
    pub evidence_forks: u32,
    pub accepted_evidence_versions: Vec<u32>,
    pub attestations_accepted: u64,
    pub attestations_refused: u64,
    pub last_accepted_height: Option<u64>,
    pub last_verified_at: Option<u64>,
    pub last_backing: Option<SecurityBacking>,
    pub history: Vec<StateEvent>,
}

/// Builds the profile. Reads the record and nothing else - the signature is
/// the guarantee: there is no parameter into which an opinion could be
/// smuggled.
#[must_use]
pub fn profile_of(record: &DomainRecord) -> DomainProfile {
    DomainProfile {
        domain: record.domain,
        state: record.state,
        consensus_kind: record.descriptor.consensus_kind.clone(),
        finality_kind: record.descriptor.finality_kind,
        required_depth: record.descriptor.required_depth,
        trust_model: record.descriptor.trust_model,
        accepted_evidence_versions: record.accepted_evidence_versions.clone(),
        evidence_forks: record.evidence_forks,
        bond_atoms: record.bond_atoms,
        bond_unit: BOND_UNIT,
        bond_posters: record.bond_posters,
        attestations_accepted: record.attestations_accepted,
        attestations_refused: record.attestations_refused,
        last_accepted_height: record.last_accepted_height,
        last_verified_at: record.last_verified_at,
        last_backing: record.last_backing,
        history: record.history.clone(),
    }
}

/// The unit every bond in this module is denominated in. Named once so no
/// display surface can present atoms as tokens.
pub const BOND_UNIT: &str = "atoms";
