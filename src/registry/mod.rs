//! Participation registries for Budlum's multi-consensus L1.
//!
//! This module encodes the master-context split between two deliberately
//! separate membership models:
//!
//! * [`permissionless`] — the network-wide default for PoW/PoS/BFT domains.
//!   Anyone may join by staking; there is **no whitelist, approval or central
//!   gate**. Security = stake + slashing. This is a generic, role-parameterised
//!   primitive (see [`role`]) so future application layers can reuse it.
//!
//! * [`poa_membership`] — the isolated permissioned exception for the PoA
//!   domain (institutional / regulated parties). Entry is by **KYC + approval**,
//!   never by staking.
//!
//! The two are intentionally different types backed by different data
//! structures. There is no shared code path between them, which is what keeps
//! the PoA domain's permissioned rules from leaking into the permissionless
//! domains and vice-versa. The isolation is exercised by
//! `tests::permissionless`.

pub mod d4_merge_tests;
pub mod evidence;
pub mod invalid_vote;
pub mod liveness;
pub mod params;
pub mod permissionless;
pub mod poa_compliance;
pub mod poa_membership;
pub mod poa_onboarding;
pub mod role;

pub use invalid_vote::InvalidVoteTracker;
pub use liveness::LivenessTracker;

pub use evidence::{EvidenceError, ProofProvenance, SlashingProof, SlashingReport};
pub use params::RegistryParams;
pub use permissionless::{
    MemberStatus, PermissionlessRegistry, Registration, RegistryError, SlashOutcome,
    SlashingCondition, MIN_REGISTRATION_STAKE, UNBONDING_EPOCHS,
};
pub use poa_compliance::{
    ComplianceAction, ComplianceAuditEvent, ComplianceDomainKind, FreezeRecord, PoaComplianceError,
    PoaComplianceRegistry, ScreeningRecord, ScreeningStatus, TravelRuleRecord,
};
pub use poa_membership::{
    KycCommitment, MembershipStatus, PoaMember, PoaMembershipError, PoaMembershipRegistry,
};
pub use poa_onboarding::{
    OnboardingDecision, OnboardingEvent, PoAOnboarding, PoAWhitelist, DEFAULT_KYC_HORIZON,
};
pub use role::{roles, RoleId};
