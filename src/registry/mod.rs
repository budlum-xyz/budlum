//! Participation registries for Budlum's multi-consensus L1.
//!
//! This module encodes the master-context split between two deliberately
//! Separate membership models:
//!
//! * [`permissionless`] - the network-wide default for PoW/PoS/BFT domains.
//!   Anyone may join by staking; there is **no whitelist, approval or central
//!   Gate**. Security = stake + slashing. This is a generic, role-parameterised
//!   Primitive (see [`role`]) so future application layers can reuse it.
//!
//! * [`poa_membership`] - the isolated permissioned exception for the PoA
//!   Domain (institutional / regulated parties). Entry is by **KYC + approval**,
//!   Never by staking.
//!
//! The two are intentionally different types backed by different data
//! Structures. There is no shared code path between them, which is what keeps
//! The PoA domain's permissioned rules from leaking into the permissionless
//! Domains and vice-versa. The isolation is exercised by
//! `tests::permissionless`.

pub mod d4_merge_tests;
pub mod evidence;
pub mod identity;
pub mod identity_fill;
pub mod invalid_vote;
pub mod liveness;
pub mod params;
pub mod permissionless;
pub mod poa_compliance;
pub mod poa_membership;
pub mod poa_onboarding;
pub mod quarantine_ledger;
pub mod role;

pub use identity::{
    address_of_did, authorize_recovery, credential_id, credential_issue_digest,
    credential_revoke_digest, did_of, disclosure_proof, execute_identity_tx, field_commitment,
    merkle_root, recovery_digest, verify_disclosure, CredentialCommitment, DisclosureProof,
    FieldCommitment, GuardianApproval, IdentityError, IdentityOp, IdentityRecord, IdentityRegistry,
    IdentityTx, MethodKind, VerificationMethod, DID_METHOD_NAME,
};
pub use identity_fill::{
    build_presentation, check_receipt, credential_proof, document_digest_of, fill_template,
    template_slots, value_digest_of, FillError, PresentationReceipt, ReceiptEntry, SlotDisclosure,
};
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
pub use quarantine_ledger::{AlarmEntry, QuarantineEntry, QuarantineLedger, QuarantineReason};
pub use role::{roles, RoleId};
