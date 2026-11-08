//! Participation registries for Budlum's Universal Settlement Layer.
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
pub mod handover;
pub mod identity;
pub mod identity_fill;
pub mod invalid_vote;
pub mod liveness;
pub mod mobile_runtime;
pub mod params;
pub mod permissionless;
pub mod poa_compliance;
pub mod poa_membership;
pub mod poa_onboarding;
pub mod presence;
pub mod quarantine_ledger;
pub mod rehearsal;
pub mod role;
pub mod validator_profile;

pub use identity::{
    address_of_did, authorize_recovery, credential_id, did_of, disclosure_proof,
    execute_identity_tx, field_commitment, merkle_root, recovery_digest, verify_disclosure,
    CredentialCommitment, DisclosureProof, FieldCommitment, GuardianApproval, IdentityError,
    IdentityOp, IdentityRecord, IdentityRegistry, IdentityTx, MethodKind, VerificationMethod,
    DID_METHOD_NAME,
};
// The signing-digest helpers and the wallet-side fill
// API have no production caller in this tree - test-only until a wallet
// binary consumes them (idle-code policy: test-only, not shipped).
#[cfg(test)]
pub use identity::{credential_issue_digest, credential_revoke_digest};
#[cfg(test)]
pub use identity_fill::{build_presentation, fill_template};
pub use identity_fill::{
    check_receipt, credential_proof, document_digest_of, template_slots, value_digest_of,
    FillError, PresentationReceipt, ReceiptEntry, SlotDisclosure,
};
pub use invalid_vote::InvalidVoteTracker;
pub use liveness::{LivenessTracker, SuspensionNotice};
pub use presence::{
    hours_to_epochs, presence_signing_digest, sign_presence_signal, GossipIngestOutcome,
    PresenceAggregate,
    PresenceClass, PresenceDoubleSignEvidence, PresenceError, PresenceGossipInbox, PresenceSignal,
    PresenceTracker, ValidatorPresenceState, DUPLICATE_SIGNAL_PEER_PENALTY,
    FULL_PRESENCE_WINDOW_EPOCHS, FULL_SUSPENSION_HOURS, IOS_OPPORTUNISTIC_SUSPENSION_HOURS,
    MOBILE_PRESENCE_WINDOW_EPOCHS, MOBILE_SUSPENSION_HOURS, PRESENCE_DOUBLE_SIGN_SLASH_PPM,
    PRESENCE_GOSSIP_TOPIC, RESUME_ACTIVATION_DELAY_EPOCHS,
};

pub use evidence::{EvidenceError, ProofProvenance, SlashingProof, SlashingReport};
pub use handover::{
    ChurnRunSummary, ChurnSimulator, HandoverCoordinator, HandoverDutyKind, RecoveryMode,
    CHECKPOINT_INTERVAL_BLOCKS, CUSTODY_READ_TIMEOUT_MS, FINALITY_STALL_RECOVERY_BLOCKS,
    MAX_VALIDATOR_SEAT_FRACTION_DENOM, SEAT_ABSENCE_HANDOVER_CHECKPOINTS,
};
pub use params::{ApplicationFeeSplit, RegistryParams};
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
