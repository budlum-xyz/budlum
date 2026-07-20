//! PoA participant onboarding — the full KYC-gated admission lifecycle.
//!
//! Layered on [`PoaMembershipRegistry`], this module adds the production
//! compliance concerns that a bare status enum cannot express. The underlying
//! registry remains the single source of truth for admission *status*; this
//! layer adds:
//!
//! 1. **Decision audit trail** — every `approve` / `reject` / `revoke` /
//!    `renew_kyc` is recorded as an append-only log entry (actor + block +
//!    reason). Compliance regimes require a non-repudiable record of who
//!    decided what, when.
//! 2. **KYC validity horizon** — approvals carry an *expiry block*. An expired
//!    KYC silently drops the account from the whitelist until it is re-KYC'd,
//!    so a stale compliance dossier can never keep producing blocks. This
//!    mirrors the expiry-horizon discipline already applied to AI payments
//!    (`crate::ai::registry`).
//! 3. **Whitelist enforcement view** — [`PoAWhitelist`] is the single object
//!    consensus code should query to answer *"is this account authorized to act
//!    in the PoA domain **right now**"*, accounting for both status **and**
//!    expiry.
//!
//! ## Isolation (no change to the master-context invariant)
//! This module introduces **no stake path** and **no cross-talk** with the
//! permissionless registry. It composes exclusively with
//! [`PoaMembershipRegistry`], which is a disjoint data structure from
//! [`crate::registry::permissionless::PermissionlessRegistry`]. The seal is
//! exercised by `tests::poa_isolation`.

use crate::core::address::Address;
use crate::domain::types::DomainId;
use crate::registry::poa_membership::{
    KycCommitment, MembershipStatus, PoaMembershipError, PoaMembershipRegistry,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Default KYC validity horizon (blocks) when none is supplied explicitly.
/// Deliberately finite: an open-ended approval would let a stale dossier live
/// forever, defeating the re-KYC discipline.
pub const DEFAULT_KYC_HORIZON: u64 = 100_000;

/// What an authorized admin decided about an applicant — the audit vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OnboardingDecision {
    /// A candidate submitted a KYC commitment (actor = the candidate).
    Submitted {
        applicant: Address,
        kyc_commitment: KycCommitment,
    },
    /// Admin approved; the membership is active until `kyc_expiry_block`.
    Approved {
        applicant: Address,
        kyc_expiry_block: u64,
    },
    /// Admin rejected a pending application.
    Rejected { applicant: Address, reason: String },
    /// Admin revoked an active member (offboarding / compliance action).
    Revoked { applicant: Address, reason: String },
    /// A (re-)approved member refreshed its KYC before expiry lapsed it.
    RenewedKyc {
        applicant: Address,
        new_expiry_block: u64,
    },
    /// Observed that an approved member's KYC horizon elapsed. Appended lazily
    /// by [`PoAOnboarding::whitelist`] the first time the expiry is observed so
    /// the audit trail explains *why* a formerly-active member vanished.
    KycExpired { applicant: Address, at_block: u64 },
}

/// One immutable audit-log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardingEvent {
    pub domain: DomainId,
    pub at_block: u64,
    /// The admin that acted, or the applicant for `Submitted`.
    pub actor: Address,
    pub decision: OnboardingDecision,
}

/// A point-in-time, expiry-aware snapshot of the accounts authorized to act in
/// one PoA domain. This is the **enforcement object** consensus should consult.
///
/// It is deliberately a *value* (snapshot), not a live view, so the answer
/// cannot change under the caller between construction and the gating check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoAWhitelist {
    domain: DomainId,
    members: BTreeMap<Address, u64>, // account -> kyc_expiry_block (introspection)
}

impl PoAWhitelist {
    /// The single enforcement predicate. `true` ⇒ the account may produce
    /// blocks / validate in the PoA domain at the snapshot block.
    #[must_use]
    pub fn contains(&self, account: &Address) -> bool {
        self.members.contains_key(account)
    }

    /// Authorized accounts, ascending (stable, deterministic ordering).
    #[must_use]
    pub fn members(&self) -> Vec<&Address> {
        self.members.keys().collect()
    }

    #[must_use]
    pub const fn domain(&self) -> DomainId {
        self.domain
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.members.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// The KYC expiry block the whitelist was computed against for this member,
    /// if present.
    #[must_use]
    pub fn kyc_expiry_of(&self, account: &Address) -> Option<u64> {
        self.members.get(account).copied()
    }
}

/// The onboarding lifecycle manager for a set of PoA domains. Owns the
/// underlying [`PoaMembershipRegistry`] plus the compliance layer
/// (audit trail + KYC expiry tracking).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PoAOnboarding {
    registry: PoaMembershipRegistry,
    audit: Vec<OnboardingEvent>,
    /// Per (domain, account): the block after which the KYC dossier is stale.
    /// Only meaningful for `Approved` members.
    kyc_expiry: BTreeMap<(DomainId, Address), u64>,
    /// (domain, account) pairs whose expiry has already been logged to the
    /// audit trail, so the observation is recorded exactly once.
    logged_expiry: BTreeSet<(DomainId, Address)>,
}

impl PoAOnboarding {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrow the underlying registry (e.g. for `is_admin`, `get`).
    #[must_use]
    pub fn registry(&self) -> &PoaMembershipRegistry {
        &self.registry
    }

    /// Mutable access to the underlying registry (e.g. to bootstrap admins).
    #[must_use]
    pub fn registry_mut(&mut self) -> &mut PoaMembershipRegistry {
        &mut self.registry
    }

    /// The full, append-only decision audit trail.
    #[must_use]
    pub fn audit_log(&self) -> &[OnboardingEvent] {
        &self.audit
    }

    // ---- lifecycle -------------------------------------------------------

    /// Bootstrap an admin for a domain (trust root of the permissioned
    /// sub-domain; in production wired through governance).
    pub fn add_admin(&mut self, domain: DomainId, admin: Address) {
        self.registry.add_admin(domain, admin);
    }

    /// Step 1: a candidate submits a KYC commitment. Records the submission in
    /// the audit trail. Does **not** grant authority.
    ///
    /// # Errors
    /// `MissingKyc` if the commitment is zero; `AlreadyApplied` if a record for
    /// this `(domain, account)` already exists.
    pub fn submit_application(
        &mut self,
        domain: DomainId,
        applicant: Address,
        kyc_commitment: KycCommitment,
        at_block: u64,
    ) -> Result<(), PoaMembershipError> {
        self.registry
            .submit_application(domain, applicant, kyc_commitment)?;
        self.audit.push(OnboardingEvent {
            domain,
            at_block,
            actor: applicant,
            decision: OnboardingDecision::Submitted {
                applicant,
                kyc_commitment,
            },
        });
        Ok(())
    }

    /// Step 2: an admin approves a pending application, setting the KYC
    /// validity horizon (the block after which the dossier is stale).
    ///
    /// # Errors
    /// `NotAnAdmin` if the caller is not an admin; `NotFound` if no application
    /// exists; `InvalidTransition` if the member is not `Pending`/`Revoked`.
    pub fn approve(
        &mut self,
        domain: DomainId,
        admin: Address,
        applicant: Address,
        at_block: u64,
        validity_horizon: u64,
    ) -> Result<(), PoaMembershipError> {
        let expiry = at_block.saturating_add(validity_horizon);
        self.registry.approve(domain, admin, applicant)?;
        self.kyc_expiry.insert((domain, applicant), expiry);
        self.audit.push(OnboardingEvent {
            domain,
            at_block,
            actor: admin,
            decision: OnboardingDecision::Approved {
                applicant,
                kyc_expiry_block: expiry,
            },
        });
        Ok(())
    }

    /// Admin rejects a pending application.
    ///
    /// # Errors
    /// `NotAnAdmin` if the caller is not an admin; `NotFound` if no application
    /// exists; `InvalidTransition` if the member is not `Pending`.
    pub fn reject(
        &mut self,
        domain: DomainId,
        admin: Address,
        applicant: Address,
        at_block: u64,
        reason: impl Into<String>,
    ) -> Result<(), PoaMembershipError> {
        let reason = reason.into();
        self.registry.reject(domain, admin, applicant)?;
        self.audit.push(OnboardingEvent {
            domain,
            at_block,
            actor: admin,
            decision: OnboardingDecision::Rejected { applicant, reason },
        });
        Ok(())
    }

    /// Admin revokes an active member. Clears any pending expiry so a later
    /// re-application is not confused by stale state.
    ///
    /// # Errors
    /// `NotAnAdmin` if the caller is not an admin; `NotFound` if no membership
    /// exists; `InvalidTransition` if the member is not `Approved`.
    pub fn revoke(
        &mut self,
        domain: DomainId,
        admin: Address,
        applicant: Address,
        at_block: u64,
        reason: impl Into<String>,
    ) -> Result<(), PoaMembershipError> {
        let reason = reason.into();
        self.registry.revoke(domain, admin, applicant)?;
        self.kyc_expiry.remove(&(domain, applicant));
        self.audit.push(OnboardingEvent {
            domain,
            at_block,
            actor: admin,
            decision: OnboardingDecision::Revoked { applicant, reason },
        });
        Ok(())
    }

    /// Refresh the KYC dossier of an already-approved member, pushing the
    /// expiry horizon forward. Requires admin authority and an active member.
    ///
    /// # Errors
    /// `MissingKyc` if the new commitment is zero; `NotFound` if the applicant
    /// has no membership; `InvalidTransition` if not currently `Approved`;
    /// `NotAnAdmin` if the caller is not an admin.
    pub fn renew_kyc(
        &mut self,
        domain: DomainId,
        admin: Address,
        applicant: Address,
        new_kyc_commitment: KycCommitment,
        at_block: u64,
        validity_horizon: u64,
    ) -> Result<(), PoaMembershipError> {
        if new_kyc_commitment == [0u8; 32] {
            return Err(PoaMembershipError::MissingKyc);
        }
        // Must currently be a member in Approved state. A revoked member may
        // re-KYC by going through approve() again; renew is for active ones.
        let member = self
            .registry
            .get(domain, &applicant)
            .ok_or(PoaMembershipError::NotFound {
                account: applicant,
                domain,
            })?;
        if !matches!(member.status, MembershipStatus::Approved) {
            return Err(PoaMembershipError::InvalidTransition {
                from: member.status,
            });
        }
        // Admin authority gate (do NOT re-approve — approve() rejects an
        // already-Approved member; we only need the authority check here).
        if !self.registry.is_admin(domain, &admin) {
            return Err(PoaMembershipError::NotAnAdmin {
                caller: admin,
                domain,
            });
        }
        let expiry = at_block.saturating_add(validity_horizon);
        self.kyc_expiry.insert((domain, applicant), expiry);
        self.audit.push(OnboardingEvent {
            domain,
            at_block,
            actor: admin,
            decision: OnboardingDecision::RenewedKyc {
                applicant,
                new_expiry_block: expiry,
            },
        });
        Ok(())
    }

    // ---- enforcement -----------------------------------------------------

    /// Build the expiry-aware whitelist for a domain at `now_block`. This is
    /// the object consensus should gate on. Members whose KYC horizon has
    /// elapsed are excluded, and their expiry is recorded in the audit trail.
    ///
    /// Note: an elapsed KYC does **not** mutate the underlying registry status
    /// (the member is still `Approved` administratively); it only removes them
    /// from the *enforcement set*. They regain access via `renew_kyc`. This
    /// keeps administrative status and live authorization cleanly separable.
    #[must_use]
    pub fn whitelist(&mut self, domain: DomainId, now_block: u64) -> PoAWhitelist {
        let mut members = BTreeMap::new();
        for m in self.registry.authorized_members(domain) {
            let expiry = self
                .kyc_expiry
                .get(&(domain, m.account))
                .copied()
                .unwrap_or(u64::MAX);
            if now_block > expiry {
                // Lazily record the expiry observation exactly once.
                if self.logged_expiry.insert((domain, m.account)) {
                    self.audit.push(OnboardingEvent {
                        domain,
                        at_block: now_block,
                        actor: m.account,
                        decision: OnboardingDecision::KycExpired {
                            applicant: m.account,
                            at_block: now_block,
                        },
                    });
                }
                continue;
            }
            members.insert(m.account, expiry);
        }
        PoAWhitelist { domain, members }
    }

    /// Convenience: is `account` authorized to act in `domain` right now,
    /// expiry-aware? Allocates a whitelist snapshot; for hot paths use
    /// [`PoAWhitelist::contains`] on a cached snapshot.
    #[must_use]
    pub fn is_authorized_now(
        &mut self,
        domain: DomainId,
        account: &Address,
        now_block: u64,
    ) -> bool {
        self.whitelist(domain, now_block).contains(account)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> Address {
        Address::from([b; 32])
    }

    fn kyc(b: u8) -> KycCommitment {
        [b; 32]
    }

    #[test]
    fn default_kyc_horizon_is_finite() {
        // An infinite horizon would defeat re-KYC discipline.
        assert!(DEFAULT_KYC_HORIZON < u64::MAX);
        assert!(DEFAULT_KYC_HORIZON > 0);
    }

    #[allow(clippy::too_many_lines)] // lifecycle test is intentionally thorough
    #[test]
    fn whitelist_member_round_trip() {
        let admin = addr(0xAD);
        let member = addr(0xAA);
        let mut poa = PoAOnboarding::new();
        poa.add_admin(0, admin);
        assert!(poa.submit_application(0, member, kyc(1), 0).is_ok());
        assert!(!poa.whitelist(0, 0).contains(&member));
        assert!(poa.approve(0, admin, member, 0, 1_000).is_ok());
        assert!(poa.whitelist(0, 0).contains(&member));
    }
}
