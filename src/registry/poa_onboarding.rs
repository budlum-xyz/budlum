//! PoA participant onboarding - the full KYC-gated admission lifecycle.
//!
//! Layered on [`PoaMembershipRegistry`], this module adds the production
//! Compliance concerns that a bare status enum cannot express. The underlying
//! Registry remains the single source of truth for admission *status*; this
//! Layer adds:
//!
//! 1. **Decision audit trail** - every `approve` / `reject` / `revoke` /
//!    `renew_kyc` is recorded as an append-only log entry (actor + block +
//!    Reason). Compliance regimes require a non-repudiable record of who
//!    Decided what, when.
//! 2. **KYC validity horizon** - approvals carry an *expiry block*. An expired
//!    KYC silently drops the account from the whitelist until it is re-KYC'd,
//!    So a stale compliance dossier can never keep producing blocks. This
//!    Mirrors the expiry-horizon discipline already applied to AI payments
//!    (`crate::ai::registry`).
//! 3. **Whitelist enforcement view** - [`PoAWhitelist`] is the single object
//!    Consensus code should query to answer *"is this account authorized to act
//!    In the PoA domain **right now**"*, accounting for both status **and**
//!    Expiry.
//!
//! ## Isolation (no change to the master-context invariant)
//! This module introduces **no stake path** and **no cross-talk** with the
//! Permissionless registry. It composes exclusively with
//! [`PoaMembershipRegistry`], which is a disjoint data structure from
//! [`crate::registry::permissionless::PermissionlessRegistry`]. The seal is
//! Exercised by `tests::poa_isolation`.
//!
//! WIRING: wired - [`AccountState`](crate::core::account::AccountState) holds
//! a [`PoAOnboarding`], `AccountState::refresh_poa_admissions` recomputes the
//! admitted set at every block close, and
//! [`PoAEngine`](crate::consensus::poa::PoAEngine) gates leadership on it.
//!
//! # What this replaced
//!
//! Two admission models used to sit side by side, and the compliant one was
//! the one switched off. Consensus consulted a plain `Vec<Address>` on the
//! engine, populated only by `with_authorities`, which no production path
//! called - so the vector was empty, and an empty vector meant "no filter".
//! A domain that was supposed to be permissioned ran open, and looked healthy
//! doing it. The KYC horizon, the revocation path and the audit trail written
//! here decided nothing.
//!
//! Closing it meant choosing which model was authoritative and giving that
//! one a home in `AccountState`, because a whitelist consensus gates on has
//! to be state every node agrees about rather than a field on one node's
//! engine. The compliance lifecycle here was already the complete half; what
//! was missing was the half that made it binding.
//!
//! # Where the derived set lives
//!
//! [`PoAOnboarding::whitelist`] takes `&mut self`: observing an elapsed KYC horizon
//! writes an audit entry. Consensus reads `&AccountState` on a hot path, so
//! the observation happens once per block, at block close, and the result is
//! cached in `AccountState::poa_admitted`. That placement is not a
//! convenience - it is what makes the audit trail identical on every node. A
//! record whose contents depend on who queried and when is not a record.

use crate::core::address::Address;
use crate::domain::types::DomainId;
use crate::registry::poa_membership::{
    KycCommitment, MembershipStatus, PoaMembershipError, PoaMembershipRegistry,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Default KYC validity horizon (blocks) when none is supplied explicitly.
/// Deliberately finite: an open-ended approval would let a stale dossier live
/// Forever, defeating the re-KYC discipline.
pub const DEFAULT_KYC_HORIZON: u64 = 100_000;

/// BLG-0094 (P04-F12): the validity horizon had no upper bound, so an admin
/// could stamp an effectively permanent dossier and the re-KYC discipline
/// would never bite. A finite ceiling in blocks; even at a one-second block
/// this is years of run time, and it can only be reached deliberately.
pub const MAX_KYC_VALIDITY_HORIZON: u64 = 2 * 365 * 24 * 60 * 60 * 5;

/// What an authorized admin decided about an applicant, the audit vocabulary.
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
    /// By [`PoAOnboarding::whitelist`] the first time the expiry is observed so
    /// The audit trail explains *why* a formerly-active member vanished.
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
/// One PoA domain. This is the **enforcement object** consensus should consult.
///
/// It is deliberately a *value* (snapshot), not a live view, so the answer
/// Cannot change under the caller between construction and the gating check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoAWhitelist {
    domain: DomainId,
    members: BTreeMap<Address, u64>, // account -> kyc_expiry_block (introspection)
}

impl PoAWhitelist {
    /// The single enforcement predicate. `true` ⇒ the account may produce
    /// Blocks / validate in the PoA domain at the snapshot block.
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
    /// If present.
    #[must_use]
    pub fn kyc_expiry_of(&self, account: &Address) -> Option<u64> {
        self.members.get(account).copied()
    }
}

/// The onboarding lifecycle manager for a set of PoA domains. Owns the
/// Underlying [`PoaMembershipRegistry`] plus the compliance layer
/// (audit trail + KYC expiry tracking).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PoAOnboarding {
    registry: PoaMembershipRegistry,
    audit: Vec<OnboardingEvent>,
    /// Per (domain, account): the block after which the KYC dossier is stale.
    /// Only meaningful for `Approved` members.
    #[serde(with = "crate::core::map_keys")]
    kyc_expiry: BTreeMap<(DomainId, Address), u64>,
    /// (domain, account) pairs whose expiry has already been logged to the
    /// Audit trail, so the observation is recorded exactly once.
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
    /// Sub-domain; in production wired through governance).
    pub fn add_admin(&mut self, domain: DomainId, admin: Address) {
        self.registry.add_admin(domain, admin);
    }

    /// Step 1: a candidate submits a KYC commitment. Records the submission in
    /// The audit trail. Does **not** grant authority.
    ///
    /// # Errors
    /// `MissingKyc` if the commitment is zero; `AlreadyApplied` if a record for
    /// This `(domain, account)` already exists.
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
    /// Validity horizon (the block after which the dossier is stale).
    ///
    /// # Errors
    /// `NotAnAdmin` if the caller is not an admin; `NotFound` if no application
    /// Exists; `InvalidTransition` if the member is not `Pending`/`Revoked`.
    pub fn approve(
        &mut self,
        domain: DomainId,
        admin: Address,
        applicant: Address,
        at_block: u64,
        validity_horizon: u64,
    ) -> Result<(), PoaMembershipError> {
        if validity_horizon > MAX_KYC_VALIDITY_HORIZON {
            return Err(PoaMembershipError::InvalidValidityHorizon {
                requested: validity_horizon,
                max: MAX_KYC_VALIDITY_HORIZON,
            });
        }
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
    /// Exists; `InvalidTransition` if the member is not `Pending`.
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
    /// Re-application is not confused by stale state.
    ///
    /// # Errors
    /// `NotAnAdmin` if the caller is not an admin; `NotFound` if no membership
    /// Exists; `InvalidTransition` if the member is not `Approved`.
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
    /// Expiry horizon forward. Requires admin authority and an active member.
    ///
    /// # Errors
    /// `MissingKyc` if the new commitment is zero; `NotFound` if the applicant
    /// Has no membership; `InvalidTransition` if not currently `Approved`;
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
        if validity_horizon > MAX_KYC_VALIDITY_HORIZON {
            return Err(PoaMembershipError::InvalidValidityHorizon {
                requested: validity_horizon,
                max: MAX_KYC_VALIDITY_HORIZON,
            });
        }
        // Must currently be a member in Approved state. A revoked member may
        // Re-KYC by going through approve again; renew is for active ones.
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
        // Admin authority gate (do NOT re-approve - approve rejects an
        // Already-Approved member; we only need the authority check here).
        if !self.registry.is_admin(domain, &admin) {
            return Err(PoaMembershipError::NotAnAdmin {
                caller: admin,
                domain,
            });
        }
        // BLG-0093 (P04-F11): the refreshed dossier is WRITTEN to the member
        // record - renewing used to move the expiry horizon and leave the
        // commitment naming the original submission forever.
        self.registry
            .update_kyc_commitment(domain, applicant, new_kyc_commitment)?;
        let expiry = at_block.saturating_add(validity_horizon);
        self.kyc_expiry.insert((domain, applicant), expiry);
        // BLG-0094 (P04-F12): clear the one-shot expiry log entry so the
        // expiry after THIS renewal is recorded again instead of being
        // swallowed by the stale mark.
        self.logged_expiry.remove(&(domain, applicant));
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

    /// BLG-0094 (P04-F12): remove an admin from a domain (see
    /// [`PoaMembershipRegistry::remove_admin`] for the last-admin rule).
    pub fn remove_admin(
        &mut self,
        domain: DomainId,
        admin: Address,
    ) -> Result<(), PoaMembershipError> {
        self.registry.remove_admin(domain, admin)
    }

    // ---- enforcement -----------------------------------------------------

    /// BLG-0090 (P04-F08): the deterministic fold of the admission state -
    /// admin set, member dossiers, KYC expiries and the audit trail. This
    /// enters the state root and the snapshot digest, so a snapshot that
    /// drops an admission record diverges instead of quietly unpermissioning
    /// a domain.
    pub fn root(&self) -> [u8; 32] {
        self.registry.root_with_expiry(&self.kyc_expiry)
    }

    /// Is `domain` a permissioned domain at all?
    ///
    /// True once it has an admin. See
    /// [`PoaMembershipRegistry::has_any_admin`] for why the admin list is the
    /// declaration rather than a separate flag.
    #[must_use]
    pub fn is_permissioned(&self, domain: DomainId) -> bool {
        self.registry.has_any_admin(domain)
    }

    /// Every domain this registry holds a record for.
    ///
    /// A domain with no records is not listed, which is the point: the caller
    /// recomputing admissions must not have to know in advance which domains
    /// exist. Developers create their own permissioned domains, so that list
    /// is data, not a constant.
    #[must_use]
    pub fn domains_with_records(&self) -> BTreeSet<DomainId> {
        self.kyc_expiry
            .keys()
            .map(|(domain, _)| *domain)
            .chain(self.audit.iter().map(|e| e.domain))
            .collect()
    }

    /// Build the expiry-aware whitelist for a domain at `now_block`. This is
    /// The object consensus should gate on. Members whose KYC horizon has
    /// Elapsed are excluded, and their expiry is recorded in the audit trail.
    ///
    /// Note: an elapsed KYC does **not** mutate the underlying registry status
    /// (the member is still `Approved` administratively); it only removes them
    /// From the *enforcement set*. They regain access via `renew_kyc`. This
    /// Keeps administrative status and live authorization cleanly separable.
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
    /// Expiry-aware? Allocates a whitelist snapshot; for hot paths use
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

/// The PoA admission door at the transaction layer (BLG-0089 / P04-F07).
///
/// Carries the registry's own operations and nothing else - the shape and
/// its semantics cannot drift from the one body
/// (`execute_poa_onboarding_tx`) that holds every authority rule. Admin
/// operations name the admin as `tx.from`; the door never accepts an
/// authority the transaction claims for itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PoAOnboardingTx {
    /// Extend the admin set (an existing admin, or governance, bootstraps).
    AddAdmin {
        domain: DomainId,
        admin: Address,
    },
    /// Remove an admin (BLG-0094). The last admin of a domain refuses.
    RemoveAdmin {
        domain: DomainId,
        admin: Address,
    },
    /// A candidate applies for themselves; nothing else is accepted.
    SubmitApplication {
        domain: DomainId,
        kyc_commitment: KycCommitment,
    },
    /// Admin approves a pending application within the horizon bound.
    Approve {
        domain: DomainId,
        member: Address,
        validity_horizon: u64,
    },
    /// Admin rejects a pending application.
    Reject {
        domain: DomainId,
        member: Address,
        reason: String,
    },
    /// Admin revokes an active member.
    Revoke {
        domain: DomainId,
        member: Address,
        reason: String,
    },
    /// Admin refreshes an active member's dossier (BLG-0093 writes it).
    RenewKyc {
        domain: DomainId,
        member: Address,
        kyc_commitment: KycCommitment,
        validity_horizon: u64,
    },
}

/// Run one PoA admission operation with the authority the SENDER actually
/// has (BLG-0089 / P04-F07).
///
/// Two doors and only two: a candidate applies for themselves, and an admin
/// of the target domain decides. The first admin of a domain arrives through
/// governance (`GovernanceAction::PoaAddAdmin`), never through this door -
/// an open first-admin slot would let anyone appoint themselves to any
/// domain.
pub fn execute_poa_onboarding_tx(
    state: &mut PoAOnboarding,
    sender: &Address,
    action: PoAOnboardingTx,
    at_block: u64,
) -> Result<(), PoaMembershipError> {
    match action {
        PoAOnboardingTx::AddAdmin { domain, admin } => {
            if !state.registry.is_admin(domain, sender) {
                return Err(PoaMembershipError::NotAnAdmin {
                    caller: *sender,
                    domain,
                });
            }
            state.add_admin(domain, admin);
            Ok(())
        }
        PoAOnboardingTx::RemoveAdmin { domain, admin } => {
            if !state.registry.is_admin(domain, sender) {
                return Err(PoaMembershipError::NotAnAdmin {
                    caller: *sender,
                    domain,
                });
            }
            state.remove_admin(domain, admin)
        }
        PoAOnboardingTx::SubmitApplication {
            domain,
            kyc_commitment,
        } => {
            // Self-application only: a sender cannot push another address
            // into a KYC process.
            state.submit_application(domain, *sender, kyc_commitment, at_block)
        }
        PoAOnboardingTx::Approve {
            domain,
            member,
            validity_horizon,
        } => state.approve(domain, *sender, member, at_block, validity_horizon),
        PoAOnboardingTx::Reject {
            domain,
            member,
            reason,
        } => state.reject(domain, *sender, member, at_block, reason),
        PoAOnboardingTx::Revoke {
            domain,
            member,
            reason,
        } => state.revoke(domain, *sender, member, at_block, reason),
        PoAOnboardingTx::RenewKyc {
            domain,
            member,
            kyc_commitment,
            validity_horizon,
        } => state.renew_kyc(domain, *sender, member, kyc_commitment, at_block, validity_horizon),
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
        const _: () = assert!(DEFAULT_KYC_HORIZON < u64::MAX);
        const _: () = assert!(DEFAULT_KYC_HORIZON > 0);
    }

    // BLG-0107 (P04-F25): the stale `too_many_lines` allow is gone with the
    // refactor that shrank this test; no allow without a reason and a date.
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


    /// BLG-0089 (P04-F07): the first admin of a domain arrives through
    /// governance (`add_admin` at the trust root); the door appoints only
    /// behind an existing admin, so nobody self-appoints.
    #[test]
    fn the_first_admin_is_a_governance_act() {
        let mut onboarding = PoAOnboarding::new();
        let stranger = addr(1);
        let err = execute_poa_onboarding_tx(
            &mut onboarding,
            &stranger,
            PoAOnboardingTx::AddAdmin {
                domain: 0,
                admin: stranger,
            },
            1,
        )
        .unwrap_err();
        assert!(matches!(err, PoaMembershipError::NotAnAdmin { .. }));
        // The trust root adds the first admin; from there the door works.
        onboarding.add_admin(0, stranger);
        assert!(execute_poa_onboarding_tx(
            &mut onboarding,
            &stranger,
            PoAOnboardingTx::AddAdmin {
                domain: 0,
                admin: addr(2),
            },
            1,
        )
        .is_ok());
        assert!(onboarding.registry().is_admin(0, &addr(2)));
    }

    /// BLG-0089 (P04-F07): a candidate applies for themselves - the door
    /// carries no applicant id to retarget.
    #[test]
    fn a_candidate_applies_for_themselves() {
        let mut onboarding = PoAOnboarding::new();
        onboarding.add_admin(0, addr(9));
        let applicant = addr(3);
        assert!(execute_poa_onboarding_tx(
            &mut onboarding,
            &applicant,
            PoAOnboardingTx::SubmitApplication {
                domain: 0,
                kyc_commitment: kyc(7),
            },
            5,
        )
        .is_ok());
        // An admin decides through the same door.
        assert!(execute_poa_onboarding_tx(
            &mut onboarding,
            &addr(9),
            PoAOnboardingTx::Approve {
                domain: 0,
                member: applicant,
                validity_horizon: 100,
            },
            5,
        )
        .is_ok());
        assert!(onboarding.is_authorized_now(0, &applicant, 50));
    }

    /// BLG-0093 + BLG-0094 (P04-F11/F12): renewal writes the new dossier
    /// and reopens the expiry log for the NEXT expiry.
    #[test]
    fn renew_kyc_writes_the_dossier_and_reopens_the_expiry_log() {
        let mut onboarding = PoAOnboarding::new();
        onboarding.add_admin(0, addr(9));
        let member = addr(3);
        onboarding.submit_application(0, member, kyc(1), 0).unwrap();
        onboarding.approve(0, addr(9), member, 1, 10).unwrap();
        onboarding
            .renew_kyc(0, addr(9), member, kyc(2), 5, 10)
            .unwrap();
        assert_eq!(
            onboarding.registry().get(0, &member).unwrap().kyc_commitment,
            kyc(2),
            "the refreshed dossier must be written to the record"
        );
        // Expiry episode one (window ends at 15) logs at 16; renewal at 16
        // opens a second window and clears the one-shot mark, so the expiry
        // of THAT window (after 26) logs again instead of being swallowed.
        let _ = onboarding.whitelist(0, 16);
        onboarding
            .renew_kyc(0, addr(9), member, kyc(3), 16, 10)
            .unwrap();
        let _ = onboarding.whitelist(0, 27);
        let expired_events = onboarding
            .audit_log()
            .iter()
            .filter(|e| matches!(e.decision, OnboardingDecision::KycExpired { .. }))
            .count();
        assert_eq!(
            expired_events, 2,
            "a post-renewal expiry must be logged again"
        );
    }

    /// BLG-0094 (P04-F12): the validity horizon is bounded.
    #[test]
    fn a_validity_horizon_beyond_the_bound_is_refused() {
        let mut onboarding = PoAOnboarding::new();
        onboarding.add_admin(0, addr(9));
        onboarding.submit_application(0, addr(3), kyc(1), 0).unwrap();
        let err = onboarding
            .approve(0, addr(9), addr(3), 1, MAX_KYC_VALIDITY_HORIZON + 1)
            .unwrap_err();
        assert!(matches!(
            err,
            PoaMembershipError::InvalidValidityHorizon { .. }
        ));
    }

    /// BLG-0094 (P04-F12): admins may remove admins but never the last one;
    /// governance can (force_remove_admin).
    #[test]
    fn the_last_admin_refuses_removal_through_the_door() {
        let mut onboarding = PoAOnboarding::new();
        onboarding.add_admin(0, addr(9));
        let err = onboarding.remove_admin(0, addr(9)).unwrap_err();
        assert!(matches!(err, PoaMembershipError::LastAdmin));
        onboarding.add_admin(0, addr(8));
        assert!(onboarding.remove_admin(0, addr(8)).is_ok());
        onboarding.registry_mut().force_remove_admin(0, addr(9));
        assert!(!onboarding.is_permissioned(0));
    }
}
