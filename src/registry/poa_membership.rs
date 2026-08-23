//! PoA domain membership - the *deliberate, isolated permissioned exception*.
//!
//! Master-context rule: the PoA domain exists only for institutional / regulated
//! Parties (banks, participation-bank pilot, ...). Entry is by **KYC / identity
//! Verification + approval**, NOT by staking. This is a conscious permissioned
//! Sub-domain that does not break the network-wide permissionless proposition
//! Because its scope is narrow and explicitly bounded.
//!
//! ## Isolation guarantees (enforced by construction)
//! - This registry is a **completely separate data structure** from
//!   [`crate::registry::permissionless::PermissionlessRegistry`]. They share no
//!   Storage, no keys and no code path.
//! - There is **no `stake`-based entry** here at all - the only way in is
//!   `submit_application` → `approve` by an authorized PoA admin.
//! - The permissionless registry has **no approval gate**; this one has **no
//!   Stake gate**. Neither type can be used where the other is expected, so the
//!   Two models cannot leak into each other.
//! - Cross-domain messaging (via `CrossDomainMessage`) between PoA and other
//!   Domains is still possible, but PoA's admission rules never travel with the
//!   Message - messaging is orthogonal to membership.

use crate::core::address::Address;
use crate::domain::types::DomainId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Opaque commitment to an off-chain KYC/identity record (e.g. a hash of the
/// Verified legal-entity dossier). The chain never stores raw PII.
pub type KycCommitment = [u8; 32];

/// Where an applicant is in the permissioned admission flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MembershipStatus {
    /// KYC submitted, awaiting an authorized admin decision.
    Pending,
    /// Approved and currently authorized to act in the PoA domain.
    Approved,
    /// Approval revoked (compliance action, offboarding, ...).
    Revoked,
    /// Application rejected.
    Rejected,
}

/// A KYC-gated membership record for one authorized party in one PoA domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoaMember {
    pub account: Address,
    pub domain: DomainId,
    pub kyc_commitment: KycCommitment,
    pub status: MembershipStatus,
    /// Admin that approved/last acted on this member (audit trail).
    pub decided_by: Option<Address>,
}

impl PoaMember {
    pub fn is_authorized(&self) -> bool {
        matches!(self.status, MembershipStatus::Approved)
    }
}

/// Errors specific to the permissioned PoA flow.
///
/// Note the deliberate absence of any stake-related variant: staking is simply
/// Not a concept in this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoaMembershipError {
    /// The caller is not an authorized PoA admin for this domain.
    NotAnAdmin { caller: Address, domain: DomainId },
    /// No application/membership exists for this account+domain.
    NotFound { account: Address, domain: DomainId },
    /// An application already exists.
    AlreadyApplied { account: Address, domain: DomainId },
    /// The member is not in a state that allows this transition.
    InvalidTransition { from: MembershipStatus },
    /// Missing / zero KYC commitment.
    MissingKyc,
}

impl std::fmt::Display for PoaMembershipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoaMembershipError::NotAnAdmin { caller, domain } => {
                write!(f, "{caller} is not an admin of PoA domain {domain}")
            }
            PoaMembershipError::NotFound { account, domain } => {
                write!(f, "no PoA membership for {account} in domain {domain}")
            }
            PoaMembershipError::AlreadyApplied { account, domain } => {
                write!(f, "{account} already applied to PoA domain {domain}")
            }
            PoaMembershipError::InvalidTransition { from } => {
                write!(f, "invalid membership transition from {from:?}")
            }
            PoaMembershipError::MissingKyc => write!(f, "missing KYC commitment"),
        }
    }
}

impl std::error::Error for PoaMembershipError {}

/// The isolated permissioned registry for a set of PoA domains.
///
/// Admins are the compliance-authorized approvers; members are KYC'd parties.
/// Both are keyed by `(domain, account)` so PoA domains are independent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PoaMembershipRegistry {
    admins: BTreeMap<(DomainId, Address), ()>,
    members: BTreeMap<(DomainId, Address), PoaMember>,
}

impl PoaMembershipRegistry {
    pub fn new() -> Self {
        Self {
            admins: BTreeMap::new(),
            members: BTreeMap::new(),
        }
    }

    /// Bootstrap an admin for a PoA domain. In production this is expected to be
    /// Wired through governance; here it is the trust root of the permissioned
    /// Sub-domain.
    pub fn add_admin(&mut self, domain: DomainId, admin: Address) {
        self.admins.insert((domain, admin), ());
    }

    /// Has anyone been made admin of `domain`?
    ///
    /// This is how a domain declares itself permissioned. There is no
    /// separate "is this domain gated" flag, because a flag and an admin list
    /// can disagree; an admin is both the declaration and the thing that can
    /// act on it. A domain nobody administers is not a locked domain, it is
    /// not a permissioned domain at all.
    #[must_use]
    pub fn has_any_admin(&self, domain: DomainId) -> bool {
        self.admins
            .range((domain, Address::zero())..)
            .next()
            .is_some_and(|((d, _), ())| *d == domain)
    }

    pub fn is_admin(&self, domain: DomainId, account: &Address) -> bool {
        self.admins.contains_key(&(domain, *account))
    }

    /// Step 1 of admission: a candidate submits a KYC commitment. This does NOT
    /// Grant any authority - it only creates a `Pending` record.
    pub fn submit_application(
        &mut self,
        domain: DomainId,
        account: Address,
        kyc_commitment: KycCommitment,
    ) -> Result<(), PoaMembershipError> {
        if kyc_commitment == [0u8; 32] {
            return Err(PoaMembershipError::MissingKyc);
        }
        if self.members.contains_key(&(domain, account)) {
            return Err(PoaMembershipError::AlreadyApplied { account, domain });
        }
        self.members.insert(
            (domain, account),
            PoaMember {
                account,
                domain,
                kyc_commitment,
                status: MembershipStatus::Pending,
                decided_by: None,
            },
        );
        Ok(())
    }

    /// Step 2: an authorized admin approves a pending application. This is the
    /// Permission gate that has NO analogue in the permissionless registry.
    pub fn approve(
        &mut self,
        domain: DomainId,
        admin: Address,
        account: Address,
    ) -> Result<(), PoaMembershipError> {
        self.require_admin(domain, &admin)?;
        let member = self
            .members
            .get_mut(&(domain, account))
            .ok_or(PoaMembershipError::NotFound { account, domain })?;
        match member.status {
            MembershipStatus::Pending | MembershipStatus::Revoked => {
                member.status = MembershipStatus::Approved;
                member.decided_by = Some(admin);
                Ok(())
            }
            other => Err(PoaMembershipError::InvalidTransition { from: other }),
        }
    }

    /// Reject a pending application (admin only).
    pub fn reject(
        &mut self,
        domain: DomainId,
        admin: Address,
        account: Address,
    ) -> Result<(), PoaMembershipError> {
        self.require_admin(domain, &admin)?;
        let member = self
            .members
            .get_mut(&(domain, account))
            .ok_or(PoaMembershipError::NotFound { account, domain })?;
        match member.status {
            MembershipStatus::Pending => {
                member.status = MembershipStatus::Rejected;
                member.decided_by = Some(admin);
                Ok(())
            }
            other => Err(PoaMembershipError::InvalidTransition { from: other }),
        }
    }

    /// Revoke an approved member (admin only; e.g. compliance offboarding).
    pub fn revoke(
        &mut self,
        domain: DomainId,
        admin: Address,
        account: Address,
    ) -> Result<(), PoaMembershipError> {
        self.require_admin(domain, &admin)?;
        let member = self
            .members
            .get_mut(&(domain, account))
            .ok_or(PoaMembershipError::NotFound { account, domain })?;
        match member.status {
            MembershipStatus::Approved => {
                member.status = MembershipStatus::Revoked;
                member.decided_by = Some(admin);
                Ok(())
            }
            other => Err(PoaMembershipError::InvalidTransition { from: other }),
        }
    }

    /// The authorization check the PoA domain should use. True ONLY for
    /// KYC-approved members - never as a function of stake.
    pub fn is_authorized(&self, domain: DomainId, account: &Address) -> bool {
        self.members
            .get(&(domain, *account))
            .map(PoaMember::is_authorized)
            .unwrap_or(false)
    }

    pub fn get(&self, domain: DomainId, account: &Address) -> Option<&PoaMember> {
        self.members.get(&(domain, *account))
    }

    pub fn authorized_members(&self, domain: DomainId) -> Vec<&PoaMember> {
        self.members
            .values()
            .filter(|m| m.domain == domain && m.is_authorized())
            .collect()
    }

    fn require_admin(&self, domain: DomainId, caller: &Address) -> Result<(), PoaMembershipError> {
        if self.is_admin(domain, caller) {
            Ok(())
        } else {
            Err(PoaMembershipError::NotAnAdmin {
                caller: *caller,
                domain,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> Address {
        Address::from([b; 32])
    }

    const DOMAIN: DomainId = 42;

    fn kyc(b: u8) -> KycCommitment {
        [b; 32]
    }

    #[test]
    fn approval_flow_grants_authorization() {
        let mut reg = PoaMembershipRegistry::new();
        reg.add_admin(DOMAIN, addr(1));
        reg.submit_application(DOMAIN, addr(2), kyc(9)).unwrap();
        assert!(!reg.is_authorized(DOMAIN, &addr(2)));
        reg.approve(DOMAIN, addr(1), addr(2)).unwrap();
        assert!(reg.is_authorized(DOMAIN, &addr(2)));
    }

    #[test]
    fn non_admin_cannot_approve() {
        let mut reg = PoaMembershipRegistry::new();
        reg.add_admin(DOMAIN, addr(1));
        reg.submit_application(DOMAIN, addr(2), kyc(9)).unwrap();
        let err = reg.approve(DOMAIN, addr(3), addr(2)).unwrap_err();
        assert!(matches!(err, PoaMembershipError::NotAnAdmin { .. }));
        assert!(!reg.is_authorized(DOMAIN, &addr(2)));
    }

    #[test]
    fn application_requires_kyc_commitment() {
        let mut reg = PoaMembershipRegistry::new();
        let err = reg
            .submit_application(DOMAIN, addr(2), [0u8; 32])
            .unwrap_err();
        assert!(matches!(err, PoaMembershipError::MissingKyc));
    }

    #[test]
    fn revoke_removes_authorization() {
        let mut reg = PoaMembershipRegistry::new();
        reg.add_admin(DOMAIN, addr(1));
        reg.submit_application(DOMAIN, addr(2), kyc(9)).unwrap();
        reg.approve(DOMAIN, addr(1), addr(2)).unwrap();
        reg.revoke(DOMAIN, addr(1), addr(2)).unwrap();
        assert!(!reg.is_authorized(DOMAIN, &addr(2)));
    }
}
