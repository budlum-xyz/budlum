//! Permissionless verifier/validator/relayer registry.
//!
//! Master-context rule: on PoW/PoS/BFT domains there is **no whitelist, no
//! admin-approval and no central gate**. Participation == staking. Security is
//! provided by economic incentive (stake) + slashing, never by permission.
//!
//! This is a shared primitive: it is generic over [`RoleId`] so future
//! application layers (out of scope here) can reuse it with their own roles.
//!
//! ## What this module intentionally does NOT do
//! - It never stores an allow-list of approved accounts.
//! - It never exposes an `approve()` / `admit()` gate for PoW/PoS/BFT roles.
//! - It knows nothing about KYC. KYC-gated membership lives in a *separate*
//!   module ([`crate::registry::poa_membership`]) with a separate data
//!   structure, so PoA's permissioned rules cannot leak in here.

use crate::core::address::Address;
use crate::core::chain_config::FIXED_POINT_SCALE;
use crate::registry::evidence::{EvidenceError, SlashingReport};
use crate::registry::params::RegistryParams;
use crate::registry::role::RoleId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Default minimum stake required to register for a role.
///
/// NOTE: this is only the *default* used by [`PermissionlessRegistry::new`].
/// The effective floor is a governance/config parameter
/// ([`RegistryParams::min_stake`]) — this constant must not be treated as a
/// hard rule. It is a *stake floor*, not a permission check: anyone meeting it
/// can join.
pub const MIN_REGISTRATION_STAKE: u64 = 1_000;

/// Default number of epochs that unbonded stake stays locked. Also overridable
/// via [`RegistryParams::unbonding_epochs`]; kept as a constant for the default
/// and for existing callers/tests.
pub const UNBONDING_EPOCHS: u64 = 7;

/// Reasons a registered member can be slashed. Explicitly enumerated so the
/// economic-security surface is auditable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlashingCondition {
    /// Signed two conflicting blocks/messages at the same height/slot.
    DoubleSign,
    /// Failed liveness / availability obligations (e.g. missed duties).
    LivenessFault,
    /// Provably malicious behaviour (invalid proof, equivocation, censorship
    /// evidence, etc.).
    MaliciousBehaviour,
}

impl SlashingCondition {
    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            SlashingCondition::DoubleSign => b"double_sign",
            SlashingCondition::LivenessFault => b"liveness_fault",
            SlashingCondition::MaliciousBehaviour => b"malicious_behaviour",
        }
    }
}

/// Lifecycle status of a registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberStatus {
    /// Actively bonded and eligible to perform its role.
    Active,
    /// Currently unbonding; stake is locked until `release_epoch`.
    Unbonding { release_epoch: u64 },
    /// Slashed and jailed.
    Slashed,
}

/// A single (account, role) registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registration {
    pub account: Address,
    pub role: RoleId,
    pub stake: u64,
    pub status: MemberStatus,
    /// Epoch at which the account registered (bookkeeping / liveness windows).
    pub registered_epoch: u64,
}

impl Registration {
    /// Eligible to actively perform the role right now. This is purely a
    /// function of bonded stake + status (never any allow-list): the member
    /// must be `Active` and still hold a positive bond.
    pub fn is_active(&self) -> bool {
        matches!(self.status, MemberStatus::Active) && self.stake > 0
    }
}

/// Errors surfaced by the permissionless registry.
///
/// Note there is deliberately **no** `NotWhitelisted` / `NotApproved` variant:
/// the only economic gate is [`RegistryError::InsufficientStake`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    InsufficientStake {
        required: u64,
        provided: u64,
    },
    AlreadyRegistered {
        account: Address,
        role: RoleId,
    },
    NotRegistered {
        account: Address,
        role: RoleId,
    },
    NotActive {
        account: Address,
        role: RoleId,
    },
    StillUnbonding {
        release_epoch: u64,
        current_epoch: u64,
    },
    /// The sender is not an eligible relayer (not registered, or slashed).
    /// Used to gate permissionless cross-domain message submission.
    RelayerNotActive {
        account: Address,
    },
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryError::InsufficientStake { required, provided } => write!(
                f,
                "insufficient stake: required {required}, provided {provided}"
            ),
            RegistryError::AlreadyRegistered { account, role } => {
                write!(f, "{account} already registered as {role}")
            }
            RegistryError::NotRegistered { account, role } => {
                write!(f, "{account} is not registered as {role}")
            }
            RegistryError::NotActive { account, role } => {
                write!(f, "{account} is not active as {role}")
            }
            RegistryError::StillUnbonding {
                release_epoch,
                current_epoch,
            } => write!(
                f,
                "stake still unbonding until epoch {release_epoch} (now {current_epoch})"
            ),
            RegistryError::RelayerNotActive { account } => write!(
                f,
                "{account} is not an active relayer (register with stake first)"
            ),
        }
    }
}

impl std::error::Error for RegistryError {}

/// Outcome of a slashing action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlashOutcome {
    pub condition: SlashingCondition,
    pub penalty: u64,
    pub remaining_stake: u64,
}

/// The permissionless registry itself.
///
/// Keyed by `(role, account)` so the same account may hold several roles
/// (e.g. be both a validator and a relayer) with independent stakes.
///
/// Carries its [`RegistryParams`] so the stake floor, unbonding window and
/// slash ratios are governance/config-driven, never hard-coded.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PermissionlessRegistry {
    // NOTE: the key is a `(RoleId, Address)` tuple, which serde_json cannot emit
    // as a JSON object key (JSON requires string keys). We therefore (de)serialize
    // this map as a flat sequence of `Registration`s — each already carries its
    // `role` + `account`, so the map is rebuilt losslessly on load. Without this,
    // snapshot serialization silently produced empty output (Phase 0.16 bug).
    #[serde(with = "registrations_as_seq")]
    registrations: BTreeMap<(RoleId, Address), Registration>,
    #[serde(default)]
    params: RegistryParams,
    /// Persistent audit log of actioned slashing reports (Phase 0.40, Görev 1).
    ///
    /// Phase 0.38 slashed equivocators immediately but kept no record, so a restart
    /// or a governance/dispute/audit query lost the evidence. Every report that
    /// the registry actually acts on (`slash_from_report` → `Ok(Some)`) is
    /// appended here. It is `#[serde(default)]` so schema-3 snapshots taken
    /// before Phase 0.40 still deserialize (the log simply comes back empty).
    ///
    /// This does NOT open a second slashing path: the log is written *inside*
    /// the one canonical `slash_from_report`, recording what that path already
    /// did.
    #[serde(default)]
    slashing_history: Vec<SlashingRecord>,
}

/// A persisted, actioned slashing report plus the outcome it produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingRecord {
    pub report: SlashingReport,
    pub penalty: u64,
    pub remaining_stake: u64,
}

/// (De)serialize the registrations map as a `Vec<Registration>` so it survives
/// JSON (which cannot key an object by a tuple).
mod registrations_as_seq {
    use super::{Address, Registration, RoleId};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;

    pub fn serialize<S>(
        map: &BTreeMap<(RoleId, Address), Registration>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let entries: Vec<&Registration> = map.values().collect();
        entries.serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<BTreeMap<(RoleId, Address), Registration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let entries = Vec::<Registration>::deserialize(deserializer)?;
        Ok(entries
            .into_iter()
            .map(|r| ((r.role, r.account), r))
            .collect())
    }
}

impl PermissionlessRegistry {
    pub fn new() -> Self {
        Self {
            registrations: BTreeMap::new(),
            params: RegistryParams::default(),
            slashing_history: Vec::new(),
        }
    }

    /// Construct with explicit parameters (e.g. loaded from chain config or
    /// updated by governance).
    pub fn with_params(params: RegistryParams) -> Self {
        Self {
            registrations: BTreeMap::new(),
            params,
            slashing_history: Vec::new(),
        }
    }

    /// Current parameters.
    pub fn params(&self) -> &RegistryParams {
        &self.params
    }

    /// Replace parameters (e.g. after a governance parameter update). Existing
    /// registrations are untouched; the new floor applies to future actions.
    pub fn set_params(&mut self, params: RegistryParams) {
        self.params = params;
    }

    /// Register `account` for `role` by bonding `stake`.
    ///
    /// This is the permissionless entry point: **any** account may call it.
    /// The ONLY precondition is meeting [`MIN_REGISTRATION_STAKE`]. There is no
    /// whitelist lookup, no approval step, and no admin gate.
    pub fn register(
        &mut self,
        account: Address,
        role: RoleId,
        stake: u64,
        current_epoch: u64,
    ) -> Result<(), RegistryError> {
        if stake < self.params.min_stake {
            return Err(RegistryError::InsufficientStake {
                required: self.params.min_stake,
                provided: stake,
            });
        }
        let key = (role, account);
        if self.registrations.contains_key(&key) {
            return Err(RegistryError::AlreadyRegistered { account, role });
        }
        self.registrations.insert(
            key,
            Registration {
                account,
                role,
                stake,
                status: MemberStatus::Active,
                registered_epoch: current_epoch,
            },
        );
        Ok(())
    }

    /// Convenience wrappers for the well-known protocol roles.
    pub fn register_validator(
        &mut self,
        account: Address,
        stake: u64,
        current_epoch: u64,
    ) -> Result<(), RegistryError> {
        self.register(
            account,
            crate::registry::role::roles::VALIDATOR,
            stake,
            current_epoch,
        )
    }

    pub fn register_verifier(
        &mut self,
        account: Address,
        stake: u64,
        current_epoch: u64,
    ) -> Result<(), RegistryError> {
        self.register(
            account,
            crate::registry::role::roles::VERIFIER,
            stake,
            current_epoch,
        )
    }

    pub fn register_relayer(
        &mut self,
        account: Address,
        stake: u64,
        current_epoch: u64,
    ) -> Result<(), RegistryError> {
        self.register(
            account,
            crate::registry::role::roles::RELAYER,
            stake,
            current_epoch,
        )
    }

    /// Phase 0.38, Faz 1: convenience wrapper for the B.U.D. `STORAGE_OPERATOR`
    /// role. Like every other role, registration is permissionless — any
    /// account can join by staking the `min_stake` floor. There is no
    /// whitelist, no admin gate (master context, CLAUDE.md §2).
    pub fn register_storage_operator(
        &mut self,
        account: Address,
        stake: u64,
        current_epoch: u64,
    ) -> Result<(), RegistryError> {
        self.register(
            account,
            crate::registry::role::roles::STORAGE_OPERATOR,
            stake,
            current_epoch,
        )
    }

    /// Idempotently synchronise a role's bonded stake to `total_stake`.
    ///
    /// This is the bridge used to keep the registry in lock-step with the
    /// consensus validator set: applying a `Stake`/`Unstake` transaction calls
    /// this so that "staking == being registered" holds automatically, with no
    /// separate manual registration step.
    ///
    /// Semantics:
    /// - Not yet registered and `total_stake >= params.min_stake` → registered
    ///   `Active`.
    /// - Not yet registered and below the floor → no-op (the economic floor is
    ///   the only gate; there is still no whitelist).
    /// - Already registered → its stake is set to `total_stake`; if that drops
    ///   to zero the registration is removed. A slashed member is left slashed.
    pub fn upsert_stake(
        &mut self,
        account: Address,
        role: RoleId,
        total_stake: u64,
        current_epoch: u64,
    ) {
        let key = (role, account);
        match self.registrations.get_mut(&key) {
            Some(reg) => {
                // Do not silently un-slash a jailed member by re-staking.
                if matches!(reg.status, MemberStatus::Slashed) {
                    reg.stake = total_stake;
                    return;
                }
                if total_stake == 0 {
                    self.registrations.remove(&key);
                } else {
                    reg.stake = total_stake;
                }
            }
            None => {
                if total_stake >= self.params.min_stake {
                    self.registrations.insert(
                        key,
                        Registration {
                            account,
                            role,
                            stake: total_stake,
                            status: MemberStatus::Active,
                            registered_epoch: current_epoch,
                        },
                    );
                }
            }
        }
    }

    /// Increase an existing bond.
    pub fn add_stake(
        &mut self,
        account: Address,
        role: RoleId,
        amount: u64,
    ) -> Result<u64, RegistryError> {
        let reg = self
            .registrations
            .get_mut(&(role, account))
            .ok_or(RegistryError::NotRegistered { account, role })?;
        reg.stake = reg.stake.saturating_add(amount);
        Ok(reg.stake)
    }

    /// Begin unbonding: the registration is marked `Unbonding` and its stake is
    /// locked until `current_epoch + UNBONDING_EPOCHS`.
    pub fn begin_unbonding(
        &mut self,
        account: Address,
        role: RoleId,
        current_epoch: u64,
    ) -> Result<u64, RegistryError> {
        let reg = self
            .registrations
            .get_mut(&(role, account))
            .ok_or(RegistryError::NotRegistered { account, role })?;
        if !matches!(reg.status, MemberStatus::Active) {
            return Err(RegistryError::NotActive { account, role });
        }
        let release_epoch = current_epoch.saturating_add(self.params.unbonding_epochs);
        reg.status = MemberStatus::Unbonding { release_epoch };
        Ok(release_epoch)
    }

    /// Complete withdrawal after the unbonding period elapses. Returns the
    /// released stake and removes the registration.
    pub fn withdraw(
        &mut self,
        account: Address,
        role: RoleId,
        current_epoch: u64,
    ) -> Result<u64, RegistryError> {
        let reg = self
            .registrations
            .get(&(role, account))
            .ok_or(RegistryError::NotRegistered { account, role })?;
        match reg.status {
            MemberStatus::Unbonding { release_epoch } => {
                if current_epoch < release_epoch {
                    return Err(RegistryError::StillUnbonding {
                        release_epoch,
                        current_epoch,
                    });
                }
            }
            _ => return Err(RegistryError::NotActive { account, role }),
        }
        let reg = self
            .registrations
            .remove(&(role, account))
            .expect("checked");
        Ok(reg.stake)
    }

    /// Slash a member for a proven offence. Applies a fixed-point ratio penalty
    /// (`FIXED_POINT_SCALE`-scaled) and jails the member (`Slashed`).
    pub fn slash(
        &mut self,
        account: Address,
        role: RoleId,
        condition: SlashingCondition,
        slash_ratio_fixed: u64,
    ) -> Result<SlashOutcome, RegistryError> {
        let reg = self
            .registrations
            .get_mut(&(role, account))
            .ok_or(RegistryError::NotRegistered { account, role })?;

        // Already jailed: treat as no-op so the same evidence cannot inflate
        // slashing_history / re-apply penalty (dedup for slash_from_report).
        if matches!(reg.status, MemberStatus::Slashed) {
            return Ok(SlashOutcome {
                condition,
                penalty: 0,
                remaining_stake: reg.stake,
            });
        }

        let penalty =
            ((reg.stake as u128 * slash_ratio_fixed as u128) / FIXED_POINT_SCALE as u128) as u64;
        reg.stake = reg.stake.saturating_sub(penalty);
        reg.status = MemberStatus::Slashed;
        let remaining_stake = reg.stake;

        // Phase 0.334 / A5: cross-role slash — jail every other registration of
        // the same address so a slashed validator cannot continue as relayer/prover.
        self.slash_cross_role(account, role, condition, slash_ratio_fixed);

        Ok(SlashOutcome {
            condition,
            penalty,
            remaining_stake,
        })
    }

    /// Jail (and proportionally slash) all other roles held by `account`.
    fn slash_cross_role(
        &mut self,
        account: Address,
        primary_role: RoleId,
        _condition: SlashingCondition,
        slash_ratio_fixed: u64,
    ) {
        let other_keys: Vec<RoleId> = self
            .registrations
            .keys()
            .filter_map(|(role, addr)| {
                if *addr == account && *role != primary_role {
                    Some(*role)
                } else {
                    None
                }
            })
            .collect();

        for role in other_keys {
            if let Some(reg) = self.registrations.get_mut(&(role, account)) {
                if matches!(reg.status, MemberStatus::Slashed) {
                    continue;
                }
                let penalty = ((reg.stake as u128 * slash_ratio_fixed as u128)
                    / FIXED_POINT_SCALE as u128) as u64;
                reg.stake = reg.stake.saturating_sub(penalty);
                reg.status = MemberStatus::Slashed;
            }
        }
    }

    /// Slash directly from a canonical [`SlashingReport`].
    ///
    /// This is the entry point the rest of the node (consensus, RPC, other
    /// domains) should use: the report carries its own condition and the slash
    /// ratio is resolved from [`RegistryParams`]. The registry will only act on
    /// reports that are structurally valid AND consensus-verified
    /// (`report.is_actionable()`), so an externally-submitted, unverified report
    /// can be accepted by a permissionless RPC endpoint without ever slashing on
    /// unproven claims.
    ///
    /// Returns `Ok(None)` if the offender is not registered for that role
    /// (nothing to slash) and `Ok(Some(outcome))` on success.
    pub fn slash_from_report(
        &mut self,
        report: &SlashingReport,
    ) -> Result<Option<SlashOutcome>, EvidenceError> {
        report.is_actionable()?;
        let condition = report.condition();
        let ratio = self.params.slash_ratio(condition);
        match self.slash(report.offender, report.role, condition, ratio) {
            Ok(outcome) => {
                // Dedup: already-slashed re-submission (penalty==0) must not
                // inflate audit history.
                if outcome.penalty == 0 {
                    return Ok(None);
                }
                self.slashing_history.push(SlashingRecord {
                    report: report.clone(),
                    penalty: outcome.penalty,
                    remaining_stake: outcome.remaining_stake,
                });
                Ok(Some(outcome))
            }
            Err(RegistryError::NotRegistered { .. }) => Ok(None),
            // The only other error paths are unreachable here (slash never
            // returns NotActive/etc.), but be defensive: treat as no-op.
            Err(_) => Ok(None),
        }
    }

    /// All persisted slashing records, in the order they were actioned.
    pub fn slashing_history(&self) -> &[SlashingRecord] {
        &self.slashing_history
    }

    /// Persisted slashing records for a specific offender (Phase 0.40, Görev 1).
    /// Includes equivocation (`DoubleSign`), liveness, invalid-vote-spam and any
    /// other actioned report against `offender`.
    pub fn slashing_history_for(&self, offender: &Address) -> Vec<&SlashingRecord> {
        self.slashing_history
            .iter()
            .filter(|r| &r.report.offender == offender)
            .collect()
    }

    /// Read a registration.
    pub fn get(&self, account: &Address, role: RoleId) -> Option<&Registration> {
        self.registrations.get(&(role, *account))
    }

    /// True iff the account is *actively* registered for the role. This is the
    /// authorization check the rest of the node should use — it is purely a
    /// function of bonded stake + status, never of any allow-list.
    pub fn is_active(&self, account: &Address, role: RoleId) -> bool {
        self.get(account, role)
            .map(Registration::is_active)
            .unwrap_or(false)
    }

    /// All active members of a role.
    pub fn active_members(&self, role: RoleId) -> Vec<&Registration> {
        self.registrations
            .values()
            .filter(|r| r.role == role && r.is_active())
            .collect()
    }

    /// Eligibility check for submitting relayed cross-domain messages.
    ///
    /// A relayer may submit while `Active` OR while `Unbonding` — unbonding is
    /// an exit process, not a punishment: the stake is still locked and remains
    /// slashable, so economic security still holds. A `Slashed` relayer (or an
    /// unregistered account) is rejected.
    pub fn is_active_relayer(&self, account: &Address) -> bool {
        match self.get(account, crate::registry::role::roles::RELAYER) {
            Some(reg) => {
                matches!(
                    reg.status,
                    MemberStatus::Active | MemberStatus::Unbonding { .. }
                ) && reg.stake > 0
            }
            None => false,
        }
    }

    /// Result-returning variant of [`Self::is_active_relayer`] for call sites
    /// that want a descriptive error.
    pub fn ensure_active_relayer(&self, account: &Address) -> Result<(), RegistryError> {
        if self.is_active_relayer(account) {
            Ok(())
        } else {
            Err(RegistryError::RelayerNotActive { account: *account })
        }
    }

    /// Reward-eligibility check for a prover.
    ///
    /// IMPORTANT: unlike [`Self::is_active_relayer`], this is NOT a submission
    /// gate. Proof submission is fully permissionless (STARK proofs are
    /// self-verifying, so the network need not trust the submitter). This
    /// predicate is consulted ONLY when deciding whether a successful proof
    /// earns its submitter a reward. Active = registered with positive stake and
    /// not slashed (unbonding still counts, mirroring the relayer semantics).
    pub fn is_active_prover(&self, account: &Address) -> bool {
        match self.get(account, crate::registry::role::roles::PROVER) {
            Some(reg) => {
                matches!(
                    reg.status,
                    MemberStatus::Active | MemberStatus::Unbonding { .. }
                ) && reg.stake > 0
            }
            None => false,
        }
    }

    /// Total stake bonded to a role (active registrations only).
    pub fn total_stake(&self, role: RoleId) -> u64 {
        self.registrations
            .values()
            .filter(|r| r.role == role && r.is_active())
            .map(|r| r.stake)
            .fold(0u64, |acc, s| acc.saturating_add(s))
    }

    pub fn len(&self) -> usize {
        self.registrations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.registrations.is_empty()
    }

    /// Return all registrations as a flat `Vec<Registration>`.
    /// Useful for test introspection and audit queries.
    pub fn registrations_as_seq(&self) -> Vec<&Registration> {
        self.registrations.values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::role::roles;

    fn addr(b: u8) -> Address {
        Address::from([b; 32])
    }

    #[test]
    fn anyone_can_register_by_staking_no_whitelist() {
        let mut reg = PermissionlessRegistry::new();
        // A fresh, never-approved account joins purely by staking.
        reg.register_validator(addr(1), MIN_REGISTRATION_STAKE, 0)
            .unwrap();
        assert!(reg.is_active(&addr(1), roles::VALIDATOR));
    }

    #[test]
    fn registration_below_min_stake_rejected() {
        let mut reg = PermissionlessRegistry::new();
        let err = reg
            .register_relayer(addr(2), MIN_REGISTRATION_STAKE - 1, 0)
            .unwrap_err();
        assert!(matches!(err, RegistryError::InsufficientStake { .. }));
    }

    #[test]
    fn duplicate_registration_rejected() {
        let mut reg = PermissionlessRegistry::new();
        reg.register_verifier(addr(3), MIN_REGISTRATION_STAKE, 0)
            .unwrap();
        assert!(reg
            .register_verifier(addr(3), MIN_REGISTRATION_STAKE, 0)
            .is_err());
    }

    #[test]
    fn unbonding_locks_stake_until_release_epoch() {
        let mut reg = PermissionlessRegistry::new();
        reg.register_validator(addr(4), 5_000, 10).unwrap();
        let release = reg.begin_unbonding(addr(4), roles::VALIDATOR, 10).unwrap();
        assert_eq!(release, 10 + UNBONDING_EPOCHS);
        // Too early.
        assert!(reg
            .withdraw(addr(4), roles::VALIDATOR, release - 1)
            .is_err());
        // After unbonding.
        let released = reg.withdraw(addr(4), roles::VALIDATOR, release).unwrap();
        assert_eq!(released, 5_000);
        assert!(reg.get(&addr(4), roles::VALIDATOR).is_none());
    }

    #[test]
    fn slashing_reduces_stake_and_jails() {
        let mut reg = PermissionlessRegistry::new();
        reg.register_validator(addr(5), 10_000, 0).unwrap();
        // 50% slash.
        let outcome = reg
            .slash(
                addr(5),
                roles::VALIDATOR,
                SlashingCondition::DoubleSign,
                FIXED_POINT_SCALE / 2,
            )
            .unwrap();
        assert_eq!(outcome.penalty, 5_000);
        assert_eq!(outcome.remaining_stake, 5_000);
        assert!(!reg.is_active(&addr(5), roles::VALIDATOR));
    }

    #[test]
    fn generic_over_arbitrary_roles() {
        let mut reg = PermissionlessRegistry::new();
        let custom = RoleId::new(4242);
        reg.register(addr(6), custom, MIN_REGISTRATION_STAKE, 0)
            .unwrap();
        assert!(reg.is_active(&addr(6), custom));
        assert_eq!(reg.active_members(custom).len(), 1);
    }

    #[test]
    fn same_account_can_hold_multiple_roles() {
        let mut reg = PermissionlessRegistry::new();
        reg.register_validator(addr(7), MIN_REGISTRATION_STAKE, 0)
            .unwrap();
        reg.register_relayer(addr(7), MIN_REGISTRATION_STAKE, 0)
            .unwrap();
        assert!(reg.is_active(&addr(7), roles::VALIDATOR));
        assert!(reg.is_active(&addr(7), roles::RELAYER));
    }

    /// Phase 0.334 / A5: slashing one role jails the same address in other roles.
    #[test]
    fn tur117_cross_role_slash_jails_all_roles() {
        let mut reg = PermissionlessRegistry::new();
        reg.register_validator(addr(77), 10_000, 0).unwrap();
        reg.register_relayer(addr(77), MIN_REGISTRATION_STAKE, 0)
            .unwrap();
        assert!(reg.is_active(&addr(77), roles::VALIDATOR));
        assert!(reg.is_active(&addr(77), roles::RELAYER));

        reg.slash(
            addr(77),
            roles::VALIDATOR,
            SlashingCondition::DoubleSign,
            FIXED_POINT_SCALE / 2,
        )
        .unwrap();

        assert!(!reg.is_active(&addr(77), roles::VALIDATOR));
        assert!(!reg.is_active(&addr(77), roles::RELAYER));
        // Relayer stake also reduced by the same ratio.
        let relayer = reg.get(&addr(77), roles::RELAYER).unwrap();
        assert_eq!(relayer.stake, MIN_REGISTRATION_STAKE / 2);
        assert!(matches!(relayer.status, MemberStatus::Slashed));
    }
}
