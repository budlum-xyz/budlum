//! Generic, permissionless verifier/relayer/attester registry.
//!
//! **One** registry, **one** staking mechanism, **one** slashing pipeline -
//! Shared by every role (Master Verifier, Relayer, Attester, Storage Operator,
//! AI Verifier, or any future caller-defined role).
//!
//! ## Invariants
//! - The ONLY gate is meeting [`MIN_REGISTRATION_STAKE`]. No whitelist.
//! - Slashing one role automatically jails **all** other roles held by the
//!   Same address (cross-role slashing).
//! - Evidence-gated slashing: only consensus-verified reports are acted on.
//! - Deterministic `state_root` for snapshot/consensus commitment.
//!
//! WIRING: unwired - measured, and the reason is narrower than it used to be.
//!
//! The previous reason said "a separate crate consumed by downstream
//! verifiers". That has no counterpart: no crate in the `budzero` workspace
//! depends on it and the package is not published. Today the only thing that
//! runs this code is its own tests.
//!
//! It is not deleted, because it is not functionless: it is the **independent
//! second expression** of the twin in the core (`src/registry/permissionless.rs`).
//! The same role lifecycle is written twice, in two separate code bases, and the
//! `slash_expression` gate prevents their slashing arithmetic from diverging;
//! the mirror tests run on both sides. Two independent writings of one account
//! make it harder for a single writing to be silently wrong - a small scale
//! version of Wheeler's double compiling idea.
//!
//! So this crate is not a library waiting for a consumer but a cross check of
//! the core. It is written down because that was the claim: if a real consumer
//! ever appears the reason changes, and if it does not, the code is still not
//! lying.
//!
//! ## The relationship with the twin in the core (`src/registry/permissionless.rs`)
//!
//! The two registries state the same role lifecycle in two separations: this
//! crate is offered downstream (to verifier clients), the one in the core is the
//! node's consensus state. Two different answers to the same question were
//! measured once and closed (repeat slashing: `Ok(penalty: 0)` versus
//! `Err(AlreadySlashed)`); the rule that keeps the class from returning: every
//! change in the slashing/unbonding semantics is applied to BOTH and the mirror
//! tests run on both sides.
//!
//! Deliberately kept differences (2026-08-22: there were two, one was closed by
//! decision G0):
//! - A zero penalty slashing is now recorded on both sides (the core was
//!   aligned; audit trail integrity is canonical - the event happened, it went
//!   into the record).
//! - The core side logs a refused slashing with `tracing::warn`; this crate
//!   carries no logging dependency, and tracking the `Ok(None)` return is the
//!   caller's responsibility.

use crate::address::Address;
use crate::evidence::{EvidenceError, SlashingReport};
use crate::params::{slash_penalty, RegistryParams};
use crate::role::RoleId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Default minimum stake required to register for a role.
pub const MIN_REGISTRATION_STAKE: u64 = 1_000;

/// Default number of epochs that unbonded stake stays locked.
pub const UNBONDING_EPOCHS: u64 = 7;

/// The cap for slashing records: the newest records are kept in live state and
/// the older ones belong to the archive layer, the block history. This is the
/// same value as its twin in the main tree
/// (`src/registry/permissionless.rs::MAX_SLASHING_HISTORY`); if the two
/// registries had different caps they would answer the same report sequence
/// with different `slashing_history` contents.
pub const MAX_SLASHING_HISTORY: usize = 4096;

/// Reasons a registered member can be slashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlashingCondition {
    /// Signed two conflicting blocks/messages at the same height/slot.
    DoubleSign,
    /// Failed liveness / availability obligations.
    LivenessFault,
    /// Provably malicious behaviour.
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
    Active,
    Unbonding { release_epoch: u64 },
    Slashed,
}

/// A single (account, role) registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registration {
    pub account: Address,
    pub role: RoleId,
    pub stake: u64,
    pub status: MemberStatus,
    pub registered_epoch: u64,
}

impl Registration {
    pub fn is_active(&self) -> bool {
        matches!(self.status, MemberStatus::Active) && self.stake > 0
    }

    /// Does it still hold a slashable bond: `Active` **or** `Unbonding`.
    ///
    /// This registry and `src/registry/permissionless.rs` must give the same answer
    /// to the same questions; both state the same lifecycle of the same roles.
    /// Task assignment asks `is_active`, responsibility asks `is_slashable`: an
    /// exiting member's bond is still locked, so it can be held responsible for
    /// work it did, but no new work may be given to it.
    pub fn is_slashable(&self) -> bool {
        matches!(
            self.status,
            MemberStatus::Active | MemberStatus::Unbonding { .. }
        ) && self.stake > 0
    }
}

/// Errors surfaced by the registry.
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
    RelayerNotActive {
        account: Address,
    },
    AlreadySlashed {
        account: Address,
        role: RoleId,
    },
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryError::InsufficientStake { required, provided } => {
                write!(
                    f,
                    "insufficient stake: required {required}, provided {provided}"
                )
            }
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
            } => {
                write!(
                    f,
                    "stake still unbonding until epoch {release_epoch} (now {current_epoch})"
                )
            }
            RegistryError::RelayerNotActive { account } => {
                write!(f, "{account} is not an active relayer")
            }
            RegistryError::AlreadySlashed { account, role } => {
                write!(
                    f,
                    "{account} already slashed as {role}; slashing is idempotent"
                )
            }
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

/// A persisted slashing record for audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingRecord {
    pub report: SlashingReport,
    pub penalty: u64,
    pub remaining_stake: u64,
}

/// The generic, RoleId-based verifier registry.
///
/// Keyed by `(RoleId, Address)` so the same account may hold several roles
/// With independent stakes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerifierRegistry {
    #[serde(with = "registrations_as_seq")]
    registrations: BTreeMap<(RoleId, Address), Registration>,
    #[serde(default)]
    params: RegistryParams,
    #[serde(default)]
    slashing_history: Vec<SlashingRecord>,
}

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

impl VerifierRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_params(params: RegistryParams) -> Self {
        Self {
            registrations: BTreeMap::new(),
            params,
            slashing_history: Vec::new(),
        }
    }

    pub fn params(&self) -> &RegistryParams {
        &self.params
    }

    pub fn set_params(&mut self, params: RegistryParams) {
        self.params = params;
    }

    // ─── Registration ──────────────────────────────────────────────────

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

    pub fn register_master_verifier(
        &mut self,
        account: Address,
        stake: u64,
        current_epoch: u64,
    ) -> Result<(), RegistryError> {
        self.register(
            account,
            crate::role::roles::MASTER_VERIFIER,
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
        self.register(account, crate::role::roles::RELAYER, stake, current_epoch)
    }

    pub fn register_attester(
        &mut self,
        account: Address,
        stake: u64,
        current_epoch: u64,
    ) -> Result<(), RegistryError> {
        self.register(account, crate::role::roles::ATTESTER, stake, current_epoch)
    }

    pub fn register_validator(
        &mut self,
        account: Address,
        stake: u64,
        current_epoch: u64,
    ) -> Result<(), RegistryError> {
        self.register(account, crate::role::roles::VALIDATOR, stake, current_epoch)
    }

    pub fn register_ai_operator(
        &mut self,
        account: Address,
        stake: u64,
        current_epoch: u64,
    ) -> Result<(), RegistryError> {
        self.register(
            account,
            crate::role::roles::AI_OPERATOR,
            stake,
            current_epoch,
        )
    }

    pub fn register_content_validator(
        &mut self,
        account: Address,
        stake: u64,
        current_epoch: u64,
    ) -> Result<(), RegistryError> {
        self.register(
            account,
            crate::role::roles::CONTENT_VALIDATOR,
            stake,
            current_epoch,
        )
    }

    // ─── Stake management ──────────────────────────────────────────────

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

    // ─── Unbonding / withdrawal ────────────────────────────────────────

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
        // The `match` above already read this entry, so the key is present.
        // Handled rather than unwrapped: this crate is consumed by verifiers
        // whose release profile aborts on panic, and a future edit to that
        // match must not be able to turn a missing key into a downed process.
        let reg = self
            .registrations
            .remove(&(role, account))
            .ok_or(RegistryError::NotActive { account, role })?;
        Ok(reg.stake)
    }

    // ─── Slashing ──────────────────────────────────────────────────────

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
        // HIGH (2026-08-17): slashing must be idempotent - replaying the same
        // report must not burn the remaining stake again. Refuse if already Slashed.
        if matches!(reg.status, MemberStatus::Slashed) {
            return Err(RegistryError::AlreadySlashed { account, role });
        }

        let penalty = slash_penalty(reg.stake, slash_ratio_fixed);
        reg.stake = reg.stake.saturating_sub(penalty);
        reg.status = MemberStatus::Slashed;
        let remaining_stake = reg.stake;

        self.slash_cross_role(account, role, slash_ratio_fixed);

        Ok(SlashOutcome {
            condition,
            penalty,
            remaining_stake,
        })
    }

    fn slash_cross_role(&mut self, account: Address, primary_role: RoleId, slash_ratio_fixed: u64) {
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
                let penalty = slash_penalty(reg.stake, slash_ratio_fixed);
                reg.stake = reg.stake.saturating_sub(penalty);
                reg.status = MemberStatus::Slashed;
            }
        }
    }

    pub fn slash_from_report(
        &mut self,
        report: &SlashingReport,
    ) -> Result<Option<SlashOutcome>, EvidenceError> {
        report.is_actionable()?;
        let condition = report.condition();
        let ratio = self.params.slash_ratio(condition);
        match self.slash(report.offender, report.role, condition, ratio) {
            Ok(outcome) => {
                self.record_slash(SlashingRecord {
                    report: report.clone(),
                    penalty: outcome.penalty,
                    remaining_stake: outcome.remaining_stake,
                });
                Ok(Some(outcome))
            }
            Err(RegistryError::NotRegistered { .. }) => Ok(None),
            Err(_) => Ok(None),
        }
    }

    /// Adds a slashing record, dropping the oldest once the cap is exceeded.
    ///
    /// The same behaviour as `src/registry/permissionless.rs::record_slash`:
    /// the newest records stay in live state. A history growing without a cap
    /// is an unbounded load on the memory and serialisation of every process
    /// keeping this record alive.
    fn record_slash(&mut self, record: SlashingRecord) {
        self.slashing_history.push(record);
        if self.slashing_history.len() > MAX_SLASHING_HISTORY {
            let excess = self.slashing_history.len() - MAX_SLASHING_HISTORY;
            self.slashing_history.drain(..excess);
        }
    }

    pub fn slashing_history(&self) -> &[SlashingRecord] {
        &self.slashing_history
    }

    pub fn slashing_history_for(&self, offender: &Address) -> Vec<&SlashingRecord> {
        self.slashing_history
            .iter()
            .filter(|r| &r.report.offender == offender)
            .collect()
    }

    // ─── Queries ───────────────────────────────────────────────────────

    pub fn get(&self, account: &Address, role: RoleId) -> Option<&Registration> {
        self.registrations.get(&(role, *account))
    }

    pub fn is_active(&self, account: &Address, role: RoleId) -> bool {
        self.get(account, role)
            .map(Registration::is_active)
            .unwrap_or(false)
    }

    pub fn active_members(&self, role: RoleId) -> Vec<&Registration> {
        self.registrations
            .values()
            .filter(|r| r.role == role && r.is_active())
            .collect()
    }

    // The role helpers ask a single question: can this member be given new work
    // NOW? The answer is yes only for `MemberStatus::Active`
    // (the 2026-08-22 decision, G0; aligned with the core
    // `src/registry/permissionless.rs` on the same day with the same decision - the
    // two registries must give the same answer to the same question). Responsibility
    // lives in `Registration::is_slashable`: the exiting member stays slashable
    // for the length of its lock, but takes no new work.
    pub fn is_active_relayer(&self, account: &Address) -> bool {
        self.get(account, crate::role::roles::RELAYER)
            .is_some_and(Registration::is_active)
    }

    pub fn is_active_attester(&self, account: &Address) -> bool {
        self.get(account, crate::role::roles::ATTESTER)
            .is_some_and(Registration::is_active)
    }

    pub fn is_active_master_verifier(&self, account: &Address) -> bool {
        self.is_active(account, crate::role::roles::MASTER_VERIFIER)
    }

    pub fn is_active_ai_operator(&self, account: &Address) -> bool {
        self.get(account, crate::role::roles::AI_OPERATOR)
            .is_some_and(Registration::is_active)
    }

    pub fn is_active_content_validator(&self, account: &Address) -> bool {
        self.get(account, crate::role::roles::CONTENT_VALIDATOR)
            .is_some_and(Registration::is_active)
    }

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

    pub fn registrations_as_seq(&self) -> Vec<&Registration> {
        self.registrations.values().collect()
    }

    // ─── State Root ────────────────────────────────────────────────────

    pub fn state_root(&self) -> [u8; 32] {
        if self.is_empty() {
            return [0u8; 32];
        }
        let mut hasher = Sha256::default();
        hasher.update(b"BDLM_VERIFIER_REGISTRY_V1");
        for (key, reg) in &self.registrations {
            hasher.update(key.0.as_bytes());
            hasher.update(key.1.as_bytes());
            hasher.update(reg.stake.to_le_bytes());
            hasher.update((reg.registered_epoch).to_le_bytes());
            match reg.status {
                MemberStatus::Active => hasher.update(b"active"),
                MemberStatus::Unbonding { release_epoch } => {
                    hasher.update(b"unbonding");
                    hasher.update(release_epoch.to_le_bytes());
                }
                MemberStatus::Slashed => hasher.update(b"slashed"),
            }
        }
        hasher.finalize().into()
    }
}

// ─── Unit Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::FIXED_POINT_SCALE;
    use crate::role::roles;

    fn addr(b: u8) -> Address {
        Address::from([b; 32])
    }

    /// Withdrawing must never panic, whatever order the caller uses.
    ///
    /// The removal below used to be an `expect("checked")` that leaned on the
    /// status match a few lines above. That was true, but the guarantee lived
    /// away from the read. This walks every reachable status so the refusal is
    /// asserted rather than assumed.
    #[test]
    fn withdraw_refuses_every_non_withdrawable_status_without_panicking() {
        let account = addr(9);

        // Never registered.
        let mut reg = VerifierRegistry::new();
        assert!(matches!(
            reg.withdraw(account, roles::VALIDATOR, 100),
            Err(RegistryError::NotRegistered { .. })
        ));

        // Registered and active: not unbonding yet.
        reg.register_validator(account, 5_000, 0)
            .expect("stake is above the minimum");
        assert!(matches!(
            reg.withdraw(account, roles::VALIDATOR, 100),
            Err(RegistryError::NotActive { .. })
        ));

        // Unbonding but still locked.
        let release = reg
            .begin_unbonding(account, roles::VALIDATOR, 10)
            .expect("an active registration can begin unbonding");
        assert!(
            release > 10,
            "unbonding must lock the stake for some epochs"
        );
        assert!(matches!(
            reg.withdraw(account, roles::VALIDATOR, release - 1),
            Err(RegistryError::StillUnbonding { .. })
        ));

        // Released: the one path that pays out, and it pays the full stake.
        assert_eq!(
            reg.withdraw(account, roles::VALIDATOR, release),
            Ok(5_000),
            "a released registration returns the whole stake"
        );

        // Withdrawing twice must refuse, not double-pay.
        assert!(matches!(
            reg.withdraw(account, roles::VALIDATOR, release),
            Err(RegistryError::NotRegistered { .. })
        ));
    }

    /// Slashing the same registration twice must not burn the stake twice.
    ///
    /// This is the replay case: the same evidence arriving again must leave
    /// the remaining stake untouched.
    #[test]
    fn slashing_twice_does_not_burn_the_remainder_again() {
        let account = addr(11);
        let mut reg = VerifierRegistry::new();
        reg.register_validator(account, 10_000, 0)
            .expect("stake is above the minimum");

        let half = FIXED_POINT_SCALE / 2;
        let first = reg
            .slash(
                account,
                roles::VALIDATOR,
                SlashingCondition::DoubleSign,
                half,
            )
            .expect("an active registration can be slashed");
        assert_eq!(first.penalty, 5_000);
        assert_eq!(first.remaining_stake, 5_000);

        let replay = reg.slash(
            account,
            roles::VALIDATOR,
            SlashingCondition::DoubleSign,
            half,
        );
        assert!(
            matches!(replay, Err(RegistryError::AlreadySlashed { .. })),
            "a replayed slash must be refused, got {replay:?}"
        );

        let after = reg
            .get(&account, roles::VALIDATOR)
            .expect("the registration still exists after being slashed");
        assert_eq!(
            after.stake, 5_000,
            "the remaining stake must survive the replay untouched"
        );
    }

    /// One address, several roles: slashing one jails all of them.
    ///
    /// The module header promises this, so it is asserted rather than trusted.
    #[test]
    fn slashing_one_role_jails_every_other_role_the_address_holds() {
        let account = addr(12);
        let mut reg = VerifierRegistry::new();
        reg.register_master_verifier(account, 5_000, 0)
            .expect("stake is above the minimum");
        reg.register_relayer(account, 3_000, 0)
            .expect("stake is above the minimum");
        reg.register_attester(account, 2_000, 0)
            .expect("stake is above the minimum");

        let half = FIXED_POINT_SCALE / 2;
        reg.slash(
            account,
            roles::MASTER_VERIFIER,
            SlashingCondition::DoubleSign,
            half,
        )
        .expect("an active registration can be slashed");

        for role in [roles::MASTER_VERIFIER, roles::RELAYER, roles::ATTESTER] {
            assert!(
                !reg.is_active(&account, role),
                "role {role:?} stayed active after a cross-role slash"
            );
        }
    }

    /// An exiting member takes no new task but stays slashable.
    ///
    /// This mirrors the test of the same name inside
    /// `src/registry/permissionless.rs`. The two registries state the same lifecycle
    /// of the same roles; giving different answers to the same input silently misleads
    /// a caller that does not know which one is being read. The difference was measured
    /// and closed: `Unbonding` was refused here and accepted in the core. The
    /// G0 decision of 2026-08-22: the helpers were pulled onto `is_active` on
    /// both sides - a departing member takes no new work, while its
    /// slashability continues under the separate `is_slashable` question.
    #[test]
    fn an_unbonding_member_takes_no_new_work_but_stays_slashable() {
        let mut reg = VerifierRegistry::new();
        let a = addr(21);
        reg.register_relayer(a, MIN_REGISTRATION_STAKE, 0)
            .expect("record");

        assert!(reg.is_active(&a, roles::RELAYER));
        assert!(reg.is_active_relayer(&a));

        reg.begin_unbonding(a, roles::RELAYER, 1)
            .expect("unbonding");

        assert!(
            !reg.is_active(&a, roles::RELAYER),
            "an exiting member is given no new task"
        );
        assert!(
            !reg.is_active_relayer(&a),
            "the role helper gives no new work either: authority is Active only"
        );
        assert!(
            reg.get(&a, roles::RELAYER)
                .is_some_and(|r| r.is_slashable()),
            "the bond is still locked: responsibility continues"
        );
    }

    /// A slashed member must not return `true` to any question.
    #[test]
    fn a_slashed_member_is_neither_active_nor_slashable_again() {
        let mut reg = VerifierRegistry::new();
        let a = addr(22);
        reg.register_relayer(a, MIN_REGISTRATION_STAKE, 0)
            .expect("record");
        reg.slash(
            a,
            roles::RELAYER,
            SlashingCondition::DoubleSign,
            FIXED_POINT_SCALE,
        )
        .expect("ilk kesme");

        assert!(!reg.is_active(&a, roles::RELAYER));
        assert!(
            !reg.is_active_relayer(&a),
            "a slashed bond cannot be slashed a second time"
        );
    }

    #[test]
    fn anyone_can_register_by_staking() {
        let mut reg = VerifierRegistry::new();
        reg.register_master_verifier(addr(1), MIN_REGISTRATION_STAKE, 0)
            .unwrap();
        assert!(reg.is_active_master_verifier(&addr(1)));
    }

    #[test]
    fn below_min_stake_rejected() {
        let mut reg = VerifierRegistry::new();
        let err = reg
            .register_relayer(addr(2), MIN_REGISTRATION_STAKE - 1, 0)
            .unwrap_err();
        assert!(matches!(err, RegistryError::InsufficientStake { .. }));
    }

    #[test]
    fn duplicate_registration_rejected() {
        let mut reg = VerifierRegistry::new();
        reg.register_attester(addr(3), MIN_REGISTRATION_STAKE, 0)
            .unwrap();
        assert!(reg
            .register_attester(addr(3), MIN_REGISTRATION_STAKE, 0)
            .is_err());
    }

    #[test]
    fn same_account_can_hold_all_three_roles() {
        let mut reg = VerifierRegistry::new();
        let account = addr(7);
        reg.register_master_verifier(account, 5_000, 0).unwrap();
        reg.register_relayer(account, 3_000, 0).unwrap();
        reg.register_attester(account, 2_000, 0).unwrap();

        assert!(reg.is_active_master_verifier(&account));
        assert!(reg.is_active_relayer(&account));
        assert!(reg.is_active_attester(&account));
    }

    #[test]
    fn unbonding_locks_stake_until_release() {
        let mut reg = VerifierRegistry::new();
        reg.register_validator(addr(4), 5_000, 10).unwrap();
        let release = reg.begin_unbonding(addr(4), roles::VALIDATOR, 10).unwrap();
        assert_eq!(release, 10 + UNBONDING_EPOCHS);
        assert!(reg
            .withdraw(addr(4), roles::VALIDATOR, release - 1)
            .is_err());
        let released = reg.withdraw(addr(4), roles::VALIDATOR, release).unwrap();
        assert_eq!(released, 5_000);
        assert!(reg.get(&addr(4), roles::VALIDATOR).is_none());
    }

    #[test]
    fn cannot_withdraw_while_active() {
        let mut reg = VerifierRegistry::new();
        reg.register_attester(addr(8), MIN_REGISTRATION_STAKE, 0)
            .unwrap();
        assert!(reg.withdraw(addr(8), roles::ATTESTER, 100).is_err());
    }

    #[test]
    fn slashing_reduces_stake_and_jails() {
        let mut reg = VerifierRegistry::new();
        reg.register_validator(addr(5), 10_000, 0).unwrap();
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
    fn cross_role_slash_jails_all_roles() {
        let mut reg = VerifierRegistry::new();
        let account = addr(77);
        reg.register_master_verifier(account, 10_000, 0).unwrap();
        reg.register_relayer(account, MIN_REGISTRATION_STAKE, 0)
            .unwrap();
        reg.register_attester(account, 2_000, 0).unwrap();

        reg.slash(
            account,
            roles::MASTER_VERIFIER,
            SlashingCondition::DoubleSign,
            FIXED_POINT_SCALE / 2,
        )
        .unwrap();

        assert!(!reg.is_active_master_verifier(&account));
        assert!(!reg.is_active_relayer(&account));
        assert!(!reg.is_active_attester(&account));
    }

    #[test]
    fn malicious_slash_burns_entire_bond() {
        let mut reg = VerifierRegistry::new();
        reg.register_master_verifier(addr(9), 10_000, 0).unwrap();
        let outcome = reg
            .slash(
                addr(9),
                roles::MASTER_VERIFIER,
                SlashingCondition::MaliciousBehaviour,
                FIXED_POINT_SCALE,
            )
            .unwrap();
        assert_eq!(outcome.penalty, 10_000);
        assert_eq!(outcome.remaining_stake, 0);
    }

    #[test]
    fn unverified_report_not_actionable() {
        use crate::evidence::{ProofProvenance, SlashingProof};

        let mut reg = VerifierRegistry::new();
        reg.register_master_verifier(addr(10), 10_000, 0).unwrap();

        let report = SlashingReport::new(
            addr(10),
            roles::MASTER_VERIFIER,
            SlashingProof::Liveness {
                window_start_epoch: 0,
                window_end_epoch: 10,
                missed: 5,
                expected: 10,
            },
            ProofProvenance::Unverified,
            None,
        );

        let result = reg.slash_from_report(&report);
        assert!(result.is_err());
        assert!(reg.is_active_master_verifier(&addr(10)));
    }

    #[test]
    fn consensus_verified_report_slashes() {
        use crate::evidence::{ProofProvenance, SlashingProof};

        let mut reg = VerifierRegistry::new();
        reg.register_master_verifier(addr(11), 10_000, 0).unwrap();

        let report = SlashingReport::new(
            addr(11),
            roles::MASTER_VERIFIER,
            SlashingProof::Liveness {
                window_start_epoch: 0,
                window_end_epoch: 10,
                missed: 5,
                expected: 10,
            },
            ProofProvenance::ConsensusVerified,
            None,
        );

        let result = reg.slash_from_report(&report).unwrap();
        assert!(result.is_some());
        assert!(!reg.is_active_master_verifier(&addr(11)));
    }

    /// The slashing history stops at the cap: the newest are kept, the oldest dropped.
    ///
    /// The counterpart test in the main tree carries the same name
    /// (`the_slashing_history_stops_growing_at_the_cap`): the two registries
    /// have to answer the same report sequence with the same length and the same
    /// order, otherwise a caller that does not know which one it is reading is
    /// silently misanswered.
    #[test]
    fn the_slashing_history_stops_growing_at_the_cap() {
        use crate::evidence::{ProofProvenance, SlashingProof};

        let mut reg = VerifierRegistry::new();
        let total = MAX_SLASHING_HISTORY + 3;
        for i in 0..total {
            let mut raw = [0u8; 32];
            raw[0] = (i / 256) as u8 + 1;
            raw[1] = (i % 256) as u8;
            let offender = Address::from(raw);
            reg.register_master_verifier(offender, 10_000, 0).unwrap();
            let report = SlashingReport::new(
                offender,
                roles::MASTER_VERIFIER,
                SlashingProof::Liveness {
                    window_start_epoch: 0,
                    window_end_epoch: 10,
                    missed: 5,
                    expected: 10,
                },
                ProofProvenance::ConsensusVerified,
                None,
            );
            assert!(reg.slash_from_report(&report).unwrap().is_some());
        }

        assert_eq!(reg.slashing_history().len(), MAX_SLASHING_HISTORY);
        // The oldest three records dropped: the first remaining record must belong to report i=3.
        let mut expected_first = [0u8; 32];
        expected_first[0] = 1;
        expected_first[1] = 3;
        let first = reg
            .slashing_history()
            .first()
            .map(|record| record.report.offender);
        assert_eq!(first, Some(Address::from(expected_first)));
        // The newest record sits at the end of the sequence: pruning happened from the front.
        let mut expected_last = [0u8; 32];
        expected_last[0] = ((total - 1) / 256) as u8 + 1;
        expected_last[1] = ((total - 1) % 256) as u8;
        let last = reg
            .slashing_history()
            .last()
            .map(|record| record.report.offender);
        assert_eq!(last, Some(Address::from(expected_last)));
    }

    #[test]
    fn d4_ai_and_content_validator_roles() {
        let mut reg = VerifierRegistry::new();
        reg.register_ai_operator(addr(20), MIN_REGISTRATION_STAKE, 0)
            .unwrap();
        reg.register_content_validator(addr(21), MIN_REGISTRATION_STAKE, 0)
            .unwrap();
        assert!(reg.is_active_ai_operator(&addr(20)));
        assert!(reg.is_active_content_validator(&addr(21)));
    }
}
