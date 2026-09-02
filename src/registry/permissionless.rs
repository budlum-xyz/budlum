//! Permissionless verifier/validator/relayer registry.
//!
//! Master-context rule: on PoW/PoS/BFT domains there is **no whitelist, no
//! Admin-approval and no central gate**. Participation == staking. Security is
//! Provided by economic incentive (stake) + slashing, never by permission.
//!
//! This is a shared primitive: it is generic over [`RoleId`] so future
//! Application layers (out of scope here) can reuse it with their own roles.
//!
//! ## What this module intentionally does NOT do
//! - It never stores an allow-list of approved accounts.
//! - It never exposes an `approve` / `admit` gate for PoW/PoS/BFT roles.
//! - It knows nothing about KYC. KYC-gated membership lives in a *separate*
//!   Module ([`crate::registry::poa_membership`]) with a separate data
//!   Structure, so PoA's permissioned rules cannot leak in here.

use crate::core::address::Address;
use crate::core::chain_config::slash_penalty;
use crate::registry::evidence::{EvidenceError, SlashingReport};
use crate::registry::params::RegistryParams;
use crate::registry::role::RoleId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Default minimum stake required to register for a role.
///
/// NOTE: this is only the *default* used by [`PermissionlessRegistry::new`].
/// The effective floor is a governance/config parameter
/// ([`RegistryParams::min_stake`]) - this constant must not be treated as a
/// Hard rule. It is a *stake floor*, not a permission check: anyone meeting it
/// Can join.
pub const MIN_REGISTRATION_STAKE: u64 = 1_000;

/// Default number of epochs that unbonded stake stays locked. Also overridable
/// Via [`RegistryParams::unbonding_epochs`]; kept as a constant for the default
/// And for existing callers/tests.
pub const UNBONDING_EPOCHS: u64 = 7;

/// How many slashing records the live registry keeps.
///
/// The history was unbounded and is hashed into [`PermissionlessRegistry::root`],
/// so it is consensus state that grew for the life of the chain. It is not
/// cheap to abuse - `SlashingReport::is_actionable` requires
/// `ProofProvenance::ConsensusVerified`, so records only appear for slashes
/// that actually happened - but "only grows when a validator misbehaves" is
/// still monotonic.
///
/// 4096 is far above any plausible operational need: at one slash per epoch it
/// is several years of history, and the records that matter to jail checks and
/// operator tooling are the recent ones. Older records remain reconstructible
/// from block history, which is where an audit trail belongs.
///
/// Changing this value is a consensus change: every node must apply the same
/// cap or two nodes that observed the same slashes would compute different
/// registry roots.
pub const MAX_SLASHING_HISTORY: usize = 4096;

/// Reasons a registered member can be slashed. Explicitly enumerated so the
/// Economic-security surface is auditable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlashingCondition {
    /// Signed two conflicting blocks/messages at the same height/slot.
    DoubleSign,
    /// Failed liveness / availability obligations (e.g. missed duties).
    LivenessFault,
    /// Provably malicious behaviour (invalid proof, equivocation, censorship
    /// Evidence, etc.).
    MaliciousBehaviour,
}

/// Stand-in bytes hashed when a registry entry cannot be serialized.
///
/// Derived `Serialize` on owned data has no failing case, so this never fires.
/// It is not a panic because the call site computes a state root that every
/// node computes alike: aborting would drop the whole validator set at once
/// rather than a single node.
const REGISTRY_SERIALIZE_FAILED: &[u8] = b"budlum/serialize-failed/permissionless-registry";

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
    /// Function of bonded stake + status (never any allow-list): the member
    /// Must be `Active` and still hold a positive bond.
    pub fn is_active(&self) -> bool {
        matches!(self.status, MemberStatus::Active) && self.stake > 0
    }

    /// Does the member still hold a slashable bond: `Active` **or**
    /// `Unbonding`.
    ///
    /// # Why there are two separate questions
    ///
    /// The two questions are not the same, and conflating them produced a quiet
    /// divergence. Role helpers such as `is_active_relayer` accepted
    /// `Unbonding`, while `is_active` did not; the same name gave two different
    /// answers, and the difference was written down nowhere.
    ///
    /// The right distinction is one of intent. To **hand out new work**, the
    /// member must be `Active`: assigning work to someone on their way out means
    /// their bond unlocks before the work is finished. To **hold them
    /// responsible for work already done**, `Unbonding` is enough, because the
    /// bond is still locked and still slashable. Otherwise a relayer would
    /// submit its transaction and then immediately call `begin_unbonding` to
    /// step out of responsibility.
    pub fn is_slashable(&self) -> bool {
        matches!(
            self.status,
            MemberStatus::Active | MemberStatus::Unbonding { .. }
        ) && self.stake > 0
    }
}

/// Errors surfaced by the permissionless registry.
///
/// Note there is deliberately **no** `NotWhitelisted` / `NotApproved` variant:
/// The only economic gate is [`RegistryError::InsufficientStake`].
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
    /// The account is already slashed for this role.
    ///
    /// A repeated slash used to return `Ok` with `penalty: 0`, which reads at
    /// the call site as "the slash was applied and cost nothing" rather than
    /// "this was a replay". The budzero registry rejected the same call, so
    /// the two registries disagreed on the same input; this variant is the
    /// core side of that agreement.
    AlreadySlashed {
        account: Address,
        role: RoleId,
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
            RegistryError::AlreadySlashed { account, role } => {
                write!(f, "{account} is already slashed as {role}")
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

/// The permissionless registry itself.
///
/// Keyed by `(role, account)` so the same account may hold several roles
/// (e.g. be both a validator and a relayer) with independent stakes.
///
/// Carries its [`RegistryParams`] so the stake floor, unbonding window and
/// Slash ratios are governance/config-driven, never hard-coded.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PermissionlessRegistry {
    #[serde(with = "registrations_as_seq")]
    registrations: BTreeMap<(RoleId, Address), Registration>,
    #[serde(default)]
    params: RegistryParams,
    #[serde(default)]
    /// Slashing records, newest last, capped at [`MAX_SLASHING_HISTORY`].
    ///
    /// Consensus state: `root()` hashes every record, so the cap has to be
    /// applied identically on every node. Trimming from the front on insert is
    /// deterministic - it depends only on the number of records, not on time,
    /// node age, or when a node joined.
    slashing_history: Vec<SlashingRecord>,
}

/// A persisted, actioned slashing report plus the outcome it produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingRecord {
    pub report: SlashingReport,
    pub penalty: u64,
    pub remaining_stake: u64,
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

impl PermissionlessRegistry {
    pub fn new() -> Self {
        Self {
            registrations: BTreeMap::new(),
            params: RegistryParams::default(),
            slashing_history: Vec::new(),
        }
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

    // Convenience wrappers for well-known roles (unified)

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

    /// DeEd master verifier - alias to VERIFIER (RoleId 2)
    pub fn register_master_verifier(
        &mut self,
        account: Address,
        stake: u64,
        current_epoch: u64,
    ) -> Result<(), RegistryError> {
        self.register(
            account,
            crate::registry::role::roles::MASTER_VERIFIER,
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

    pub fn register_ai_verifier(
        &mut self,
        account: Address,
        stake: u64,
        current_epoch: u64,
    ) -> Result<(), RegistryError> {
        self.register(
            account,
            crate::registry::role::roles::AI_VERIFIER,
            stake,
            current_epoch,
        )
    }

    /// Supply-chain attester (ATTESTER=7) - unified registry
    pub fn register_attester(
        &mut self,
        account: Address,
        stake: u64,
        current_epoch: u64,
    ) -> Result<(), RegistryError> {
        self.register(
            account,
            crate::registry::role::roles::ATTESTER,
            stake,
            current_epoch,
        )
    }

    /// AI inference layer operator (RoleId 8) - must be preserved
    pub fn register_ai_operator(
        &mut self,
        account: Address,
        stake: u64,
        current_epoch: u64,
    ) -> Result<(), RegistryError> {
        self.register(
            account,
            crate::registry::role::roles::AI_OPERATOR,
            stake,
            current_epoch,
        )
    }

    /// SocialFi content validator (RoleId 9)
    pub fn register_content_validator(
        &mut self,
        account: Address,
        stake: u64,
        current_epoch: u64,
    ) -> Result<(), RegistryError> {
        self.register(
            account,
            crate::registry::role::roles::CONTENT_VALIDATOR,
            stake,
            current_epoch,
        )
    }

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

    pub fn begin_unbonding(
        &mut self,
        account: Address,
        role: RoleId,
        current_epoch: u64,
    ) -> Result<u64, RegistryError> {
        let unbonding_epochs = self.params.unbonding_epochs;
        self.begin_unbonding_with_delay(account, role, current_epoch, unbonding_epochs)
    }

    pub fn begin_unbonding_with_delay(
        &mut self,
        account: Address,
        role: RoleId,
        current_epoch: u64,
        unbonding_epochs: u64,
    ) -> Result<u64, RegistryError> {
        let reg = self
            .registrations
            .get_mut(&(role, account))
            .ok_or(RegistryError::NotRegistered { account, role })?;
        if !matches!(reg.status, MemberStatus::Active) {
            return Err(RegistryError::NotActive { account, role });
        }
        let release_epoch = current_epoch.saturating_add(unbonding_epochs);
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
        // Returning an error instead of panicking keeps a future edit to that
        // match from turning a missing key into a downed node.
        let reg = self
            .registrations
            .remove(&(role, account))
            .ok_or(RegistryError::NotActive { account, role })?;
        Ok(reg.stake)
    }

    /// Cut stake for a condition the caller has already established.
    ///
    /// This takes a bare `SlashingCondition` and trusts it. That is correct
    /// for the two callers it has, both of which sit behind consensus:
    /// `Account::apply_slashing` mirrors a slash the consensus layer already
    /// decided, and the executor path slashes an AI inference layer bond on an equivocation
    /// the same block proved.
    ///
    /// It is the wrong entry point for anything carrying a
    /// [`crate::registry::evidence::SlashingReport`], because a report has a
    /// provenance field and this signature cannot see it. Use
    /// [`Self::slash_from_report`], which refuses a report the consensus
    /// layer has not marked `ConsensusVerified`. An externally submitted
    /// report passes structural validation, so a path that only checks shape
    /// would cut real stake on an unverified claim.
    pub fn slash(
        &mut self,
        account: Address,
        role: RoleId,
        condition: SlashingCondition,
        slash_ratio_fixed: u64,
    ) -> Result<SlashOutcome, RegistryError> {
        // `slash_role_only` now refuses a replay, so reaching the next line
        // means this is the first slash for the role and the cross-role sweep
        // is owed. The previous `already_slashed` precheck existed only to
        // suppress that sweep after a zero-penalty `Ok`.
        let outcome = self.slash_role_only(account, role, condition, slash_ratio_fixed)?;
        self.slash_cross_role(account, role, condition, slash_ratio_fixed);
        Ok(outcome)
    }

    /// Slash only the specified application role without mutating independent
    /// Consensus/storage/relayer bonds. AI inference layer equivocation uses this path because
    /// The approved penalty is the RoleId(8) bond, not an implicit validator
    /// Slash unsupported by consensus evidence.
    pub fn slash_role_only(
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

        // A replayed slash is refused rather than answered with a zero-penalty
        // `Ok`. Both readings leave the stake untouched, but only one of them
        // tells the caller that nothing happened: an `Ok` here is
        // indistinguishable from a slash that legitimately cost nothing, so a
        // caller that logs `penalty` or counts successful slashes records a
        // second punishment that never occurred.
        if matches!(reg.status, MemberStatus::Slashed) {
            return Err(RegistryError::AlreadySlashed { account, role });
        }

        let penalty = slash_penalty(reg.stake, slash_ratio_fixed);
        reg.stake = reg.stake.saturating_sub(penalty);
        reg.status = MemberStatus::Slashed;

        Ok(SlashOutcome {
            condition,
            penalty,
            remaining_stake: reg.stake,
        })
    }

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
                // A slash with a zero penalty is recorded too; the G0 decision
                // of 2026-08-22, aligned with budzero. The earlier early return
                // erased a zero-penalty slash from the record entirely: the
                // report was actionable and the event happened, yet it never
                // appeared in the audit trail. Record integrity is worth more
                // than the zero penalty itself, and the two ledgers must give
                // the same answer to the same question.
                self.record_slash(SlashingRecord {
                    report: report.clone(),
                    penalty: outcome.penalty,
                    remaining_stake: outcome.remaining_stake,
                });
                Ok(Some(outcome))
            }
            // Not registered is a legitimate no-op: evidence can name an
            // account that never held the role, and there is nothing to cut.
            Err(RegistryError::NotRegistered { .. }) => Ok(None),
            // Everything else used to collapse into the same `Ok(None)`, so a
            // slash that failed for any other reason was indistinguishable
            // from one that correctly found nothing to do. Consensus called
            // this and moved on believing the report had been handled.
            //
            // Still `Ok(None)` - a failed slash must not abort block
            // application, or one bad report would halt the chain, but it is
            // no longer silent. An operator seeing this line knows evidence
            // was accepted and then dropped.
            Err(reason) => {
                tracing::warn!(
                    offender = %report.offender,
                    role = ?report.role,
                    ?condition,
                    %reason,
                    "slashing report was actionable but the registry refused it; \
                     no stake was cut"
                );
                Ok(None)
            }
        }
    }

    /// Append a slashing record, dropping the oldest once the cap is reached.
    ///
    /// Trimming from the front keeps the newest records, which are the ones
    /// jail checks and operator tooling read. Anything older belongs in an
    /// archive built from block history, not in live consensus state.
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

    // Active checks for all well-known roles (unified)

    // These helpers ask about SLASHABILITY, not about assigning work.
    //
    // Unbonding is an EXIT process, not a punishment: the stake is still locked
    // and still slashable. A member whose lock persists being able to keep
    // relaying is not a hole but a deliberate liveness decision; otherwise
    // calling `begin_unbonding` would create an asymmetry in which the network
    // loses relay capacity throughout the exit window while the member's
    // responsibility continues.
    //
    // The question of assigning work is separate and lives in
    // `Registration::is_active`. Removing this distinction, by making both of
    // them `is_active`, was tried and reverted: it inverted the decision the
    // `unbonding_relayer_can_still_submit` test documents without updating that
    // test, so the consensus behaviour fell into contradiction.
    pub fn is_active_relayer(&self, account: &Address) -> bool {
        self.get(account, crate::registry::role::roles::RELAYER)
            .is_some_and(Registration::is_slashable)
    }

    pub fn ensure_active_relayer(&self, account: &Address) -> Result<(), RegistryError> {
        if self.is_active_relayer(account) {
            Ok(())
        } else {
            Err(RegistryError::RelayerNotActive { account: *account })
        }
    }

    pub fn is_active_attester(&self, account: &Address) -> bool {
        self.get(account, crate::registry::role::roles::ATTESTER)
            .is_some_and(Registration::is_slashable)
    }

    pub fn ensure_active_attester(&self, account: &Address) -> Result<(), RegistryError> {
        if self.is_active_attester(account) {
            Ok(())
        } else {
            Err(RegistryError::NotActive {
                account: *account,
                role: crate::registry::role::roles::ATTESTER,
            })
        }
    }

    pub fn is_active_master_verifier(&self, account: &Address) -> bool {
        self.is_active(account, crate::registry::role::roles::MASTER_VERIFIER)
    }

    pub fn is_active_ai_operator(&self, account: &Address) -> bool {
        self.get(account, crate::registry::role::roles::AI_OPERATOR)
            .is_some_and(Registration::is_slashable)
    }

    pub fn is_active_content_validator(&self, account: &Address) -> bool {
        self.get(account, crate::registry::role::roles::CONTENT_VALIDATOR)
            .is_some_and(Registration::is_slashable)
    }

    pub fn is_active_ai_verifier(&self, account: &Address) -> bool {
        match self.get(account, crate::registry::role::roles::AI_VERIFIER) {
            Some(reg) => {
                matches!(
                    reg.status,
                    MemberStatus::Active | MemberStatus::Unbonding { .. }
                ) && reg.stake > 0
            }
            None => false,
        }
    }

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

    pub fn total_stake(&self, role: RoleId) -> u64 {
        self.registrations
            .values()
            .filter(|r| r.role == role && r.is_active())
            .map(|r| r.stake)
            .fold(0u64, |acc, s| acc.saturating_add(s))
    }

    /// Total bonded stake represented only by this registry, excluding a
    /// Mirrored role such as VALIDATOR. All lifecycle states count because an
    /// Unbonding, jailed, or partially slashed remainder still exists as locked
    /// Supply until a canonical withdrawal or burn removes it.
    pub fn total_bonded_stake_excluding(&self, excluded_role: RoleId) -> u128 {
        self.registrations
            .values()
            .filter(|registration| registration.role != excluded_role)
            .fold(0u128, |total, registration| {
                total.saturating_add(registration.stake as u128)
            })
    }

    pub fn len(&self) -> usize {
        self.registrations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.registrations.is_empty()
    }

    pub fn has_non_default_state(&self) -> bool {
        !self.registrations.is_empty()
            || !self.slashing_history.is_empty()
            || self.params != RegistryParams::default()
    }

    pub fn root(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_PERMISSIONLESS_REGISTRY_V1");
        hasher.update(
            bincode::serialize(&self.params).unwrap_or_else(|_| REGISTRY_SERIALIZE_FAILED.to_vec()),
        );
        for registration in self.registrations.values() {
            hasher.update(
                bincode::serialize(registration)
                    .unwrap_or_else(|_| REGISTRY_SERIALIZE_FAILED.to_vec()),
            );
        }
        for record in &self.slashing_history {
            hasher.update(
                bincode::serialize(record).unwrap_or_else(|_| REGISTRY_SERIALIZE_FAILED.to_vec()),
            );
        }
        hasher.finalize().into()
    }

    pub fn registrations_as_seq(&self) -> Vec<&Registration> {
        self.registrations.values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::chain_config::FIXED_POINT_SCALE;
    use crate::registry::role::roles;

    fn addr(b: u8) -> Address {
        Address::from([b; 32])
    }

    #[test]
    fn anyone_can_register_by_staking_no_whitelist() {
        let mut reg = PermissionlessRegistry::new();
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

    /// A replayed slash must be refused, not answered with a zero penalty.
    ///
    /// The two registries disagreed on exactly this input: budzero returned
    /// `Err(AlreadySlashed)`, core returned `Ok(penalty: 0)`. Nothing covered
    /// the second call, which is why the divergence survived. An `Ok` here is
    /// indistinguishable from a slash that legitimately cost nothing.
    #[test]
    fn slashing_the_same_role_twice_is_refused() {
        let mut reg = PermissionlessRegistry::new();
        reg.register_validator(addr(9), MIN_REGISTRATION_STAKE, 0)
            .unwrap();

        let first = reg
            .slash(
                addr(9),
                roles::VALIDATOR,
                SlashingCondition::DoubleSign,
                FIXED_POINT_SCALE,
            )
            .expect("the first slash applies");
        assert!(first.penalty > 0, "the first slash must cost stake");
        let after_first = first.remaining_stake;

        let err = reg
            .slash(
                addr(9),
                roles::VALIDATOR,
                SlashingCondition::DoubleSign,
                FIXED_POINT_SCALE,
            )
            .expect_err("the replay must be refused");
        assert_eq!(
            err,
            RegistryError::AlreadySlashed {
                account: addr(9),
                role: roles::VALIDATOR
            }
        );

        // The refusal must not have moved any stake either.
        assert_eq!(
            reg.get(&addr(9), roles::VALIDATOR)
                .map(|r| r.stake)
                .unwrap_or_default(),
            after_first,
            "a refused replay must leave the stake untouched"
        );
    }

    /// `slash_role_only` is the path the executor uses for AI inference layer equivocation;
    /// it must refuse a replay for the same reason.
    #[test]
    fn slashing_a_role_only_twice_is_refused() {
        let mut reg = PermissionlessRegistry::new();
        reg.register_validator(addr(10), MIN_REGISTRATION_STAKE, 0)
            .unwrap();
        reg.slash_role_only(
            addr(10),
            roles::VALIDATOR,
            SlashingCondition::MaliciousBehaviour,
            FIXED_POINT_SCALE,
        )
        .expect("the first slash applies");
        assert!(reg
            .slash_role_only(
                addr(10),
                roles::VALIDATOR,
                SlashingCondition::MaliciousBehaviour,
                FIXED_POINT_SCALE,
            )
            .is_err());
    }

    #[test]
    fn unbonding_locks_stake_until_release_epoch() {
        let mut reg = PermissionlessRegistry::new();
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
    fn slashing_reduces_stake_and_jails() {
        let mut reg = PermissionlessRegistry::new();
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

    #[test]
    fn cross_role_slash_jails_all_roles() {
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
        let relayer = reg.get(&addr(77), roles::RELAYER).unwrap();
        assert_eq!(relayer.stake, MIN_REGISTRATION_STAKE / 2);
        assert!(matches!(relayer.status, MemberStatus::Slashed));
    }

    // New roles tests

    #[test]
    fn d4_master_verifier_alias_registers_and_is_active() {
        let mut reg = PermissionlessRegistry::new();
        reg.register_master_verifier(addr(10), MIN_REGISTRATION_STAKE, 0)
            .unwrap();
        assert!(reg.is_active_master_verifier(&addr(10)));
        assert!(reg.is_active(&addr(10), roles::VERIFIER)); // alias
    }

    /// A member on the way out takes no work assignment but stays slashable.
    ///
    /// The two questions are answered separately, and the distinction is
    /// deliberate: `is_active` asks about work assignment, while the role
    /// helpers, which read `is_slashable`, ask about slashability. Making both
    /// answer the same for the same status would turn calling `begin_unbonding`
    /// into the way to escape responsibility.
    ///
    /// Unbonding is an exit process, not a punishment: as long as the bond is
    /// locked, the member can keep relaying. The opposite was tried and
    /// reverted, because the network lost relay capacity throughout the exit
    /// window while the member's responsibility continued.
    #[test]
    fn an_unbonding_member_takes_no_new_work_but_stays_slashable() {
        let mut reg = PermissionlessRegistry::new();
        let a = addr(21);
        reg.register_relayer(a, MIN_REGISTRATION_STAKE, 0)
            .expect("registration");

        assert!(
            reg.is_active(&a, roles::RELAYER),
            "while active it takes work"
        );
        assert!(reg.is_active_relayer(&a), "while active it is slashable");

        reg.begin_unbonding(a, roles::RELAYER, 1)
            .expect("unbonding");

        assert!(
            !reg.is_active(&a, roles::RELAYER),
            "no new work is assigned to a member on the way out"
        );
        assert!(
            reg.is_active_relayer(&a),
            "the role helper asks about slashability: relaying continues while the bond is locked"
        );
        assert!(
            reg.get(&a, roles::RELAYER)
                .is_some_and(|r| r.is_slashable()),
            "the bond is still locked, so responsibility continues"
        );
    }

    /// A zero-penalty slash must still be recorded, mirroring budzero's
    /// `verifier-registry`.
    ///
    /// A condition whose ratio is zero, such as liveness, makes the slash
    /// "free": the stake does not change. The earlier code erased that event
    /// from the history entirely, and having two ledgers give different answers
    /// for the same entry quietly misled a caller who did not know which one was
    /// being read. That is the G0 decision of 2026-08-22: record integrity is
    /// canonical, so the event happened, it entered the record, and its penalty
    /// is zero.
    #[test]
    fn a_zero_penalty_slash_is_still_recorded() {
        let params = RegistryParams {
            liveness_slash_ratio_fixed: 0,
            ..RegistryParams::default()
        };
        let mut reg = PermissionlessRegistry::with_params(params);
        let a = addr(23);
        reg.register_relayer(a, MIN_REGISTRATION_STAKE, 0)
            .expect("registration");

        let report = crate::registry::evidence::SlashingReport::consensus_liveness(
            a,
            roles::RELAYER,
            0,
            10,
            5,
            10,
            None,
        );
        let outcome = reg
            .slash_from_report(&report)
            .expect("the report is actionable")
            .expect("the slash was applied");
        assert_eq!(
            outcome.penalty, 0,
            "the ratio is zero, so the penalty must be zero"
        );
        assert_eq!(
            reg.slashing_history().len(),
            1,
            "the event must enter the record: an offence with a zero penalty is still an offence"
        );
        assert_eq!(reg.slashing_history()[0].penalty, 0);
        assert!(
            !reg.is_active_relayer(&a),
            "the member still moves into the Slashed status"
        );
    }

    /// A slashed member must answer `true` to no question.
    #[test]
    fn a_slashed_member_is_neither_active_nor_slashable_again() {
        let mut reg = PermissionlessRegistry::new();
        let a = addr(22);
        reg.register_relayer(a, MIN_REGISTRATION_STAKE, 0)
            .expect("registration");
        reg.slash(
            a,
            roles::RELAYER,
            SlashingCondition::DoubleSign,
            FIXED_POINT_SCALE,
        )
        .expect("the first slash");

        assert!(!reg.is_active(&a, roles::RELAYER));
        assert!(
            !reg.is_active_relayer(&a),
            "a slashed bond cannot be slashed a second time"
        );
    }

    #[test]
    fn d4_attester_ai_content_validator_roles() {
        let mut reg = PermissionlessRegistry::new();
        reg.register_attester(addr(20), MIN_REGISTRATION_STAKE, 0)
            .unwrap();
        reg.register_ai_operator(addr(21), MIN_REGISTRATION_STAKE, 0)
            .unwrap();
        reg.register_content_validator(addr(22), MIN_REGISTRATION_STAKE, 0)
            .unwrap();

        assert!(reg.is_active_attester(&addr(20)));
        assert!(reg.is_active_ai_operator(&addr(21)));
        assert!(reg.is_active_content_validator(&addr(22)));

        // Same account can hold all three new roles
        reg.register_attester(addr(30), 5_000, 0).unwrap();
        reg.register_ai_operator(addr(30), 3_000, 0).unwrap();
        reg.register_content_validator(addr(30), 2_000, 0).unwrap();
        assert!(reg.is_active_attester(&addr(30)));
        assert!(reg.is_active_ai_operator(&addr(30)));
        assert!(reg.is_active_content_validator(&addr(30)));
    }

    #[test]
    fn d4_cross_role_slash_jails_attester_and_content_validator() {
        let mut reg = PermissionlessRegistry::new();
        reg.register_validator(addr(77), 10_000, 0).unwrap();
        reg.register_attester(addr(77), MIN_REGISTRATION_STAKE, 0)
            .unwrap();
        reg.register_content_validator(addr(77), 2_000, 0).unwrap();

        reg.slash(
            addr(77),
            roles::VALIDATOR,
            SlashingCondition::DoubleSign,
            FIXED_POINT_SCALE / 2,
        )
        .unwrap();

        assert!(!reg.is_active_attester(&addr(77)));
        assert!(!reg.is_active_content_validator(&addr(77)));
    }

    // ---: permissionless relayer bond + malicious-relayer slash ---

    #[test]
    fn d1_permissionless_relayer_bond_then_griefing_slash_jails() {
        let mut reg = PermissionlessRegistry::new();
        let relayer = addr(123);

        // Permissionless entry: anyone may bond the min stake and become an
        // Active relayer - no whitelist, no admin gate (see README, "Permissionless").
        reg.register_relayer(relayer, MIN_REGISTRATION_STAKE, 0)
            .unwrap();
        assert!(reg.is_active_relayer(&relayer));
        assert!(reg.ensure_active_relayer(&relayer).is_ok());

        // A griefing offence (slashing variant) slashes the relayer
        // 100% and jails it - it can no longer relay.
        reg.slash(
            relayer,
            roles::RELAYER,
            SlashingCondition::MaliciousBehaviour,
            FIXED_POINT_SCALE,
        )
        .unwrap();
        assert!(!reg.is_active_relayer(&relayer));
        assert!(reg.ensure_active_relayer(&relayer).is_err());
    }

    #[test]
    fn d1_malicious_relayer_griefing_report_is_well_formed() {
        // The griefing report is structurally valid, malicious (100% slash),
        // And can drive a registry slash of the RELAYER role.
        let report = crate::registry::evidence::SlashingReport::consensus_invalid_relay_griefing(
            addr(7),
            "submitted resource-wasting proofs".into(),
            Some(addr(8)),
        );
        assert!(report.validate_shape().is_ok());
        assert_eq!(report.condition(), SlashingCondition::MaliciousBehaviour);
    }

    #[test]
    fn d1_malicious_relayer_invalid_proof_slash_from_report() {
        // A consensus-verified invalid-relay-proof report must
        // Drive a 100% (MaliciousBehaviour) slash of the RELAYER bond and jail
        // The relayer so it can no longer relay. This is the registry-level
        // Path that backs submit_relay_proof rejection (see relayer_e2e path).
        let mut reg = PermissionlessRegistry::new();
        let relayer = addr(123);
        let stake = 10_000u64;
        reg.register_relayer(relayer, stake, 0).unwrap();
        assert!(reg.is_active_relayer(&relayer));

        let report = crate::registry::evidence::SlashingReport::consensus_invalid_relay_proof(
            relayer,
            "tampered/invalid relay proof".into(),
            Some(addr(8)),
        );
        assert!(report.validate_shape().is_ok());
        assert_eq!(report.condition(), SlashingCondition::MaliciousBehaviour);

        let outcome = reg
            .slash_from_report(&report)
            .unwrap()
            .expect("slash applied");
        // 100% slash of the full bond.
        assert_eq!(outcome.penalty, stake);
        assert_eq!(outcome.remaining_stake, 0);

        // Relayer is jailed and can no longer relay.
        assert!(!reg.is_active(&relayer, roles::RELAYER));
        assert!(!reg.is_active_relayer(&relayer));
        assert!(reg.ensure_active_relayer(&relayer).is_err());
    }

    /// A slash that the registry refuses must not look like a slash that
    /// correctly found nothing to do.
    ///
    /// `slash_from_report` used to map every `Err` to `Ok(None)`. Consensus
    /// calls this and moves on, so a report that was accepted as actionable
    /// and then dropped by the registry was indistinguishable from a report
    /// naming an account that never held the role. All four call sites also
    /// use `let _ =`, so neither layer would have noticed.
    ///
    /// It still returns `Ok(None)` - a failed slash must not abort block
    /// application, or one bad report would halt the chain, but the refusal
    /// is logged now. This test pins the two cases apart at the source level,
    /// since a `tracing::warn!` is not observable from a unit test.
    #[test]
    fn a_refused_slash_is_logged_rather_than_silently_dropped() {
        let src = include_str!("permissionless.rs");
        let at = src
            .find("pub fn slash_from_report(")
            .expect("slash_from_report must still exist");
        let body = &src[at..(at + 2400).min(src.len())];

        assert!(
            body.contains("tracing::warn!"),
            "slash_from_report drops a refused slash without saying so"
        );
        assert!(
            !body.contains("Err(_) => Ok(None)"),
            "slash_from_report still collapses every error into a silent Ok(None)"
        );
        // The legitimate no-op must stay a quiet no-op: evidence naming an
        // account that never held the role is normal, not an incident.
        assert!(
            body.contains("Err(RegistryError::NotRegistered { .. }) => Ok(None)"),
            "an unregistered offender should remain a quiet no-op"
        );
    }

    /// The scan above must be able to fail.
    #[test]
    fn the_silent_slash_scan_can_detect_a_violation() {
        let planted = "match self.slash(a, b, c, d) {\n    Err(_) => Ok(None),\n}";
        assert!(
            planted.contains("Err(_) => Ok(None)"),
            "the pattern the scan looks for must match the shape it forbids"
        );
        assert!(
            !planted.contains("tracing::warn!"),
            "the planted violation must lack the log the real code has"
        );
    }

    /// The slashing history is capped, and the cap is deterministic.
    ///
    /// Consensus state - `root()` hashes every record, so a cap that depended
    /// on time, node age, or when a node joined would make two nodes that saw
    /// the same slashes compute different registry roots. Trimming from the
    /// front on insert depends only on the count.
    #[test]
    fn the_slashing_history_stops_growing_at_the_cap() {
        let mut registry = PermissionlessRegistry::new();
        for n in 0..(MAX_SLASHING_HISTORY as u64 + 500) {
            registry.record_slash(sample_record(n));
        }

        assert_eq!(
            registry.slashing_history().len(),
            MAX_SLASHING_HISTORY,
            "the history must stop at the cap"
        );
        let penalties: Vec<u64> = registry
            .slashing_history()
            .iter()
            .map(|r| r.penalty)
            .collect();
        assert_eq!(
            *penalties.first().expect("non-empty"),
            500,
            "the oldest surviving record should be the 501st inserted"
        );
        assert_eq!(
            *penalties.last().expect("non-empty"),
            MAX_SLASHING_HISTORY as u64 + 499,
            "the newest record must be kept"
        );
    }

    /// Two registries fed the same slashes must agree, cap or no cap.
    ///
    /// If trimming were non-deterministic the two roots would diverge and the
    /// nodes would fork.
    #[test]
    fn trimming_keeps_the_registry_root_deterministic() {
        let build = || {
            let mut registry = PermissionlessRegistry::new();
            for n in 0..(MAX_SLASHING_HISTORY as u64 + 37) {
                registry.record_slash(sample_record(n));
            }
            registry
        };
        assert_eq!(
            build().root(),
            build().root(),
            "two nodes applying the same slashes must reach the same registry root"
        );
    }

    /// Below the cap nothing is dropped.
    #[test]
    fn a_short_history_is_untouched() {
        let mut registry = PermissionlessRegistry::new();
        for n in 0..10u64 {
            registry.record_slash(sample_record(n));
        }
        assert_eq!(registry.slashing_history().len(), 10);
        assert_eq!(registry.slashing_history()[0].penalty, 0);
    }

    fn sample_record(n: u64) -> SlashingRecord {
        SlashingRecord {
            report: SlashingReport::consensus_double_sign(
                Address::from([u8::try_from(n % 251).unwrap_or(0); 32]),
                n,
                format!("{n:064x}"),
                format!("{:064x}", n + 1),
                vec![u8::try_from(n % 256).unwrap_or(0)],
                vec![u8::try_from((n + 1) % 256).unwrap_or(0)],
                None,
            ),
            penalty: n,
            remaining_stake: 0,
        }
    }

    /// The Kani harnesses in `kani/src/lib.rs` prove properties about a copy of
    /// this function's arithmetic, because `cargo kani` cannot build this crate
    /// (it ships rustc 1.93.0-nightly; `rust-version` here is 1.97.1) and
    /// because unrolling a populated `BTreeMap` of registrations is not what is
    /// under proof.
    ///
    /// A copy can drift. This test is the thing that stops it: it recomputes
    /// both expressions over the boundary values the proofs care about and
    /// fails if they ever disagree. If the registry's formula changes, update
    /// `penalty_for` in `kani/src/lib.rs` in the same commit - the proofs are
    /// about production only for as long as the two match.
    #[test]
    fn bond_arithmetic_matches_the_kani_mirror() {
        // Mirrors `kani/src/lib.rs::penalty_for`, kept literal on purpose.
        //
        // The previous version of this mirror was the pre-B35 expression,
        // `u64::try_from(...).expect(...)`, and this test compared it against
        // the registry's `as u64` over ratios in `[0, FIXED_POINT_SCALE]`.
        // Over that range the two agree, so the test passed for as long as the
        // bug existed. The ratios where they disagree are exactly the ones the
        // sweep below did not contain, which is why the range now runs past
        // the ceiling.
        fn kani_mirror(stake: u64, slash_ratio_fixed: u64) -> u64 {
            let quotient = (u128::from(stake) * u128::from(slash_ratio_fixed)) / 1_000_000u128;
            if quotient > u128::from(u64::MAX) {
                return stake;
            }
            let narrow = quotient as u64;
            if narrow > stake {
                stake
            } else {
                narrow
            }
        }

        assert_eq!(
            1_000_000u64, FIXED_POINT_SCALE,
            "the mirror hardcodes 1_000_000; FIXED_POINT_SCALE moved"
        );

        let stakes = [
            0u64,
            1,
            999,
            1_000,
            1_000_000,
            u64::MAX / 2,
            u64::MAX - 1,
            u64::MAX,
        ];
        // Ratios above the ceiling are included deliberately. `validate`
        // refuses them, so they are not reachable through governance today,
        // and that is the reason to test them here rather than the reason not
        // to: the clamp is what holds if a path ever reaches this function
        // without passing that guard, and an untested clamp is a comment.
        let ratios = [
            0u64,
            1,
            FIXED_POINT_SCALE / 100,
            FIXED_POINT_SCALE / 2,
            FIXED_POINT_SCALE - 1,
            FIXED_POINT_SCALE,
            FIXED_POINT_SCALE + 1,
            2 * FIXED_POINT_SCALE,
            u64::MAX,
        ];

        for stake in stakes {
            for ratio in ratios {
                let registry = slash_penalty(stake, ratio);
                assert_eq!(
                    registry,
                    kani_mirror(stake, ratio),
                    "registry and Kani mirror disagree at stake={stake}, ratio={ratio}"
                );
                // The property the proofs establish, checked here at the
                // boundaries so a divergence shows up as a failed invariant and
                // not only as a failed equality.
                assert!(
                    registry <= stake,
                    "penalty {registry} exceeds stake {stake} at ratio={ratio}"
                );
            }
        }

        // The specific input that used to wrap. Written out rather than left
        // to the sweep above, because this is the regression: the old
        // expression returned 18_446_744_073_708 here, against a stake of
        // 18_446_744_073_709_551_615. A 100.0001% slash took one part in a
        // million of the bond and left the rest.
        let wrapped = ((u128::from(u64::MAX) * u128::from(FIXED_POINT_SCALE + 1))
            / u128::from(FIXED_POINT_SCALE)) as u64;
        assert!(
            wrapped < u64::MAX,
            "this input no longer overflows a u64; if the widths changed, \
             the clamp below is being asserted against nothing"
        );
        assert_eq!(
            slash_penalty(u64::MAX, FIXED_POINT_SCALE + 1),
            u64::MAX,
            "a ratio one unit above the ceiling must take the whole bond, \
             not wrap to a fraction of it"
        );
    }
}
