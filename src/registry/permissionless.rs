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
    /// BLG-0092 (P04-F10): the role-bond door registers the verifier family
    /// and nothing else; any other RoleId is refused by name.
    UnsupportedRole {
        role: RoleId,
    },
    /// Adding the amount would overflow the recorded stake.
    StakeOverflow {
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
            RegistryError::UnsupportedRole { role } => {
                write!(f, "role {role} has no bond registration path")
            }
            RegistryError::RelayerNotActive { account } => write!(
                f,
                "{account} is not an active relayer (register with stake first)"
            ),
            RegistryError::AlreadySlashed { account, role } => {
                write!(f, "{account} is already slashed as {role}")
            }
            RegistryError::StakeOverflow { account, role } => {
                write!(f, "stake of {account} as {role} would overflow")
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

/// Maximum active delegation positions and pending exits retained in live state.
/// WIRING: registry surface - the delegation door that reads it lands with its wiring wave.
pub const MAX_DELEGATIONS: usize = 100_000;
// The unbonding period, the commission cap and the per-epoch commission
// change limit are economic values (K9): they live in `RegistryParams`
// (`delegation_unbonding_epochs`, `max_validator_commission_ppm`,
// `max_commission_change_ppm_per_epoch`), not here.

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationPosition {
    pub delegator: Address,
    pub validator: Address,
    pub amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationUnbonding {
    pub delegator: Address,
    pub validator: Address,
    pub amount: u64,
    pub release_epoch: u64,
}

/// A delegator reward the epoch close credited to the delegator but that has
/// not been claimed yet. Consensus state: the entry moves value that already
/// left the reward pool, so every node has to agree on it exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// WIRING: registry surface - the delegation door that reads it lands with its wiring wave.
pub struct ClaimableReward {
    pub delegator: Address,
    pub validator: Address,
    pub amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorCommission {
    pub validator: Address,
    pub commission_ppm: u32,
    pub last_change_epoch: u64,
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
    #[serde(default)]
    charged_offences: BTreeMap<String, std::collections::BTreeSet<(u8, u64, u64)>>,
    /// Active validator delegation positions. These are consensus state and
    /// therefore participate in the registry root and snapshot serde.
    #[serde(default)]
    delegations: Vec<DelegationPosition>,
    /// Delegations that left voting stake but remain locked until release.
    #[serde(default)]
    delegation_unbonding: Vec<DelegationUnbonding>,
    /// Validator reward commission schedule, also consensus state.
    #[serde(default)]
    validator_commissions: Vec<ValidatorCommission>,
    /// Delegator rewards earned but not claimed yet. Consensus state: the
    /// whole vector is hashed into the delegation root.
    #[serde(default)]
    claimable_rewards: Vec<ClaimableReward>,
}

fn permissionless_member_key(role: RoleId, account: Address) -> String {
    format!(
        "{}:{}",
        hex::encode(role.as_bytes()),
        hex::encode(account.as_bytes())
    )
}

fn permissionless_offence_window(
    proof: &crate::registry::evidence::SlashingProof,
) -> Option<(u8, u64, u64)> {
    use crate::registry::evidence::SlashingProof;
    match proof {
        SlashingProof::Liveness {
            window_start_epoch,
            window_end_epoch,
            ..
        } => Some((1, *window_start_epoch, *window_end_epoch)),
        SlashingProof::DoubleSign { height, .. } => Some((2, *height, *height)),
        SlashingProof::InvalidSignatureSpam { epoch, .. } => Some((3, *epoch, *epoch)),
        SlashingProof::Other { .. } => None,
    }
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
            charged_offences: BTreeMap::new(),
            delegations: Vec::new(),
            delegation_unbonding: Vec::new(),
            validator_commissions: Vec::new(),
            claimable_rewards: Vec::new(),
        }
    }

    pub fn with_params(params: RegistryParams) -> Self {
        Self {
            registrations: BTreeMap::new(),
            params,
            slashing_history: Vec::new(),
            charged_offences: BTreeMap::new(),
            delegations: Vec::new(),
            delegation_unbonding: Vec::new(),
            validator_commissions: Vec::new(),
            claimable_rewards: Vec::new(),
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
        let unbonding_epochs = self.params.unbonding_epochs;
        match self.registrations.get_mut(&key) {
            Some(reg) => {
                if matches!(reg.status, MemberStatus::Slashed) {
                    // A slashed entry may only shrink. Writing the caller's
                    // uncut total back would undo the slash on the next
                    // Stake or Unstake of the mirrored validator bond.
                    reg.stake = reg.stake.min(total_stake);
                    return;
                }
                if total_stake == 0 {
                    // A full exit keeps the entry under the unbonding lock so a
                    // later report can still cut it. Removing it would free the
                    // stake at once.
                    if matches!(reg.status, MemberStatus::Active) {
                        reg.status = MemberStatus::Unbonding {
                            release_epoch: current_epoch.saturating_add(unbonding_epochs),
                        };
                    }
                } else {
                    reg.stake = total_stake;
                    if matches!(reg.status, MemberStatus::Unbonding { .. }) {
                        reg.status = MemberStatus::Active;
                    }
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
        if !matches!(reg.status, MemberStatus::Active) {
            return Err(RegistryError::NotActive { account, role });
        }
        reg.stake = reg
            .stake
            .checked_add(amount)
            .ok_or(RegistryError::StakeOverflow { account, role })?;
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
        // BLG-0087 (P04-F05, decision A): a Slashed member may exit. The
        // alternative - only Active can unbond, only Unbonding can withdraw,
        // and re-register says AlreadyRegistered - left the remaining bond
        // locked for good. Unbonding is not an escape from a later slash: the
        // unbonding queue is cut on any further report (BLG-0085).
        if !matches!(reg.status, MemberStatus::Active | MemberStatus::Slashed) {
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
        // BLG-0087 (P04-F05, decision B): a liveness fault is a timed jail,
        // not a permanent slash. The stake is cut, but the status stays
        // Active so the jail expiry at the validators map can actually
        // release the validator - `MemberStatus::Slashed` had no exit
        // (begin_unbonding needed Active, withdraw needed Unbonding).
        if condition != SlashingCondition::LivenessFault {
            reg.status = MemberStatus::Slashed;
        }

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
        condition: SlashingCondition,
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
                // BLG-0087 (decision B): the liveness cross-role sweep cuts
                // the stake but keeps the entries Active, as the primary
                // role does.
                if condition != SlashingCondition::LivenessFault {
                    reg.status = MemberStatus::Slashed;
                }
            }
        }
    }

    pub fn slash_from_report(
        &mut self,
        report: &SlashingReport,
    ) -> Result<Option<SlashOutcome>, EvidenceError> {
        report.is_actionable()?;
        let condition = report.condition();
        // BLG-0087 (P04-F05, decision B): a liveness fault no longer lands in
        // `Slashed`, so the `AlreadySlashed` replay guard does not cover it.
        // The history is the ledger of what has already been applied: a
        // repeated liveness report is answered with a no-op instead of a
        // second stake cut.
        let window_key = permissionless_offence_window(&report.proof);
        let member_key = permissionless_member_key(report.role, report.offender);
        if let Some(wk) = window_key {
            if self
                .charged_offences
                .get(&member_key)
                .is_some_and(|set| set.contains(&wk))
            {
                return Ok(None);
            }
        }
        let in_history = self.slashing_history.iter().any(|r| {
            if r.report.offender != report.offender || r.report.role != report.role {
                return false;
            }
            match (window_key, permissionless_offence_window(&r.report.proof)) {
                (Some(a), Some(b)) => a == b,
                _ => r.report == *report,
            }
        });
        if in_history {
            return Ok(None);
        }
        let ratio = self.params.slash_ratio(condition);
        match self.slash(report.offender, report.role, condition, ratio) {
            Ok(outcome) => {
                if let Some(wk) = window_key {
                    let set = self.charged_offences.entry(member_key).or_default();
                    set.insert(wk);
                    if set.len() > MAX_SLASHING_HISTORY {
                        if let Some(&oldest) = set.iter().next() {
                            set.remove(&oldest);
                        }
                    }
                }
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
        self.get(account, role).is_some_and(Registration::is_active)
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
            .fold(0u64, u64::saturating_add)
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
                total.saturating_add(u128::from(registration.stake))
            })
    }

    /// Index of `(validator, delegator)` in the active-position table.
    ///
    /// The table is kept sorted by that key, so a lookup is a binary search and
    /// every validator's positions sit in one contiguous slice. That is the
    /// difference between an O(every position) scan on every stake operation -
    /// which a flood of one-unit positions turns into permanent per-block work
    /// for every node - and O(log n) plus the positions of the single validator
    /// involved.
    fn delegation_slot(&self, delegator: Address, validator: Address) -> Result<usize, usize> {
        self.delegations.binary_search_by(|position| {
            (position.validator, position.delegator).cmp(&(validator, delegator))
        })
    }

    /// The contiguous slice of the sorted table that belongs to `validator`.
    fn delegation_span(&self, validator: &Address) -> std::ops::Range<usize> {
        let start = self
            .delegations
            .partition_point(|position| position.validator < *validator);
        let end = self
            .delegations
            .partition_point(|position| position.validator <= *validator);
        start..end
    }

    /// Index of `(validator, delegator)` in the claimable-reward table, kept
    /// sorted by the same key as the positions.
    fn claimable_slot(&self, delegator: Address, validator: Address) -> Result<usize, usize> {
        self.claimable_rewards.binary_search_by(|reward| {
            (reward.validator, reward.delegator).cmp(&(validator, delegator))
        })
    }

    /// Restore the order both delegation tables are indexed by.
    ///
    /// Every mutation below inserts at the key's position, so the tables are
    /// sorted for as long as they are only touched through this type. A
    /// snapshot is the one way a table can arrive in another order, written by
    /// a build that appended in arrival order, so a restored registry is sorted
    /// once - before it is hashed or queried - and every node agrees on the
    /// same table for the same rows.
    pub fn reindex_delegations(&mut self) {
        self.delegations
            .sort_by_key(|position| (position.validator, position.delegator));
        self.claimable_rewards
            .sort_by_key(|reward| (reward.validator, reward.delegator));
    }

    /// Add an active delegation position. The account layer performs the
    /// validator and liquid-balance checks; this method owns the canonical
    /// position mutation and its bounded-state checks.
    ///
    /// A *new* position has to clear `min_delegation_amount`: the delegation
    /// fee is flat, so without a floor any funded account can add positions a
    /// base unit at a time, recover the principal by undelegating, and leave
    /// every node paying the enlarged per-block and per-epoch work for the life
    /// of the chain. One validator also carries at most
    /// `max_delegations_per_validator` positions, which is what bounds the
    /// slice its own stake operations walk.
    pub fn delegate(
        &mut self,
        delegator: Address,
        validator: Address,
        amount: u64,
    ) -> Result<(), String> {
        if amount == 0 {
            return Err("delegation amount must be non-zero".into());
        }
        if delegator == validator {
            return Err("a validator cannot delegate to itself".into());
        }
        match self.delegation_slot(delegator, validator) {
            // An existing position is grown by any non-zero amount: it already
            // cleared the floor when it was created.
            Ok(index) => {
                self.delegations[index].amount = self.delegations[index]
                    .amount
                    .checked_add(amount)
                    .ok_or_else(|| "delegation amount overflow".to_string())?;
                Ok(())
            }
            Err(index) => {
                self.admit_new_delegation_position(validator, amount)?;
                self.delegations.insert(
                    index,
                    DelegationPosition {
                        delegator,
                        validator,
                        amount,
                    },
                );
                Ok(())
            }
        }
    }

    /// The entry-side bounds on a new delegation position.
    fn admit_new_delegation_position(&self, validator: Address, amount: u64) -> Result<(), String> {
        let floor = self.params.min_delegation_amount;
        if amount < floor {
            return Err(format!(
                "delegation amount must be at least {floor} base units"
            ));
        }
        if self.delegations.len() >= MAX_DELEGATIONS {
            return Err("delegation position limit reached".into());
        }
        let cap = self.params.max_delegations_per_validator;
        if (self.delegation_span(&validator).len() as u64) >= cap {
            return Err(format!(
                "this validator already holds the maximum of {cap} delegation positions"
            ));
        }
        Ok(())
    }

    /// Move an active delegation position from one validator to another
    /// without an unbonding round trip. Voting weight follows the position, so
    /// the caller adjusts both validators' aggregate stake after this returns.
    ///
    /// The source position must already exist and cover the amount; the
    /// destination either grows an existing position or takes a new one, under
    /// the same [`MAX_DELEGATIONS`] ceiling and the same entry-side bounds as
    /// [`Self::delegate`].
    pub fn move_delegation(
        &mut self,
        delegator: Address,
        from: Address,
        to: Address,
        amount: u64,
    ) -> Result<(), String> {
        if amount == 0 {
            return Err("redelegation amount must be non-zero".into());
        }
        if from == to {
            return Err("redelegation needs two different validators".into());
        }
        if delegator == to {
            return Err("a validator cannot delegate to itself".into());
        }
        let source = self
            .delegation_slot(delegator, from)
            .map_err(|_| "no active delegation to redelegate from".to_string())?;
        if self.delegations[source].amount < amount {
            return Err("redelegation exceeds the active position".into());
        }
        match self.delegation_slot(delegator, to) {
            Ok(index) => {
                self.delegations[index].amount = self.delegations[index]
                    .amount
                    .checked_add(amount)
                    .ok_or_else(|| "delegation amount overflow".to_string())?;
            }
            Err(index) => {
                self.admit_new_delegation_position(to, amount)?;
                self.delegations.insert(
                    index,
                    DelegationPosition {
                        delegator,
                        validator: to,
                        amount,
                    },
                );
            }
        }
        // The insert above may have moved the source, so the slot is read
        // again rather than reused: a stale index would debit another
        // delegator's position.
        let source = self
            .delegation_slot(delegator, from)
            .map_err(|_| "no active delegation to redelegate from".to_string())?;
        self.delegations[source].amount -= amount;
        if self.delegations[source].amount == 0 {
            // The emptied position leaves the table: a zero row is never
            // created, so it must never be left behind either.
            self.delegations.remove(source);
        }
        Ok(())
    }

    /// Credit a delegator reward that the epoch close has already taken out of
    /// the reward pool. The value sits here until [`Self::claim_delegator_rewards`]
    /// moves it to the delegator's liquid balance, so a delegator who never
    /// claims cannot be paid twice and a node that restarts sees the same debt.
    ///
    /// The table is sorted by `(validator, delegator)` and addressed by binary
    /// search, so the epoch close - which credits one debt per position it
    /// walked - no longer pays a scan of the whole table for each of them.
    pub fn credit_claimable_reward(
        &mut self,
        delegator: Address,
        validator: Address,
        amount: u64,
    ) -> Result<(), String> {
        if amount == 0 {
            return Ok(());
        }
        match self.claimable_slot(delegator, validator) {
            Ok(index) => {
                self.claimable_rewards[index].amount = self.claimable_rewards[index]
                    .amount
                    .checked_add(amount)
                    .ok_or_else(|| "claimable reward overflow".to_string())?;
                Ok(())
            }
            Err(index) => {
                if self.claimable_rewards.len() >= MAX_DELEGATIONS {
                    return Err("claimable reward limit reached".into());
                }
                self.claimable_rewards.insert(
                    index,
                    ClaimableReward {
                        delegator,
                        validator,
                        amount,
                    },
                );
                Ok(())
            }
        }
    }

    /// Credit many delegator rewards for one validator in a single pass.
    ///
    /// The epoch close credits one debt per position it walked, and doing that
    /// through [`Self::credit_claimable_reward`] pays a table insert per
    /// position. `credits` arrives in delegator order - it is produced from
    /// [`Self::delegations_for`], which is sorted - and the claimable table is
    /// sorted by `(validator, delegator)`, so the whole block is one merge
    /// instead of one insert per row.
    ///
    /// Rows already held for this validator keep their amounts and are added
    /// to; a pair that appears twice in `credits` is merged as well. All or
    /// nothing: an amount that would overflow leaves the table unchanged, which
    /// is the same choice the single-credit door makes.
    pub fn credit_claimable_rewards(
        &mut self,
        validator: Address,
        credits: &[(Address, u64)],
    ) -> Result<u64, String> {
        if credits.is_empty() {
            return Ok(0);
        }
        let start = self
            .claimable_rewards
            .partition_point(|reward| reward.validator < validator);
        let end = self
            .claimable_rewards
            .partition_point(|reward| reward.validator <= validator);
        let span = start..end;
        let existing = &self.claimable_rewards[span.clone()];
        let rows_outside_the_block = self.claimable_rewards.len() - existing.len();
        let mut merged: Vec<ClaimableReward> = Vec::with_capacity(existing.len() + credits.len());
        let mut credit_total = 0u64;
        let mut left = existing.iter().peekable();
        let mut right = credits.iter().peekable();
        while left.peek().is_some() || right.peek().is_some() {
            let take_existing = match (left.peek(), right.peek()) {
                (Some(existing), Some((delegator, _))) => existing.delegator <= *delegator,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => false,
            };
            // `peek` is only ever read to decide, so neither arm has to
            // unwrap: the loop condition above already proved that the side it
            // takes from holds an element, and a `None` there is a broken
            // invariant, handled by ending the merge rather than panicking.
            if take_existing {
                let Some(row) = left.next() else { break };
                // A credit for the same delegator lands on this row.
                let mut amount = row.amount;
                if let Some((delegator, extra)) = right.peek().map(|pair| **pair) {
                    if delegator == row.delegator {
                        let _ = right.next();
                        amount = amount
                            .checked_add(extra)
                            .ok_or_else(|| "claimable reward overflow".to_string())?;
                        credit_total = credit_total.saturating_add(extra);
                    }
                }
                merged.push(ClaimableReward {
                    delegator: row.delegator,
                    validator,
                    amount,
                });
            } else {
                let Some((delegator, amount)) = right.next().copied() else {
                    break;
                };
                if amount == 0 {
                    continue;
                }
                // Two credits for one new delegator are merged, not duplicated:
                // a second row for the same key would break the ordering the
                // lookups rely on.
                let mut amount = amount;
                while let Some((next_delegator, extra)) = right.peek().map(|pair| **pair) {
                    if next_delegator != delegator {
                        break;
                    }
                    let _ = right.next();
                    amount = amount
                        .checked_add(extra)
                        .ok_or_else(|| "claimable reward overflow".to_string())?;
                }
                credit_total = credit_total.saturating_add(amount);
                merged.push(ClaimableReward {
                    delegator,
                    validator,
                    amount,
                });
            }
        }
        if rows_outside_the_block + merged.len() > MAX_DELEGATIONS {
            return Err("claimable reward limit reached".into());
        }
        self.claimable_rewards.splice(span, merged);
        Ok(credit_total)
    }

    /// What `delegator` has earned on `validator` and not claimed yet.
    #[must_use]
    pub fn claimable_reward(&self, delegator: Address, validator: Address) -> u64 {
        self.claimable_slot(delegator, validator)
            .map_or(0, |index| self.claimable_rewards[index].amount)
    }

    /// Take the claimable reward of one `(delegator, validator)` pair. The
    /// entry is removed before the caller credits anything, so a claim can
    /// never pay twice.
    pub fn claim_delegator_rewards(
        &mut self,
        delegator: Address,
        validator: Address,
    ) -> Result<u64, String> {
        let index = self
            .claimable_slot(delegator, validator)
            .map_err(|_| "no claimable reward for this delegator and validator".to_string())?;
        // Decide before the remove: a zero reward refuses with its row still
        // in place, so a failed claim cannot drop what it refused to pay.
        if self.claimable_rewards[index].amount == 0 {
            return Err("the claimable reward is zero".into());
        }
        Ok(self.claimable_rewards.remove(index).amount)
    }

    pub fn delegated_amount(&self, delegator: Address, validator: Address) -> u64 {
        self.delegation_slot(delegator, validator)
            .map_or(0, |index| self.delegations[index].amount)
    }

    /// Everything one validator's delegators have bonded. The positions are one
    /// contiguous slice of the sorted table, so the sum is over that
    /// validator's rows only - bounded by `max_delegations_per_validator`, not
    /// by the size of the whole table.
    pub fn delegated_stake(&self, validator: &Address) -> u64 {
        let span = self.delegation_span(validator);
        self.delegations[span].iter().fold(0u64, |total, position| {
            total.saturating_add(position.amount)
        })
    }

    /// One validator's positions, in delegator order, without touching any
    /// other validator's rows.
    pub fn delegations_for(&self, validator: &Address) -> Vec<DelegationPosition> {
        let span = self.delegation_span(validator);
        self.delegations[span].to_vec()
    }

    /// Move an active position into the canonical unbonding queue. The
    /// validator's consensus stake is adjusted by the account layer only
    /// after this operation succeeds.
    pub fn begin_delegation_unbonding(
        &mut self,
        delegator: Address,
        validator: Address,
        amount: u64,
        current_epoch: u64,
    ) -> Result<(), String> {
        if amount == 0 {
            return Err("delegation unbond amount must be non-zero".into());
        }
        let position_index = self
            .delegation_slot(delegator, validator)
            .map_err(|_| "delegation position not found".to_string())?;
        let available = self.delegations[position_index].amount;
        if available < amount {
            return Err(format!(
                "delegation unbond exceeds position: requested {amount}, available {available}"
            ));
        }
        let release_epoch = current_epoch.saturating_add(self.params.delegation_unbonding_epochs);
        let has_release_entry = self.delegation_unbonding.iter().any(|entry| {
            entry.delegator == delegator
                && entry.validator == validator
                && entry.release_epoch == release_epoch
        });
        if !has_release_entry && self.delegation_unbonding.len() >= MAX_DELEGATIONS {
            return Err("delegation unbonding limit reached".into());
        }
        let release_index = self.delegation_unbonding.iter().position(|entry| {
            entry.delegator == delegator
                && entry.validator == validator
                && entry.release_epoch == release_epoch
        });
        if let Some(index) = release_index {
            self.delegation_unbonding[index].amount = self.delegation_unbonding[index]
                .amount
                .checked_add(amount)
                .ok_or_else(|| "delegation unbonding overflow".to_string())?;
        } else {
            self.delegation_unbonding.push(DelegationUnbonding {
                delegator,
                validator,
                amount,
                release_epoch,
            });
        }
        self.delegations[position_index].amount -= amount;
        if self.delegations[position_index].amount == 0 {
            self.delegations.remove(position_index);
        }
        Ok(())
    }

    pub fn withdrawable_delegation(
        &self,
        delegator: Address,
        validator: Address,
        current_epoch: u64,
    ) -> u64 {
        self.delegation_unbonding
            .iter()
            .filter(|entry| {
                entry.delegator == delegator
                    && entry.validator == validator
                    && entry.release_epoch <= current_epoch
            })
            .fold(0u64, |total, entry| total.saturating_add(entry.amount))
    }

    pub fn withdraw_delegation(
        &mut self,
        delegator: Address,
        validator: Address,
        current_epoch: u64,
    ) -> Result<u64, String> {
        let mut withdrawn = 0u64;
        for entry in self.delegation_unbonding.iter().filter(|entry| {
            entry.delegator == delegator
                && entry.validator == validator
                && entry.release_epoch <= current_epoch
        }) {
            withdrawn = withdrawn
                .checked_add(entry.amount)
                .ok_or_else(|| "delegation withdrawal overflow".to_string())?;
        }
        if withdrawn == 0 {
            return Err("delegation is still unbonding or does not exist".into());
        }
        self.delegation_unbonding.retain(|entry| {
            !(entry.delegator == delegator
                && entry.validator == validator
                && entry.release_epoch <= current_epoch)
        });
        Ok(withdrawn)
    }

    pub fn total_delegation_unbonding_supply(&self) -> u128 {
        self.delegation_unbonding
            .iter()
            .fold(0u128, |total, entry| {
                total.saturating_add(u128::from(entry.amount))
            })
    }

    pub fn delegation_count(&self) -> usize {
        self.delegations.len()
    }

    pub fn delegation_unbonding_count(&self) -> usize {
        self.delegation_unbonding.len()
    }

    pub fn delegation_unbonding_for(&self, validator: &Address) -> Vec<DelegationUnbonding> {
        self.delegation_unbonding
            .iter()
            .filter(|entry| entry.validator == *validator)
            .cloned()
            .collect()
    }

    pub fn validator_commission_count(&self) -> usize {
        self.validator_commissions.len()
    }

    #[must_use]
    pub fn slashing_history_count(&self) -> usize {
        self.slashing_history.len()
    }

    /// The commission row of `validator`, if it ever set one.
    pub fn validator_commission(&self, validator: &Address) -> Option<&ValidatorCommission> {
        self.validator_commissions
            .iter()
            .find(|commission| commission.validator == *validator)
    }

    pub fn validator_commission_ppm(&self, validator: &Address) -> u32 {
        self.validator_commissions
            .iter()
            .find(|commission| commission.validator == *validator)
            .map_or(0, |commission| commission.commission_ppm)
    }

    pub fn set_validator_commission(
        &mut self,
        validator: Address,
        commission_ppm: u32,
        current_epoch: u64,
    ) -> Result<(), String> {
        let max_commission = self.params.max_validator_commission_ppm;
        let max_change = self.params.max_commission_change_ppm_per_epoch;
        if u64::from(commission_ppm) > max_commission {
            return Err(format!(
                "commission exceeds maximum of {max_commission} ppm"
            ));
        }
        if let Some(existing) = self
            .validator_commissions
            .iter_mut()
            .find(|existing| existing.validator == validator)
        {
            if existing.last_change_epoch == current_epoch {
                return Err("commission can change only once per epoch".into());
            }
            let change = existing.commission_ppm.abs_diff(commission_ppm);
            if u64::from(change) > max_change {
                return Err(format!(
                    "commission change exceeds {max_change} ppm per epoch"
                ));
            }
            existing.commission_ppm = commission_ppm;
            existing.last_change_epoch = current_epoch;
        } else {
            self.validator_commissions.push(ValidatorCommission {
                validator,
                commission_ppm,
                last_change_epoch: current_epoch,
            });
        }
        Ok(())
    }

    /// Burn active delegated stake proportionally to a validator slash. The
    /// caller has already reduced the validator's aggregate bond by
    /// `penalty`; this cuts the positions by the delegated part of it,
    /// `penalty * delegated / stake_before`, split by amount, so the
    /// positions and the aggregate stake stay in the same state.
    ///
    /// Every position is cut by its own proportional share; the rounding
    /// remainder of the delegated part goes to the positions in order, one
    /// unit each, never more than a position holds. An earlier version gave
    /// the last position everything the others did not take, up to the
    /// whole penalty, so one delegator paid the validator's own share.
    pub fn reduce_delegated_for_slash(
        &mut self,
        validator: &Address,
        penalty: u64,
        stake_before: u64,
    ) {
        let delegated = self.delegated_stake(validator);
        if penalty == 0 || delegated == 0 || stake_before == 0 {
            return;
        }
        let scale = |amount: u64| -> u64 {
            u64::try_from(u128::from(penalty) * u128::from(amount) / u128::from(stake_before))
                .unwrap_or(u64::MAX)
                .min(amount)
        };
        let target = scale(delegated);
        let span = self.delegation_span(validator);
        let mut cut_total = 0u64;
        for position in &mut self.delegations[span.clone()] {
            let cut = scale(position.amount);
            position.amount -= cut;
            cut_total = cut_total.saturating_add(cut);
        }
        // The per-position floors can fall short of the delegated share by
        // at most one unit per position.
        for position in &mut self.delegations[span.clone()] {
            if cut_total >= target {
                break;
            }
            if position.amount > 0 {
                position.amount -= 1;
                cut_total += 1;
            }
        }
        // A position slashed to nothing leaves the table, highest index first
        // so the removals cannot shift one another.
        for index in span.rev() {
            if self.delegations[index].amount == 0 {
                self.delegations.remove(index);
            }
        }
    }

    /// Pending delegation exits remain slashable until they are withdrawn.
    pub fn slash_delegation_unbonding(
        &mut self,
        validator: &Address,
        slash_ratio_fixed: u64,
    ) -> u64 {
        let mut cut_total = 0u64;
        for entry in self
            .delegation_unbonding
            .iter_mut()
            .filter(|entry| entry.validator == *validator)
        {
            let cut = crate::core::chain_config::slash_penalty(entry.amount, slash_ratio_fixed);
            entry.amount = entry.amount.saturating_sub(cut);
            cut_total = cut_total.saturating_add(cut);
        }
        self.delegation_unbonding.retain(|entry| entry.amount > 0);
        cut_total
    }

    /// The delegation state on its own (the global header carries it, V7):
    /// positions, exits and commissions. `None` when there is none, so an
    /// empty delegation state claims no root.
    #[must_use]
    pub fn delegation_root(&self) -> Option<[u8; 32]> {
        if self.delegations.is_empty()
            && self.delegation_unbonding.is_empty()
            && self.validator_commissions.is_empty()
            && self.claimable_rewards.is_empty()
        {
            return None;
        }
        Some(crate::core::hash::hash_fields_bytes(&[
            b"BDLM_DELEGATION_ROOT_V1",
            &bincode::serialize(&self.delegations)
                .unwrap_or_else(|_| REGISTRY_SERIALIZE_FAILED.to_vec()),
            &bincode::serialize(&self.delegation_unbonding)
                .unwrap_or_else(|_| REGISTRY_SERIALIZE_FAILED.to_vec()),
            &bincode::serialize(&self.validator_commissions)
                .unwrap_or_else(|_| REGISTRY_SERIALIZE_FAILED.to_vec()),
            &bincode::serialize(&self.claimable_rewards)
                .unwrap_or_else(|_| REGISTRY_SERIALIZE_FAILED.to_vec()),
        ]))
    }

    pub fn len(&self) -> usize {
        self.registrations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.registrations.is_empty()
            && self.delegations.is_empty()
            && self.delegation_unbonding.is_empty()
            && self.validator_commissions.is_empty()
            && self.claimable_rewards.is_empty()
    }

    pub fn has_non_default_state(&self) -> bool {
        !self.is_empty()
            || !self.slashing_history.is_empty()
            || !self.charged_offences.is_empty()
            || self.params != RegistryParams::default()
    }

    /// Framed, versioned consensus commitment. Each section has a distinct
    /// tag and an explicit count; each encoded record has a length prefix.
    /// V1 concatenated records from different sections without boundaries, so
    /// e.g. a delegation and a claimable reward with identical fields collided.
    /// V2 changes nonempty registry state roots and requires a coordinated chain
    /// upgrade (or a fresh testnet genesis) rather than mixed-version replay.
    pub fn root(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        fn field(hasher: &mut Sha256, bytes: &[u8]) {
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        }

        let mut hasher = Sha256::new();
        field(&mut hasher, b"BDLM_PERMISSIONLESS_REGISTRY_V2");
        field(&mut hasher, b"params");
        field(
            &mut hasher,
            &bincode::serialize(&self.params)
                .unwrap_or_else(|_| REGISTRY_SERIALIZE_FAILED.to_vec()),
        );
        macro_rules! section {
            ($name:expr, $records:expr) => {{
                let records = $records;
                field(&mut hasher, $name);
                hasher.update((records.len() as u64).to_le_bytes());
                for record in records {
                    let bytes = bincode::serialize(&record)
                        .unwrap_or_else(|_| REGISTRY_SERIALIZE_FAILED.to_vec());
                    field(&mut hasher, &bytes);
                }
            }};
        }
        section!(b"registrations", self.registrations.values());
        section!(b"slashing_history", self.slashing_history.iter());
        section!(b"delegations", self.delegations.iter());
        section!(b"delegation_unbonding", self.delegation_unbonding.iter());
        section!(b"validator_commissions", self.validator_commissions.iter());
        section!(b"claimable_rewards", self.claimable_rewards.iter());
        section!(b"charged_offences", self.charged_offences.iter());
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
    fn registry_root_distinguishes_identical_records_in_different_sections() {
        let mut base = PermissionlessRegistry::new();
        base.register_validator(addr(1), MIN_REGISTRATION_STAKE, 0)
            .unwrap();
        let mut stake = base.clone();
        stake.delegate(addr(9), addr(1), 100).unwrap();
        let mut reward = base;
        reward
            .credit_claimable_reward(addr(9), addr(1), 100)
            .unwrap();

        // The old V1 transcript was identical: same params and registrations,
        // followed by these indistinguishable raw record bytes.
        assert_eq!(
            bincode::serialize(&stake.delegations[0]).unwrap(),
            bincode::serialize(&reward.claimable_rewards[0]).unwrap()
        );
        assert_ne!(stake.root(), reward.root());
        assert_eq!(stake.root(), stake.clone().root());
        let decoded: PermissionlessRegistry =
            bincode::deserialize(&bincode::serialize(&stake).unwrap()).unwrap();
        assert_eq!(stake.root(), decoded.root());
    }

    #[test]
    fn a_delegation_moves_between_validators_in_one_step() {
        let mut reg = PermissionlessRegistry::new();
        reg.register_validator(addr(1), MIN_REGISTRATION_STAKE, 0)
            .unwrap();
        reg.register_validator(addr(2), MIN_REGISTRATION_STAKE, 0)
            .unwrap();
        reg.delegate(addr(9), addr(1), 250).unwrap();

        // A new destination position has to clear the same floor a fresh
        // delegation does: redelegating must not be a way to create the dust
        // positions the floor exists to prevent.
        let floor = reg.params().min_delegation_amount;
        assert!(reg
            .move_delegation(addr(9), addr(1), addr(2), floor - 1)
            .is_err());
        reg.move_delegation(addr(9), addr(1), addr(2), 100).unwrap();
        assert_eq!(reg.delegated_amount(addr(9), addr(1)), 150);
        assert_eq!(reg.delegated_amount(addr(9), addr(2)), 100);
        assert_eq!(reg.delegated_stake(&addr(1)), 150);
        assert_eq!(reg.delegated_stake(&addr(2)), 100);

        // moving the whole position retires the source row
        reg.move_delegation(addr(9), addr(1), addr(2), 150).unwrap();
        assert_eq!(reg.delegated_amount(addr(9), addr(1)), 0);
        assert_eq!(reg.delegated_amount(addr(9), addr(2)), 250);
        assert_eq!(reg.delegations_for(&addr(1)).len(), 0);
    }

    /// The delegation table is addressed by binary search, so it has to stay
    /// sorted by `(validator, delegator)` whatever order rows arrive in - and
    /// every lookup has to answer for a row that is not first in the table.
    ///
    /// The order is consensus: `root()` hashes the table as it stands, so two
    /// nodes that received the same positions in different order must still
    /// produce the same root.
    #[test]
    fn the_delegation_table_is_sorted_and_answers_from_any_position() {
        let mut forward = PermissionlessRegistry::new();
        let mut backward = PermissionlessRegistry::new();
        let validators = [addr(3), addr(1), addr(2)];
        let delegators = [addr(9), addr(7), addr(8)];
        for validator in validators {
            for delegator in delegators {
                forward.delegate(delegator, validator, 100).unwrap();
            }
        }
        for validator in validators.iter().rev() {
            for delegator in delegators.iter().rev() {
                backward.delegate(*delegator, *validator, 100).unwrap();
            }
        }
        assert_eq!(
            forward.delegations, backward.delegations,
            "arrival order must not decide the table"
        );
        assert_eq!(forward.root(), backward.root());
        assert!(
            forward
                .delegations
                .windows(2)
                .all(|pair| (pair[0].validator, pair[0].delegator)
                    < (pair[1].validator, pair[1].delegator)),
            "the table is sorted by (validator, delegator)"
        );

        // Every row answers its own lookup, including the last one in the
        // table and the only row of a validator at the end.
        for validator in validators {
            assert_eq!(forward.delegated_stake(&validator), 300);
            assert_eq!(forward.delegations_for(&validator).len(), 3);
            for delegator in delegators {
                assert_eq!(forward.delegated_amount(delegator, validator), 100);
            }
        }
        assert_eq!(forward.delegated_stake(&addr(4)), 0);
        assert!(forward.delegations_for(&addr(4)).is_empty());
        assert_eq!(forward.delegated_amount(addr(6), addr(1)), 0);
    }

    /// One validator cannot be turned into an unbounded slice of the table.
    #[test]
    fn a_validator_cannot_carry_more_positions_than_its_cap() {
        let mut reg = PermissionlessRegistry::new();
        let validator = addr(1);
        let cap = 8u64;
        reg.set_params(RegistryParams {
            max_delegations_per_validator: cap,
            min_delegation_amount: 1,
            ..RegistryParams::default()
        });
        for index in 0..cap {
            let mut byte = [0u8; 32];
            byte[0] = u8::try_from(index).unwrap();
            reg.delegate(Address::from(byte), validator, 1).unwrap();
        }
        let err = reg
            .delegate(addr(200), validator, 1)
            .expect_err("the per-validator cap must refuse another position");
        assert!(err.contains("maximum of 8"), "got: {err}");
        // A position already held is still grown: the cap bounds rows, not
        // stake.
        reg.delegate(Address::from([0u8; 32]), validator, 1)
            .unwrap();
        assert_eq!(reg.delegations_for(&validator).len(), cap as usize);
    }

    /// A new position below the floor is refused, an existing one is not
    /// re-checked, and the floor is governance-settable rather than fixed.
    #[test]
    fn a_dust_position_cannot_be_created() {
        let mut reg = PermissionlessRegistry::new();
        let validator = addr(1);
        reg.set_params(RegistryParams {
            min_delegation_amount: 100,
            ..RegistryParams::default()
        });
        let err = reg
            .delegate(addr(9), validator, 99)
            .expect_err("a position below the floor must be refused");
        assert!(err.contains("at least 100"), "got: {err}");
        reg.delegate(addr(9), validator, 100).unwrap();
        reg.delegate(addr(9), validator, 1).unwrap();
        assert_eq!(reg.delegated_amount(addr(9), validator), 101);
    }

    /// The claimable table is sorted by `(validator, delegator)` too, and the
    /// epoch close credits a whole validator's delegators in one merge.
    #[test]
    fn the_epoch_close_credits_a_whole_validator_in_one_merge() {
        let mut reg = PermissionlessRegistry::new();
        let first = addr(1);
        let second = addr(2);
        // A reward already held for the second validator has to survive a
        // merge that touches only the first.
        reg.credit_claimable_reward(addr(5), second, 7).unwrap();
        reg.credit_claimable_reward(addr(4), first, 3).unwrap();
        let credited = reg
            .credit_claimable_rewards(first, &[(addr(2), 10), (addr(4), 5), (addr(8), 20)])
            .unwrap();
        assert_eq!(credited, 35);
        assert_eq!(reg.claimable_reward(addr(2), first), 10);
        assert_eq!(reg.claimable_reward(addr(4), first), 8);
        assert_eq!(reg.claimable_reward(addr(8), first), 20);
        assert_eq!(reg.claimable_reward(addr(5), second), 7);
        assert_eq!(reg.claimable_reward(addr(4), second), 0);
        assert!(
            reg.claimable_rewards
                .windows(2)
                .all(|pair| (pair[0].validator, pair[0].delegator)
                    < (pair[1].validator, pair[1].delegator)),
            "the claimable table is sorted by (validator, delegator)"
        );
        // Every row is still claimable exactly once.
        assert_eq!(reg.claim_delegator_rewards(addr(4), first).unwrap(), 8);
        assert!(reg.claim_delegator_rewards(addr(4), first).is_err());
        assert_eq!(reg.claimable_reward(addr(5), second), 7);
    }

    #[test]
    fn a_redelegation_refuses_more_than_the_position_and_the_same_validator() {
        let mut reg = PermissionlessRegistry::new();
        reg.register_validator(addr(1), MIN_REGISTRATION_STAKE, 0)
            .unwrap();
        reg.register_validator(addr(2), MIN_REGISTRATION_STAKE, 0)
            .unwrap();
        reg.delegate(addr(9), addr(1), 100).unwrap();
        assert!(reg.move_delegation(addr(9), addr(1), addr(2), 101).is_err());
        assert!(reg.move_delegation(addr(9), addr(1), addr(1), 10).is_err());
        assert!(reg.move_delegation(addr(9), addr(2), addr(1), 10).is_err());
        assert_eq!(reg.delegated_amount(addr(9), addr(1)), 100);
    }

    #[test]
    fn a_claimable_reward_is_claimed_once() {
        let mut reg = PermissionlessRegistry::new();
        reg.credit_claimable_reward(addr(9), addr(1), 70).unwrap();
        reg.credit_claimable_reward(addr(9), addr(1), 20).unwrap();
        assert_eq!(reg.claimable_reward(addr(9), addr(1)), 90);
        assert_eq!(reg.claim_delegator_rewards(addr(9), addr(1)).unwrap(), 90);
        assert_eq!(reg.claimable_reward(addr(9), addr(1)), 0);
        assert!(reg.claim_delegator_rewards(addr(9), addr(1)).is_err());
    }

    #[test]
    fn claimable_rewards_are_part_of_the_delegation_root() {
        let mut reg = PermissionlessRegistry::new();
        let empty = reg.delegation_root();
        reg.credit_claimable_reward(addr(9), addr(1), 5).unwrap();
        assert_ne!(reg.delegation_root(), empty);
        assert!(reg.delegation_root().is_some());
    }

    #[test]
    fn anyone_can_register_by_staking_no_whitelist() {
        let mut reg = PermissionlessRegistry::new();
        reg.register_validator(addr(1), MIN_REGISTRATION_STAKE, 0)
            .unwrap();
        assert!(reg.is_active(&addr(1), roles::VALIDATOR));
    }

    #[test]
    fn add_stake_refuses_overflow_and_inactive_members() {
        let mut reg = PermissionlessRegistry::new();
        reg.register_validator(addr(4), u64::MAX, 0).unwrap();
        let err = reg.add_stake(addr(4), roles::VALIDATOR, 1).unwrap_err();
        assert!(matches!(err, RegistryError::StakeOverflow { .. }));
        reg.begin_unbonding(addr(4), roles::VALIDATOR, 0).unwrap();
        let err = reg.add_stake(addr(4), roles::VALIDATOR, 1).unwrap_err();
        assert!(matches!(err, RegistryError::NotActive { .. }));
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

    /// BLG-0084: a later stake sync with the uncut total must not undo a slash.
    #[test]
    fn upsert_stake_cannot_raise_a_slashed_entry() {
        let mut reg = PermissionlessRegistry::new();
        reg.register_validator(addr(11), 10_000, 0).unwrap();
        let outcome = reg
            .slash(
                addr(11),
                roles::VALIDATOR,
                SlashingCondition::DoubleSign,
                FIXED_POINT_SCALE / 2,
            )
            .unwrap();
        assert!(outcome.penalty > 0);
        reg.upsert_stake(addr(11), roles::VALIDATOR, 10_000, 1);
        let after = reg.get(&addr(11), roles::VALIDATOR).unwrap();
        assert_eq!(after.stake, outcome.remaining_stake);
        // A smaller total still applies, including a full exit.
        reg.upsert_stake(addr(11), roles::VALIDATOR, 0, 2);
        assert_eq!(reg.get(&addr(11), roles::VALIDATOR).unwrap().stake, 0);
    }

    #[test]
    fn upsert_stake_to_zero_keeps_the_entry_under_the_unbonding_lock() {
        let mut reg = PermissionlessRegistry::new();
        reg.register_validator(addr(12), 10_000, 0).unwrap();
        reg.upsert_stake(addr(12), roles::VALIDATOR, 0, 5);
        let entry = reg.get(&addr(12), roles::VALIDATOR).expect("entry kept");
        let release_epoch = 5 + reg.params().unbonding_epochs;
        assert_eq!(entry.status, MemberStatus::Unbonding { release_epoch });
        assert!(reg.withdraw(addr(12), roles::VALIDATOR, 5).is_err());
    }

    /// BLG-0087 (P04-F05, decision A): Slashed is not a dead end. The member
    /// can unbond the remaining stake and withdraw it after the delay;
    /// unbonding is not an escape from a later slash (the unbonding queue is
    /// still cut on any further report).
    #[test]
    fn a_slashed_member_can_exit_through_unbonding() {
        let mut reg = PermissionlessRegistry::new();
        reg.register_validator(addr(7), MIN_REGISTRATION_STAKE, 0)
            .unwrap();
        reg.slash_role_only(
            addr(7),
            roles::VALIDATOR,
            SlashingCondition::DoubleSign,
            200,
        )
        .unwrap();
        assert!(matches!(
            reg.registrations
                .get(&(roles::VALIDATOR, addr(7)))
                .unwrap()
                .status,
            MemberStatus::Slashed
        ));
        let release = reg.begin_unbonding(addr(7), roles::VALIDATOR, 5).unwrap();
        assert_eq!(release, 5 + reg.params().unbonding_epochs);
        assert!(reg.withdraw(addr(7), roles::VALIDATOR, release).is_ok());
    }

    /// BLG-0087 (P04-F05, decision B): a liveness fault is a timed jail. The
    /// entry is not Slashed at the registry level, so the release after the
    /// jail expiry actually works.
    #[test]
    fn a_liveness_fault_does_not_slash_the_registry_entry() {
        let mut reg = PermissionlessRegistry::new();
        reg.register_validator(addr(8), MIN_REGISTRATION_STAKE, 0)
            .unwrap();
        let report = SlashingReport::consensus_liveness(
            addr(8),
            roles::VALIDATOR,
            crate::registry::evidence::SlashingProof::Liveness {
                window_start_epoch: 1,
                window_end_epoch: 2,
                missed: 9,
                expected: 10,
            },
            None,
        );
        let outcome = reg.slash_from_report(&report).unwrap();
        assert!(outcome.is_some());
        let entry = reg.registrations.get(&(roles::VALIDATOR, addr(8))).unwrap();
        assert!(
            matches!(entry.status, MemberStatus::Active),
            "a liveness fault must not write Slashed: {:?}",
            entry.status
        );
        assert!(
            entry.stake < MIN_REGISTRATION_STAKE,
            "the stake is still cut"
        );
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
                .is_some_and(super::Registration::is_slashable),
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
            crate::registry::evidence::SlashingProof::Liveness {
                window_start_epoch: 0,
                window_end_epoch: 10,
                missed: 5,
                expected: 10,
            },
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
            reg.is_active_relayer(&a),
            "a liveness fault is a timed jail, not a registry Slashed (BLG-0087, decision B)"
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
        // BLG-0099 (P04-F17): bond on bond is refused - a second
        // registration of the same role must not stack stake or reset
        // cooldowns (F04's seam).
        assert!(
            reg.register_attester(addr(30), 6_000, 0).is_err(),
            "bonding an attester role twice must refuse"
        );
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
        let body = &src[at..(at + 4000).min(src.len())];

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
                crate::registry::evidence::SlashingProof::DoubleSign {
                    height: n,
                    kind: crate::registry::evidence::DoubleSignKind::BlockHeader,
                    epoch: None,
                    block_hash_1: format!("{n:064x}"),
                    block_hash_2: format!("{:064x}", n + 1),
                    signature_1: vec![u8::try_from(n % 256).unwrap_or(0)],
                    signature_2: vec![u8::try_from((n + 1) % 256).unwrap_or(0)],
                },
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

    #[test]
    fn rebond_from_unbonding_restores_active_member_status() {
        let mut reg = PermissionlessRegistry::new();
        let addr = Address::from([0x42; 32]);
        let min_stake = reg.params().min_stake;
        reg.register(addr, roles::VALIDATOR, min_stake, 0)
            .expect("register validator");
        reg.upsert_stake(addr, roles::VALIDATOR, 0, 1);
        assert!(matches!(
            reg.get(&addr, roles::VALIDATOR).unwrap().status,
            MemberStatus::Unbonding { .. }
        ));
        assert!(!reg.is_active(&addr, roles::VALIDATOR));

        reg.upsert_stake(addr, roles::VALIDATOR, min_stake, 2);
        assert_eq!(
            reg.get(&addr, roles::VALIDATOR).unwrap().status,
            MemberStatus::Active
        );
        assert!(reg.is_active(&addr, roles::VALIDATOR));
    }

    #[test]
    fn delegation_lifecycle_keeps_exit_locked_and_rooted() {
        let mut reg = PermissionlessRegistry::new();
        let validator = Address::from([0x11; 32]);
        let delegator = Address::from([0x22; 32]);
        reg.register_validator(validator, 10_000, 0).unwrap();
        reg.delegate(delegator, validator, 2_000).unwrap();
        assert_eq!(reg.delegated_stake(&validator), 2_000);
        assert_eq!(reg.delegated_amount(delegator, validator), 2_000);
        assert_ne!(reg.root(), PermissionlessRegistry::new().root());

        reg.begin_delegation_unbonding(delegator, validator, 750, 0)
            .unwrap();
        assert_eq!(reg.delegated_stake(&validator), 1_250);
        assert_eq!(reg.withdrawable_delegation(delegator, validator, 99), 0);
        assert!(reg.withdraw_delegation(delegator, validator, 99).is_err());
        assert_eq!(
            reg.withdraw_delegation(
                delegator,
                validator,
                reg.params().delegation_unbonding_epochs
            )
            .unwrap(),
            750
        );
        assert_eq!(reg.total_delegation_unbonding_supply(), 0);
    }

    #[test]
    fn a_slash_cuts_every_delegation_by_its_own_share() {
        let mut reg = PermissionlessRegistry::new();
        let validator = Address::from([0x11; 32]);
        reg.register_validator(validator, 9_000, 0).unwrap();
        reg.delegate(Address::from([0x21; 32]), validator, 500)
            .unwrap();
        reg.delegate(Address::from([0x22; 32]), validator, 500)
            .unwrap();
        // Stake before the slash: 9,000 self + 1,000 delegated; a 5 percent
        // penalty is 500, of which the delegated tenth is 50.
        reg.reduce_delegated_for_slash(&validator, 500, 10_000);
        assert_eq!(
            reg.delegated_amount(Address::from([0x21; 32]), validator),
            475
        );
        assert_eq!(
            reg.delegated_amount(Address::from([0x22; 32]), validator),
            475
        );
        assert_eq!(reg.delegated_stake(&validator), 950);
    }

    #[test]
    fn commission_is_capped_and_rate_limited() {
        let mut reg = PermissionlessRegistry::new();
        let validator = Address::from([0x33; 32]);
        reg.register_validator(validator, 10_000, 0).unwrap();
        reg.set_validator_commission(validator, 100_000, 0).unwrap();
        assert_eq!(reg.validator_commission_ppm(&validator), 100_000);
        assert!(reg.set_validator_commission(validator, 111_000, 0).is_err());
        assert!(reg.set_validator_commission(validator, 111_000, 1).is_err());
        reg.set_validator_commission(validator, 110_000, 1).unwrap();
        assert_eq!(reg.validator_commission_ppm(&validator), 110_000);
        assert!(reg.set_validator_commission(validator, 200_001, 2).is_err());
    }
}
