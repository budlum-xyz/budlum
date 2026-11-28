//! Client-side transaction safety, stale-simulation detection, autonomous agent
//! spending guardrails, and proof-nullifier sender binding.
//!
//! Addresses wallet and UX failure modes:
//! - stale state/nonce simulation before signing and zero-delta / unlimited approvals,
//! - slippage quote drift checks and delegation-override conflicts,
//! - bounded slot-expiring spending policies for autonomous AI agent wallets,
//! - mempool ZK proof front-running protection binding `(sender, nullifier, chain_id)`.
//!
//! WIRING: Client wallet safety, agent execution guardrails, and mempool proof
//! nullifier bindings exposed to wallet CLI/SDK callers and `crate::transfer`.

use sha3::{Digest, Sha3_256};

/// Errors returned by pre-signing wallet safety and agent policy gates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxSafetyError {
    /// Simulated chain ID disagrees with live network ID.
    ChainMismatch {
        /// Chain ID observed when simulating.
        expected: u64,
        /// Live chain ID prior to signing.
        got: u64,
    },
    /// Sender account nonce changed since simulation.
    StaleNonce {
        /// Nonce used during simulation.
        simulated: u64,
        /// Live sender nonce prior to signing.
        current: u64,
    },
    /// Simulation is older than the permitted block age window.
    StaleBlockWindow {
        /// Block height captured at simulation time.
        simulated_height: u64,
        /// Current live block height.
        current_height: u64,
        /// Maximum allowed block age.
        max_age_blocks: u64,
    },
    /// State epoch drifted since pre-sign simulation.
    StateEpochDrift {
        /// Epoch captured at simulation time.
        simulated_epoch: u64,
        /// Live epoch prior to signing.
        current_epoch: u64,
    },
    /// Approval grant requests allowance without modifying simulated allowance state.
    ZeroDeltaApproval {
        /// Spender target of the approval intent.
        spender: [u8; 32],
    },
    /// Approval requests `u128::MAX` or exceeds the configured allowance ceiling.
    UnlimitedApprovalRefused {
        /// Spender target of the approval intent.
        spender: [u8; 32],
        /// Requested allowance amount.
        requested: u128,
        /// Configured ceiling for this spender.
        cap: u128,
    },
    /// Transaction minimum output fell below the simulated slippage floor.
    SlippageFloorViolation {
        /// Minimum output quoted during simulation.
        quoted_min_out: u128,
        /// Actual minimum output encoded in the transaction.
        actual_min_out: u128,
    },
    /// Active EOA/account delegation target conflicts with the simulated delegate.
    DelegationOverrideConflict {
        /// Delegate expected at simulation time.
        expected_delegate: Option<[u8; 32]>,
        /// Live delegate active on-chain.
        active_delegate: Option<[u8; 32]>,
    },
    /// Autonomous agent policy expired before `current_height`.
    PolicyExpired {
        /// Live block height.
        current_height: u64,
        /// Last valid height of the policy.
        expires_at_height: u64,
    },
    /// Target address is outside the agent's allowlist.
    TargetNotAllowlisted {
        /// Requested destination or contract address.
        target: [u8; 32],
    },
    /// Single-transaction amount exceeds the agent per-tx ceiling.
    PerTxCapExceeded {
        /// Requested spend amount.
        amount: u128,
        /// Maximum spend per transaction.
        per_tx_cap: u128,
    },
    /// Cumulative epoch spend would exceed the agent epoch cap.
    EpochCapExceeded {
        /// Atoms already spent in the current epoch.
        used: u128,
        /// Requested additional atoms.
        requested: u128,
        /// Maximum spend allowed per epoch.
        epoch_cap: u128,
    },
    /// Amount exceeds the deterministic human-veto threshold without countersignature.
    HumanVetoRequired {
        /// Requested spend amount.
        amount: u128,
        /// Threshold requiring explicit human approval.
        veto_threshold: u128,
    },
    /// Claimed sender-bound nullifier does not match `(chain_id, tx_sender, proof_digest, inner_nullifier)`.
    SenderNullifierMismatch,
    /// Sender-bound nullifier was already spent in the mempool/replay ledger.
    ReplayNullifierUsed,
    /// State root changed between simulation and signing.
    StateRootDrift {
        /// State root at simulation time.
        simulated_root: [u8; 32],
        /// Live state root prior to signing.
        current_root: [u8; 32],
    },
    /// Storage slots touched by the simulated call mutated before signing.
    TouchedStorageDrift {
        /// Digest of touched storage slots at simulation time.
        simulated_digest: [u8; 32],
        /// Live digest of the same slots prior to signing.
        current_digest: [u8; 32],
    },
    /// Dependent execution was simulated before its prerequisite approval confirmed.
    UnconfirmedApprovalDependency {
        /// Epoch of the confirmed approval required by the simulation.
        required_epoch: u64,
        /// Latest confirmed approval epoch observed on-chain.
        confirmed_epoch: Option<u64>,
    },
    /// On-chain minimum output is zero or below the simulation slippage floor.
    UnenforcedExecutionFloor {
        /// Expected output displayed by off-chain simulation.
        simulated_expected_out: u128,
        /// Enforced on-chain minimum output (`0` enables sandwich capture).
        enforced_min_out: u128,
        /// Maximum tolerated slippage in basis points.
        max_slippage_bps: u16,
    },
    /// Enforced on-chain execution deadline expired before signing.
    ExpiredExecutionDeadline {
        /// Enforced execution deadline epoch.
        deadline_epoch: u64,
        /// Current live epoch.
        current_epoch: u64,
    },
    /// Hook or adapter runtime implementation drifted despite matching address capability bits.
    HookBehaviourDrift {
        /// Hook or adapter contract address.
        hook_address: [u8; 32],
        /// Diagnostic mismatch reason.
        reason: String,
    },
    /// Self-transfer wash loop between identical sender and recipient is refused.
    SelfTransferProhibited {
        /// Account acting as both sender and recipient.
        account: [u8; 32],
    },
}

impl std::fmt::Display for TxSafetyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for TxSafetyError {}

/// Pre-sign simulation snapshot bound to exact chain/nonce/epoch state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulationSnapshot {
    /// Simulated chain ID.
    pub chain_id: u64,
    /// Sender nonce observed during simulation.
    pub sender_nonce: u64,
    /// Block height observed during simulation.
    pub block_height: u64,
    /// State epoch observed during simulation.
    pub state_epoch: u64,
    /// Minimum output quoted during simulation.
    pub quoted_min_out_atoms: u128,
    /// Expected EOA/account delegation target, if any.
    pub expected_delegate: Option<[u8; 32]>,
    /// Optional allowance grant included in the simulated transaction.
    pub approval_grant: Option<ApprovalIntent>,
}

/// Token/asset approval request verified against zero-delta and unlimited traps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalIntent {
    /// Authorized spender account or contract.
    pub spender: [u8; 32],
    /// Requested allowance amount in atoms.
    pub requested_allowance: u128,
    /// Simulated state delta caused by the approval call.
    pub simulated_state_delta: u128,
    /// Hard wallet-side cap permitted for this approval.
    pub max_allowed_allowance: u128,
}

/// Live chain conditions observed immediately prior to user signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveSignContext {
    /// Live chain ID.
    pub chain_id: u64,
    /// Live sender nonce.
    pub current_nonce: u64,
    /// Live block height.
    pub current_height: u64,
    /// Live state epoch.
    pub current_epoch: u64,
    /// Minimum output encoded in the transaction to be signed.
    pub tx_min_out_atoms: u128,
    /// Active EOA/account delegation target observed live.
    pub active_delegate: Option<[u8; 32]>,
    /// Maximum allowed simulation age in blocks.
    pub max_simulation_age_blocks: u64,
}

/// Verify that a pre-sign simulation matches live wallet state, avoids
/// zero-delta / unlimited approval traps, preserves slippage bounds, and detects
/// delegation overrides before signing.
///
/// # Errors
///
/// Returns [`TxSafetyError`] on any stale state, approval trap, slippage drift,
/// or delegation conflict.
pub fn verify_simulation_freshness(
    sim: &SimulationSnapshot,
    live: &LiveSignContext,
) -> Result<(), TxSafetyError> {
    if sim.chain_id != live.chain_id {
        return Err(TxSafetyError::ChainMismatch {
            expected: sim.chain_id,
            got: live.chain_id,
        });
    }
    if sim.sender_nonce != live.current_nonce {
        return Err(TxSafetyError::StaleNonce {
            simulated: sim.sender_nonce,
            current: live.current_nonce,
        });
    }
    if sim.state_epoch != live.current_epoch {
        return Err(TxSafetyError::StateEpochDrift {
            simulated_epoch: sim.state_epoch,
            current_epoch: live.current_epoch,
        });
    }
    if live.current_height < sim.block_height
        || live.current_height.saturating_sub(sim.block_height) > live.max_simulation_age_blocks
    {
        return Err(TxSafetyError::StaleBlockWindow {
            simulated_height: sim.block_height,
            current_height: live.current_height,
            max_age_blocks: live.max_simulation_age_blocks,
        });
    }
    if sim.expected_delegate != live.active_delegate {
        return Err(TxSafetyError::DelegationOverrideConflict {
            expected_delegate: sim.expected_delegate,
            active_delegate: live.active_delegate,
        });
    }
    if live.tx_min_out_atoms < sim.quoted_min_out_atoms {
        return Err(TxSafetyError::SlippageFloorViolation {
            quoted_min_out: sim.quoted_min_out_atoms,
            actual_min_out: live.tx_min_out_atoms,
        });
    }
    if let Some(app) = sim.approval_grant {
        if app.requested_allowance > 0 && app.simulated_state_delta == 0 {
            return Err(TxSafetyError::ZeroDeltaApproval {
                spender: app.spender,
            });
        }
        if app.requested_allowance == u128::MAX
            || app.requested_allowance > app.max_allowed_allowance
        {
            return Err(TxSafetyError::UnlimitedApprovalRefused {
                spender: app.spender,
                requested: app.requested_allowance,
                cap: app.max_allowed_allowance,
            });
        }
    }
    Ok(())
}

/// Deterministic spending policy for autonomous AI agent keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentExecutionPolicy {
    /// Block height after which the agent session key automatically expires.
    pub expires_at_height: u64,
    /// Maximum atoms allowed per transaction.
    pub per_tx_cap_atoms: u128,
    /// Cumulative atoms allowed per epoch.
    pub epoch_cap_atoms: u128,
    /// Spend threshold above which explicit human countersignature is required.
    pub human_veto_above_atoms: u128,
    /// Explicit set of destination/contract addresses the agent may interact with.
    pub allowed_targets: Vec<[u8; 32]>,
}

/// Stateful per-epoch spend tracker enforcing [`AgentExecutionPolicy`].
#[derive(Debug, Clone, Default)]
pub struct AgentSpendGuard {
    current_epoch: u64,
    epoch_spent_atoms: u128,
}

impl AgentSpendGuard {
    /// Construct a spend tracker anchored at `epoch`.
    #[must_use]
    pub fn new(epoch: u64) -> Self {
        Self {
            current_epoch: epoch,
            epoch_spent_atoms: 0,
        }
    }

    /// Reset cumulative epoch expenditure when advancing to a strictly higher epoch.
    pub fn advance_epoch(&mut self, new_epoch: u64) {
        if new_epoch > self.current_epoch {
            self.current_epoch = new_epoch;
            self.epoch_spent_atoms = 0;
        }
    }

    /// Authorize an agent-initiated spend if within expiry, target allowlist,
    /// per-tx cap, epoch ceiling, and deterministic human-veto threshold.
    ///
    /// # Errors
    ///
    /// Returns [`TxSafetyError`] without mutating spent balance on refusal.
    pub fn authorize_spend(
        &mut self,
        policy: &AgentExecutionPolicy,
        current_height: u64,
        target: &[u8; 32],
        amount_atoms: u128,
        human_countersigned: bool,
    ) -> Result<(), TxSafetyError> {
        if current_height > policy.expires_at_height {
            return Err(TxSafetyError::PolicyExpired {
                current_height,
                expires_at_height: policy.expires_at_height,
            });
        }
        if !policy.allowed_targets.iter().any(|t| t == target) {
            return Err(TxSafetyError::TargetNotAllowlisted { target: *target });
        }
        if amount_atoms > policy.human_veto_above_atoms && !human_countersigned {
            return Err(TxSafetyError::HumanVetoRequired {
                amount: amount_atoms,
                veto_threshold: policy.human_veto_above_atoms,
            });
        }
        if amount_atoms > policy.per_tx_cap_atoms {
            return Err(TxSafetyError::PerTxCapExceeded {
                amount: amount_atoms,
                per_tx_cap: policy.per_tx_cap_atoms,
            });
        }
        let next = self.epoch_spent_atoms.checked_add(amount_atoms).ok_or(
            TxSafetyError::EpochCapExceeded {
                used: self.epoch_spent_atoms,
                requested: amount_atoms,
                epoch_cap: policy.epoch_cap_atoms,
            },
        )?;
        if next > policy.epoch_cap_atoms {
            return Err(TxSafetyError::EpochCapExceeded {
                used: self.epoch_spent_atoms,
                requested: amount_atoms,
                epoch_cap: policy.epoch_cap_atoms,
            });
        }
        self.epoch_spent_atoms = next;
        Ok(())
    }

    /// Return the cumulative atoms already authorized in the active epoch.
    #[must_use]
    pub fn epoch_spent_atoms(&self) -> u128 {
        self.epoch_spent_atoms
    }
}

/// Exact chain, nonce, state, storage-slot, and approval-ordering binding for
/// off-chain transaction simulation validity.
///
/// WIRING: Checked by [`enforce_simulation_binding`] and [`verify_swap_execution_safety`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulationBindingKey {
    /// Target chain ID.
    pub chain_id: u64,
    /// Sender nonce observed during simulation.
    pub account_nonce: u64,
    /// State root at simulation time.
    pub state_root: [u8; 32],
    /// Digest over touched storage slots (pool reserves, allowances, hook config).
    pub touched_storage_digest: [u8; 32],
    /// Confirmed approval epoch that a dependent swap simulation relies on, if any.
    pub required_approval_confirmed_epoch: Option<u64>,
}

/// Live state observed immediately before signing against [`SimulationBindingKey`].
///
/// WIRING: Passed into [`enforce_simulation_binding`] and [`verify_swap_execution_safety`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveSimulationBinding {
    /// Live chain ID.
    pub chain_id: u64,
    /// Live sender nonce.
    pub account_nonce: u64,
    /// Live state root.
    pub state_root: [u8; 32],
    /// Live digest over the storage slots touched by simulation.
    pub touched_storage_digest: [u8; 32],
    /// Latest confirmed epoch of the prerequisite approval transaction, if any.
    pub approval_confirmed_epoch: Option<u64>,
}

/// Enforced on-chain execution constraints separating simulated UX estimates
/// from transaction-enforced slippage and deadline invariants.
///
/// WIRING: Checked by [`enforce_execution_floor`] and [`verify_swap_execution_safety`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnforcedExecutionFloor {
    /// Expected output shown by simulation preview.
    pub simulated_expected_out: u128,
    /// Hard minimum output encoded into on-chain transaction parameters.
    pub onchain_enforced_min_out: u128,
    /// Enforced execution deadline epoch.
    pub deadline_epoch: u64,
    /// Maximum allowed slippage below `simulated_expected_out` (in bps, `0..=10_000`).
    pub max_slippage_bps: u16,
}

/// Runtime integrity pin for hook/adapter addresses whose capability bits do
/// not prevent mutable proxy, external oracle, or dynamic fee drift.
///
/// WIRING: Checked by [`verify_hook_capability_pin`] and [`verify_swap_execution_safety`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookCapabilityPin {
    /// Hook or adapter address carrying capability bits.
    pub hook_address: [u8; 32],
    /// Expected address-encoded capability bitmask.
    pub expected_capability_bits: u16,
    /// Live address-encoded capability bitmask.
    pub observed_capability_bits: u16,
    /// Governance/simulation-pinned runtime code hash behind the hook address.
    pub pinned_runtime_code_hash: [u8; 32],
    /// Live observed runtime code hash behind the hook address.
    pub observed_runtime_code_hash: [u8; 32],
    /// Maximum tolerated fee bps authorized by the wallet policy.
    pub max_fee_bps: u16,
    /// Live fee bps currently read from hook state.
    pub observed_fee_bps: u16,
}

/// Verify that off-chain simulation remains bound to exact state root, touched
/// storage slots, nonce, chain ID, and confirmed prerequisite approval order.
///
/// # Errors
///
/// Returns [`TxSafetyError`] when any chain, nonce, root, storage digest, or
/// prerequisite approval ordering invariant disagrees with live state.
pub fn enforce_simulation_binding(
    expected: &SimulationBindingKey,
    live: &LiveSimulationBinding,
) -> Result<(), TxSafetyError> {
    if expected.chain_id != live.chain_id {
        return Err(TxSafetyError::ChainMismatch {
            expected: expected.chain_id,
            got: live.chain_id,
        });
    }
    if expected.account_nonce != live.account_nonce {
        return Err(TxSafetyError::StaleNonce {
            simulated: expected.account_nonce,
            current: live.account_nonce,
        });
    }
    if expected.state_root != live.state_root {
        return Err(TxSafetyError::StateRootDrift {
            simulated_root: expected.state_root,
            current_root: live.state_root,
        });
    }
    if expected.touched_storage_digest != live.touched_storage_digest {
        return Err(TxSafetyError::TouchedStorageDrift {
            simulated_digest: expected.touched_storage_digest,
            current_digest: live.touched_storage_digest,
        });
    }
    if let Some(required_epoch) = expected.required_approval_confirmed_epoch {
        match live.approval_confirmed_epoch {
            Some(confirmed) if confirmed >= required_epoch => {}
            other => {
                return Err(TxSafetyError::UnconfirmedApprovalDependency {
                    required_epoch,
                    confirmed_epoch: other,
                });
            }
        }
    }
    Ok(())
}

/// Refuse preview-only quotes that fail to encode a non-zero on-chain `min_out`
/// floor, exceed `max_slippage_bps`, or carry an expired deadline.
///
/// # Errors
///
/// Returns [`TxSafetyError::ExpiredExecutionDeadline`] or
/// [`TxSafetyError::UnenforcedExecutionFloor`].
pub fn enforce_execution_floor(
    floor: &EnforcedExecutionFloor,
    current_epoch: u64,
) -> Result<(), TxSafetyError> {
    if floor.deadline_epoch < current_epoch {
        return Err(TxSafetyError::ExpiredExecutionDeadline {
            deadline_epoch: floor.deadline_epoch,
            current_epoch,
        });
    }
    if floor.max_slippage_bps > 10_000 || floor.onchain_enforced_min_out == 0 {
        return Err(TxSafetyError::UnenforcedExecutionFloor {
            simulated_expected_out: floor.simulated_expected_out,
            enforced_min_out: floor.onchain_enforced_min_out,
            max_slippage_bps: floor.max_slippage_bps,
        });
    }
    let keep_bps = 10_000u128.saturating_sub(u128::from(floor.max_slippage_bps));
    let required_floor = floor.simulated_expected_out.saturating_mul(keep_bps) / 10_000u128;
    if floor.onchain_enforced_min_out < required_floor.max(1) {
        return Err(TxSafetyError::UnenforcedExecutionFloor {
            simulated_expected_out: floor.simulated_expected_out,
            enforced_min_out: floor.onchain_enforced_min_out,
            max_slippage_bps: floor.max_slippage_bps,
        });
    }
    Ok(())
}

/// Verify that a hook/adapter address keeps both its declared capability bits
/// and its pinned runtime code hash and fee ceiling.
///
/// # Errors
///
/// Returns [`TxSafetyError::HookBehaviourDrift`] on bitmask, runtime code
/// hash, or dynamic fee drift.
pub fn verify_hook_capability_pin(pin: &HookCapabilityPin) -> Result<(), TxSafetyError> {
    if pin.expected_capability_bits != pin.observed_capability_bits {
        return Err(TxSafetyError::HookBehaviourDrift {
            hook_address: pin.hook_address,
            reason: format!(
                "capability bits drifted (expected=0x{:04x}, observed=0x{:04x})",
                pin.expected_capability_bits, pin.observed_capability_bits
            ),
        });
    }
    if pin.pinned_runtime_code_hash == [0u8; 32]
        || pin.pinned_runtime_code_hash != pin.observed_runtime_code_hash
    {
        return Err(TxSafetyError::HookBehaviourDrift {
            hook_address: pin.hook_address,
            reason: "runtime code hash missing or drifted behind capability address".into(),
        });
    }
    if pin.observed_fee_bps > pin.max_fee_bps {
        return Err(TxSafetyError::HookBehaviourDrift {
            hook_address: pin.hook_address,
            reason: format!(
                "hook fee {} bps exceeds wallet policy ceiling {} bps",
                pin.observed_fee_bps, pin.max_fee_bps
            ),
        });
    }
    Ok(())
}

/// Refuse degenerate self-transfers used in automated wash-volume loops.
///
/// # Errors
///
/// Returns [`TxSafetyError::SelfTransferProhibited`] when `sender == recipient`
/// and `sender` is non-zero.
pub fn enforce_non_self_agent_transfer(
    sender: &[u8; 32],
    recipient: &[u8; 32],
) -> Result<(), TxSafetyError> {
    if *sender != [0u8; 32] && sender == recipient {
        return Err(TxSafetyError::SelfTransferProhibited { account: *sender });
    }
    Ok(())
}

/// End-to-end pre-sign safety check combining simulation binding, enforced
/// execution floor, and optional hook runtime integrity pinning.
///
/// WIRING: Unified pre-sign swap/hook gate exposed by [`crate::tx_safety`].
///
/// # Errors
///
/// Returns [`TxSafetyError`] on the first failed check.
pub fn verify_swap_execution_safety(
    binding: &SimulationBindingKey,
    live_binding: &LiveSimulationBinding,
    floor: &EnforcedExecutionFloor,
    current_epoch: u64,
    hook_pin: Option<&HookCapabilityPin>,
) -> Result<(), TxSafetyError> {
    enforce_simulation_binding(binding, live_binding)?;
    enforce_execution_floor(floor, current_epoch)?;
    if let Some(pin) = hook_pin {
        verify_hook_capability_pin(pin)?;
    }
    Ok(())
}

/// Derive a sender-bound mempool nullifier commitment preventing proof
/// front-running when submitted to a public mempool.
#[must_use]
pub fn derive_sender_bound_nullifier(
    chain_id: u64,
    sender: &[u8; 32],
    proof_digest: &[u8; 32],
    inner_nullifier: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"BDLM_ZK_SENDER_NULLIFIER_V1");
    h.update(chain_id.to_le_bytes());
    h.update(sender);
    h.update(proof_digest);
    h.update(inner_nullifier);
    h.finalize().into()
}

/// Verify that a mempool ZK proof submission matches `tx_sender` and has not
/// already spent its sender-bound nullifier.
///
/// # Errors
///
/// Returns [`TxSafetyError::SenderNullifierMismatch`] or [`TxSafetyError::ReplayNullifierUsed`].
pub fn verify_mempool_proof_binding(
    chain_id: u64,
    tx_sender: &[u8; 32],
    proof_digest: &[u8; 32],
    inner_nullifier: &[u8; 32],
    claimed_bound_nullifier: &[u8; 32],
    spent_nullifiers: &mut std::collections::BTreeSet<[u8; 32]>,
) -> Result<[u8; 32], TxSafetyError> {
    let expected =
        derive_sender_bound_nullifier(chain_id, tx_sender, proof_digest, inner_nullifier);
    if expected != *claimed_bound_nullifier {
        return Err(TxSafetyError::SenderNullifierMismatch);
    }
    if !spent_nullifiers.insert(expected) {
        return Err(TxSafetyError::ReplayNullifierUsed);
    }
    Ok(expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn clean_sim() -> (SimulationSnapshot, LiveSignContext) {
        let sim = SimulationSnapshot {
            chain_id: 45_261,
            sender_nonce: 7,
            block_height: 100,
            state_epoch: 10,
            quoted_min_out_atoms: 950,
            expected_delegate: None,
            approval_grant: Some(ApprovalIntent {
                spender: [0x11; 32],
                requested_allowance: 1_000,
                simulated_state_delta: 1_000,
                max_allowed_allowance: 5_000,
            }),
        };
        let live = LiveSignContext {
            chain_id: 45_261,
            current_nonce: 7,
            current_height: 102,
            current_epoch: 10,
            tx_min_out_atoms: 950,
            active_delegate: None,
            max_simulation_age_blocks: 5,
        };
        (sim, live)
    }

    #[test]
    fn simulation_guard_accepts_fresh_state_and_rejects_stale_or_traps() {
        let (sim, live) = clean_sim();
        assert!(verify_simulation_freshness(&sim, &live).is_ok());

        let mut stale_nonce = live.clone();
        stale_nonce.current_nonce = 8;
        assert!(matches!(
            verify_simulation_freshness(&sim, &stale_nonce),
            Err(TxSafetyError::StaleNonce { .. })
        ));

        let mut stale_height = live.clone();
        stale_height.current_height = 110;
        assert!(matches!(
            verify_simulation_freshness(&sim, &stale_height),
            Err(TxSafetyError::StaleBlockWindow { .. })
        ));

        let mut delegate_hijack = live.clone();
        delegate_hijack.active_delegate = Some([0xEE; 32]);
        assert!(matches!(
            verify_simulation_freshness(&sim, &delegate_hijack),
            Err(TxSafetyError::DelegationOverrideConflict { .. })
        ));

        let mut slippage = live.clone();
        slippage.tx_min_out_atoms = 900;
        assert!(matches!(
            verify_simulation_freshness(&sim, &slippage),
            Err(TxSafetyError::SlippageFloorViolation { .. })
        ));

        let mut zero_delta_sim = sim.clone();
        zero_delta_sim
            .approval_grant
            .as_mut()
            .expect("approval fixture")
            .simulated_state_delta = 0;
        assert!(matches!(
            verify_simulation_freshness(&zero_delta_sim, &live),
            Err(TxSafetyError::ZeroDeltaApproval { .. })
        ));

        let mut unlimited_sim = sim;
        unlimited_sim
            .approval_grant
            .as_mut()
            .expect("approval fixture")
            .requested_allowance = u128::MAX;
        assert!(matches!(
            verify_simulation_freshness(&unlimited_sim, &live),
            Err(TxSafetyError::UnlimitedApprovalRefused { .. })
        ));
    }

    #[test]
    fn agent_execution_guard_enforces_caps_veto_and_expiry() {
        let target = [0xAA; 32];
        let other = [0xBB; 32];
        let policy = AgentExecutionPolicy {
            expires_at_height: 500,
            per_tx_cap_atoms: 100,
            epoch_cap_atoms: 150,
            human_veto_above_atoms: 80,
            allowed_targets: vec![target],
        };
        let mut guard = AgentSpendGuard::new(1);

        assert!(guard
            .authorize_spend(&policy, 490, &target, 70, false)
            .is_ok());
        assert_eq!(guard.epoch_spent_atoms(), 70);

        assert!(matches!(
            guard.authorize_spend(&policy, 491, &target, 90, false),
            Err(TxSafetyError::HumanVetoRequired { .. })
        ));
        assert_eq!(guard.epoch_spent_atoms(), 70);

        assert!(matches!(
            guard.authorize_spend(&policy, 491, &target, 90, true),
            Err(TxSafetyError::EpochCapExceeded { .. })
        ));
        assert!(guard
            .authorize_spend(&policy, 491, &other, 10, false)
            .is_err());
        assert!(guard
            .authorize_spend(&policy, 501, &target, 10, false)
            .is_err());

        guard.advance_epoch(2);
        assert!(guard
            .authorize_spend(&policy, 492, &target, 80, false)
            .is_ok());
    }

    #[test]
    fn mempool_sender_nullifier_blocks_front_running_and_replay() {
        let alice = [0x01; 32];
        let bob = [0x02; 32];
        let proof = [0xCC; 32];
        let inner = [0xDD; 32];
        let bound = derive_sender_bound_nullifier(45_261, &alice, &proof, &inner);
        let mut spent = BTreeSet::new();

        assert_eq!(
            verify_mempool_proof_binding(45_261, &bob, &proof, &inner, &bound, &mut spent),
            Err(TxSafetyError::SenderNullifierMismatch)
        );
        assert_eq!(
            verify_mempool_proof_binding(45_261, &alice, &proof, &inner, &bound, &mut spent),
            Ok(bound)
        );
        assert_eq!(
            verify_mempool_proof_binding(45_261, &alice, &proof, &inner, &bound, &mut spent),
            Err(TxSafetyError::ReplayNullifierUsed)
        );
    }

    #[test]
    fn simulation_binding_and_approval_order_reject_stale_state_or_pending_approve() {
        let key = SimulationBindingKey {
            chain_id: 45_261,
            account_nonce: 9,
            state_root: [0x21; 32],
            touched_storage_digest: [0x34; 32],
            required_approval_confirmed_epoch: Some(15),
        };
        let live_ok = LiveSimulationBinding {
            chain_id: 45_261,
            account_nonce: 9,
            state_root: [0x21; 32],
            touched_storage_digest: [0x34; 32],
            approval_confirmed_epoch: Some(15),
        };
        assert!(enforce_simulation_binding(&key, &live_ok).is_ok());

        let mut storage_drift = live_ok.clone();
        storage_drift.touched_storage_digest = [0x99; 32];
        assert!(matches!(
            enforce_simulation_binding(&key, &storage_drift),
            Err(TxSafetyError::TouchedStorageDrift { .. })
        ));

        let mut root_drift = live_ok.clone();
        root_drift.state_root = [0x88; 32];
        assert!(matches!(
            enforce_simulation_binding(&key, &root_drift),
            Err(TxSafetyError::StateRootDrift { .. })
        ));

        let mut unconfirmed_approve = live_ok;
        unconfirmed_approve.approval_confirmed_epoch = Some(14);
        assert!(matches!(
            enforce_simulation_binding(&key, &unconfirmed_approve),
            Err(TxSafetyError::UnconfirmedApprovalDependency { .. })
        ));
    }

    #[test]
    fn enforced_execution_floor_and_hook_pin_block_sandwich_and_runtime_drift() {
        let binding = SimulationBindingKey {
            chain_id: 45_261,
            account_nonce: 1,
            state_root: [0x12; 32],
            touched_storage_digest: [0x34; 32],
            required_approval_confirmed_epoch: None,
        };
        let live_binding = LiveSimulationBinding {
            chain_id: 45_261,
            account_nonce: 1,
            state_root: [0x12; 32],
            touched_storage_digest: [0x34; 32],
            approval_confirmed_epoch: None,
        };
        let good_floor = EnforcedExecutionFloor {
            simulated_expected_out: 1_000,
            onchain_enforced_min_out: 980,
            deadline_epoch: 50,
            max_slippage_bps: 200,
        };
        let good_hook = HookCapabilityPin {
            hook_address: [0x55; 32],
            expected_capability_bits: 0x0080,
            observed_capability_bits: 0x0080,
            pinned_runtime_code_hash: [0xAA; 32],
            observed_runtime_code_hash: [0xAA; 32],
            max_fee_bps: 30,
            observed_fee_bps: 25,
        };
        assert!(verify_swap_execution_safety(
            &binding,
            &live_binding,
            &good_floor,
            40,
            Some(&good_hook),
        )
        .is_ok());

        let zero_min_out = EnforcedExecutionFloor {
            onchain_enforced_min_out: 0,
            ..good_floor
        };
        assert!(matches!(
            enforce_execution_floor(&zero_min_out, 40),
            Err(TxSafetyError::UnenforcedExecutionFloor { .. })
        ));
        assert!(matches!(
            enforce_execution_floor(&good_floor, 51),
            Err(TxSafetyError::ExpiredExecutionDeadline { .. })
        ));

        let mut drifted_hook = good_hook;
        drifted_hook.observed_runtime_code_hash = [0xBB; 32];
        assert!(matches!(
            verify_hook_capability_pin(&drifted_hook),
            Err(TxSafetyError::HookBehaviourDrift { .. })
        ));

        let mut fee_spike_hook = good_hook;
        fee_spike_hook.observed_fee_bps = 500;
        assert!(matches!(
            verify_hook_capability_pin(&fee_spike_hook),
            Err(TxSafetyError::HookBehaviourDrift { .. })
        ));
    }

    #[test]
    fn agent_self_transfer_wash_loop_is_refused() {
        let agent = [0x42; 32];
        let peer = [0x43; 32];
        assert_eq!(
            enforce_non_self_agent_transfer(&agent, &agent),
            Err(TxSafetyError::SelfTransferProhibited { account: agent })
        );
        assert!(enforce_non_self_agent_transfer(&agent, &peer).is_ok());
    }
}
