use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType};
use crate::error::{BudlumError, BudlumResult};
use crate::execution::zkvm::{ZkVmExecutor, DEFAULT_CONTRACT_GAS_LIMIT};
use bincode;
use serde_json;

pub struct Executor;

/// The only execution-proof backend this path accepts.
///
/// It is matched exactly, and the comparison lives here so the name has one
/// home. The string arrives inside the transaction envelope
/// (`ProofEnvelope.backend`), so a substring test is not an allow-list: any
/// name that merely mentions Plonky3 - `"Plonky3-nightly"`,
/// `"Plonky3 with a local patch"` - used to be accepted, and what the gate
/// guards is only checked structurally downstream.
///
/// The value is not a label this node invented: it is the id the proof library
/// compares against before it decodes anything
/// (`bud_proof::plonky3_prover`, `"Plonky3-Keccak-Goldilocks"`). The exact match
/// was briefly `"Plonky3"`, which is a name no prover emits, and the result was a
/// path that could not be satisfied from either side - an envelope the verifier
/// would have opened was refused in the mempool, and an envelope shaped for the
/// mempool's word was refused by the verifier. Both gates now read this
/// constant: `ProofVerifier::validate_envelope_structure` refuses any other
/// backend, so the two cannot drift into two different acceptances again.
///
/// The gate is deliberately the same on every network (`_chain_id` is
/// unread): an unproven execution is as worthless on devnet as on mainnet.
pub const AI_EXECUTION_BACKEND_PLONKY3: &str = "Plonky3-Keccak-Goldilocks";

fn ai_execution_backend_allowed(_chain_id: u64, backend: &str) -> bool {
    backend == AI_EXECUTION_BACKEND_PLONKY3
}

fn privacy_transfers_enabled(chain_id: u64) -> bool {
    // Allowlist, not a denylist.
    //
    // `PrivateTransferSubmit` reaches `note_registry.apply_transfer`, which
    // takes the nullifier the submitter hands it: the binding check
    // `nullifier == derive_nullifier(commitment, proof)` only runs when
    // `apply_transfer_with_proofs` is called with proofs, and nothing in the
    // tree calls it that way. So today a transfer proves who signed the
    // transaction, never that the signer owns the note; value conservation and
    // membership are unwired too. That is survivable on the two networks where
    // the notes are worth nothing.
    //
    // The old test was `chain_id != Mainnet`, which answers "is this not the
    // one network we care about" instead of "is this a network where losing the
    // notes costs nothing". Every id nobody has claimed yet - a second mainnet,
    // a public testnet that grows real value - came back enabled.
    chain_id
        == crate::core::chain_config::Network::Devnet
            .chain_id()
            .value()
        || chain_id
            == crate::core::chain_config::Network::Testnet
                .chain_id()
                .value()
}

impl Executor {
    pub fn apply_transaction(state: &mut AccountState, tx: &Transaction) -> Result<(), String> {
        Self::apply_transaction_checked(state, tx).map_err(|e| e.message().to_string())
    }

    pub fn apply_transaction_checked(
        state: &mut AccountState,
        tx: &Transaction,
    ) -> BudlumResult<()> {
        // The zero address is not a sender: only the canonical genesis
        // transaction may originate from it, and it is rejected everywhere
        // but the genesis block by `validate_and_add_block`. Accepting any
        // zero-address sender here would let an attacker fill blocks with
        // free, unsigned, fee-free transactions (BUDLUM finding #65/#171).
        if tx.from == Address::zero() {
            if tx.verify() {
                return Ok(());
            }
            return Err(BudlumError::validation(
                "zero_address_sender_forbidden",
                "the zero address cannot originate transactions outside the canonical genesis transaction",
            ));
        }
        if state.burn_reserve_address == Some(tx.from) {
            return Err(BudlumError::validation(
                "burn_reserve_locked",
                "Burn reserve is schedule-controlled and cannot originate transactions",
            ));
        }

        match tx.tx_type {
            TransactionType::Unstake => {
                if tx.amount == 0 {
                    return Err(BudlumError::validation(
                        "unstake_amount_zero",
                        "Unstake amount cannot be 0",
                    ));
                }
                if tx.fee == 0 {
                    return Err(BudlumError::validation(
                        "unstake_fee_zero",
                        "Unstake fee cannot be 0 (consensus cost-floor)",
                    ));
                }
            }
            TransactionType::Vote if tx.fee == 0 => {
                return Err(BudlumError::validation(
                    "vote_fee_zero",
                    "Vote fee cannot be 0 (consensus cost-floor)",
                ));
            }
            _ => {}
        }

        let liquid_cost = match tx.tx_type {
            TransactionType::Unstake | TransactionType::Vote => tx.fee,
            _ => tx.total_cost(),
        };

        {
            let sender_account = state.get_or_create(&tx.from);
            if sender_account.balance < liquid_cost {
                return Err(BudlumError::validation(
                    "insufficient_balance",
                    "Insufficient balance",
                ));
            }
        }

        let total_cost = tx.total_cost();

        match &tx.tx_type {
            TransactionType::Transfer => {
                let spendable = state.spendable_balance(&tx.from);
                if total_cost > spendable {
                    return Err(BudlumError::validation(
                        "vesting_locked",
                        format!(
                            "Transfer exceeds spendable balance: have {spendable}, need {total_cost}"
                        ),
                    ));
                }
                let sender = state.get_or_create(&tx.from);
                // Checked arithmetic for critical
                // Balance paths. Sender sub is safe (balance check above),
                // But receiver add must not silently cap at u64::MAX.
                sender.balance = sender.balance.checked_sub(total_cost).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);

                let receiver = state.get_or_create(&tx.to);
                receiver.balance = receiver.balance.checked_add(tx.amount).ok_or_else(|| {
                    BudlumError::validation(
                        "balance_overflow",
                        "Receiver balance overflow: transfer would exceed u64::MAX",
                    )
                })?;
            }
            TransactionType::Stake => {
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(total_cost).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);

                let stake_amount = tx.amount;
                let min_stake = crate::core::chain_config::Network::from_chain_id(tx.chain_id)
                    .map(|network| network.min_stake())
                    .unwrap_or(1);
                let validator = state.get_validator_mut(&tx.from);

                if let Some(v) = validator {
                    v.stake = v.stake.checked_add(stake_amount).ok_or_else(|| {
                        BudlumError::validation("stake_overflow", "stake overflow")
                    })?;
                    v.active = v.stake >= min_stake && v.is_consensus_ready();
                    if !v.active {
                        tracing::warn!(
                            validator = %tx.from,
                            missing_keys = ?v.missing_consensus_keys(),
                            "validator stake updated but validator remains bonded/inactive until consensus keys are complete"
                        );
                    }
                } else {
                    // User-approved decision: staking may succeed before the
                    // Validator finishes its key ceremony, but such validators
                    // Must remain bonded/inactive and must not enter quorum.
                    state.add_validator(tx.from, stake_amount);
                    if let Some(v) = state.get_validator_mut(&tx.from) {
                        v.active = v.stake >= min_stake && v.is_consensus_ready();
                        if !v.active {
                            tracing::warn!(
                                validator = %tx.from,
                                missing_keys = ?v.missing_consensus_keys(),
                                "new validator bonded but inactive until consensus keys are complete"
                            );
                        }
                    }
                }
                state.sync_validator_registration(&tx.from);
            }
            TransactionType::RegisterConsensusKeys(registration) => {
                if tx.amount != 0 || tx.to != Address::zero() || !tx.data.is_empty() {
                    return Err(BudlumError::validation(
                        "consensus_key_registration_shape",
                        "Consensus key registration requires zero amount/recipient and empty data",
                    ));
                }
                registration
                    .validate(tx.from, tx.chain_id)
                    .map_err(|error| BudlumError::validation("invalid_consensus_keys", error))?;

                let min_stake = crate::core::chain_config::Network::from_chain_id(tx.chain_id)
                    .map(|network| network.min_stake())
                    .unwrap_or(1);
                let validator = state.get_validator_mut(&tx.from).ok_or_else(|| {
                    BudlumError::validation(
                        "validator_not_bonded",
                        "Stake must be bonded before consensus keys are registered",
                    )
                })?;
                if validator.active {
                    return Err(BudlumError::validation(
                        "active_validator_key_rotation_forbidden",
                        "Active validator keys cannot change mid-epoch; unbond before replacement",
                    ));
                }
                validator.vrf_public_key = registration.vrf_public_key.clone();
                validator.bls_public_key = registration.bls_public_key.clone();
                validator.pop_signature = registration.pop_signature.clone();
                validator.pq_public_key = registration.pq_public_key.clone();
                validator.active = validator.stake >= min_stake
                    && validator.is_consensus_ready()
                    && validator.verify_pop_is_valid(tx.chain_id);

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation(
                        "balance_underflow",
                        "Consensus key registration fee underflow",
                    )
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::AiOperatorBond => {
                let required = state.required_ai_bond(tx.chain_id);
                if tx.amount < required {
                    return Err(BudlumError::validation(
                        "ai_operator_bond_below_floor",
                        format!(
                            "AI inference layer operator bond {} is below network validator floor {}",
                            tx.amount, required
                        ),
                    ));
                }
                if tx.to != Address::zero() || !tx.data.is_empty() {
                    return Err(BudlumError::validation(
                        "ai_operator_bond_shape",
                        "AI inference layer operator bond requires zero recipient and empty data",
                    ));
                }
                if state.spendable_balance(&tx.from) < total_cost {
                    return Err(BudlumError::validation(
                        "ai_operator_bond_vesting_locked",
                        "AI inference layer operator bond exceeds spendable balance",
                    ));
                }
                state
                    .bond_ai_operator(&tx.from, tx.amount, tx.chain_id)
                    .map_err(|e| {
                        BudlumError::validation("ai_operator_bond_failed", e.to_string())
                    })?;
                // Security audit: AI inference layer operators may submit AI inference results
                // (RoleId=8, verified below); the AI verifier
                // stake is established together with the bond, so the verifier
                // authority check in the registry layer does not refuse these
                // operators. The bond amount is above MIN_VERIFIER_STAKE
                // (the network floor), so the lock succeeds.
                let _ = state
                    .ai_registry
                    .lock_verifier_stake(&tx.from, crate::ai::registry::MIN_VERIFIER_STAKE);
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation(
                        "balance_underflow",
                        "AI inference layer bond fee underflow",
                    )
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::AiOperatorUnbond => {
                if tx.amount != 0 || tx.to != Address::zero() || !tx.data.is_empty() {
                    return Err(BudlumError::validation(
                        "ai_operator_unbond_shape",
                        "AI inference layer unbond requires zero amount/recipient and empty data",
                    ));
                }
                let release_epoch = state
                    .begin_ai_operator_unbonding(&tx.from)
                    .map_err(|error| BudlumError::validation("ai_operator_unbond_failed", error))?;
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation(
                        "balance_underflow",
                        "AI inference layer unbond fee underflow",
                    )
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
                tracing::info!(
                    operator = %tx.from,
                    release_epoch,
                    "AI inference layer operator entered unbonding"
                );
            }
            TransactionType::AiOperatorWithdraw => {
                if tx.amount != 0 || tx.to != Address::zero() || !tx.data.is_empty() {
                    return Err(BudlumError::validation(
                        "ai_operator_withdraw_shape",
                        "AI inference layer withdrawal requires zero amount/recipient and empty data",
                    ));
                }
                let withdrawn = state
                    .withdraw_ai_operator(&tx.from, tx.fee)
                    .map_err(|error| {
                        BudlumError::validation("ai_operator_withdraw_failed", error)
                    })?;
                tracing::info!(
                    operator = %tx.from,
                    amount = withdrawn,
                    "AI inference layer operator bond withdrawn"
                );
            }
            TransactionType::Unstake => {
                let current_stake = state
                    .get_validator(&tx.from)
                    .map(|v| v.stake)
                    .ok_or_else(|| BudlumError::validation("not_validator", "Not a validator"))?;
                if current_stake < tx.amount {
                    return Err(BudlumError::validation(
                        "insufficient_stake",
                        "Insufficient stake",
                    ));
                }

                for proposal in state.governance.proposals.iter_mut() {
                    if proposal.status == crate::core::governance::ProposalStatus::Active {
                        proposal.reduce_vote_weight(&tx.from, tx.amount);
                    }
                }

                if let Some(validator) = state.get_validator_mut(&tx.from) {
                    validator.stake = validator.stake.checked_sub(tx.amount).ok_or_else(|| {
                        BudlumError::validation("stake_underflow", "stake underflow")
                    })?;
                    if validator.stake == 0 {
                        validator.active = false;
                    }
                }

                // The unbonding window is a governance parameter
                // (`RegistryParams::unbonding_epochs`, whitelisted in
                // `GOVERNANCE_PARAMETER_WHITELIST`). Reading the compile-time
                // Constant here made every accepted governance vote a no-op on
                // The only path that actually queues validator stake: the
                // Registry stored the new window, the ledger kept releasing
                // After the hard-coded 7. `PermissionlessRegistry::begin_unbonding`
                // Already reads the parameter, so the two views disagreed.
                let unbonding_epochs = state.registry.params().unbonding_epochs;
                state
                    .unbonding_queue
                    .push(crate::core::account::UnbondingEntry {
                        address: tx.from,
                        amount: tx.amount,
                        release_epoch: state.epoch_index.saturating_add(unbonding_epochs),
                    });

                // Mirror the reduced stake into the permissionless registry.
                // `Stake` calls this; `Unstake` did not, so the registry kept
                // Showing the pre-unstake stake forever. `registry.is_active`
                // Is what the liveness / invalid-vote slashing paths and the
                // RPC member views consult, and `registry.root()` is hashed
                // Into the state root, so the stale entry was consensus state.
                state.sync_validator_registration(&tx.from);

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::Vote => {
                if tx.data.len() > 9 {
                    let required_fee = state.required_governance_proposal_fee(&tx.from);
                    if tx.fee < required_fee {
                        return Err(BudlumError::validation(
                            "governance_proposal_fee_too_low",
                            format!(
                                "Governance proposal fee {} is below escalating requirement {}",
                                tx.fee, required_fee
                            ),
                        ));
                    }
                }
                let sender_acc = state.get_or_create(&tx.from);
                sender_acc.balance = sender_acc.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender_acc.nonce = sender_acc.nonce.saturating_add(1);

                if tx.to != Address::zero() {
                    if let Some(target) = state.get_validator_mut(&tx.to) {
                        if tx.amount > 0 {
                            target.votes_for += 1;
                        } else {
                            target.votes_against += 1;
                        }
                    }
                } else if !tx.data.is_empty() && tx.data.len() >= 9 {
                    if tx.data.len() == 9 {
                        let vote_for = tx.data[0] != 0;
                        let mut id_bytes = [0u8; 8];
                        id_bytes.copy_from_slice(&tx.data[1..9]);
                        let proposal_id = u64::from_le_bytes(id_bytes);

                        let voter_stake = state.get_validator(&tx.from).map_or(0, |v| v.stake);
                        if voter_stake == 0 {
                            return Err(BudlumError::validation(
                                "governance_voter_not_validator",
                                "Only validators can vote in governance",
                            ));
                        }

                        if let Some(proposal) = state.governance.find_proposal_mut(proposal_id) {
                            proposal
                                .add_vote(tx.from, voter_stake, vote_for, state.epoch_index)
                                .map_err(|e| {
                                    BudlumError::validation("governance_vote_failed", e)
                                })?;
                        }
                    } else {
                        let mut duration_bytes = [0u8; 8];
                        duration_bytes.copy_from_slice(&tx.data[0..8]);
                        let duration = u64::from_le_bytes(duration_bytes);
                        let p_type: crate::core::governance::ProposalType =
                            serde_json::from_slice(&tx.data[8..]).map_err(|e| {
                                BudlumError::validation(
                                    "governance_proposal_invalid",
                                    e.to_string(),
                                )
                            })?;

                        let proposer_stake = state.get_validator(&tx.from).map_or(0, |v| v.stake);
                        if proposer_stake == 0 {
                            return Err(BudlumError::validation(
                                "governance_proposer_not_validator",
                                "Only active validators can create proposals",
                            ));
                        }

                        // The submitted flat transaction fee already carries
                        // The full escalating proposal price checked above. Do
                        // Not levy a second hidden debit: the fee-only protocol
                        // Must route the charged amount through block settlement.
                        state
                            .governance
                            .create_proposal(tx.from, p_type, state.epoch_index, duration)
                            .map_err(|e| {
                                BudlumError::validation("governance_proposal_creation_failed", e)
                            })?;
                    }
                }
            }
            TransactionType::ContractCall => {
                let receipt = ZkVmExecutor::execute_bytecode(&tx.data, DEFAULT_CONTRACT_GAS_LIMIT)
                    .map_err(|e| BudlumError::validation("contract_execution_failed", e))?;

                if !receipt.events.is_empty()
                    && receipt.events[0] == 0x00A1_00A1
                    && receipt.events.len() >= 4
                {
                    let mut model_id = [0u8; 32];
                    model_id[0..8].copy_from_slice(&receipt.events[1].to_le_bytes());
                    let max_fee = receipt.events[2];
                    // Use current_block_height instead of
                    // Epoch_index * 100 approximation for consistency.
                    let deadline_block =
                        state.current_block_height.saturating_add(receipt.events[3]);
                    let mut req = crate::ai::types::AiInferenceRequest {
                        request_id: crate::ai::types::AiRequestId::default(),
                        requester: tx.from,
                        model_id: crate::ai::types::AiModelId(model_id),
                        input_commitment: crate::core::transaction::Transaction::signing_hash(tx),
                        input_ref: crate::ai::types::BoundedBytes::try_new(tx.data.clone())
                            .unwrap_or_default(),
                        max_fee,
                        callback: Some(tx.from),
                        submitted_at_block: state.current_block_height,
                        deadline_block,
                        effort: crate::ai_inference::effort::EffortTier::default(),
                        perception: None,
                    };
                    req.request_id = req.calculate_id();
                    // The closed-loop read declaration (V3): the contract path passes through the
                    // same gate. Old contract calls carrying no declaration are
                    // refused fail-closed - a request that does not say what it reads
                    // is the way to feed an image to a text model.
                    crate::ai_inference::admit_inference_request(&state.ai_registry, &req)
                        .map_err(|e| BudlumError::validation("ai_perception_rejected", e))?;
                    let current_block = state.current_block_height;
                    let pollen_grant = state
                        .marketplace
                        .validate_ai_read_ref(req.input_ref.as_slice(), &tx.from, current_block)
                        .map_err(|e| BudlumError::validation("ai_data_access_denied", e))?;
                    // Sender must have sufficient balance
                    // For max_fee escrow BEFORE submitting. Without this, an
                    // Account with 0 balance can submit requests (the
                    // Saturating_sub silently keeps it at 0 - fee leak).
                    // `spendable_balance`, not `get_balance`: the vesting lock
                    // is a spend gate, and an escrow is a spend. Transfer and
                    // AiOperatorBond already ask the gated question; the
                    // three paths that asked the raw one let the team account
                    // move locked $BUD by choosing a different transaction
                    // type. The instance was reported on one path, so the
                    // class is closed on all of them.
                    let sender_balance = state.spendable_balance(&tx.from);
                    if sender_balance < max_fee {
                        return Err(BudlumError::validation(
                            "ai_insufficient_balance_for_escrow",
                            format!("Insufficient balance for max_fee escrow: have {sender_balance}, need {max_fee}"),
                        ));
                    }
                    // Previously the error was silently swallowed
                    // With `let _ = ...`, and max_fee was never deducted from the
                    // Sender's balance. Now we properly handle the result:
                    // - On success: deduct max_fee from sender balance (escrow)
                    // - On failure: don't deduct max_fee, but the contract call
                    //   Fee was already consumed by the ZKVM execution
                    match state.ai_registry.submit_request(req, current_block) {
                        Ok(_) => {
                            if let Some(grant_id) = pollen_grant {
                                state
                                    .marketplace
                                    .consume_ai_read_grant(&grant_id, &tx.from, current_block)
                                    .map_err(|e| {
                                        BudlumError::validation("ai_data_access_denied", e)
                                    })?;
                            }
                            // Deduct max_fee from sender (escrow for verifiers)
                            let sender = state.get_or_create(&tx.from);
                            sender.balance =
                                sender.balance.checked_sub(max_fee).ok_or_else(|| {
                                    BudlumError::validation(
                                        "balance_underflow",
                                        "balance underflow",
                                    )
                                })?;
                        }
                        Err(_) => {
                            // Request rejected (deadline, max_fee=0, etc.)
                            // Max_fee NOT deducted - no fee leak
                        }
                    }
                }

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::BnsRegister => {
                let (name, duration): (String, u64) = bincode::deserialize(&tx.data)
                    .map_err(|e| BudlumError::validation("bns_invalid_data", e.to_string()))?;

                let cost = state.bns_registry.calculate_cost(&name, duration);
                if tx.amount < cost {
                    return Err(BudlumError::validation(
                        "bns_insufficient_payment",
                        format!(
                            "Required: {cost}, provided: {amount}",
                            cost = cost,
                            amount = tx.amount
                        ),
                    ));
                }

                state
                    .bns_registry
                    .register(name, tx.from, state.epoch_index, duration)
                    .map_err(|e| {
                        BudlumError::validation("bns_registration_failed", e.to_string())
                    })?;

                let sender = state.get_or_create(&tx.from);
                // SECURITY H1 FIX: Only subtract exact cost
                sender.balance = sender
                    .balance
                    .checked_sub(tx.fee)
                    .ok_or_else(|| {
                        BudlumError::validation(
                            "balance_underflow",
                            "balance underflow on fee deduction",
                        )
                    })?
                    .checked_sub(cost)
                    .ok_or_else(|| {
                        BudlumError::validation(
                            "balance_underflow",
                            "balance underflow on cost deduction",
                        )
                    })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::BnsSetContent => {
                let (name, cid): (String, crate::storage::content_id::ContentId) =
                    bincode::deserialize(&tx.data)
                        .map_err(|e| BudlumError::validation("bns_invalid_data", e.to_string()))?;

                state
                    .bns_registry
                    .set_content(&name, &tx.from, cid)
                    .map_err(|e| {
                        BudlumError::validation("bns_set_content_failed", e.to_string())
                    })?;

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::BnsRegisterSubdomain => {
                let (parent, label, sub_owner): (String, String, Address) =
                    bincode::deserialize(&tx.data)
                        .map_err(|e| BudlumError::validation("bns_invalid_data", e.to_string()))?;

                state
                    .bns_registry
                    .register_subdomain(&parent, label, sub_owner, &tx.from)
                    .map_err(|e| BudlumError::validation("bns_subdomain_failed", e.to_string()))?;

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::BnsSetStorage => {
                let (name, root, dom_id): (String, [u8; 32], u32) = bincode::deserialize(&tx.data)
                    .map_err(|e| BudlumError::validation("bns_invalid_data", e.to_string()))?;

                state
                    .bns_registry
                    .set_storage(&name, tx.from, root, dom_id, state.epoch_index)
                    .map_err(|e| {
                        BudlumError::validation("bns_set_storage_failed", e.to_string())
                    })?;

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::NftMint => {
                let (cid, author): (crate::storage::content_id::ContentId, Option<String>) =
                    bincode::deserialize(&tx.data)
                        .map_err(|e| BudlumError::validation("nft_invalid_data", e.to_string()))?;

                // A duplicate id means the registry's counter disagrees with
                // its own contents, which `mint` refuses rather than
                // overwriting somebody's NFT. Surfaced as a validation error
                // so the block is rejected instead of silently reassigning
                // ownership.
                state
                    .nft_registry
                    .mint(tx.from, cid, state.epoch_index, author)
                    .map_err(|e| BudlumError::validation("nft_mint_refused", e.to_string()))?;

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::NftTransfer => {
                let (id, to): (u64, Address) = bincode::deserialize(&tx.data)
                    .map_err(|e| BudlumError::validation("nft_invalid_data", e.to_string()))?;

                state
                    .nft_registry
                    .transfer(id, &tx.from, to)
                    .map_err(|e| BudlumError::validation("nft_transfer_failed", e.to_string()))?;

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::NftBurn => {
                let id: u64 = bincode::deserialize(&tx.data)
                    .map_err(|e| BudlumError::validation("nft_invalid_data", e.to_string()))?;

                let cid = state
                    .nft_registry
                    .burn(id, &tx.from)
                    .map_err(|e| BudlumError::validation("nft_burn_failed", e.to_string()))?;

                // Constitution section 1: when an NFT is burned the data is physically deleted from B.U.D. storage.
                // Physical pruning is handled at Blockchain level (storage_registry.prune_content);
                // Here we record the CID for the post-block prune hook.
                tracing::info!(%cid, "NftBurn recorded - storage content pruning delegated to blockchain");

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::NftBoost { nft_id, amount } => {
                let amount = *amount;
                // Prevent saturating_mul overflow
                if amount > u64::MAX / 100 {
                    return Err(BudlumError::validation(
                        "boost_amount_too_large",
                        format!(
                            "Boost amount {} exceeds safe maximum {}",
                            amount,
                            u64::MAX / 100
                        ),
                    ));
                }
                let bud_share = amount.checked_mul(4).ok_or_else(|| {
                    BudlumError::validation("share_overflow", "bud_share overflow")
                })? / 100;
                let creator_share = amount.checked_mul(16).ok_or_else(|| {
                    BudlumError::validation("share_overflow", "creator_share overflow")
                })? / 100;
                let protocol_share = amount
                    .checked_sub(bud_share)
                    .ok_or_else(|| {
                        BudlumError::validation("share_underflow", "bud_share exceeds amount")
                    })?
                    .checked_sub(creator_share)
                    .ok_or_else(|| {
                        BudlumError::validation(
                            "share_underflow",
                            "creator_share exceeds remainder",
                        )
                    })?;

                let nft = state
                    .nft_registry
                    .get_nft(*nft_id)
                    .cloned()
                    .ok_or(BudlumError::validation("nft_not_found", "NFT not found"))?;

                let booster = state.get_or_create(&tx.from);
                if booster.balance
                    < amount.checked_add(tx.fee).ok_or_else(|| {
                        BudlumError::validation("cost_overflow", "boost cost overflow")
                    })?
                {
                    return Err(BudlumError::validation(
                        "insufficient_funds",
                        "Cannot afford boost",
                    ));
                }
                booster.balance = booster
                    .balance
                    .checked_sub(amount)
                    .ok_or_else(|| {
                        BudlumError::validation("balance_underflow", "boost amount underflow")
                    })?
                    .checked_sub(tx.fee)
                    .ok_or_else(|| {
                        BudlumError::validation("balance_underflow", "boost fee underflow")
                    })?;
                booster.nonce = booster.nonce.saturating_add(1);

                let creator = state.get_or_create(&nft.owner);
                // Checked add for creator share credit
                creator.balance = creator.balance.checked_add(creator_share).ok_or_else(|| {
                    BudlumError::validation("balance_overflow", "NFT boost creator share overflow")
                })?;

                // F4 (Constitution §3): route 4% B.U.D. share to storage operator pool.
                // Distributed by blockchain after block commit via distribute_bud_boost_share.
                state.pending_bud_boost_share = state
                    .pending_bud_boost_share
                    .checked_add(bud_share)
                    .ok_or_else(|| {
                        BudlumError::validation(
                            "pending_share_overflow",
                            "pending bud boost share overflow",
                        )
                    })?;

                // F4 treasury_pool (Q-X4 config_driven): 80% protocol share goes to burn_reserve (treasury) if set,
                // Otherwise implicit burn (honest fallback). This makes Treasury/Burn explicit per Constitution §3.
                // Analysis: "Implicit burn" is CORRECT - the booster's
                // Balance was already reduced by `amount`, and only `creator_share`
                // + `bud_share` are credited elsewhere. The remaining `protocol_share`
                // (80%) is effectively burned because it leaves no account balance.
                // This is equivalent to deducting from booster and not crediting
                // Anyone - circulating_supply strictly decreases. No fix needed.
                if protocol_share > 0 {
                    if let Some(treasury_addr) = state.burn_reserve_address {
                        let treasury = state.get_or_create(&treasury_addr);
                        // Checked add for treasury credit
                        treasury.balance = treasury
                            .balance
                            .checked_add(protocol_share)
                            .ok_or_else(|| {
                                BudlumError::validation(
                                    "balance_overflow",
                                    "Protocol treasury share overflow",
                                )
                            })?;
                        tracing::info!(
                            nft_id = %nft_id,
                            protocol_treasury = %treasury_addr,
                            protocol_fee = %protocol_share,
                            "SocialFi: Protocol treasury credited (80%)"
                        );
                    } else {
                        tracing::info!(
                            nft_id = %nft_id,
                            protocol_fee = %protocol_share,
                            "SocialFi: Protocol fee burned (no treasury set, Constitution Treasury/Burn)"
                        );
                    }
                }

                tracing::info!(nft_id = %nft_id, creator_reward = %creator_share, bud_share = %bud_share, protocol_fee = %protocol_share, "SocialFi: Content Boosted");
            }
            TransactionType::NftUpdateLight { nft_id, delta_mcd } => {
                // Real luminance update with ownership check.
                let nft = state
                    .nft_registry
                    .get_nft(*nft_id)
                    .ok_or(BudlumError::validation("nft_not_found", "NFT not found"))?;
                // Only the NFT owner can update its luminance.
                if nft.owner != tx.from {
                    return Err(BudlumError::validation(
                        "not_owner",
                        "Only the NFT owner can update luminance",
                    ));
                }
                state
                    .nft_registry
                    .update_luminance(*nft_id, *delta_mcd)
                    .map_err(|e| BudlumError::validation("luminance_update", e.to_string()))?;
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::NftTag { nft_id, tag } => {
                let _ = (nft_id, tag);
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::UniversalRelay(ext_tx) => {
                tracing::info!(chain = ?ext_tx.chain, target = %ext_tx.target_address, from = %tx.from, "Universal Relayer: permissionless relay request (fee-paid)");
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::RelayerResult(res) => {
                // Relayer EVM Proofs - cryptographic verification.
                if res.receipt_proof.is_empty() {
                    return Err(BudlumError::validation(
                        "relayer_invalid_proof",
                        "Receipt proof cannot be empty",
                    ));
                }
                // Verify external_state_root non-zero
                // (zero root = no state commitment, can't verify anything).
                if res.external_state_root == [0u8; 32] {
                    return Err(BudlumError::validation(
                        "relayer_zero_root",
                        "External state root cannot be zero",
                    ));
                }
                // A Merkle proof only proves consistency with a declared
                // Root. Economic bridge effects additionally require that
                // Root to be present in the consensus-owned, finalized
                // External-root registry. A relayer cannot create that
                // Anchor by submitting this transaction.
                let domain_id = res.chain.domain_id();
                match state.external_roots.get(&domain_id) {
                    Some(finalized_root) if finalized_root == &res.external_state_root => {}
                    _ => {
                        return Err(BudlumError::validation(
                            "relayer_unanchored_root",
                            "external state root has no finalized light-client anchor",
                        ));
                    }
                }
                // / real cryptographic verification.
                // Receipt_proof = bincode(MerkleProof); leaf'in
                // it is proved that the leaf is a BDLM_RELAYER_RESULT_V1 result fact and that the path
                // reaches external_state_root. (Anchoring the root to the external
                // finalize commitment is the EVM light-client job;
                // this gate soundly verifies the proof chain itself.)
                let proof: crate::cross_domain::event_tree::MerkleProof =
                    bincode::deserialize(&res.receipt_proof).map_err(|e| {
                        BudlumError::validation("relayer_proof_malformed", e.to_string())
                    })?;
                if proof.leaf != res.result_leaf() {
                    return Err(BudlumError::validation(
                        "relayer_leaf_mismatch",
                        "Proof leaf does not match the declared result facts",
                    ));
                }
                if !proof.verify(res.external_state_root) {
                    return Err(BudlumError::validation(
                        "relayer_proof_invalid",
                        "Merkle proof does not anchor to the declared external state root",
                    ));
                }

                tracing::info!(
                    chain = ?res.chain,
                    tx_hash = %res.tx_hash,
                    success = %res.success,
                    root = %hex::encode(res.external_state_root),
                    proof_len = res.receipt_proof.len(),
                    "Universal Relayer: External result verified and recorded"
                );

                // Bridge state transition from external result
                if let Some(ref msg) = res.message {
                    if res.success {
                        match msg.kind {
                            crate::cross_domain::message::MessageKind::BridgeLock => {
                                // Inbound lock from external chain -> Mint on Budlum.
                                // The amounts and the ceiling are settled before the
                                // bridge state moves: once `mint` has run, the replay
                                // id is spent and the transfer reads as minted, so a
                                // refusal after it would leave a consumed lock with
                                // nothing, or only part, credited.
                                let transfer = state
                                    .bridge_state
                                    .get_transfer(&msg.message_id)
                                    .ok_or_else(|| {
                                        BudlumError::validation(
                                            "bridge_mint_failed",
                                            "Unknown bridge transfer for mint",
                                        )
                                    })?
                                    .clone();
                                let params = *state.registry.params();
                                let (final_amount, fee) =
                                    crate::cross_domain::bridge::split_bridge_fee(
                                        transfer.amount,
                                        params.bridge_relayer_fee_ppm,
                                        params.bridge_relayer_min_fee,
                                    )
                                    .map_err(|e| {
                                        BudlumError::validation("bridge_fee_below_minimum", e.0)
                                    })?;
                                if final_amount > u64::MAX as u128 {
                                    return Err(BudlumError::validation(
                                        "bridge_mint_failed",
                                        "Bridge amount exceeds maximum representable balance",
                                    ));
                                }
                                if fee > u64::MAX as u128 {
                                    return Err(BudlumError::validation(
                                        "bridge_mint_failed",
                                        "Bridge fee exceeds maximum representable balance",
                                    ));
                                }
                                let minted = (final_amount as u64)
                                    .checked_add(fee as u64)
                                    .ok_or_else(|| {
                                        BudlumError::validation(
                                            "bridge_mint_failed",
                                            "Bridge amount exceeds maximum representable balance",
                                        )
                                    })?;
                                state.ensure_mint_headroom(minted).map_err(|e| {
                                    BudlumError::validation("bridge_mint_overflow", &e)
                                })?;
                                state
                                    .bridge_state
                                    .mint(msg, state.current_block_height)
                                    .map_err(|e| {
                                        BudlumError::validation("bridge_mint_failed", e.0)
                                    })?;
                                // This is the supply-creating path: the on-chain
                                // counterpart of the asset arriving from the bridge
                                // is minted here, the same as in
                                // `Blockchain::mint_bridge_transfer_from_verified_event`.
                                // `try_mint_balance` asks the fixed ceiling; a plain
                                // `try_add_balance` only guarded `u64` overflow, so a
                                // chain already at `BUD_TOTAL_SUPPLY` kept minting
                                // through this entry point while the RPC entry point
                                // refused. The relayer fee comes out of the same mint
                                // and is subject to the same ceiling.
                                state
                                    .try_mint_balance(&transfer.recipient, final_amount as u64)
                                    .map_err(|e| {
                                        BudlumError::validation("bridge_mint_overflow", &e)
                                    })?;
                                // Credit relayer fee to tx.from (the
                                // Relayer who submitted the proof). Previously the fee was
                                // Silently dropped - BUD lost to the void. The submit_relay_proof
                                // Path correctly credits the relayer; this path should too.
                                if fee > 0 {
                                    state.try_mint_balance(&tx.from, fee as u64).map_err(|e| {
                                        BudlumError::validation("bridge_fee_overflow", &e)
                                    })?;
                                }
                            }
                            crate::cross_domain::message::MessageKind::BridgeBurn => {
                                // Inbound burn (from target back to source) -> Unlock on Budlum
                                // Correlation_id is MANDATORY - without it
                                // We cannot identify which transfer to unlock. Also, owner
                                // Balance must be refunded after unlock (1% relayer fee
                                // Deducted, consistent with submit_relay_proof).
                                let transfer_id = msg.correlation_id.ok_or_else(|| {
                                    BudlumError::validation(
                                        "bridge_unlock_failed",
                                        "Bridge burn message missing correlation_id",
                                    )
                                })?;
                                let transfer = state
                                    .bridge_state
                                    .get_transfer(&transfer_id)
                                    .ok_or_else(|| {
                                        BudlumError::validation(
                                            "bridge_unlock_failed",
                                            "Unknown bridge transfer for unlock",
                                        )
                                    })?
                                    .clone();
                                // The check the other unlock path already had.
                                // Both paths now call the same rule, so the
                                // answer no longer depends on which entry
                                // point the message came through.
                                crate::cross_domain::bridge::check_burn_matches_lock_domain(
                                    transfer.source_domain,
                                    msg.target_domain,
                                )
                                .map_err(|e| {
                                    BudlumError::validation("bridge_unlock_failed", e.0)
                                })?;
                                state
                                    .bridge_state
                                    .unlock(
                                        transfer_id,
                                        msg.source_domain,
                                        state.current_block_height,
                                    )
                                    .map_err(|e| {
                                        BudlumError::validation("bridge_unlock_failed", e.0)
                                    })?;
                                // Refund owner (1% relayer fee deducted, same as submit_relay_proof)
                                let params = *state.registry.params();
                                let (final_amount, fee) =
                                    crate::cross_domain::bridge::split_bridge_fee(
                                        transfer.amount,
                                        params.bridge_relayer_fee_ppm,
                                        params.bridge_relayer_min_fee,
                                    )
                                    .map_err(|e| {
                                        BudlumError::validation("bridge_fee_below_minimum", e.0)
                                    })?;
                                if final_amount > u64::MAX as u128 {
                                    return Err(BudlumError::validation(
                                        "bridge_unlock_failed",
                                        "Unlock amount exceeds maximum representable balance",
                                    ));
                                }
                                // Use try_add_balance instead of add_balance
                                state
                                    .try_add_balance(&transfer.owner, final_amount as u64)
                                    .map_err(|e| {
                                        BudlumError::validation("bridge_unlock_overflow", &e)
                                    })?;
                                // Fix: Credit relayer fee
                                // To tx.from on unlock. Use try_add_balance for overflow safety.
                                if fee > 0 {
                                    state.try_add_balance(&tx.from, fee as u64).map_err(|e| {
                                        BudlumError::validation("bridge_unlock_fee_overflow", &e)
                                    })?;
                                }
                            }
                            _ => {}
                        }
                    }
                }

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::AiOfferData { cid, price } => {
                state
                    .marketplace
                    .create_offer(tx.from, *cid, *price)
                    .map_err(|e| BudlumError::validation("offer_invalid", e))?;
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::AiPurchaseData { offer_id } => {
                let offer = state.marketplace.get_offer(*offer_id).cloned().ok_or(
                    BudlumError::validation("offer_not_found", "Offer not found"),
                )?;
                if !offer.active {
                    return Err(BudlumError::validation(
                        "marketplace_offer_inactive",
                        "Offer inactive",
                    ));
                }

                // SECURITY H2 FIX
                state
                    .marketplace
                    .close_offer(*offer_id, &offer.seller)
                    .map_err(|e| BudlumError::validation("race", e))?;

                let total_cost = offer.price.checked_add(tx.fee).ok_or_else(|| {
                    BudlumError::validation("cost_overflow", "offer cost overflow")
                })?;
                // Vesting-gated, same reason as the escrow path above.
                if state.spendable_balance(&tx.from) < total_cost {
                    return Err(BudlumError::validation("funds", "Insufficient funds"));
                }

                let buyer = state.get_or_create(&tx.from);
                buyer.balance = buyer.balance.checked_sub(total_cost).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                buyer.nonce = buyer.nonce.saturating_add(1);

                let seller = state.get_or_create(&offer.seller);
                // Checked add for seller credit
                seller.balance = seller.balance.checked_add(offer.price).ok_or_else(|| {
                    BudlumError::validation("balance_overflow", "Marketplace sale credit overflow")
                })?;
            }
            TransactionType::BudlumxyzRegisterApp {
                name,
                category,
                website_url,
                manifest_id,
            } => {
                // / M5: an anti-sybil registration fee. Symmetric with the H1 pattern
                // in the BNS branch: the exact minimum fee is required and fully deducted.
                if tx.amount < crate::budlumxyz::BUDLUMXYZ_REGISTER_MIN_FEE {
                    return Err(BudlumError::validation(
                        "hub_insufficient_fee",
                        format!(
                            "App registration requires {} fee, provided: {}",
                            crate::budlumxyz::BUDLUMXYZ_REGISTER_MIN_FEE,
                            tx.amount
                        ),
                    ));
                }
                // A duplicate id means the registry's counter disagrees with
                // its own contents. Refused rather than overwriting another
                // developer's listing, and refused here, before the fee is
                // taken below: charging for a registration that did not
                // happen would be the worse of the two failures.
                state
                    .budlumxyz
                    .register_app(
                        name.clone(),
                        tx.from,
                        category.clone(),
                        website_url.clone(),
                        *manifest_id,
                        state.epoch_index,
                    )
                    .map_err(|e| BudlumError::validation("hub_register_refused", e.to_string()))?;
                let sender = state.get_or_create(&tx.from);
                // Balance check before deduction
                let hub_total = tx
                    .fee
                    .checked_add(crate::budlumxyz::BUDLUMXYZ_REGISTER_MIN_FEE)
                    .ok_or_else(|| {
                        BudlumError::validation("cost_overflow", "hub total cost overflow")
                    })?;
                if sender.balance < hub_total {
                    return Err(BudlumError::validation(
                        "insufficient_funds",
                        format!(
                            "Hub registration requires {}, balance: {}",
                            hub_total, sender.balance
                        ),
                    ));
                }
                sender.balance = sender
                    .balance
                    .checked_sub(tx.fee)
                    .ok_or_else(|| {
                        BudlumError::validation("balance_underflow", "hub fee underflow")
                    })?
                    .checked_sub(crate::budlumxyz::BUDLUMXYZ_REGISTER_MIN_FEE)
                    .ok_or_else(|| {
                        BudlumError::validation("balance_underflow", "hub register fee underflow")
                    })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::BudlumxyzAttestApp { app_id } => {
                // Ownership proof, not audit. `attest_app_as_developer`
                // refuses unless `tx.from` is the app's registered developer,
                // and that refusal is the whole point of the transaction:
                // before this existed, `developer_attested` and `verified`
                // were hashed into the state root and no path could ever set
                // either, so both were permanently false and the two bits
                // were state that could not change.
                state
                    .budlumxyz
                    .attest_app_as_developer(*app_id, &tx.from)
                    .map_err(|e| BudlumError::validation("hub_attest_refused", e.to_string()))?;
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "hub attest fee underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::AiModelRegister(spec) => {
                let mut spec = spec.clone();
                if spec.owner != tx.from {
                    spec.owner = tx.from;
                }
                // The anti-sybil registration fee (governance adjustable,
                // RegistryParams::ai_model_register_fee). Exact cost: less is
                // refused; the whole amount is added on top of the fee. A tier 2 decision
                // (2026-08-14): an economic parameter, set by governance -
                // not hard-coded.
                let reg_fee = state.registry.params().ai_model_register_fee;
                if reg_fee > 0 && tx.amount < reg_fee {
                    return Err(BudlumError::validation(
                        "ai_model_register_fee_insufficient",
                        format!(
                            "AI model registration requires amount >= {reg_fee} (governance-tunable)"
                        ),
                    ));
                }
                state
                    .ai_registry
                    .register_model(spec)
                    .map_err(|e| BudlumError::validation("ai_model_registration_failed", e))?;
                let sender = state.get_or_create(&tx.from);
                let total = tx.fee.checked_add(reg_fee).ok_or_else(|| {
                    BudlumError::validation("cost_overflow", "AI register cost overflow")
                })?;
                if sender.balance < total {
                    return Err(BudlumError::validation(
                        "insufficient_funds",
                        format!(
                            "AI registration requires {total}, balance: {}",
                            sender.balance
                        ),
                    ));
                }
                sender.balance = sender.balance.checked_sub(total).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "AI fee underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::AiInferenceRequest(req) => {
                let mut req = req.clone();
                if req.requester != tx.from {
                    req.requester = tx.from;
                }
                {
                    // Security audit (MEDIUM): the direct AI inference path was bypassing
                    // the vesting spendable gate. Escrow is a spend;
                    // a vesting-locked balance cannot enter escrow (the same gate as
                    // AiOperatorBond).
                    let sender_balance = state.spendable_balance(&tx.from);
                    if sender_balance
                        < req.max_fee.checked_add(tx.fee).ok_or_else(|| {
                            BudlumError::validation("cost_overflow", "AI cost overflow")
                        })?
                    {
                        return Err(BudlumError::validation(
                            "ai_insufficient_fee_balance",
                            "Sender balance insufficient for AI inference request max_fee",
                        ));
                    }
                }
                // Executor-layer deadline enforcement (defense-in-depth):
                let current_block = state.current_block_height;
                // The closed-loop read declaration (V3): requests without a declaration are
                // refused fail-closed (see ai_inference::admit_inference_request).
                crate::ai_inference::admit_inference_request(&state.ai_registry, &req)
                    .map_err(|e| BudlumError::validation("ai_perception_rejected", e))?;
                let pollen_grant = state
                    .marketplace
                    .validate_ai_read_ref(req.input_ref.as_slice(), &tx.from, current_block)
                    .map_err(|e| BudlumError::validation("ai_data_access_denied", e))?;
                state
                    .ai_registry
                    .submit_request(req.clone(), current_block)
                    .map_err(|e| BudlumError::validation("ai_request_failed", e))?;
                if let Some(grant_id) = pollen_grant {
                    state
                        .marketplace
                        .consume_ai_read_grant(&grant_id, &tx.from, current_block)
                        .map_err(|e| BudlumError::validation("ai_data_access_denied", e))?;
                }
                // Balance check before deduction (spendable: the vesting gate -
                // finding #356; the deduction comes from the spendable part and the lock
                // is not broken because the first gate already verified spendable).
                // spendable is read BEFORE the mutable borrow of `get_or_create`
                // (E0502): if the account does not exist spendable is 0, and it is 0 after
                // creation too - reordering does not change behaviour.
                let ai_total = tx.fee.checked_add(req.max_fee).ok_or_else(|| {
                    BudlumError::validation("cost_overflow", "AI total cost overflow")
                })?;
                let spendable = state.spendable_balance(&tx.from);
                if spendable < ai_total {
                    return Err(BudlumError::validation(
                        "insufficient_funds",
                        format!(
                            "AI inference requires {}, spendable: {}",
                            ai_total, spendable
                        ),
                    ));
                }
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender
                    .balance
                    .checked_sub(tx.fee)
                    .ok_or_else(|| {
                        BudlumError::validation("balance_underflow", "AI fee underflow")
                    })?
                    .checked_sub(req.max_fee)
                    .ok_or_else(|| {
                        BudlumError::validation("balance_underflow", "AI max_fee underflow")
                    })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::AiInferenceResult(res) => {
                // AI inference layer production authorization is permissionless but bonded:
                // Only an active RoleId(8) operator may submit inference results.
                // A PoS validator, legacy AI_VERIFIER role, or governance
                // Whitelist entry is not an implicit AI inference layer operator bond.
                if !state
                    .registry
                    .is_active(&tx.from, crate::registry::role::roles::AI_OPERATOR)
                {
                    return Err(BudlumError::validation(
                        "ai_operator_unauthorized",
                        "Inference result signer must be an active bonded AI_OPERATOR (RoleId=8)",
                    ));
                }
                let mut res = res.clone();
                if res.verifier != tx.from {
                    res.verifier = tx.from;
                }
                // Executor-layer deadline enforcement (defense-in-depth):
                let current_block = state.current_block_height;
                // The dispute clock is consensus block time, never a
                // Submitter-controlled payload field.
                res.submitted_at_block = current_block;
                let outcome = match state.ai_registry.submit_result(res.clone(), current_block) {
                    Ok(outcome) => outcome,
                    Err(error) if crate::ai::registry::is_equivocation_error(&error) => {
                        // The conflicting outer transaction is itself signed by
                        // The bonded operator. Commit the registry's evidence
                        // Marker and charge the tx instead of rolling the marker
                        // Back with a failed state transition.
                        tracing::warn!(
                            operator = %tx.from,
                            request_id = %res.request_id.to_hex(),
                            "AI inference layer equivocation evidence committed"
                        );
                        None
                    }
                    Err(error) => {
                        return Err(BudlumError::validation("ai_result_failed", error));
                    }
                };

                if let Some(finalized) = outcome {
                    let req = state.ai_registry.requests.get(&finalized.request_id);
                    if let Some(req) = req {
                        // The `req` borrow ends here; the bridge works through the copied
                        // `requester` and the local `res` - it does not clash with the mutable
                        // `state` access of the reward loop.
                        let requester = req.requester;
                        if !finalized.agreeing_verifiers.is_empty() {
                            // Integer division remainder protection.
                            // Max_fee / verifier_count loses the remainder.
                            // Distribute remaining units to verifiers in order
                            // (first verifier gets the extra unit).
                            let verifier_count = finalized.agreeing_verifiers.len() as u64;
                            let reward_per_verifier = req.max_fee / verifier_count;
                            let remainder = req.max_fee % verifier_count;
                            for (i, verifier_addr) in
                                finalized.agreeing_verifiers.iter().enumerate()
                            {
                                let acc = state.get_or_create(verifier_addr);
                                let extra = if (i as u64) < remainder { 1 } else { 0 };
                                // Checked add for verifier reward
                                let reward = reward_per_verifier + extra;
                                acc.balance = acc.balance.checked_add(reward).ok_or_else(|| {
                                    BudlumError::validation(
                                        "balance_overflow",
                                        "AI verifier reward overflow",
                                    )
                                })?;
                            }
                        }
                        // The SocialFi bridge (best effort): a finalized AI inference layer
                        // output is minted to the requester as a "ai-inference" NFT.
                        // A failure is NOT a block refusal - the inference result
                        // is already final; the bridge is a product surface, not a consensus
                        // condition. A duplicate ContentId (the same output in two
                        // requests) is only logged.
                        // Tier 1 because letting the NFT path refuse a block would
                        // roll back a finalized inference result.
                        let output_bytes = res.output_ref.as_slice().to_vec();
                        let content_id = crate::storage::content_id::ContentId::of(&output_bytes);
                        if let Err(e) = crate::ai_inference::social::ai_output_to_nft(
                            &mut state.nft_registry,
                            requester,
                            &output_bytes,
                            state.epoch_index,
                        ) {
                            tracing::warn!(%e, "ai_inference output NFT mint skipped (best-effort)");
                        }
                        // The Pollen bridge (the reverse direction, the same best-effort block):
                        // the output is also recorded as a DataAsset -
                        // manifest_id = NFT'nin ContentId'si, metadata
                        // the commitment is the finalized output commitment. That way
                        // the NFT owner (the requester) can read their own output again through the
                        // Pollen grant mechanism;
                        // no new closed-loop path is opened, the existing
                        // AiDataInputRef + validate_ai_read_ref path is used.
                        let asset = crate::pollen::data_rights::DataAsset::new(
                            requester,
                            content_id,
                            res.output_commitment,
                            false,
                        );
                        if let Err(e) = state.marketplace.register_data_asset(asset) {
                            tracing::warn!(
                                %e,
                                "ai_inference output DataAsset registration skipped (best-effort)"
                            );
                        }
                    }
                }

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::AiFeeReclaim(request_id) => {
                // Reclaim escrowed max_fee for expired unfinalized request.
                // Only the original requester can reclaim their fee.
                let current_block = state.current_block_height;
                let (requester, max_fee) = state
                    .ai_registry
                    .reclaim_fee(request_id, current_block)
                    .map_err(|e| BudlumError::validation("ai_fee_reclaim_failed", e))?;

                // Only the original requester can reclaim
                if requester != tx.from {
                    return Err(BudlumError::validation(
                        "ai_fee_reclaim_unauthorized",
                        "Only the original requester can reclaim the escrowed fee",
                    ));
                }

                // Use `&requester` (verified by reclaim_fee) instead
                // Of `&tx.from`. These are equal (checked above), but using the verified
                // Value is the canonical pattern and prevents future regressions if the
                // Auth check changes. Same for sender below.
                let requester_acc = state.get_or_create(&requester);
                requester_acc.balance =
                    requester_acc.balance.checked_add(max_fee).ok_or_else(|| {
                        BudlumError::validation("balance_overflow", "AI fee reclaim overflow")
                    })?;

                let sender = state.get_or_create(&requester);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::AiModelDeactivate(model_id) => {
                // Deactivate an AI model (owner-only).
                state
                    .ai_registry
                    .deactivate_model(model_id, &tx.from)
                    .map_err(|e| BudlumError::validation("ai_model_deactivate_failed", e))?;

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::AiModelReactivate(model_id) => {
                // Reactivate a previously
                // Deactivated AI model (owner-only).
                state
                    .ai_registry
                    .reactivate_model(model_id, &tx.from)
                    .map_err(|e| BudlumError::validation("ai_model_reactivate_failed", e))?;

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::AiRequestCancel(request_id) => {
                // Cancel a pending AI inference request.
                // Only the original requester can cancel. Escrowed max_fee
                // Is refunded to the requester.
                let current_block = state.current_block_height;
                let (requester, max_fee) = state
                    .ai_registry
                    .cancel_request(request_id, &tx.from, current_block)
                    .map_err(|e| BudlumError::validation("ai_request_cancel_failed", e))?;

                // Refund escrowed max_fee to the requester
                let requester_acc = state.get_or_create(&requester);
                requester_acc.balance =
                    requester_acc.balance.checked_add(max_fee).ok_or_else(|| {
                        BudlumError::validation("balance_overflow", "AI fee reclaim overflow")
                    })?;

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::PollenRegisterDataAsset(asset) => {
                let mut asset = asset.clone();
                if asset.owner != tx.from {
                    return Err(BudlumError::validation(
                        "pollen_asset_owner_mismatch",
                        "DataAsset owner must equal tx.from",
                    ));
                }
                // Recompute canonical id from immutable fields to prevent forged ids.
                asset.asset_id = crate::pollen::DataAsset::derive_id(
                    &asset.owner,
                    &asset.manifest_id,
                    &asset.metadata_commitment,
                );
                state
                    .marketplace
                    .register_data_asset(asset)
                    .map_err(|e| BudlumError::validation("pollen_asset_register_failed", e))?;
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::PollenAuthorizeSale(authorization) => {
                let authorization = authorization.clone();
                if authorization.seller != tx.from {
                    return Err(BudlumError::validation(
                        "pollen_sale_seller_mismatch",
                        "SaleAuthorization seller must equal tx.from",
                    ));
                }
                state
                    .marketplace
                    .create_sale_authorization(authorization)
                    .map_err(|e| BudlumError::validation("pollen_sale_authorization_failed", e))?;
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::PollenGrantAccess(grant) => {
                let grant = grant.clone();
                // P12-3 conservative rule: until real owner-signature verification
                // Lands, grants are owner-submitted. This prevents buyer-side
                // Forged owner_signature from creating data access.
                if grant.owner != tx.from {
                    return Err(BudlumError::validation(
                        "pollen_grant_owner_mismatch",
                        "AccessGrant owner must equal tx.from",
                    ));
                }
                state
                    .marketplace
                    .create_access_grant(grant)
                    .map_err(|e| BudlumError::validation("pollen_grant_failed", e))?;
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::PollenRevokeGrant(grant_id) => {
                state
                    .marketplace
                    .revoke_access_grant(grant_id, &tx.from)
                    .map_err(|e| BudlumError::validation("pollen_grant_revoke_failed", e))?;
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::PollenRevokeDataAsset(asset_id) => {
                state
                    .marketplace
                    .revoke_data_asset(asset_id, &tx.from)
                    .map_err(|e| BudlumError::validation("pollen_asset_revoke_failed", e))?;
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::AiDisputeSlash {
                request_id,
                verifier,
            } => {
                // Proven same-request conflicting commitments burn the complete
                // RoleId(8) bond. This is application-role evidence: it must not
                // Silently erase an independent PoS validator stake.
                if !state
                    .registry
                    .is_active(verifier, crate::registry::role::roles::AI_OPERATOR)
                {
                    return Err(BudlumError::validation(
                        "ai_slash_operator_inactive",
                        "Equivocation target is not an active bonded AI_OPERATOR",
                    ));
                }
                let current_block = state.current_block_height;
                let (_slashed_operator, _legacy_unbacked_stake) = state
                    .ai_registry
                    .slash_equivocator(request_id, verifier, current_block)
                    .map_err(|e| BudlumError::validation("ai_dispute_slash_failed", e))?;
                let slash = state
                    .registry
                    .slash_role_only(
                        *verifier,
                        crate::registry::role::roles::AI_OPERATOR,
                        crate::registry::permissionless::SlashingCondition::MaliciousBehaviour,
                        crate::core::chain_config::FIXED_POINT_SCALE,
                    )
                    .map_err(|e| BudlumError::validation("ai_role_slash_failed", e.to_string()))?;
                tracing::warn!(
                    operator = %verifier,
                    penalty = slash.penalty,
                    "Burned full AI inference layer RoleId(8) bond for proven equivocation"
                );
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::AiAgentPayment(payment) => {
                // Agent-to-Agent payment in Agentic Economy.
                let current_block = state.current_block_height;
                // From_agent must match tx signer (no spoofed payer).
                if payment.from_agent != tx.from {
                    return Err(BudlumError::validation(
                        "ai_payment_from_spoof",
                        "Agent payment: from_agent must equal tx.from",
                    ));
                }
                let total_cost = payment.amount.checked_add(tx.fee).ok_or_else(|| {
                    BudlumError::validation("cost_overflow", "payment cost overflow")
                })?;
                // Check sender has sufficient *spendable* balance: an agent
                // payment moves value out of the account exactly like a
                // transfer, so the vesting lock applies here too.
                if state.spendable_balance(&tx.from) < total_cost {
                    return Err(BudlumError::validation(
                        "ai_payment_insufficient_funds",
                        "Insufficient funds for agent payment + fee",
                    ));
                }
                // Validate and register the payment
                state
                    .ai_registry
                    .submit_agent_payment(payment.clone(), current_block)
                    .map_err(|e| BudlumError::validation("ai_payment_invalid", e))?;
                // Deduct from sender immediately
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(total_cost).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
                // If not escrowed, credit recipient immediately and ARCHIVE
                // Settlement receipt - never drop payment_id without trail.
                if !payment.is_escrowed() {
                    let recipient = state.get_or_create(&payment.to_agent);
                    recipient.balance =
                        recipient
                            .balance
                            .checked_add(payment.amount)
                            .ok_or_else(|| {
                                BudlumError::validation(
                                    "balance_overflow",
                                    "Agent payment credit overflow",
                                )
                            })?;
                    state
                        .ai_registry
                        .settle_agent_payment_immediate(&payment.payment_id, current_block)
                        .map_err(|e| BudlumError::validation("ai_payment_settle_failed", e))?;
                }
                // If escrowed, balance stays deducted but recipient is not
                // Credited until release_agent_payment is called (by executor
                // On outcome finalization or by explicit release tx).
            }
            TransactionType::AiAgentPaymentRelease(payment_id) => {
                // Release escrowed payment to recipient after outcome finalization.
                // Get amount BEFORE release (release removes the payment from registry).
                let payment_amount = state
                    .ai_registry
                    .get_agent_payment(payment_id)
                    .ok_or_else(|| {
                        BudlumError::validation(
                            "ai_payment_release_failed",
                            "Agent payment: payment_id not found",
                        )
                    })?
                    .amount;
                // Use actual block height instead of
                // Epoch_index * 100 approximation - these are NOT equivalent
                // In general and cause expiry timing inconsistencies.
                let current_block = state.current_block_height;
                let recipient = state
                    .ai_registry
                    .release_agent_payment(payment_id, current_block)
                    .map_err(|e| BudlumError::validation("ai_payment_release_failed", e))?;
                // Credit recipient
                let recipient_acc = state.get_or_create(&recipient);
                recipient_acc.balance = recipient_acc
                    .balance
                    .checked_add(payment_amount)
                    .ok_or_else(|| {
                        BudlumError::validation(
                            "balance_overflow",
                            "Agent payment release overflow",
                        )
                    })?;
                // Deduct fee from sender
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::AiAgentPaymentReclaim(payment_id) => {
                // Reclaim expired escrowed payment back to sender.
                // Use actual block height for consistency.
                let current_block = state.current_block_height;
                let amount = state
                    .ai_registry
                    .reclaim_agent_payment(payment_id, &tx.from, current_block)
                    .map_err(|e| BudlumError::validation("ai_payment_reclaim_failed", e))?;
                // Validate that the sender can cover the fee
                // After reclaim. Previously, if amount < fee, the fee was silently
                // Dropped via saturating_sub (network loses fee revenue). Now we
                // Validate upfront, matching the pattern of all other tx types.
                {
                    let sender = state.get_or_create(&tx.from);
                    let total_available = sender.balance.checked_add(amount).ok_or_else(|| {
                        BudlumError::validation("balance_overflow", "reclaim balance overflow")
                    })?;
                    if total_available < tx.fee {
                        return Err(BudlumError::validation(
                            "ai_payment_reclaim_insufficient_fee",
                            "Reclaimed amount + existing balance insufficient for tx fee",
                        ));
                    }
                }
                // Refund to sender and deduct fee atomically
                // Checked add + sub for reclaim + fee
                let sender = state.get_or_create(&tx.from);
                let new_balance = sender
                    .balance
                    .checked_add(amount)
                    .and_then(|b| b.checked_sub(tx.fee))
                    .ok_or_else(|| {
                        BudlumError::validation(
                            "balance_arithmetic_overflow",
                            "AI payment reclaim + fee arithmetic overflow",
                        )
                    })?;
                sender.balance = new_balance;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::PrivacyNoteInsert(commitment) => {
                if !privacy_transfers_enabled(tx.chain_id) {
                    return Err(BudlumError::validation(
                        "privacy_mainnet_disabled",
                        "privacy note insertion is disabled on mainnet until full proof verification is wired",
                    ));
                }
                // The same boundary `PrivateTransferSubmit::validate_shape`
                // holds: only a packed field element is a note.
                if !crate::privacy::is_note_hash(commitment) {
                    return Err(BudlumError::validation(
                        "privacy_note_shape",
                        "commitment is not a packed field element",
                    ));
                }
                state
                    .note_registry
                    .insert_note(*commitment)
                    .map_err(|e| BudlumError::validation("privacy_note_insert", e))?;
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::PrivateTransferSubmit(sub) => {
                if !privacy_transfers_enabled(tx.chain_id) {
                    return Err(BudlumError::validation(
                        "privacy_mainnet_disabled",
                        "private transfers are disabled on mainnet until ownership, value-conservation, and membership proofs are wired",
                    ));
                }
                sub.validate_shape()
                    .map_err(|e| BudlumError::validation("private_transfer_shape", e))?;
                if !sub.verify_digest_matches() {
                    return Err(BudlumError::validation(
                        "private_transfer_digest",
                        "public_digest does not match nullifiers/outputs",
                    ));
                }
                // Authorization: the signature is over `public_digest` and must verify
                // against the key of the account sending the transaction.
                //
                // The verifier is chosen by the transaction signature version. It used to
                // use Ed25519 unconditionally and pass `tx.from` as the public
                // key; that is only correct in V4, because there the 32-byte
                // address **is** the key itself. In V5 the address is the hash of
                // the key, so the same call could accept no valid signature at
                // all: an account with an ML-DSA-87 wallet could not make a
                // confidential transfer.
                //
                // On the V5 path the key comes from the transaction's `signer_public_key`
                // field; `Transaction::verify` has already verified that this key derives
                // the `from` address, so the signature here is also bound to
                // the sending account.
                let authorized = match tx.signature_version {
                    crate::core::transaction::SIGNATURE_VERSION_V5 => {
                        crate::crypto::primitives::verify_ml_dsa_87_signature(
                            &sub.public_digest,
                            &sub.authorization_sig,
                            &tx.signer_public_key,
                        )
                        .is_ok()
                    }
                    _ => crate::crypto::primitives::verify_signature(
                        &sub.public_digest,
                        &sub.authorization_sig,
                        tx.from.as_bytes(),
                    )
                    .is_ok(),
                };
                if !authorized {
                    return Err(BudlumError::validation(
                        "private_transfer_auth",
                        "authorization_sig invalid for tx.from",
                    ));
                }
                state
                    .note_registry
                    .apply_transfer(
                        &sub.spent_commitments,
                        &sub.nullifiers,
                        &sub.output_commitments,
                    )
                    .map_err(|e| BudlumError::validation("private_transfer_apply", e))?;
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::AiAttachExecutionProof { request_id, proof } => {
                if !state
                    .registry
                    .is_active(&tx.from, crate::registry::role::roles::AI_OPERATOR)
                {
                    return Err(BudlumError::validation(
                        "ai_operator_unauthorized",
                        "Execution proof signer must be an active bonded AI_OPERATOR (RoleId=8)",
                    ));
                }
                // Model-aware structural verify + program_hash bind.
                // STARK verify is performed when proof_bytes deserialize as
                // bud_proof::ProofEnvelope AND guest program words are supplied
                // Via model execution_program_hash registration path (host
                // Re-derives guest is not available on-chain for arbitrary
                // Weights - STARK of the weight-binding guest is verified
                // When postcard envelope is present via prove_mlp_inference).
                let req = state
                    .ai_registry
                    .requests
                    .get(request_id)
                    .ok_or_else(|| {
                        BudlumError::validation("ai_exec_no_request", "request not found")
                    })?
                    .clone();
                let results = state.ai_registry.results.get(request_id).ok_or_else(|| {
                    BudlumError::validation("ai_exec_no_result", "no results for request")
                })?;
                let res = results
                    .iter()
                    .find(|r| r.verifier == tx.from)
                    .ok_or_else(|| {
                        BudlumError::validation(
                            "ai_exec_not_verifier_result",
                            "tx.from has no result for request",
                        )
                    })?
                    .clone();
                let model = state.ai_registry.models.get(&proof.model_id).cloned();
                // A proof may affect finalization or payment only after full
                // STARK verification against the registered guest program and
                // the public inputs the proof was produced against.
                //
                // This used to be unreachable, and the comment here said the
                // transaction path had "no program/public-input bundle to pass
                // to the verifier". Both halves of that bundle now exist: the
                // model registers `execution_program_hash`, which the AIR also
                // binds, and `AiExecutionProof::public_inputs` carries the
                // inputs the envelope was produced against. A proof that omits
                // them cannot be verified, so a proof-required model still
                // fails closed - but for a reason that names what is missing
                // from the proof rather than what is missing from the node.
                let mut stark_girisi: Option<(Vec<u64>, bud_proof::ExecutionPublicInputs)> = None;
                if model
                    .as_ref()
                    .is_some_and(|spec| spec.require_execution_proof)
                {
                    let Some(ref claimed_inputs) = proof.public_inputs else {
                        return Err(BudlumError::validation(
                            "ai_exec_no_public_inputs",
                            "proof-required model needs an execution proof carrying its public inputs",
                        ));
                    };
                    let spec = model.as_ref().ok_or_else(|| {
                        BudlumError::validation("ai_exec_no_model", "model not registered")
                    })?;
                    let Some(registered_program_hash) = spec.execution_program_hash else {
                        return Err(BudlumError::validation(
                            "ai_exec_no_program_hash",
                            "proof-required model must register execution_program_hash",
                        ));
                    };
                    // The public inputs are the prover's claim; bind them to
                    // the registration before spending work on the STARK. The
                    // AIR ties `program_hash` to the trace, so agreeing here
                    // means the proof is about the registered program.
                    if claimed_inputs.program_hash != registered_program_hash {
                        return Err(BudlumError::validation(
                            "ai_exec_program_hash",
                            "public inputs name a different program than the model registered",
                        ));
                    }
                    if claimed_inputs.exit_code != 0 {
                        return Err(BudlumError::validation(
                            "ai_exec_exit_code",
                            "execution proof attests to a failed run",
                        ));
                    }
                    // The public inputs are the prover's claim; `chain_id` has
                    // to be bound just as `program_hash` is. Without that binding,
                    // a proof produced for one chain and entirely valid there
                    // would verify here too: the AIR binds `chain_id` to the trace
                    // but cannot know which chain is the right one; that decision
                    // belongs to the verifier. Because `tx.chain_id` is part of the transaction
                    // signature the sender cannot choose it freely.
                    if claimed_inputs.chain_id != tx.chain_id {
                        return Err(BudlumError::validation(
                            "ai_exec_chain_id",
                            "public inputs bind the proof to a different chain",
                        ));
                    }
                    let expected_inputs = claimed_inputs.to_execution_inputs();
                    let program = crate::ai::execution::guest_program_for_model(spec)
                        .map_err(|e| BudlumError::validation("ai_exec_program_rebuild", e))?;
                    stark_girisi = Some((program, expected_inputs));
                }
                // One call for both halves. The bundle is the only shape this
                // path can reach for, so a proof cannot clear the structural
                // checks and skip the STARK, or clear the STARK while its
                // commitments name a different request.
                let giris = stark_girisi
                    .as_ref()
                    .map(|(program, inputs)| (program.as_slice(), inputs));
                let report = match giris {
                    Some((program, inputs)) => crate::ai::execution::verify_execution_proof_full(
                        proof,
                        &req,
                        &res,
                        model.as_ref(),
                        Some((program, inputs)),
                    ),
                    None => crate::ai::execution::verify_execution_proof_structural_with_model(
                        proof,
                        &req,
                        &res,
                        model.as_ref(),
                    ),
                };
                if !report.is_structurally_valid() {
                    return Err(BudlumError::validation(
                        "ai_exec_structural",
                        format!("execution proof structural check failed: {report:?}"),
                    ));
                }
                if report.stark_ok == Some(false) {
                    return Err(BudlumError::validation(
                        "ai_exec_stark",
                        report
                            .stark_error
                            .unwrap_or_else(|| "execution STARK verify failed".to_string()),
                    ));
                }
                // Attempt STARK verify of postcard envelope (fail closed if
                // Bytes present but invalid). Without guest program words we
                // Only check envelope deserializes + public_inputs_hash shape.
                // Size bound before deserialization, which is the one bound
                // that cannot be delegated: `validate_envelope_structure`
                // takes a decoded envelope, and decoding is the work this
                // refusal exists to avoid paying for. The other four
                // structural checks run below, through the shared function,
                // once there is something decoded to check.
                if proof.proof_bytes.len() > crate::execution::proof_verifier::MAX_PROOF_BYTES {
                    return Err(BudlumError::validation(
                        "ai_exec_proof_too_large",
                        "execution proof_bytes exceed MAX_PROOF_BYTES",
                    ));
                }
                // Production gas metering - validate
                // Proof size against the execution class limits before
                // Deserializing the full envelope.
                if let Some(ref model_spec) = model {
                    if model_spec.execution_class != 0 {
                        let class = crate::ai::execution::AiExecutionModelClass::from_u8(
                            model_spec.execution_class,
                        );
                        if let Some(cls) = class {
                            let limits = cls.limits();
                            // Proof size heuristic: bound by max_params * 64 bytes
                            // (each param contributes ~64 bytes to the STARK trace).
                            let max_proof = limits.max_params.checked_mul(64).ok_or_else(|| {
                                BudlumError::validation("proof_overflow", "max proof size overflow")
                            })?;
                            if proof.proof_bytes.len() > max_proof {
                                return Err(BudlumError::validation(
                                    "ai_exec_gas_exceeded",
                                    format!(
                                        "proof size {} exceeds class limit {} (class={})",
                                        proof.proof_bytes.len(),
                                        max_proof,
                                        cls.as_str()
                                    ),
                                ));
                            }
                        }
                    }

                    // The model-shaped half of `validate_gas_budget`.
                    //
                    // Only the size bound is asked for, and the gas ceiling is
                    // passed as `u64::MAX` on purpose. `max_fee` on the
                    // request is a balance escrowed from the requester's
                    // account; `estimate_full_gas` returns gas units; nothing
                    // in this tree converts between them. Passing the real
                    // `max_fee` here would compare a balance against a gas
                    // figure, which typechecks because both are `u64` and is
                    // still a unit error. Measured: `GAS_BASE_STARK` alone is
                    // 10_000 and every `max_fee` in the tree is at most 500,
                    // so it would reject every valid request.
                    //
                    // The `u64::MAX` is deliberately visible rather than
                    // hidden behind a default, so nobody reads this as a
                    // budget that was checked.
                    if let Some(ref dims) = model_spec.execution_dims {
                        let sizing = crate::ai::execution::FixedPointMlpSpec {
                            dims: dims.clone(),
                            weights: vec![
                                0i32;
                                dims.windows(2)
                                    .map(|w| w[0] as usize * w[1] as usize)
                                    .sum()
                            ],
                            biases: vec![0i32; dims.iter().skip(1).map(|d| *d as usize).sum()],
                        };
                        crate::ai::execution::validate_gas_budget(
                            &sizing,
                            proof.proof_bytes.len(),
                            u64::MAX,
                        )
                        .map_err(|e| BudlumError::validation("ai_exec_proof_size", e))?;
                    }
                }
                if let Ok(envelope) =
                    postcard::from_bytes::<bud_proof::ProofEnvelope>(&proof.proof_bytes)
                {
                    // Ask the verifier what a well-formed envelope is, rather
                    // than restating it here.
                    //
                    // `ProofVerifier::validate_envelope_structure` makes five
                    // checks and this path had copied three of them by hand:
                    // size, degree bits and format version. The two it did
                    // not copy were the empty-backend refusal and the
                    // requirement that `p3_version` and `fri_params_id` be
                    // present, so an envelope naming no prover version and no
                    // FRI parameter set reached `attach_execution_proof`.
                    // Those two fields are how a verifier knows which
                    // parameters a proof was produced under; an envelope that
                    // omits them is not verifiable against anything, and it
                    // was being recorded as attached evidence.
                    //
                    // Copied checks drift by omission, silently, and the
                    // omission is invisible at the copy site because what is
                    // missing is not written anywhere. One definition.
                    let structural = crate::execution::proof_verifier::ProofEnvelope {
                        proof_format_version: envelope.proof_format_version,
                        backend: envelope.backend.clone(),
                        p3_version: envelope.p3_version.clone(),
                        fri_params_id: envelope.fri_params_id.clone(),
                        public_inputs_hash: envelope.public_inputs_hash,
                        proof_bytes: envelope.proof_bytes.clone(),
                        degree_bits: envelope.degree_bits,
                    };
                    crate::execution::proof_verifier::ProofVerifier::validate_envelope_structure(
                        &structural,
                    )
                    .map_err(|e| BudlumError::validation("ai_exec_envelope", e.to_string()))?;
                    // Backend allow-list. Structural envelopes are not proof
                    // Evidence by themselves; this transaction path only accepts
                    // Production Plonky3-backed envelopes and still fails closed
                    // For proof-required models until full verification is wired.
                    if !ai_execution_backend_allowed(tx.chain_id, &envelope.backend) {
                        return Err(BudlumError::validation(
                            "ai_exec_backend",
                            format!("unsupported proof backend: {}", envelope.backend),
                        ));
                    }
                } else {
                    return Err(BudlumError::validation(
                        "ai_exec_deserialize",
                        "proof_bytes is not a valid bud_proof::ProofEnvelope (postcard)",
                    ));
                }
                state
                    .ai_registry
                    .attach_execution_proof(request_id, &tx.from, proof.clone())
                    .map_err(|e| BudlumError::validation("ai_exec_attach", e))?;
                // If this attach unlocks finalization for require_execution_proof models,
                // Try re-check by re-submitting is not automatic, next result or
                // Explicit finalize path. For single-verifier threshold, caller may
                // Re-submit same result after attach; multi-verifier attaches race.
                // Convenience: attempt threshold re-eval without new result.
                let _ = state.ai_registry.try_finalize_with_proofs(request_id);
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.checked_sub(tx.fee).ok_or_else(|| {
                    BudlumError::validation("balance_underflow", "balance underflow")
                })?;
                sender.nonce = sender.nonce.saturating_add(1);
            }
        }

        Ok(())
    }

    pub fn apply_block(
        state: &mut AccountState,
        transactions: &[Transaction],
        block_producer: Option<&Address>,
    ) -> Result<(), String> {
        Self::apply_block_checked(state, transactions, block_producer)
            .map_err(|e| e.message().to_string())
    }

    pub fn apply_block_checked(
        state: &mut AccountState,
        transactions: &[Transaction],
        block_producer: Option<&Address>,
    ) -> BudlumResult<()> {
        for tx in transactions {
            Self::apply_transaction_checked(state, tx)?;
        }
        if let Some(producer) = block_producer {
            // Economic policy (2026-07-25): validators earn only the
            // Flat transaction fees, less the configured metabolic burn.
            // `tokenomics.block_reward` is retained for snapshot/wire
            // Compatibility but MUST NOT mint supply.
            for tx in transactions {
                let burn = state.tokenomics.metabolic_burn(tx.fee);
                let producer_fee = tx.fee.checked_sub(burn).ok_or_else(|| {
                    BudlumError::validation("fee_underflow", "producer fee underflow")
                })?;
                if producer_fee > 0 {
                    // Use try_add_balance for producer rewards
                    // To prevent silent u64 overflow capping on accumulated block fees.
                    state
                        .try_add_balance(producer, producer_fee)
                        .map_err(|e| BudlumError::validation("producer_fee_overflow", &e))?;
                }
            }
        }

        // Execute passed governance proposals
        // (e.g. whitelist/dewhitelist verifiers) and apply their actions.
        let governance_actions = state.governance.execute_passed_proposals(state.epoch_index);
        for action in governance_actions {
            match action {
                crate::core::governance::GovernanceAction::WhitelistVerifier(addr) => {
                    state.ai_registry.whitelist_verifier(addr);
                }
                crate::core::governance::GovernanceAction::DewhitelistVerifier(addr) => {
                    state.ai_registry.dewhitelist_verifier(&addr);
                }
                crate::core::governance::GovernanceAction::VerifyHubApp { app_id } => {
                    // Reachable only if `execute_passed_proposals` starts
                    // emitting this action. Today it does not: the arm for
                    // `ProposalType::VerifyHubApp` falls through to `_ =>
                    // None`, and the badge is written by
                    // `AccountState::execute_proposal`, which reads the
                    // `ProposalType` directly and never goes through a
                    // `GovernanceAction`.
                    //
                    // Two writers for one badge is the shape that produces a
                    // double application, so this arm deliberately does not
                    // write. It refuses instead, because the alternative is
                    // an arm that looks like it applies the vote and
                    // silently does nothing, which is worse than one that
                    // stops the block.
                    return Err(BudlumError::validation(
                        "hub_verify_wrong_path",
                        format!(
                            "VerifyHubApp for app {app_id} arrived as a GovernanceAction; \
                             the badge is written by AccountState::execute_proposal, so \
                             emitting it here would apply the same vote twice"
                        ),
                    ));
                }
                crate::core::governance::GovernanceAction::SetEncryptionPolicy(policy) => {
                    // P12-4: DAO parameter-only update. This cannot grant decrypt
                    // Authority or bypass user-owned AccessGrant checks.
                    state
                        .marketplace
                        .set_encryption_policy(policy)
                        .map_err(|e| BudlumError::validation("pollen_encryption_policy", e))?;
                }
                crate::core::governance::GovernanceAction::SetConstitutionParameter(parameter) => {
                    // P12-10: Constitution Engine updates are bounded. Hard
                    // Guardrails (AI default-deny, no governance read override,
                    // Permissionless core, PoA isolation) fail closed in
                    // ConstitutionRegistry::set_parameter.
                    state
                        .governance
                        .constitution
                        .set_parameter(parameter)
                        .map_err(|e| BudlumError::validation("constitution_parameter", e))?;
                }
                crate::core::governance::GovernanceAction::UnfreezeConsensusDomain {
                    domain_id,
                    expected_validator_set_hash,
                    justification_hash,
                } => {
                    // Governance-controlled domain unfreeze: queue for Blockchain to apply to ConsensusDomainRegistry.
                    state.pending_domain_unfreezes.push(
                        crate::core::account::PendingDomainUnfreeze {
                            domain_id,
                            expected_validator_set_hash,
                            justification_hash,
                        },
                    );
                    tracing::info!(
                        "Queued governance domain unfreeze: domain={} expected_hash={} justification={}",
                        domain_id,
                        hex::encode(expected_validator_set_hash),
                        hex::encode(justification_hash)
                    );
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{ai_execution_backend_allowed, privacy_transfers_enabled};

    #[test]
    fn attach_path_rejects_test_ai_execution_backend() {
        let mainnet = crate::core::chain_config::Network::Mainnet
            .chain_id()
            .value();
        let devnet = crate::core::chain_config::Network::Devnet
            .chain_id()
            .value();

        assert!(!ai_execution_backend_allowed(mainnet, "test"));
        assert!(!ai_execution_backend_allowed(mainnet, "test-backend"));
        assert!(ai_execution_backend_allowed(
            mainnet,
            "Plonky3-Keccak-Goldilocks"
        ));
        assert!(!ai_execution_backend_allowed(devnet, "test"));
    }

    /// The backend name arrives inside the transaction envelope, so a
    /// substring test is not an allow-list: anything that merely mentions
    /// Plonky3 passes it. What sits behind the gate is
    /// `verify_execution_proof_structural_with_model` - the proof bytes are
    /// never verified cryptographically - so the name is the only thing
    /// separating an attached proof from an invented one.
    #[test]
    fn a_backend_that_only_names_plonky3_is_not_plonky3() {
        let devnet = crate::core::chain_config::Network::Devnet
            .chain_id()
            .value();
        assert!(ai_execution_backend_allowed(
            devnet,
            "Plonky3-Keccak-Goldilocks"
        ));
        for spoofed in [
            "Plonky3",
            "Plonky3-nightly",
            "not-really-Plonky3-at-all",
            "Plonky3 with a local patch",
            "xPlonky3x",
        ] {
            assert!(
                !ai_execution_backend_allowed(devnet, spoofed),
                "backend {spoofed} is not Plonky3 but passed the allow-list"
            );
        }
    }

    /// The gate has to be an allowlist. Ownership (the nullifier binding
    /// proof), value conservation and membership are not wired, so this
    /// surface is only ever on where losing the notes costs nothing.
    /// `chain_id != Mainnet` answers the wrong question: it turns the feature
    /// ON for every id nobody has claimed yet, including a second mainnet or a
    /// public testnet that grows real value.
    #[test]
    fn privacy_transfers_stay_off_for_an_unclaimed_chain_id() {
        let mainnet = crate::core::chain_config::Network::Mainnet
            .chain_id()
            .value();
        let testnet = crate::core::chain_config::Network::Testnet
            .chain_id()
            .value();
        let devnet = crate::core::chain_config::Network::Devnet
            .chain_id()
            .value();

        assert!(!privacy_transfers_enabled(mainnet), "mainnet must stay off");
        assert!(privacy_transfers_enabled(devnet), "devnet must stay on");
        assert!(privacy_transfers_enabled(testnet), "testnet must stay on");

        for unclaimed in [1u64, 42, 1337, 45263, u64::MAX] {
            assert!(
                !privacy_transfers_enabled(unclaimed),
                "chain id {unclaimed} has no ownership proof wired; the surface must stay off"
            );
        }
    }

    #[test]
    fn mainnet_disables_privacy_execution_surface() {
        let mainnet = crate::core::chain_config::Network::Mainnet
            .chain_id()
            .value();
        let devnet = crate::core::chain_config::Network::Devnet
            .chain_id()
            .value();

        assert!(!privacy_transfers_enabled(mainnet));
        assert!(privacy_transfers_enabled(devnet));
    }
}
