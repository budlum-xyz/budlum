use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType};
use crate::error::{BudlumError, BudlumResult};
use crate::execution::zkvm::{ZkVmExecutor, DEFAULT_CONTRACT_GAS_LIMIT};

pub struct Executor;

impl Executor {
    pub fn apply_transaction(state: &mut AccountState, tx: &Transaction) -> Result<(), String> {
        Self::apply_transaction_checked(state, tx).map_err(|e| e.message().to_string())
    }

    pub fn apply_transaction_checked(
        state: &mut AccountState,
        tx: &Transaction,
    ) -> BudlumResult<()> {
        if tx.from == Address::zero() {
            return Ok(());
        }

        // Tur 9.5 (security audit §10): enforce the cost-floor /
        // shape checks for Unstake and Vote at the consensus
        // boundary. The `tx_precheck` layer catches these at the
        // RPC boundary, but consensus (this function) is the
        // canonical gatekeeper — a zero-fee, zero-amount, empty-data
        // Unstake/Vote must be rejected here too, otherwise an
        // internal path (replay, sync, etc.) could inject spam
        // that bypasses the RPC check.
        //
        // We do NOT call `is_valid()` here because that helper
        // also runs the full signature check, which is performed
        // by the caller (`validate_and_add_block` /
        // `validate_pool_transaction`); running it twice is
        // redundant and also breaks the in-test pattern of
        // constructing unsigned txs for unit-test convenience.
        // The cost-floor / shape rules below are the consensus
        // invariant — duplicated here, not derived from `is_valid`.
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

        // Tur 12 / BUG #10: liquid balance is only charged `fee` for Unstake/Vote.
        // `tx.amount` on Unstake is stake principal (not liquid); Vote amount is
        // not a liquid debit either. Charging amount+fee blocked fully-staked
        // validators from ever unstaking (self-DoS).
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

        match tx.tx_type {
            TransactionType::Transfer => {
                // Tur 2 tokenomics integration: enforce team-vesting on
                // outgoing transfers. The `state.spendable_balance` helper
                // already accounts for the locked portion of the team
                // account at the current epoch; we check it BEFORE any
                // mutable move so the rejection is atomic.
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
                sender.balance = sender.balance.saturating_sub(total_cost);
                sender.nonce = sender.nonce.saturating_add(1);

                let receiver = state.get_or_create(&tx.to);
                receiver.balance = receiver.balance.saturating_add(tx.amount);
            }
            TransactionType::Stake => {
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.saturating_sub(total_cost);
                sender.nonce = sender.nonce.saturating_add(1);

                let stake_amount = tx.amount;
                let validator = state.get_validator_mut(&tx.from);

                if let Some(v) = validator {
                    v.stake = v.stake.saturating_add(stake_amount);
                    v.active = true;
                } else {
                    state.add_validator(tx.from, stake_amount);
                }
                // Tur 5: keep the permissionless registry in lock-step with the
                // on-chain validator set so `is_active(staker, VALIDATOR)`
                // returns `true` the moment the first stake lands.
                state.sync_validator_registration(&tx.from);
            }
            TransactionType::Unstake => {
                let sender_start_balance = state.get_balance(&tx.from);
                if sender_start_balance < tx.fee {
                    return Err(BudlumError::validation(
                        "insufficient_fee_balance",
                        "Insufficient balance for fee",
                    ));
                }

                // Validate stake availability without holding a long-lived mut borrow.
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

                // Tur 11: stake-recycling double-vote mitigation.
                // When stake is unbonded, reduce that voter's contribution
                // on still-active governance proposals by the unstaked amount.
                for proposal in state.governance.proposals.iter_mut() {
                    if proposal.status == crate::core::governance::ProposalStatus::Active {
                        if let Some(&voted_for) = proposal.voters.get(&tx.from) {
                            if voted_for {
                                proposal.votes_for = proposal.votes_for.saturating_sub(tx.amount);
                            } else {
                                proposal.votes_against =
                                    proposal.votes_against.saturating_sub(tx.amount);
                            }
                        }
                    }
                }

                if let Some(validator) = state.get_validator_mut(&tx.from) {
                    validator.stake = validator.stake.saturating_sub(tx.amount);
                    if validator.stake == 0 {
                        validator.active = false;
                    }
                } else {
                    return Err(BudlumError::validation("not_validator", "Not a validator"));
                }

                state
                    .unbonding_queue
                    .push(crate::core::account::UnbondingEntry {
                        address: tx.from,
                        amount: tx.amount,
                        release_epoch: state.epoch_index + crate::core::account::UNBONDING_EPOCHS,
                    });

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.saturating_sub(tx.fee);
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::Vote => {
                let sender_acc = state.get_or_create(&tx.from);
                sender_acc.balance = sender_acc.balance.saturating_sub(tx.fee);
                sender_acc.nonce = sender_acc.nonce.saturating_add(1);

                if tx.to != Address::zero() {
                    if let Some(target) = state.get_validator_mut(&tx.to) {
                        if tx.amount > 0 {
                            target.votes_for += 1;
                        } else {
                            target.votes_against += 1;
                        }
                        tracing::info!("Validator Vote recorded: {} -> {}", tx.from, tx.to);
                    }
                } else if !tx.data.is_empty() && tx.data.len() >= 9 {
                    if tx.data.len() == 9 {
                        let vote_for = tx.data[0] != 0;
                        let mut id_bytes = [0u8; 8];
                        id_bytes.copy_from_slice(&tx.data[1..9]);
                        let proposal_id = u64::from_le_bytes(id_bytes);

                        let voter_stake =
                            state.get_validator(&tx.from).map(|v| v.stake).unwrap_or(0);
                        if voter_stake == 0 {
                            return Err(BudlumError::validation(
                                "governance_voter_not_validator",
                                "Only validators can vote in governance",
                            ));
                        }

                        if let Some(proposal) = state.governance.find_proposal_mut(proposal_id) {
                            proposal
                                .add_vote(tx.from, voter_stake, vote_for)
                                .map_err(|e| {
                                    BudlumError::validation("governance_vote_failed", e)
                                })?;
                            tracing::info!(
                                "Governance Vote: Proposal {} from {}",
                                proposal_id,
                                tx.from
                            );
                        } else {
                            return Err(BudlumError::validation(
                                "proposal_not_found",
                                "Proposal not found",
                            ));
                        }
                    } else {
                        // Tur 11 / A2: only active validators (stake > 0) may create proposals.
                        let proposer_stake =
                            state.get_validator(&tx.from).map(|v| v.stake).unwrap_or(0);
                        if proposer_stake == 0 {
                            return Err(BudlumError::validation(
                                "governance_proposer_not_validator",
                                "Only active validators can create proposals",
                            ));
                        }

                        // Likely a Proposal: [duration (8), ProposalType (...)]
                        let mut dur_bytes = [0u8; 8];
                        dur_bytes.copy_from_slice(&tx.data[0..8]);
                        let duration = u64::from_le_bytes(dur_bytes);

                        let p_type: crate::core::governance::ProposalType =
                            serde_json::from_slice(&tx.data[8..]).map_err(|e| {
                                BudlumError::validation(
                                    "invalid_proposal_data",
                                    format!("Invalid proposal data: {}", e),
                                )
                            })?;

                        let id = state.governance.create_proposal(
                            tx.from,
                            p_type,
                            state.epoch_index,
                            duration,
                        );
                        tracing::info!("Governance Proposal Created: ID {} from {}", id, tx.from);
                    }
                }
            }
            TransactionType::ContractCall => {
                ZkVmExecutor::execute_bytecode(&tx.data, DEFAULT_CONTRACT_GAS_LIMIT)
                    .map_err(|e| BudlumError::validation("contract_execution_failed", e))?;

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.saturating_sub(tx.fee);
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::BnsRegister => {
                // data: bincode({ name: String, duration: u64 })
                let (name, duration): (String, u64) = bincode::deserialize(&tx.data)
                    .map_err(|e| BudlumError::validation("bns_invalid_data", e.to_string()))?;

                let cost = state.bns_registry.calculate_cost(&name, duration);
                if tx.amount < cost {
                    return Err(BudlumError::validation("bns_insufficient_payment", format!("Required: {}, provided: {}", cost, tx.amount)));
                }

                state
                    .bns_registry
                    .register(name, tx.from, state.epoch_index, duration)
                    .map_err(|e| BudlumError::validation("bns_registration_failed", e.to_string()))?;

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.saturating_sub(tx.fee).saturating_sub(tx.amount);
                sender.nonce = sender.nonce.saturating_add(1);
                
                // Add to burn snapshot (half of name revenue is burned, for example)
                // TODO: Integrate with Tokenomics burn path
            }
            TransactionType::BnsSetContent => {
                // ... existing ...
                let (name, cid): (String, crate::storage::content_id::ContentId) = bincode::deserialize(&tx.data)
                    .map_err(|e| BudlumError::validation("bns_invalid_data", e.to_string()))?;

                state
                    .bns_registry
                    .set_content(&name, &tx.from, cid)
                    .map_err(|e| BudlumError::validation("bns_set_content_failed", e.to_string()))?;

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.saturating_sub(tx.fee);
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::BnsRegisterSubdomain => {
                // data: bincode({ parent_name: String, sub_label: String, sub_owner: Address })
                let (parent, label, sub_owner): (String, String, Address) = bincode::deserialize(&tx.data)
                    .map_err(|e| BudlumError::validation("bns_invalid_data", e.to_string()))?;

                state
                    .bns_registry
                    .register_subdomain(&parent, label, sub_owner, &tx.from)
                    .map_err(|e| BudlumError::validation("bns_subdomain_failed", e.to_string()))?;

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.saturating_sub(tx.fee);
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::NftMint => {
                // data: bincode({ cid: ContentId, author_name: Option<String> })
                let (cid, author_name): (crate::storage::content_id::ContentId, Option<String>) = bincode::deserialize(&tx.data)
                    .map_err(|e| BudlumError::validation("nft_invalid_data", e.to_string()))?;

                state.nft_registry.mint(tx.from, cid, state.epoch_index, author_name);

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.saturating_sub(tx.fee);
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::NftTransfer => {
                // data: bincode({ nft_id: u64, to: Address })
                let (id, to): (u64, Address) = bincode::deserialize(&tx.data)
                    .map_err(|e| BudlumError::validation("nft_invalid_data", e.to_string()))?;

                state.nft_registry.transfer(id, &tx.from, to)
                    .map_err(|e| BudlumError::validation("nft_transfer_failed", e.to_string()))?;

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.saturating_sub(tx.fee);
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
        let mut total_fees: u64 = 0;
        for tx in transactions {
            if tx.from == Address::zero() {
                continue;
            }
            if let Err(e) = Self::apply_transaction_checked(state, tx) {
                return Err(BudlumError::validation(
                    "transaction_apply_failed",
                    format!("TX apply failed: {}", e),
                ));
            }
            total_fees = total_fees.saturating_add(tx.fee);
        }
        // Tur 2 tokenomics integration: the metabolic (tx-fee) burn must be
        // subtracted from the producer's reward and permanently destroyed.
        // We compute everything from immutable borrows first, then take the
        // mutable borrows for the actual balance moves, so the borrow checker
        // stays happy.
        let (block_reward, metabolic_burn_total) = {
            // Use the canonical `metabolic_burn(fee)` helper from
            // `TokenomicsParams` so the rounding behaviour is identical to
            // the module's own unit tests.
            let mut total_burn: u64 = 0;
            for tx in transactions {
                if tx.from == Address::zero() {
                    continue;
                }
                total_burn = total_burn.saturating_add(state.tokenomics.metabolic_burn(tx.fee));
            }
            (state.tokenomics.block_reward, total_burn)
        };

        if let Some(producer) = block_producer {
            // Producer reward = block_reward + (fees - metabolic_burn).
            // The burn is permanently destroyed (no account receives it), so
            // total supply strictly decreases by `metabolic_burn_total` minus
            // the freshly minted `block_reward` (a net deflationary effect
            // when burn > 0).
            //
            // TUR 4 SUPPLY CAP (Tur 24 kararı, Seçenek B — sert tavan):
            // $BUD arz tavanı (`BUD_TOTAL_SUPPLY = 100M`) aşılamaz. Kalan pay
            // tam ödemeye yetmiyorsa, block_reward kısmi ödenir (clamp); fee
            // kısmı her zaman tam ödenir (fee'ler zaten supply'den çıkmış —
            // sender'lardan kesildi). Net: cap asla aşılmaz, fee'ler her zaman
            // teslim edilir, block_reward payı clamp edilir.
            let max_supply = crate::tokenomics::BUD_TOTAL_SUPPLY as u128;
            let current_supply = state.circulating_supply();
            let cap_room = max_supply.saturating_sub(current_supply);

            // block_reward kısmı: cap'te yer varsa hepsi, yoksa sadece kalan oda kadar
            let block_reward_paid: u64 = if cap_room >= block_reward as u128 {
                block_reward
            } else {
                cap_room as u64
            };
            // fee kısmı (zaten sender'lardan kesildi): cap'te yer varsa hepsi, yoksa kalan
            let fee_remainder = total_fees.saturating_sub(metabolic_burn_total);
            let fee_paid: u64 = if cap_room >= block_reward as u128 {
                fee_remainder
            } else {
                let room_after_block = cap_room.saturating_sub(block_reward_paid as u128);
                if (fee_remainder as u128) <= room_after_block {
                    fee_remainder
                } else {
                    room_after_block as u64
                }
            };

            let reward = block_reward_paid.saturating_add(fee_paid);
            if reward > 0 {
                let producer_account = state.get_or_create(producer);
                producer_account.balance = producer_account.balance.saturating_add(reward);
                tracing::info!(
                    "Producer {} received reward: {} (fees_paid: {}, burn: {}, block_paid: {} / block_full: {})",
                    producer,
                    reward,
                    fee_paid,
                    metabolic_burn_total,
                    block_reward_paid,
                    block_reward
                );
            } else {
                tracing::info!(
                    "Producer {} received no reward (fees: {}, burn: {}, block: {}; cap reached)",
                    producer,
                    total_fees,
                    metabolic_burn_total,
                    block_reward
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::account::AccountState;
    use crate::core::transaction::{Transaction, TransactionType};
    use bud_isa::{Instruction, Opcode};

    #[test]
    fn test_apply_block_reward() {
        let mut state = AccountState::new();
        let producer = Address::from_hex(&"0".repeat(64)).unwrap();
        let txs = vec![];

        Executor::apply_block(&mut state, &txs, Some(&producer)).unwrap();

        let reward = state.tokenomics.block_reward;
        let account = state.get_or_create(&producer);
        assert_eq!(account.balance, reward);
    }

    #[test]
    fn test_apply_block_reward_with_fees() {
        let mut state = AccountState::new();
        let producer = Address::from_hex(&"01".repeat(32)).unwrap();
        let alice = Address::from_hex(&"02".repeat(32)).unwrap();
        state.add_balance(&alice, 100);

        let mut tx = Transaction::new(alice, Address::zero(), 10, vec![]);
        tx.fee = 5;
        tx.nonce = 0;

        Executor::apply_block(&mut state, &[tx], Some(&producer)).unwrap();

        let reward = state.tokenomics.block_reward;
        let producer_acc = state.get_or_create(&producer);
        assert_eq!(producer_acc.balance, reward + 5);

        let alice_acc = state.get_or_create(&alice);
        assert_eq!(alice_acc.balance, 100 - 15);
    }

    #[test]
    fn test_vote_for_transaction() {
        let mut state = AccountState::new();
        let alice = Address::from_hex(&"01".repeat(32)).unwrap();
        let val_pubkey = Address::from_hex(&"02".repeat(32)).unwrap();

        state.add_balance(&alice, 100);
        state.add_validator(val_pubkey, 1000);

        let mut tx = Transaction::new(alice, val_pubkey, 1, vec![]);
        tx.tx_type = TransactionType::Vote;
        tx.fee = 2;

        Executor::apply_transaction(&mut state, &tx).unwrap();

        let validator = state.get_validator(&val_pubkey).unwrap();
        assert_eq!(validator.votes_for, 1);
        assert_eq!(validator.votes_against, 0);

        let alice_acc = state.get_or_create(&alice);
        assert_eq!(alice_acc.balance, 98);
    }

    #[test]
    fn test_vote_against_transaction() {
        let mut state = AccountState::new();
        let alice = Address::from_hex(&"01".repeat(32)).unwrap();
        let val_pubkey = Address::from_hex(&"02".repeat(32)).unwrap();

        state.add_balance(&alice, 100);
        state.add_validator(val_pubkey, 1000);

        let mut tx = Transaction::new(alice, val_pubkey, 0, vec![]);
        tx.tx_type = TransactionType::Vote;
        tx.fee = 2;

        Executor::apply_transaction(&mut state, &tx).unwrap();

        let validator = state.get_validator(&val_pubkey).unwrap();
        assert_eq!(validator.votes_for, 0);
        assert_eq!(validator.votes_against, 1);
    }

    #[test]
    fn test_contract_call_executes_budzkvm_bytecode() {
        let mut state = AccountState::new();
        let alice = Address::from_hex(&"03".repeat(32)).unwrap();
        state.add_balance(&alice, 100);

        let program = vec![
            Instruction {
                opcode: Opcode::Load,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 11,
            }
            .encode(),
            Instruction {
                opcode: Opcode::Log,
                rd: 0,
                rs1: 1,
                rs2: 0,
                imm: 0,
            }
            .encode(),
            Instruction {
                opcode: Opcode::Halt,
                rd: 0,
                rs1: 0,
                rs2: 0,
                imm: 0,
            }
            .encode(),
        ];
        let bytecode: Vec<u8> = program
            .into_iter()
            .flat_map(|instruction| instruction.to_le_bytes())
            .collect();
        let tx = Transaction::new_contract_call(alice, 7, 0, bytecode);

        Executor::apply_transaction(&mut state, &tx).unwrap();

        let alice_acc = state.get_or_create(&alice);
        assert_eq!(alice_acc.balance, 93);
        assert_eq!(alice_acc.nonce, 1);
    }
}

/// Tur 9.5 (security audit §10): a zero-fee Unstake must be
/// rejected at the consensus boundary, not only at the RPC
/// `tx_precheck` boundary. Without this, an internal path
/// (replay, sync, etc.) could inject zero-fee Unstake spam
/// that bloats the mempool and chain without paying the
/// cost-floor.
#[test]
fn consensus_rejects_zero_fee_unstake() {
    let mut state = AccountState::new();
    let alice = Address::from_hex(&"01".repeat(32)).unwrap();
    state.add_balance(&alice, 1_000_000);
    state.add_validator(alice, 1_000);

    let mut tx = Transaction::new(alice, Address::zero(), 100, vec![]);
    tx.tx_type = TransactionType::Unstake;
    tx.fee = 0; // zero-fee spam
    tx.nonce = 0;
    let kp = crate::crypto::primitives::KeyPair::generate().unwrap();
    tx.sign(&kp);

    let err = Executor::apply_transaction(&mut state, &tx)
        .expect_err("zero-fee Unstake must be rejected at consensus");
    assert!(
        err.contains("unstake_fee_zero") || err.contains("Unstake fee cannot be 0"),
        "expected cost-floor error, got: {err}"
    );
}

/// Tur 9.5 (security audit §10): a zero-amount Unstake must
/// be rejected. Without this, an Unstake with amount=0 would
/// be a silent no-op (executor skips the stake subtraction
/// because `validator.stake < 0` is false, but still bumps the
/// nonce and pays the fee). It also bypasses the unbonding
/// queue invariant.
#[test]
fn consensus_rejects_zero_amount_unstake() {
    let mut state = AccountState::new();
    let alice = Address::from_hex(&"01".repeat(32)).unwrap();
    state.add_balance(&alice, 1_000_000);
    state.add_validator(alice, 1_000);

    let mut tx = Transaction::new(alice, Address::zero(), 0, vec![]);
    tx.tx_type = TransactionType::Unstake;
    tx.fee = 1;
    tx.nonce = 0;
    let kp = crate::crypto::primitives::KeyPair::generate().unwrap();
    tx.sign(&kp);

    let err = Executor::apply_transaction(&mut state, &tx)
        .expect_err("zero-amount Unstake must be rejected at consensus");
    assert!(
        err.contains("unstake_amount_zero") || err.contains("Unstake amount cannot be 0"),
        "expected amount-zero error, got: {err}"
    );
}

/// Tur 9.5 (security audit §10): a zero-fee Vote must be
/// rejected at consensus. Same rationale as the Unstake
/// cost-floor: governance spam must not be free.
#[test]
fn consensus_rejects_zero_fee_vote() {
    let mut state = AccountState::new();
    let alice = Address::from_hex(&"01".repeat(32)).unwrap();
    state.add_balance(&alice, 1_000_000);
    state.add_validator(alice, 1_000);

    // 9-byte vote data: bool + u64 proposal_id
    let mut data = vec![1u8];
    data.extend_from_slice(&42u64.to_le_bytes());
    let mut tx = Transaction::new(alice, Address::zero(), 0, data);
    tx.tx_type = TransactionType::Vote;
    tx.fee = 0; // zero-fee spam
    tx.nonce = 0;
    let kp = crate::crypto::primitives::KeyPair::generate().unwrap();
    tx.sign(&kp);

    let err = Executor::apply_transaction(&mut state, &tx)
        .expect_err("zero-fee Vote must be rejected at consensus");
    assert!(
        err.contains("vote_fee_zero") || err.contains("Vote fee cannot be 0"),
        "expected cost-floor error, got: {err}"
    );
}

/// Tur 11 / A2: only validators with stake > 0 may open governance proposals.
#[test]
fn tur11_non_validator_cannot_create_proposal() {
    use crate::core::governance::ProposalType;
    use crate::core::transaction::Transaction;

    let mut state = AccountState::new();
    let alice = Address::from_hex(&"0a".repeat(32)).unwrap();
    state.add_balance(&alice, 1_000_000);
    // deliberately NOT a validator

    let tx = Transaction::new_proposal(alice, ProposalType::ChangeBaseFee(2), 10, 0);
    let err = Executor::apply_transaction(&mut state, &tx)
        .expect_err("non-validator must not create proposals");
    assert!(
        err.contains("governance_proposer_not_validator")
            || err.contains("Only active validators can create proposals"),
        "expected proposer gate error, got: {err}"
    );
}

/// Tur 11 / A2: an active validator can still create a proposal.
#[test]
fn tur11_validator_can_create_proposal() {
    use crate::core::governance::ProposalType;
    use crate::core::transaction::Transaction;

    let mut state = AccountState::new();
    let alice = Address::from_hex(&"0b".repeat(32)).unwrap();
    state.add_balance(&alice, 1_000_000);
    state.add_validator(alice, 1_000);

    let tx = Transaction::new_proposal(alice, ProposalType::ChangeBaseFee(2), 10, 0);
    Executor::apply_transaction(&mut state, &tx).expect("validator proposal must succeed");
    assert_eq!(state.governance.proposals.len(), 1);
    assert_eq!(state.governance.proposals[0].proposer, alice);
}

/// Tur 11: unstaking reduces the unstaker's contribution on active proposals.
#[test]
fn tur11_unstake_reduces_active_proposal_vote_weight() {
    use crate::core::governance::ProposalType;
    use crate::core::transaction::Transaction;

    let mut state = AccountState::new();
    let alice = Address::from_hex(&"0c".repeat(32)).unwrap();
    state.add_balance(&alice, 1_000_000);
    state.add_validator(alice, 1_000);

    // Create proposal + vote FOR with full stake.
    let create = Transaction::new_proposal(alice, ProposalType::ChangeBaseFee(3), 10, 0);
    Executor::apply_transaction(&mut state, &create).unwrap();
    let proposal_id = state.governance.proposals[0].id;

    let vote = Transaction::new_vote(alice, proposal_id, true, 1);
    Executor::apply_transaction(&mut state, &vote).unwrap();
    assert_eq!(state.governance.proposals[0].votes_for, 1_000);

    // Unstake 400; active proposal weight must drop by 400.
    let mut unstake = Transaction::new(alice, Address::zero(), 400, vec![]);
    unstake.tx_type = TransactionType::Unstake;
    unstake.fee = 1;
    unstake.nonce = 2;
    Executor::apply_transaction(&mut state, &unstake).unwrap();

    assert_eq!(state.governance.proposals[0].votes_for, 600);
    assert_eq!(state.get_validator(&alice).unwrap().stake, 600);
}

/// Tur 11 / A11: L1 VM memory is large enough for the compiler heap base (4096).
/// `execute_bytecode` also runs the STARK path; here we pin the memory-size
/// contract directly on the same `Vm::with_gas_limit` API L1 uses.
#[test]
fn tur11_zkvm_memory_covers_compiler_heap_base() {
    use bud_isa::{Instruction, Opcode};
    use bud_vm::Vm;

    // Store value from r1 at absolute address 4096 (rs1=0 base + imm).
    let program = vec![
        Instruction {
            opcode: Opcode::Load,
            rd: 1,
            rs1: 0,
            rs2: 0,
            imm: 7,
        }
        .encode(),
        Instruction {
            opcode: Opcode::Store,
            rd: 0,
            rs1: 0,
            rs2: 1,
            imm: 4096,
        }
        .encode(),
        Instruction {
            opcode: Opcode::Halt,
            rd: 0,
            rs1: 0,
            rs2: 0,
            imm: 0,
        }
        .encode(),
    ];

    // Old L1 size (1024) must reject the heap-base store.
    let mut too_small = Vm::with_gas_limit(1024, 10_000);
    assert!(
        too_small.run(&program).is_err(),
        "1024-byte memory must reject store at heap base 4096"
    );

    // Tur 11 L1 size (8192) must accept it.
    let mut large_enough = Vm::with_gas_limit(8192, 10_000);
    large_enough
        .run(&program)
        .expect("heap-base store must succeed with 8192-byte VM memory");
    // 8 bytes starting at 4096 hold the stored little-endian value 7.
    let word = u64::from_le_bytes(large_enough.memory[4096..4104].try_into().unwrap());
    assert_eq!(word, 7);
}

/// Tur 12 / BUG #10: a validator with all funds staked (zero free liquid
/// beyond the fee) must still be able to unstake — amount is stake, not liquid.
#[test]
fn tur12_fully_staked_validator_can_unstake() {
    let mut state = AccountState::new();
    let alice = Address::from_hex(&"0d".repeat(32)).unwrap();
    // Only enough liquid balance to cover the fee.
    state.add_balance(&alice, 1);
    state.add_validator(alice, 10_000);

    let mut unstake = Transaction::new(alice, Address::zero(), 5_000, vec![]);
    unstake.tx_type = TransactionType::Unstake;
    unstake.fee = 1;
    unstake.nonce = 0;

    Executor::apply_transaction(&mut state, &unstake)
        .expect("fully-staked validator must be able to unstake when fee is covered");
    assert_eq!(state.get_validator(&alice).unwrap().stake, 5_000);
    assert_eq!(state.get_balance(&alice), 0);
}
