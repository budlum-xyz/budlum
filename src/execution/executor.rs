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
                state.sync_validator_registration(&tx.from);
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
                                .add_vote(tx.from, voter_stake, vote_for)
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

                        state.governance.create_proposal(
                            tx.from,
                            p_type,
                            state.epoch_index,
                            duration,
                        );
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
                let (name, duration): (String, u64) = bincode::deserialize(&tx.data)
                    .map_err(|e| BudlumError::validation("bns_invalid_data", e.to_string()))?;

                let cost = state.bns_registry.calculate_cost(&name, duration);
                if tx.amount < cost {
                    return Err(BudlumError::validation(
                        "bns_insufficient_payment",
                        format!("Required: {}, provided: {}", cost, tx.amount),
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
                sender.balance = sender.balance.saturating_sub(tx.fee).saturating_sub(cost);
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
                sender.balance = sender.balance.saturating_sub(tx.fee);
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
                sender.balance = sender.balance.saturating_sub(tx.fee);
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
                sender.balance = sender.balance.saturating_sub(tx.fee);
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::NftMint => {
                let (cid, author): (crate::storage::content_id::ContentId, Option<String>) =
                    bincode::deserialize(&tx.data)
                        .map_err(|e| BudlumError::validation("nft_invalid_data", e.to_string()))?;

                state
                    .nft_registry
                    .mint(tx.from, cid, state.epoch_index, author);

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.saturating_sub(tx.fee);
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
                sender.balance = sender.balance.saturating_sub(tx.fee);
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::NftBurn => {
                let id: u64 = bincode::deserialize(&tx.data)
                    .map_err(|e| BudlumError::validation("nft_invalid_data", e.to_string()))?;

                let cid = state
                    .nft_registry
                    .burn(id, &tx.from)
                    .map_err(|e| BudlumError::validation("nft_burn_failed", e.to_string()))?;

                tracing::info!(%cid, "B.U.D. Hard Prune Triggered by NftBurn");

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.saturating_sub(tx.fee);
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::NftBoost { nft_id, amount } => {
                let amount = *amount;
                let bud_share = amount.saturating_mul(4) / 100;
                let creator_share = amount.saturating_mul(16) / 100;
                let protocol_share = amount
                    .saturating_sub(bud_share)
                    .saturating_sub(creator_share);

                let nft = state
                    .nft_registry
                    .get_nft(*nft_id)
                    .cloned()
                    .ok_or(BudlumError::validation("nft_not_found", "NFT not found"))?;

                let booster = state.get_or_create(&tx.from);
                if booster.balance < amount.saturating_add(tx.fee) {
                    return Err(BudlumError::validation(
                        "insufficient_funds",
                        "Cannot afford boost",
                    ));
                }
                booster.balance = booster
                    .balance
                    .saturating_sub(amount)
                    .saturating_sub(tx.fee);
                booster.nonce = booster.nonce.saturating_add(1);

                let creator = state.get_or_create(&nft.owner);
                creator.balance = creator.balance.saturating_add(creator_share);

                tracing::info!(nft_id = %nft_id, creator_reward = %creator_share, protocol_fee = %protocol_share, "SocialFi: Content Boosted");
            }
            TransactionType::UniversalRelay(ext_tx) => {
                tracing::info!(chain = ?ext_tx.chain, target = %ext_tx.target_address, "Universal Relayer: Master Key authorization");
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.saturating_sub(tx.fee);
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::RelayerResult(res) => {
                // ADIM 6 §6.2: Relayer EVM Proofs
                // Verification logic stub for cross-chain receipt proof.
                // In production, this would verify the Merkle proof against
                // a previously submitted and finalized external state root.
                if res.receipt_proof.is_empty() {
                    return Err(BudlumError::validation(
                        "relayer_invalid_proof",
                        "Receipt proof cannot be empty",
                    ));
                }

                tracing::info!(
                    chain = ?res.chain,
                    tx_hash = %res.tx_hash,
                    success = %res.success,
                    "Universal Relayer: External result verified and recorded"
                );

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.saturating_sub(tx.fee);
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::AiOfferData { cid, price } => {
                state.marketplace.create_offer(tx.from, *cid, *price);
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.saturating_sub(tx.fee);
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

                let total_cost = offer.price.saturating_add(tx.fee);
                if state.get_balance(&tx.from) < total_cost {
                    return Err(BudlumError::validation("funds", "Insufficient funds"));
                }

                let buyer = state.get_or_create(&tx.from);
                buyer.balance = buyer.balance.saturating_sub(total_cost);
                buyer.nonce = buyer.nonce.saturating_add(1);

                let seller = state.get_or_create(&offer.seller);
                seller.balance = seller.balance.saturating_add(offer.price);
            }
            TransactionType::HubRegisterApp {
                name,
                category,
                website_url,
                manifest_id,
            } => {
                state.hub.register_app(
                    name.clone(),
                    tx.from,
                    category.clone(),
                    website_url.clone(),
                    *manifest_id,
                    state.epoch_index,
                );
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
        for tx in transactions {
            Self::apply_transaction_checked(state, tx)?;
        }
        if let Some(producer) = block_producer {
            // Mint block reward
            let reward = state.tokenomics.block_reward;
            if reward > 0 {
                let supply = state.circulating_supply();
                let cap = crate::tokenomics::BUD_TOTAL_SUPPLY as u128;
                let actual = reward.min(cap.saturating_sub(supply) as u64);
                if actual > 0 {
                    state.add_balance(producer, actual);
                }
            }
            // Distribute tx fees (minus metabolic burn) to producer
            for tx in transactions {
                let burn = state.tokenomics.metabolic_burn(tx.fee);
                let producer_fee = tx.fee.saturating_sub(burn);
                if producer_fee > 0 {
                    state.add_balance(producer, producer_fee);
                }
            }
        }
        Ok(())
    }
}
