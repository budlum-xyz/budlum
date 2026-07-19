use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType};
use crate::error::{BudlumError, BudlumResult};
use crate::execution::zkvm::{ZkVmExecutor, DEFAULT_CONTRACT_GAS_LIMIT};
use bincode;
use serde_json;

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
                let receipt = ZkVmExecutor::execute_bytecode(&tx.data, DEFAULT_CONTRACT_GAS_LIMIT)
                    .map_err(|e| BudlumError::validation("contract_execution_failed", e))?;

                if !receipt.events.is_empty() && receipt.events[0] == 0x00A1_00A1 {
                    if receipt.events.len() >= 4 {
                        let mut model_id = [0u8; 32];
                        model_id[0..8].copy_from_slice(&receipt.events[1].to_le_bytes());
                        let max_fee = receipt.events[2];
                        let deadline_block = state
                            .epoch_index
                            .saturating_mul(100)
                            .saturating_add(receipt.events[3]);
                        let mut req = crate::ai::types::AiInferenceRequest {
                            request_id: crate::ai::types::AiRequestId::default(),
                            requester: tx.from,
                            model_id: crate::ai::types::AiModelId(model_id),
                            input_commitment: crate::core::transaction::Transaction::signing_hash(
                                &tx,
                            ),
                            input_ref: crate::ai::types::BoundedBytes::try_new(tx.data.clone())
                                .unwrap_or_default(),
                            max_fee,
                            callback: Some(tx.from),
                            submitted_at_block: state.epoch_index.saturating_mul(100),
                            deadline_block,
                        };
                        req.request_id = req.calculate_id();
                        let current_block = state.epoch_index.saturating_mul(100);
                        // P5 Bulgu 14+17: Previously the error was silently swallowed
                        // with `let _ = ...`, and max_fee was never deducted from the
                        // sender's balance. Now we properly handle the result:
                        // - On success: deduct max_fee from sender balance (escrow)
                        // - On failure: don't deduct max_fee, but the contract call
                        //   fee was already consumed by the ZKVM execution
                        match state.ai_registry.submit_request(req, current_block) {
                            Ok(_) => {
                                // Deduct max_fee from sender (escrow for verifiers)
                                let sender = state.get_or_create(&tx.from);
                                sender.balance = sender.balance.saturating_sub(max_fee);
                            }
                            Err(_) => {
                                // Request rejected (deadline, max_fee=0, etc.)
                                // max_fee NOT deducted — no fee leak
                            }
                        }
                    }
                }

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

                // Constitution §1: "NFT yakılırsa veri B.U.D. storage'dan fiziksel silinir."
                // Physical pruning is handled at Blockchain level (storage_registry.prune_content);
                // here we record the CID for the post-block prune hook.
                tracing::info!(%cid, "NftBurn recorded — storage content pruning delegated to blockchain");

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

                // F4 (Constitution §3): route 4% B.U.D. share to storage operator pool.
                // Distributed by blockchain after block commit via distribute_bud_boost_share.
                state.pending_bud_boost_share =
                    state.pending_bud_boost_share.saturating_add(bud_share);

                // F4 treasury_pool (Q-X4 config_driven): 80% protocol share goes to burn_reserve (treasury) if set,
                // otherwise implicit burn (honest fallback). This makes Treasury/Burn explicit per Constitution §3.
                if protocol_share > 0 {
                    if let Some(treasury_addr) = state.burn_reserve_address {
                        let treasury = state.get_or_create(&treasury_addr);
                        treasury.balance = treasury.balance.saturating_add(protocol_share);
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
                // Phase 8.9 C3 fix: real luminance update with ownership check.
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
                sender.balance = sender.balance.saturating_sub(tx.fee);
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::NftTag { nft_id, tag } => {
                let _ = (nft_id, tag);
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.saturating_sub(tx.fee);
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::UniversalRelay(ext_tx) => {
                tracing::info!(chain = ?ext_tx.chain, target = %ext_tx.target_address, "Universal Relayer: Master Key authorization");
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.saturating_sub(tx.fee);
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::RelayerResult(res) => {
                // Phase 6 §6.2: Relayer EVM Proofs — cryptographic verification.
                if res.receipt_proof.is_empty() {
                    return Err(BudlumError::validation(
                        "relayer_invalid_proof",
                        "Receipt proof cannot be empty",
                    ));
                }
                // Phase 8.9 C4 fix: verify external_state_root non-zero
                // (zero root = no state commitment, can't verify anything).
                if res.external_state_root == [0u8; 32] {
                    return Err(BudlumError::validation(
                        "relayer_zero_root",
                        "External state root cannot be zero",
                    ));
                }
                // Phase 8.9 / L1 fix: gerçek kriptografik doğrulama.
                // receipt_proof = bincode(MerkleProof); leaf'in
                // BDLM_RELAYER_RESULT_V1 result-fact leaf'i olduğu ve path'in
                // external_state_root'a çıktığı kanıtlanır. (Kökün harici
                // finalize commitment'a anchor'ı = EVM light-client → Phase 9;
                // bu kapı kanıt zincirinin kendisini sound şekilde doğrular.)
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

                // Phase 9: Bridge state transition from external result
                if let Some(ref msg) = res.message {
                    if res.success {
                        match msg.kind {
                            crate::cross_domain::message::MessageKind::BridgeLock => {
                                // Inbound lock from external chain -> Mint on Budlum
                                state.bridge_state.mint(msg).map_err(|e| {
                                    BudlumError::validation("bridge_mint_failed", e.0)
                                })?;
                                let fee = msg.nonce.saturating_mul(1); // placeholder for fee logic
                                                                       // credit recipient
                                                                       // amount logic needs to be tied to msg payload
                            }
                            crate::cross_domain::message::MessageKind::BridgeBurn => {
                                // Inbound burn (from target back to source) -> Unlock on Budlum
                                // Correlation ID usually links it.
                                if let Some(correlation_id) = msg.correlation_id {
                                    state
                                        .bridge_state
                                        .unlock(correlation_id, msg.source_domain)
                                        .map_err(|e| {
                                            BudlumError::validation("bridge_unlock_failed", e.0)
                                        })?;
                                }
                            }
                            _ => {}
                        }
                    }
                }

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.saturating_sub(tx.fee);
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::AiOfferData { cid, price } => {
                state
                    .marketplace
                    .create_offer(tx.from, *cid, *price)
                    .map_err(|e| BudlumError::validation("offer_invalid", e))?;
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
                // Phase 8.9 / M5: anti-sybil kayıt ücreti. BNS kolundaki
                // H1 deseniyle simetrik: tam minimum ücret zorunlu + tam düşüm.
                if tx.amount < crate::hub::HUB_REGISTER_MIN_FEE {
                    return Err(BudlumError::validation(
                        "hub_insufficient_fee",
                        format!(
                            "App registration requires {} fee, provided: {}",
                            crate::hub::HUB_REGISTER_MIN_FEE,
                            tx.amount
                        ),
                    ));
                }
                state.hub.register_app(
                    name.clone(),
                    tx.from,
                    category.clone(),
                    website_url.clone(),
                    *manifest_id,
                    state.epoch_index,
                );
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender
                    .balance
                    .saturating_sub(tx.fee)
                    .saturating_sub(crate::hub::HUB_REGISTER_MIN_FEE);
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::AiModelRegister(spec) => {
                let mut spec = spec.clone();
                if spec.owner != tx.from {
                    spec.owner = tx.from;
                }
                state
                    .ai_registry
                    .register_model(spec)
                    .map_err(|e| BudlumError::validation("ai_model_registration_failed", e))?;
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.saturating_sub(tx.fee);
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::AiInferenceRequest(req) => {
                let mut req = req.clone();
                if req.requester != tx.from {
                    req.requester = tx.from;
                }
                {
                    let sender = state.get_or_create(&tx.from);
                    if sender.balance < req.max_fee.saturating_add(tx.fee) {
                        return Err(BudlumError::validation(
                            "ai_insufficient_fee_balance",
                            "Sender balance insufficient for AI inference request max_fee",
                        ));
                    }
                }
                // P5 Bulgu 1 — Executor-layer deadline enforcement (defense-in-depth):
                let current_block = state.epoch_index.saturating_mul(100);
                state
                    .ai_registry
                    .submit_request(req.clone(), current_block)
                    .map_err(|e| BudlumError::validation("ai_request_failed", e))?;
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender
                    .balance
                    .saturating_sub(tx.fee)
                    .saturating_sub(req.max_fee);
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::AiInferenceResult(res) => {
                // P5 Bulgu 2 — Verifier auth via PermissionlessRegistry RoleId(6).
                // AI verifiers must be registered in the permissionless registry
                // with AI_VERIFIER role, not just PoS validators.
                {
                    let is_registered_verifier = state
                        .registry
                        .is_active(&tx.from, crate::registry::role::roles::AI_VERIFIER);
                    if !is_registered_verifier {
                        // Fallback: also allow PoS validators (backward compat)
                        let validator = state.validators.get(&tx.from);
                        let is_validator = validator
                            .map(|v| v.active && v.stake >= 1_000)
                            .unwrap_or(false);
                        if !is_validator {
                            return Err(BudlumError::validation(
                                "ai_verifier_unauthorized",
                                "Verifier must be registered as AI_VERIFIER (RoleId=6) or be an active validator with >= 1000 stake",
                            ));
                        }
                    }
                }
                let mut res = res.clone();
                if res.verifier != tx.from {
                    res.verifier = tx.from;
                }
                // P5 Bulgu 1 — Executor-layer deadline enforcement (defense-in-depth):
                let current_block = state.epoch_index.saturating_mul(100);
                let outcome = state
                    .ai_registry
                    .submit_result(res.clone(), current_block)
                    .map_err(|e| BudlumError::validation("ai_result_failed", e))?;

                if let Some(finalized) = outcome {
                    let req = state.ai_registry.requests.get(&finalized.request_id);
                    if let Some(req) = req {
                        if !finalized.agreeing_verifiers.is_empty() {
                            // P5 Bulgu 16: Integer division remainder protection.
                            // max_fee / verifier_count loses the remainder.
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
                                acc.balance =
                                    acc.balance.saturating_add(reward_per_verifier + extra);
                            }
                        }
                    }
                }

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.saturating_sub(tx.fee);
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::AiFeeReclaim(request_id) => {
                // P5 Bulgu 4: Reclaim escrowed max_fee for expired unfinalized request.
                // Only the original requester can reclaim their fee.
                let current_block = state.epoch_index.saturating_mul(100);
                let (requester, max_fee) = state
                    .ai_registry
                    .reclaim_fee(&request_id, current_block)
                    .map_err(|e| BudlumError::validation("ai_fee_reclaim_failed", e))?;

                // Only the original requester can reclaim
                if requester != tx.from {
                    return Err(BudlumError::validation(
                        "ai_fee_reclaim_unauthorized",
                        "Only the original requester can reclaim the escrowed fee",
                    ));
                }

                // Refund max_fee to the requester
                let requester_acc = state.get_or_create(&tx.from);
                requester_acc.balance = requester_acc.balance.saturating_add(max_fee);

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.saturating_sub(tx.fee);
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::AiModelDeactivate(model_id) => {
                // P5 Bulgu 6: Deactivate an AI model (owner-only).
                state
                    .ai_registry
                    .deactivate_model(&model_id, &tx.from)
                    .map_err(|e| BudlumError::validation("ai_model_deactivate_failed", e))?;

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.saturating_sub(tx.fee);
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::AiModelReactivate(model_id) => {
                // P5 ADIM7 Bulgu 6 extension: Reactivate a previously
                // deactivated AI model (owner-only).
                state
                    .ai_registry
                    .reactivate_model(&model_id, &tx.from)
                    .map_err(|e| BudlumError::validation("ai_model_reactivate_failed", e))?;

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.saturating_sub(tx.fee);
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::AiRequestCancel(request_id) => {
                // P5 ADIM7 Bulgu 21: Cancel a pending AI inference request.
                // Only the original requester can cancel. Escrowed max_fee
                // is refunded to the requester.
                let current_block = state.epoch_index.saturating_mul(100);
                let (requester, max_fee) = state
                    .ai_registry
                    .cancel_request(&request_id, &tx.from, current_block)
                    .map_err(|e| BudlumError::validation("ai_request_cancel_failed", e))?;

                // Refund escrowed max_fee to the requester
                let requester_acc = state.get_or_create(&requester);
                requester_acc.balance = requester_acc.balance.saturating_add(max_fee);

                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.saturating_sub(tx.fee);
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::AiDisputeSlash {
                request_id,
                verifier,
            } => {
                // P5 ADIM8 Bulgu 23 + ADIM9 Bulgu 25+26: Slash a verifier
                // for equivocation (with dispute window enforcement).
                let current_block = state.epoch_index.saturating_mul(100);
                let (slashed_verifier, seized_stake) = state
                    .ai_registry
                    .slash_equivocator(&request_id, &verifier, current_block)
                    .map_err(|e| BudlumError::validation("ai_dispute_slash_failed", e))?;
                if let Some(validator) = state.validators.get_mut(&slashed_verifier) {
                    validator.slashed = true;
                    validator.active = false;
                    validator.stake = 0;
                }
                // P5 ADIM9 Bulgu 26: Burn seized verifier stake (or send to treasury).
                // For now, burned — prevents economic incentive to slash falsely.
                let _ = seized_stake; // Burned
                let sender = state.get_or_create(&tx.from);
                sender.balance = sender.balance.saturating_sub(tx.fee);
                sender.nonce = sender.nonce.saturating_add(1);
            }
            TransactionType::AiAgentPayment(payment) => {
                // P5 ADIM11 Bulgu 31: Agent-to-Agent payment in Agentic Economy.
                let current_block = state.epoch_index.saturating_mul(100);
                let total_cost = payment.amount.saturating_add(tx.fee);
                // Check sender has sufficient balance
                if state.get_balance(&tx.from) < total_cost {
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
                sender.balance = sender.balance.saturating_sub(total_cost);
                sender.nonce = sender.nonce.saturating_add(1);
                // If not escrowed, credit recipient immediately
                if !payment.is_escrowed() {
                    let recipient = state.get_or_create(&payment.to_agent);
                    recipient.balance = recipient.balance.saturating_add(payment.amount);
                    // Remove from registry (already settled)
                    state.ai_registry.agent_payments.remove(&payment.payment_id);
                }
                // If escrowed, balance stays deducted but recipient is not
                // credited until release_agent_payment is called (by executor
                // on outcome finalization or by explicit release tx).
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
