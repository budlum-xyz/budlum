use crate::core::hash::hash_fields_bytes;
use crate::crypto::primitives::{verify_signature, KeyPair};
use crate::domain::types::DomainStatus;
use crate::garden::liveness::{GardenLivenessState, GardenPresenceSignal};
use crate::garden::storage::GardenContentStore;
use crate::garden::types::{
    verify_garden_execution_chain, GardenBlock, GardenBlockHashInput, GardenChainId,
    GardenContentKind, GardenGenesis, GardenImageRecord, GardenMessageRecord, GardenPostRecord,
    GardenTrace, GardenTxKind, GardenVote, SignedGardenTx, TAG_GARDEN_BLOCK,
};
use std::collections::{BTreeMap, BTreeSet};

struct AppliedTraceEntry {
    tx_hash_hex: String,
    kind_label: String,
    sender_hex: String,
    content_id_hex: Option<String>,
}

/// Isolated PoA state machine for a single Garden sovereign domain.
///
/// All state changes occur strictly inside finalized blocks (G-1). Refusals
/// validate completely before mutating state so failed calls leave the chain
/// untouched.
#[derive(Clone, Debug)]
pub struct GardenChainState {
    pub genesis: GardenGenesis,
    pub liveness: GardenLivenessState,
    pub store: GardenContentStore,
    pub height: u64,
    pub current_round: u64,
    pub head_hash: [u8; 32],
    pub blocks: Vec<GardenBlock>,
    pub nonces: BTreeMap<String, u64>,
    pub messages: Vec<GardenMessageRecord>,
    pub posts: Vec<GardenPostRecord>,
    pub images: Vec<GardenImageRecord>,
    pub traces: BTreeMap<String, GardenTrace>,
    pub content_to_tx: BTreeMap<String, String>,
    pub budlum_domain_id: Option<u32>,
    pub last_anchored_budlum_height: Option<u64>,
}

impl GardenChainState {
    pub fn new(
        genesis: GardenGenesis,
        host_name: String,
        storage_root: Option<&std::path::Path>,
    ) -> Result<Self, String> {
        verify_garden_execution_chain(genesis.chain_id.value())?;
        let liveness = GardenLivenessState::new(
            genesis.chain_id,
            genesis.host_pubkey,
            host_name,
            genesis.limits.clone(),
        );
        let store = GardenContentStore::new(
            genesis.chain_id.value(),
            genesis.limits.clone(),
            genesis.placement_table.clone(),
            storage_root,
        )?;
        let head_hash = genesis.genesis_hash;
        Ok(Self {
            genesis,
            liveness,
            store,
            height: 0,
            current_round: 0,
            head_hash,
            blocks: Vec::new(),
            nonces: BTreeMap::new(),
            messages: Vec::new(),
            posts: Vec::new(),
            images: Vec::new(),
            traces: BTreeMap::new(),
            content_to_tx: BTreeMap::new(),
            budlum_domain_id: None,
            last_anchored_budlum_height: None,
        })
    }

    pub fn chain_id(&self) -> GardenChainId {
        self.genesis.chain_id
    }

    pub fn status(&self) -> DomainStatus {
        self.liveness.status
    }

    /// Deterministic PoA slot leader for `(height, round)` (Directive 4.5, 7.6).
    pub fn expected_proposer(&self, height: u64, round: u64) -> Result<[u8; 32], String> {
        let active = self.liveness.active_validator_pubkeys();
        if active.is_empty() {
            return Err("no active validators in garden".into());
        }
        let seed_bytes = hash_fields_bytes(&[
            TAG_GARDEN_BLOCK,
            &self.genesis.genesis_hash,
            &height.to_le_bytes(),
        ]);
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&seed_bytes[..8]);
        let offset = (u64::from_le_bytes(raw) as usize).wrapping_add(round as usize);
        Ok(active[offset % active.len()])
    }

    /// Advance round when the expected slot leader failed to publish a block
    /// within its slot (Directive 4.5, 7.6).
    pub fn advance_round(&mut self) -> Result<(u64, [u8; 32]), String> {
        self.liveness.require_accepts_new_blocks()?;
        let next_round = self.current_round.saturating_add(1);
        let next_height = self.height.saturating_add(1);
        let leader = self.expected_proposer(next_height, next_round)?;
        self.current_round = next_round;
        Ok((next_round, leader))
    }

    /// Quorum threshold for the current active validator set.
    pub fn quorum_threshold(active_count: usize) -> usize {
        if active_count <= 1 {
            1
        } else {
            (2 * active_count) / 3 + 1
        }
    }

    /// Validate a transaction before proposing a block (never mutates state).
    pub fn validate_tx(&self, signed_tx: &SignedGardenTx) -> Result<(), String> {
        signed_tx.verify(self.genesis.chain_id)?;
        let next_expected = self
            .nonces
            .get(&hex::encode(signed_tx.tx.sender))
            .copied()
            .unwrap_or(0);
        if signed_tx.tx.nonce != next_expected {
            return Err(format!(
                "invalid garden tx nonce: expected {}, got {}",
                next_expected, signed_tx.tx.nonce
            ));
        }

        // HostHeartbeat or ReturnValidator(host) is permitted while Frozen so the
        // host can unfreeze the Garden (3.2); all other txs require Active.
        let wakes_frozen_host = match &signed_tx.tx.kind {
            GardenTxKind::HostHeartbeat { .. } => true,
            GardenTxKind::ReturnValidator { pubkey } => *pubkey == self.genesis.host_pubkey,
            _ => false,
        };
        if self.liveness.status == DomainStatus::Retired {
            return Err("garden is Retired".into());
        }
        if self.liveness.status == DomainStatus::Frozen && !wakes_frozen_host {
            return Err("garden is Frozen while host is absent".into());
        }

        match &signed_tx.tx.kind {
            GardenTxKind::JoinValidator {
                pubkey,
                display_name,
            } => {
                if &signed_tx.tx.sender != pubkey {
                    return Err("JoinValidator must be signed by the joining validator".into());
                }
                if display_name.trim().is_empty() || display_name.len() > 64 {
                    return Err("validator display_name must be 1..=64 bytes".into());
                }
                if self.liveness.is_active_validator(pubkey) {
                    return Err("validator already active".into());
                }
                if !self.liveness.validators.contains_key(&hex::encode(pubkey))
                    && self.liveness.active_validator_count() >= self.genesis.limits.max_validators
                {
                    return Err("garden max_validators limit reached".into());
                }
            }
            GardenTxKind::LeaveValidator { pubkey } => {
                if &signed_tx.tx.sender != pubkey {
                    return Err("LeaveValidator must be signed by the leaving validator".into());
                }
                if !self.liveness.is_active_validator(pubkey) {
                    return Err("only an active validator can leave".into());
                }
            }
            GardenTxKind::ReturnValidator { pubkey } => {
                if &signed_tx.tx.sender != pubkey {
                    return Err("ReturnValidator must be signed by the returning validator".into());
                }
                if !self.liveness.validators.contains_key(&hex::encode(pubkey)) {
                    return Err("validator must join via invite before returning".into());
                }
            }
            GardenTxKind::HostHeartbeat { .. } => {
                if signed_tx.tx.sender != self.genesis.host_pubkey {
                    return Err("only the Garden host can send HostHeartbeat".into());
                }
            }
            GardenTxKind::PublishMessage { text } => {
                if !self.liveness.is_active_validator(&signed_tx.tx.sender) {
                    return Err("only active Garden participants can publish messages".into());
                }
                if text.is_empty() || text.len() > self.genesis.limits.max_object_bytes {
                    return Err("message length out of bounds".into());
                }
            }
            GardenTxKind::PublishPost {
                title,
                body,
                image_content_id,
            } => {
                if !self.liveness.is_active_validator(&signed_tx.tx.sender) {
                    return Err("only active Garden participants can publish posts".into());
                }
                if title.trim().is_empty() || title.len() > 256 {
                    return Err("post title must be 1..=256 bytes".into());
                }
                let total = title.len().saturating_add(body.len());
                if total == 0 || total > self.genesis.limits.max_object_bytes {
                    return Err("post payload exceeds max_object_bytes".into());
                }
                if let Some(cid) = image_content_id {
                    let cid_hex = hex::encode(cid);
                    if self.store.resolve_and_verify(&cid_hex).is_err() {
                        return Err("referenced post attachment image not found in Garden".into());
                    }
                }
            }
            GardenTxKind::PublishImage {
                mime_type,
                filename,
                content_id,
                data,
            } => {
                if !self.liveness.is_active_validator(&signed_tx.tx.sender) {
                    return Err("only active Garden participants can upload images".into());
                }
                if mime_type.trim().is_empty() || filename.trim().is_empty() {
                    return Err("image mime_type and filename must be non-empty".into());
                }
                if data.is_empty() || data.len() > self.genesis.limits.max_object_bytes {
                    return Err("image byte length exceeds TESTNET-DEFAULT limit".into());
                }
                let expected =
                    GardenContentStore::compute_content_id(&GardenContentKind::Image, data);
                if &expected != content_id {
                    return Err("image content_id does not match payload digest".into());
                }
            }
        }
        Ok(())
    }

    /// Build a candidate block for the current `(height + 1, round)` signed by
    /// `proposer_kp`, executing transactions on a speculative clone first so
    /// invalid transactions never corrupt state.
    pub fn build_block(
        &self,
        proposer_kp: &KeyPair,
        round: u64,
        timestamp_ms: u64,
        txs: Vec<SignedGardenTx>,
    ) -> Result<GardenBlock, String> {
        let next_height = self.height.saturating_add(1);
        let expected = self.expected_proposer(next_height, round)?;
        let proposer_pk = proposer_kp.public_key_bytes();
        if proposer_pk != expected {
            return Err(format!(
                "wrong PoA proposer for height {} round {}: expected {}, got {}",
                next_height,
                round,
                hex::encode(expected),
                hex::encode(proposer_pk)
            ));
        }

        let mut speculative = self.clone();
        speculative.store = GardenContentStore::new(
            self.genesis.chain_id.value(),
            self.genesis.limits.clone(),
            self.genesis.placement_table.clone(),
            None,
        )?;
        // Copy existing in-memory objects into speculative store without touching disk.
        for obj_cid in self.content_to_tx.keys() {
            if let Ok(obj) = self.store.resolve_and_verify(obj_cid) {
                let active = speculative.liveness.active_validator_pubkeys();
                if !active.is_empty() {
                    let _ =
                        speculative
                            .store
                            .put_object(obj.kind, obj.mime_type, obj.payload, &active);
                }
            }
        }

        speculative.apply_tx_batch(next_height, &txs)?;
        let state_root = speculative.compute_state_root();
        let content_root = speculative.store.content_root();
        let tx_hashes: Vec<[u8; 32]> = txs.iter().map(|t| t.tx_hash).collect();
        let block_hash = GardenBlock::compute_block_hash(&GardenBlockHashInput {
            chain_id: self.genesis.chain_id,
            height: next_height,
            round,
            parent_hash: &self.head_hash,
            proposer: &proposer_pk,
            timestamp_ms,
            tx_hashes: &tx_hashes,
            state_root: &state_root,
            content_root: &content_root,
        });
        let proposer_sig = proposer_kp.sign(&block_hash).to_vec();
        let proposer_vote = GardenVote::sign(
            proposer_kp,
            self.genesis.chain_id,
            next_height,
            round,
            block_hash,
        );

        Ok(GardenBlock {
            chain_id: self.genesis.chain_id,
            height: next_height,
            round,
            parent_hash: self.head_hash,
            proposer: proposer_pk,
            timestamp_ms,
            txs,
            state_root,
            content_root,
            block_hash,
            proposer_sig,
            votes: vec![proposer_vote],
        })
    }

    /// Apply and finalize a block along with its validator votes.
    ///
    /// Executes all verification against a speculative clone first; commits to
    /// `self` and disk storage only if everything succeeds (refusal never
    /// mutates state).
    pub fn apply_finalized_block(&mut self, block: GardenBlock) -> Result<(), String> {
        if block.chain_id != self.genesis.chain_id {
            return Err("block chain_id mismatch".into());
        }
        let expected_height = self.height.saturating_add(1);
        if block.height != expected_height {
            return Err(format!(
                "unexpected garden block height: expected {}, got {}",
                expected_height, block.height
            ));
        }
        if block.parent_hash != self.head_hash {
            return Err("garden block parent_hash mismatch".into());
        }
        let expected_proposer = self.expected_proposer(block.height, block.round)?;
        if block.proposer != expected_proposer {
            return Err("garden block proposer mismatch".into());
        }
        verify_signature(&block.block_hash, &block.proposer_sig, &block.proposer)
            .map_err(|e| format!("invalid proposer signature: {e}"))?;

        let tx_hashes: Vec<[u8; 32]> = block.txs.iter().map(|t| t.tx_hash).collect();
        let recomputed_hash = GardenBlock::compute_block_hash(&GardenBlockHashInput {
            chain_id: block.chain_id,
            height: block.height,
            round: block.round,
            parent_hash: &block.parent_hash,
            proposer: &block.proposer,
            timestamp_ms: block.timestamp_ms,
            tx_hashes: &tx_hashes,
            state_root: &block.state_root,
            content_root: &block.content_root,
        });
        if recomputed_hash != block.block_hash {
            return Err("garden block_hash mismatch".into());
        }

        // Verify PoA validator votes against active validators prior to this block.
        let mut unique_voters = BTreeSet::new();
        for vote in &block.votes {
            if vote.block_hash != block.block_hash
                || vote.height != block.height
                || vote.round != block.round
            {
                return Err("garden vote header mismatch".into());
            }
            if !self.liveness.is_active_validator(&vote.validator) {
                return Err("vote from inactive or unknown validator".into());
            }
            vote.verify(self.genesis.chain_id)?;
            unique_voters.insert(vote.validator);
        }
        let active_count = self.liveness.active_validator_count();
        let needed = Self::quorum_threshold(active_count);
        if unique_voters.len() < needed {
            return Err(format!(
                "insufficient PoA quorum votes: got {}, need {}",
                unique_voters.len(),
                needed
            ));
        }

        // Validate + apply transactions in a speculative copy first.
        let mut speculative = self.clone();
        let applied_content_txs = speculative.apply_tx_batch(block.height, &block.txs)?;
        let computed_state_root = speculative.compute_state_root();
        if computed_state_root != block.state_root {
            return Err("garden state_root mismatch after block execution".into());
        }
        let computed_content_root = speculative.store.content_root();
        if computed_content_root != block.content_root {
            return Err("garden content_root mismatch after block execution".into());
        }

        // Record execution traces with final signing validators.
        let signing_validators_hex: Vec<String> = unique_voters.iter().map(hex::encode).collect();
        let proposer_hex = hex::encode(block.proposer);
        let block_hash_hex = hex::encode(block.block_hash);
        for item in applied_content_txs {
            speculative.traces.insert(
                item.tx_hash_hex.clone(),
                GardenTrace {
                    chain_id: block.chain_id.value(),
                    tx_hash_hex: item.tx_hash_hex,
                    content_id_hex: item.content_id_hex,
                    kind: item.kind_label,
                    sender_hex: item.sender_hex,
                    block_height: block.height,
                    block_round: block.round,
                    block_hash_hex: block_hash_hex.clone(),
                    proposer_hex: proposer_hex.clone(),
                    signing_validators_hex: signing_validators_hex.clone(),
                    budlum_domain_id: speculative.budlum_domain_id,
                    budlum_anchored_height: speculative.last_anchored_budlum_height,
                },
            );
        }

        speculative.height = block.height;
        speculative.current_round = 0;
        speculative.head_hash = block.block_hash;
        speculative.blocks.push(block);

        // If the Garden became Retired (last validator departed), wipe all
        // disk and memory content cleanly.
        if speculative.liveness.status == DomainStatus::Retired {
            speculative.store.wipe_all()?;
        }

        *self = speculative;
        Ok(())
    }

    fn apply_tx_batch(
        &mut self,
        block_height: u64,
        txs: &[SignedGardenTx],
    ) -> Result<Vec<AppliedTraceEntry>, String> {
        let mut trace_entries = Vec::new();
        for signed_tx in txs {
            self.validate_tx(signed_tx)?;
            let sender_hex = hex::encode(signed_tx.tx.sender);
            let tx_hash_hex = hex::encode(signed_tx.tx_hash);
            let next_nonce = self.nonces.get(&sender_hex).copied().unwrap_or(0) + 1;
            self.nonces.insert(sender_hex.clone(), next_nonce);

            match &signed_tx.tx.kind {
                GardenTxKind::JoinValidator {
                    pubkey,
                    display_name,
                } => {
                    self.liveness
                        .join_validator(*pubkey, display_name.clone(), block_height)?;
                    let active = self.liveness.active_validator_pubkeys();
                    self.store.rebalance_after_membership_change(&active)?;
                    trace_entries.push(AppliedTraceEntry {
                        tx_hash_hex,
                        kind_label: "JoinValidator".to_string(),
                        sender_hex,
                        content_id_hex: None,
                    });
                }
                GardenTxKind::LeaveValidator { pubkey } => {
                    self.liveness.leave_validator(pubkey)?;
                    let active = self.liveness.active_validator_pubkeys();
                    self.store.rebalance_after_membership_change(&active)?;
                    trace_entries.push(AppliedTraceEntry {
                        tx_hash_hex,
                        kind_label: "LeaveValidator".to_string(),
                        sender_hex,
                        content_id_hex: None,
                    });
                }
                GardenTxKind::ReturnValidator { pubkey } => {
                    self.liveness.return_validator(pubkey)?;
                    let active = self.liveness.active_validator_pubkeys();
                    self.store.rebalance_after_membership_change(&active)?;
                    trace_entries.push(AppliedTraceEntry {
                        tx_hash_hex,
                        kind_label: "ReturnValidator".to_string(),
                        sender_hex,
                        content_id_hex: None,
                    });
                }
                GardenTxKind::HostHeartbeat { epoch } => {
                    if *epoch > self.liveness.current_epoch {
                        self.liveness.current_epoch = *epoch;
                    }
                    self.liveness.last_host_epoch = self.liveness.last_host_epoch.max(*epoch);
                    self.liveness.host_present = true;
                    if self.liveness.status == DomainStatus::Frozen {
                        self.liveness.status = DomainStatus::Active;
                    }
                    trace_entries.push(AppliedTraceEntry {
                        tx_hash_hex,
                        kind_label: "HostHeartbeat".to_string(),
                        sender_hex,
                        content_id_hex: None,
                    });
                }
                GardenTxKind::PublishMessage { text } => {
                    let active = self.liveness.active_validator_pubkeys();
                    let stored = self.store.put_object(
                        GardenContentKind::Message,
                        "text/plain; charset=utf-8".into(),
                        text.as_bytes().to_vec(),
                        &active,
                    )?;
                    let cid_bytes = GardenContentStore::compute_content_id(
                        &GardenContentKind::Message,
                        text.as_bytes(),
                    );
                    self.content_to_tx
                        .insert(stored.content_id_hex.clone(), tx_hash_hex.clone());
                    self.messages.push(GardenMessageRecord {
                        content_id: cid_bytes,
                        tx_hash: signed_tx.tx_hash,
                        sender: signed_tx.tx.sender,
                        block_height,
                        text: text.clone(),
                    });
                    trace_entries.push(AppliedTraceEntry {
                        tx_hash_hex,
                        kind_label: "PublishMessage".to_string(),
                        sender_hex,
                        content_id_hex: Some(stored.content_id_hex),
                    });
                }
                GardenTxKind::PublishPost {
                    title,
                    body,
                    image_content_id,
                } => {
                    let active = self.liveness.active_validator_pubkeys();
                    let post_bytes = serde_json::to_vec(&(title, body, image_content_id))
                        .map_err(|e| format!("failed to encode post payload: {e}"))?;
                    let stored = self.store.put_object(
                        GardenContentKind::Post,
                        "application/json".into(),
                        post_bytes.clone(),
                        &active,
                    )?;
                    let cid_bytes = GardenContentStore::compute_content_id(
                        &GardenContentKind::Post,
                        &post_bytes,
                    );
                    self.content_to_tx
                        .insert(stored.content_id_hex.clone(), tx_hash_hex.clone());
                    self.posts.push(GardenPostRecord {
                        content_id: cid_bytes,
                        tx_hash: signed_tx.tx_hash,
                        sender: signed_tx.tx.sender,
                        block_height,
                        title: title.clone(),
                        body: body.clone(),
                        image_content_id: *image_content_id,
                    });
                    trace_entries.push(AppliedTraceEntry {
                        tx_hash_hex,
                        kind_label: "PublishPost".to_string(),
                        sender_hex,
                        content_id_hex: Some(stored.content_id_hex),
                    });
                }
                GardenTxKind::PublishImage {
                    mime_type,
                    filename,
                    content_id,
                    data,
                } => {
                    let active = self.liveness.active_validator_pubkeys();
                    let stored = self.store.put_object(
                        GardenContentKind::Image,
                        mime_type.clone(),
                        data.clone(),
                        &active,
                    )?;
                    self.content_to_tx
                        .insert(stored.content_id_hex.clone(), tx_hash_hex.clone());
                    self.images.push(GardenImageRecord {
                        content_id: *content_id,
                        tx_hash: signed_tx.tx_hash,
                        uploader: signed_tx.tx.sender,
                        block_height,
                        mime_type: mime_type.clone(),
                        filename: filename.clone(),
                        byte_len: data.len() as u64,
                    });
                    trace_entries.push(AppliedTraceEntry {
                        tx_hash_hex,
                        kind_label: "PublishImage".to_string(),
                        sender_hex,
                        content_id_hex: Some(stored.content_id_hex),
                    });
                }
            }
        }
        Ok(trace_entries)
    }

    fn compute_state_root(&self) -> [u8; 32] {
        let mut val_buf = Vec::new();
        for (k, v) in &self.liveness.validators {
            val_buf.extend_from_slice(k.as_bytes());
            val_buf.push(u8::from(v.active));
            val_buf.push(u8::from(v.is_host));
        }
        let status_byte = match self.liveness.status {
            DomainStatus::Active => [0u8],
            DomainStatus::Frozen => [1u8],
            DomainStatus::Retired => [2u8],
        };
        hash_fields_bytes(&[
            TAG_GARDEN_BLOCK,
            &self.genesis.genesis_hash,
            &status_byte,
            &val_buf,
            &(self.messages.len() as u64).to_le_bytes(),
            &(self.posts.len() as u64).to_le_bytes(),
            &(self.images.len() as u64).to_le_bytes(),
        ])
    }

    pub fn apply_host_presence(
        &mut self,
        signal: &GardenPresenceSignal,
    ) -> Result<DomainStatus, String> {
        self.liveness.record_host_presence(signal)
    }

    pub fn query_trace_by_tx_or_content(&self, id_hex: &str) -> Option<GardenTrace> {
        let clean = id_hex.strip_prefix("0x").unwrap_or(id_hex);
        if let Some(trace) = self.traces.get(clean) {
            return Some(trace.clone());
        }
        if let Some(tx_hash) = self.content_to_tx.get(clean) {
            return self.traces.get(tx_hash).cloned();
        }
        None
    }
}
