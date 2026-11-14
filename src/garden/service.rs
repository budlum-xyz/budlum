use crate::crypto::primitives::KeyPair;
use crate::domain::types::DomainStatus;
use crate::garden::invite::GardenInvitePayload;
use crate::garden::liveness::GardenPresenceSignal;
use crate::garden::node::{
    GardenNode, GardenNodeClient, GardenNodeServer, GardenPeerRequest, GardenPeerResponse,
    GardenStatusSnapshot,
};
use crate::garden::storage::{GardenContentStore, GardenStoredObject};
use crate::garden::types::{
    verify_garden_execution_chain, GardenBlock, GardenContentKind, GardenLimits, GardenTrace,
    GardenTxKind, SignedGardenTx,
};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;

/// High-level Garden coordinator wired into Budlum's `RpcServer` to serve
/// `bud_garden*` JSON-RPC calls cleanly.
pub struct GardenService {
    /// Keyed by chain_id string for deterministic string-keyed serialization.
    gardens: BTreeMap<String, GardenServiceEntry>,
    active_chain_id: Option<u64>,
    storage_root: Option<PathBuf>,
    budlum_height: u64,
}

struct GardenServiceEntry {
    host_node: GardenNode,
    participants: BTreeMap<String, GardenNode>,
    timestamp_ms: u64,
}

impl Default for GardenService {
    fn default() -> Self {
        Self::new(None)
    }
}

impl GardenService {
    pub fn new(storage_root: Option<PathBuf>) -> Self {
        Self {
            gardens: BTreeMap::new(),
            active_chain_id: None,
            storage_root,
            budlum_height: 1,
        }
    }

    fn current_entry_mut(
        &mut self,
        chain_id: Option<u64>,
    ) -> Result<&mut GardenServiceEntry, String> {
        let target = chain_id
            .or(self.active_chain_id)
            .ok_or_else(|| "no active Garden exists on this node".to_string())?;
        self.gardens
            .get_mut(&target.to_string())
            .ok_or_else(|| format!("Garden chain {} not found", target))
    }

    fn current_entry(&self, chain_id: Option<u64>) -> Result<&GardenServiceEntry, String> {
        let target = chain_id
            .or(self.active_chain_id)
            .ok_or_else(|| "no active Garden exists on this node".to_string())?;
        self.gardens
            .get(&target.to_string())
            .ok_or_else(|| format!("Garden chain {} not found", target))
    }

    pub fn create_garden(
        &mut self,
        title: String,
        host_name: String,
        host_multiaddr: String,
        relay_multiaddrs: Vec<String>,
        nonce: u64,
    ) -> Result<(GardenInvitePayload, GardenStatusSnapshot), String> {
        let host_storage = self.storage_root.as_ref().map(|r| r.join("host"));
        let mut host_node = GardenNode::new(host_name, host_storage)?;
        host_node.set_network_addrs(host_multiaddr, relay_multiaddrs);
        let invite =
            host_node.create_garden(title, 1_700_000_000_000, nonce, GardenLimits::default())?;
        let snap = host_node.status_snapshot()?;
        let _dir_opt = host_node.storage_dir();
        let chain_id = snap.chain_id;
        let host_hex = hex::encode(host_node.pubkey());
        let mut participants = BTreeMap::new();
        participants.insert(host_hex, host_node_clone_for_participant(&host_node)?);
        self.gardens.insert(
            chain_id.to_string(),
            GardenServiceEntry {
                host_node,
                participants,
                timestamp_ms: 1_700_000_000_000,
            },
        );
        self.active_chain_id = Some(chain_id);
        Ok((invite, snap))
    }

    pub fn get_invite(&self, chain_id: Option<u64>) -> Result<serde_json::Value, String> {
        let entry = self.current_entry(chain_id)?;
        let payload = entry.host_node.invite_payload()?;
        let link = payload.to_invite_link()?;
        let qr_payload = payload.to_qr_payload()?;
        Ok(serde_json::json!({
            "invite_link": link,
            "qr_payload": qr_payload,
            "payload": payload,
        }))
    }

    pub fn join_by_invite(
        &mut self,
        invite_or_qr: &str,
        validator_name: String,
    ) -> Result<serde_json::Value, String> {
        let payload = GardenInvitePayload::decode_any(invite_or_qr)?;
        let storage_root = self.storage_root.as_ref().map(|r| r.join(&validator_name));
        let mut bh = self.budlum_height;
        let entry = self.current_entry_mut(Some(payload.chain_id))?;
        let genesis = entry
            .host_node
            .state
            .as_ref()
            .ok_or_else(|| "host has no genesis".to_string())?
            .genesis
            .clone();

        let mut joiner = GardenNode::new(validator_name.clone(), storage_root)?;
        joiner.init_from_invite(&payload, genesis)?;
        let joiner_pk = joiner.pubkey();
        let joiner_hex = hex::encode(joiner_pk);
        let join_tx = joiner.sign_tx(
            payload.chain_id,
            GardenTxKind::JoinValidator {
                pubkey: joiner_pk,
                display_name: validator_name,
            },
        )?;

        if let Some(host_state) = entry.host_node.state.as_ref() {
            for b in &host_state.blocks {
                joiner.apply_finalized_block(b.clone())?;
            }
        }

        let block =
            Self::finalize_tx_across_entry(entry, &mut bh, vec![join_tx], Some(&mut joiner))?;
        entry.participants.insert(joiner_hex.clone(), joiner);
        self.budlum_height = bh;
        Ok(serde_json::json!({
            "chain_id": payload.chain_id,
            "validator_pubkey_hex": joiner_hex,
            "joined_at_height": block.height,
        }))
    }

    pub fn leave_validator(
        &mut self,
        chain_id: Option<u64>,
        validator_pubkey_hex: &str,
    ) -> Result<GardenStatusSnapshot, String> {
        let mut bh = self.budlum_height;
        let entry = self.current_entry_mut(chain_id)?;
        let chain_num = entry
            .host_node
            .state
            .as_ref()
            .ok_or_else(|| "host has no Garden state".to_string())?
            .genesis
            .chain_id
            .value();
        let leave_tx = {
            let participant = entry
                .participants
                .get_mut(validator_pubkey_hex)
                .ok_or_else(|| format!("unknown Garden validator {}", validator_pubkey_hex))?;
            let pk = participant.pubkey();
            participant.sign_tx(chain_num, GardenTxKind::LeaveValidator { pubkey: pk })?
        };
        Self::finalize_tx_across_entry(entry, &mut bh, vec![leave_tx], None)?;
        let is_retired = entry
            .host_node
            .state
            .as_ref()
            .is_some_and(|s| s.status() == DomainStatus::Retired);
        if is_retired {
            for p in entry.participants.values_mut() {
                let _ = p.leave_local_cleanup();
            }
        } else if let Some(p) = entry.participants.get_mut(validator_pubkey_hex) {
            p.leave_local_cleanup()?;
        }
        let snap = entry.host_node.status_snapshot()?;
        self.budlum_height = bh;
        Ok(snap)
    }

    pub fn return_validator(
        &mut self,
        chain_id: Option<u64>,
        validator_pubkey_hex: &str,
    ) -> Result<GardenStatusSnapshot, String> {
        let mut bh = self.budlum_height;
        let storage_root = self.storage_root.clone();
        let entry = self.current_entry_mut(chain_id)?;
        let chain_num = entry
            .host_node
            .state
            .as_ref()
            .ok_or_else(|| "host has no Garden state".to_string())?
            .genesis
            .chain_id
            .value();
        // Refresh returning node from host's current state so it catches up
        // before proposing/applying the ReturnValidator block.
        let host_state_snapshot = entry.host_node.state.clone();
        let return_tx = {
            let participant = entry
                .participants
                .get_mut(validator_pubkey_hex)
                .ok_or_else(|| format!("unknown Garden validator {}", validator_pubkey_hex))?;
            if let Some(mut refreshed) = host_state_snapshot {
                let node_dir = storage_root
                    .as_ref()
                    .map(|r| r.join(&participant.display_name));
                if let Some(dir_root) = node_dir.as_deref() {
                    if let Ok(rebuilt_store) = GardenContentStore::new(
                        chain_num,
                        refreshed.genesis.limits.clone(),
                        refreshed.genesis.placement_table.clone(),
                        Some(dir_root),
                    ) {
                        let active = refreshed.liveness.active_validator_pubkeys();
                        let mut fresh_store = rebuilt_store;
                        for cid in refreshed.content_to_tx.keys() {
                            if let Ok(obj) = refreshed.store.resolve_and_verify(cid) {
                                let _ = fresh_store.put_object(
                                    obj.kind,
                                    obj.mime_type,
                                    obj.payload,
                                    &active,
                                );
                            }
                        }
                        refreshed.store = fresh_store;
                    }
                }
                participant.state = Some(refreshed);
            }
            let pk = participant.pubkey();
            participant.sign_tx(chain_num, GardenTxKind::ReturnValidator { pubkey: pk })?
        };
        Self::finalize_tx_across_entry(entry, &mut bh, vec![return_tx], None)?;
        let snap = entry.host_node.status_snapshot()?;
        self.budlum_height = bh;
        Ok(snap)
    }

    pub fn publish_content(
        &mut self,
        chain_id: u64,
        sender_pubkey_hex: &str,
        kind: GardenContentKind,
        title_or_mime: String,
        body_or_filename: String,
        payload_bytes: Vec<u8>,
    ) -> Result<serde_json::Value, String> {
        verify_garden_execution_chain(chain_id)?;
        let mut bh = self.budlum_height;
        let entry = self.current_entry_mut(Some(chain_id))?;
        let tx_kind = match kind {
            GardenContentKind::Message => GardenTxKind::PublishMessage {
                text: String::from_utf8(payload_bytes)
                    .map_err(|_| "message payload must be valid UTF-8".to_string())?,
            },
            GardenContentKind::Post => GardenTxKind::PublishPost {
                title: title_or_mime,
                body: body_or_filename,
                image_content_id: None,
            },
            GardenContentKind::Image => {
                let cid = GardenContentStore::compute_content_id(
                    &GardenContentKind::Image,
                    &payload_bytes,
                );
                GardenTxKind::PublishImage {
                    mime_type: title_or_mime,
                    filename: body_or_filename,
                    content_id: cid,
                    data: payload_bytes,
                }
            }
        };
        let signed_tx = {
            let participant = entry
                .participants
                .get_mut(sender_pubkey_hex)
                .ok_or_else(|| format!("unknown Garden sender {}", sender_pubkey_hex))?;
            participant.sign_tx(chain_id, tx_kind)?
        };
        let tx_hash_hex = hex::encode(signed_tx.tx_hash);
        let block = match Self::finalize_tx_across_entry(entry, &mut bh, vec![signed_tx], None) {
            Ok(b) => b,
            Err(e) => {
                if let Some(p) = entry.participants.get_mut(sender_pubkey_hex) {
                    p.next_tx_nonce = p.next_tx_nonce.saturating_sub(1);
                }
                return Err(e);
            }
        };
        let trace = entry.host_node.query_trace(&tx_hash_hex);
        self.budlum_height = bh;
        Ok(serde_json::json!({
            "chain_id": chain_id,
            "tx_hash_hex": tx_hash_hex,
            "block_height": block.height,
            "trace": trace,
        }))
    }

    pub fn status(&self, chain_id: Option<u64>) -> Result<GardenStatusSnapshot, String> {
        self.current_entry(chain_id)?.host_node.status_snapshot()
    }

    pub fn advance_round(&mut self, chain_id: Option<u64>) -> Result<serde_json::Value, String> {
        let entry = self.current_entry_mut(chain_id)?;
        let (round, leader) = {
            let state = entry
                .host_node
                .state
                .as_mut()
                .ok_or_else(|| "host has no Garden state".to_string())?;
            state.advance_round()?
        };
        for p in entry.participants.values_mut() {
            if let Some(s) = p.state.as_mut() {
                let _ = s.advance_round();
            }
        }
        Ok(serde_json::json!({
            "round": round,
            "next_proposer_hex": hex::encode(leader),
        }))
    }

    /// Query a remote Garden node over TCP (`GardenPeerRequest::GetStatus`).
    pub fn query_peer_status(&self, peer_addr: &str) -> Result<GardenPeerResponse, String> {
        let addr: SocketAddr = peer_addr
            .parse()
            .map_err(|e| format!("invalid peer socket address '{peer_addr}': {e}"))?;
        GardenNodeClient::call(addr, &GardenPeerRequest::GetStatus)
    }

    /// Spawn a temporary local peer listener for an ephemeral probe and stop it.
    pub fn probe_local_node_listener(&self, chain_id: Option<u64>) -> Result<String, String> {
        let entry = self.current_entry(chain_id)?;
        let probe_node = host_node_clone_for_participant(&entry.host_node)?;
        let mut srv = GardenNodeServer::start("127.0.0.1:0", probe_node)?;
        let resp = GardenNodeClient::call(srv.addr, &GardenPeerRequest::GetStatus)?;
        srv.stop();
        let _stopped = srv.is_stopped();
        Ok(resp.data.to_string())
    }

    pub fn query_trace(&self, chain_id: Option<u64>, id_hex: &str) -> Result<GardenTrace, String> {
        self.current_entry(chain_id)?
            .host_node
            .query_trace(id_hex)
            .ok_or_else(|| format!("trace not found for {}", id_hex))
    }

    pub fn resolve_content(
        &self,
        chain_id: Option<u64>,
        content_id_hex: &str,
    ) -> Result<GardenStoredObject, String> {
        self.current_entry(chain_id)?
            .host_node
            .resolve_content(content_id_hex)
    }

    /// Record a signed host presence signal (7.8) and update Garden + Budlum status.
    pub fn record_host_presence(
        &mut self,
        chain_id: Option<u64>,
        signal: &GardenPresenceSignal,
    ) -> Result<DomainStatus, String> {
        let entry = self.current_entry_mut(chain_id)?;
        let state = entry
            .host_node
            .state
            .as_mut()
            .ok_or_else(|| "host has no Garden state".to_string())?;
        let new_status = state.apply_host_presence(signal)?;
        entry
            .host_node
            .settlement
            .sync_domain_status(state.genesis.chain_id.value(), new_status)?;
        Ok(new_status)
    }

    fn finalize_tx_across_entry(
        entry: &mut GardenServiceEntry,
        budlum_height: &mut u64,
        txs: Vec<SignedGardenTx>,
        extra_joiner: Option<&mut GardenNode>,
    ) -> Result<GardenBlock, String> {
        entry.timestamp_ms = entry.timestamp_ms.saturating_add(1_000);
        let ts = entry.timestamp_ms;

        let (next_height, round, expected_proposer) = {
            let state = entry
                .host_node
                .state
                .as_ref()
                .ok_or_else(|| "host has no Garden state".to_string())?;
            let h = state.height.saturating_add(1);
            let r = state.current_round;
            let p = state.expected_proposer(h, r)?;
            (h, r, p)
        };
        let proposer_hex = hex::encode(expected_proposer);
        let proposer_kp = entry
            .participants
            .get(&proposer_hex)
            .map(|n| n.keypair.clone())
            .ok_or_else(|| "expected PoA proposer keypair not found".to_string())?;

        let mut block = {
            let state = entry
                .host_node
                .state
                .as_ref()
                .ok_or_else(|| "host has no Garden state".to_string())?;
            state.build_block(&proposer_kp, round, ts, txs)?
        };

        let mut collected_votes = Vec::new();
        let mut signer_kps: Vec<KeyPair> = Vec::new();
        for p in entry.participants.values() {
            if let Ok(vote) = p.vote_on_block(&block) {
                collected_votes.push(vote);
                signer_kps.push(p.keypair.clone());
            }
        }
        block.votes = collected_votes;

        entry.host_node.apply_finalized_block(block.clone())?;
        let mut returning_pks = std::collections::BTreeSet::new();
        for tx in &block.txs {
            if let GardenTxKind::ReturnValidator { pubkey } = &tx.tx.kind {
                returning_pks.insert(*pubkey);
            }
        }
        for p in entry.participants.values_mut() {
            let pk = p.pubkey();
            let was_active = p
                .state
                .as_ref()
                .is_some_and(|s| s.liveness.is_active_validator(&pk));
            if was_active || returning_pks.contains(&pk) {
                p.apply_finalized_block(block.clone())?;
            }
        }
        if let Some(joiner) = extra_joiner {
            joiner.apply_finalized_block(block.clone())?;
        }

        *budlum_height = budlum_height.saturating_add(1);
        let bh = *budlum_height;
        if let Some(state) = entry.host_node.state.as_mut() {
            if state.liveness.active_validator_count() > 0 && next_height > 0 {
                let refs: Vec<&KeyPair> = signer_kps.iter().collect();
                let _ = entry
                    .host_node
                    .settlement
                    .anchor_garden_block(state, &block, &refs, bh);
            }
        }

        Ok(block)
    }
}

fn host_node_clone_for_participant(host: &GardenNode) -> Result<GardenNode, String> {
    let mut node = GardenNode::from_keypair(host.keypair.clone(), host.display_name.clone(), None);
    node.set_network_addrs(host.host_multiaddr.clone(), host.relay_multiaddrs.clone());
    node.settlement = host.settlement.clone();
    if let Some(s) = &host.state {
        let mut p_state = crate::garden::consensus::GardenChainState::new(
            s.genesis.clone(),
            host.display_name.clone(),
            None,
        )?;
        p_state.budlum_domain_id = s.budlum_domain_id;
        p_state.last_anchored_budlum_height = s.last_anchored_budlum_height;
        node.state = Some(p_state);
    }
    Ok(node)
}
