use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::cross_domain::event_tree::{DomainEvent, DomainEventKind};
use crate::cross_domain::message::{
    CrossDomainMessage, CrossDomainMessageParams, MessageId, MessageKind,
};
use crate::cross_domain::nonce::ReplayNonceStore;
use crate::domain::types::{DomainId, Hash32};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// B2 fix (ARENA1, P2 schema-4, 2026-07-18): `AssetId` eskiden `Hash32`
// (= [u8;32]) alias'ıydı — serde_json object-key olarak serialize EDİLEMEZDİ
// (R3 anti-pattern; bridge_state snapshot/RPC yoluna girerse patlar). Artık
// string-serde struct (Address deseni, `src/core/address.rs`); AsRef<[u8]> ile
// mevcut hash_fields_bytes çağrıları uyumlu.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AssetId(#[serde(with = "asset_id_serde")] pub [u8; 32]);

impl AssetId {
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        if s == "0" {
            return Ok(AssetId([0u8; 32]));
        }
        let bytes = hex::decode(s).map_err(|e| e.to_string())?;
        if bytes.len() != 32 {
            return Err(format!("Invalid asset id length: expected 32, got {}", bytes.len()));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        Ok(AssetId(id))
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    pub fn zero() -> Self {
        AssetId([0u8; 32])
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Default for AssetId {
    fn default() -> Self {
        Self::zero()
    }
}

impl std::fmt::Display for AssetId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl std::fmt::Debug for AssetId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AssetId({})", self.to_hex())
    }
}

impl From<[u8; 32]> for AssetId {
    fn from(bytes: [u8; 32]) -> Self {
        AssetId(bytes)
    }
}

impl AsRef<[u8]> for AssetId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Hex-string serde helper (Address deseni) — JSON-safe object-key.
mod asset_id_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(val: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(val))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(s.strip_prefix("0x").unwrap_or(&s))
            .map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "Invalid asset id length: expected 32, got {}",
                bytes.len()
            )));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        Ok(id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BridgeStatus {
    Active { domain: DomainId },
    Locked { domain: DomainId },
    Minted { domain: DomainId },
    Burned { domain: DomainId },
    Unlocked { domain: DomainId },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BridgeTransfer {
    pub message_id: MessageId,
    pub asset_id: AssetId,
    pub source_domain: DomainId,
    pub target_domain: DomainId,
    pub owner: Address,
    pub recipient: Address,
    pub amount: u128,
    pub status: BridgeStatus,
    pub source_event_hash: Hash32,
    /// Phase 0.10 (security audit §3): height at which this lock expires.
    /// `BridgeState::sweep_expired_locks(current_height)` returns
    /// `Locked` transfers to `Active` once `current_height >= expiry_height`,
    /// preventing permanent DoS via a forgotten/abandoned lock.
    #[serde(default)]
    pub expiry_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeError(pub String);

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Bridge error: {}", self.0)
    }
}

impl std::error::Error for BridgeError {}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BridgeState {
    asset_locations: BTreeMap<AssetId, BridgeStatus>,
    transfers: BTreeMap<MessageId, BridgeTransfer>,
    /// Expiry queue: expiry_height -> [message_id]
    /// Phase 9 (ARENA2): Fix O(N) sweep DoS by indexing by height.
    expiry_queue: BTreeMap<u64, Vec<MessageId>>,
    replay: ReplayNonceStore,
}

impl BridgeState {
    pub fn new() -> Self {
        Self {
            asset_locations: BTreeMap::new(),
            transfers: BTreeMap::new(),
            expiry_queue: BTreeMap::new(),
            replay: ReplayNonceStore::new(),
        }
    }

    pub fn register_asset(
        &mut self,
        asset_id: AssetId,
        domain: DomainId,
    ) -> Result<(), BridgeError> {
        if self.asset_locations.contains_key(&asset_id) {
            return Err(BridgeError("Asset is already registered".into()));
        }
        self.asset_locations
            .insert(asset_id, BridgeStatus::Active { domain });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn lock(
        &mut self,
        source_domain: DomainId,
        target_domain: DomainId,
        source_height: u64,
        event_index: u32,
        asset_id: AssetId,
        owner: Address,
        recipient: Address,
        amount: u128,
        expiry_height: u64,
    ) -> Result<(BridgeTransfer, DomainEvent), BridgeError> {
        self.require_asset_status(
            asset_id,
            BridgeStatus::Active {
                domain: source_domain,
            },
        )?;
        let nonce = self.replay.next_nonce(source_domain, target_domain, owner);
        let payload_hash = bridge_payload_hash(asset_id, amount);
        let message = CrossDomainMessage::new(CrossDomainMessageParams {
            source_domain,
            target_domain,
            source_height,
            event_index,
            nonce,
            sender: owner,
            recipient,
            payload_hash,
            kind: MessageKind::BridgeLock,
            expiry_height,
        });
        let event = DomainEvent {
            domain_id: source_domain,
            domain_height: source_height,
            event_index,
            kind: DomainEventKind::BridgeLocked,
            emitter: owner,
            message: Some(message.clone()),
            payload_hash,
        };
        let transfer = BridgeTransfer {
            message_id: message.message_id,
            asset_id,
            source_domain,
            target_domain,
            owner,
            recipient,
            amount,
            status: BridgeStatus::Locked {
                domain: source_domain,
            },
            source_event_hash: event.leaf_hash(),
            expiry_height,
        };

        self.asset_locations.insert(
            asset_id,
            BridgeStatus::Locked {
                domain: source_domain,
            },
        );
        self.transfers.insert(transfer.message_id, transfer.clone());
        if expiry_height > 0 {
            self.expiry_queue
                .entry(expiry_height)
                .or_default()
                .push(transfer.message_id);
        }
        Ok((transfer, event))
    }

    pub fn mint(&mut self, message: &CrossDomainMessage) -> Result<(), BridgeError> {
        if !message.verify_id() {
            return Err(BridgeError("Invalid cross-domain message id".into()));
        }
        let transfer = self
            .transfers
            .get(&message.message_id)
            .ok_or_else(|| BridgeError("Unknown bridge transfer".into()))?;
        if self.replay.is_processed(&message.message_id) {
            return Err(BridgeError(
                "Cross-domain message was already processed".into(),
            ));
        }
        if transfer.status
            != (BridgeStatus::Locked {
                domain: message.source_domain,
            })
        {
            return Err(BridgeError(
                "Transfer is not locked on source domain".into(),
            ));
        }
        self.replay
            .mark_processed(message.message_id)
            .map_err(BridgeError)?;

        let transfer = self
            .transfers
            .get_mut(&message.message_id)
            .ok_or_else(|| BridgeError("Unknown bridge transfer".into()))?;

        transfer.status = BridgeStatus::Minted {
            domain: message.target_domain,
        };
        self.asset_locations.insert(
            transfer.asset_id,
            BridgeStatus::Minted {
                domain: message.target_domain,
            },
        );
        Ok(())
    }

    pub fn get_transfer(&self, message_id: &MessageId) -> Option<&BridgeTransfer> {
        self.transfers.get(message_id)
    }

    pub fn burn(&mut self, message_id: MessageId, domain: DomainId) -> Result<(), BridgeError> {
        self.burn_with_event(message_id, domain, 0, 0, 0)
            .map(|_| ())
    }

    pub fn burn_with_event(
        &mut self,
        message_id: MessageId,
        domain: DomainId,
        domain_height: u64,
        event_index: u32,
        expiry_height: u64,
    ) -> Result<DomainEvent, BridgeError> {
        let transfer = self
            .transfers
            .get(&message_id)
            .ok_or_else(|| BridgeError("Unknown bridge transfer".into()))?;
        if transfer.status != (BridgeStatus::Minted { domain }) {
            return Err(BridgeError("Transfer is not minted on burn domain".into()));
        }
        let asset_id = transfer.asset_id;
        let amount = transfer.amount;
        let source_domain = transfer.source_domain;
        let owner = transfer.owner;
        let recipient = transfer.recipient;

        let nonce = self.replay.next_nonce(domain, source_domain, recipient);
        let payload_hash = bridge_payload_hash(asset_id, amount);
        let message = CrossDomainMessage::new_correlated(
            CrossDomainMessageParams {
                source_domain: domain,
                target_domain: source_domain,
                source_height: domain_height,
                event_index,
                nonce,
                sender: recipient,
                recipient: owner,
                payload_hash,
                kind: MessageKind::BridgeBurn,
                expiry_height,
            },
            message_id,
        );
        let event = DomainEvent {
            domain_id: domain,
            domain_height,
            event_index,
            kind: DomainEventKind::BridgeBurned,
            emitter: recipient,
            message: Some(message),
            payload_hash,
        };

        let transfer = self
            .transfers
            .get_mut(&message_id)
            .ok_or_else(|| BridgeError("Unknown bridge transfer".into()))?;
        transfer.status = BridgeStatus::Burned { domain };
        self.asset_locations
            .insert(transfer.asset_id, BridgeStatus::Burned { domain });
        Ok(event)
    }

    pub fn unlock(
        &mut self,
        message_id: MessageId,
        source_domain: DomainId,
    ) -> Result<(), BridgeError> {
        let transfer = self
            .transfers
            .get_mut(&message_id)
            .ok_or_else(|| BridgeError("Unknown bridge transfer".into()))?;
        if transfer.status
            != (BridgeStatus::Burned {
                domain: transfer.target_domain,
            })
        {
            return Err(BridgeError(
                "Transfer is not burned on target domain".into(),
            ));
        }
        // V17 fix (ARENAX Phase 10.5 denetimi, ARENA1 cross_domain): unlock
        // mesajı **burn domain'inden** (transfer.target_domain) gelir. Önceki
        // kod `transfer.source_domain != source_domain` kontrol ediyordu;
        // production'da `executor.rs` `msg.source_domain` (= burn domain =
        // target_domain) geçtiğü için 1 != 2 mismatch → tüm unlock'lar reddi.
        // Doğru kontrol: gelen domain burn domain'ine eşit olmalı.
        if transfer.target_domain != source_domain {
            return Err(BridgeError(
                "Unlock must originate from the burn (target) domain".into(),
            ));
        }
        // Asset **orijinal source domain**'de (lock'un yapıldığı yer) Active'e döner.
        let original_source = transfer.source_domain;
        transfer.status = BridgeStatus::Unlocked {
            domain: original_source,
        };
        self.asset_locations.insert(
            transfer.asset_id,
            BridgeStatus::Active {
                domain: original_source,
            },
        );
        Ok(())
    }

    pub fn root(&self) -> Hash32 {
        let leaves: Vec<Hash32> = self
            .asset_locations
            .iter()
            .map(|(asset_id, status)| {
                let status = status_bytes(status);
                hash_fields_bytes(&[b"BDLM_BRIDGE_ASSET_LEAF_V1", asset_id.as_ref(), &status])
            })
            .collect();
        crate::settlement::commitment_tree::merkle_root(&leaves)
    }

    pub fn replay_root(&self) -> Hash32 {
        self.replay.root()
    }

    pub fn source_event_hash(&self, message_id: &MessageId) -> Option<Hash32> {
        self.transfers
            .get(message_id)
            .map(|transfer| transfer.source_event_hash)
    }

    pub fn transfer(&self, message_id: &MessageId) -> Option<&BridgeTransfer> {
        self.transfers.get(message_id)
    }

    /// Phase 0.10 (security audit §3): sweep all `Locked` transfers whose
    /// `expiry_height` is below `current_height`, returning their
    /// `asset_id` back to `Active` so a forgotten/abandoned lock can
    /// never permanently DoS the bridge. Returns the (asset_id, amount)
    /// list of released locks for the caller's audit log.
    ///
    /// Idempotent: transfers already past `expiry_height` stay `Active`
    /// once released; subsequent calls are no-ops.
    pub fn sweep_expired_locks(&mut self, current_height: u64) -> Vec<(AssetId, u128)> {
        let mut released = Vec::new();

        // Phase 9 (ARENA2): O(log N) sweep using the expiry queue.
        let heights: Vec<u64> = self
            .expiry_queue
            .range(..=current_height)
            .map(|(&h, _)| h)
            .collect();

        for h in heights {
            if let Some(mids) = self.expiry_queue.remove(&h) {
                for mid in mids {
                    if let Some(t) = self.transfers.get_mut(&mid) {
                        // Only release if it's still Locked (might have been minted/burned already)
                        if let BridgeStatus::Locked { domain } = t.status.clone() {
                            t.status = BridgeStatus::Active { domain };
                            self.asset_locations
                                .insert(t.asset_id, BridgeStatus::Active { domain });
                            released.push((t.asset_id, t.amount));
                        }
                    }
                }
            }
        }
        released
    }

    fn require_asset_status(
        &self,
        asset_id: AssetId,
        expected: BridgeStatus,
    ) -> Result<(), BridgeError> {
        let current = self
            .asset_locations
            .get(&asset_id)
            .ok_or_else(|| BridgeError("Unknown asset".into()))?;
        if current != &expected {
            return Err(BridgeError(
                "Asset is not active in the source domain".into(),
            ));
        }
        Ok(())
    }
}

pub fn bridge_payload_hash(asset_id: AssetId, amount: u128) -> Hash32 {
    hash_fields_bytes(&[b"BDLM_BRIDGE_PAYLOAD_V1", asset_id.as_ref(), &amount.to_le_bytes()])
}

fn status_bytes(status: &BridgeStatus) -> Vec<u8> {
    match status {
        BridgeStatus::Active { domain } => status_with_domain(b"active", *domain),
        BridgeStatus::Locked { domain } => status_with_domain(b"locked", *domain),
        BridgeStatus::Minted { domain } => status_with_domain(b"minted", *domain),
        BridgeStatus::Burned { domain } => status_with_domain(b"burned", *domain),
        BridgeStatus::Unlocked { domain } => status_with_domain(b"unlocked", *domain),
    }
}

fn status_with_domain(tag: &[u8], domain: DomainId) -> Vec<u8> {
    let mut out = tag.to_vec();
    out.extend_from_slice(&domain.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_prevents_replay_mint() {
        let mut bridge = BridgeState::new();
        let asset = AssetId(hash_fields_bytes(&[b"asset"]));
        let owner = Address::zero();
        let recipient = Address::zero();
        bridge.register_asset(asset, 1).unwrap();

        let (_transfer, event) = bridge
            .lock(1, 2, 10, 0, asset, owner, recipient, 100, 1000)
            .unwrap();
        let message = event.message.unwrap();

        bridge.mint(&message).unwrap();
        assert!(bridge.mint(&message).is_err());
    }

    #[test]
    fn bridge_rejects_double_lock_and_out_of_order_transitions() {
        let mut bridge = BridgeState::new();
        let asset = AssetId(hash_fields_bytes(&[b"asset"]));
        let owner = Address::from([1u8; 32]);
        let recipient = Address::from([2u8; 32]);
        bridge.register_asset(asset, 1).unwrap();

        let (transfer, event) = bridge
            .lock(1, 2, 10, 0, asset, owner, recipient, 100, 1000)
            .unwrap();

        assert!(bridge
            .lock(1, 2, 11, 0, asset, owner, recipient, 100, 1000)
            .is_err());
        assert!(bridge.burn(transfer.message_id, 2).is_err());
        assert!(bridge.unlock(transfer.message_id, 1).is_err());

        let message = event.message.unwrap();
        bridge.mint(&message).unwrap();
        assert!(bridge.unlock(transfer.message_id, 1).is_err());
        bridge.burn(transfer.message_id, 2).unwrap();
        // V17 regression: unlock must originate from the burn domain (target=2),
        // NOT the original lock source (1). Old code checked source_domain, so
        // production (msg.source_domain = burn domain = 2) was always rejected.
        assert!(bridge.unlock(transfer.message_id, 9).is_err());
        assert!(bridge.unlock(transfer.message_id, 1).is_err()); // source domain ≠ burn domain
        bridge.unlock(transfer.message_id, 2).unwrap(); // burn domain → succeeds
    }
}
