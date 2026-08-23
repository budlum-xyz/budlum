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

// Fix (2026-07-18): `AssetId` eskiden `Hash32`
// (= [u8;32]) alias'ıydı - serde_json object-key olarak serialize EDİLEMEZDİ
// (R3 anti-pattern; bridge_state snapshot/RPC yoluna girerse patlar). Artık
// String-serde struct (Address deseni, `src/core/address.rs`); AsRef<[u8]> ile
// Mevcut hash_fields_bytes çağrıları uyumlu.
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
            return Err(format!(
                "Invalid asset id length: expected 32, got {}",
                bytes.len()
            ));
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

/// Hex-string serde helper (Address deseni), JSON-safe object-key.
mod asset_id_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(val: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(val))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes =
            hex::decode(s.strip_prefix("0x").unwrap_or(&s)).map_err(serde::de::Error::custom)?;
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
    /// (security audit §3) height at which this lock expires.
    /// `BridgeState::sweep_expired_locks(current_height)` returns
    /// `Locked` transfers to `Active` once `current_height >= expiry_height`,
    /// Preventing permanent DoS via a forgotten/abandoned lock.
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
    /// Fix O(N) sweep DoS by indexing by height.
    expiry_queue: BTreeMap<u64, Vec<MessageId>>,
    pub replay: ReplayNonceStore,
}

/// Split an inbound bridge amount into the recipient's share and the relayer's.
///
/// # Why this exists
///
/// The rate was written out three times in `blockchain.rs` as
/// `amount.saturating_mul(1) / 100`, once per mint/unlock path. Three copies of
/// an economic constant drift: change one and the other two keep the old price
/// without saying so.
///
/// # Why there is a floor
///
/// Integer division rounds down, so a pure percentage charges nothing below
/// `100 / rate` units. At the 1% the call sites used, every transfer of 99 base
/// units or less was relayed for free:
///
///     amount  1 -> fee 0
///     amount 50 -> fee 0
///     amount 99 -> fee 0
///     amount 100 -> fee 1
///
/// The relayer still pays external gas for each of those messages, so an
/// attacker splitting a large bridge into 99-unit pieces moves value across for
/// nothing and bills the relayers for it. The floor makes every relayed message
/// cost something.
///
/// # Errors
///
/// Returns `Err` when the amount cannot cover `min_fee`. Relaying at a loss and
/// crediting a negative balance are both worse than refusing, and the caller
/// surfaces the refusal instead of silently moving zero.
pub fn split_bridge_fee(
    amount: u128,
    fee_ppm: u64,
    min_fee: u64,
) -> Result<(u128, u128), BridgeError> {
    let min_fee = u128::from(min_fee);
    if amount <= min_fee {
        return Err(BridgeError(format!(
            "bridge amount {amount} does not cover the minimum relayer fee {min_fee}"
        )));
    }
    let proportional = amount.saturating_mul(u128::from(fee_ppm)) / 1_000_000u128;
    let fee = proportional.max(min_fee);
    // `amount > min_fee` and `fee_ppm < 100%` (enforced by
    // `RegistryParams::validate`) together keep this below `amount`.
    let recipient = amount.saturating_sub(fee);
    Ok((recipient, fee))
}

/// Refuse a relayed burn whose lock was opened in a different domain.
///
/// A burn message says "the tokens were destroyed on the target chain, release
/// the lock here". Two domains have to agree for that to be true: the domain
/// the lock was opened *from*, and the domain the burn message names as its
/// target. If they differ, the message is talking about a different transfer
/// than the one about to be unlocked.
///
/// # Why this is a function and not two comparisons
///
/// It was two comparisons - one of them missing. Two production paths unlock a
/// bridge transfer: `Blockchain::submit_relay_proof` and the executor's
/// external-result handler. They perform the same six steps (unlock, fetch
/// transfer, split the fee, two overflow refusals, credit), the second was
/// written by copying the first, and its own comment says so. But this check
/// was in the first and not the second, so which check applied depended on
/// which entry point the message arrived through - and an attacker picks the
/// entry point.
///
/// A check that lives in one caller is not a rule, it is a habit. Callers may
/// be added; a rule with one home cannot be forgotten by the next one.
///
/// # Errors
///
/// Returns `Err` when the transfer's source domain is not the burn message's
/// target domain.
pub fn check_burn_matches_lock_domain(
    lock_source_domain: DomainId,
    burn_target_domain: DomainId,
) -> Result<(), BridgeError> {
    if lock_source_domain != burn_target_domain {
        return Err(BridgeError(format!(
            "relayed burn targets domain {burn_target_domain} but the lock was opened from domain {lock_source_domain}"
        )));
    }
    Ok(())
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
        // Verify payload_hash binds to the
        // Stored transfer's asset_id and amount. Without this check, a
        // Relayer could substitute a message with a different payload_hash
        // Claiming a different amount - fund inflation vector.
        let expected_payload = bridge_payload_hash(transfer.asset_id, transfer.amount);
        if message.payload_hash != expected_payload {
            return Err(BridgeError(format!(
                "B2: payload_hash mismatch - message claims {:?}, transfer binds {:?}",
                message.payload_hash, expected_payload
            )));
        }
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
        // (denetimi, cross_domain) unlock
        // Mesajı **burn domain'inden** (transfer.target_domain) gelir. Önceki
        // Kod `transfer.source_domain != source_domain` kontrol ediyordu;
        // Production'da `executor.rs` `msg.source_domain` (= burn domain =
        // Target_domain) geçtiğü için 1 != 2 mismatch → tüm unlock'lar reddi.
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
        // Root eskiden yalnızca asset_locations'ı
        // Hash'liyordu - transfers (owner/recipient/amount/status) kapsam
        // Dışındaydı. Artık transfer metadata da digest'e girer.
        let mut leaves: Vec<Hash32> = self
            .asset_locations
            .iter()
            .map(|(asset_id, status)| {
                let status = status_bytes(status);
                hash_fields_bytes(&[b"BDLM_BRIDGE_ASSET_LEAF_V1", asset_id.as_ref(), &status])
            })
            .collect();
        for (msg_id, transfer) in &self.transfers {
            let status = status_bytes(&transfer.status);
            leaves.push(hash_fields_bytes(&[
                b"BDLM_BRIDGE_TRANSFER_V1",
                msg_id,
                transfer.asset_id.as_ref(),
                &transfer.source_domain.to_le_bytes(),
                &transfer.target_domain.to_le_bytes(),
                &transfer.owner.0,
                &transfer.recipient.0,
                &transfer.amount.to_le_bytes(),
                &status,
                &transfer.source_event_hash,
                &transfer.expiry_height.to_le_bytes(),
            ]));
        }
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

    /// (security audit §3) sweep all `Locked` transfers whose
    /// `expiry_height` is below `current_height`, returning their
    /// `asset_id` back to `Active` so a forgotten/abandoned lock can
    /// Never permanently DoS the bridge. Returns the (asset_id, amount)
    /// List of released locks for the caller's audit log.
    ///
    /// Idempotent: transfers already past `expiry_height` stay `Active`
    /// Once released; subsequent calls are no-ops.
    /// Sweep expired locks and return (owner, amount) for balance refund.
    /// Owner bilgisi döndürülür ki caller bakiye iadesi yapabilsin.
    pub fn sweep_expired_locks(&mut self, current_height: u64) -> Vec<(Address, u128)> {
        let mut released = Vec::new();

        // O(log N) sweep using the expiry queue.
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
                            released.push((t.owner, t.amount));
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
    hash_fields_bytes(&[
        b"BDLM_BRIDGE_PAYLOAD_V1",
        asset_id.as_ref(),
        &amount.to_le_bytes(),
    ])
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
        // Regression: unlock must originate from the burn domain (target=2),
        // NOT the original lock source (1). Old code checked source_domain, so
        // Production (msg.source_domain = burn domain = 2) was always rejected.
        assert!(bridge.unlock(transfer.message_id, 9).is_err());
        assert!(bridge.unlock(transfer.message_id, 1).is_err()); // source domain ≠ burn domain
        bridge.unlock(transfer.message_id, 2).unwrap(); // burn domain → succeeds
    }

    /// Regression: mutating transfer amount without going through state
    /// Transitions must change `root` (transfer metadata is in digest).
    #[test]
    fn forged_transfer_amount_changes_bridge_root() {
        let mut bridge = BridgeState::new();
        let asset = AssetId(hash_fields_bytes(&[b"v24-asset"]));
        let owner = Address::from([0x11u8; 32]);
        let recipient = Address::from([0x22u8; 32]);
        bridge.register_asset(asset, 1).unwrap();
        let (transfer, _event) = bridge
            .lock(1, 2, 10, 0, asset, owner, recipient, 100, 1000)
            .unwrap();
        let root_before = bridge.root();
        // Forge: change amount in-place (simulates corrupted snapshot/memory).
        if let Some(t) = bridge.transfers.get_mut(&transfer.message_id) {
            t.amount = t.amount.saturating_add(999);
        }
        let root_after = bridge.root();
        assert_ne!(
            root_before, root_after,
            "Forged transfer amount must change bridge root"
        );
    }
}

#[cfg(test)]
mod bridge_fee_split {
    use super::{check_burn_matches_lock_domain, split_bridge_fee};

    const PPM_1_PCT: u64 = 10_000;

    /// The regression: a percentage alone charges nothing on small transfers.
    ///
    /// Measured against the arithmetic the three call sites used
    /// (`amount * 1 / 100`):
    ///
    ///     amount  1 -> fee 0
    ///     amount 50 -> fee 0
    ///     amount 99 -> fee 0
    ///
    /// Every one of those is a relayed message with real external gas behind
    /// it, paid for by nobody.
    #[test]
    fn small_transfers_are_no_longer_free() {
        for amount in [11u128, 50, 99, 100] {
            // The hardcoded expression this replaced, written out so the
            // Comparison below is against what the chain really charged.
            // `* 1` is the identity the old call sites carried; clippy is
            // Right that it does nothing, which is the point.
            let old_fee = amount / 100;
            let (recipient, fee) = split_bridge_fee(amount, PPM_1_PCT, 10).expect("covers floor");
            assert!(fee > 0, "amount {amount} relayed for free");
            assert!(
                fee >= old_fee,
                "amount {amount}: new fee {fee} below the old {old_fee}"
            );
            assert_eq!(recipient + fee, amount, "value must be conserved");
        }
    }

    /// Splitting a transfer must not make it cheaper than sending it whole.
    ///
    /// This is the attack the floor exists to stop, stated as a property.
    #[test]
    fn splitting_a_transfer_never_reduces_total_fees() {
        let whole = 10_000u128;
        let (_, single_fee) = split_bridge_fee(whole, PPM_1_PCT, 10).expect("covers floor");

        for pieces in [2u128, 10, 100] {
            let piece = whole / pieces;
            let (_, piece_fee) = split_bridge_fee(piece, PPM_1_PCT, 10).expect("covers floor");
            let total = piece_fee * pieces;
            assert!(
                total >= single_fee,
                "splitting into {pieces} pieces costs {total}, less than {single_fee} whole"
            );
        }
    }

    /// Above the floor the proportional rate is what applies, unchanged.
    ///
    /// Without this the fix could be a floor that swallows every transfer.
    #[test]
    fn large_transfers_still_pay_the_percentage() {
        let (recipient, fee) = split_bridge_fee(1_000_000, PPM_1_PCT, 10).expect("covers floor");
        assert_eq!(fee, 10_000, "1% of 1_000_000");
        assert_eq!(recipient, 990_000);
    }

    /// An amount that cannot cover the floor is refused, not relayed at a loss.
    #[test]
    fn an_amount_below_the_floor_is_refused() {
        assert!(
            split_bridge_fee(10, PPM_1_PCT, 10).is_err(),
            "equal to floor"
        );
        assert!(split_bridge_fee(1, PPM_1_PCT, 10).is_err(), "below floor");
        assert!(
            split_bridge_fee(11, PPM_1_PCT, 10).is_ok(),
            "just above floor"
        );
    }

    /// The recipient is never credited more than arrived, and never nothing.
    #[test]
    fn value_is_conserved_and_the_recipient_is_never_zeroed() {
        for amount in [11u128, 100, 12_345, u128::from(u64::MAX)] {
            let (recipient, fee) = split_bridge_fee(amount, PPM_1_PCT, 10).expect("covers floor");
            assert_eq!(recipient + fee, amount);
            assert!(recipient > 0, "amount {amount} left the recipient nothing");
        }
    }
    #[test]
    fn a_relayed_burn_from_the_wrong_domain_is_refused() {
        // The lock was opened from domain 1; the burn message claims to
        // target domain 9. It is describing some other transfer.
        assert!(check_burn_matches_lock_domain(1, 9).is_err());
        assert!(check_burn_matches_lock_domain(1, 1).is_ok());
    }

    #[test]
    fn both_unlock_paths_call_the_same_domain_rule() {
        // The rule used to live in `submit_relay_proof` and not in the
        // executor's external-result handler, so which check applied depended
        // on which entry point a message arrived through - and an attacker
        // picks the entry point. This test reads the two call sites rather
        // than the behaviour, because the defect was structural: the logic
        // was correct wherever it existed, and absent where it did not.
        let chain = include_str!("../chain/blockchain.rs");
        let executor = include_str!("../execution/executor.rs");
        for (name, src) in [("blockchain.rs", chain), ("executor.rs", executor)] {
            assert!(
                src.contains("check_burn_matches_lock_domain"),
                "{name} unlocks a bridge transfer without calling the shared domain rule"
            );
        }
        // And nobody has re-inlined the old comparison.
        assert!(
            !chain.contains("Relayed burn target domain does not match lock source"),
            "the inline check came back; one rule, one home"
        );
    }
}
