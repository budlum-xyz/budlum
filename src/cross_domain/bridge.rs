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

// Fix (2026-07-18): `AssetId` used to be an alias for `Hash32` (= [u8;32]),
// which serde_json CANNOT serialise as an object key (the R3 anti-pattern; it
// blows up the moment bridge_state reaches the snapshot or RPC path). It is now
// a String-serde struct following the `Address` pattern in
// `src/core/address.rs`, and `AsRef<[u8]>` keeps the existing
// `hash_fields_bytes` calls working.
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
    #[serde(with = "crate::core::map_keys")]
    transfers: BTreeMap<MessageId, BridgeTransfer>,
    /// Expiry queue: expiry_height -> [message_id]
    /// Fix O(N) sweep DoS by indexing by height.
    expiry_queue: BTreeMap<u64, Vec<MessageId>>,
    pub replay: ReplayNonceStore,
    /// Settled queue: the height a transfer reached a terminal status
    /// (`Unlocked`, or `Active` again after its lock expired) -> [message_id].
    /// `sweep_expired_locks` drops those rows `SETTLED_RETENTION_BLOCKS`
    /// later. Without it `transfers` only ever grew: every row stayed for
    /// the life of the chain, and with it the per-block cost of `root()`,
    /// which hashes every row into the state root.
    ///
    /// Part of the committed state. `drop_settled_rows` removes a transfer
    /// row, and with it a leaf of [`Self::root`], at a height this queue
    /// decides; two nodes with the same rows and different queues would
    /// therefore compute different bridge roots later, so the queue is
    /// hashed into the root as well and a persisted row without it is not
    /// loaded. The readers that filled it with an empty map on load
    /// (`LegacyBridgeStateV1`, `LegacyBridgeStateV2`) are gone for that
    /// reason: no network has launched, so there is no old row to be loyal
    /// to, and a node that pruned on a different schedule than its peers
    /// would have split from them at the first retention cutoff.
    settled_queue: BTreeMap<u64, Vec<MessageId>>,
}

/// Blocks a settled transfer row stays readable after it reached a terminal
/// status, before `sweep_expired_locks` drops it.
///
/// Terminal means nothing can move it again: `unlock` is the last step of the
/// lock/mint/burn/unlock chain, and an expired lock's asset is already back in
/// `Active`. The row is kept for a while so a block explorer or a relayer's
/// audit can still read the receipt of a recent settlement; ten times the
/// replay store's finality depth is long past any reorg the consensus
/// tolerates. Rows in `Locked`, `Minted` or `Burned` are never dropped: they
/// are inventory, not history.
const SETTLED_RETENTION_BLOCKS: u64 = 10 * crate::cross_domain::nonce::FINALITY_PRUNE_DEPTH;

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
            settled_queue: BTreeMap::new(),
            replay: ReplayNonceStore::new(),
        }
    }

    /// How many transfer rows this state holds, terminal or not.
    #[must_use]
    pub fn transfer_count(&self) -> usize {
        self.transfers.len()
    }

    /// Record that `message_id` reached a terminal status at `height`, so
    /// the sweep can drop its row after [`SETTLED_RETENTION_BLOCKS`].
    fn mark_settled(&mut self, message_id: MessageId, height: u64) {
        self.settled_queue
            .entry(height)
            .or_default()
            .push(message_id);
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

    /// Mint a locked transfer on the target domain after relay verification.
    ///
    /// `current_height` is the Budlum chain height at which this mint is
    /// applied. It is threaded to the replay store so that
    /// [`ReplayNonceStore::mark_processed_at`] records *when* the message was
    /// processed; the height-aware pruning in that store then only removes
    /// entries older than the finality window, so replay protection is never
    /// lost on a message that is still within finality.
    ///
    /// Passing the height is what lets the store prune at all. The previous
    /// call used a height-less `mark_processed`, which never prunes and
    /// records no height, so a long-running node leaked the processed-message
    /// set unboundedly (an OOM liveness failure) and had a count-based fallback
    /// whose own documentation warns it opens a replay window.
    pub fn mint(
        &mut self,
        message: &CrossDomainMessage,
        current_height: u64,
    ) -> Result<(), BridgeError> {
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
            .mark_processed_at(message.message_id, current_height)
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

    /// Sum of amounts on transfers still in [`BridgeStatus::Locked`].
    ///
    /// Minted, burned and unlocked transfers are inventory that has already
    /// moved; only the locked set is capital currently trapped in the bridge.
    /// Saturates at `u128::MAX` rather than overflowing a scrape.
    #[must_use]
    pub fn locked_amount_total(&self) -> u128 {
        let mut total = 0u128;
        for transfer in self.transfers.values() {
            if matches!(transfer.status, BridgeStatus::Locked { .. }) {
                total = total.saturating_add(transfer.amount);
            }
        }
        total
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

    /// Return a burned transfer's asset to its source domain.
    ///
    /// `settled_height` is the block this unlock lands in; the row becomes
    /// history at that height and is dropped by the sweep
    /// `SETTLED_RETENTION_BLOCKS` later.
    pub fn unlock(
        &mut self,
        message_id: MessageId,
        source_domain: DomainId,
        settled_height: u64,
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
        // The cross_domain unlock message arrives from the **burn domain**,
        // which is `transfer.target_domain`. The earlier code checked
        // `transfer.source_domain != source_domain`; in production
        // `executor.rs` passes `msg.source_domain` (the burn domain, so
        // target_domain), which gave a 1 != 2 mismatch and refused every
        // unlock. The correct check is that the incoming domain equals the burn
        // domain.
        if transfer.target_domain != source_domain {
            return Err(BridgeError(
                "Unlock must originate from the burn (target) domain".into(),
            ));
        }
        // The asset returns to Active on the **original source domain**, where
        // the lock was made.
        let original_source = transfer.source_domain;
        transfer.status = BridgeStatus::Unlocked {
            domain: original_source,
        };
        let asset_id = transfer.asset_id;
        self.asset_locations.insert(
            asset_id,
            BridgeStatus::Active {
                domain: original_source,
            },
        );
        self.mark_settled(message_id, settled_height);
        Ok(())
    }

    pub fn root(&self) -> Hash32 {
        // The root used to hash only asset_locations, leaving the transfers
        // (owner, recipient, amount, status) out of scope. The transfer
        // metadata now goes into the digest as well.
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
        // The settled queue decides when a transfer leaf above disappears,
        // so it is part of what the root commits to: two nodes with equal
        // rows and unequal queues would agree now and disagree at the
        // retention cutoff.
        for (height, message_ids) in &self.settled_queue {
            for message_id in message_ids {
                leaves.push(hash_fields_bytes(&[
                    b"BDLM_BRIDGE_SETTLED_V1",
                    &height.to_le_bytes(),
                    message_id,
                ]));
            }
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
    /// The owner is returned so the caller can refund the balance.
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
                            self.mark_settled(mid, current_height);
                        }
                    }
                }
            }
        }
        self.drop_settled_rows(current_height);
        released
    }

    /// Drop the rows of transfers that settled `SETTLED_RETENTION_BLOCKS`
    /// or more blocks ago. Runs inside the block-apply sweep, so every node
    /// drops the same rows at the same height and the bridge root stays
    /// consensus-equal.
    fn drop_settled_rows(&mut self, current_height: u64) {
        let cutoff = current_height.saturating_sub(SETTLED_RETENTION_BLOCKS);
        let due: Vec<u64> = self
            .settled_queue
            .range(..=cutoff)
            .map(|(&h, _)| h)
            .collect();
        for h in due {
            if let Some(mids) = self.settled_queue.remove(&h) {
                for mid in mids {
                    // Only a terminal row is dropped. A row re-listed here
                    // that somehow moved again stays; the queue is a hint,
                    // the status is the fact.
                    let terminal = self.transfers.get(&mid).is_some_and(|t| {
                        matches!(
                            t.status,
                            BridgeStatus::Unlocked { .. } | BridgeStatus::Active { .. }
                        )
                    });
                    if terminal {
                        self.transfers.remove(&mid);
                    }
                }
            }
        }
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

        bridge.mint(&message, 0).unwrap();
        assert!(bridge.mint(&message, 0).is_err());
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
        assert!(bridge.unlock(transfer.message_id, 1, 0).is_err());

        let message = event.message.unwrap();
        bridge.mint(&message, 0).unwrap();
        assert!(bridge.unlock(transfer.message_id, 1, 0).is_err());
        bridge.burn(transfer.message_id, 2).unwrap();
        // Regression: unlock must originate from the burn domain (target=2),
        // NOT the original lock source (1). Old code checked source_domain, so
        // Production (msg.source_domain = burn domain = 2) was always rejected.
        assert!(bridge.unlock(transfer.message_id, 9, 0).is_err());
        assert!(bridge.unlock(transfer.message_id, 1, 0).is_err()); // source domain ≠ burn domain
        bridge.unlock(transfer.message_id, 2, 0).unwrap(); // burn domain → succeeds
    }

    fn settled_round(bridge: &mut BridgeState, asset_seed: u8, unlock_height: u64) -> MessageId {
        let asset = AssetId(hash_fields_bytes(&[&[asset_seed]]));
        let owner = Address::from([1u8; 32]);
        let recipient = Address::from([2u8; 32]);
        bridge.register_asset(asset, 1).unwrap();
        let (transfer, event) = bridge
            .lock(1, 2, 10, 0, asset, owner, recipient, 100, u64::MAX)
            .unwrap();
        let message = event.message.unwrap();
        bridge.mint(&message, 0).unwrap();
        bridge.burn(transfer.message_id, 2).unwrap();
        bridge
            .unlock(transfer.message_id, 2, unlock_height)
            .unwrap();
        transfer.message_id
    }

    /// A row that finished its lock/mint/burn/unlock chain is history, and
    /// history leaves the table after the retention window.
    ///
    /// `transfers` had no removal path at all: every row ever created stayed
    /// for the life of the chain, and `root()` hashed all of them on every
    /// block. The row is kept for `SETTLED_RETENTION_BLOCKS` so a recent
    /// settlement can still be read, then the block-apply sweep drops it.
    #[test]
    fn an_unlocked_transfer_leaves_the_table_after_the_retention_window() {
        let mut bridge = BridgeState::new();
        let id = settled_round(&mut bridge, 1, 500);
        assert_eq!(bridge.transfer_count(), 1);

        bridge.sweep_expired_locks(500 + SETTLED_RETENTION_BLOCKS - 1);
        assert!(
            bridge.get_transfer(&id).is_some(),
            "a settled row is readable for the whole retention window"
        );
        bridge.sweep_expired_locks(500 + SETTLED_RETENTION_BLOCKS);
        assert!(
            bridge.get_transfer(&id).is_none(),
            "a settled row is dropped once the window has passed"
        );
        assert_eq!(bridge.transfer_count(), 0);
        assert!(
            bridge.unlock(id, 2, 1).is_err(),
            "a dropped row cannot be moved again"
        );
    }

    /// An expired lock the sweep returned to `Active` is history too.
    #[test]
    fn an_expired_lock_leaves_the_table_after_the_retention_window() {
        let mut bridge = BridgeState::new();
        let asset = AssetId(hash_fields_bytes(&[b"expiring"]));
        let owner = Address::from([1u8; 32]);
        bridge.register_asset(asset, 1).unwrap();
        let (transfer, _) = bridge
            .lock(1, 2, 10, 0, asset, owner, owner, 100, 300)
            .unwrap();
        let released = bridge.sweep_expired_locks(300);
        assert_eq!(released, vec![(owner, 100)]);
        assert!(bridge.get_transfer(&transfer.message_id).is_some());
        bridge.sweep_expired_locks(300 + SETTLED_RETENTION_BLOCKS);
        assert!(bridge.get_transfer(&transfer.message_id).is_none());
    }

    /// Inventory is never dropped: a transfer still locked, minted or burned
    /// is money in flight, however old it is.
    #[test]
    fn transfers_still_in_flight_are_never_dropped() {
        let far = u64::MAX / 2;
        let owner = Address::from([1u8; 32]);
        let mut bridge = BridgeState::new();

        let locked = AssetId(hash_fields_bytes(&[b"locked"]));
        bridge.register_asset(locked, 1).unwrap();
        let (t_locked, _) = bridge
            .lock(1, 2, 10, 0, locked, owner, owner, 1, u64::MAX)
            .unwrap();

        let minted = AssetId(hash_fields_bytes(&[b"minted"]));
        bridge.register_asset(minted, 1).unwrap();
        let (t_minted, e) = bridge
            .lock(1, 2, 11, 0, minted, owner, owner, 1, u64::MAX)
            .unwrap();
        bridge.mint(&e.message.unwrap(), 0).unwrap();

        let burned = AssetId(hash_fields_bytes(&[b"burned"]));
        bridge.register_asset(burned, 1).unwrap();
        let (t_burned, e) = bridge
            .lock(1, 2, 12, 0, burned, owner, owner, 1, u64::MAX)
            .unwrap();
        bridge.mint(&e.message.unwrap(), 0).unwrap();
        bridge.burn(t_burned.message_id, 2).unwrap();

        bridge.sweep_expired_locks(far);
        for (what, id) in [
            ("locked", t_locked.message_id),
            ("minted", t_minted.message_id),
            ("burned", t_burned.message_id),
        ] {
            assert!(
                bridge.get_transfer(&id).is_some(),
                "a {what} transfer must survive the sweep"
            );
        }
        assert_eq!(bridge.transfer_count(), 3);
    }

    /// Dropping a row moves the root, so the drop has to happen at the same
    /// height on every node. It runs in the block-apply sweep, keyed on the
    /// height the row settled at; two states that settle and sweep at the
    /// same heights agree, and a state that has not swept yet does not.
    #[test]
    fn dropping_settled_rows_is_deterministic_and_visible_in_the_root() {
        let mut a = BridgeState::new();
        let mut b = BridgeState::new();
        settled_round(&mut a, 3, 500);
        settled_round(&mut b, 3, 500);
        assert_eq!(a.root(), b.root());
        let before = a.root();

        a.sweep_expired_locks(500 + SETTLED_RETENTION_BLOCKS);
        assert_ne!(
            a.root(),
            before,
            "dropping the row must move the bridge root"
        );
        assert_ne!(
            a.root(),
            b.root(),
            "a node that has not swept yet disagrees"
        );
        b.sweep_expired_locks(500 + SETTLED_RETENTION_BLOCKS);
        assert_eq!(
            a.root(),
            b.root(),
            "the same sweep at the same height agrees"
        );
        assert_eq!(a.transfer_count(), 0);
    }

    /// The retention window is long past what the replay store treats as
    /// final, so a settled row can never be dropped while its message could
    /// still be reorganised. The bound is checked at compile time; the
    /// test pins the concrete number so a change to either constant is a
    /// visible diff here as well.
    #[test]
    fn settled_retention_exceeds_the_replay_finality_depth() {
        const {
            assert!(
                SETTLED_RETENTION_BLOCKS >= 10 * crate::cross_domain::nonce::FINALITY_PRUNE_DEPTH
            );
        }
        assert_eq!(SETTLED_RETENTION_BLOCKS, 10_000);
    }

    /// A persisted row without the settled queue is refused, and the queue
    /// is part of the committed root.
    ///
    /// The row used to load through a fallback shape that left the queue
    /// empty. The queue decides the height at which `drop_settled_rows`
    /// removes a transfer leaf from `root()`, so a node that loaded such a
    /// row kept rows its peers dropped and split from them at the first
    /// retention cutoff. Now the shorter bincode row does not decode, the
    /// JSON form without the field does not either, and two states with the
    /// same rows and different queues have different roots today.
    #[test]
    fn a_state_without_the_settled_queue_is_refused_and_the_queue_is_committed() {
        let mut bridge = BridgeState::new();
        let id = settled_round(&mut bridge, 4, 500);
        assert!(bridge.get_transfer(&id).is_some());

        let empty = BridgeState::new();
        let mut value = serde_json::to_value(&empty).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("settled_queue")
            .expect("the field must be present to be removed");
        assert!(
            serde_json::from_value::<BridgeState>(value).is_err(),
            "a JSON state without the queue must not load with an empty one"
        );

        // The older bincode row is exactly the current row minus its
        // trailing map: bincode is positional and an empty `BTreeMap` is a
        // zero `u64` length, so strip those eight bytes from a state whose
        // queue is empty and the result is what the older build wrote.
        let mut forgot_the_queue = bridge.clone();
        forgot_the_queue.settled_queue.clear();
        let current = bincode::serialize(&forgot_the_queue).unwrap();
        let empty_map = 0u64.to_le_bytes();
        assert!(current.ends_with(&empty_map));
        let older = &current[..current.len() - empty_map.len()];
        assert!(
            bincode::deserialize::<BridgeState>(older).is_err(),
            "the shorter bincode row must be refused"
        );

        // Same rows, different queue: different root, today, not at the cutoff.
        assert_eq!(forgot_the_queue.transfers, bridge.transfers);
        assert_ne!(forgot_the_queue.root(), bridge.root());
        // The full round trip keeps the queue and the root.
        let bytes = bincode::serialize(&bridge).unwrap();
        let back: BridgeState = bincode::deserialize(&bytes).unwrap();
        assert_eq!(back.root(), bridge.root());
        assert!(!back.settled_queue.is_empty());
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
