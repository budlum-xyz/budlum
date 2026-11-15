//! The Garden state machine.
//!
//! Every validator executes the same blocks and reaches the same state. The
//! functions here read no clock and no local file: a block is valid or not
//! from the previous state and the block alone.

use super::net::validator_dial_address;
use super::settlement::authority_set_hash;
use super::types::{
    is_safe_label, join_message, status_code, verify_garden_execution_chain, GardenBlock,
    GardenCommit, GardenContentKind, GardenGenesis, GardenHeader, GardenKey, GardenTx,
    GardenTxKind, GardenValidator, GardenValidatorStatus, GardenVote, SignedGardenTx,
    MAX_ADDRESS_BYTES, MAX_CAPTION_BYTES, MAX_MIME_BYTES, MAX_NAME_BYTES, MIN_PUBLICATION_CHARGE,
};
use crate::core::hash::hash_fields_bytes;
use crate::crypto::primitives::verify_signature;
use crate::domain::types::{DomainStatus, Hash32};
use std::collections::{BTreeMap, BTreeSet};

/// Byte length of an ed25519 signature.
const SIGNATURE_BYTES: usize = 64;

/// The most one block may move the chain clock forward: one year.
/// TESTNET-DEFAULT. This state machine reads no clock, so it cannot tell a
/// true timestamp from a false one. It can keep one block from using up the
/// range: a block at the far end would leave no later timestamp, and with it
/// no later block. The bound is wide, so a Garden that stood frozen for
/// months still gets the true time on its next block. Whether a timestamp is
/// true is asked where a clock is at hand: a node does not vote for a block
/// dated ahead of its own clock.
const MAX_BLOCK_TIMESTAMP_STEP_MS: u64 = 365 * 24 * 60 * 60 * 1000;

/// Domain tag for the Garden state root.
const TAG_GARDEN_STATE: &[u8] = b"BDLM_GARDEN_STATE_V1";
/// Domain tag for the Garden content root.
const TAG_GARDEN_CONTENT_ROOT: &[u8] = b"BDLM_GARDEN_CONTENT_ROOT_V1";
/// Domain tag for the Garden transaction root.
const TAG_GARDEN_TX_ROOT: &[u8] = b"BDLM_GARDEN_TX_ROOT_V1";

/// A published object as the chain records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GardenObject {
    pub content_id: Hash32,
    pub kind: GardenContentKind,
    pub author: GardenKey,
    pub size: u32,
    pub mime: String,
    pub caption: String,
    pub tx_id: Hash32,
    pub height: u64,
}

/// The state of a Garden chain after some block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GardenState {
    pub genesis: GardenGenesis,
    pub status: DomainStatus,
    pub height: u64,
    pub last_hash: Hash32,
    pub last_timestamp_ms: u64,
    pub validators: BTreeMap<GardenKey, GardenValidator>,
    pub nonces: BTreeMap<GardenKey, u64>,
    /// The publications, by content id and author. The same content may be
    /// published by several validators; each has its own record, so nobody
    /// takes the publication of somebody else by naming its content first.
    pub objects: BTreeMap<(Hash32, GardenKey), GardenObject>,
    /// What each validator has used of its share, in bytes. It follows from
    /// `objects`, so the state root does not name it again.
    pub published: BTreeMap<GardenKey, u64>,
}

/// The root of the transactions of a block.
pub fn tx_root(txs: &[SignedGardenTx]) -> Hash32 {
    let mut bytes = Vec::with_capacity(txs.len() * 32);
    for tx in txs {
        bytes.extend_from_slice(&tx.id());
        bytes.extend_from_slice(&hash_fields_bytes(&[&tx.signature]));
    }
    hash_fields_bytes(&[
        TAG_GARDEN_TX_ROOT,
        &(txs.len() as u64).to_le_bytes(),
        &bytes,
    ])
}

/// The number of votes that is more than two thirds of `electorate`.
pub const fn quorum(electorate: usize) -> usize {
    electorate.saturating_mul(2) / 3 + 1
}

impl GardenState {
    /// The state at height zero: the host is the first validator.
    fn from_genesis(genesis: GardenGenesis) -> Result<Self, String> {
        genesis.verify()?;
        let mut validators = BTreeMap::new();
        validators.insert(
            genesis.host,
            GardenValidator {
                key: genesis.host,
                name: genesis.host_name.clone(),
                address: genesis.host_address.clone(),
                status: GardenValidatorStatus::Active,
                joined_height: 0,
            },
        );
        Ok(Self {
            status: DomainStatus::Active,
            height: 0,
            last_hash: genesis.hash(),
            last_timestamp_ms: genesis.created_unix_ms,
            validators,
            nonces: BTreeMap::new(),
            objects: BTreeMap::new(),
            published: BTreeMap::new(),
            genesis,
        })
    }

    pub const fn chain_id(&self) -> u64 {
        self.genesis.chain_id
    }

    pub const fn host(&self) -> GardenKey {
        self.genesis.host
    }

    /// The active validators, sorted by key.
    pub fn active(&self) -> Vec<GardenKey> {
        self.validators
            .values()
            .filter(|v| v.status == GardenValidatorStatus::Active)
            .map(|v| v.key)
            .collect()
    }

    /// The publications of `content_id`, one for each validator that
    /// published it.
    pub fn publications(&self, content_id: &Hash32) -> impl Iterator<Item = &GardenObject> {
        self.objects
            .range((*content_id, [0u8; 32])..=(*content_id, [0xffu8; 32]))
            .map(|(_, object)| object)
    }

    /// True when a finalized publication names `content_id`.
    pub fn holds_content(&self, content_id: &Hash32) -> bool {
        self.publications(content_id).next().is_some()
    }

    /// True when a finalized publication of `content_id` declares `len`
    /// bytes. A publication is charged by the size it declares, and this
    /// state machine never sees the bytes. So bytes of the declared size are
    /// the only bytes its author was charged for.
    pub fn accounts_for(&self, content_id: &Hash32, len: u64) -> bool {
        self.publications(content_id)
            .any(|object| u64::from(object.size) == len)
    }

    /// The content ids the Garden holds, each one once.
    pub fn content_ids(&self) -> Vec<Hash32> {
        let mut ids: Vec<Hash32> = self.objects.keys().map(|(id, _)| *id).collect();
        ids.dedup();
        ids
    }

    pub fn is_active(&self, key: &GardenKey) -> bool {
        self.validators
            .get(key)
            .is_some_and(|v| v.status == GardenValidatorStatus::Active)
    }

    /// The next nonce `sender` must use.
    pub fn next_nonce(&self, sender: &GardenKey) -> u64 {
        self.nonces.get(sender).copied().unwrap_or(0)
    }

    /// The validators that may propose the next block.
    ///
    /// While the host is away the host is still a proposer, because the only
    /// block that can follow is the one that carries its return.
    fn proposers(&self) -> Vec<GardenKey> {
        let mut set: BTreeSet<GardenKey> = self.active().into_iter().collect();
        if self.status == DomainStatus::Frozen {
            set.insert(self.host());
        }
        set.into_iter().collect()
    }

    /// The proposer of `(next height, round)`.
    pub fn leader(&self, round: u64) -> Option<GardenKey> {
        let proposers = self.proposers();
        let count = u64::try_from(proposers.len()).ok().filter(|n| *n > 0)?;
        let slot = self.height.wrapping_add(1).wrapping_add(round) % count;
        proposers.get(usize::try_from(slot).ok()?).copied()
    }

    /// The validators whose votes finalize a block with these transactions.
    ///
    /// It is the active set before the block, without the validators the
    /// block suspends, and with the host when the block carries its return.
    pub fn electorate(&self, txs: &[SignedGardenTx]) -> Vec<GardenKey> {
        let mut set: BTreeSet<GardenKey> = self.active().into_iter().collect();
        for signed in txs {
            match &signed.tx.kind {
                GardenTxKind::Suspend { target } => {
                    set.remove(target);
                }
                GardenTxKind::Resume { .. }
                    if signed.tx.sender == self.host() && self.status == DomainStatus::Frozen =>
                {
                    set.insert(self.host());
                }
                _ => {}
            }
        }
        set.into_iter().collect()
    }

    /// The state root. It covers the status and every table, the
    /// publication table through `content_root`, the content root of this
    /// state. A header names both roots, and the table is hashed once for
    /// the two.
    fn state_root_over(&self, content_root: &Hash32) -> Hash32 {
        let mut validators = Vec::new();
        for v in self.validators.values() {
            validators.extend_from_slice(&hash_fields_bytes(&[
                &v.key,
                v.name.as_bytes(),
                v.address.as_bytes(),
                &[v.status.code()],
                &v.joined_height.to_le_bytes(),
            ]));
        }
        let mut nonces = Vec::new();
        for (key, nonce) in &self.nonces {
            nonces.extend_from_slice(key);
            nonces.extend_from_slice(&nonce.to_le_bytes());
        }
        hash_fields_bytes(&[
            TAG_GARDEN_STATE,
            &self.genesis.hash(),
            &[status_code(self.status)],
            &(self.validators.len() as u64).to_le_bytes(),
            &validators,
            &(self.nonces.len() as u64).to_le_bytes(),
            &nonces,
            content_root,
        ])
    }

    /// The root of every published object.
    pub fn content_root(&self) -> Hash32 {
        let mut objects = Vec::new();
        for o in self.objects.values() {
            objects.extend_from_slice(&hash_fields_bytes(&[
                &o.content_id,
                &[o.kind.code()],
                &o.author,
                &o.size.to_le_bytes(),
                o.mime.as_bytes(),
                o.caption.as_bytes(),
                &o.tx_id,
                &o.height.to_le_bytes(),
            ]));
        }
        hash_fields_bytes(&[
            TAG_GARDEN_CONTENT_ROOT,
            &(self.objects.len() as u64).to_le_bytes(),
            &objects,
        ])
    }

    /// Choose the transactions of the next block from `pool`, in pool order.
    ///
    /// Returns the chosen transactions and the ids of the ones that can
    /// never be valid again, so the caller can drop them.
    fn select_txs<'a>(
        &self,
        pool: impl Iterator<Item = &'a SignedGardenTx>,
        room: usize,
    ) -> (Vec<SignedGardenTx>, Vec<Hash32>, Self) {
        let limits = &self.genesis.limits;
        let height = self.height.saturating_add(1);
        let mut scratch = self.clone();
        let mut chosen = Vec::new();
        let mut dead = Vec::new();
        let mut per_sender: BTreeMap<GardenKey, u32> = BTreeMap::new();
        for signed in pool {
            if chosen.len() >= room {
                break;
            }
            let used = per_sender.get(&signed.tx.sender).copied().unwrap_or(0);
            if used >= limits.max_sender_txs_per_block {
                continue;
            }
            let expected = scratch.next_nonce(&signed.tx.sender);
            if signed.tx.nonce > expected {
                continue;
            }
            let mut attempt = scratch.clone();
            match attempt.apply_tx(signed, height, None) {
                Ok(()) => {
                    scratch = attempt;
                    per_sender.insert(signed.tx.sender, used.saturating_add(1));
                    chosen.push(signed.clone());
                }
                Err(_) if signed.tx.nonce < expected || self.status == DomainStatus::Active => {
                    dead.push(signed.id());
                }
                Err(_) => {}
            }
        }
        (chosen, dead, scratch)
    }

    /// The transactions the leader `me` puts in the next block: a report for
    /// each validator in `absent`, and what the pool offers in the room that
    /// is left. `sign` signs a report of this leader.
    ///
    /// The reports come first in the count and last in the block. A block
    /// that leaves an absent validator in the electorate may never gather
    /// its votes, so a full pool must not push a report out. The reports are
    /// written after the pool, because the host's return opens the block of
    /// a frozen Garden and the leader's own transactions use the nonces
    /// before them.
    pub fn assemble<'a>(
        &self,
        pool: impl Iterator<Item = &'a SignedGardenTx>,
        me: &GardenKey,
        absent: &[GardenKey],
        sign: impl Fn(GardenTx) -> Option<SignedGardenTx>,
    ) -> (Vec<SignedGardenTx>, Vec<Hash32>) {
        let host = self.host();
        let wanted: BTreeSet<GardenKey> = absent
            .iter()
            .copied()
            .filter(|key| *key != host && key != me && self.is_active(key))
            .collect();
        let block_room = self.genesis.limits.max_block_txs as usize;
        let reserved = wanted.len().min(block_room.saturating_sub(1));
        let (mut txs, dead, mut next) = self.select_txs(pool, block_room.saturating_sub(reserved));
        if txs.is_empty() || next.status != DomainStatus::Active || !next.is_active(me) {
            return (txs, dead);
        }
        let height = self.height.saturating_add(1);
        for target in wanted.into_iter().take(reserved) {
            let report = sign(GardenTx {
                chain_id: self.chain_id(),
                sender: *me,
                nonce: next.next_nonce(me),
                kind: GardenTxKind::Suspend { target },
            });
            let Some(report) = report else {
                continue;
            };
            if next.apply_tx(&report, height, Some(me)).is_ok() {
                txs.push(report);
            }
        }
        (txs, dead)
    }

    /// Cheap field and shape checks on one transaction before any hashing or
    /// signature check runs. Both pending-pool admission and block execution
    /// call this, so a transaction that can never enter a block is refused
    /// at the door.
    pub fn check_tx_shape(&self, signed: &SignedGardenTx) -> Result<(), String> {
        verify_garden_execution_chain(signed.tx.chain_id)?;
        if signed.tx.chain_id != self.chain_id() {
            return Err(format!(
                "garden transaction is for chain {}, this Garden is chain {}",
                signed.tx.chain_id,
                self.chain_id()
            ));
        }
        if signed.signature.len() != SIGNATURE_BYTES {
            return Err("garden transaction signature is invalid: wrong length".into());
        }
        let sender = &signed.tx.sender;
        match &signed.tx.kind {
            GardenTxKind::Join {
                name,
                address,
                invite_signature,
            } => {
                if !is_safe_label(name, MAX_NAME_BYTES) {
                    return Err("validator name must be 1..=32 bytes of plain text".into());
                }
                if address.len() > MAX_ADDRESS_BYTES {
                    return Err("validator address is too long".into());
                }
                if !address.is_empty() {
                    validator_dial_address(address, sender)
                        .map_err(|e| format!("validator address is refused: {e}"))?;
                }
                if invite_signature.len() != SIGNATURE_BYTES {
                    return Err("join request is not signed by the invite".into());
                }
            }
            GardenTxKind::Leave | GardenTxKind::Suspend { .. } => {}
            GardenTxKind::Resume { address } => {
                if address.len() > MAX_ADDRESS_BYTES {
                    return Err("validator address is too long".into());
                }
                if !address.is_empty() {
                    validator_dial_address(address, sender)
                        .map_err(|e| format!("validator address is refused: {e}"))?;
                }
            }
            GardenTxKind::Publish {
                size,
                mime,
                caption,
                ..
            } => {
                let max_object = self.genesis.limits.max_object_bytes;
                if *size == 0 || *size > max_object {
                    return Err(format!(
                        "object size {size} is outside 1..={max_object} bytes"
                    ));
                }
                if mime.len() > MAX_MIME_BYTES || mime.chars().any(char::is_control) {
                    return Err("object MIME type is invalid".into());
                }
                if caption.len() > MAX_CAPTION_BYTES || caption.chars().any(char::is_control) {
                    return Err("object caption is invalid".into());
                }
            }
        }
        Ok(())
    }

    /// Check one transaction against this state without changing anything.
    pub fn check_tx(&self, signed: &SignedGardenTx) -> Result<(), String> {
        if self.status == DomainStatus::Retired {
            return Err("garden is retired; it has no next block".into());
        }
        let mut scratch = self.clone();
        scratch.apply_tx(signed, self.height.saturating_add(1), None)
    }

    /// Apply one transaction. The caller works on a copy, so a refusal leaves
    /// the committed state untouched.
    ///
    /// `leader` is the proposer of the block the transaction stands in, and
    /// `None` for a transaction that stands in no block yet. An absence
    /// report is the leader's own word about the block it builds: it is
    /// valid in that block only and never as a transaction somebody sent.
    fn apply_tx(
        &mut self,
        signed: &SignedGardenTx,
        height: u64,
        leader: Option<&GardenKey>,
    ) -> Result<(), String> {
        self.check_tx_shape(signed)?;
        signed.verify(self.chain_id())?;
        let sender = signed.tx.sender;
        let expected = self.next_nonce(&sender);
        if signed.tx.nonce != expected {
            return Err(format!(
                "garden transaction nonce is {}, expected {expected}",
                signed.tx.nonce
            ));
        }
        let host = self.host();
        let limits = self.genesis.limits.clone();
        let sender_status = self.validators.get(&sender).map(|v| v.status);
        match &signed.tx.kind {
            GardenTxKind::Join {
                name,
                address,
                invite_signature,
            } => {
                if self.status != DomainStatus::Active {
                    return Err("garden is not running; nobody can join now".into());
                }
                if sender_status.is_some() {
                    return Err("this key already joined; use resume to return".into());
                }
                if self.validators.len() >= limits.max_validators as usize {
                    return Err(format!(
                        "garden is full: at most {} validators",
                        limits.max_validators
                    ));
                }
                verify_signature(
                    &join_message(self.chain_id(), &sender),
                    invite_signature,
                    &self.genesis.invite_key,
                )
                .map_err(|_| "join request is not signed by the invite".to_string())?;
                self.validators.insert(
                    sender,
                    GardenValidator {
                        key: sender,
                        name: name.clone(),
                        address: address.clone(),
                        status: GardenValidatorStatus::Active,
                        joined_height: height,
                    },
                );
            }
            GardenTxKind::Leave => {
                if !matches!(
                    sender_status,
                    Some(GardenValidatorStatus::Active | GardenValidatorStatus::Suspended)
                ) {
                    return Err("only a validator of this Garden can leave it".into());
                }
                if let Some(v) = self.validators.get_mut(&sender) {
                    v.status = GardenValidatorStatus::Left;
                }
                if self.active().is_empty() {
                    self.status = DomainStatus::Retired;
                } else if sender == host {
                    self.status = DomainStatus::Frozen;
                }
            }
            GardenTxKind::Resume { address } => {
                // A validator that is away comes back with it. An active one
                // uses it to say where it is now: a node that dropped out
                // without a departure block returns on another address.
                let moved = sender_status == Some(GardenValidatorStatus::Active)
                    && self
                        .validators
                        .get(&sender)
                        .is_some_and(|v| v.address != *address);
                let away = matches!(
                    sender_status,
                    Some(GardenValidatorStatus::Left | GardenValidatorStatus::Suspended)
                );
                if !away && !moved {
                    return Err("only a validator that is away or has moved can resume".into());
                }
                if self.status == DomainStatus::Frozen && sender != host {
                    return Err("garden is frozen until the host returns".into());
                }
                if let Some(v) = self.validators.get_mut(&sender) {
                    v.status = GardenValidatorStatus::Active;
                    v.address.clone_from(address);
                }
                if sender == host {
                    self.status = DomainStatus::Active;
                }
            }
            GardenTxKind::Suspend { target } => {
                if self.status != DomainStatus::Active {
                    return Err("garden is not running".into());
                }
                if sender_status != Some(GardenValidatorStatus::Active) {
                    return Err("only an active validator can report an absence".into());
                }
                if leader != Some(&sender) {
                    return Err(
                        "an absence report counts only from the leader of the block it stands in"
                            .into(),
                    );
                }
                if *target == host {
                    return Err(
                        "the host is never suspended; its absence freezes the Garden".into(),
                    );
                }
                if *target == sender || !self.is_active(target) {
                    return Err("suspend target must be another active validator".into());
                }
                if let Some(v) = self.validators.get_mut(target) {
                    v.status = GardenValidatorStatus::Suspended;
                }
            }
            GardenTxKind::Publish {
                kind,
                content_id,
                size,
                mime,
                caption,
            } => {
                if self.status != DomainStatus::Active {
                    return Err("garden is not running; nothing can be published now".into());
                }
                if sender_status != Some(GardenValidatorStatus::Active) {
                    return Err("only an active validator can publish".into());
                }
                if self.objects.contains_key(&(*content_id, sender)) {
                    return Err("this validator already published this content".into());
                }
                let share = limits.max_published_bytes_per_validator;
                let used = self.published.get(&sender).copied().unwrap_or(0);
                // A publication is charged the size it declares. The chain
                // never sees the bytes, and it does not have to: a node keeps
                // bytes for a publication only when they have the declared
                // size (`accounts_for`), so an understated size buys no
                // storage. Charging a whole object for every publication
                // would bound the same thing, and leave a validator
                // `share / max_object_bytes` messages for the life of the
                // Garden.
                let after = used.saturating_add(u64::from(*size).max(MIN_PUBLICATION_CHARGE));
                if after > share {
                    return Err(format!(
                        "this validator used {used} of its share of {share} bytes; \
                         the publication does not fit"
                    ));
                }
                self.published.insert(sender, after);
                self.objects.insert(
                    (*content_id, sender),
                    GardenObject {
                        content_id: *content_id,
                        kind: *kind,
                        author: sender,
                        size: *size,
                        mime: mime.clone(),
                        caption: caption.clone(),
                        tx_id: signed.id(),
                        height,
                    },
                );
            }
        }
        self.nonces.insert(sender, expected.saturating_add(1));
        Ok(())
    }

    /// Execute `txs` on a copy of this state and build the header that
    /// commits to the result.
    pub fn build_header(
        &self,
        txs: &[SignedGardenTx],
        proposer: GardenKey,
        round: u64,
        timestamp_ms: u64,
    ) -> Result<(GardenHeader, Self), String> {
        let next = self.execute(txs, &proposer)?;
        let content_root = next.content_root();
        let header = GardenHeader {
            chain_id: self.chain_id(),
            height: self.height.saturating_add(1),
            round,
            parent_hash: self.last_hash,
            proposer,
            timestamp_ms: timestamp_ms.clamp(
                self.last_timestamp_ms.saturating_add(1),
                self.last_timestamp_ms
                    .saturating_add(MAX_BLOCK_TIMESTAMP_STEP_MS),
            ),
            tx_root: tx_root(txs),
            state_root: next.state_root_over(&content_root),
            content_root,
            authority_set_hash: authority_set_hash(self.chain_id(), &self.electorate(txs))?,
            next_authority_set_hash: authority_set_hash(self.chain_id(), &next.active())?,
            status_after: next.status,
        };
        Ok((header, next))
    }

    /// Run the block-level rules and every transaction on a copy. `leader`
    /// is the proposer of the block.
    fn execute(&self, txs: &[SignedGardenTx], leader: &GardenKey) -> Result<Self, String> {
        let limits = &self.genesis.limits;
        match self.status {
            DomainStatus::Retired => return Err("garden is retired; it has no next block".into()),
            DomainStatus::Frozen => {
                let returns = txs.first().is_some_and(|first| {
                    first.tx.sender == self.host()
                        && matches!(first.tx.kind, GardenTxKind::Resume { .. })
                });
                if !returns {
                    return Err("garden is frozen until the host returns".into());
                }
            }
            DomainStatus::Active => {}
        }
        if txs.is_empty() {
            return Err("a Garden block carries at least one transaction".into());
        }
        if txs.len() > limits.max_block_txs as usize {
            return Err(format!(
                "block carries {} transactions, the limit is {}",
                txs.len(),
                limits.max_block_txs
            ));
        }
        let mut per_sender: BTreeMap<GardenKey, u32> = BTreeMap::new();
        let mut next = self.clone();
        let height = self.height.saturating_add(1);
        for signed in txs {
            // An absence report is the leader's duty, not a request of its
            // own. Counting it would cap how many validators one block can
            // release, and a block that releases too few never gathers its
            // votes. A block still reports each validator at most once.
            if let GardenTxKind::Suspend { target } = &signed.tx.kind {
                // A report says a validator of the last block went silent.
                // One this block admits or brings back has given no silence
                // to report, and no voter can have heard it yet, so every
                // voter would sign the report.
                if !self.is_active(target) {
                    return Err(
                        "an absence report names a validator of this block, not of the last".into(),
                    );
                }
            } else {
                let count = per_sender.entry(signed.tx.sender).or_insert(0);
                *count = count.saturating_add(1);
                if *count > limits.max_sender_txs_per_block {
                    return Err(format!(
                        "one sender has more than {} transactions in a block",
                        limits.max_sender_txs_per_block
                    ));
                }
            }
            next.apply_tx(signed, height, Some(leader))?;
        }
        if self.electorate(txs).is_empty() {
            return Err("block leaves nobody to finalize it".into());
        }
        Ok(next)
    }

    /// Verify a proposed block against this state and return the state it
    /// leads to. Nothing is changed when the block is refused.
    pub fn verify_block(&self, block: &GardenBlock) -> Result<Self, String> {
        self.check_header(block)?;
        self.run_block(block)
    }

    /// The part of block verification that costs one signature: the block
    /// extends this chain, and the leader of its round signed it. Whatever
    /// costs more runs after this, so only the validator that leads a round
    /// can make a node do that work.
    fn check_header(&self, block: &GardenBlock) -> Result<(), String> {
        let header = &block.header;
        if header.chain_id != self.chain_id() {
            return Err("block is for another Garden".into());
        }
        if header.height != self.height.saturating_add(1) {
            return Err(format!(
                "block height is {}, expected {}",
                header.height,
                self.height.saturating_add(1)
            ));
        }
        if header.parent_hash != self.last_hash {
            return Err("block does not extend the finalized chain".into());
        }
        if header.timestamp_ms <= self.last_timestamp_ms {
            return Err("block timestamp does not advance".into());
        }
        let latest = self
            .last_timestamp_ms
            .saturating_add(MAX_BLOCK_TIMESTAMP_STEP_MS);
        if header.timestamp_ms > latest {
            return Err(format!(
                "block timestamp {} is past {latest}, the furthest one block moves the clock",
                header.timestamp_ms
            ));
        }
        if self.leader(header.round) != Some(header.proposer) {
            return Err("block proposer is not the leader of its round".into());
        }
        verify_signature(&header.hash(), &block.proposer_signature, &header.proposer)
            .map_err(|_| "block proposer signature is invalid".to_string())
    }

    /// Execute a block whose header passed [`Self::check_header`] and return
    /// the state it leads to.
    fn run_block(&self, block: &GardenBlock) -> Result<Self, String> {
        let header = &block.header;
        let (expected, mut next) = self.build_header(
            &block.txs,
            header.proposer,
            header.round,
            header.timestamp_ms,
        )?;
        if expected != *header {
            return Err("block header does not match the executed transactions".into());
        }
        next.height = header.height;
        next.last_hash = header.hash();
        next.last_timestamp_ms = header.timestamp_ms;
        Ok(next)
    }

    /// Verify that `votes` finalize `block`: more than two thirds of the
    /// electorate signed it, and the host is among the signers.
    fn verify_votes(&self, block: &GardenBlock, votes: &[GardenVote]) -> Result<(), String> {
        let electorate: BTreeSet<GardenKey> = self.electorate(&block.txs).into_iter().collect();
        // A block takes one vote from each validator, so a longer list
        // decides nothing. The list comes from the wire and every vote costs
        // a signature check: it is refused before the first one.
        if votes.len() > electorate.len() {
            return Err(format!(
                "commit carries {} votes for an electorate of {}",
                votes.len(),
                electorate.len()
            ));
        }
        let mut signers = BTreeSet::new();
        for vote in votes {
            if !electorate.contains(&vote.voter) {
                return Err("vote from outside the electorate".into());
            }
            if signers.contains(&vote.voter) {
                return Err("commit carries more than one vote of a validator".into());
            }
            vote.verify(&block.header)?;
            signers.insert(vote.voter);
        }
        if !signers.contains(&self.host()) {
            return Err("block is not signed by the host".into());
        }
        let needed = quorum(electorate.len());
        if signers.len() < needed {
            return Err(format!(
                "block has {} of the {needed} votes it needs",
                signers.len()
            ));
        }
        Ok(())
    }

    /// Verify a finalized block and return the state after it.
    ///
    /// The votes are counted before the block is executed. Executing a block
    /// costs far more than checking its votes, and one validator can write
    /// a block; the votes of the host and of two thirds are what one
    /// validator cannot write.
    pub fn apply_commit(&self, commit: &GardenCommit) -> Result<Self, String> {
        self.check_header(&commit.block)?;
        self.verify_votes(&commit.block, &commit.votes)?;
        self.run_block(&commit.block)
    }
}

/// Where a transaction sits in the chain, kept for trace queries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GardenTxLocation {
    height: u64,
    index: u32,
}

/// The finalized chain a validator holds: the state and every commit.
#[derive(Clone, Debug)]
pub struct GardenLedger {
    pub state: GardenState,
    pub commits: Vec<GardenCommit>,
    /// The electorate of each commit, in the same order as `commits`.
    pub electorates: Vec<Vec<GardenKey>>,
    tx_index: BTreeMap<Hash32, GardenTxLocation>,
}

impl GardenLedger {
    pub fn new(genesis: GardenGenesis) -> Result<Self, String> {
        Ok(Self {
            state: GardenState::from_genesis(genesis)?,
            commits: Vec::new(),
            electorates: Vec::new(),
            tx_index: BTreeMap::new(),
        })
    }

    /// Append a finalized block. The ledger is unchanged when it is refused.
    pub fn append(&mut self, commit: GardenCommit) -> Result<(), String> {
        let next = self.state.apply_commit(&commit)?;
        for (index, signed) in commit.block.txs.iter().enumerate() {
            self.tx_index.insert(
                signed.id(),
                GardenTxLocation {
                    height: commit.block.header.height,
                    index: u32::try_from(index).unwrap_or(u32::MAX),
                },
            );
        }
        self.electorates
            .push(self.state.electorate(&commit.block.txs));
        self.state = next;
        self.commits.push(commit);
        Ok(())
    }

    /// The block height and the position in that block of a finalized
    /// transaction.
    pub fn locate(&self, tx_id: &Hash32) -> Option<(u64, u32)> {
        self.tx_index
            .get(tx_id)
            .map(|location| (location.height, location.index))
    }

    /// The commit at `height` and its electorate, when this ledger holds it.
    pub fn commit_at(&self, height: u64) -> Option<(&GardenCommit, &[GardenKey])> {
        let index = usize::try_from(height.checked_sub(1)?).ok()?;
        Some((
            self.commits.get(index)?,
            self.electorates.get(index)?.as_slice(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit::Net;
    use super::super::types::{invite_keypair, GardenLimits};
    use super::*;
    use crate::crypto::primitives::KeyPair;

    #[test]
    fn garden_host_is_the_first_validator_and_joins_need_the_invite() {
        let mut net = Net::new();
        assert_eq!(net.ledger.state.active(), vec![net.host]);
        let a = net.join("alice");
        assert!(net.ledger.state.is_active(&a));
        assert_eq!(net.ledger.state.height, 1);

        let stranger = KeyPair::generate().unwrap();
        let key = stranger.public_key_bytes();
        let forged = invite_keypair(&[6u8; 32])
            .unwrap()
            .sign(&join_message(net.ledger.state.chain_id(), &key))
            .to_vec();
        net.keys.insert(key, stranger);
        let tx = net.tx(
            &key,
            GardenTxKind::Join {
                name: "mallory".into(),
                address: String::new(),
                invite_signature: forged,
            },
        );
        let before = net.ledger.state.clone();
        let refusal = net.commit(vec![tx]).unwrap_err();
        assert!(refusal.contains("not signed by the invite"), "{refusal}");
        assert_eq!(net.ledger.state, before);
    }

    #[test]
    fn garden_block_needs_the_host_and_more_than_two_thirds() {
        let mut net = Net::new();
        let a = net.join("a");
        let b = net.join("b");
        let c = net.join("c");
        let host = net.host;
        let tx = net.publish(&a, 1);
        let block = net.block(vec![tx]).unwrap();

        let without_host = net.votes(&block, &[a, b, c]);
        let refusal = net
            .ledger
            .state
            .verify_votes(&block, &without_host)
            .unwrap_err();
        assert!(refusal.contains("not signed by the host"), "{refusal}");

        let host_alone = net.votes(&block, &[host]);
        assert!(net.ledger.state.verify_votes(&block, &host_alone).is_err());
        let two = net.votes(&block, &[host, a]);
        assert!(net.ledger.state.verify_votes(&block, &two).is_err());
        let three = net.votes(&block, &[host, a, b]);
        net.ledger.state.verify_votes(&block, &three).unwrap();

        let outsider = KeyPair::generate().unwrap();
        let mut padded = three;
        padded.push(GardenVote::sign(&block.header, &outsider));
        assert!(net.ledger.state.verify_votes(&block, &padded).is_err());
        assert_eq!(quorum(1), 1);
        assert_eq!(quorum(2), 2);
        assert_eq!(quorum(3), 3);
        assert_eq!(quorum(6), 5);
    }

    #[test]
    fn garden_refused_block_leaves_the_state_untouched() {
        let mut net = Net::new();
        let a = net.join("a");
        let before = net.ledger.state.clone();
        let good = net.publish(&a, 1);
        let mut replay = good.clone();
        replay.tx.nonce = 7;
        assert!(net.ledger.state.check_tx(&replay).is_err());
        let block = net.block(vec![good.clone()]).unwrap();
        let mut tampered = block;
        tampered.header.state_root = [0u8; 32];
        tampered.proposer_signature = net.keys[&tampered.header.proposer]
            .sign(&tampered.header.hash())
            .to_vec();
        let votes = net.votes(&tampered, &[net.host, a]);
        let refusal = net
            .ledger
            .append(GardenCommit {
                block: tampered,
                votes,
            })
            .unwrap_err();
        assert!(refusal.contains("does not match"), "{refusal}");
        assert_eq!(net.ledger.state, before);
        assert_eq!(net.ledger.commits.len(), 1);

        net.commit(vec![good.clone()]).unwrap();
        let again = net.ledger.state.check_tx(&good).unwrap_err();
        assert!(again.contains("nonce"), "{again}");
    }

    #[test]
    fn garden_host_leave_freezes_and_host_return_resumes() {
        let mut net = Net::new();
        let a = net.join("a");
        let host = net.host;
        net.commit(vec![net.tx(&host, GardenTxKind::Leave)])
            .unwrap();
        assert_eq!(net.ledger.state.status, DomainStatus::Frozen);

        let blocked = net.publish(&a, 1);
        let refusal = net.block(vec![blocked]).unwrap_err();
        assert!(
            refusal.contains("frozen until the host returns"),
            "{refusal}"
        );

        let resume = net.tx(
            &host,
            GardenTxKind::Resume {
                address: String::new(),
            },
        );
        let block = net.block(vec![resume]).unwrap();
        assert_eq!(net.ledger.state.electorate(&block.txs).len(), 2);
        let votes = net.votes(&block, &[host, a]);
        net.ledger.append(GardenCommit { block, votes }).unwrap();
        assert_eq!(net.ledger.state.status, DomainStatus::Active);
        net.commit(vec![net.publish(&a, 1)]).unwrap();
    }

    #[test]
    fn garden_suspended_validator_leaves_the_electorate_and_keeps_its_record() {
        let mut net = Net::new();
        let a = net.join("a");
        let b = net.join("b");
        let host = net.host;
        // The leader of the block is the one that reports.
        let leader = net.ledger.state.leader(0).unwrap();
        let (a, b) = if leader == b { (b, a) } else { (a, b) };
        let name = net.ledger.state.validators[&b].name.clone();
        let about_host = net.tx(&leader, GardenTxKind::Suspend { target: host });
        let refusal = net.block(vec![about_host]).unwrap_err();
        assert!(refusal.contains("never suspended"), "{refusal}");

        let suspend = net.tx(&leader, GardenTxKind::Suspend { target: b });
        let block = net.block(vec![suspend]).unwrap();
        assert_eq!(net.ledger.state.electorate(&block.txs), {
            let mut e = vec![host, a];
            e.sort_unstable();
            e
        });
        let votes = net.votes(&block, &[host, a]);
        net.ledger.append(GardenCommit { block, votes }).unwrap();
        let record = &net.ledger.state.validators[&b];
        assert_eq!(record.status, GardenValidatorStatus::Suspended);
        assert_eq!(record.name, name);

        net.commit(vec![net.tx(
            &b,
            GardenTxKind::Resume {
                address: String::new(),
            },
        )])
        .unwrap();
        assert!(net.ledger.state.is_active(&b));
    }

    #[test]
    fn garden_active_validator_resumes_only_to_announce_a_new_address() {
        let mut net = Net::new();
        let a = net.join("a");
        let same = net.tx(
            &a,
            GardenTxKind::Resume {
                address: String::new(),
            },
        );
        let refusal = net.ledger.state.check_tx(&same).unwrap_err();
        assert!(refusal.contains("away or has moved"), "{refusal}");

        let new_address = format!(
            "/ip4/127.0.0.1/tcp/4001/p2p/{}",
            super::super::net::peer_id_of(&a).unwrap()
        );
        let moved = net.tx(
            &a,
            GardenTxKind::Resume {
                address: new_address.clone(),
            },
        );
        net.commit(vec![moved]).unwrap();
        let record = &net.ledger.state.validators[&a];
        assert_eq!(record.status, GardenValidatorStatus::Active);
        assert_eq!(record.address, new_address);
        assert_eq!(net.ledger.state.status, DomainStatus::Active);
    }

    #[test]
    fn garden_retires_when_the_last_validator_leaves() {
        let mut net = Net::new();
        let a = net.join("a");
        let host = net.host;
        net.commit(vec![net.tx(&a, GardenTxKind::Leave)]).unwrap();
        assert_eq!(net.ledger.state.status, DomainStatus::Active);
        net.commit(vec![net.tx(&host, GardenTxKind::Leave)])
            .unwrap();
        assert_eq!(net.ledger.state.status, DomainStatus::Retired);
        assert!(net.ledger.state.leader(0).is_none());
        let refusal = net
            .ledger
            .state
            .check_tx(&net.publish(&host, 1))
            .unwrap_err();
        assert!(refusal.contains("retired"), "{refusal}");
    }

    #[test]
    fn garden_limits_bound_validators_objects_and_request_rate() {
        let mut net = Net::new();
        let a = net.join("a");
        let max = net.ledger.state.genesis.limits.max_sender_txs_per_block;
        let first = net.ledger.state.next_nonce(&a);
        let mut burst = Vec::new();
        for i in 0..=max {
            let tx = GardenTx {
                chain_id: net.ledger.state.chain_id(),
                sender: a,
                nonce: first + u64::from(i),
                kind: GardenTxKind::Publish {
                    kind: GardenContentKind::Message,
                    content_id: [u8::try_from(i).unwrap() + 1; 32],
                    size: 1,
                    mime: String::new(),
                    caption: String::new(),
                },
            };
            burst.push(tx.sign(&net.keys[&a]).unwrap());
        }
        let refusal = net.block(burst).unwrap_err();
        assert!(refusal.contains("more than"), "{refusal}");

        let too_big = net.tx(
            &a,
            GardenTxKind::Publish {
                kind: GardenContentKind::Image,
                content_id: [9u8; 32],
                size: net.ledger.state.genesis.limits.max_object_bytes + 1,
                mime: "image/png".into(),
                caption: String::new(),
            },
        );
        assert!(net.ledger.state.check_tx(&too_big).is_err());

        let mut small = Net::new();
        small.ledger.state.genesis.limits.max_validators = 2;
        small.ledger.state.last_hash = small.ledger.state.genesis.hash();
        small.join("a");
        let (_, third) = small.join_tx("b");
        let refusal = small.ledger.state.check_tx(&third).unwrap_err();
        assert!(refusal.contains("garden is full"), "{refusal}");
    }

    #[test]
    fn garden_leader_rotates_by_height_and_round() {
        let mut net = Net::new();
        net.join("a");
        net.join("b");
        let state = &net.ledger.state;
        let proposers = state.proposers();
        assert_eq!(proposers.len(), 3);
        let seen: BTreeSet<GardenKey> = (0..3).filter_map(|r| state.leader(r)).collect();
        assert_eq!(seen.len(), 3);
        assert_eq!(state.leader(0), state.leader(3));
        let tx = net.publish(&net.host, 1);
        let mut block = net.block(vec![tx]).unwrap();
        let wrong = proposers
            .iter()
            .copied()
            .find(|k| Some(*k) != net.ledger.state.leader(0))
            .unwrap();
        block.header.proposer = wrong;
        block.proposer_signature = net.keys[&wrong].sign(&block.header.hash()).to_vec();
        let refusal = net.ledger.state.verify_block(&block).unwrap_err();
        assert!(refusal.contains("not the leader"), "{refusal}");
    }

    /// An absence report is the word of the leader of the block it stands
    /// in. A report of anybody else must not reach a block: the host does
    /// not sign a block that reports a validator it still hears, so a report
    /// that every leader picks up again stops the chain for good.
    #[test]
    fn garden_absence_report_counts_only_from_the_leader_of_its_block() {
        let mut net = Net::new();
        for name in ["a", "b", "c"] {
            net.join(name);
        }
        let state = net.ledger.state.clone();
        let host = net.host;
        let leader = state.leader(0).unwrap();
        let others: Vec<GardenKey> = state
            .active()
            .into_iter()
            .filter(|key| *key != host && *key != leader)
            .collect();
        let (member, target) = (others[0], others[1]);
        let claim = net.tx(&member, GardenTxKind::Suspend { target });

        // Sent as a transaction it is refused, so no pool keeps it.
        let refusal = state.check_tx(&claim).unwrap_err();
        assert!(refusal.contains("leader"), "{refusal}");
        // A leader that finds it in its pool leaves it out and drops it.
        let post = net.publish(&host, 1);
        let pool = [post.clone(), claim.clone()];
        let (chosen, dead) = state.assemble(pool.iter(), &leader, &[], |_| None);
        assert_eq!(chosen, vec![post.clone()]);
        assert_eq!(dead, vec![claim.id()]);
        // A block that carries it anyway is no block.
        let refusal = net.block(vec![post, claim]).unwrap_err();
        assert!(refusal.contains("leader"), "{refusal}");
        // The leader's own report is still one.
        let own = reports(&net, &leader, &[target]);
        net.block(own).unwrap();
    }

    /// Two validators say the same thing. Each has its own publication under
    /// its own name, whichever comes first, and nobody takes the content of
    /// somebody else by naming it first.
    #[test]
    fn garden_same_content_is_published_by_each_validator_under_its_own_name() {
        let mut net = Net::new();
        let a = net.join("a");
        let b = net.join("b");
        let first = net.publish(&b, 7);
        let second = net.publish(&a, 7);
        net.commit(vec![first.clone()]).unwrap();
        net.commit(vec![second.clone()]).unwrap();
        let state = &net.ledger.state;
        let content = [7u8; 32];
        assert!(state.holds_content(&content));
        let mut said: Vec<(GardenKey, Hash32)> = state
            .publications(&content)
            .map(|object| (object.author, object.tx_id))
            .collect();
        said.sort_unstable();
        let mut expected = vec![(b, first.id()), (a, second.id())];
        expected.sort_unstable();
        assert_eq!(said, expected);
        assert_eq!(state.content_ids(), vec![content]);
        // One validator has one publication of one content.
        let again = net.publish(&a, 7);
        let refusal = net.ledger.state.check_tx(&again).unwrap_err();
        assert!(refusal.contains("already published"), "{refusal}");
    }

    /// One validator cannot fill the disks of the others: what it publishes
    /// over the life of the Garden has a ceiling.
    #[test]
    fn garden_validator_publishes_up_to_its_share_and_no_more() {
        let mut net = Net::new();
        // A share of three full objects keeps the test short.
        let size = net.ledger.state.genesis.limits.max_object_bytes;
        net.ledger
            .state
            .genesis
            .limits
            .max_published_bytes_per_validator = 3 * u64::from(size);
        net.ledger.state.last_hash = net.ledger.state.genesis.hash();
        let a = net.join("a");
        let b = net.join("b");
        let limits = net.ledger.state.genesis.limits.clone();
        let fits = 3;
        let post = |net: &Net, sender: &GardenKey, n: u64| {
            let mut content_id = [0u8; 32];
            content_id[..8].copy_from_slice(&n.to_le_bytes());
            net.tx(
                sender,
                GardenTxKind::Publish {
                    kind: GardenContentKind::Image,
                    content_id,
                    size,
                    mime: "image/png".into(),
                    caption: String::new(),
                },
            )
        };
        for n in 0..fits {
            let tx = post(&net, &a, n);
            net.commit(vec![tx]).unwrap();
        }
        let over = post(&net, &a, fits);
        let refusal = net.ledger.state.check_tx(&over).unwrap_err();
        assert!(refusal.contains("share"), "{refusal}");
        // The share is per validator: the next one still publishes.
        let other = post(&net, &b, fits + 1);
        net.commit(vec![other]).unwrap();
        // A small publication counts as the record the chain keeps for it.
        let before = net.ledger.state.published[&b];
        let small = net.publish(&b, 9);
        net.commit(vec![small]).unwrap();
        assert_eq!(
            net.ledger.state.published[&b],
            before + MIN_PUBLICATION_CHARGE
        );

        let mut bad = limits;
        bad.max_published_bytes_per_validator = u64::from(size) - 1;
        assert!(bad.validate().is_err());
        // The share is part of what an invite commits to.
        let genesis = net.ledger.state.genesis.clone();
        let mut other_share = genesis.clone();
        other_share.limits.max_published_bytes_per_validator += 1;
        assert_ne!(genesis.hash(), other_share.hash());
    }

    /// A message is charged as a message. With the size of a whole object
    /// charged for each publication, the share would be used up after
    /// `share / max_object_bytes` messages, whatever their size.
    #[test]
    fn garden_small_publications_are_charged_by_their_size_not_as_whole_objects() {
        let mut net = Net::new();
        let host = net.host;
        let limits = net.ledger.state.genesis.limits.clone();
        let whole_objects =
            limits.max_published_bytes_per_validator / u64::from(limits.max_object_bytes);
        let messages = u8::try_from(whole_objects + 1).unwrap();
        for id in 1..=messages {
            net.commit(vec![net.publish(&host, id)]).unwrap();
        }
        assert_eq!(
            net.ledger.state.published[&host],
            u64::from(messages) * MIN_PUBLICATION_CHARGE
        );
    }

    /// The reports of `leader` about `targets`, as a proposer writes them.
    fn reports(net: &Net, leader: &GardenKey, targets: &[GardenKey]) -> Vec<SignedGardenTx> {
        let first = net.ledger.state.next_nonce(leader);
        targets
            .iter()
            .zip(first..)
            .map(|(target, nonce)| {
                GardenTx {
                    chain_id: net.ledger.state.chain_id(),
                    sender: *leader,
                    nonce,
                    kind: GardenTxKind::Suspend { target: *target },
                }
                .sign(net.key(leader))
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn garden_block_reports_every_absent_validator_at_once() {
        let mut net = Net::new();
        for i in 0..12 {
            net.join(&format!("v{i}"));
        }
        let state = &net.ledger.state;
        let leader = state.leader(0).unwrap();
        let host = net.host;
        let gone: Vec<GardenKey> = state
            .active()
            .into_iter()
            .filter(|key| *key != host && *key != leader)
            .take(10)
            .collect();
        assert_eq!(gone.len(), 10);
        assert!(gone.len() > state.genesis.limits.max_sender_txs_per_block as usize);
        // The ten are gone at once. Only a block that reports all of them
        // leaves an electorate the three that stayed can satisfy.
        let stayed: Vec<GardenKey> = state
            .active()
            .into_iter()
            .filter(|key| !gone.contains(key))
            .collect();
        let block = net.block(reports(&net, &leader, &gone)).unwrap();
        assert_eq!(net.ledger.state.electorate(&block.txs), stayed);
        let votes = net.votes(&block, &stayed);
        net.ledger.append(GardenCommit { block, votes }).unwrap();
        assert_eq!(net.ledger.state.active(), stayed);
        assert_eq!(net.ledger.state.status, DomainStatus::Active);
    }

    #[test]
    fn garden_leader_keeps_room_for_absence_reports_in_a_full_block() {
        let mut net = Net::new();
        let limits = GardenLimits {
            max_validators: 8,
            max_block_txs: 8,
            max_sender_txs_per_block: 8,
            ..GardenLimits::default()
        };
        limits.validate().unwrap();
        net.ledger.state.genesis.limits = limits;
        net.ledger.state.last_hash = net.ledger.state.genesis.hash();
        let a = net.join("a");
        let b = net.join("b");
        let c = net.join("c");
        let leader = net.ledger.state.leader(0).unwrap();
        let host = net.host;
        let mut gone: Vec<GardenKey> = [a, b, c]
            .into_iter()
            .filter(|key| *key != leader)
            .take(2)
            .collect();
        gone.sort_unstable();
        // A pool that fills the block on its own.
        let writer = if leader == host { a } else { host };
        let first = net.ledger.state.next_nonce(&writer);
        let pool: Vec<SignedGardenTx> = (0..8u8)
            .map(|i| {
                GardenTx {
                    chain_id: net.ledger.state.chain_id(),
                    sender: writer,
                    nonce: first + u64::from(i),
                    kind: GardenTxKind::Publish {
                        kind: GardenContentKind::Message,
                        content_id: [i + 1; 32],
                        size: 1,
                        mime: String::new(),
                        caption: String::new(),
                    },
                }
                .sign(net.key(&writer))
                .unwrap()
            })
            .collect();
        let key = net.key(&leader);
        let (txs, _) = net
            .ledger
            .state
            .assemble(pool.iter(), &leader, &gone, |tx| tx.sign(key).ok());
        assert_eq!(txs.len(), 8);
        let reported: Vec<GardenKey> = txs
            .iter()
            .filter_map(|tx| match &tx.tx.kind {
                GardenTxKind::Suspend { target } => Some(*target),
                _ => None,
            })
            .collect();
        assert_eq!(reported, gone);
        // Two of four are gone: without the reports the block needs three
        // votes and only two validators are there to give them.
        let block = net.block(txs).unwrap();
        let electorate = net.ledger.state.electorate(&block.txs);
        assert_eq!(electorate.len(), 2);
        let votes = net.votes(&block, &electorate);
        net.ledger.append(GardenCommit { block, votes }).unwrap();
    }

    #[test]
    fn garden_host_return_block_reports_who_left_during_the_freeze() {
        let mut net = Net::new();
        let a = net.join("a");
        let b = net.join("b");
        let c = net.join("c");
        let host = net.host;
        let leave = net.tx(&host, GardenTxKind::Leave);
        net.commit(vec![leave]).unwrap();
        assert_eq!(net.ledger.state.status, DomainStatus::Frozen);
        // a and b walk away while nothing can be written. The host comes
        // back to c alone.
        let back = net.tx(
            &host,
            GardenTxKind::Resume {
                address: String::new(),
            },
        );
        let alone = net.block(vec![back.clone()]).unwrap();
        let votes = net.votes(&alone, &[host, c]);
        let refusal = net
            .ledger
            .state
            .apply_commit(&GardenCommit {
                block: alone,
                votes,
            })
            .unwrap_err();
        assert!(refusal.contains("votes it needs"), "{refusal}");

        // a and b lead no round any more; the first round one of the two
        // that are there leads carries the return.
        let round = (0..4)
            .find(|round| {
                let leader = net.ledger.state.leader(*round);
                leader == Some(host) || leader == Some(c)
            })
            .unwrap();
        let leader = net.ledger.state.leader(round).unwrap();
        let key = net.key(&leader);
        let (txs, _) = net
            .ledger
            .state
            .assemble(std::iter::once(&back), &leader, &[a, b], |tx| {
                tx.sign(key).ok()
            });
        assert_eq!(txs.len(), 3, "the return block carries no absence report");
        let block = net.block_in_round(txs, round).unwrap();
        assert_eq!(net.ledger.state.electorate(&block.txs), {
            let mut left = vec![host, c];
            left.sort_unstable();
            left
        });
        let votes = net.votes(&block, &[host, c]);
        net.ledger.append(GardenCommit { block, votes }).unwrap();
        assert_eq!(net.ledger.state.status, DomainStatus::Active);
        assert_eq!(net.ledger.state.active().len(), 2);
    }

    #[test]
    fn garden_block_timestamp_cannot_use_up_the_clock() {
        let mut net = Net::new();
        net.join("a");
        let state = net.ledger.state.clone();
        let leader = state.leader(0).unwrap();
        let txs = vec![net.publish(&leader, 1)];
        let latest = state.last_timestamp_ms + MAX_BLOCK_TIMESTAMP_STEP_MS;

        // A proposer that asks for the far end gets the bound instead.
        let (header, _) = state.build_header(&txs, leader, 0, u64::MAX).unwrap();
        assert_eq!(header.timestamp_ms, latest);

        // A header written by hand past the bound is refused. One at the
        // bound is not.
        let block_of = |header: GardenHeader| GardenBlock {
            proposer_signature: net.key(&leader).sign(&header.hash()).to_vec(),
            header,
            txs: txs.clone(),
        };
        for past in [latest + 1, u64::MAX] {
            let mut far = header.clone();
            far.timestamp_ms = past;
            let refusal = state.verify_block(&block_of(far)).unwrap_err();
            assert!(refusal.contains("timestamp"), "{refusal}");
        }
        let block = block_of(header);
        let after = state.verify_block(&block).unwrap();
        assert_eq!(after.last_timestamp_ms, latest);

        // The chain is not at its end after such a block: the next proposer
        // still finds a timestamp.
        let votes = net.votes(&block, &state.electorate(&block.txs));
        net.ledger.append(GardenCommit { block, votes }).unwrap();
        let next = net.ledger.state.leader(0).unwrap();
        let more = vec![net.publish(&next, 2)];
        let (header, _) = net.ledger.state.build_header(&more, next, 0, 0).unwrap();
        assert_eq!(header.timestamp_ms, latest + 1);
    }

    /// A report says a validator of the last block went silent. A validator
    /// the block itself admits or brings back has given no silence to report,
    /// and no voter heard it yet, so every voter would sign the report.
    #[test]
    fn garden_absence_report_cannot_target_a_validator_the_same_block_seats() {
        let mut net = Net::new();
        let host = net.host;
        let (newcomer, join) = net.join_tx("v");
        let report = reports(&net, &host, &[newcomer]);
        let refusal = net
            .block(vec![join.clone(), report[0].clone()])
            .unwrap_err();
        assert!(refusal.contains("not of the last"), "{refusal}");
        // The join alone is still a block, and the report is one after it.
        net.commit(vec![join]).unwrap();
        net.join("w");
        let leader = net.ledger.state.leader(0).unwrap();
        let target = net
            .ledger
            .state
            .active()
            .into_iter()
            .find(|key| *key != host && *key != leader)
            .unwrap();
        let report = reports(&net, &leader, &[target]);
        let block = net.block(report).unwrap();
        let votes = net.votes(&block, &net.ledger.state.electorate(&block.txs));
        net.ledger.append(GardenCommit { block, votes }).unwrap();
        assert!(!net.ledger.state.is_active(&target));

        // The same holds for a validator that returns in the block.
        let leader = net.ledger.state.leader(0).unwrap();
        let back = net.tx(
            &target,
            GardenTxKind::Resume {
                address: String::new(),
            },
        );
        let report = reports(&net, &leader, &[target]);
        let refusal = net
            .block(vec![back.clone(), report[0].clone()])
            .unwrap_err();
        assert!(refusal.contains("not of the last"), "{refusal}");
        net.commit(vec![back]).unwrap();
        assert!(net.ledger.state.is_active(&target));
    }

    /// The vote list of a commit comes from the wire. A block takes one vote
    /// from each validator, so a longer list or a repeated voter is refused
    /// before a signature is checked.
    #[test]
    fn garden_commit_takes_one_vote_from_each_validator() {
        let mut net = Net::new();
        let host = net.host;
        let guests: Vec<GardenKey> = ["a", "b", "c"].iter().map(|name| net.join(name)).collect();
        let state = net.ledger.state.clone();
        let block = net.block(vec![net.publish(&host, 1)]).unwrap();
        assert_eq!(state.electorate(&block.txs).len(), 4);

        let mut voters = vec![host];
        voters.extend(&guests);
        let honest = net.votes(&block, &voters);
        state
            .apply_commit(&GardenCommit {
                block: block.clone(),
                votes: honest.clone(),
            })
            .unwrap();

        // One more vote than there are validators.
        let mut padded = honest.clone();
        padded.push(honest[0].clone());
        let refusal = state
            .apply_commit(&GardenCommit {
                block: block.clone(),
                votes: padded,
            })
            .unwrap_err();
        assert!(
            refusal.contains("5 votes for an electorate of 4"),
            "{refusal}"
        );

        // A list of the right length that counts one validator twice. The
        // signers are still a quorum, so only the repeat can refuse it.
        let mut repeated = net.votes(&block, &[host, host, guests[0], guests[1]]);
        let refusal = state
            .apply_commit(&GardenCommit {
                block: block.clone(),
                votes: repeated.clone(),
            })
            .unwrap_err();
        assert!(refusal.contains("more than one vote"), "{refusal}");

        // The count is taken before any signature: a list that is too long
        // and carries no valid signature at all is refused for its length.
        for vote in &mut repeated {
            vote.signature = vec![0u8; 64];
        }
        repeated.push(repeated[0].clone());
        let refusal = state
            .apply_commit(&GardenCommit {
                block,
                votes: repeated,
            })
            .unwrap_err();
        assert!(refusal.contains("votes for an electorate of"), "{refusal}");
    }

    /// A commit is executed only after its votes are counted. Executing a
    /// block is the expensive part, and one validator can write a block: the
    /// votes of the host and of two thirds are what one validator cannot.
    #[test]
    fn garden_commit_without_its_votes_is_refused_before_the_block_is_executed() {
        let mut net = Net::new();
        let host = net.host;
        net.join("a");
        let state = net.ledger.state.clone();
        let mut block = net.block(vec![net.publish(&host, 1)]).unwrap();
        // A block its proposer signed, with a state root no execution gives.
        block.header.state_root = [9u8; 32];
        block.proposer_signature = net
            .key(&block.header.proposer)
            .sign(&block.header.hash())
            .to_vec();
        let refusal = state
            .apply_commit(&GardenCommit {
                block: block.clone(),
                votes: Vec::new(),
            })
            .unwrap_err();
        assert!(refusal.contains("not signed by the host"), "{refusal}");
        // With the votes it is executed, and refused for what it is.
        let votes = net.votes(&block, &state.electorate(&block.txs));
        let refusal = state
            .apply_commit(&GardenCommit { block, votes })
            .unwrap_err();
        assert!(refusal.contains("does not match"), "{refusal}");
    }

    #[test]
    fn garden_tx_refuses_an_address_that_is_not_a_valid_dial_address() {
        let mut net = Net::new();
        let kp = KeyPair::generate().unwrap();
        let key = kp.public_key_bytes();
        let other = KeyPair::generate().unwrap().public_key_bytes();
        let me_id = super::super::net::peer_id_of(&key).unwrap();
        let other_id = super::super::net::peer_id_of(&other).unwrap();
        let invite_signature = invite_keypair(&super::super::testkit::TOKEN)
            .unwrap()
            .sign(&join_message(net.ledger.state.chain_id(), &key))
            .to_vec();
        net.keys.insert(key, kp);

        let bad_addresses = [
            format!("/ip4/127.0.0.1/tcp/22/p2p/{me_id}"),
            format!("/ip4/0.0.0.0/tcp/4001/p2p/{me_id}"),
            format!("/ip4/127.0.0.1/tcp/4001/ip4/10.0.0.1/tcp/4002/p2p/{me_id}"),
            "/ip4/127.0.0.1/tcp/4001".to_string(),
            format!("/ip4/127.0.0.1/tcp/4001/p2p/{other_id}"),
        ];
        for address in &bad_addresses {
            let join = net.tx(
                &key,
                GardenTxKind::Join {
                    name: "alice".into(),
                    address: address.clone(),
                    invite_signature: invite_signature.clone(),
                },
            );
            assert!(
                net.ledger.state.check_tx(&join).is_err(),
                "Join accepted invalid address {address}"
            );
            assert!(
                net.commit(vec![join]).is_err(),
                "block executed Join with invalid address {address}"
            );
        }

        let good_join = net.tx(
            &key,
            GardenTxKind::Join {
                name: "alice".into(),
                address: format!("/ip4/127.0.0.1/tcp/4001/p2p/{me_id}"),
                invite_signature,
            },
        );
        net.commit(vec![good_join]).unwrap();

        for address in &bad_addresses {
            let resume = net.tx(
                &key,
                GardenTxKind::Resume {
                    address: address.clone(),
                },
            );
            assert!(
                net.ledger.state.check_tx(&resume).is_err(),
                "Resume accepted invalid address {address}"
            );
        }
    }

    /// One step of a random Garden history. The numbers pick a key among the
    /// keys the history has seen so far, members or not.
    #[derive(Clone, Debug)]
    enum Step {
        Join,
        Leave(u8),
        Resume(u8),
        Publish(u8, u8, u32),
        Suspend(u8),
        Repeat,
    }

    fn step() -> impl proptest::strategy::Strategy<Value = Step> {
        use proptest::prelude::*;
        prop_oneof![
            3 => Just(Step::Join),
            2 => any::<u8>().prop_map(Step::Leave),
            2 => any::<u8>().prop_map(Step::Resume),
            5 => (any::<u8>(), 0u8..6, 0u32..3 * 4096).prop_map(|(who, id, size)| Step::Publish(who, id, size)),
            2 => any::<u8>().prop_map(Step::Suspend),
            1 => Just(Step::Repeat),
        ]
    }

    /// What holds after every block and after every refusal.
    fn hold(state: &GardenState) -> Result<(), String> {
        let host = state.host();
        let active = state.active();
        let ensure = |holds: bool, what: &str| {
            if holds {
                Ok(())
            } else {
                Err(format!(
                    "{what} (status {:?}, {} active)",
                    state.status,
                    active.len()
                ))
            }
        };
        ensure(
            state.is_active(&host) == (state.status == DomainStatus::Active),
            "the Garden runs exactly while the host is active",
        )?;
        ensure(
            active.is_empty() == (state.status == DomainStatus::Retired),
            "the Garden is retired exactly when nobody is active",
        )?;
        ensure(
            state.validators[&host].status != GardenValidatorStatus::Suspended,
            "the host is never suspended",
        )?;
        ensure(
            state.leader(0).is_some() == (state.status != DomainStatus::Retired),
            "a Garden has a leader exactly until it retires",
        )?;
        ensure(
            state.electorate(&[]) == active,
            "the electorate of an empty block is the active set",
        )?;
        let share = state.genesis.limits.max_published_bytes_per_validator;
        let mut charged: BTreeMap<GardenKey, u64> = BTreeMap::new();
        for object in state.objects.values() {
            *charged.entry(object.author).or_insert(0) +=
                u64::from(object.size).max(MIN_PUBLICATION_CHARGE);
        }
        ensure(
            charged == state.published,
            "the used share is the sum of what the validator published",
        )?;
        ensure(
            state.published.values().all(|used| *used <= share),
            "no validator is past its share",
        )
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(48))]

        /// Random histories of joins, departures, returns, publications,
        /// absence reports and repeated transactions, valid and not.
        ///
        /// A refusal changes nothing (G-4), a block moves the height by one,
        /// what a transaction check refuses no block accepts, the rules of
        /// `hold` stand after every step, and a second ledger that reads the
        /// finalized blocks arrives at the same state.
        #[test]
        fn garden_random_history_keeps_its_rules_and_replays_to_the_same_state(
            steps in proptest::collection::vec(step(), 1..40)
        ) {
            use proptest::prelude::*;
            let mut net = Net::new();
            net.ledger.state.genesis.limits.max_published_bytes_per_validator =
                3 * MIN_PUBLICATION_CHARGE;
            let origin = net.ledger.clone();
            let mut last: Option<SignedGardenTx> = None;
            for step in steps {
                let before = net.ledger.state.clone();
                let known: Vec<GardenKey> = net.keys.keys().copied().collect();
                let pick = |index: u8| known[usize::from(index) % known.len()];
                let tx = match step {
                    Step::Join => net.join_tx("v").1,
                    Step::Leave(who) => net.tx(&pick(who), GardenTxKind::Leave),
                    Step::Resume(who) => net.tx(
                        &pick(who),
                        GardenTxKind::Resume { address: String::new() },
                    ),
                    Step::Publish(who, id, size) => net.tx(
                        &pick(who),
                        GardenTxKind::Publish {
                            kind: GardenContentKind::Message,
                            content_id: [id; 32],
                            size,
                            mime: "text/plain".into(),
                            caption: String::new(),
                        },
                    ),
                    Step::Suspend(target) => {
                        let Some(leader) = before.leader(0) else {
                            continue;
                        };
                        net.tx(&leader, GardenTxKind::Suspend { target: pick(target) })
                    }
                    Step::Repeat => {
                        let Some(tx) = last.clone() else {
                            continue;
                        };
                        tx
                    }
                };
                let is_report = matches!(tx.tx.kind, GardenTxKind::Suspend { .. });
                let admitted = before.check_tx(&tx);
                let outcome = net.commit(vec![tx.clone()]);
                let after = &net.ledger.state;
                match &outcome {
                    Ok(()) => {
                        prop_assert_eq!(after.height, before.height + 1);
                        prop_assert_eq!(
                            after.next_nonce(&tx.tx.sender),
                            before.next_nonce(&tx.tx.sender) + 1
                        );
                        prop_assert!(
                            is_report || admitted.is_ok(),
                            "a block took what the transaction check refuses: {:?}",
                            admitted
                        );
                        last = Some(tx);
                    }
                    Err(_) => prop_assert_eq!(after, &before, "a refusal changed the state"),
                }
                if let Err(broken) = hold(after) {
                    return Err(TestCaseError::fail(broken));
                }
            }
            let mut replay = origin;
            for commit in &net.ledger.commits {
                prop_assert!(replay.append(commit.clone()).is_ok());
            }
            prop_assert_eq!(&replay.state, &net.ledger.state);
            prop_assert_eq!(
                replay.state.state_root_over(&replay.state.content_root()),
                net.ledger.state.state_root_over(&net.ledger.state.content_root())
            );
        }
    }
}
