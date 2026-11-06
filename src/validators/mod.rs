//! Validator classes and the single registration door.
//!
//! A validator is Full, Mobile or MobileOpportunistic. One transaction family,
//! [`ValidatorTx`], registers a validator, changes its class, rotates its
//! operator key and raises its custody quota. The owner account (the stake
//! owner, who also receives the rewards) is the only signer of the registration,
//! class change and operator key rotation. The operator key, a separate
//! ML-DSA-65 key that lives on the phone, signs only the custody quota update
//! and can do nothing else: it cannot move stake, change the class or change
//! the reward address.
//!
//! The directory is consensus state. It is rooted in the state root and
//! snapshotted. A Full validator's stake lives in `AccountState::validators`
//! (the consensus set); a Mobile validator holds no seat, so its bond lives in
//! the directory record itself and never enters a quorum.

pub mod presence;

use crate::core::address::Address;
use crate::crypto::scheme::SchemeId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The longest multiaddress or gateway address a registration may carry.
pub const MAX_OFFER_ADDRESS_BYTES: usize = 256;
/// The most relay multiaddresses one registration may carry.
pub const MAX_RELAY_ADDRESSES: usize = 8;
/// The custody quota ceiling of an iOS opportunistic validator: 8 GiB.
pub const MOBILE_OPPORTUNISTIC_MAX_QUOTA_BYTES: u64 = 8 * 1024 * 1024 * 1024;
/// Epochs between a request and the moment it takes effect.
pub const ACTIVATION_DELAY_EPOCHS: u64 = 1;
/// Compressed BLS12-381 G2 public key length.
pub const BLS_KEY_LEN: usize = 96;
/// Compressed BLS12-381 G1 proof-of-possession length.
pub const BLS_POP_LEN: usize = 48;

/// The class of a validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ValidatorClass {
    /// Runs every block, proposes, holds a finality seat.
    Full,
    /// A phone: stores content, answers audits, holds no seat.
    Mobile,
    /// An iPhone: the same duties, only while the app is open or charging.
    MobileOpportunistic,
}

impl ValidatorClass {
    /// Whether the class holds a consensus seat.
    #[must_use]
    pub const fn holds_seat(self) -> bool {
        matches!(self, Self::Full)
    }

    /// The byte written into signing preimages and the directory root.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Full => 0,
            Self::Mobile => 1,
            Self::MobileOpportunistic => 2,
        }
    }
}

/// A refused validator operation: a stable code and a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorError {
    pub code: &'static str,
    pub message: String,
}

impl ValidatorError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ValidatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

/// A relay service a Full validator offers: multiaddresses and capacity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayOffer {
    pub multiaddrs: Vec<String>,
    pub capacity_kbps: u64,
}

/// An upload gateway a Full validator offers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayOffer {
    pub address: String,
}

/// The hash-chain leader election commitment of a Full validator (section
/// 7.4.7): the chain head and how many links the chain has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaderCommitment {
    pub commitment: [u8; 32],
    pub length: u64,
}

/// The fields only a Full validator carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeatFields {
    /// The slot VRF key. The PoS engine still draws with it until the hash
    /// chain election is the only election; it is refused for the
    /// mobile classes.
    pub vrf_key: Vec<u8>,
    /// The ML-DSA-65 half of the finality vote.
    pub pq_vote_key: Vec<u8>,
    pub leader_commitment: LeaderCommitment,
}

/// The registration payload (section 7.3 table).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorRegistration {
    /// The stake owner. It must be the transaction sender.
    pub owner: Address,
    pub class: ValidatorClass,
    /// ML-DSA-65 operator key.
    pub operator_key: Vec<u8>,
    pub bls_key: Vec<u8>,
    pub bls_pop: Vec<u8>,
    /// Present for `Full`, absent for the mobile classes.
    pub seat: Option<SeatFields>,
    pub custody_quota_bytes: u64,
    /// Optional, `Full` only.
    pub relay_offer: Option<RelayOffer>,
    /// Optional, `Full` only.
    pub gateway_offer: Option<GatewayOffer>,
    /// libp2p Ed25519 peer key (transport only).
    pub peer_id: [u8; 32],
}

/// The validator transaction family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorTx {
    /// Register and bond the sender as a validator. The signed amount is the
    /// stake.
    Register(Box<ValidatorRegistration>),
    /// Change class; takes effect one epoch later. A move to `Full` carries
    /// the seat fields.
    ChangeClass {
        new_class: ValidatorClass,
        seat: Option<SeatFields>,
    },
    /// Replace the operator key; takes effect one epoch later.
    RotateOperatorKey { new_operator_key: Vec<u8> },
    /// Raise the custody quota. Signed by the operator key, carried by any
    /// account that pays the fee.
    UpdateCustodyQuota {
        owner: Address,
        new_quota_bytes: u64,
        seq: u64,
        operator_signature: Vec<u8>,
    },
    /// `ResumeValidator` (section 7.8.7): lift a suspension. Takes effect
    /// one epoch later. The mobile app sends it by itself.
    Resume,
}

fn check_operator_key(key: &[u8]) -> Result<(), ValidatorError> {
    crate::crypto::pq::validate_public_key(SchemeId::ML_DSA_65, key).map_err(|e| {
        ValidatorError::new(
            "validator_operator_key_invalid",
            format!("the operator key must be an ML-DSA-65 public key: {e}"),
        )
    })
}

impl SeatFields {
    fn check(&self) -> Result<(), ValidatorError> {
        if self.vrf_key.len() != 32 {
            return Err(ValidatorError::new(
                "validator_seat_vrf_key",
                "the VRF key must be 32 bytes",
            ));
        }
        crate::crypto::pq::validate_public_key(SchemeId::ML_DSA_65, &self.pq_vote_key).map_err(
            |e| {
                ValidatorError::new(
                    "validator_seat_pq_vote_key",
                    format!("the PQ vote key must be an ML-DSA-65 public key: {e}"),
                )
            },
        )?;
        if self.leader_commitment.length == 0
            || self.leader_commitment.length > crate::consensus::filiz::FILIZ_CHAIN_LENGTH
        {
            return Err(ValidatorError::new(
                "validator_seat_leader_commitment",
                "the leader commitment chain length is out of range",
            ));
        }
        Ok(())
    }
}

impl ValidatorRegistration {
    /// Stateless checks: required fields per class, forbidden fields per
    /// class, key and offer shapes.
    ///
    /// # Errors
    ///
    /// A [`ValidatorError`] naming the first field that breaks the class rule.
    pub fn validate_shape(&self) -> Result<(), ValidatorError> {
        check_operator_key(&self.operator_key)?;
        if self.bls_key.len() != BLS_KEY_LEN || self.bls_pop.len() != BLS_POP_LEN {
            return Err(ValidatorError::new(
                "validator_bls_key",
                "the BLS key and proof of possession have the wrong length",
            ));
        }
        if self.peer_id == [0u8; 32] {
            return Err(ValidatorError::new(
                "validator_peer_id",
                "the peer id must not be zero",
            ));
        }
        if self.custody_quota_bytes == 0 {
            return Err(ValidatorError::new(
                "validator_quota_zero",
                "a validator stores content: the custody quota must be positive",
            ));
        }
        match self.class {
            ValidatorClass::Full => {
                let seat = self.seat.as_ref().ok_or_else(|| {
                    ValidatorError::new(
                        "validator_full_needs_seat_fields",
                        "a Full validator needs the VRF key, the PQ vote key and the leader commitment",
                    )
                })?;
                seat.check()?;
            }
            ValidatorClass::Mobile | ValidatorClass::MobileOpportunistic => {
                if self.seat.is_some() {
                    return Err(ValidatorError::new(
                        "validator_mobile_refuses_seat_fields",
                        "a mobile validator holds no seat: the VRF key, PQ vote key and leader commitment are refused",
                    ));
                }
                if self.relay_offer.is_some() {
                    return Err(ValidatorError::new(
                        "validator_mobile_refuses_relay_offer",
                        "a mobile validator does not offer a relay",
                    ));
                }
                if self.gateway_offer.is_some() {
                    return Err(ValidatorError::new(
                        "validator_mobile_refuses_gateway_offer",
                        "a mobile validator does not offer a gateway",
                    ));
                }
                if self.class == ValidatorClass::MobileOpportunistic
                    && self.custody_quota_bytes > MOBILE_OPPORTUNISTIC_MAX_QUOTA_BYTES
                {
                    return Err(ValidatorError::new(
                        "validator_quota_above_class_cap",
                        "an opportunistic mobile validator holds at most 8 GiB",
                    ));
                }
            }
        }
        if let Some(relay) = &self.relay_offer {
            if relay.multiaddrs.is_empty()
                || relay.multiaddrs.len() > MAX_RELAY_ADDRESSES
                || relay.capacity_kbps == 0
                || relay
                    .multiaddrs
                    .iter()
                    .any(|a| a.is_empty() || a.len() > MAX_OFFER_ADDRESS_BYTES)
            {
                return Err(ValidatorError::new(
                    "validator_relay_offer",
                    "a relay offer needs one to eight multiaddresses and a positive capacity",
                ));
            }
        }
        if let Some(gateway) = &self.gateway_offer {
            if gateway.address.is_empty() || gateway.address.len() > MAX_OFFER_ADDRESS_BYTES {
                return Err(ValidatorError::new(
                    "validator_gateway_offer",
                    "a gateway offer needs a non-empty address",
                ));
            }
        }
        Ok(())
    }
}

impl ValidatorTx {
    /// Stateless shape check, run at admission.
    ///
    /// # Errors
    ///
    /// A [`ValidatorError`] naming the refused field.
    pub fn validate_shape(&self) -> Result<(), ValidatorError> {
        match self {
            Self::Register(registration) => registration.validate_shape(),
            Self::ChangeClass { new_class, seat } => match (new_class.holds_seat(), seat) {
                (true, None) => Err(ValidatorError::new(
                    "validator_full_needs_seat_fields",
                    "a change to Full carries the seat fields",
                )),
                (true, Some(seat)) => seat.check(),
                (false, Some(_)) => Err(ValidatorError::new(
                    "validator_mobile_refuses_seat_fields",
                    "a change to a mobile class carries no seat fields",
                )),
                (false, None) => Ok(()),
            },
            Self::RotateOperatorKey { new_operator_key } => check_operator_key(new_operator_key),
            Self::UpdateCustodyQuota {
                new_quota_bytes,
                operator_signature,
                ..
            } => {
                if *new_quota_bytes == 0 {
                    return Err(ValidatorError::new(
                        "validator_quota_zero",
                        "the custody quota must be positive",
                    ));
                }
                let expected =
                    crate::crypto::pq::signature_len(SchemeId::ML_DSA_65).map_err(|e| {
                        ValidatorError::new("validator_operator_key_invalid", e.to_string())
                    })?;
                if operator_signature.len() != expected {
                    return Err(ValidatorError::new(
                        "validator_operator_signature_length",
                        "the operator signature has the wrong length",
                    ));
                }
                Ok(())
            }
            Self::Resume => Ok(()),
        }
    }
}

/// The bytes the operator key signs to raise a quota. The FIPS 204 context
/// (`ctx::VALIDATOR_V1`) separates it from every other signing surface; the
/// chain id and the record sequence stop a replay.
#[must_use]
pub fn quota_update_message(
    chain_id: u64,
    owner: &Address,
    new_quota_bytes: u64,
    seq: u64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(8 + 32 + 8 + 8 + 16);
    message.extend_from_slice(b"UpdateCustodyQuota");
    message.extend_from_slice(&chain_id.to_le_bytes());
    message.extend_from_slice(owner.as_bytes());
    message.extend_from_slice(&new_quota_bytes.to_le_bytes());
    message.extend_from_slice(&seq.to_le_bytes());
    message
}

/// A change waiting for its activation epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending<T> {
    pub value: T,
    pub activation_epoch: u64,
}

/// One validator's directory entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorRecord {
    pub owner: Address,
    pub class: ValidatorClass,
    /// The bond held here. Zero for a Full validator, whose stake lives in the
    /// consensus set.
    pub stake: u64,
    pub operator_key: Vec<u8>,
    pub bls_key: Vec<u8>,
    pub bls_pop: Vec<u8>,
    pub peer_id: [u8; 32],
    pub custody_quota_bytes: u64,
    pub relay_offer: Option<RelayOffer>,
    pub gateway_offer: Option<GatewayOffer>,
    pub registered_epoch: u64,
    /// Replay counter of the operator-signed quota update.
    pub quota_seq: u64,
    pub pending_class: Option<Pending<(ValidatorClass, Option<SeatFields>)>>,
    pub pending_operator_key: Option<Pending<Vec<u8>>>,
    pub pending_quota: Option<Pending<u64>>,
}

/// The consensus-state directory of validators.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorDirectory {
    #[serde(with = "crate::core::map_keys")]
    records: BTreeMap<[u8; 32], ValidatorRecord>,
}

impl ValidatorDirectory {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    #[must_use]
    pub fn get(&self, owner: &Address) -> Option<&ValidatorRecord> {
        self.records.get(&owner.0)
    }

    /// Every record, in owner order.
    pub fn iter(&self) -> impl Iterator<Item = &ValidatorRecord> {
        self.records.values()
    }

    /// Insert a registration. The floor for the class and the stake the
    /// transaction bonds are decided by the caller; this method owns the
    /// uniqueness rules.
    ///
    /// # Errors
    ///
    /// A second registration of the owner, a peer id or operator key already
    /// in use, or a stake below `floor`.
    pub fn register(
        &mut self,
        registration: &ValidatorRegistration,
        bonded_stake: u64,
        floor: u64,
        epoch: u64,
    ) -> Result<(), ValidatorError> {
        if bonded_stake < floor {
            return Err(ValidatorError::new(
                "validator_stake_below_class_floor",
                format!(
                    "{:?} validators bond at least {floor}, got {bonded_stake}",
                    registration.class
                ),
            ));
        }
        if self.records.contains_key(&registration.owner.0) {
            return Err(ValidatorError::new(
                "validator_already_registered",
                "the owner already has a validator record",
            ));
        }
        if self.records.values().any(|r| {
            r.peer_id == registration.peer_id || r.operator_key == registration.operator_key
        }) {
            return Err(ValidatorError::new(
                "validator_peer_or_operator_key_in_use",
                "the peer id or the operator key belongs to another validator",
            ));
        }
        self.records.insert(
            registration.owner.0,
            ValidatorRecord {
                owner: registration.owner,
                class: registration.class,
                stake: if registration.class.holds_seat() {
                    0
                } else {
                    bonded_stake
                },
                operator_key: registration.operator_key.clone(),
                bls_key: registration.bls_key.clone(),
                bls_pop: registration.bls_pop.clone(),
                peer_id: registration.peer_id,
                custody_quota_bytes: registration.custody_quota_bytes,
                relay_offer: registration.relay_offer.clone(),
                gateway_offer: registration.gateway_offer.clone(),
                registered_epoch: epoch,
                quota_seq: 0,
                pending_class: None,
                pending_operator_key: None,
                pending_quota: None,
            },
        );
        Ok(())
    }

    /// Queue a class change for `epoch + 1`.
    ///
    /// A Full validator cannot change class here: it leaves its seat through
    /// the seat handover, which also moves its stake.
    ///
    /// # Errors
    ///
    /// No record, a change already pending, the same class, a move out of
    /// `Full`, or a move to `Full` whose bond is below `full_floor`.
    pub fn request_class_change(
        &mut self,
        owner: &Address,
        new_class: ValidatorClass,
        seat: Option<SeatFields>,
        full_floor: u64,
        epoch: u64,
    ) -> Result<(), ValidatorError> {
        let record = self.records.get_mut(&owner.0).ok_or_else(no_record)?;
        if record.pending_class.is_some() {
            return Err(ValidatorError::new(
                "validator_class_change_pending",
                "a class change is already pending",
            ));
        }
        if record.class == new_class {
            return Err(ValidatorError::new(
                "validator_class_unchanged",
                "the validator already has this class",
            ));
        }
        if record.class.holds_seat() {
            return Err(ValidatorError::new(
                "validator_full_leaves_through_handover",
                "a Full validator leaves its seat through the seat handover, not a class change",
            ));
        }
        if new_class.holds_seat() && record.stake < full_floor {
            return Err(ValidatorError::new(
                "validator_stake_below_class_floor",
                format!(
                    "Full validators bond at least {full_floor}, the record holds {}",
                    record.stake
                ),
            ));
        }
        if new_class == ValidatorClass::MobileOpportunistic
            && record.custody_quota_bytes > MOBILE_OPPORTUNISTIC_MAX_QUOTA_BYTES
        {
            return Err(ValidatorError::new(
                "validator_quota_above_class_cap",
                "the quota is above what an opportunistic validator may hold",
            ));
        }
        record.pending_class = Some(Pending {
            value: (new_class, seat),
            activation_epoch: epoch.saturating_add(ACTIVATION_DELAY_EPOCHS),
        });
        Ok(())
    }

    /// Queue an operator key rotation for `epoch + 1`.
    ///
    /// # Errors
    ///
    /// No record, a rotation already pending, or the key already in use.
    pub fn request_operator_rotation(
        &mut self,
        owner: &Address,
        new_operator_key: Vec<u8>,
        epoch: u64,
    ) -> Result<(), ValidatorError> {
        if self
            .records
            .values()
            .any(|r| r.operator_key == new_operator_key)
        {
            return Err(ValidatorError::new(
                "validator_peer_or_operator_key_in_use",
                "the operator key belongs to a validator already",
            ));
        }
        let record = self.records.get_mut(&owner.0).ok_or_else(no_record)?;
        if record.pending_operator_key.is_some() {
            return Err(ValidatorError::new(
                "validator_rotation_pending",
                "an operator key rotation is already pending",
            ));
        }
        record.pending_operator_key = Some(Pending {
            value: new_operator_key,
            activation_epoch: epoch.saturating_add(ACTIVATION_DELAY_EPOCHS),
        });
        Ok(())
    }

    /// Queue a quota increase for `epoch + 1`. The operator signature has been
    /// checked by the caller against [`ValidatorRecord::operator_key`]; this
    /// method checks the replay counter and the direction.
    ///
    /// A decrease is refused: a smaller quota is reached by releasing shares
    /// (`StorageTx::ReleaseShares`), which carries no penalty.
    ///
    /// # Errors
    ///
    /// No record, a stale sequence, a pending quota, no increase, or a quota
    /// above the class cap.
    pub fn request_quota_increase(
        &mut self,
        owner: &Address,
        new_quota_bytes: u64,
        seq: u64,
        epoch: u64,
    ) -> Result<(), ValidatorError> {
        let record = self.records.get_mut(&owner.0).ok_or_else(no_record)?;
        if seq != record.quota_seq {
            return Err(ValidatorError::new(
                "validator_quota_sequence",
                format!("expected sequence {}, got {seq}", record.quota_seq),
            ));
        }
        if record.pending_quota.is_some() {
            return Err(ValidatorError::new(
                "validator_quota_pending",
                "a quota change is already pending",
            ));
        }
        if new_quota_bytes <= record.custody_quota_bytes {
            return Err(ValidatorError::new(
                "validator_quota_decrease_via_release",
                "UpdateCustodyQuota raises the quota; lower it by releasing shares",
            ));
        }
        if record.class == ValidatorClass::MobileOpportunistic
            && new_quota_bytes > MOBILE_OPPORTUNISTIC_MAX_QUOTA_BYTES
        {
            return Err(ValidatorError::new(
                "validator_quota_above_class_cap",
                "an opportunistic mobile validator holds at most 8 GiB",
            ));
        }
        record.quota_seq = record.quota_seq.saturating_add(1);
        record.pending_quota = Some(Pending {
            value: new_quota_bytes,
            activation_epoch: epoch.saturating_add(ACTIVATION_DELAY_EPOCHS),
        });
        Ok(())
    }

    /// Apply the operator key and quota changes whose epoch has come, and
    /// return the class changes that are due. The class changes are returned,
    /// not applied: a move to `Full` also moves stake into the consensus set,
    /// which the account state does and then confirms with
    /// [`Self::finish_class_change`].
    pub fn activate_due(
        &mut self,
        epoch: u64,
    ) -> Vec<(Address, ValidatorClass, Option<SeatFields>)> {
        let mut due_classes = Vec::new();
        for record in self.records.values_mut() {
            if record
                .pending_operator_key
                .as_ref()
                .is_some_and(|p| p.activation_epoch <= epoch)
            {
                if let Some(pending) = record.pending_operator_key.take() {
                    record.operator_key = pending.value;
                }
            }
            if record
                .pending_quota
                .as_ref()
                .is_some_and(|p| p.activation_epoch <= epoch)
            {
                if let Some(pending) = record.pending_quota.take() {
                    record.custody_quota_bytes = pending.value;
                }
            }
            if record
                .pending_class
                .as_ref()
                .is_some_and(|p| p.activation_epoch <= epoch)
            {
                if let Some(pending) = record.pending_class.take() {
                    due_classes.push((record.owner, pending.value.0, pending.value.1));
                }
            }
        }
        due_classes
    }

    /// Record a class change the account state carried out. `moved_stake` is
    /// what left the record for the consensus set.
    pub fn finish_class_change(
        &mut self,
        owner: &Address,
        class: ValidatorClass,
        moved_stake: u64,
    ) {
        if let Some(record) = self.records.get_mut(&owner.0) {
            record.class = class;
            record.stake = record.stake.saturating_sub(moved_stake);
        }
    }

    /// The directory root, folded into the state root once the directory is
    /// not empty.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        let encoded = bincode::serialize(self)
            .unwrap_or_else(|_| b"budlum/serialize-failed/validator-directory".to_vec());
        crate::core::hash::hash_fields_bytes(&[b"BDLM_VALIDATOR_DIRECTORY_V1", &encoded])
    }

    /// Records offering a relay.
    pub fn relays(&self) -> impl Iterator<Item = &ValidatorRecord> {
        self.records.values().filter(|r| r.relay_offer.is_some())
    }

    /// Records offering a gateway.
    pub fn gateways(&self) -> impl Iterator<Item = &ValidatorRecord> {
        self.records.values().filter(|r| r.gateway_offer.is_some())
    }
}

fn no_record() -> ValidatorError {
    ValidatorError::new(
        "validator_not_registered",
        "the sender has no validator record",
    )
}

/// What an RPC reader asks of the directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryQuery {
    /// One validator by owner.
    One(Address),
    /// Every validator offering a relay.
    Relays,
    /// Every validator offering a gateway.
    Gateways,
}

impl ValidatorRecord {
    /// The record as the RPC reads show it.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let class = match self.class {
            ValidatorClass::Full => "full",
            ValidatorClass::Mobile => "mobile",
            ValidatorClass::MobileOpportunistic => "mobile_opportunistic",
        };
        serde_json::json!({
            "owner": format!("0x{}", self.owner.to_hex()),
            "class": class,
            "heldStake": self.stake,
            "operatorKey": format!("0x{}", hex::encode(&self.operator_key)),
            "peerId": format!("0x{}", hex::encode(self.peer_id)),
            "custodyQuotaBytes": self.custody_quota_bytes,
            "relayOffer": self.relay_offer.as_ref().map(|r| serde_json::json!({
                "multiaddrs": r.multiaddrs,
                "capacityKbps": r.capacity_kbps,
            })),
            "gatewayOffer": self.gateway_offer.as_ref().map(|g| serde_json::json!({
                "address": g.address,
            })),
            "registeredEpoch": self.registered_epoch,
            "pendingClass": self.pending_class.as_ref().map(|p| serde_json::json!({
                "activationEpoch": p.activation_epoch,
            })),
            "pendingOperatorKey": self.pending_operator_key.as_ref().map(|p| serde_json::json!({
                "activationEpoch": p.activation_epoch,
            })),
            "pendingQuota": self.pending_quota.as_ref().map(|p| serde_json::json!({
                "quotaBytes": p.value,
                "activationEpoch": p.activation_epoch,
            })),
        })
    }
}

impl ValidatorDirectory {
    /// Answer an RPC read.
    #[must_use]
    pub fn query_json(&self, query: DirectoryQuery) -> serde_json::Value {
        match query {
            DirectoryQuery::One(owner) => self
                .get(&owner)
                .map_or(serde_json::Value::Null, ValidatorRecord::to_json),
            DirectoryQuery::Relays => {
                let list: Vec<_> = self.relays().map(ValidatorRecord::to_json).collect();
                serde_json::json!({ "count": list.len(), "relays": list })
            }
            DirectoryQuery::Gateways => {
                let list: Vec<_> = self.gateways().map(ValidatorRecord::to_json).collect();
                serde_json::json!({ "count": list.len(), "gateways": list })
            }
        }
    }
}
