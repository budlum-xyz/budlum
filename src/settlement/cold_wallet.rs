//! The cold wallet for the Universal Settlement Layer.
//!
//! # The threat model, stated before the code
//!
//! A cold wallet exists because the online side is assumed to be compromised.
//! Not "might be" - **is**. Every design decision below follows from that, and
//! the ones that look paranoid are the ones that carry the weight:
//!
//! - Nothing in a [`SettlementRequest`] is trusted. Not the chain id, not the
//!   height, not the value, not the nonce. Each is checked against what the cold
//!   side already knows, and the check is the cold side's own policy, never a
//!   field the request supplies.
//! - A cold wallet that signs anything is an offline oracle for whoever holds
//!   the online key. The value of moving the key offline is exactly the value of
//!   the checks it runs, and a wallet with no checks is worse than a hot one
//!   because it also gives the operator a false sense of safety.
//! - Refusals are recorded and returned. A cold wallet that refuses silently
//!   leaves the operator with a signature that never arrives and no way to tell
//!   a policy refusal from a broken channel.
//!
//! # What the cold side refuses, and why each one matters
//!
//! 1. **A chain id it does not serve.** Without this, a signature produced for a
//!    testnet verifies on mainnet. The chain id is in the signed payload, not
//!    merely in the request, so a swapped envelope does not help.
//! 2. **A height at or below the last signed height.** Signing an older
//!    settlement after a newer one is a rollback signature - it lets an attacker
//!    with the online key ask the cold side to re-attest a state the network has
//!    already moved past.
//! 3. **A second settlement for a height already signed.** Distinct from the
//!    rule above: the height is equal, not lower. Two settlements for one height
//!    is a double-settlement, and a nonce that keeps advancing does not make it
//!    legitimate.
//! 4. **A nonce at or below the last signed nonce.** This is replay protection,
//!    and it is strictly increasing rather than "different" because a
//!    different-but-lower nonce is precisely the replay.
//! 5. **A value above the cold side's own ceiling.** The ceiling is the cold
//!    side's, held in its own state. A ceiling carried in the request would be a
//!    ceiling chosen by the attacker.
//! 6. **A request that exceeds the per-epoch budget.** One large settlement is
//!    bounded by rule 5; a thousand small ones are bounded by this.
//! 7. **A key epoch that has been rotated out.** After rotation the old key must
//!    stop signing immediately, not at some convenient moment - otherwise
//!    rotating a leaked key does not actually stop the leak.
//! 8. **A quorum it cannot reach.** No single cold device signs alone.
//!
//! # What this is not
//!
//! This is the policy and state layer. It does not hold a private key and it
//! does not perform a signature: `sign` returns the canonical payload to be
//! signed, and the caller hands it to whatever holds the key. Keeping the two
//! apart is deliberate - the policy is reviewable and testable on its own, and a
//! reviewer who has to read key handling to check a policy rule will not read
//! the policy rule.

use serde::{Deserialize, Serialize};

/// The rotation log is an audit trail, not an append-only denial-of-service
/// surface. Once this many entries exist the oldest entry is evicted; the
/// current epoch remains authoritative.
pub const MAX_COLD_ROTATION_HISTORY: usize = 1_024;
/// Rotation reasons are operator evidence, not an unbounded payload channel.
pub const MAX_ROTATION_REASON_BYTES: usize = 256;

/// The ceiling on one settlement, in atoms.
///
/// Held by the cold side. A request that carries its own ceiling is a request
/// from somebody who would like to raise it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdWalletPolicy {
    /// What the cold wallet serves. A request for anything else is refused.
    pub chain_id: u64,
    /// The most one settlement may move.
    pub max_value_per_settlement_atoms: u128,
    /// The most one epoch may move in total, across every settlement.
    pub max_value_per_epoch_atoms: u128,
    /// How far the height must advance between settlements. Zero allows
    /// consecutive heights; a larger number means the cold side will not be
    /// asked to sign on every block.
    pub min_height_advance: u64,
    /// How many cold devices must agree before a payload is released for
    /// signing.
    pub required_quorum: u32,
    /// How many devices exist.
    pub device_count: u32,
    /// How many refusals to keep. Bounded, because a refusal log that grows with
    /// every attempt is a way to fill a cold device's storage from the network
    /// side.
    pub refusal_history_capacity: usize,
}

impl ColdWalletPolicy {
    /// Reject policy values that would make the state machine trivially
    /// bypassable or permanently unusable. `new` remains infallible for
    /// backwards compatibility, so `check` calls this guard before it accepts
    /// any request; an invalid policy therefore fails closed rather than
    /// becoming a zero-quorum wallet.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.chain_id == 0 {
            return Err("chain-id-zero");
        }
        if self.max_value_per_settlement_atoms == 0 {
            return Err("per-settlement-ceiling-zero");
        }
        if self.max_value_per_epoch_atoms == 0 {
            return Err("per-epoch-budget-zero");
        }
        if self.max_value_per_settlement_atoms > self.max_value_per_epoch_atoms {
            return Err("settlement-ceiling-above-epoch-budget");
        }
        if self.device_count == 0 {
            return Err("device-count-zero");
        }
        if self.required_quorum == 0 {
            return Err("quorum-zero");
        }
        if self.required_quorum > self.device_count {
            return Err("quorum-above-device-count");
        }
        Ok(())
    }
}

impl Default for ColdWalletPolicy {
    fn default() -> Self {
        Self {
            chain_id: 1,
            max_value_per_settlement_atoms: 0,
            max_value_per_epoch_atoms: 0,
            min_height_advance: 1,
            required_quorum: 2,
            device_count: 3,
            refusal_history_capacity: 64,
        }
    }
}

/// What the online side asks the cold side to sign.
///
/// Every field is untrusted. The struct is deliberately flat and carries no
/// policy: a request that could also carry the rules it is checked against
/// would be a request that chose its own rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementRequest {
    pub chain_id: u64,
    pub height: u64,
    pub epoch: u64,
    pub global_root: [u8; 32],
    pub value_atoms: u128,
    pub nonce: u64,
}

/// Why the cold side refused.
///
/// Returned to the caller and appended to the refusal history. Each variant
/// names the rule, because an operator diagnosing a stuck settlement needs to
/// know which of eight rules fired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ColdRefusal {
    InvalidPolicy {
        rule: String,
    },
    InvalidState {
        rule: String,
    },
    WrongChain {
        expected: u64,
        got: u64,
    },
    HeightRolledBack {
        last_signed: u64,
        requested: u64,
    },
    HeightAlreadySettled {
        height: u64,
    },
    NonceReplayed {
        last_signed: u64,
        requested: u64,
    },
    ValueAboveCeiling {
        ceiling: u128,
        requested: u128,
    },
    EpochBudgetExceeded {
        spent: u128,
        requested: u128,
        budget: u128,
    },
    KeyRotatedOut {
        current_epoch: u32,
        presented: u32,
    },
    KeyEpochAhead {
        current_epoch: u32,
        presented: u32,
    },
    QuorumNotReached {
        required: u32,
        presented: u32,
    },
    QuorumExceedsDeviceCount {
        device_count: u32,
        presented: u32,
    },
    EpochRolledBack {
        last_signed: u64,
        requested: u64,
    },
    NonceZero,
    HeightAdvanceTooSmall {
        required: u64,
        actual: u64,
    },
}

impl ColdRefusal {
    /// A stable label, for the refusal history.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::InvalidPolicy { .. } => "invalid-policy",
            Self::InvalidState { .. } => "invalid-state",
            Self::WrongChain { .. } => "wrong-chain",
            Self::HeightRolledBack { .. } => "height-rolled-back",
            Self::HeightAlreadySettled { .. } => "height-already-settled",
            Self::NonceReplayed { .. } => "nonce-replayed",
            Self::ValueAboveCeiling { .. } => "value-above-ceiling",
            Self::EpochBudgetExceeded { .. } => "epoch-budget-exceeded",
            Self::KeyRotatedOut { .. } => "key-rotated-out",
            Self::KeyEpochAhead { .. } => "key-epoch-ahead",
            Self::QuorumNotReached { .. } => "quorum-not-reached",
            Self::QuorumExceedsDeviceCount { .. } => "quorum-exceeds-device-count",
            Self::EpochRolledBack { .. } => "epoch-rolled-back",
            Self::NonceZero => "nonce-zero",
            Self::HeightAdvanceTooSmall { .. } => "height-advance-too-small",
        }
    }
}

/// One entry in the refusal history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefusalRecord {
    /// Owned because the record is serialized and deserialized independently
    /// of the process that produced the refusal.
    pub kind: String,
    /// The height the refused request claimed. Recorded because an operator
    /// asking "why did height N not settle" needs to find it.
    pub height: u64,
    pub nonce: u64,
}

/// One key rotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotation {
    /// The epoch the new key took effect in.
    pub key_epoch: u32,
    /// The height the rotation happened at. Recorded so a rotation can be tied
    /// to a point in the chain rather than to a wall clock nobody agrees on.
    pub at_height: u64,
    /// Why. A rotation nobody can explain afterwards is indistinguishable from
    /// a key that was changed by somebody who should not have been able to.
    pub reason: String,
}

/// The cold side's state.
///
/// Small, and everything in it is something a second cold device could
/// independently arrive at: counters, the current key epoch, and bounded
/// histories. What the device thinks is not in here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdWalletState {
    pub policy: ColdWalletPolicy,
    /// The height of the last settlement this device signed. Monotonic.
    pub last_signed_height: u64,
    /// The nonce of the last settlement this device signed. Monotonic.
    pub last_signed_nonce: u64,
    /// The key epoch currently in force. A request presenting an older epoch is
    /// refused.
    pub key_epoch: u32,
    /// Value already released in the current epoch.
    pub epoch_spent_atoms: u128,
    /// Which epoch `epoch_spent_atoms` belongs to. When the request's epoch
    /// differs, the counter resets - it is a per-epoch budget, not a lifetime
    /// one.
    pub budget_epoch: u64,
    pub rotations: Vec<KeyRotation>,
    pub refusals: Vec<RefusalRecord>,
    /// How many settlements this device has signed. Reported because a cold
    /// device that has signed nothing since it was installed is a cold device
    /// nobody is using, and that is an operational fact worth seeing.
    pub signed_count: u64,
}

/// Why a key rotation was refused before it changed state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RotationError {
    EpochExhausted,
    EmptyReason,
    ReasonTooLong { bytes: usize, maximum: usize },
}

impl std::fmt::Display for RotationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EpochExhausted => write!(f, "cold-wallet key epoch exhausted"),
            Self::EmptyReason => write!(f, "cold-wallet key rotation reason is empty"),
            Self::ReasonTooLong { bytes, maximum } => {
                write!(f, "cold-wallet key rotation reason is {bytes} bytes; maximum is {maximum}")
            }
        }
    }
}

impl std::error::Error for RotationError {}

impl ColdWalletState {
    /// A cold wallet with `policy` and nothing signed yet.
    #[must_use]
    pub fn new(policy: ColdWalletPolicy) -> Self {
        Self {
            policy,
            last_signed_height: 0,
            last_signed_nonce: 0,
            key_epoch: 1,
            epoch_spent_atoms: 0,
            budget_epoch: 0,
            rotations: Vec::new(),
            refusals: Vec::new(),
            signed_count: 0,
        }
    }

    /// Validate state restored from storage before it is allowed to sign.
    ///
    /// The state is serializable because a cold device must survive a reboot,
    /// but deserialization is not authentication. This guard prevents a
    /// tampered snapshot from smuggling in counters, a budget, or an unbounded
    /// audit log.
    pub fn validate(&self) -> Result<(), &'static str> {
        self.policy.validate()?;
        if self.key_epoch == 0 {
            return Err("key-epoch-zero");
        }
        if self.refusals.len() > self.policy.refusal_history_capacity {
            return Err("refusal-history-over-capacity");
        }
        if self.rotations.len() > MAX_COLD_ROTATION_HISTORY {
            return Err("rotation-history-over-capacity");
        }
        if self.signed_count == 0
            && (self.last_signed_height != 0
                || self.last_signed_nonce != 0
                || self.epoch_spent_atoms != 0
                || self.budget_epoch != 0)
        {
            return Err("counters-without-a-signed-settlement");
        }
        if self.epoch_spent_atoms > self.policy.max_value_per_epoch_atoms {
            return Err("epoch-spent-above-budget");
        }
        let mut previous = 0u32;
        for rotation in &self.rotations {
            if rotation.key_epoch <= previous || rotation.key_epoch > self.key_epoch {
                return Err("rotation-epochs-not-monotonic");
            }
            if rotation.reason.is_empty() {
                return Err("empty-rotation-reason");
            }
            if rotation.reason.len() > MAX_ROTATION_REASON_BYTES {
                return Err("rotation-reason-too-long");
            }
            previous = rotation.key_epoch;
        }
        // An empty rotation history is valid at epoch one. If a history is
        // present, its newest entry must explain the current epoch.
        if let Some(last) = self.rotations.last() {
            if last.key_epoch != self.key_epoch {
                return Err("current-key-epoch-not-recorded");
            }
        }
        Ok(())
    }

    /// The canonical payload for a request.
    ///
    /// This is what gets signed. The chain id is inside it, so a signature
    /// produced for one chain does not verify on another even if the envelope
    /// around it is swapped.
    #[must_use]
    pub fn payload_for(request: &SettlementRequest, key_epoch: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 8 + 8 + 8 + 32 + 16 + 8 + 4);
        out.extend_from_slice(b"USL-COLD-SETTLEMENT-V1");
        out.extend_from_slice(&request.chain_id.to_le_bytes());
        out.extend_from_slice(&request.height.to_le_bytes());
        out.extend_from_slice(&request.epoch.to_le_bytes());
        out.extend_from_slice(&request.global_root);
        out.extend_from_slice(&request.value_atoms.to_le_bytes());
        out.extend_from_slice(&request.nonce.to_le_bytes());
        // The key epoch is inside the payload too. Without it, a payload signed
        // under a rotated-out key is byte-identical to one signed under the
        // current key, and the rotation would not actually invalidate anything.
        out.extend_from_slice(&key_epoch.to_le_bytes());
        out
    }

    /// Checks `request` against this device's own state and policy, and returns
    /// the payload to sign if every check passes.
    ///
    /// The check order is the substance of this function and is not arbitrary:
    ///
    /// - Chain id first, because a request for another chain should not consume
    ///   budget or advance counters.
    /// - Key epoch and quorum next: both are about whether this device may act
    ///   at all, which is prior to what it is being asked to do.
    /// - Then replay (height, nonce), then limits (value, budget). Replay before
    ///   limits, because a replayed request that also exceeds the ceiling should
    ///   be reported as a replay - the operator needs to know somebody is trying
    ///   again, not that the amount was too big.
    ///
    /// Nothing is mutated on refusal. A refused request consumes no budget,
    /// advances no counter, and leaves the device exactly as it was, apart from
    /// the refusal record.
    ///
    /// # Errors
    ///
    /// The first [`ColdRefusal`] that applies.
    pub fn sign(
        &mut self,
        request: &SettlementRequest,
        presented_key_epoch: u32,
        presented_signatures: u32,
    ) -> Result<Vec<u8>, ColdRefusal> {
        let refusal = self.check(request, presented_key_epoch, presented_signatures);
        match refusal {
            Ok(()) => {
                let payload = Self::payload_for(request, self.key_epoch);
                // Compute every next value before mutating any field. This is
                // important for a restored or hand-edited state: a late
                // arithmetic refusal must not partially advance the epoch.
                let next_spent = if request.epoch != self.budget_epoch {
                    request.value_atoms
                } else {
                    match self.epoch_spent_atoms.checked_add(request.value_atoms) {
                        Some(total) => total,
                        None => {
                            let err = ColdRefusal::EpochBudgetExceeded {
                                spent: self.epoch_spent_atoms,
                                requested: request.value_atoms,
                                budget: self.policy.max_value_per_epoch_atoms,
                            };
                            self.record_refusal(request, &err);
                            return Err(err);
                        }
                    }
                };
                let next_count = match self.signed_count.checked_add(1) {
                    Some(count) => count,
                    None => {
                        let err = ColdRefusal::InvalidState {
                            rule: "signed-count-exhausted".to_string(),
                        };
                        self.record_refusal(request, &err);
                        return Err(err);
                    }
                };
                self.last_signed_height = request.height;
                self.last_signed_nonce = request.nonce;
                self.budget_epoch = request.epoch;
                self.epoch_spent_atoms = next_spent;
                self.signed_count = next_count;
                Ok(payload)
            }
            Err(err) => {
                self.record_refusal(request, &err);
                Err(err)
            }
        }
    }

    /// The checks, without the mutation. Exposed so a device can pre-check a
    /// batch and report which ones would be refused before committing to any.
    ///
    /// # Errors
    ///
    /// The first [`ColdRefusal`] that applies.
    pub fn check(
        &self,
        request: &SettlementRequest,
        presented_key_epoch: u32,
        presented_signatures: u32,
    ) -> Result<(), ColdRefusal> {
        if let Err(rule) = self.validate() {
            if self.policy.validate().is_err() {
                return Err(ColdRefusal::InvalidPolicy {
                    rule: rule.to_string(),
                });
            }
            return Err(ColdRefusal::InvalidState {
                rule: rule.to_string(),
            });
        }
        if request.chain_id != self.policy.chain_id {
            return Err(ColdRefusal::WrongChain {
                expected: self.policy.chain_id,
                got: request.chain_id,
            });
        }
        if presented_key_epoch < self.key_epoch {
            return Err(ColdRefusal::KeyRotatedOut {
                current_epoch: self.key_epoch,
                presented: presented_key_epoch,
            });
        }
        if presented_key_epoch > self.key_epoch {
            return Err(ColdRefusal::KeyEpochAhead {
                current_epoch: self.key_epoch,
                presented: presented_key_epoch,
            });
        }
        if presented_signatures > self.policy.device_count {
            return Err(ColdRefusal::QuorumExceedsDeviceCount {
                device_count: self.policy.device_count,
                presented: presented_signatures,
            });
        }
        if presented_signatures < self.policy.required_quorum {
            return Err(ColdRefusal::QuorumNotReached {
                required: self.policy.required_quorum,
                presented: presented_signatures,
            });
        }
        // Equal height is a double settlement, not a rollback, and the two are
        // reported separately because they mean different things: a rollback
        // suggests a confused online side, a repeat suggests a retry that
        // somebody should look at.
        if request.height < self.last_signed_height {
            return Err(ColdRefusal::HeightRolledBack {
                last_signed: self.last_signed_height,
                requested: request.height,
            });
        }
        if request.height == self.last_signed_height && self.signed_count > 0 {
            return Err(ColdRefusal::HeightAlreadySettled {
                height: request.height,
            });
        }
        if self.signed_count > 0 {
            let advance = request.height.saturating_sub(self.last_signed_height);
            if advance < self.policy.min_height_advance {
                return Err(ColdRefusal::HeightAdvanceTooSmall {
                    required: self.policy.min_height_advance,
                    actual: advance,
                });
            }
        }
        if request.epoch < self.budget_epoch {
            return Err(ColdRefusal::EpochRolledBack {
                last_signed: self.budget_epoch,
                requested: request.epoch,
            });
        }
        if request.nonce == 0 {
            return Err(ColdRefusal::NonceZero);
        }
        if request.nonce <= self.last_signed_nonce {
            return Err(ColdRefusal::NonceReplayed {
                last_signed: self.last_signed_nonce,
                requested: request.nonce,
            });
        }
        if request.value_atoms > self.policy.max_value_per_settlement_atoms {
            return Err(ColdRefusal::ValueAboveCeiling {
                ceiling: self.policy.max_value_per_settlement_atoms,
                requested: request.value_atoms,
            });
        }
        let spent_before = if request.epoch == self.budget_epoch {
            self.epoch_spent_atoms
        } else {
            0
        };
        let Some(total) = spent_before.checked_add(request.value_atoms) else {
            return Err(ColdRefusal::EpochBudgetExceeded {
                spent: spent_before,
                requested: request.value_atoms,
                budget: self.policy.max_value_per_epoch_atoms,
            });
        };
        if total > self.policy.max_value_per_epoch_atoms {
            return Err(ColdRefusal::EpochBudgetExceeded {
                spent: spent_before,
                requested: request.value_atoms,
                budget: self.policy.max_value_per_epoch_atoms,
            });
        }
        Ok(())
    }

    /// Appends to the refusal history, evicting the oldest when full.
    ///
    /// Bounded on purpose: an unbounded refusal log is a way to fill a cold
    /// device's storage from the network side, which is the one attack a cold
    /// device is supposed to be immune to by being offline.
    fn record_refusal(&mut self, request: &SettlementRequest, err: &ColdRefusal) {
        let record = RefusalRecord {
            kind: err.kind().to_string(),
            height: request.height,
            nonce: request.nonce,
        };
        if self.policy.refusal_history_capacity == 0 {
            return;
        }
        if self.refusals.len() >= self.policy.refusal_history_capacity {
            self.refusals.remove(0);
        }
        self.refusals.push(record);
    }

    /// Rotates the key. The old epoch stops being accepted immediately.
    ///
    /// Returns the new epoch. The rotation is recorded with the height, because
    /// a rotation that cannot be tied to a point in the chain cannot be audited.
    pub fn rotate_key(&mut self, at_height: u64, reason: &str) -> Result<u32, RotationError> {
        if reason.is_empty() {
            return Err(RotationError::EmptyReason);
        }
        if reason.len() > MAX_ROTATION_REASON_BYTES {
            return Err(RotationError::ReasonTooLong {
                bytes: reason.len(),
                maximum: MAX_ROTATION_REASON_BYTES,
            });
        }
        let next = self
            .key_epoch
            .checked_add(1)
            .ok_or(RotationError::EpochExhausted)?;
        self.key_epoch = next;
        if self.rotations.len() >= MAX_COLD_ROTATION_HISTORY {
            self.rotations.remove(0);
        }
        self.rotations.push(KeyRotation {
            key_epoch: self.key_epoch,
            at_height,
            reason: reason.to_string(),
        });
        Ok(self.key_epoch)
    }

    /// How much of this epoch's budget remains.
    #[must_use]
    pub fn budget_remaining(&self, epoch: u64) -> u128 {
        let spent = if epoch < self.budget_epoch {
            return 0;
        } else if epoch == self.budget_epoch {
            self.epoch_spent_atoms
        } else {
            0
        };
        self.policy.max_value_per_epoch_atoms.saturating_sub(spent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ColdWalletPolicy {
        ColdWalletPolicy {
            chain_id: 7,
            max_value_per_settlement_atoms: 1000,
            max_value_per_epoch_atoms: 3000,
            min_height_advance: 1,
            required_quorum: 2,
            device_count: 3,
            refusal_history_capacity: 4,
        }
    }

    fn request(height: u64, nonce: u64, value: u128) -> SettlementRequest {
        SettlementRequest {
            chain_id: 7,
            height,
            epoch: 1,
            global_root: [height as u8; 32],
            value_atoms: value,
            nonce,
        }
    }

    #[test]
    fn an_invalid_policy_fails_closed_before_any_request_is_seen() {
        let mut cold = ColdWalletState::new(ColdWalletPolicy {
            required_quorum: 0,
            ..policy()
        });
        let err = cold.sign(&request(10, 1, 500), 1, 0).unwrap_err();
        assert!(matches!(err, ColdRefusal::InvalidPolicy { .. }));
        assert_eq!(cold.signed_count, 0);
    }

    #[test]
    fn a_first_settlement_signs_and_advances_everything() {
        let mut cold = ColdWalletState::new(policy());
        let payload = cold.sign(&request(10, 1, 500), 1, 2).expect("must sign");
        assert!(payload.starts_with(b"USL-COLD-SETTLEMENT-V1"));
        assert_eq!(cold.last_signed_height, 10);
        assert_eq!(cold.last_signed_nonce, 1);
        assert_eq!(cold.epoch_spent_atoms, 500);
        assert_eq!(cold.signed_count, 1);
        assert!(cold.refusals.is_empty());
    }

    #[test]
    fn a_request_for_another_chain_is_refused() {
        // Without this a testnet signature verifies on mainnet.
        let mut cold = ColdWalletState::new(policy());
        let mut other = request(10, 1, 500);
        other.chain_id = 8;
        let err = cold.sign(&other, 1, 2).unwrap_err();
        assert_eq!(
            err,
            ColdRefusal::WrongChain {
                expected: 7,
                got: 8
            }
        );
        assert_eq!(cold.signed_count, 0, "a refused request advanced a counter");
    }

    #[test]
    fn the_chain_id_is_inside_the_signed_payload() {
        // A swapped envelope must not make one chain's signature work on
        // another, so the chain id has to be in what is signed, not only in the
        // request.
        let a = request(10, 1, 500);
        let mut b = a;
        b.chain_id = 8;
        assert_ne!(
            ColdWalletState::payload_for(&a, 1),
            ColdWalletState::payload_for(&b, 1)
        );
    }

    #[test]
    fn the_key_epoch_is_inside_the_signed_payload() {
        // Otherwise a rotation invalidates nothing: a payload signed under the
        // old key would be byte-identical to one signed under the new one.
        let r = request(10, 1, 500);
        assert_ne!(
            ColdWalletState::payload_for(&r, 1),
            ColdWalletState::payload_for(&r, 2)
        );
    }

    #[test]
    fn a_rotated_out_key_stops_signing_immediately() {
        // Rotating a leaked key has to actually stop the leak, not stop it at
        // some convenient moment.
        let mut cold = ColdWalletState::new(policy());
        let new_epoch = cold
            .rotate_key(100, "suspected leak")
            .expect("rotation must fit");
        assert_eq!(new_epoch, 2);
        let err = cold.sign(&request(10, 1, 500), 1, 2).unwrap_err();
        assert_eq!(
            err,
            ColdRefusal::KeyRotatedOut {
                current_epoch: 2,
                presented: 1
            }
        );
        assert_eq!(cold.rotations.len(), 1);
        assert_eq!(cold.rotations.first().map(|r| r.at_height), Some(100));
        cold.sign(&request(10, 1, 500), 2, 2)
            .expect("the new epoch signs");
    }

    #[test]
    fn a_future_key_epoch_is_not_accepted_as_current() {
        let mut cold = ColdWalletState::new(policy());
        let err = cold.sign(&request(10, 1, 500), 2, 2).unwrap_err();
        assert_eq!(
            err,
            ColdRefusal::KeyEpochAhead {
                current_epoch: 1,
                presented: 2
            }
        );
        assert_eq!(cold.signed_count, 0);
    }

    #[test]
    fn a_single_device_cannot_sign_alone() {
        let mut cold = ColdWalletState::new(policy());
        let err = cold.sign(&request(10, 1, 500), 1, 1).unwrap_err();
        assert_eq!(
            err,
            ColdRefusal::QuorumNotReached {
                required: 2,
                presented: 1
            }
        );
        assert_eq!(cold.signed_count, 0);
    }

    #[test]
    fn a_lower_height_is_a_rollback_and_is_refused() {
        // Signing an older settlement after a newer one is a rollback
        // signature: it re-attests a state the network has moved past.
        let mut cold = ColdWalletState::new(policy());
        cold.sign(&request(100, 1, 500), 1, 2).expect("sign 100");
        let err = cold.sign(&request(90, 2, 500), 1, 2).unwrap_err();
        assert_eq!(
            err,
            ColdRefusal::HeightRolledBack {
                last_signed: 100,
                requested: 90
            }
        );
    }

    #[test]
    fn a_second_settlement_for_the_same_height_is_refused_separately() {
        // Distinct from a rollback: the height is equal, not lower. A nonce that
        // keeps advancing does not make a double settlement legitimate.
        let mut cold = ColdWalletState::new(policy());
        cold.sign(&request(100, 1, 500), 1, 2).expect("sign 100");
        let err = cold.sign(&request(100, 2, 500), 1, 2).unwrap_err();
        assert_eq!(
            err,
            ColdRefusal::HeightAlreadySettled { height: 100 },
            "a repeated height must be reported as a repeat, not as a rollback"
        );
    }

    #[test]
    fn a_replayed_nonce_is_refused_even_with_a_new_height() {
        let mut cold = ColdWalletState::new(policy());
        cold.sign(&request(10, 5, 500), 1, 2).expect("sign");
        let err = cold.sign(&request(20, 5, 500), 1, 2).unwrap_err();
        assert_eq!(
            err,
            ColdRefusal::NonceReplayed {
                last_signed: 5,
                requested: 5
            },
            "an equal nonce is a replay; only strictly greater is new"
        );
    }

    #[test]
    fn the_value_ceiling_is_the_cold_sides_own() {
        let mut cold = ColdWalletState::new(policy());
        let err = cold.sign(&request(10, 1, 1001), 1, 2).unwrap_err();
        assert_eq!(
            err,
            ColdRefusal::ValueAboveCeiling {
                ceiling: 1000,
                requested: 1001
            }
        );
        // Exactly at the ceiling is allowed: the ceiling is a maximum, not a
        // threshold to stay under.
        cold.sign(&request(10, 1, 1000), 1, 2)
            .expect("at the ceiling");
    }

    #[test]
    fn the_epoch_budget_bounds_many_small_settlements() {
        // One large settlement is bounded by the per-settlement ceiling; a
        // thousand small ones are bounded by this.
        let mut cold = ColdWalletState::new(policy());
        cold.sign(&request(10, 1, 1000), 1, 2).expect("1st");
        cold.sign(&request(20, 2, 1000), 1, 2).expect("2nd");
        cold.sign(&request(30, 3, 1000), 1, 2)
            .expect("3rd fills the budget");
        assert_eq!(cold.budget_remaining(1), 0);
        let err = cold.sign(&request(40, 4, 1), 1, 2).unwrap_err();
        assert!(matches!(err, ColdRefusal::EpochBudgetExceeded { .. }));
    }

    #[test]
    fn the_budget_resets_on_a_new_epoch() {
        let mut cold = ColdWalletState::new(policy());
        cold.sign(&request(10, 1, 3000), 1, 2)
            .expect("fills epoch 1");
        assert_eq!(cold.budget_remaining(1), 0);
        assert_eq!(
            cold.budget_remaining(2),
            3000,
            "a new epoch has a fresh budget"
        );
        let mut next = request(20, 2, 3000);
        next.epoch = 2;
        cold.sign(&next, 1, 2).expect("epoch 2 has its own budget");
        assert_eq!(cold.epoch_spent_atoms, 3000);
    }

    #[test]
    fn an_old_epoch_cannot_reset_the_budget() {
        let mut cold = ColdWalletState::new(policy());
        cold.sign(&request(10, 1, 3000), 1, 2).expect("fills epoch 1");
        let mut old = request(20, 2, 1);
        old.epoch = 0;
        let err = cold.sign(&old, 1, 2).unwrap_err();
        assert_eq!(
            err,
            ColdRefusal::EpochRolledBack {
                last_signed: 1,
                requested: 0
            }
        );
        assert_eq!(cold.epoch_spent_atoms, 3000);
        assert_eq!(cold.budget_epoch, 1);
    }

    #[test]
    fn the_refusal_log_is_bounded() {
        // An unbounded refusal log is a way to fill a cold device's storage from
        // the network side - the one attack being offline is supposed to prevent.
        let mut cold = ColdWalletState::new(policy());
        for i in 0..20u64 {
            let mut bad = request(10, 1, 500);
            bad.chain_id = 99;
            bad.nonce = i;
            let _ = cold.sign(&bad, 1, 2);
        }
        assert_eq!(
            cold.refusals.len(),
            4,
            "the refusal log grew past its capacity"
        );
        assert!(cold.refusals.iter().all(|r| r.kind == "wrong-chain"));
    }

    #[test]
    fn a_refusal_leaves_the_device_untouched() {
        let mut cold = ColdWalletState::new(policy());
        cold.sign(&request(10, 1, 500), 1, 2).expect("sign");
        let before = cold.clone();
        let _ = cold.sign(&request(20, 1, 500), 1, 2);
        assert_eq!(cold.last_signed_height, before.last_signed_height);
        assert_eq!(cold.last_signed_nonce, before.last_signed_nonce);
        assert_eq!(cold.epoch_spent_atoms, before.epoch_spent_atoms);
        assert_eq!(cold.signed_count, before.signed_count);
        assert_eq!(cold.refusals.len(), 1, "only the refusal record was added");
    }

    #[test]
    fn a_zero_capacity_refusal_log_is_a_valid_no_log_mode() {
        let mut cold = ColdWalletState::new(ColdWalletPolicy {
            refusal_history_capacity: 0,
            ..policy()
        });
        let _ = cold.sign(&request(10, 1, 500), 1, 1);
        assert!(cold.refusals.is_empty());
    }

    #[test]
    fn rotation_reason_and_epoch_overflow_fail_closed() {
        let mut cold = ColdWalletState::new(policy());
        assert_eq!(
            cold.rotate_key(10, "").unwrap_err(),
            RotationError::EmptyReason
        );
        assert_eq!(
            cold.rotate_key(10, &"x".repeat(MAX_ROTATION_REASON_BYTES + 1))
                .unwrap_err(),
            RotationError::ReasonTooLong {
                bytes: MAX_ROTATION_REASON_BYTES + 1,
                maximum: MAX_ROTATION_REASON_BYTES
            }
        );
        cold.key_epoch = u32::MAX;
        assert_eq!(
            cold.rotate_key(10, "exhausted").unwrap_err(),
            RotationError::EpochExhausted
        );
    }

    #[test]
    fn replay_is_reported_before_the_amount_is() {
        // A replayed request that also exceeds the ceiling must be reported as a
        // replay: the operator needs to know somebody is trying again, not that
        // the amount was too big.
        let mut cold = ColdWalletState::new(policy());
        cold.sign(&request(10, 5, 500), 1, 2).expect("sign");
        let err = cold.sign(&request(20, 5, 99999), 1, 2).unwrap_err();
        assert!(
            matches!(err, ColdRefusal::NonceReplayed { .. }),
            "the replay was masked by the ceiling check: {err:?}"
        );
    }

    #[test]
    fn the_minimum_height_advance_is_enforced() {
        let mut cold = ColdWalletState::new(ColdWalletPolicy {
            min_height_advance: 10,
            ..policy()
        });
        cold.sign(&request(100, 1, 500), 1, 2).expect("sign");
        let err = cold.sign(&request(105, 2, 500), 1, 2).unwrap_err();
        assert_eq!(
            err,
            ColdRefusal::HeightAdvanceTooSmall {
                required: 10,
                actual: 5
            }
        );
        cold.sign(&request(110, 2, 500), 1, 2)
            .expect("ten blocks later");
    }

    #[test]
    fn a_device_that_has_signed_nothing_never_takes_a_first_height_as_a_rollback() {
        // The zero state must accept height 1. Comparing against a
        // `last_signed_height` of zero without guarding the "never signed" case
        // would make the first settlement on a fresh device look like a replay.
        let mut cold = ColdWalletState::new(policy());
        cold.sign(&request(1, 1, 100), 1, 2)
            .expect("a fresh device signs height 1");
        assert_eq!(cold.signed_count, 1);
    }
}
