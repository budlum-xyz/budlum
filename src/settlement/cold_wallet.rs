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
    WrongChain { expected: u64, got: u64 },
    HeightRolledBack { last_signed: u64, requested: u64 },
    HeightAlreadySettled { height: u64 },
    NonceReplayed { last_signed: u64, requested: u64 },
    ValueAboveCeiling { ceiling: u128, requested: u128 },
    EpochBudgetExceeded { spent: u128, requested: u128, budget: u128 },
    KeyRotatedOut { current_epoch: u32, presented: u32 },
    QuorumNotReached { required: u32, presented: u32 },
    HeightAdvanceTooSmall { required: u64, actual: u64 },
}

impl ColdRefusal {
    /// A stable label, for the refusal history.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::WrongChain { .. } => "wrong-chain",
            Self::HeightRolledBack { .. } => "height-rolled-back",
            Self::HeightAlreadySettled { .. } => "height-already-settled",
            Self::NonceReplayed { .. } => "nonce-replayed",
            Self::ValueAboveCeiling { .. } => "value-above-ceiling",
            Self::EpochBudgetExceeded { .. } => "epoch-budget-exceeded",
            Self::KeyRotatedOut { .. } => "key-rotated-out",
            Self::QuorumNotReached { .. } => "quorum-not-reached",
            Self::HeightAdvanceTooSmall { .. } => "height-advance-too-small",
        }
    }
}

/// One entry in the refusal history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefusalRecord {
    pub kind: &'static str,
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
                self.last_signed_height = request.height;
                self.last_signed_nonce = request.nonce;
                if request.epoch != self.budget_epoch {
                    self.budget_epoch = request.epoch;
                    self.epoch_spent_atoms = 0;
                }
                self.epoch_spent_atoms = self
                    .epoch_spent_atoms
                    .saturating_add(request.value_atoms);
                self.signed_count = self.signed_count.saturating_add(1);
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
        let total = spent_before.saturating_add(request.value_atoms);
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
            kind: err.kind(),
            height: request.height,
            nonce: request.nonce,
        };
        if self.refusals.len() >= self.policy.refusal_history_capacity {
            self.refusals.remove(0);
        }
        self.refusals.push(record);
    }

    /// Rotates the key. The old epoch stops being accepted immediately.
    ///
    /// Returns the new epoch. The rotation is recorded with the height, because
    /// a rotation that cannot be tied to a point in the chain cannot be audited.
    pub fn rotate_key(&mut self, at_height: u64, reason: &str) -> u32 {
        self.key_epoch = self.key_epoch.saturating_add(1);
        self.rotations.push(KeyRotation {
            key_epoch: self.key_epoch,
            at_height,
            reason: reason.to_string(),
        });
        self.key_epoch
    }

    /// How much of this epoch's budget remains.
    #[must_use]
    pub fn budget_remaining(&self, epoch: u64) -> u128 {
        let spent = if epoch == self.budget_epoch {
            self.epoch_spent_atoms
        } else {
            0
        };
        self.policy
            .max_value_per_epoch_atoms
            .saturating_sub(spent)
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
        assert_eq!(err, ColdRefusal::WrongChain { expected: 7, got: 8 });
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
        let new_epoch = cold.rotate_key(100, "suspected leak");
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
        cold.sign(&request(10, 1, 500), 2, 2).expect("the new epoch signs");
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
        cold.sign(&request(10, 1, 1000), 1, 2).expect("at the ceiling");
    }

    #[test]
    fn the_epoch_budget_bounds_many_small_settlements() {
        // One large settlement is bounded by the per-settlement ceiling; a
        // thousand small ones are bounded by this.
        let mut cold = ColdWalletState::new(policy());
        cold.sign(&request(10, 1, 1000), 1, 2).expect("1st");
        cold.sign(&request(20, 2, 1000), 1, 2).expect("2nd");
        cold.sign(&request(30, 3, 1000), 1, 2).expect("3rd fills the budget");
        assert_eq!(cold.budget_remaining(1), 0);
        let err = cold.sign(&request(40, 4, 1), 1, 2).unwrap_err();
        assert!(matches!(err, ColdRefusal::EpochBudgetExceeded { .. }));
    }

    #[test]
    fn the_budget_resets_on_a_new_epoch() {
        let mut cold = ColdWalletState::new(policy());
        cold.sign(&request(10, 1, 3000), 1, 2).expect("fills epoch 1");
        assert_eq!(cold.budget_remaining(1), 0);
        assert_eq!(cold.budget_remaining(2), 3000, "a new epoch has a fresh budget");
        let mut next = request(20, 2, 3000);
        next.epoch = 2;
        cold.sign(&next, 1, 2).expect("epoch 2 has its own budget");
        assert_eq!(cold.epoch_spent_atoms, 3000);
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
        assert_eq!(cold.refusals.len(), 4, "the refusal log grew past its capacity");
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
        cold.sign(&request(110, 2, 500), 1, 2).expect("ten blocks later");
    }

    #[test]
    fn a_device_that_has_signed_nothing_never_takes_a_first_height_as_a_rollback() {
        // The zero state must accept height 1. Comparing against a
        // `last_signed_height` of zero without guarding the "never signed" case
        // would make the first settlement on a fresh device look like a replay.
        let mut cold = ColdWalletState::new(policy());
        cold.sign(&request(1, 1, 100), 1, 2).expect("a fresh device signs height 1");
        assert_eq!(cold.signed_count, 1);
    }
}
