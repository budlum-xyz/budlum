//! The cryptographic quorum gate for cold-wallet settlements.
//!
//! `cold_wallet` is the policy and state layer: it decides whether a
//! settlement may be signed at all (chain id, replay, ceiling, budget, epoch)
//! and it counts how many devices claim to back the request. What it
//! deliberately does not do is check *who* those devices are, because the
//! policy layer cannot hold keys. This module is the missing half: it turns
//! the presented signature count from a number into a proof.
//!
//! WIRING: the cold-anchor committee channel (the same dormant cold-wallet
//! path named by `cold_wallet`) is where [`crate::settlement::cold_wallet::ColdWalletState::sign_with_quorum`]
//! becomes live for settlement release, and where quorum-signed rotation of a
//! compromised anchor key is released as the reserve anchor (3-of-6 cold
//! committee, per the 2026-09-17 decision record). The rules here are pinned
//! by this file's tests until that channel lands.
//!
//! # What this module is not
//!
//! This is **not** a threshold signature scheme. There is no secret sharing
//! and no single aggregated signature: `k` distinct devices each produce their
//! own signature over the same payload, and every signature is verified
//! independently against its own key. "Threshold" in cryptographic literature
//! means something else (FROST, Shamir-based schemes), and reading a multisig
//! as a threshold scheme is how a reviewer ends up trusting a property the
//! code never provided. The property here is exactly this, and no more: one
//! holder of one device key cannot pass the gate alone, because
//! `required_quorum > 1` and every device is counted at most once.
//!
//! # Threat model, stated before the code
//!
//! The online side is assumed compromised (same premise as `cold_wallet`).
//! Consequences for this module:
//!
//! - A presented signature count is attacker-chosen. Only distinct, verified
//!   device signatures over the canonical payload are evidence.
//! - Replay across key epochs is refused at the payload layer already
//!   (the key epoch is inside `ColdWalletState::payload_for`), but a quorum
//!   that did not also pin the epoch it is signing for would let an attacker
//!   present signatures collected before a rotation as if they were current.
//! - Signature malleability in Ed25519 is real: a valid `(R, s)` under weak
//!   verification can admit variants the signer never produced. Every
//!   verification here is `verify_strict`, which rejects non-canonical
//!   encodings and weak public keys; accepting a malleable signature set would
//!   let two presentations of one signing act be counted as two devices.
//!
//! # The six development fixtures, and why they must never hold value
//!
//! [`dev_fixture_device_signers`] returns six deterministic device signers.
//! Their private keys are derived from seeds visible in this file, which means
//! **they are public knowledge**: any signature any of them makes can be
//! forged by anyone who has ever cloned this repository. They exist so that
//! tests, devnets, and integration harnesses have stable identities to run a
//! 3-of-6 gate against, and so that the 2026-09-17 chain of custody (the cold
//! committee is six devices) has concrete, inspectable shape in code. A
//! production custody device key is generated on the device, never derived
//! from material that lives in version control; the fixture path here is
//! explicitly not that. This paragraph exists because a deployer reaches the
//! dev fixtures exactly when in a hurry, and the fixture that silently becomes
//! the production key is how cold wallets die.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::cold_wallet::ColdWalletPolicy;

/// How many development fixture devices exist.
///
/// Six, and no more or fewer: the 2026-09-17 decision fixed the cold
/// committee at six devices with a 3-of-6 quorum for the reserve-anchor
/// channel, and the fixtures exist to model exactly that committee.
pub const DEV_FIXTURE_DEVICE_COUNT: u32 = 6;

/// One cold device's public identity.
///
/// The key bytes are stored rather than a parsed [`VerifyingKey`] so the
/// identity round-trips through serde exactly as it is announced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerIdentity {
    /// 1-based device number within the committee. Zero is never a signer,
    /// because "device zero" is how an off-by-one forgery hides.
    pub device_id: u32,
    /// A human-facing label. Never used in verification; it exists for audit
    /// trails and refusal logs.
    pub label: String,
    /// The device's public verification key, raw bytes.
    pub verifying_key: [u8; 32],
}

/// One device's signature over the canonical settlement payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSignature {
    /// Which device produced it. Checked against [`SignerIdentity`] and for
    /// distinctness: one device counted twice is not two devices.
    pub device_id: u32,
    /// The key epoch the device believes it is signing under. Pinned so that
    /// signatures collected before a rotation cannot be presented as current.
    pub key_epoch: u32,
    /// Strictly-verified Ed25519 signature bytes. `Vec<u8>` matches the
    /// codebase's signature convention; the exactly-64-bytes rule is enforced
    /// at verification, where anything else is an invalid signature.
    pub signature: Vec<u8>,
}

/// A device that can sign. Only the development fixtures hold a signing key
/// inside this module; production custody is deliberately out of scope here.
pub struct DeviceSigner {
    pub identity: SignerIdentity,
    key: SigningKey,
}

impl Clone for DeviceSigner {
    fn clone(&self) -> Self {
        Self {
            identity: self.identity.clone(),
            key: SigningKey::from_bytes(&self.key.to_bytes()),
        }
    }
}

impl DeviceSigner {
    /// Signs `payload` for `key_epoch`, returning the device signature record.
    ///
    /// A signature is produced over exactly the bytes supplied. The caller is
    /// responsible for passing the canonical payload; anything else is a
    /// signature over words these checks never examined, and the gate below
    /// will (correctly) still accept it against this device - which is why the
    /// payload layer pins the chain id, height, value, nonce and key epoch.
    #[must_use]
    /// WIRING: the committee channels (emergency-anchor rotation in
    /// `pq_anchor::rotate_anchor_key_with_committee`, future anchor-break
    /// quorums) sign certificates through this helper; exercised by those
    /// callers' tests until a production committee channel submits payloads.
    pub fn sign_payload(&self, payload: &[u8], key_epoch: u32) -> DeviceSignature {
        let signature = self.key.sign(payload);
        DeviceSignature {
            device_id: self.identity.device_id,
            key_epoch,
            signature: signature.to_bytes().to_vec(),
        }
    }
}

/// The six development fixture devices, in committee order 1..=6.
///
/// Deterministic on purpose: a test that cannot reproduce its signers cannot
/// reproduce its quorum. Seeds are fixed bytes in this file, which is exactly
/// why these keys must never custody anything (see the module header).
#[must_use]
pub fn dev_fixture_device_signers() -> Vec<DeviceSigner> {
    (1..=DEV_FIXTURE_DEVICE_COUNT)
        .map(|i| {
            let mut seed = [0u8; 32];
            // A deliberately simple, visibly deterministic pattern. Anything
            // subtler would only pretend these keys have entropy.
            for (j, byte) in seed.iter_mut().enumerate() {
                *byte = 0xC0 ^ (i as u8) ^ (j as u8);
            }
            let key = SigningKey::from_bytes(&seed);
            let verifying_key = key.verifying_key().to_bytes();
            DeviceSigner {
                identity: SignerIdentity {
                    device_id: i,
                    label: format!("cold-quorum-dev-fixture-{i}"),
                    verifying_key,
                },
                key,
            }
        })
        .collect()
}

/// Why a presented quorum was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumError {
    /// The policy itself is invalid (fail closed, same rule as the policy
    /// layer: a zero-quorum wallet must fail closed, not open).
    InvalidPolicy { rule: String },
    /// More signatures than devices: somebody is padding the set with
    /// signatures the committee could never have produced.
    TooManySignatures { device_count: u32, presented: usize },
    /// Fewer signatures than the policy requires. This is the gate firing as
    /// designed; the caller has not shown enough of the committee.
    QuorumNotReached { required: u32, presented: usize },
    /// A device id outside `1..=device_count`.
    SignerOutOfRange { device_id: u32, device_count: u32 },
    /// One device counted twice. Distinctness is the whole quorum property.
    DuplicateSigner { device_id: u32 },
    /// A signature pinned to a different key epoch than the one the gate is
    /// asked to accept (rotation boundary enforcement).
    EpochMismatch {
        signer_epoch: u32,
        current_epoch: u32,
    },
    /// A device id the presented identity set does not know.
    UnknownSigner { device_id: u32 },
    /// The cryptographically decisive failure: a signature did not verify
    /// strictly against the claimed device key over the presented payload.
    InvalidSignature { device_id: u32 },
}

impl QuorumError {
    /// A stable label, for refusal logs and audit trails.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::InvalidPolicy { .. } => "quorum-invalid-policy",
            Self::TooManySignatures { .. } => "quorum-too-many-signatures",
            Self::QuorumNotReached { .. } => "quorum-not-reached",
            Self::SignerOutOfRange { .. } => "quorum-signer-out-of-range",
            Self::DuplicateSigner { .. } => "quorum-duplicate-signer",
            Self::EpochMismatch { .. } => "quorum-epoch-mismatch",
            Self::UnknownSigner { .. } => "quorum-unknown-signer",
            Self::InvalidSignature { .. } => "quorum-invalid-signature",
        }
    }
}

impl std::fmt::Display for QuorumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPolicy { rule } => write!(f, "cold quorum policy invalid: {rule}"),
            Self::TooManySignatures {
                device_count,
                presented,
            } => write!(
                f,
                "cold quorum saw {presented} signatures for {device_count} devices"
            ),
            Self::QuorumNotReached {
                required,
                presented,
            } => write!(f, "cold quorum requires {required}, got {presented}"),
            Self::SignerOutOfRange {
                device_id,
                device_count,
            } => write!(
                f,
                "cold quorum signer id {device_id} outside 1..={device_count}"
            ),
            Self::DuplicateSigner { device_id } => {
                write!(f, "cold quorum signer id {device_id} presented twice")
            }
            Self::EpochMismatch {
                signer_epoch,
                current_epoch,
            } => write!(
                f,
                "cold quorum signature pinned to epoch {signer_epoch}, current is {current_epoch}"
            ),
            Self::UnknownSigner { device_id } => {
                write!(f, "cold quorum signer id {device_id} has no known identity")
            }
            Self::InvalidSignature { device_id } => {
                write!(
                    f,
                    "cold quorum device {device_id} signature failed strict verification"
                )
            }
        }
    }
}

impl std::error::Error for QuorumError {}

/// Verifies a presented quorum strictly.
///
/// Check order is substance, not style:
///
/// 1. Policy validity first: fail closed if the policy could not govern a
///    real committee at all.
/// 2. Cardinality bounds before any cryptography: a set that cannot be a
///    quorum either way does not get to cost the cold side a verification.
/// 3. Uniqueness and range before any cryptography for the same reason.
/// 4. Epoch pinning before any cryptography: a signature from the wrong epoch
///    is rejected by rule, not by hoping the crypto notices.
/// 5. Strict signature verification last: the only evidence that survives is
///    a per-device `verify_strict` pass over the exact payload bytes.
///
/// Returns the sorted, distinct device ids that verified. The caller couples
/// this set's length into the policy layer's quorum counting, so "the number
/// presented" is always the number proven, never the number claimed.
pub fn verify_quorum(
    policy: &ColdWalletPolicy,
    identities: &[SignerIdentity],
    payload: &[u8],
    current_key_epoch: u32,
    signatures: &[DeviceSignature],
) -> Result<Vec<u32>, QuorumError> {
    if let Err(rule) = policy.validate() {
        return Err(QuorumError::InvalidPolicy {
            rule: rule.to_string(),
        });
    }
    if signatures.len() > policy.device_count as usize {
        return Err(QuorumError::TooManySignatures {
            device_count: policy.device_count,
            presented: signatures.len(),
        });
    }
    if signatures.len() < policy.required_quorum as usize {
        return Err(QuorumError::QuorumNotReached {
            required: policy.required_quorum,
            presented: signatures.len(),
        });
    }
    let mut seen: Vec<u32> = Vec::with_capacity(signatures.len());
    for sig in signatures {
        if sig.device_id == 0 || sig.device_id > policy.device_count {
            return Err(QuorumError::SignerOutOfRange {
                device_id: sig.device_id,
                device_count: policy.device_count,
            });
        }
        if seen.contains(&sig.device_id) {
            return Err(QuorumError::DuplicateSigner {
                device_id: sig.device_id,
            });
        }
        seen.push(sig.device_id);
        if sig.key_epoch != current_key_epoch {
            return Err(QuorumError::EpochMismatch {
                signer_epoch: sig.key_epoch,
                current_epoch: current_key_epoch,
            });
        }
    }
    for sig in signatures {
        let identity = identities
            .iter()
            .find(|i| i.device_id == sig.device_id)
            .ok_or(QuorumError::UnknownSigner {
                device_id: sig.device_id,
            })?;
        let verifying_key = VerifyingKey::from_bytes(&identity.verifying_key).map_err(|_| {
            QuorumError::InvalidSignature {
                device_id: sig.device_id,
            }
        })?;
        let raw: [u8; 64] =
            sig.signature
                .as_slice()
                .try_into()
                .map_err(|_| QuorumError::InvalidSignature {
                    device_id: sig.device_id,
                })?;
        let signature = Signature::from_bytes(&raw);
        verifying_key
            .verify_strict(payload, &signature)
            .map_err(|_| QuorumError::InvalidSignature {
                device_id: sig.device_id,
            })?;
    }
    seen.sort_unstable();
    Ok(seen)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settlement::cold_wallet::ColdWalletState;
    use crate::settlement::cold_wallet::SettlementRequest;

    fn policy() -> ColdWalletPolicy {
        ColdWalletPolicy {
            chain_id: 7,
            max_value_per_settlement_atoms: 1_000,
            max_value_per_epoch_atoms: 3_000,
            min_height_advance: 1,
            required_quorum: 3,
            device_count: 6,
            refusal_history_capacity: 8,
        }
    }

    fn payload() -> Vec<u8> {
        let req = SettlementRequest {
            chain_id: 7,
            height: 10,
            epoch: 1,
            global_root: [9u8; 32],
            value_atoms: 100,
            nonce: 1,
        };
        ColdWalletState::payload_for(&req, 1)
    }

    fn three_of_six(payload: &[u8], epoch: u32) -> Vec<DeviceSignature> {
        dev_fixture_device_signers()[..3]
            .iter()
            .map(|d| d.sign_payload(payload, epoch))
            .collect()
    }

    #[test]
    fn fixture_committee_is_six_distinct_identities() {
        let signers = dev_fixture_device_signers();
        assert_eq!(signers.len() as u32, DEV_FIXTURE_DEVICE_COUNT);
        let mut keys: Vec<[u8; 32]> = signers.iter().map(|s| s.identity.verifying_key).collect();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), DEV_FIXTURE_DEVICE_COUNT as usize);
        for (n, s) in signers.iter().enumerate() {
            assert_eq!(s.identity.device_id as usize, n + 1);
            assert!(s.identity.label.starts_with("cold-quorum-dev-fixture-"));
        }
    }

    #[test]
    fn fixture_devices_are_reproducible() {
        let a = dev_fixture_device_signers();
        let b = dev_fixture_device_signers();
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.identity, y.identity);
        }
    }

    #[test]
    fn three_distinct_valid_signatures_pass() {
        let payload = payload();
        let signers = dev_fixture_device_signers();
        let identities: Vec<SignerIdentity> = signers.iter().map(|s| s.identity.clone()).collect();
        let sigs = three_of_six(&payload, 1);
        let passed =
            verify_quorum(&policy(), &identities, &payload, 1, &sigs).expect("3-of-6 must pass");
        assert_eq!(passed, vec![1, 2, 3]);
    }

    #[test]
    fn two_of_six_is_below_quorum() {
        let payload = payload();
        let signers = dev_fixture_device_signers();
        let identities: Vec<SignerIdentity> = signers.iter().map(|s| s.identity.clone()).collect();
        let sigs: Vec<DeviceSignature> = signers[..2]
            .iter()
            .map(|d| d.sign_payload(&payload, 1))
            .collect();
        let err = verify_quorum(&policy(), &identities, &payload, 1, &sigs)
            .expect_err("2-of-6 must fail");
        assert_eq!(err.kind(), "quorum-not-reached");
    }

    #[test]
    fn one_device_counted_twice_is_not_two_devices() {
        let payload = payload();
        let signers = dev_fixture_device_signers();
        let identities: Vec<SignerIdentity> = signers.iter().map(|s| s.identity.clone()).collect();
        let first = signers[0].sign_payload(&payload, 1);
        let second = signers[1].sign_payload(&payload, 1);
        let sigs = vec![first.clone(), first, second];
        let err = verify_quorum(&policy(), &identities, &payload, 1, &sigs)
            .expect_err("duplicate device must fail");
        assert_eq!(err.kind(), "quorum-duplicate-signer");
    }

    #[test]
    fn device_id_zero_is_out_of_range() {
        let payload = payload();
        let signers = dev_fixture_device_signers();
        let identities: Vec<SignerIdentity> = signers.iter().map(|s| s.identity.clone()).collect();
        let mut sigs = three_of_six(&payload, 1);
        sigs[0].device_id = 0;
        let err = verify_quorum(&policy(), &identities, &payload, 1, &sigs)
            .expect_err("device zero must fail");
        assert_eq!(err.kind(), "quorum-signer-out-of-range");
    }

    #[test]
    fn device_id_above_committee_is_out_of_range() {
        let payload = payload();
        let signers = dev_fixture_device_signers();
        let identities: Vec<SignerIdentity> = signers.iter().map(|s| s.identity.clone()).collect();
        let mut sigs = three_of_six(&payload, 1);
        sigs[2].device_id = 7;
        let err = verify_quorum(&policy(), &identities, &payload, 1, &sigs)
            .expect_err("device 7 of 6 must fail");
        assert_eq!(err.kind(), "quorum-signer-out-of-range");
    }

    #[test]
    fn signatures_pinned_to_a_rotated_out_epoch_are_refused() {
        let payload = payload();
        let signers = dev_fixture_device_signers();
        let identities: Vec<SignerIdentity> = signers.iter().map(|s| s.identity.clone()).collect();
        let sigs = three_of_six(&payload, 1);
        let err = verify_quorum(&policy(), &identities, &payload, 2, &sigs)
            .expect_err("epoch-1 signatures must not pass an epoch-2 gate");
        assert_eq!(err.kind(), "quorum-epoch-mismatch");
    }

    #[test]
    fn a_tampered_payload_breaks_every_signature() {
        let payload = payload();
        let signers = dev_fixture_device_signers();
        let identities: Vec<SignerIdentity> = signers.iter().map(|s| s.identity.clone()).collect();
        let sigs = three_of_six(&payload, 1);
        let mut forged = payload.clone();
        let last_payload_byte = forged.len() - 1;
        forged[last_payload_byte] ^= 0x01;
        let err = verify_quorum(&policy(), &identities, &forged, 1, &sigs)
            .expect_err("tampered payload must fail");
        assert_eq!(err.kind(), "quorum-invalid-signature");
    }

    #[test]
    fn a_signature_from_a_device_not_in_the_identity_set_is_refused() {
        let payload = payload();
        let signers = dev_fixture_device_signers();
        // Only devices 4..=6 are known; signatures come from 1..=3.
        let identities: Vec<SignerIdentity> =
            signers[3..].iter().map(|s| s.identity.clone()).collect();
        let sigs = three_of_six(&payload, 1);
        let err = verify_quorum(&policy(), &identities, &payload, 1, &sigs)
            .expect_err("unknown devices must fail");
        assert_eq!(err.kind(), "quorum-unknown-signer");
    }

    #[test]
    fn a_flipped_signature_break_fails_strictly() {
        let payload = payload();
        let signers = dev_fixture_device_signers();
        let identities: Vec<SignerIdentity> = signers.iter().map(|s| s.identity.clone()).collect();
        let mut sigs = three_of_six(&payload, 1);
        sigs[1].signature[31] ^= 0x80;
        let err = verify_quorum(&policy(), &identities, &payload, 1, &sigs)
            .expect_err("malleated signature must fail");
        assert_eq!(err.kind(), "quorum-invalid-signature");
    }

    #[test]
    fn more_signatures_than_devices_is_padding() {
        let payload = payload();
        let signers = dev_fixture_device_signers();
        let identities: Vec<SignerIdentity> = signers.iter().map(|s| s.identity.clone()).collect();
        let mut sigs: Vec<DeviceSignature> = signers
            .iter()
            .map(|d| d.sign_payload(&payload, 1))
            .collect();
        sigs.push(sigs[0].clone());
        let err = verify_quorum(&policy(), &identities, &payload, 1, &sigs)
            .expect_err("7 signatures for 6 devices must fail");
        assert_eq!(err.kind(), "quorum-too-many-signatures");
    }

    #[test]
    fn zero_quorum_policy_fails_closed_not_open() {
        let payload = payload();
        let signers = dev_fixture_device_signers();
        let identities: Vec<SignerIdentity> = signers.iter().map(|s| s.identity.clone()).collect();
        let mut broken = policy();
        broken.required_quorum = 0;
        let sigs = three_of_six(&payload, 1);
        let err = verify_quorum(&broken, &identities, &payload, 1, &sigs)
            .expect_err("invalid policy must fail closed");
        assert_eq!(err.kind(), "quorum-invalid-policy");
    }
}
