//! Babylon / BTC-restaking EOTS finality: the adapter for a chain whose
//! finality votes are EOTS-signed - an extractable one-time signature over a
//! Bitcoin checkpoint.
//!
//! WIRING: this adapter is admitted by `super::selftest::admit` and
//!   reached through `super::registry::ExternalDomainRegistry` once a
//!   registration names `babylon_eots::eots_adapter_id`; the dispatch table
//!   that maps an incoming envelope to an adapter is `super::intake`'s, and
//!   the entry there lands with the registry's Babylon domain record.
//!
//! # The target system, in its own terms
//!
//! Babylon lets Bitcoin holders stake their coins on a proof-of-stake chain.
//! The finality provider of each epoch signs one *epoch vote* with an EOTS
//! key: a key that is published at the start of the epoch, before anybody
//! knows which checkpoint the epoch will land on. Signing two conflicting
//! epoch votes under that key reveals the key to anybody who sees both, which
//! is what makes the stake behind it slashable without a court.
//!
//! # What this adapter verifies
//!
//! 1. The evidence decodes in full (bincode, fixint, trailing bytes refused,
//!    512 KiB cap) and names this adapter, this network, and a version this
//!    adapter reads.
//! 2. The epoch vote is a **BIP340 Schnorr** signature under an x-only
//!    secp256k1 key over a domain-tagged message that commits, in order, to
//!    the Budlum chain id, the epoch, the external block height, the state
//!    root, and the Bitcoin checkpoint (block hash, height, MMR root).
//! 3. The EOTS key the vote is signed under is the key that was announced for
//!    that epoch in the pinned registration. A vote under a key nobody
//!    announced is a vote by nobody.
//! 4. When the domain has a Bitcoin weak-subjectivity anchor, the checkpoint
//!    the vote names must be **at least `required_confirmations` blocks below
//!    the anchored tip**. The anchor is the operator's statement of how much
//!    Bitcoin work exists; a checkpoint inside the confirmation window is not
//!    buried by it, and is refused rather than graded.
//! 5. A post-quantum half (ML-DSA-65 over the same message, under the FIPS 204
//!    context [`crate::crypto::ctx::CROSS_DOMAIN_V1`]) is verified whenever it
//!    is carried, and a caller that requires it
//!    ([`VerificationPolicy::require_slashable`]) is refused evidence without
//!    one. A secp256k1 signature is *not* post-quantum: an adapter that
//!    accepted a classical half on a PQ-required path would be claiming a
//!    property the signature does not have.
//! 6. Two conflicting epoch votes by one provider (same height, same epoch,
//!    different state root or different checkpoint) produce
//!    [`EotsEquivocationProof`]: both messages, both signatures, and the key,
//!    under one digest. Any holder can check it without trusting this
//!    adapter.
//!
//! # What it does not do
//!
//! - **No key extraction.** Two BIP340 signatures over one message under one
//!   nonce cannot be solved for the key: the challenge is identical, so the
//!   two equations are dependent. Extraction needs two signatures over two
//!   *different* messages that reused one nonce, and a BIP340 verifier cannot
//!   tell that case from two honest signatures over two different messages -
//!   the nonce is not on the wire. So the adapter produces verifiable
//!   equivocation evidence and lets the registry's bond do the slashing; it
//!   never claims a secret it did not derive.
//! - **No Bitcoin SPV.** The MMR root and the checkpoint hash are taken as the
//!   target chain committed to them; proving them against Bitcoin's header
//!   chain is `super::bitcoin_spv`'s job. A second, unreviewed SPV inside
//!   this adapter would be exactly the drift that module exists to prevent.
//! - **No slashing.** The adapter reports; the registry prices.
//! - **No default confirmation depth.** The number enforced is the one in the
//!   domain's anchor. Without an anchor the adapter says so rather than
//!   assuming six.

use crate::core::address::Address;
use crate::cross_domain::external::selftest::{
    BytePatch, ExpectedRefusal, FaultProbe, RefusalKind,
};
use crate::cross_domain::external::spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, RawConsensusEvidence, SecurityBacking, TimeUnit, TrustModel,
    VerificationPolicy,
};
use crate::crypto::facts::ObservedScheme;
use crate::domain::types::Hash32;
use k256::schnorr::signature::Verifier;
use k256::schnorr::{Signature as SchnorrSignature, VerifyingKey as SchnorrVerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A ceiling on the encoded payload, checked before deserialization.
pub const MAX_PAYLOAD_BYTES: usize = 512 * 1024;

/// A ceiling on the votes one payload may carry: one vote, or an
/// equivocation pair. A payload with more is a shape this adapter does not
/// read, and refusing it is cheaper than reading it.
pub const MAX_VOTES: usize = 2;

/// A BIP340 Schnorr signature is 64 bytes.
pub const SCHNORR_SIGNATURE_LEN: usize = 64;

/// An x-only secp256k1 public key is 32 bytes.
pub const SCHNORR_PUBLIC_KEY_LEN: usize = 32;

/// The adapter's canonical name. Single source of truth for both the
/// [`AdapterId`] a registration names and the descriptor's `name`, so a
/// reader can check the two agree.
pub const EOTS_ADAPTER_NAME: &str = "babylon-eots-restaking-finality";

/// The adapter id, derived from its name so anybody can check that a
/// registration means what it says.
#[must_use]
pub fn eots_adapter_id() -> AdapterId {
    AdapterId::from_name(EOTS_ADAPTER_NAME)
}

/// The evidence version this adapter reads.
pub const EVIDENCE_VERSION: u32 = 1;

/// The adapter's own version. Bumped when the reading changes, never when the
/// evidence format does.
pub const ADAPTER_VERSION: u32 = 1;

/// `BDLM_*` domain tag prefixed to every epoch-vote message. A signature made
/// for any other protocol under the same key does not verify here.
pub const EPOCH_VOTE_TAG: &[u8] = b"BDLM_BABYLON_EOTS_VOTE_V1";

/// `BDLM_*` domain tag prefixed to the equivocation digest.
pub const EQUIVOCATION_TAG: &[u8] = b"BDLM_BABYLON_EOTS_EQUIVOCATION_V1";

/// The Bitcoin checkpoint an epoch vote covers.
///
/// Babylon periodic checkpointing commits to an MMR of Bitcoin headers; the
/// vote names the checkpoint block and that MMR root, so a vote for another
/// checkpoint is a vote for another Bitcoin history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtcCheckpoint {
    /// The Bitcoin block hash the checkpoint is anchored at.
    pub block_hash: [u8; 32],
    /// That block's height, in Bitcoin's own numbering.
    pub btc_height: u64,
    /// The MMR root of the headers the checkpoint commits to.
    pub mmr_root: [u8; 32],
}

/// An x-only (BIP340) EOTS public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EotsPublicKey {
    /// The 32-byte x coordinate.
    pub x_only: [u8; SCHNORR_PUBLIC_KEY_LEN],
}

impl EotsPublicKey {
    /// Whether the bytes are the x coordinate of a real secp256k1 point. A
    /// key that is not a point cannot have signed anything, and refusing it
    /// here keeps the curve error out of the signature check.
    #[must_use]
    pub fn is_on_curve(&self) -> bool {
        SchnorrVerifyingKey::from_slice(&self.x_only).is_ok()
    }
}

/// The optional post-quantum half of an epoch vote: ML-DSA-65 over the same
/// message bytes the EOTS half signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostQuantumHalf {
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

/// One finality provider's epoch vote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EotsVote {
    /// The finality provider this vote belongs to.
    pub provider: [u8; 32],
    /// The Budlum network's chain id, bound into the message so the vote
    /// cannot be replayed on another chain.
    pub chain_id: u64,
    /// The external chain height the vote finalises.
    pub height: u64,
    /// The Babylon epoch the vote was cast in.
    pub epoch: u64,
    /// The state root at `height`.
    pub state_root: [u8; 32],
    /// The Bitcoin checkpoint the finality is anchored to.
    pub checkpoint: BtcCheckpoint,
    /// The EOTS key the vote is signed under.
    pub eots_key: EotsPublicKey,
    /// The 64-byte BIP340 signature over [`epoch_vote_message`].
    pub signature: Vec<u8>,
    /// The optional ML-DSA-65 half over the same message.
    #[serde(default)]
    pub post_quantum: Option<PostQuantumHalf>,
}

/// The wire shape of one EOTS evidence envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EotsEvidence {
    /// The Budlum chain id every vote in the envelope was cast for.
    pub chain_id: u64,
    /// One vote, or two conflicting votes by one provider.
    pub votes: Vec<EotsVote>,
}

/// The exact bytes an epoch vote signs.
///
/// Every field is fixed width, so no field boundary can be shifted and no two
/// distinct votes produce the same message.
#[must_use]
pub fn epoch_vote_message(
    chain_id: u64,
    height: u64,
    epoch: u64,
    state_root: &[u8; 32],
    checkpoint: &BtcCheckpoint,
    eots_key: &EotsPublicKey,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(EPOCH_VOTE_TAG.len() + 8 * 4 + 32 * 4);
    message.extend_from_slice(EPOCH_VOTE_TAG);
    message.extend_from_slice(&chain_id.to_le_bytes());
    message.extend_from_slice(&height.to_le_bytes());
    message.extend_from_slice(&epoch.to_le_bytes());
    message.extend_from_slice(state_root);
    message.extend_from_slice(&checkpoint.block_hash);
    message.extend_from_slice(&checkpoint.btc_height.to_le_bytes());
    message.extend_from_slice(&checkpoint.mmr_root);
    message.extend_from_slice(&eots_key.x_only);
    message
}

/// The message a vote signs, built from the vote itself.
#[must_use]
pub fn vote_message(vote: &EotsVote) -> Vec<u8> {
    epoch_vote_message(
        vote.chain_id,
        vote.height,
        vote.epoch,
        &vote.state_root,
        &vote.checkpoint,
        &vote.eots_key,
    )
}

/// Verify a BIP340 signature over `message` under an x-only key.
///
/// # Errors
///
/// A reason naming which check failed: a key that is not a curve point, a
/// signature that is not a well-formed BIP340 signature, or a signature that
/// does not verify. Never a silent acceptance.
pub fn verify_schnorr(
    message: &[u8],
    signature: &[u8],
    x_only: &[u8; SCHNORR_PUBLIC_KEY_LEN],
) -> Result<(), String> {
    let signature_bytes: [u8; SCHNORR_SIGNATURE_LEN] = signature
        .try_into()
        .map_err(|_| format!("the signature is {} bytes, not 64", signature.len()))?;
    let verifying_key = SchnorrVerifyingKey::from_slice(x_only)
        .map_err(|_| "the EOTS public key is not a secp256k1 point".to_string())?;
    let signature = SchnorrSignature::from_bytes(&signature_bytes)
        .map_err(|_| "the EOTS signature is not a well-formed BIP340 signature".to_string())?;
    verifying_key
        .verify(message, &signature)
        .map_err(|_| "the EOTS signature does not verify over the epoch-vote message".to_string())
}

/// Verifiable evidence that one provider signed two conflicting epoch votes.
///
/// The two messages, both signatures and the key travel together under one
/// digest, so a slasher checks the same bytes this adapter checked. The proof
/// is deliberately *not* a secret key: see the module docs for why two
/// signatures cannot reveal one here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EotsEquivocationProof {
    /// The provider whose votes conflict.
    pub provider: [u8; 32],
    /// The EOTS key both votes are signed under.
    pub eots_key: [u8; SCHNORR_PUBLIC_KEY_LEN],
    /// The two domain-tagged messages that were signed.
    pub first_message: Vec<u8>,
    pub second_message: Vec<u8>,
    /// Both signatures over their own message.
    pub first_signature: Vec<u8>,
    pub second_signature: Vec<u8>,
    /// The two state roots, so a reader sees the conflict without decoding
    /// the messages.
    pub first_state_root: [u8; 32],
    pub second_state_root: [u8; 32],
    /// The two checkpoints. A conflict over the checkpoint alone is still a
    /// conflict: it is one claim about Bitcoin's history.
    pub first_checkpoint: BtcCheckpoint,
    pub second_checkpoint: BtcCheckpoint,
    /// `H(EQUIVOCATION_TAG || provider || key || len-prefixed messages and
    /// signatures || both claims)`, so the evidence cannot be re-encoded into
    /// a second event.
    pub proof_digest: [u8; 32],
}

impl EotsEquivocationProof {
    /// Recompute the digest from the proof's own fields.
    #[must_use]
    pub fn recomputed_digest(&self) -> [u8; 32] {
        let mut acc = Vec::with_capacity(512);
        acc.extend_from_slice(EQUIVOCATION_TAG);
        acc.extend_from_slice(&self.provider);
        acc.extend_from_slice(&self.eots_key);
        for bytes in [
            &self.first_message,
            &self.second_message,
            &self.first_signature,
            &self.second_signature,
        ] {
            acc.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            acc.extend_from_slice(bytes);
        }
        acc.extend_from_slice(&self.first_state_root);
        acc.extend_from_slice(&self.second_state_root);
        for checkpoint in [&self.first_checkpoint, &self.second_checkpoint] {
            acc.extend_from_slice(&checkpoint.block_hash);
            acc.extend_from_slice(&checkpoint.btc_height.to_le_bytes());
            acc.extend_from_slice(&checkpoint.mmr_root);
        }
        crate::core::hash::hash_fields_bytes(&[&acc])
    }

    /// Whether the two signed messages differ. Two identical messages are one
    /// claim, not equivocation.
    #[must_use]
    pub fn messages_differ(&self) -> bool {
        self.first_message != self.second_message
    }

    /// Check the proof with nothing but the proof: both signatures must
    /// verify under the named key over the named messages, the messages must
    /// differ, both messages must decode as canonical epoch-vote statements
    /// for the same non-zero `(chain_id, height, epoch)` bound to the proof's
    /// state roots, checkpoints, and EOTS key, and the digest must be the one
    /// the fields produce.
    ///
    /// # Errors
    ///
    /// The reason the proof does not hold.
    pub fn check(&self) -> Result<(), String> {
        if self.provider.iter().all(|b| *b == 0) {
            return Err("the equivocation proof names an all-zero finality provider".to_string());
        }
        if !self.messages_differ() {
            return Err("the two votes sign the same message: not an equivocation".to_string());
        }
        let first = parse_epoch_vote_message(&self.first_message)
            .map_err(|reason| format!("first vote message: {reason}"))?;
        let second = parse_epoch_vote_message(&self.second_message)
            .map_err(|reason| format!("second vote message: {reason}"))?;
        if first.chain_id != second.chain_id
            || first.height != second.height
            || first.epoch != second.epoch
        {
            return Err(
                "the two votes do not target the same (chain_id, height, epoch)".to_string(),
            );
        }
        if first.eots_key != self.eots_key || second.eots_key != self.eots_key {
            return Err("the signed messages do not bind to the proof's EOTS key".to_string());
        }
        if first.state_root != self.first_state_root
            || second.state_root != self.second_state_root
            || first.checkpoint != self.first_checkpoint
            || second.checkpoint != self.second_checkpoint
        {
            return Err(
                "the proof's state_root or checkpoint fields do not match the signed messages"
                    .to_string(),
            );
        }
        if self.first_state_root == self.second_state_root
            && self.first_checkpoint == self.second_checkpoint
        {
            return Err(
                "the two votes carry identical state_root and checkpoint claims".to_string(),
            );
        }
        verify_schnorr(&self.first_message, &self.first_signature, &self.eots_key)
            .map_err(|reason| format!("first vote: {reason}"))?;
        verify_schnorr(&self.second_message, &self.second_signature, &self.eots_key)
            .map_err(|reason| format!("second vote: {reason}"))?;
        if self.proof_digest != self.recomputed_digest() {
            return Err("the proof digest is not the digest of its own fields".to_string());
        }
        Ok(())
    }
}

struct ParsedEpochVoteMessage {
    chain_id: u64,
    height: u64,
    epoch: u64,
    state_root: [u8; 32],
    checkpoint: BtcCheckpoint,
    eots_key: [u8; SCHNORR_PUBLIC_KEY_LEN],
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    let slice = bytes.get(offset..offset.checked_add(8)?)?;
    let arr: [u8; 8] = slice.try_into().ok()?;
    Some(u64::from_le_bytes(arr))
}

fn read_arr32(bytes: &[u8], offset: usize) -> Option<[u8; 32]> {
    let slice = bytes.get(offset..offset.checked_add(32)?)?;
    slice.try_into().ok()
}

fn parse_epoch_vote_message(message: &[u8]) -> Result<ParsedEpochVoteMessage, String> {
    let expected_len = EPOCH_VOTE_TAG.len() + 8 * 4 + 32 * 4;
    if message.len() != expected_len {
        return Err(format!(
            "epoch-vote message is {} bytes, not the canonical {expected_len} bytes",
            message.len()
        ));
    }
    let body = message
        .strip_prefix(EPOCH_VOTE_TAG)
        .ok_or_else(|| "epoch-vote message does not start with EPOCH_VOTE_TAG".to_string())?;
    let chain_id = read_u64_le(body, 0).ok_or_else(|| "missing chain_id".to_string())?;
    let height = read_u64_le(body, 8).ok_or_else(|| "missing height".to_string())?;
    let epoch = read_u64_le(body, 16).ok_or_else(|| "missing epoch".to_string())?;
    let state_root = read_arr32(body, 24).ok_or_else(|| "missing state_root".to_string())?;
    let block_hash = read_arr32(body, 56).ok_or_else(|| "missing block_hash".to_string())?;
    let btc_height = read_u64_le(body, 88).ok_or_else(|| "missing btc_height".to_string())?;
    let mmr_root = read_arr32(body, 96).ok_or_else(|| "missing mmr_root".to_string())?;
    let eots_key = read_arr32(body, 128).ok_or_else(|| "missing eots_key".to_string())?;
    if chain_id == 0 || height == 0 || btc_height == 0 {
        return Err(
            "epoch-vote message carries a zero chain_id, height, or btc_height".to_string(),
        );
    }
    if state_root.iter().all(|b| *b == 0)
        || block_hash.iter().all(|b| *b == 0)
        || mmr_root.iter().all(|b| *b == 0)
    {
        return Err(
            "epoch-vote message carries an all-zero state_root, block_hash, or mmr_root"
                .to_string(),
        );
    }
    Ok(ParsedEpochVoteMessage {
        chain_id,
        height,
        epoch,
        state_root,
        checkpoint: BtcCheckpoint {
            block_hash,
            btc_height,
            mmr_root,
        },
        eots_key,
    })
}

/// The Bitcoin weak-subjectivity anchor a domain is registered with: the most
/// recent Bitcoin block the operator has verified, and how deep a checkpoint
/// must be below it to count as buried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtcWeakSubjectivityAnchor {
    pub tip_block_hash: [u8; 32],
    pub tip_height: u64,
    pub required_confirmations: u64,
}

impl BtcWeakSubjectivityAnchor {
    /// The lowest Bitcoin height a vote's checkpoint may name and still be
    /// buried by this anchor.
    ///
    /// WIRING: the admission report prints this bound beside the anchor, and
    /// the registry's rejection reason quotes it.
    #[must_use]
    pub const fn minimum_checkpoint_height(&self) -> u64 {
        self.tip_height.saturating_sub(self.required_confirmations)
    }
}

/// What shipping a default depth would mean, said once.
///
/// Babylon's own mainnet guidance is six Bitcoin blocks, and this constant
/// records that. The adapter does **not** read it: a default that fires when
/// the operator forgot an anchor would be the adapter inventing Bitcoin work
/// on the operator's behalf. It exists so tests and registrations can name
/// the number they mean.
pub const DEFAULT_REQUIRED_BTC_CONFIRMATIONS: u64 = 6;

impl EotsEvidence {
    /// Decode a payload.
    ///
    /// # Errors
    ///
    /// [`AdapterError::Malformed`] for a payload above the cap, one that does
    /// not decode, or one with trailing bytes.
    pub fn decode(payload: &[u8]) -> Result<Self, AdapterError> {
        use bincode::Options;
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(AdapterError::Malformed {
                offset: MAX_PAYLOAD_BYTES,
                reason: format!(
                    "payload is {} bytes, above the {MAX_PAYLOAD_BYTES}-byte cap",
                    payload.len()
                ),
            });
        }
        let byte_limit = u64::try_from(payload.len()).unwrap_or(u64::MAX);
        bincode::options()
            .with_fixint_encoding()
            .with_limit(byte_limit)
            .reject_trailing_bytes()
            .deserialize(payload)
            .map_err(|e| AdapterError::Malformed {
                offset: 0,
                reason: format!("payload does not decode: {e}"),
            })
    }

    /// Encode a payload.
    ///
    /// # Errors
    ///
    /// A serialization failure, or an encoding above the cap.
    pub fn encode(&self) -> Result<Vec<u8>, AdapterError> {
        let bytes = bincode::serialize(self).map_err(|e| AdapterError::Malformed {
            offset: 0,
            reason: format!("payload does not encode: {e}"),
        })?;
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(AdapterError::Malformed {
                offset: MAX_PAYLOAD_BYTES,
                reason: format!("encoded payload is {} bytes", bytes.len()),
            });
        }
        Ok(bytes)
    }

    /// Every shape rule, checked before any signature.
    ///
    /// # Errors
    ///
    /// [`AdapterError::ConsensusRule`] naming the rule that failed.
    pub fn validate_shape(&self) -> Result<(), AdapterError> {
        if self.chain_id == 0 {
            return Err(rule("the evidence carries a zero chain id"));
        }
        if self.votes.is_empty() {
            return Err(rule("the evidence carries no vote"));
        }
        if self.votes.len() > MAX_VOTES {
            return Err(rule(format!(
                "the evidence carries {} votes, above the {MAX_VOTES} cap",
                self.votes.len()
            )));
        }
        for (index, vote) in self.votes.iter().enumerate() {
            if vote.chain_id != self.chain_id {
                return Err(rule(format!(
                    "vote {index} names chain id {} but the envelope is for {}",
                    vote.chain_id, self.chain_id
                )));
            }
            if vote.provider.iter().all(|b| *b == 0) {
                return Err(rule(format!(
                    "vote {index} carries an all-zero finality provider"
                )));
            }
            if vote.height == 0 {
                return Err(rule(format!("vote {index} carries height 0")));
            }
            if vote.state_root.iter().all(|b| *b == 0) {
                return Err(rule(format!("vote {index} carries an all-zero state root")));
            }
            if vote.checkpoint.block_hash.iter().all(|b| *b == 0) {
                return Err(rule(format!(
                    "vote {index} names an all-zero Bitcoin checkpoint"
                )));
            }
            if vote.checkpoint.mmr_root.iter().all(|b| *b == 0) {
                return Err(rule(format!("vote {index} carries an all-zero MMR root")));
            }
            if vote.signature.len() != SCHNORR_SIGNATURE_LEN {
                return Err(rule(format!(
                    "vote {index} carries a {}-byte EOTS signature, not the {SCHNORR_SIGNATURE_LEN} bytes of BIP340",
                    vote.signature.len()
                )));
            }
            if vote.signature.iter().all(|b| *b == 0) {
                // An all-zero signature is not a signature that happens to
                // fail the curve: it is a placeholder, and calling it a crypto
                // failure would hide that the vote was never signed at all.
                return Err(rule(format!(
                    "vote {index} carries an all-zero EOTS signature"
                )));
            }
            if !vote.eots_key.is_on_curve() {
                return Err(rule(format!(
                    "vote {index} names an EOTS key that is not a secp256k1 point"
                )));
            }
            if let Some(pq) = &vote.post_quantum {
                let public_key_len =
                    crate::crypto::pq::public_key_len(crate::crypto::scheme::SchemeId::ML_DSA_65)
                        .map_err(|e| AdapterError::Unavailable {
                        reason: format!("the ML-DSA-65 lengths are not available: {e}"),
                    })?;
                let signature_len =
                    crate::crypto::pq::signature_len(crate::crypto::scheme::SchemeId::ML_DSA_65)
                        .map_err(|e| AdapterError::Unavailable {
                            reason: format!("the ML-DSA-65 lengths are not available: {e}"),
                        })?;
                if pq.public_key.len() != public_key_len {
                    return Err(rule(format!(
                        "vote {index} carries a {}-byte post-quantum public key, not the {public_key_len} bytes of ML-DSA-65",
                        pq.public_key.len()
                    )));
                }
                if pq.signature.len() != signature_len {
                    return Err(rule(format!(
                        "vote {index} carries a {}-byte post-quantum signature, not the {signature_len} bytes of ML-DSA-65",
                        pq.signature.len()
                    )));
                }
            }
        }
        if self.votes.len() == 2 && self.votes[0].provider != self.votes[1].provider {
            return Err(rule(
                "the two votes name different finality providers, which is not one provider's equivocation",
            ));
        }
        Ok(())
    }

    /// The conflicting pair, when the envelope carries one: same provider,
    /// same height, same epoch, and a different state root or checkpoint.
    #[must_use]
    pub fn conflict(&self) -> Option<(&EotsVote, &EotsVote)> {
        let [first, second] = self.votes.as_slice() else {
            return None;
        };
        if first.provider != second.provider
            || first.height != second.height
            || first.epoch != second.epoch
        {
            return None;
        }
        let differs = first.state_root != second.state_root
            || first.checkpoint.block_hash != second.checkpoint.block_hash
            || first.checkpoint.btc_height != second.checkpoint.btc_height
            || first.checkpoint.mmr_root != second.checkpoint.mmr_root;
        differs.then_some((first, second))
    }
}

/// The Babylon / BTC-restaking EOTS adapter.
#[derive(Debug, Clone)]
pub struct BabylonEotsAdapter {
    descriptor: AdapterDescriptor,
    network: String,
    chain_id: u64,
    /// The EOTS key announced for each epoch, as the pinned registration
    /// recorded it. An epoch nobody announced a key for has no provider.
    epoch_keys: Vec<(u64, EotsPublicKey)>,
    /// The post-quantum ML-DSA-65 public key announced for each epoch, when
    /// the registration pins one.
    epoch_pq_keys: Vec<(u64, Vec<u8>)>,
    /// The anchor, when the operator supplied one.
    anchor: Option<BtcWeakSubjectivityAnchor>,
    golden: Option<RawConsensusEvidence>,
}

impl BabylonEotsAdapter {
    /// A descriptor for a Babylon domain on `network` at `chain_id`, with no
    /// epoch keys and no anchor: it refuses every vote until both are
    /// supplied, which is the honest starting state.
    #[must_use]
    pub fn new(network: &str, chain_id: u64) -> Self {
        Self {
            descriptor: AdapterDescriptor {
                id: eots_adapter_id(),
                name: EOTS_ADAPTER_NAME.to_string(),
                adapter_version: ADAPTER_VERSION,
                accepted_evidence_versions: vec![EVIDENCE_VERSION],
                consensus_kind: "babylon-btc-restaking-eots".to_string(),
                finality_kind: FinalityKind::EconomicFinality,
                required_depth: 1,
                time_unit: TimeUnit::Epoch,
                trust_model: TrustModel::HonestMajority { set_size: 1 },
            },
            network: network.to_string(),
            chain_id,
            epoch_keys: Vec::new(),
            epoch_pq_keys: Vec::new(),
            anchor: None,
            golden: None,
        }
    }

    /// Pin the EOTS key announced for `epoch`.
    ///
    /// WIRING: the registration pins the announcement table from the domain
    /// record; no production line builds one yet.
    #[must_use]
    pub fn with_epoch_key(mut self, epoch: u64, key: EotsPublicKey) -> Self {
        self.epoch_keys.push((epoch, key));
        self
    }

    /// Convenience: pin the post-quantum ML-DSA-65 public key announced for `epoch`.
    ///
    /// WIRING: the registration pins the post-quantum announcement table from
    /// the domain record alongside `with_epoch_key`.
    #[must_use]
    pub fn with_epoch_pq_key(mut self, epoch: u64, pq_public_key: Vec<u8>) -> Self {
        self.epoch_pq_keys.push((epoch, pq_public_key));
        self
    }

    /// Pin the Bitcoin weak-subjectivity anchor.
    ///
    /// WIRING: the registration pins the anchor from the domain record; no
    /// production line builds one yet.
    #[must_use]
    pub const fn with_anchor(mut self, anchor: BtcWeakSubjectivityAnchor) -> Self {
        self.anchor = Some(anchor);
        self
    }

    /// Attach the known-good sample, which turns on the byte-level fault
    /// probe that needs one and lets [`super::selftest::admit`] prove the
    /// adapter accepts what it should.
    #[must_use]
    pub fn with_golden(mut self, golden: RawConsensusEvidence) -> Self {
        self.golden = Some(golden);
        self
    }

    /// The network this adapter is pinned to.
    #[must_use]
    pub fn network(&self) -> &str {
        &self.network
    }

    /// The EOTS key announced for `epoch`, if any.
    ///
    /// WIRING: read by the registry when it records which provider vouched for
    /// an epoch, and by `verify_evidence` below.
    #[must_use]
    pub fn announced_key(&self, epoch: u64) -> Option<EotsPublicKey> {
        self.epoch_keys
            .iter()
            .find(|(announced, _)| *announced == epoch)
            .map(|(_, key)| *key)
    }

    fn announced_pq_key(&self, epoch: u64) -> Option<&[u8]> {
        self.epoch_pq_keys
            .iter()
            .find(|(announced, _)| *announced == epoch)
            .map(|(_, key)| key.as_slice())
    }

    /// Whether the caller's policy requires a post-quantum half.
    ///
    /// `require_slashable` is the only policy field that speaks to backing, and
    /// it is the closest thing the contract has to "I will not accept a
    /// classical-only claim". The mapping lives here, in one place, instead of
    /// being re-inferred at every call site.
    #[must_use]
    pub const fn requires_post_quantum(policy: &VerificationPolicy) -> bool {
        policy.require_slashable
    }

    /// Verify one evidence envelope.
    ///
    /// Returns the attestation for the first vote and, when the envelope
    /// carries a conflicting pair, the equivocation proof a slasher checks.
    ///
    /// # Errors
    ///
    /// Any [`AdapterError`]; every branch refuses rather than approximates.
    pub fn verify_evidence(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<(FinalityAttestation, Option<EotsEquivocationProof>), AdapterError> {
        if evidence.adapter != self.descriptor.id {
            return Err(AdapterError::WrongAdapter {
                expected: self.descriptor.name.clone(),
                found: hex::encode(evidence.adapter.as_bytes()),
            });
        }
        // Fail-closed: an adapter bound to an empty (or whitespace-only)
        // network label is a configuration error. Without this guard the
        // `evidence.network != self.network` comparison below would treat
        // `"" == ""` as a match and accept any payload that also carries an
        // empty network, silently turning the adapter into an
        // accept-everything end. Reject every payload instead.
        if self.network.trim().is_empty() {
            return Err(AdapterError::ConsensusRule {
                rule: "BabylonEotsAdapter network identifier must not be empty".into(),
            });
        }
        if evidence.network != self.network {
            return Err(AdapterError::WrongAdapter {
                expected: self.network.clone(),
                found: evidence.network.clone(),
            });
        }
        if !self
            .descriptor
            .accepted_evidence_versions
            .contains(&evidence.evidence_version)
        {
            return Err(AdapterError::UnsupportedEvidenceVersion {
                version: evidence.evidence_version,
                accepted: EVIDENCE_VERSION.to_string(),
            });
        }
        if policy.min_depth > self.descriptor.required_depth {
            return Err(AdapterError::InsufficientDepth {
                observed: self.descriptor.required_depth,
                required: policy.min_depth,
            });
        }

        let anchor = self.anchor.as_ref().ok_or_else(|| {
            rule("no Bitcoin weak-subjectivity anchor is pinned for this Babylon domain")
        })?;
        if anchor.required_confirmations == 0 {
            return Err(rule(
                "pinned Bitcoin weak-subjectivity anchor must require at least 1 confirmation",
            ));
        }

        let decoded = EotsEvidence::decode(&evidence.payload)?;
        decoded.validate_shape()?;
        if decoded.chain_id != self.chain_id {
            return Err(rule(format!(
                "evidence chain id {} is not the pinned chain id {}",
                decoded.chain_id, self.chain_id
            )));
        }
        if decoded.votes.len() == 2 && decoded.conflict().is_none() {
            return Err(rule(
                "a two-vote evidence bundle must carry two conflicting votes for the same provider, height, and epoch",
            ));
        }

        let requires_pq = Self::requires_post_quantum(policy);
        let mut all_pq_pinned_and_verified = true;
        for (index, vote) in decoded.votes.iter().enumerate() {
            let announced = self.announced_key(vote.epoch).ok_or_else(|| {
                rule(format!(
                    "vote {index} is cast in epoch {} and no EOTS key was announced for it",
                    vote.epoch
                ))
            })?;
            if announced.x_only != vote.eots_key.x_only {
                return Err(rule(format!(
                    "vote {index} is signed under a key the epoch {} announcement does not name",
                    vote.epoch
                )));
            }
            Self::check_buried(index, vote, anchor)?;
            if requires_pq
                && (vote.post_quantum.is_none() || self.announced_pq_key(vote.epoch).is_none())
            {
                return Err(AdapterError::UnslashableBacking);
            }
            let message = vote_message(vote);
            verify_schnorr(&message, &vote.signature, &vote.eots_key.x_only).map_err(|reason| {
                AdapterError::Crypto {
                    what: format!("vote {index}: {reason}"),
                }
            })?;
            if let Some(pq) = &vote.post_quantum {
                let Some(pinned_pq) = self.announced_pq_key(vote.epoch) else {
                    return Err(rule(format!(
                        "vote {index} carries a post-quantum signature in epoch {}, which has no pinned ML-DSA-65 key",
                        vote.epoch
                    )));
                };
                if pq.public_key.as_slice() != pinned_pq {
                    return Err(rule(format!(
                        "vote {index} carries a post-quantum public key that does not match the pinned epoch {} ML-DSA-65 key",
                        vote.epoch
                    )));
                }
                crate::crypto::pq::verify(
                    crate::crypto::scheme::SchemeId::ML_DSA_65,
                    &pq.public_key,
                    &message,
                    crate::crypto::ctx::CROSS_DOMAIN_V1,
                    &pq.signature,
                )
                .map_err(|e| AdapterError::Crypto {
                    what: format!(
                        "vote {index}: the ML-DSA-65 half does not sign the same epoch-vote message as the EOTS half: {e}"
                    ),
                })?;
            } else {
                all_pq_pinned_and_verified = false;
            }
        }

        if policy.require_declared_match {
            if evidence.declared_height != decoded.votes[0].height {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if evidence.declared_root != decoded.votes[0].state_root {
                return Err(AdapterError::DeclarationMismatch {
                    field: "state_root",
                });
            }
        }

        if policy.max_age != 0 {
            // Age is measured in epochs, the unit `finalized_at` is in, and a
            // vote from the future is as stale as one from the past: it can no
            // longer be aged, and accepting it would let a provider pre-date a
            // claim.
            let epoch = decoded.votes[0].epoch;
            let age = if epoch > policy.now {
                return Err(AdapterError::Stale {
                    age: epoch - policy.now,
                    max_age: policy.max_age,
                });
            } else {
                policy.now - epoch
            };
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        let attestation = self.attest(evidence, &decoded.votes[0], all_pq_pinned_and_verified);
        let proof = decoded
            .conflict()
            .map(|(first, second)| equivocation_proof(first, second));
        Ok((attestation, proof))
    }

    /// The weak-subjectivity inequality, as one named check.
    ///
    /// # Errors
    ///
    /// [`AdapterError::ConsensusRule`] when the checkpoint is above the
    /// anchored tip or inside the confirmation window.
    fn check_buried(
        index: usize,
        vote: &EotsVote,
        anchor: &BtcWeakSubjectivityAnchor,
    ) -> Result<(), AdapterError> {
        let btc_height = vote.checkpoint.btc_height;
        if btc_height > anchor.tip_height {
            return Err(rule(format!(
                "vote {index} names Bitcoin checkpoint {btc_height}, above the anchored tip {}",
                anchor.tip_height
            )));
        }
        let depth = anchor.tip_height - btc_height;
        if depth < anchor.required_confirmations {
            return Err(rule(format!(
                "vote {index} names Bitcoin checkpoint {btc_height} only {depth} blocks below the anchored tip {}, below the required {}",
                anchor.tip_height, anchor.required_confirmations
            )));
        }
        Ok(())
    }

    /// The attestation a verified vote produces.
    fn attest(
        &self,
        evidence: &RawConsensusEvidence,
        vote: &EotsVote,
        pq_pinned_and_verified: bool,
    ) -> FinalityAttestation {
        let total_weight = u128::from(
            self.anchor
                .map_or(0, |anchor| anchor.required_confirmations),
        );
        // SLASHABLE-DEPENDS-ON-SCHEME: this domain's slashing guarantee is key
        // extraction - an equivocating finality provider reveals its EOTS secret
        // and the Bitcoin stake is taken. The guarantee is therefore only as
        // strong as the signature that would have to be forged to fake the
        // equivocation, so a classical-only vote is reported as not slashable
        // even though the remote protocol calls the stake slashable. Every
        // other adapter in this tree decides the field from the remote
        // protocol's economics alone; the gate
        // `slashable-is-not-quietly-a-scheme-claim` keeps the list of
        // exceptions to one line per site so a consumer comparing domains can
        // find them.
        let security = if pq_pinned_and_verified {
            SecurityBacking::SignatureSet {
                scheme: ObservedScheme::Secp256k1,
                signers: 1,
                required: 1,
                total_weight,
                slashable: true,
            }
        } else {
            SecurityBacking::SignatureSet {
                scheme: ObservedScheme::Secp256k1,
                signers: 1,
                required: 1,
                total_weight,
                slashable: false,
            }
        };
        FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &self.network),
            height: vote.height,
            state_root: vote.state_root,
            finalized_at: vote.epoch,
            time_unit: TimeUnit::Epoch,
            security,
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
            // The Bitcoin checkpoint is what the vote covers on Bitcoin; the
            // state root is the external chain's own commitment.
            attested_block_hash: Some(Hash32::from(vote.checkpoint.block_hash)),
            attested_event_root: None,
            attested_tx_root: None,
        }
    }
}

impl ExternalFinalityAdapter for BabylonEotsAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        self.descriptor.clone()
    }

    fn has_pinned_trust_anchor(&self) -> bool {
        self.anchor
            .as_ref()
            .is_some_and(|a| a.required_confirmations > 0)
            && !self.epoch_keys.is_empty()
    }

    fn verify(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, AdapterError> {
        let (attestation, conflict) = self.verify_evidence(evidence, policy)?;
        if conflict.is_some() {
            return Err(rule(
                "evidence carries two conflicting epoch votes (equivocation) and cannot attest finality",
            ));
        }
        Ok(attestation)
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        let mut probes = vec![
            FaultProbe {
                name: "a state root the votes do not carry is a declaration mismatch".to_string(),
                patch: BytePatch::DeclaredRoot { value: [0u8; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "a height the votes do not have is a declaration mismatch".to_string(),
                patch: BytePatch::DeclaredHeight { value: u64::MAX },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "a truncated payload must be refused, not partly parsed".to_string(),
                patch: BytePatch::TruncatePayload { keep: 16 },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "an evidence version the adapter does not read must be refused".to_string(),
                patch: BytePatch::EvidenceVersion {
                    value: EVIDENCE_VERSION + 1,
                },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "the adapter must not attest a different network".to_string(),
                patch: BytePatch::Network {
                    value: "not-the-pinned-network".to_string(),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::WrongAdapter),
            },
        ];

        // A signature-level corruption. The offset is *found* in the encoded
        // payload rather than hard-coded, so the probe follows the encoding
        // instead of an offset a field change would silently move.
        if let Some(golden) = &self.golden {
            if let Some((offset, byte)) = signature_corruption(golden) {
                probes.push(FaultProbe {
                    name: "one corrupted byte of the EOTS signature is a crypto refusal"
                        .to_string(),
                    patch: BytePatch::InPayload {
                        offset,
                        bytes: vec![byte],
                    },
                    expect: ExpectedRefusal::Kind(RefusalKind::Crypto),
                });
            }
        }
        probes
    }

    fn golden_evidence(&self) -> Option<RawConsensusEvidence> {
        self.golden.clone()
    }
}

/// Where to corrupt the golden sample's EOTS signature, and what to write.
///
/// The offset is found by searching the encoded payload for the signature's
/// own first eight bytes rather than hard-coded, and the replacement flips the
/// low bit of the first signature byte, so a BIP340 parse succeeds and the
/// verification is what refuses. Returns `None` when the sample does not
/// decode or carries no signature of the right length.
fn signature_corruption(golden: &RawConsensusEvidence) -> Option<(usize, u8)> {
    let decoded = EotsEvidence::decode(&golden.payload).ok()?;
    let signature = decoded.votes.first()?.signature.as_slice();
    if signature.len() != SCHNORR_SIGNATURE_LEN {
        return None;
    }
    let prefix = signature.get(..8)?;
    let offset = golden
        .payload
        .windows(prefix.len())
        .position(|window| window == prefix)?;
    let first = *signature.first()?;
    Some((offset, first ^ 0x01))
}

/// Convenience: the digest a vote is identified by: `H(EPOCH_VOTE_TAG ||
/// provider || height || epoch || state_root || checkpoint)`. Two votes over
/// one claim share it; a conflicting pair does not.
#[must_use]
pub fn vote_digest(vote: &EotsVote) -> [u8; 32] {
    crate::core::hash::hash_fields_bytes(&[
        EPOCH_VOTE_TAG,
        &vote.provider,
        &vote.height.to_le_bytes(),
        &vote.epoch.to_le_bytes(),
        &vote.state_root,
        &vote.checkpoint.block_hash,
        &vote.checkpoint.btc_height.to_le_bytes(),
        &vote.checkpoint.mmr_root,
    ])
}

/// The address a provider's x-only key maps to, so a registry record can key a
/// provider without a second identifier.
///
/// WIRING: the registry stores a provider's bond under this address; no
/// production line registers a Babylon provider yet.
#[must_use]
pub fn provider_address(x_only: &[u8; SCHNORR_PUBLIC_KEY_LEN]) -> Address {
    let digest = Sha256::digest(x_only);
    let mut address = [0u8; 32];
    address.copy_from_slice(&digest);
    Address(address)
}

fn equivocation_proof(first: &EotsVote, second: &EotsVote) -> EotsEquivocationProof {
    let mut proof = EotsEquivocationProof {
        provider: first.provider,
        eots_key: first.eots_key.x_only,
        first_message: vote_message(first),
        second_message: vote_message(second),
        first_signature: first.signature.clone(),
        second_signature: second.signature.clone(),
        first_state_root: first.state_root,
        second_state_root: second.state_root,
        first_checkpoint: first.checkpoint,
        second_checkpoint: second.checkpoint,
        proof_digest: [0u8; 32],
    };
    proof.proof_digest = proof.recomputed_digest();
    proof
}

fn rule(reason: impl Into<String>) -> AdapterError {
    AdapterError::ConsensusRule {
        rule: reason.into(),
    }
}

/// The governance-pinned trust anchor a Babylon EOTS domain is registered
/// under: the chain id, the Bitcoin weak-subjectivity anchor, and the epoch
/// EOTS (and optional post-quantum) key tables the provider announced.
///
/// This is the data a registration carries and a slasher's proof is checked
/// against. It is deliberately a plain, serialisable value: a domain whose
/// adapter cannot be rebuilt from its stored pin is a domain that silently
/// stops serving on restart, so the pin must round-trip through consensus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedBabylonEots {
    /// The chain id every vote in the domain is bound to.
    pub chain_id: u64,
    /// The Bitcoin weak-subjectivity anchor the checkpoints must be buried
    /// under.
    pub anchor: BtcWeakSubjectivityAnchor,
    /// The `(epoch, EOTS key)` table the provider announced.
    pub epoch_keys: Vec<(u64, EotsPublicKey)>,
    /// The `(epoch, ML-DSA-65 public key)` table, when the provider announced
    /// post-quantum keys. An epoch may carry an EOTS key without a PQ key; the
    /// reverse is rejected.
    #[serde(default)]
    pub epoch_pq_keys: Vec<(u64, Vec<u8>)>,
}

/// Largest epoch-key table a registration may carry. A table is governance
/// data, not a free-form blob; an unbounded one is a vector a hostile
/// registration could use to inflate the domain record.
pub const MAX_PINNED_EPOCHS: usize = 4096;

impl PinnedBabylonEots {
    /// Check the pin's shape. Every field must be well-formed for the pin to
    /// be a trust anchor at all: a pin that does not validate cannot certify a
    /// single vote, and refusing it at install time is the only place the
    /// shape is enforced once.
    ///
    /// # Errors
    ///
    /// A reason naming the field that is wrong.
    pub fn validate(&self) -> Result<(), String> {
        if self.chain_id == 0 {
            return Err("the pinned chain id is zero".to_string());
        }
        if self.anchor.required_confirmations == 0 {
            return Err("the anchor requires zero confirmations".to_string());
        }
        if self.anchor.tip_height < self.anchor.required_confirmations {
            return Err("the anchor tip is shallower than its confirmation depth".to_string());
        }
        if self.anchor.tip_block_hash.iter().all(|b| *b == 0) {
            return Err("the anchor tip block hash is all zero".to_string());
        }
        if self.epoch_keys.is_empty() {
            return Err("the pinned epoch-key table is empty".to_string());
        }
        if self.epoch_keys.len() > MAX_PINNED_EPOCHS {
            return Err(format!(
                "the pinned epoch-key table has {} entries, over the {MAX_PINNED_EPOCHS} cap",
                self.epoch_keys.len()
            ));
        }
        let mut previous: Option<u64> = None;
        for (epoch, key) in &self.epoch_keys {
            if *epoch == 0 {
                return Err("an epoch in the pinned table is zero".to_string());
            }
            if Some(*epoch) <= previous {
                return Err(format!(
                    "the pinned epoch-key table is not strictly increasing at epoch {epoch}"
                ));
            }
            if !key.is_on_curve() {
                return Err(format!(
                    "the EOTS key for epoch {epoch} is not a curve point"
                ));
            }
            previous = Some(*epoch);
        }
        let mut previous_pq: Option<u64> = None;
        for (epoch, key) in &self.epoch_pq_keys {
            if *epoch == 0 {
                return Err("a post-quantum epoch in the pinned table is zero".to_string());
            }
            if Some(*epoch) <= previous_pq {
                return Err(format!(
                    "the pinned post-quantum table is not strictly increasing at epoch {epoch}"
                ));
            }
            if key.is_empty() {
                return Err(format!("the post-quantum key for epoch {epoch} is empty"));
            }
            if !self.epoch_keys.iter().any(|(e, _)| *e == *epoch) {
                return Err(format!(
                    "a post-quantum key is pinned for epoch {epoch}, which has no EOTS key"
                ));
            }
            previous_pq = Some(*epoch);
        }
        Ok(())
    }

    /// The EOTS key announced for `epoch`, if the table names it.
    #[must_use]
    pub fn epoch_key(&self, epoch: u64) -> Option<&EotsPublicKey> {
        self.epoch_keys
            .iter()
            .find(|(announced, _)| *announced == epoch)
            .map(|(_, key)| key)
    }

    /// Rebuild the adapter this pin describes, bound to `network`.
    ///
    /// The adapter is reconstructed from the pin on every verification, so a
    /// restart and live operation derive the same trust root from the same
    /// stored data.
    #[must_use]
    pub fn build_adapter(&self, network: &str) -> BabylonEotsAdapter {
        let mut adapter = BabylonEotsAdapter::new(network, self.chain_id).with_anchor(self.anchor);
        for (epoch, key) in &self.epoch_keys {
            adapter = adapter.with_epoch_key(*epoch, *key);
        }
        for (epoch, key) in &self.epoch_pq_keys {
            adapter = adapter.with_epoch_pq_key(*epoch, key.clone());
        }
        adapter
    }
}

/// Verify an EOTS equivocation proof against a governance-pinned trust anchor.
///
/// The proof is first checked with nothing but itself ([`EotsEquivocationProof::check`]:
/// both signatures verify under the named key, the messages differ, the
/// digest is the one the fields produce). Then the proof is bound to *this*
/// domain: its votes must name the pinned chain id, and the EOTS key they are
/// signed under must be the one the pin announced for that epoch. A proof that
/// is internally consistent but signed under a key governance never announced
/// is refused - it is a valid equivocation, by somebody who is not this
/// domain's provider.
///
/// # Errors
///
/// The reason the proof does not bind to the pin.
pub fn verify_eots_equivocation(
    pinned: &PinnedBabylonEots,
    proof: &EotsEquivocationProof,
) -> Result<(), String> {
    proof.check()?;
    let first = parse_epoch_vote_message(&proof.first_message)?;
    if first.chain_id != pinned.chain_id {
        return Err(format!(
            "the equivocation votes name chain id {} but the pinned chain id is {}",
            first.chain_id, pinned.chain_id
        ));
    }
    let Some(announced) = pinned.epoch_key(first.epoch) else {
        return Err(format!(
            "the equivocation votes name epoch {} and no EOTS key was announced for it",
            first.epoch
        ));
    };
    if announced.x_only != proof.eots_key {
        return Err(format!(
            "the equivocation proof is signed under a key the epoch {} announcement does not name",
            first.epoch
        ));
    }
    Ok(())
}

/// Test-only fixtures shared with the intake and transaction-door tests.
///
/// The intake tests need a real signed vote and a real conflicting pair; the
/// private helpers below `mod tests` are not visible outside this module.
/// This surface exists only under `cfg(test)`, and it builds the same bytes a
/// registration and a slasher would build.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use k256::schnorr::signature::Signer;

    pub(crate) const CHAIN_ID: u64 = 45_261;
    pub(crate) const NETWORK: &str = "babylon-mainnet";
    pub(crate) const EPOCH: u64 = 19_004;
    pub(crate) const HEIGHT: u64 = 884_213;
    /// The seed of the one provider the pinned table names.
    pub(crate) const PINNED_SEED: u8 = 0x5B;

    fn signing_key(seed: u8) -> k256::schnorr::SigningKey {
        k256::schnorr::SigningKey::from_slice(&[seed; 32]).expect("the seed is a valid scalar")
    }

    pub(crate) fn public_key_for(seed: u8) -> EotsPublicKey {
        let bytes = signing_key(seed).verifying_key().to_bytes();
        let mut x_only = [0u8; SCHNORR_PUBLIC_KEY_LEN];
        x_only.copy_from_slice(bytes.as_slice());
        EotsPublicKey { x_only }
    }

    fn checkpoint(btc_height: u64, salt: u8) -> BtcCheckpoint {
        BtcCheckpoint {
            block_hash: [salt; 32],
            btc_height,
            mmr_root: [salt.wrapping_add(1); 32],
        }
    }

    fn vote(
        seed: u8,
        height: u64,
        epoch: u64,
        state_root: [u8; 32],
        checkpoint: BtcCheckpoint,
    ) -> EotsVote {
        let key = public_key_for(seed);
        let message = epoch_vote_message(CHAIN_ID, height, epoch, &state_root, &checkpoint, &key);
        let signature: SchnorrSignature = signing_key(seed).sign(&message);
        EotsVote {
            provider: [0x11; 32],
            chain_id: CHAIN_ID,
            height,
            epoch,
            state_root,
            checkpoint,
            eots_key: key,
            signature: signature.to_bytes().to_vec(),
            post_quantum: None,
        }
    }

    fn envelope(votes: Vec<EotsVote>) -> RawConsensusEvidence {
        let payload = EotsEvidence {
            chain_id: CHAIN_ID,
            votes,
        }
        .encode()
        .expect("encodes");
        let decoded = EotsEvidence::decode(&payload).expect("decodes");
        let first = decoded.votes.first().expect("one vote");
        RawConsensusEvidence {
            adapter: eots_adapter_id(),
            evidence_version: EVIDENCE_VERSION,
            network: NETWORK.to_string(),
            payload,
            declared_height: first.height,
            declared_root: first.state_root,
            submitter: Address::from([0x2A; 32]),
        }
    }

    fn first_vote(seed: u8) -> EotsVote {
        vote(seed, HEIGHT, EPOCH, [0x91; 32], checkpoint(870_000, 0x33))
    }

    /// The pin governance installs for `NETWORK`: the one announced key and
    /// a Bitcoin anchor that buries the fixture checkpoints.
    pub(crate) fn pinned() -> PinnedBabylonEots {
        PinnedBabylonEots {
            chain_id: CHAIN_ID,
            anchor: BtcWeakSubjectivityAnchor {
                tip_block_hash: [0xC4; 32],
                tip_height: 870_010,
                required_confirmations: DEFAULT_REQUIRED_BTC_CONFIRMATIONS,
            },
            epoch_keys: vec![(EPOCH, public_key_for(PINNED_SEED))],
            epoch_pq_keys: Vec::new(),
        }
    }

    /// A single well-formed vote by the pinned provider, for registration.
    pub(crate) fn golden_evidence() -> RawConsensusEvidence {
        envelope(vec![first_vote(PINNED_SEED)])
    }

    /// Two conflicting votes by `seed`'s provider at one height and epoch.
    pub(crate) fn conflicting_evidence(seed: u8) -> RawConsensusEvidence {
        let second = vote(seed, HEIGHT, EPOCH, [0x91; 32], checkpoint(869_000, 0x44));
        envelope(vec![first_vote(seed), second])
    }

    /// The equivocation proof a slasher carries, derived exactly as the
    /// adapter derives it from the evidence: verify the pair against `pinned`
    /// and take the proof it yields.
    pub(crate) fn equivocation_proof(
        pinned: &PinnedBabylonEots,
        seed: u8,
    ) -> EotsEquivocationProof {
        let mut policy = VerificationPolicy::strict(0);
        policy.require_slashable = false;
        pinned
            .build_adapter(NETWORK)
            .verify_evidence(&conflicting_evidence(seed), &policy)
            .expect("a conflicting pair verifies and yields a proof")
            .1
            .expect("the pair yields a proof")
    }

    /// An equivocation proof by a provider the pinned table does NOT name.
    ///
    /// The adapter refuses votes signed under a key it never announced, so
    /// this cannot come out of [`Self::equivocation_proof`]; it is built
    /// straight from the two conflicting votes. The proof is internally
    /// consistent - [`EotsEquivocationProof::check`] passes - and is refused
    /// only because the key it names is not the one governance announced.
    pub(crate) fn foreign_equivocation_proof(seed: u8) -> EotsEquivocationProof {
        let first = vote(seed, HEIGHT, EPOCH, [0x91; 32], checkpoint(870_000, 0x33));
        let second = vote(seed, HEIGHT, EPOCH, [0x91; 32], checkpoint(869_000, 0x44));
        super::equivocation_proof(&first, &second)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::external::selftest::{admit, ProbeOutcome};
    use crate::crypto::pq::{ml_dsa_public_key, ml_dsa_sign};
    use crate::crypto::scheme::SchemeId;

    const CHAIN_ID: u64 = 45_261;
    const NETWORK: &str = "babylon-mainnet";
    const EPOCH: u64 = 19_004;
    const HEIGHT: u64 = 884_213;

    /// A provider key. `0x5B` repeated is a valid secp256k1 scalar.
    fn eots_signing_key() -> k256::schnorr::SigningKey {
        k256::schnorr::SigningKey::from_slice(&[0x5B; 32]).expect("the seed is a valid scalar")
    }

    /// The x-only public key of a signing key, copied out of the curve type's
    /// own byte array.
    fn x_only_of(signing: &k256::schnorr::SigningKey) -> EotsPublicKey {
        let bytes = signing.verifying_key().to_bytes();
        let mut x_only = [0u8; SCHNORR_PUBLIC_KEY_LEN];
        x_only.copy_from_slice(bytes.as_slice());
        EotsPublicKey { x_only }
    }

    fn eots_public_key() -> EotsPublicKey {
        x_only_of(&eots_signing_key())
    }

    fn checkpoint(btc_height: u64, salt: u8) -> BtcCheckpoint {
        BtcCheckpoint {
            block_hash: [salt; 32],
            btc_height,
            mmr_root: [salt.wrapping_add(1); 32],
        }
    }

    /// A vote signed by both halves.
    fn signed_vote(
        provider: [u8; 32],
        eots_key: EotsPublicKey,
        height: u64,
        epoch: u64,
        state_root: [u8; 32],
        checkpoint: BtcCheckpoint,
    ) -> EotsVote {
        let signing = eots_signing_key();
        let message =
            epoch_vote_message(CHAIN_ID, height, epoch, &state_root, &checkpoint, &eots_key);
        let signature: SchnorrSignature = {
            use k256::schnorr::signature::Signer;
            signing.sign(&message)
        };
        let seed = [0x7Bu8; 32];
        let public_key = ml_dsa_public_key(SchemeId::ML_DSA_65, &seed).expect("ml-dsa-65 key");
        let pq_signature = ml_dsa_sign(
            SchemeId::ML_DSA_65,
            &seed,
            &message,
            crate::crypto::ctx::CROSS_DOMAIN_V1,
            &[0x11; 32],
        )
        .expect("ml-dsa-65 sign");
        EotsVote {
            provider,
            chain_id: CHAIN_ID,
            height,
            epoch,
            state_root,
            checkpoint,
            eots_key,
            signature: signature.to_bytes().to_vec(),
            post_quantum: Some(PostQuantumHalf {
                public_key,
                signature: pq_signature,
            }),
        }
    }

    fn golden_vote() -> EotsVote {
        signed_vote(
            [0x11; 32],
            eots_public_key(),
            HEIGHT,
            EPOCH,
            [0x91; 32],
            checkpoint(870_000, 0x33),
        )
    }

    fn envelope(votes: Vec<EotsVote>) -> RawConsensusEvidence {
        let payload = EotsEvidence {
            chain_id: CHAIN_ID,
            votes,
        }
        .encode()
        .expect("encodes");
        let decoded = EotsEvidence::decode(&payload).expect("decodes");
        let first = decoded.votes.first().expect("one vote");
        RawConsensusEvidence {
            adapter: eots_adapter_id(),
            evidence_version: EVIDENCE_VERSION,
            network: NETWORK.to_string(),
            payload,
            declared_height: first.height,
            declared_root: first.state_root,
            submitter: crate::core::address::Address::from([0x2A; 32]),
        }
    }

    fn adapter() -> BabylonEotsAdapter {
        let pq_pk = ml_dsa_public_key(SchemeId::ML_DSA_65, &[0x7B; 32]).expect("ml-dsa-65 key");
        BabylonEotsAdapter::new(NETWORK, CHAIN_ID)
            .with_epoch_key(EPOCH, eots_public_key())
            .with_epoch_pq_key(EPOCH, pq_pk)
            .with_anchor(BtcWeakSubjectivityAnchor {
                tip_block_hash: [0xC4; 32],
                tip_height: 870_010,
                required_confirmations: DEFAULT_REQUIRED_BTC_CONFIRMATIONS,
            })
    }

    fn policy() -> VerificationPolicy {
        VerificationPolicy::strict(0)
    }

    #[test]
    fn empty_network_adapter_refuses_evidence_fail_closed() {
        // An adapter constructed with an empty network label is a
        // configuration error. It must refuse every evidence payload
        // fail-closed instead of accepting payloads that also carry an
        // empty network (where `"" == ""` would otherwise match).
        let adapter = BabylonEotsAdapter::new("", 0);
        let raw = RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: EVIDENCE_VERSION,
            network: String::new(),
            payload: Vec::new(),
            declared_height: 0,
            declared_root: [0u8; 32],
            submitter: crate::core::address::Address([0u8; 32]),
        };
        let err = adapter
            .verify(&raw, &VerificationPolicy::strict(0))
            .unwrap_err();
        assert!(
            matches!(&err, AdapterError::ConsensusRule { rule } if rule.contains("empty")),
            "empty-network adapter must refuse fail-closed, got {err:?}"
        );
    }

    #[test]
    fn a_golden_epoch_vote_attests_the_checkpoint_it_signs() {
        let evidence = envelope(vec![golden_vote()]);
        let adapter = adapter().with_golden(evidence.clone());
        let attestation = adapter
            .verify(&evidence, &policy())
            .expect("golden verifies");
        assert_eq!(attestation.height, HEIGHT);
        assert_eq!(attestation.state_root, [0x91; 32]);
        assert_eq!(attestation.finalized_at, EPOCH);
        assert_eq!(
            attestation.attested_block_hash,
            Some(Hash32::from(checkpoint(870_000, 0x33).block_hash))
        );
        assert_eq!(
            attestation.security,
            SecurityBacking::SignatureSet {
                scheme: ObservedScheme::Secp256k1,
                signers: 1,
                required: 1,
                total_weight: u128::from(DEFAULT_REQUIRED_BTC_CONFIRMATIONS),
                slashable: true,
            }
        );
        // Admission runs the golden sample first, then every probe, so an
        // adapter that refuses everything cannot pass by refusing.
        let report = admit(&adapter, &policy());
        assert!(report.golden_verified, "{report:?}");
        assert!(report.admitted, "{report:?}");
        assert!(report
            .probes
            .iter()
            .all(|(_, outcome)| matches!(outcome, ProbeOutcome::Refused { .. })));
    }

    #[test]
    fn a_rewritten_state_root_under_an_old_signature_is_refused() {
        let mut vote = golden_vote();
        // Re-point the vote at an attacker's root without re-signing.
        vote.state_root = [0x92; 32];
        let mut evidence = envelope(vec![vote]);
        evidence.declared_root = [0x92; 32];
        let refused = adapter()
            .verify(&evidence, &policy())
            .expect_err("a rewritten root must not verify");
        assert!(
            matches!(refused, AdapterError::Crypto { .. }),
            "{refused:?}"
        );
    }

    #[test]
    fn a_vote_signed_under_a_key_the_epoch_never_announced_is_refused() {
        let stranger = k256::schnorr::SigningKey::from_slice(&[0x77; 32]).expect("valid scalar");
        let stranger_key = x_only_of(&stranger);
        // The vote signs under the stranger's own key, so the signature is
        // internally valid: only the announcement check can refuse it.
        let vote = signed_vote(
            [0x11; 32],
            stranger_key,
            HEIGHT,
            EPOCH,
            [0x91; 32],
            checkpoint(870_000, 0x33),
        );
        let evidence = envelope(vec![vote]);
        let refused = adapter()
            .verify(&evidence, &policy())
            .expect_err("an unannounced key is not a provider");
        assert!(
            matches!(refused, AdapterError::ConsensusRule { .. }),
            "{refused:?}"
        );
    }

    #[test]
    fn a_vote_from_an_epoch_without_an_announced_key_is_refused() {
        let vote = signed_vote(
            [0x11; 32],
            eots_public_key(),
            HEIGHT,
            EPOCH + 1,
            [0x91; 32],
            checkpoint(870_000, 0x33),
        );
        assert!(matches!(
            adapter().verify(&envelope(vec![vote]), &policy()),
            Err(AdapterError::ConsensusRule { .. })
        ));
    }

    #[test]
    fn a_classical_only_vote_is_refused_when_the_caller_requires_post_quantum() {
        let mut vote = golden_vote();
        vote.post_quantum = None;
        let evidence = envelope(vec![vote]);
        let mut pq_policy = policy();
        pq_policy.require_slashable = true;
        assert_eq!(
            adapter().verify(&evidence, &pq_policy),
            Err(AdapterError::UnslashableBacking)
        );
        // Without that requirement a classical half is attestable, and the
        // attestation still says which scheme backed it (with slashable=false).
        let attestation = adapter()
            .verify(&evidence, &policy())
            .expect("a classical vote attests when nobody asked for more");
        assert_eq!(
            attestation.security.observed_scheme(),
            Some(ObservedScheme::Secp256k1)
        );
        assert!(matches!(
            attestation.security,
            SecurityBacking::SignatureSet {
                slashable: false,
                ..
            }
        ));
        // An ephemeral unpinned ML-DSA-65 public key on the wire must also be refused.
        let mut unpinned_pq_vote = golden_vote();
        let rogue_seed = [0xFEu8; 32];
        let rogue_pk = ml_dsa_public_key(SchemeId::ML_DSA_65, &rogue_seed).expect("rogue key");
        let rogue_sig = ml_dsa_sign(
            SchemeId::ML_DSA_65,
            &rogue_seed,
            &vote_message(&unpinned_pq_vote),
            crate::crypto::ctx::CROSS_DOMAIN_V1,
            &[0x11; 32],
        )
        .expect("rogue sign");
        unpinned_pq_vote.post_quantum = Some(PostQuantumHalf {
            public_key: rogue_pk,
            signature: rogue_sig,
        });
        assert!(matches!(
            adapter().verify(&envelope(vec![unpinned_pq_vote]), &pq_policy),
            Err(AdapterError::ConsensusRule { .. })
        ));
    }

    #[test]
    fn a_post_quantum_half_over_other_bytes_is_refused() {
        let mut vote = golden_vote();
        let seed = [0x7Bu8; 32];
        let public_key = ml_dsa_public_key(SchemeId::ML_DSA_65, &seed).expect("key");
        let other = ml_dsa_sign(
            SchemeId::ML_DSA_65,
            &seed,
            b"a different finality claim",
            crate::crypto::ctx::CROSS_DOMAIN_V1,
            &[0x11; 32],
        )
        .expect("sign");
        vote.post_quantum = Some(PostQuantumHalf {
            public_key,
            signature: other,
        });
        let refused = adapter()
            .verify(&envelope(vec![vote]), &policy())
            .expect_err("a PQ half over other bytes is not a second opinion");
        assert!(
            matches!(refused, AdapterError::Crypto { .. }),
            "{refused:?}"
        );
    }

    /// The weak-subjectivity inequality: a checkpoint inside the confirmation
    /// window is not buried by the work the anchor states.
    #[test]
    fn a_checkpoint_inside_the_confirmation_window_is_refused() {
        let adapter = adapter();
        // The anchored tip is 870,010 with six required confirmations, so the
        // lowest acceptable checkpoint is 870,004.
        for too_recent in [870_005u64, 870_006, 870_009, 870_010] {
            let vote = signed_vote(
                [0x11; 32],
                eots_public_key(),
                HEIGHT,
                EPOCH,
                [0x91; 32],
                checkpoint(too_recent, 0x33),
            );
            let refused = adapter
                .verify(&envelope(vec![vote]), &policy())
                .expect_err("a shallow checkpoint must be refused");
            assert!(
                matches!(refused, AdapterError::ConsensusRule { .. }),
                "{too_recent}: {refused:?}"
            );
        }
        // Above the anchored tip is not a buried checkpoint at all.
        let ahead = signed_vote(
            [0x11; 32],
            eots_public_key(),
            HEIGHT,
            EPOCH,
            [0x91; 32],
            checkpoint(870_011, 0x33),
        );
        assert!(matches!(
            adapter.verify(&envelope(vec![ahead]), &policy()),
            Err(AdapterError::ConsensusRule { .. })
        ));
        // Exactly at the required depth is buried, and attests.
        let at_depth = signed_vote(
            [0x11; 32],
            eots_public_key(),
            HEIGHT,
            EPOCH,
            [0x91; 32],
            checkpoint(870_004, 0x33),
        );
        assert!(adapter.verify(&envelope(vec![at_depth]), &policy()).is_ok());
    }

    /// Without an anchor the adapter refuses every vote until an anchor is
    /// pinned, matching `BabylonEotsAdapter::new`'s documented starting state.
    #[test]
    fn an_unanchored_domain_reports_no_bitcoin_weight() {
        let pq_pk = ml_dsa_public_key(SchemeId::ML_DSA_65, &[0x7B; 32]).expect("ml-dsa-65 key");
        let adapter = BabylonEotsAdapter::new(NETWORK, CHAIN_ID)
            .with_epoch_key(EPOCH, eots_public_key())
            .with_epoch_pq_key(EPOCH, pq_pk);
        let refused = adapter
            .verify(&envelope(vec![golden_vote()]), &policy())
            .expect_err("an unanchored domain must refuse votes rather than bypass check_buried");
        assert!(matches!(refused, AdapterError::ConsensusRule { .. }));
    }

    #[test]
    fn two_conflicting_epoch_votes_yield_a_proof_anybody_can_check() {
        let first = golden_vote();
        let second = signed_vote(
            [0x11; 32],
            eots_public_key(),
            HEIGHT,
            EPOCH,
            [0x91; 32],
            checkpoint(869_000, 0x44),
        );
        let evidence = envelope(vec![first, second]);
        let (attestation, proof) = adapter()
            .verify_evidence(&evidence, &policy())
            .expect("two conflicting votes still attest in verify_evidence, and yield a proof");
        assert_eq!(attestation.height, HEIGHT);
        // ExternalFinalityAdapter::verify must refuse a self-contradicting 2-vote envelope.
        assert!(matches!(
            adapter().verify(&evidence, &policy()),
            Err(AdapterError::ConsensusRule { .. })
        ));
        let proof = proof.expect("a conflicting pair yields a proof");
        assert!(proof.messages_differ());
        assert_eq!(proof.proof_digest, proof.recomputed_digest());
        assert_eq!(proof.first_checkpoint.btc_height, 870_000);
        assert_eq!(proof.second_checkpoint.btc_height, 869_000);
        // Checkable with nothing but the proof.
        proof.check().expect("the proof holds");
        // Cross-height honest votes or spoofed state roots must be rejected by check().
        let honest_other_height = signed_vote(
            [0x11; 32],
            eots_public_key(),
            HEIGHT + 1,
            EPOCH,
            [0x92; 32],
            checkpoint(870_000, 0x44),
        );
        let mut cross_height = proof.clone();
        cross_height.second_message = vote_message(&honest_other_height);
        cross_height.second_signature = honest_other_height.signature;
        cross_height.second_state_root = honest_other_height.state_root;
        cross_height.second_checkpoint = honest_other_height.checkpoint;
        cross_height.proof_digest = cross_height.recomputed_digest();
        assert!(
            cross_height.check().is_err(),
            "two honest votes from different heights must not verify as equivocation"
        );
        let mut spoofed_root = proof.clone();
        spoofed_root.first_state_root = [0xEE; 32];
        spoofed_root.proof_digest = spoofed_root.recomputed_digest();
        assert!(
            spoofed_root.check().is_err(),
            "spoofed state_root not bound to signed message must be rejected"
        );
        // And a tampered pair no longer holds together.
        let mut tampered = proof;
        tampered.second_message[EPOCH_VOTE_TAG.len()] ^= 0xFF;
        assert!(
            tampered.check().is_err(),
            "the proof is bound to the signed bytes"
        );
    }

    #[test]
    fn a_repeated_identical_vote_is_not_equivocation() {
        let vote = golden_vote();
        let decoded = EotsEvidence {
            chain_id: CHAIN_ID,
            votes: vec![vote.clone(), vote],
        };
        assert!(decoded.conflict().is_none());
        assert_eq!(
            vote_digest(&decoded.votes[0]),
            vote_digest(&decoded.votes[1])
        );
    }

    #[test]
    fn votes_by_two_different_providers_are_not_one_equivocation() {
        let first = golden_vote();
        let second = signed_vote(
            [0x22; 32],
            eots_public_key(),
            HEIGHT,
            EPOCH,
            [0x92; 32],
            checkpoint(870_000, 0x33),
        );
        let decoded = EotsEvidence {
            chain_id: CHAIN_ID,
            votes: vec![first, second],
        };
        // Two providers disagreeing is a fork with two authors, not one
        // provider signing twice, and this adapter does not attest it.
        assert!(matches!(
            decoded.validate_shape(),
            Err(AdapterError::ConsensusRule { .. })
        ));
        assert!(decoded.conflict().is_none());
    }

    #[test]
    fn a_vote_for_another_chain_id_is_refused() {
        let mut vote = golden_vote();
        vote.chain_id = CHAIN_ID + 1;
        assert!(matches!(
            adapter().verify(&envelope(vec![vote]), &policy()),
            Err(AdapterError::ConsensusRule { .. })
        ));
    }

    #[test]
    fn a_signature_over_a_different_epoch_is_refused() {
        let vote = golden_vote();
        // Keep the signature, change the epoch the vote claims. The epoch is
        // inside the signed message, so this is a forgery and not a replay.
        let mut moved = vote;
        moved.epoch = EPOCH + 1;
        let evidence = envelope(vec![moved]);
        let pq_pk = ml_dsa_public_key(SchemeId::ML_DSA_65, &[0x7B; 32]).expect("ml-dsa-65 key");
        let refused = BabylonEotsAdapter::new(NETWORK, CHAIN_ID)
            .with_epoch_key(EPOCH, eots_public_key())
            .with_epoch_key(EPOCH + 1, eots_public_key())
            .with_epoch_pq_key(EPOCH, pq_pk.clone())
            .with_epoch_pq_key(EPOCH + 1, pq_pk)
            .with_anchor(BtcWeakSubjectivityAnchor {
                tip_block_hash: [0xC4; 32],
                tip_height: 870_010,
                required_confirmations: DEFAULT_REQUIRED_BTC_CONFIRMATIONS,
            })
            .verify(&evidence, &policy())
            .expect_err("the epoch is inside the signed message");
        assert!(
            matches!(refused, AdapterError::Crypto { .. }),
            "{refused:?}"
        );
    }

    #[test]
    fn an_eots_key_outside_the_curve_is_refused_before_any_signature_check() {
        let not_a_point = EotsPublicKey { x_only: [0xFF; 32] };
        assert!(!not_a_point.is_on_curve());
        let vote = EotsVote {
            provider: [0x11; 32],
            chain_id: CHAIN_ID,
            height: HEIGHT,
            epoch: EPOCH,
            state_root: [0x91; 32],
            checkpoint: checkpoint(870_000, 0x33),
            eots_key: not_a_point,
            signature: vec![0x11; SCHNORR_SIGNATURE_LEN],
            post_quantum: None,
        };
        assert!(matches!(
            EotsEvidence {
                chain_id: CHAIN_ID,
                votes: vec![vote]
            }
            .validate_shape(),
            Err(AdapterError::ConsensusRule { .. })
        ));
    }

    #[test]
    fn an_all_zero_signature_is_refused_by_shape_not_by_the_curve() {
        let mut vote = golden_vote();
        vote.signature = vec![0u8; SCHNORR_SIGNATURE_LEN];
        assert!(matches!(
            EotsEvidence {
                chain_id: CHAIN_ID,
                votes: vec![vote]
            }
            .validate_shape(),
            Err(AdapterError::ConsensusRule { .. })
        ));
    }

    #[test]
    fn a_third_vote_is_refused_by_the_cap() {
        let vote = golden_vote();
        let decoded = EotsEvidence {
            chain_id: CHAIN_ID,
            votes: vec![vote.clone(), vote.clone(), vote],
        };
        assert!(matches!(
            decoded.validate_shape(),
            Err(AdapterError::ConsensusRule { .. })
        ));
    }

    #[test]
    fn a_payload_with_trailing_bytes_is_malformed() {
        let payload = EotsEvidence {
            chain_id: CHAIN_ID,
            votes: vec![golden_vote()],
        }
        .encode()
        .expect("encodes");
        let mut extended = payload;
        extended.push(0x00);
        assert!(matches!(
            EotsEvidence::decode(&extended),
            Err(AdapterError::Malformed { .. })
        ));
    }

    #[test]
    fn a_declared_height_the_payload_does_not_have_is_a_mismatch() {
        let mut evidence = envelope(vec![golden_vote()]);
        evidence.declared_height = HEIGHT + 1;
        assert_eq!(
            adapter().verify(&evidence, &policy()),
            Err(AdapterError::DeclarationMismatch { field: "height" })
        );
    }

    #[test]
    fn an_age_beyond_the_callers_window_is_stale_and_a_future_epoch_is_stale() {
        let evidence = envelope(vec![golden_vote()]);
        let mut old = policy();
        old.now = EPOCH + 100;
        old.max_age = 10;
        assert!(matches!(
            adapter().verify(&evidence, &old),
            Err(AdapterError::Stale { .. })
        ));
        let mut future = policy();
        future.now = EPOCH - 100;
        future.max_age = 10;
        assert!(matches!(
            adapter().verify(&evidence, &future),
            Err(AdapterError::Stale { .. })
        ));
        let mut current = policy();
        current.now = EPOCH + 5;
        current.max_age = 10;
        assert!(adapter().verify(&evidence, &current).is_ok());
    }

    #[test]
    fn a_depth_requirement_the_adapter_cannot_meet_is_refused() {
        let evidence = envelope(vec![golden_vote()]);
        let mut deeper = policy();
        deeper.min_depth = 5;
        assert_eq!(
            adapter().verify(&evidence, &deeper),
            Err(AdapterError::InsufficientDepth {
                observed: 1,
                required: 5
            })
        );
    }

    #[test]
    fn a_providers_address_is_derived_from_its_announced_key() {
        let key = eots_public_key();
        let address = provider_address(&key.x_only);
        assert_eq!(address, provider_address(&eots_public_key().x_only));
        let other = EotsPublicKey { x_only: [0x22; 32] };
        assert_ne!(address, provider_address(&other.x_only));
    }
}
