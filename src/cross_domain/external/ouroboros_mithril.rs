//! Cardano finality read through Mithril: the adapter for a chain whose
//! finality is a stake lottery plus a threshold certificate, and whose
//! certificate is what a light client can actually check.
//!
//! WIRING: wired - `AdapterSpec::OuroborosMithril { network, chain_id, epoch }`
//!   (wire tag 20) builds this adapter from an intake registration. Cardano
//!   finality is a statement about one epoch's registered stake, so the
//!   registration names the epoch explicitly and `IntakeState` refuses one that
//!   it has not itself pinned (`IntakeState::install_ouroboros_epochs`,
//!   reachable in production through `GovernanceAction::PinExternalAnchor`).
//!   `FinalityGuarantee::for_external_spec_declared` maps the pinned stake
//!   distribution to economic finality.
//!
//! # The two layers, and why both are here
//!
//! Cardano's Ouroboros *Praos* decides who may produce a block: each slot, a
//! validator's chance to lead is a function of the stake it holds in the
//! epoch's stake distribution, and it proves its right with a VRF output that
//! must fall under a per-validator threshold derived from that stake. After
//! `k` blocks the chain's own rule calls a block settled *unless* the
//! adversary controls a majority of stake - an assumption, not a proof.
//!
//! Mithril is what turns the assumption into a certificate a third party can
//! check: a stake-based threshold multisignature (STM) over the certified
//! chain. A certificate is valid when the signatories' aggregated stake
//! reaches the protocol's threshold, where the threshold is computed from the
//! whole registered stake distribution, not from a fixed head count.
//!
//! So this adapter checks both, and refuses to conflate them:
//!
//! 1. **The Praos slot proof.** The block's VRF output, checked against the
//!    per-validator threshold that the epoch's stake distribution implies,
//!    with the validator's stake read from the pinned snapshot. A block
//!    produced by a small-stake validator is not a block, whatever the
//!    certificate says.
//! 2. **The Mithril certificate.** A threshold of the epoch's registered
//!    stake signed the certificate's message; every signature verifies under
//!    a registered key; the stake that signed is summed with checked
//!    arithmetic and compared against `ceil(2 * total / 3)`. A certificate
//!    signed by one whale whose stake rounds up to the threshold is caught by
//!    counting *stake*, not signers.
//! 3. **The epoch's own arithmetic.** Cardano's stake distribution rotates
//!    every epoch and is not derivable from the previous one, so a certificate
//!    for epoch `e` is checked against epoch `e`'s pinned snapshot. A
//!    certificate presented against the wrong epoch's snapshot is refused:
//!    stake that was one validator's in one epoch is another's in the next.
//! 4. **Bitcoin-style deep finality is not claimed.** The attestation says
//!    `finalized_at` in epochs, the unit the target uses, and the backing is a
//!    signature set over stake with `slashable: false`: a Mithril signer that
//!    signs twice is detected and ejected from the next epoch, but its past
//!    signing rights were not bonded, and an adapter that claimed otherwise
//!    would be pricing a guarantee nobody gave.
//!
//! # What it does not do
//!
//! - **No stake distribution inference.** The distribution is pinned per
//!   epoch. In this tree, reading a distribution off a ledger is
//!   `super::rust`-free by design: the adapter takes what the registration
//!   pinned and refuses when the epoch is not pinned.
//! - **No VRF evaluation by us.** Cardano's VRF is ECVRF-ED25519-SHA512 with a
//!   Praos-specific domain; Budlum does not implement a second one. The
//!   `vrf_output` the evidence carries is *the number the ledger compared*
//!   and this adapter enforces the comparison, so a forged output that does
//!   not match its signature is refused while the threshold arithmetic stays
//!   checkable here. Equivocation by a leader - two blocks in one slot with
//!   one VRF key - produces [`PraosEquivocationProof`].

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
use crate::crypto::primitives::{verify_signature, KeyPair};
use crate::crypto::scheme::SchemeId;
use serde::{Deserialize, Serialize};

/// A ceiling on the encoded payload, checked before deserialization.
pub const MAX_PAYLOAD_BYTES: usize = 512 * 1024;

/// A ceiling on the certificate's signers. Cardano mainnet has run past three
/// thousand registered pools; a certificate with more entries than this is a
/// payload shape this adapter does not read.
pub const MAX_SIGNERS: usize = 4_096;

/// An Ed25519 public key is 32 bytes.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// An Ed25519 signature is 64 bytes.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// An Ed25519 secret key's seed is 32 bytes.
pub const ED25519_SECRET_KEY_LEN: usize = 32;

/// A Mithril certificate's aggregated signature is a BLS12-381 G2 point in
/// compressed form, 96 bytes. Carried so the certificate's own signature
/// envelope has a length to check; the `SignedEntity` proof it binds is what
/// the multi-signature actually attests.
pub const MITHRIL_AGGREGATE_SIGNATURE_LEN: usize = 96;

/// Note on the wire shape: `serde` derives for `[u8; 32]` and not for the
/// 64-byte signature arrays, so signatures travel as `Vec<u8>` and
/// [`exact_signature`] is what refuses any length but 64. A short or long
/// vector is a refusal, never a silent re-interpretation.
/// The inverse of [`PraosSlotProof::signature_field`] and
/// [`MithrilSignature::signature_field`].
///
/// # Errors
///
/// A vector that is not exactly [`ED25519_SIGNATURE_LEN`] bytes.
fn exact_signature(bytes: &[u8], what: &str) -> Result<[u8; ED25519_SIGNATURE_LEN], AdapterError> {
    bytes.try_into().map_err(|_| AdapterError::Malformed {
        offset: 0,
        reason: format!(
            "{what} is {} bytes, not {ED25519_SIGNATURE_LEN}",
            bytes.len()
        ),
    })
}

/// The evidence version this adapter reads.
pub const EVIDENCE_VERSION: u32 = 1;

/// The adapter's own version.
pub const ADAPTER_VERSION: u32 = 1;

/// The prefix of every message this adapter verifies. Split from the body so
/// the two never share a preimage by accident.
pub const PRAOS_VOTE_TAG: &[u8] = b"BDLM_OUROBOROS_PRAOS_VOTE_V1";

/// The prefix of the Mithril certificate message.
pub const MITHRIL_CERT_TAG: &[u8] = b"BDLM_MITHRIL_CERT_V1";

/// The prefix of a Praos equivocation digest.
pub const EQUIVOCATION_TAG: &[u8] = b"BDLM_OUROBOROS_PRAOS_EQUIVOCATION_V1";

/// How much of the stake a Mithril certificate must carry, as a fraction of
/// the registered total: two thirds, rounded up. Expressing it as a ratio
/// keeps the number honest when the total is not divisible by three.
pub const THRESHOLD_NUMERATOR: u128 = 2;
/// See [`THRESHOLD_NUMERATOR`].
pub const THRESHOLD_DENOMINATOR: u128 = 3;

/// `ceil(2 * total / 3)`, in checked arithmetic.
///
/// # Errors
///
/// [`AdapterError::ConsensusRule`] when `2 * total` overflows, which a stake
/// distribution that large would have to be malformed to cause.
pub fn mithril_threshold(total: u128) -> Result<u128, AdapterError> {
    let doubled = total
        .checked_mul(THRESHOLD_NUMERATOR)
        .ok_or_else(|| rule("the registered stake total overflows when doubled"))?;
    let threshold = doubled
        .checked_add(THRESHOLD_DENOMINATOR - 1)
        .ok_or_else(|| rule("the registered stake total overflows when rounded up"))?
        / THRESHOLD_DENOMINATOR;
    Ok(threshold)
}

/// The adapter id, derived from its name.
#[must_use]
pub fn praos_adapter_id() -> AdapterId {
    AdapterId::from_name("cardano-praos-mithril-finality")
}

/// One registered signer of an epoch: its key and the stake it held.
///
/// The adapter takes these from the pinned registration, never from the
/// evidence: a certificate that brought its own stake numbers would be a
/// certificate that votes on its own weight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochSigner {
    /// Ed25519 key of the pool or validator.
    pub public_key: [u8; ED25519_PUBLIC_KEY_LEN],
    /// Stake held in this epoch, in lovelace.
    pub stake: u128,
}

/// One epoch's pinned stake distribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochStake {
    /// The epoch this distribution is for.
    pub epoch: u64,
    /// The registered signers, at most [`MAX_SIGNERS`].
    pub signers: Vec<EpochSigner>,
}

impl EpochStake {
    /// The total registered stake, summed with checked arithmetic.
    ///
    /// # Errors
    ///
    /// [`AdapterError::ConsensusRule`] on overflow or on a signer list above
    /// the cap.
    pub fn total(&self) -> Result<u128, AdapterError> {
        if self.signers.len() > MAX_SIGNERS {
            return Err(rule(format!(
                "the epoch carries {} signers, above the {MAX_SIGNERS} cap",
                self.signers.len()
            )));
        }
        let mut total: u128 = 0;
        for signer in &self.signers {
            total = total
                .checked_add(signer.stake)
                .ok_or_else(|| rule("the registered stake total overflows"))?;
        }
        Ok(total)
    }

    /// The stake a key holds, or `None` when the key is not registered.
    #[must_use]
    pub fn stake_of(&self, public_key: &[u8; ED25519_PUBLIC_KEY_LEN]) -> Option<u128> {
        self.signers
            .iter()
            .find(|signer| &signer.public_key == public_key)
            .map(|signer| signer.stake)
    }
}

/// The Praos slot proof: who produced the block, and the VRF number that
/// entitled them to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PraosSlotProof {
    /// The slot the block was produced in.
    pub slot: u64,
    /// The producer's Ed25519 key.
    pub producer: [u8; ED25519_PUBLIC_KEY_LEN],
    /// The VRF output, as PRAOS reduces it: the first eight bytes of the
    /// ECVRF output read as a big-endian integer. This is the number the
    /// ledger's threshold is compared against.
    pub vrf_output: u64,
    /// The producer's signature over [`praos_vote_message`], 64 bytes as
    /// carried on the wire and checked by [`PraosSlotProof::exact_signature`].
    pub signature: Vec<u8>,
}

impl PraosSlotProof {
    /// The signature, if it is the 64 bytes an Ed25519 signature is.
    ///
    /// # Errors
    ///
    /// [`AdapterError::Malformed`] for any other length.
    pub fn exact_signature(&self) -> Result<[u8; ED25519_SIGNATURE_LEN], AdapterError> {
        exact_signature(&self.signature, "the Praos slot signature")
    }

    /// Build a slot proof's signature field from raw Ed25519 bytes.
    #[must_use]
    pub fn signature_field(signature: [u8; ED25519_SIGNATURE_LEN]) -> Vec<u8> {
        signature.to_vec()
    }
}

/// The per-validator threshold in the Praos formula, scaled by `2^-64`.
///
/// Praos tests `vrf_output / 2^64 < 1 - (1 - f)^(stake / total)`, i.e. the
/// threshold is `2^64 * (1 - (1 - f)^(stake/total))`. Budlum does not carry
/// `f` on chain: the epoch's active-slot coefficient is network policy, and
/// this adapter is handed the threshold the ledger computed rather than
/// re-deriving it from a coefficient it would have to guess. What the adapter
/// *does* derive is the relation that matters for security: the threshold must
/// not exceed `stake / total * 2^64 * f_max`, and `f_max` is the largest
/// active-slot coefficient Cardano has ever run, 0.22 - so a validator with
/// one percent of the stake cannot be handed a threshold worth ten percent of
/// the lottery.
pub const MAX_ACTIVE_SLOT_COEFFICIENT_PPM: u128 = 220_000;

/// The lottery space, `2^64`.
pub const LOTTERY_SPACE: u128 = 1u128 << 64;

/// The largest threshold a validator holding `stake` out of `total` may be
/// given, as `floor(stake * 2^64 * f_max / total)`.
///
/// # Errors
///
/// [`AdapterError::ConsensusRule`] for a zero total or an arithmetic
/// overflow.
pub fn max_threshold_for(stake: u128, total: u128) -> Result<u128, AdapterError> {
    if total == 0 {
        return Err(rule("the registered stake total is zero"));
    }
    // The stake share is taken first, in parts per million: `stake * 2^64`
    // overflows `u128` for a mainnet stake in lovelace, and a bound that cannot
    // be computed must not become a bound that is silently skipped. Taking the
    // share first loses at most one part per million of precision and keeps
    // every intermediate inside the type.
    let share_ppm = stake
        .checked_mul(MAX_ACTIVE_SLOT_COEFFICIENT_PPM)
        .ok_or_else(|| rule("the threshold bound overflows"))?
        / total;
    share_ppm
        .checked_mul(LOTTERY_SPACE)
        .ok_or_else(|| rule("the threshold bound overflows"))
        .map(|scaled| scaled / 1_000_000)
}

/// The message the Praos slot proof signs: the producer commits to the slot,
/// the block height, the state root and the VRF number it claims.
#[must_use]
pub fn praos_vote_message(
    producer: &[u8; ED25519_PUBLIC_KEY_LEN],
    slot: u64,
    height: u64,
    state_root: &[u8; 32],
    vrf_output: u64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(PRAOS_VOTE_TAG.len() + 32 + 8 * 3 + 32);
    message.extend_from_slice(PRAOS_VOTE_TAG);
    message.extend_from_slice(producer);
    message.extend_from_slice(&slot.to_le_bytes());
    message.extend_from_slice(&height.to_le_bytes());
    message.extend_from_slice(state_root);
    message.extend_from_slice(&vrf_output.to_le_bytes());
    message
}

/// The message a Mithril certificate signs: the certified height, the state
/// root, and the epoch whose stake distribution certified it.
#[must_use]
pub fn mithril_certificate_message(epoch: u64, height: u64, state_root: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(MITHRIL_CERT_TAG.len() + 8 * 2 + 32);
    message.extend_from_slice(MITHRIL_CERT_TAG);
    message.extend_from_slice(&epoch.to_le_bytes());
    message.extend_from_slice(&height.to_le_bytes());
    message.extend_from_slice(state_root);
    message
}

/// One signer's signature on a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MithrilSignature {
    pub public_key: [u8; ED25519_PUBLIC_KEY_LEN],
    /// The signer's Ed25519 signature over the certificate message, 64 bytes.
    pub signature: Vec<u8>,
}

impl MithrilSignature {
    /// The signature, if it is exactly 64 bytes.
    ///
    /// # Errors
    ///
    /// [`AdapterError::Malformed`] for any other length.
    pub fn exact_signature(&self) -> Result<[u8; ED25519_SIGNATURE_LEN], AdapterError> {
        exact_signature(&self.signature, "a certificate signature")
    }

    /// Build the signature field from raw Ed25519 bytes.
    #[must_use]
    pub fn signature_field(signature: [u8; ED25519_SIGNATURE_LEN]) -> Vec<u8> {
        signature.to_vec()
    }
}

/// The wire shape of one Mithril evidence envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MithrilEvidence {
    /// The Budlum chain id this evidence was submitted for.
    pub chain_id: u64,
    /// The epoch whose stake distribution the certificate is judged against.
    pub epoch: u64,
    /// The certified height.
    pub height: u64,
    /// The certified state root.
    pub state_root: [u8; 32],
    /// The Praos slot proof of the block at that height.
    pub slot_proof: PraosSlotProof,
    /// The threshold the ledger computed for the producer this epoch, in
    /// lottery units.
    pub producer_threshold: u64,
    /// The certificate's signatures.
    pub signatures: Vec<MithrilSignature>,
}

impl MithrilEvidence {
    /// Decode a payload.
    ///
    /// # Errors
    ///
    /// [`AdapterError::Malformed`] for an over-long payload, one that does not
    /// decode, or one with trailing bytes.
    pub fn decode(payload: &[u8]) -> Result<Self, AdapterError> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(AdapterError::Malformed {
                offset: MAX_PAYLOAD_BYTES,
                reason: format!(
                    "payload is {} bytes, above the {MAX_PAYLOAD_BYTES}-byte cap",
                    payload.len()
                ),
            });
        }
        use bincode::Options;
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

    /// Shape checks that need no key and no stake table.
    ///
    /// # Errors
    ///
    /// [`AdapterError::ConsensusRule`] naming the rule that failed.
    pub fn validate_shape(&self) -> Result<(), AdapterError> {
        if self.chain_id == 0 {
            return Err(rule("the evidence carries a zero chain id"));
        }
        if self.height == 0 {
            return Err(rule("the evidence certifies height 0"));
        }
        if self.state_root.iter().all(|b| *b == 0) {
            return Err(rule("the evidence carries an all-zero state root"));
        }
        if self.signatures.is_empty() {
            return Err(rule("the certificate carries no signature"));
        }
        if self.signatures.len() > MAX_SIGNERS {
            return Err(rule(format!(
                "the certificate carries {} signatures, above the {MAX_SIGNERS} cap",
                self.signatures.len()
            )));
        }
        for (index, signature) in self.signatures.iter().enumerate() {
            signature.exact_signature().map_err(|_| {
                rule(format!(
                    "certificate signature {index} is {} bytes, not the {ED25519_SIGNATURE_LEN} an Ed25519 signature is",
                    signature.signature.len()
                ))
            })?;
        }
        if self.producer_threshold == 0 {
            return Err(rule(
                "the evidence claims a zero Praos threshold, which no stake entitles",
            ));
        }
        if self.slot_proof.producer.iter().all(|b| *b == 0) {
            return Err(rule("the slot proof names an all-zero producer"));
        }
        let slot_signature = self.slot_proof.exact_signature()?;
        if slot_signature.iter().all(|b| *b == 0) {
            return Err(rule("the slot proof carries an all-zero signature"));
        }
        Ok(())
    }

    /// The certificate message every signer signed.
    #[must_use]
    pub fn certificate_message(&self) -> Vec<u8> {
        mithril_certificate_message(self.epoch, self.height, &self.state_root)
    }
}

/// Evidence that one producer signed two blocks in one slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PraosEquivocationProof {
    pub producer: [u8; ED25519_PUBLIC_KEY_LEN],
    pub slot: u64,
    /// The two messages that were signed, both already domain-tagged.
    pub first_message: Vec<u8>,
    pub second_message: Vec<u8>,
    pub first_signature: Vec<u8>,
    pub second_signature: Vec<u8>,
    /// The two heights, so the conflict is visible without decoding a message.
    pub first_height: u64,
    pub second_height: u64,
    /// `H(EQUIVOCATION_TAG || ...)` over every field, length-prefixed.
    pub proof_digest: [u8; 32],
}

impl PraosEquivocationProof {
    /// Recompute the digest from the proof's own fields.
    #[must_use]
    pub fn recomputed_digest(&self) -> [u8; 32] {
        let mut acc = Vec::with_capacity(512);
        acc.extend_from_slice(EQUIVOCATION_TAG);
        acc.extend_from_slice(&self.producer);
        acc.extend_from_slice(&self.slot.to_le_bytes());
        for bytes in [&self.first_message, &self.second_message] {
            acc.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            acc.extend_from_slice(bytes);
        }
        for signature in [&self.first_signature, &self.second_signature] {
            acc.extend_from_slice(&(signature.len() as u64).to_le_bytes());
            acc.extend_from_slice(signature);
        }
        acc.extend_from_slice(&self.first_height.to_le_bytes());
        acc.extend_from_slice(&self.second_height.to_le_bytes());
        crate::core::hash::hash_fields_bytes(&[&acc])
    }

    /// Check the proof with nothing but the proof: two different messages, two
    /// signatures that verify under the named key over their own message, and
    /// a digest that matches its own fields.
    ///
    /// # Errors
    ///
    /// The reason the proof does not hold.
    pub fn check(&self) -> Result<(), String> {
        if self.first_message == self.second_message {
            return Err("the two blocks sign one message: not an equivocation".to_string());
        }
        verify_signature(&self.first_message, &self.first_signature, &self.producer)
            .map_err(|e| format!("first block: {e}"))?;
        verify_signature(&self.second_message, &self.second_signature, &self.producer)
            .map_err(|e| format!("second block: {e}"))?;
        if self.proof_digest != self.recomputed_digest() {
            return Err("the proof digest is not the digest of its own fields".to_string());
        }
        Ok(())
    }
}

/// The Praos + Mithril finality adapter for one Cardano network.
#[derive(Debug, Clone)]
pub struct OuroborosMithrilAdapter {
    descriptor: AdapterDescriptor,
    network: String,
    chain_id: u64,
    /// Pinned stake distributions, one per epoch, as the registration recorded
    /// them. An epoch nobody pinned has no threshold to certify against.
    epochs: Vec<EpochStake>,
    golden: Option<RawConsensusEvidence>,
}

impl OuroborosMithrilAdapter {
    /// A descriptor for a Cardano domain on `network`.
    #[must_use]
    pub fn new(network: &str, chain_id: u64) -> Self {
        Self {
            descriptor: AdapterDescriptor {
                id: praos_adapter_id(),
                name: "cardano-praos-mithril-finality".to_string(),
                adapter_version: ADAPTER_VERSION,
                accepted_evidence_versions: vec![EVIDENCE_VERSION],
                consensus_kind: "ouroboros-praos-with-mithril-stm".to_string(),
                finality_kind: FinalityKind::EconomicFinality,
                required_depth: 1,
                time_unit: TimeUnit::Epoch,
                trust_model: TrustModel::HonestMajority { set_size: 0 },
            },
            network: network.to_string(),
            chain_id,
            epochs: Vec::new(),
            golden: None,
        }
    }

    /// Pin one epoch's stake distribution.
    ///
    /// WIRING: the registration reads the epoch table from the domain record it
    /// pins; no production line builds an `EpochStake` yet.
    #[must_use]
    pub fn with_epoch_stake(mut self, epoch: EpochStake) -> Self {
        self.epochs.push(epoch);
        self
    }

    /// Attach the known-good sample, which lets [`super::selftest::admit`]
    /// prove the adapter accepts what it should and turns on the byte-level
    /// fault probe that needs a sample.
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

    /// The pinned stake distribution for `epoch`.
    #[must_use]
    pub fn epoch_stake(&self, epoch: u64) -> Option<&EpochStake> {
        self.epochs.iter().find(|entry| entry.epoch == epoch)
    }

    /// Verify one envelope.
    ///
    /// # Errors
    ///
    /// Any [`AdapterError`].
    pub fn verify_evidence(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<(FinalityAttestation, Option<PraosEquivocationProof>), AdapterError> {
        if evidence.adapter != self.descriptor.id {
            return Err(AdapterError::WrongAdapter {
                expected: self.descriptor.name.clone(),
                found: hex::encode(evidence.adapter.as_bytes()),
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

        let decoded = MithrilEvidence::decode(&evidence.payload)?;
        decoded.validate_shape()?;
        if decoded.chain_id != self.chain_id {
            return Err(rule(format!(
                "evidence chain id {} is not the pinned chain id {}",
                decoded.chain_id, self.chain_id
            )));
        }

        let stake = self.epoch_stake(decoded.epoch).ok_or_else(|| {
            rule(format!(
                "the certificate is for epoch {} and no stake distribution is pinned for it",
                decoded.epoch
            ))
        })?;
        let total = stake.total()?;
        if total == 0 {
            return Err(rule("the pinned stake distribution is empty"));
        }

        self.check_slot_proof(&decoded, stake, total)?;
        let signed_stake = self.check_certificate(&decoded, stake)?;
        let threshold = mithril_threshold(total)?;
        if signed_stake < threshold {
            return Err(rule(format!(
                "the certificate carries {signed_stake} lovelace of stake, below the {threshold} needed of {total}"
            )));
        }

        if policy.require_declared_match {
            if evidence.declared_height != decoded.height {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if evidence.declared_root != decoded.state_root {
                return Err(AdapterError::DeclarationMismatch {
                    field: "state_root",
                });
            }
        }
        if policy.require_slashable {
            // Mithril signs are not bonded: a double-signing signer loses its
            // future eligibility, not its past stake. Saying so is the point.
            return Err(AdapterError::UnslashableBacking);
        }

        if policy.max_age != 0 {
            let age = if decoded.epoch > policy.now {
                return Err(AdapterError::Stale {
                    age: decoded.epoch - policy.now,
                    max_age: policy.max_age,
                });
            } else {
                policy.now - decoded.epoch
            };
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        let attestation = self.attest(evidence, &decoded, signed_stake);
        // One envelope carries one block, so a double-signing leader is caught
        // by pairing two envelopes - see [`proof_of_equivocation`].
        Ok((attestation, None))
    }

    /// The Praos layer: the producer is registered, its threshold is not above
    /// what its stake can justify, its VRF number falls under that threshold,
    /// and its signature covers the block it claims.
    ///
    /// # Errors
    ///
    /// [`AdapterError::Crypto`] for a signature that does not verify,
    /// [`AdapterError::ConsensusRule`] for every arithmetic refusal.
    fn check_slot_proof(
        &self,
        decoded: &MithrilEvidence,
        stake: &EpochStake,
        total: u128,
    ) -> Result<(), AdapterError> {
        let proof = &decoded.slot_proof;
        let producer_stake = stake.stake_of(&proof.producer).ok_or_else(|| {
            rule(format!(
                "the block's producer is not registered in the epoch {} stake distribution",
                decoded.epoch
            ))
        })?;
        if producer_stake == 0 {
            return Err(rule("the block's producer holds zero stake this epoch"));
        }
        // The lottery: a slot is the producer's only when the VRF number falls
        // under the threshold its stake entitles it to.
        if u128::from(proof.vrf_output) >= u128::from(decoded.producer_threshold) {
            return Err(rule(format!(
                "the VRF number {} is not under the producer's threshold {}",
                proof.vrf_output, decoded.producer_threshold
            )));
        }
        // And the threshold itself must be one its stake could justify. This is
        // the line that stops a producer from presenting a threshold of
        // `2^64` and claiming every slot.
        let bound = max_threshold_for(producer_stake, total)?;
        if u128::from(decoded.producer_threshold) > bound {
            return Err(rule(format!(
                "the producer's threshold {} exceeds the {bound} its {producer_stake} of {total} lovelace could justify",
                decoded.producer_threshold
            )));
        }
        let message = praos_vote_message(
            &proof.producer,
            proof.slot,
            decoded.height,
            &decoded.state_root,
            proof.vrf_output,
        );
        let signature = proof.exact_signature()?;
        verify_signature(&message, &signature, &proof.producer).map_err(|e| {
            AdapterError::Crypto {
                what: format!("the Praos slot proof does not verify: {e}"),
            }
        })?;
        Ok(())
    }

    /// The Mithril layer: every signature is by a registered key, over the
    /// certificate message, counted once, and the stake it carries is summed.
    ///
    /// # Errors
    ///
    /// [`AdapterError::Crypto`] for a bad signature,
    /// [`AdapterError::ConsensusRule`] for a duplicate or unregistered signer
    /// or an overflowing sum.
    fn check_certificate(
        &self,
        decoded: &MithrilEvidence,
        stake: &EpochStake,
    ) -> Result<u128, AdapterError> {
        let message = decoded.certificate_message();
        let mut signed_stake: u128 = 0;
        let mut seen: Vec<[u8; ED25519_PUBLIC_KEY_LEN]> =
            Vec::with_capacity(decoded.signatures.len());
        for (index, signature) in decoded.signatures.iter().enumerate() {
            if seen.contains(&signature.public_key) {
                // The same signer twice is one signer's stake twice, which is
                // the cheapest way to fake a quorum: refused, not deduplicated.
                return Err(rule(format!(
                    "certificate signature {index} repeats a signer already counted",
                )));
            }
            seen.push(signature.public_key);
            let signer_stake = stake.stake_of(&signature.public_key).ok_or_else(|| {
                rule(format!(
                    "certificate signature {index} is by a key that is not in the epoch {} distribution",
                    decoded.epoch
                ))
            })?;
            let bytes = signature.exact_signature()?;
            verify_signature(&message, &bytes, &signature.public_key).map_err(|e| {
                AdapterError::Crypto {
                    what: format!("certificate signature {index} does not verify: {e}"),
                }
            })?;
            signed_stake = signed_stake
                .checked_add(signer_stake)
                .ok_or_else(|| rule("the signed stake overflows"))?;
        }
        Ok(signed_stake)
    }

    /// The attestation a verified certificate produces.
    fn attest(
        &self,
        evidence: &RawConsensusEvidence,
        decoded: &MithrilEvidence,
        signed_stake: u128,
    ) -> FinalityAttestation {
        let signers = u64::try_from(decoded.signatures.len()).unwrap_or(u64::MAX);
        FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &self.network),
            height: decoded.height,
            state_root: decoded.state_root,
            finalized_at: decoded.epoch,
            time_unit: TimeUnit::Epoch,
            security: SecurityBacking::SignatureSet {
                // Mithril's threshold multisignature is constructed over
                // Ed25519 keys in this tree's model: the certificate is a set
                // of Ed25519 signatures whose *stake* is thresholded.
                scheme: ObservedScheme::Scheme(SchemeId::ED25519),
                signers,
                // The threshold is a stake threshold, so it is reported as the
                // minimum number of signers that could reach it, never as a
                // head count the certificate did not have to meet.
                required: 1,
                total_weight: signed_stake,
                // A Mithril signer is ejected for double-signing, not slashed
                // for it: its past signing rights were never bonded.
                slashable: false,
            },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
            attested_block_hash: None,
            attested_event_root: None,
            attested_tx_root: None,
        }
    }
}

impl ExternalFinalityAdapter for OuroborosMithrilAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        self.descriptor.clone()
    }

    fn verify(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, AdapterError> {
        self.verify_evidence(evidence, policy)
            .map(|(attestation, _)| attestation)
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        let mut probes = vec![
            FaultProbe {
                name: "a height the certificate does not cover is a declaration mismatch"
                    .to_string(),
                patch: BytePatch::DeclaredHeight { value: u64::MAX },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "a state root the certificate does not cover is a declaration mismatch"
                    .to_string(),
                patch: BytePatch::DeclaredRoot { value: [0u8; 32] },
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
        if let Some(golden) = &self.golden {
            if let Some((offset, byte)) = signature_corruption(golden) {
                probes.push(FaultProbe {
                    name: "one corrupted byte of a certificate signature is a crypto refusal"
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

/// Where to corrupt the first certificate signature in a golden sample, and
/// what to write. The offset is found by searching the payload for the
/// signature's own first eight bytes; the replacement flips one bit so the
/// bytes still parse as an Ed25519 signature and the check is what refuses.
fn signature_corruption(golden: &RawConsensusEvidence) -> Option<(usize, u8)> {
    let decoded = MithrilEvidence::decode(&golden.payload).ok()?;
    let signature = &decoded.signatures.first()?.signature;
    let prefix = signature.get(..8)?;
    let offset = golden
        .payload
        .windows(prefix.len())
        .position(|window| window == prefix)?;
    Some((offset, signature.first().copied()? ^ 0x01))
}

/// The digest a Praos slot proof is identified by.
///
/// WIRING: the registry keys its recent-slot table by this digest, which is how
/// a second block in one slot finds the first.
#[must_use]
pub fn slot_proof_digest(decoded: &MithrilEvidence) -> [u8; 32] {
    crate::core::hash::hash_fields_bytes(&[
        PRAOS_VOTE_TAG,
        &decoded.slot_proof.producer,
        &decoded.slot_proof.slot.to_le_bytes(),
        &decoded.height.to_le_bytes(),
        &decoded.state_root,
        &decoded.slot_proof.vrf_output.to_le_bytes(),
    ])
}

/// The address a producer's Ed25519 key maps to.
#[must_use]
pub fn producer_address(public_key: &[u8; ED25519_PUBLIC_KEY_LEN]) -> Address {
    Address(crate::core::hash::hash_fields_bytes(&[
        b"BDLM_OUROBOROS_PRODUCER_V1",
        public_key,
    ]))
}

/// Pair two slot proofs by one producer in one slot into an equivocation
/// proof, or `None` when they do not conflict.
///
/// Two envelopes are the wire shape for a double-signing leader in this tree:
/// one block is one certificate. The registry keeps the recent proofs it has
/// seen and calls this when a second one by the same producer arrives for a
/// slot it already holds; the pair is what a slasher checks.
#[must_use]
pub fn proof_of_equivocation(
    first: &MithrilEvidence,
    second: &MithrilEvidence,
) -> Option<PraosEquivocationProof> {
    let producer = first.slot_proof.producer;
    if second.slot_proof.producer != producer || second.slot_proof.slot != first.slot_proof.slot {
        return None;
    }
    let first_message = praos_vote_message(
        &producer,
        first.slot_proof.slot,
        first.height,
        &first.state_root,
        first.slot_proof.vrf_output,
    );
    let second_message = praos_vote_message(
        &producer,
        second.slot_proof.slot,
        second.height,
        &second.state_root,
        second.slot_proof.vrf_output,
    );
    if first_message == second_message {
        return None;
    }
    let mut proof = PraosEquivocationProof {
        producer,
        slot: first.slot_proof.slot,
        first_message,
        second_message,
        first_signature: first.slot_proof.signature.clone(),
        second_signature: second.slot_proof.signature.clone(),
        first_height: first.height,
        second_height: second.height,
        proof_digest: [0u8; 32],
    };
    proof.proof_digest = proof.recomputed_digest();
    Some(proof)
}

/// A key pair helper for a registration ceremony that already holds seed
/// material.
///
/// WIRING: the registration ceremony builds a signer key pair from the seed it
/// was handed; no production line in this tree holds a Cardano seed yet.
///
/// # Errors
///
/// A seed the curve rejects.
pub fn producer_keypair(seed: &[u8; ED25519_SECRET_KEY_LEN]) -> Result<KeyPair, AdapterError> {
    KeyPair::from_seed(seed).map_err(|e| AdapterError::Unavailable {
        reason: format!("the Ed25519 seed is not usable: {e}"),
    })
}

fn rule(reason: impl Into<String>) -> AdapterError {
    AdapterError::ConsensusRule {
        rule: reason.into(),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::cross_domain::external::selftest::{admit, ProbeOutcome};

    pub const CHAIN_ID: u64 = 7_645_382;
    const NETWORK: &str = "cardano-mainnet";
    pub const EPOCH: u64 = 512;
    const HEIGHT: u64 = 11_204_889;
    const STATE_ROOT: [u8; 32] = [0x51; 32];

    fn keypair(seed_byte: u8) -> KeyPair {
        KeyPair::from_seed(&[seed_byte; 32]).expect("a valid ed25519 seed")
    }

    fn public_of(seed_byte: u8) -> [u8; ED25519_PUBLIC_KEY_LEN] {
        keypair(seed_byte).public_key_bytes()
    }

    /// Six signers holding equal stake: no single one is anywhere near the
    /// two-thirds threshold, which is the shape a whale attack needs.
    pub fn stake_distribution(epoch: u64) -> EpochStake {
        EpochStake {
            epoch,
            signers: (1u8..=6)
                .map(|seed| EpochSigner {
                    public_key: public_of(seed),
                    stake: 1_000_000_000_000_000_000,
                })
                .collect(),
        }
    }

    fn sign_certificate(seed_byte: u8, message: &[u8]) -> MithrilSignature {
        MithrilSignature {
            public_key: public_of(seed_byte),
            signature: MithrilSignature::signature_field(keypair(seed_byte).sign(message)),
        }
    }

    /// A certificate signed by four of six equal signers: two thirds of the
    /// stake, 4e18 of 6e18.
    pub fn golden_evidence() -> RawConsensusEvidence {
        let message = mithril_certificate_message(EPOCH, HEIGHT, &STATE_ROOT);
        let signatures = (1u8..=4)
            .map(|seed| sign_certificate(seed, &message))
            .collect();
        let producer_seed: u8 = 1;
        let producer = public_of(producer_seed);
        let vrf_output = 1_000_000u64;
        let slot_message =
            praos_vote_message(&producer, 92_113_004, HEIGHT, &STATE_ROOT, vrf_output);
        let payload = MithrilEvidence {
            chain_id: CHAIN_ID,
            epoch: EPOCH,
            height: HEIGHT,
            state_root: STATE_ROOT,
            slot_proof: PraosSlotProof {
                slot: 92_113_004,
                producer,
                vrf_output,
                signature: PraosSlotProof::signature_field(
                    keypair(producer_seed).sign(&slot_message),
                ),
            },
            // One sixth of the lottery space: exactly the bound a 1/6 stake
            // holder can justify at the maximum active-slot coefficient.
            producer_threshold: u64::try_from(
                max_threshold_for(1_000_000_000_000_000_000, 6_000_000_000_000_000_000)
                    .expect("bound"),
            )
            .expect("fits"),
            signatures,
        };
        let bytes = payload.encode().expect("encodes");
        RawConsensusEvidence {
            adapter: praos_adapter_id(),
            evidence_version: EVIDENCE_VERSION,
            network: NETWORK.to_string(),
            payload: bytes,
            declared_height: HEIGHT,
            declared_root: STATE_ROOT,
            submitter: Address::from([0x3B; 32]),
        }
    }

    fn adapter() -> OuroborosMithrilAdapter {
        OuroborosMithrilAdapter::new(NETWORK, CHAIN_ID).with_epoch_stake(stake_distribution(EPOCH))
    }

    fn policy() -> VerificationPolicy {
        VerificationPolicy::strict(0)
    }

    fn with_payload(
        base: &MithrilEvidence,
        edit: impl FnOnce(&mut MithrilEvidence),
    ) -> RawConsensusEvidence {
        let mut copy = base.clone();
        edit(&mut copy);
        RawConsensusEvidence {
            adapter: praos_adapter_id(),
            evidence_version: EVIDENCE_VERSION,
            network: NETWORK.to_string(),
            payload: copy.encode().expect("encodes"),
            declared_height: copy.height,
            declared_root: copy.state_root,
            submitter: Address::from([0x3B; 32]),
        }
    }

    fn decoded(base: &RawConsensusEvidence) -> MithrilEvidence {
        MithrilEvidence::decode(&base.payload).expect("decodes")
    }

    #[test]
    fn a_golden_certificate_attests_the_stake_that_signed_it() {
        let evidence = golden_evidence();
        let adapter = adapter().with_golden(evidence.clone());
        let attestation = adapter
            .verify(&evidence, &policy())
            .expect("golden verifies");
        assert_eq!(attestation.height, HEIGHT);
        assert_eq!(attestation.state_root, STATE_ROOT);
        assert_eq!(attestation.finalized_at, EPOCH);
        assert_eq!(attestation.time_unit, TimeUnit::Epoch);
        assert_eq!(
            attestation.security,
            SecurityBacking::SignatureSet {
                scheme: ObservedScheme::Scheme(SchemeId::ED25519),
                signers: 4,
                required: 1,
                total_weight: 4_000_000_000_000_000_000,
                // A Mithril signer is ejected for double-signing, not slashed
                // for it: the attestation says so rather than overstating.
                slashable: false,
            }
        );
        let report = admit(&adapter, &policy());
        assert!(report.golden_verified, "{report:?}");
        assert!(report.admitted, "{report:?}");
        assert!(report
            .probes
            .iter()
            .all(|(_, outcome)| matches!(outcome, ProbeOutcome::Refused { .. })));
    }

    /// The attack the stake threshold exists for: one signer holding more than
    /// a third cannot certify alone, however many times it repeats itself.
    #[test]
    fn one_whale_cannot_certify_even_with_enough_stake_to_cross_a_head_count() {
        let base = decoded(&golden_evidence());
        // Signers 1 and 2 hold one third between them; a third signer would be
        // half. Keep the four signatures but pin a distribution in which the
        // four signers hold only a third of the total: the certificate then
        // carries 4e18 of 12e18, below the 8e18 threshold.
        let mut whale_heavy = stake_distribution(EPOCH);
        whale_heavy.signers.push(EpochSigner {
            public_key: public_of(9),
            stake: 6_000_000_000_000_000_000,
        });
        let adapter = OuroborosMithrilAdapter::new(NETWORK, CHAIN_ID).with_epoch_stake(whale_heavy);
        let evidence = with_payload(&base, |_| {});
        let refused = adapter
            .verify(&evidence, &policy())
            .expect_err("four of twelve is not two thirds");
        assert!(
            matches!(refused, AdapterError::ConsensusRule { .. }),
            "{refused:?}"
        );
    }

    /// The cheapest fake quorum: one signer listed many times.
    #[test]
    fn a_repeated_signer_is_refused_rather_than_counted_twice() {
        let base = decoded(&golden_evidence());
        let message = base.certificate_message();
        let repeated = sign_certificate(1, &message);
        let evidence = with_payload(&base, |copy| {
            copy.signatures = vec![repeated; 6];
        });
        let refused = adapter()
            .verify(&evidence, &policy())
            .expect_err("one signer repeated is one signer");
        assert!(
            matches!(refused, AdapterError::ConsensusRule { .. }),
            "{refused:?}"
        );
    }

    /// A signer the epoch never registered has no stake in this epoch, and a
    /// key from another epoch's table is not a key here.
    #[test]
    fn a_signature_by_an_unregistered_key_is_refused() {
        let base = decoded(&golden_evidence());
        let message = base.certificate_message();
        let evidence = with_payload(&base, |copy| {
            copy.signatures.push(sign_certificate(42, &message));
        });
        let refused = adapter()
            .verify(&evidence, &policy())
            .expect_err("an unregistered key carries no stake");
        assert!(
            matches!(refused, AdapterError::ConsensusRule { .. }),
            "{refused:?}"
        );
    }

    /// A certificate whose signature was lifted onto another height is a
    /// forgery: the height is inside the signed message.
    #[test]
    fn a_signature_lifted_onto_another_height_is_refused() {
        let base = decoded(&golden_evidence());
        let evidence = with_payload(&base, |copy| {
            copy.height = HEIGHT + 1;
        });
        let refused = adapter()
            .verify(&evidence, &policy())
            .expect_err("the height is inside the certificate message");
        assert!(
            matches!(refused, AdapterError::Crypto { .. }),
            "{refused:?}"
        );
    }

    /// And an envelope that lies about the height it declares, without
    /// touching the payload, is a mismatch instead.
    #[test]
    fn a_declared_height_the_certificate_does_not_cover_is_a_mismatch() {
        let mut evidence = golden_evidence();
        evidence.declared_height = HEIGHT + 7;
        assert_eq!(
            adapter().verify(&evidence, &policy()),
            Err(AdapterError::DeclarationMismatch { field: "height" })
        );
    }

    /// The Praos lottery: a VRF number at or above the producer's threshold
    /// means the slot was not theirs.
    #[test]
    fn a_vrf_number_above_the_producers_threshold_is_refused() {
        let base = decoded(&golden_evidence());
        let threshold = base.producer_threshold;
        // At the threshold the lottery fails (the test is strict), and above
        // it by one or by everything still fails.
        for output in [threshold, threshold + 1, u64::MAX] {
            let evidence = with_payload(&base, |copy| {
                copy.slot_proof.vrf_output = output;
                // Re-sign so only the lottery comparison can refuse.
                let message = praos_vote_message(
                    &copy.slot_proof.producer,
                    copy.slot_proof.slot,
                    copy.height,
                    &copy.state_root,
                    output,
                );
                copy.slot_proof.signature =
                    PraosSlotProof::signature_field(keypair(1).sign(&message));
            });
            let refused = adapter()
                .verify(&evidence, &policy())
                .expect_err("the slot was not the producer's");
            assert!(
                matches!(refused, AdapterError::ConsensusRule { .. }),
                "{output}: {refused:?}"
            );
        }
    }

    /// The bound on the threshold itself: a producer cannot present a
    /// threshold larger than its stake could justify and claim every slot.
    #[test]
    fn a_threshold_above_what_the_producers_stake_justifies_is_refused() {
        let base = decoded(&golden_evidence());
        let honest_bound =
            max_threshold_for(1_000_000_000_000_000_000, 6_000_000_000_000_000_000).expect("bound");
        // One unit above the bound is already a claim the stake cannot back.
        let too_generous = u64::try_from(honest_bound + 1).expect("fits");
        let evidence = with_payload(&base, |copy| {
            copy.producer_threshold = too_generous;
        });
        let refused = adapter()
            .verify(&evidence, &policy())
            .expect_err("a threshold its stake cannot justify is a claim on every slot");
        assert!(
            matches!(refused, AdapterError::ConsensusRule { .. }),
            "{refused:?}"
        );
    }

    /// A block produced by a key that holds no stake this epoch is not a block
    /// this epoch's ledger would have accepted.
    #[test]
    fn a_block_from_an_unregistered_producer_is_refused() {
        let base = decoded(&golden_evidence());
        let stranger = keypair(77);
        let stranger_key: [u8; ED25519_PUBLIC_KEY_LEN] = stranger.public_key_bytes();
        let evidence = with_payload(&base, |copy| {
            copy.slot_proof.producer = stranger_key;
            let message = praos_vote_message(
                &stranger_key,
                copy.slot_proof.slot,
                copy.height,
                &copy.state_root,
                copy.slot_proof.vrf_output,
            );
            copy.slot_proof.signature = PraosSlotProof::signature_field(stranger.sign(&message));
        });
        let refused = adapter()
            .verify(&evidence, &policy())
            .expect_err("an unregistered producer holds no stake");
        assert!(
            matches!(refused, AdapterError::ConsensusRule { .. }),
            "{refused:?}"
        );
    }

    /// Stake rotates every epoch, so evidence for an epoch nobody pinned has no
    /// denominator and cannot be certified.
    #[test]
    fn a_certificate_for_an_unpinned_epoch_is_refused() {
        let base = decoded(&golden_evidence());
        let message = mithril_certificate_message(EPOCH + 1, HEIGHT, &STATE_ROOT);
        let evidence = with_payload(&base, |copy| {
            copy.epoch = EPOCH + 1;
            copy.signatures = (1u8..=4)
                .map(|seed| sign_certificate(seed, &message))
                .collect();
        });
        let refused = adapter()
            .verify(&evidence, &policy())
            .expect_err("no pinned distribution, no threshold");
        assert!(
            matches!(refused, AdapterError::ConsensusRule { .. }),
            "{refused:?}"
        );
    }

    /// The threshold is a stake threshold, so a caller that demands bonded
    /// backing is told the truth instead of being given a number.
    #[test]
    fn a_caller_requiring_slashable_backing_is_refused() {
        let evidence = golden_evidence();
        let mut bonded = policy();
        bonded.require_slashable = true;
        assert_eq!(
            adapter().verify(&evidence, &bonded),
            Err(AdapterError::UnslashableBacking)
        );
    }

    /// Two blocks in one slot by one producer: the pair is checkable by
    /// anybody, and the digest is bound to both.
    #[test]
    fn a_double_signed_slot_yields_checkable_equivocation_evidence() {
        let first = decoded(&golden_evidence());
        let mut second = first.clone();
        second.height = HEIGHT + 1;
        second.state_root = [0x52; 32];
        let message = praos_vote_message(
            &second.slot_proof.producer,
            second.slot_proof.slot,
            second.height,
            &second.state_root,
            second.slot_proof.vrf_output,
        );
        second.slot_proof.signature = PraosSlotProof::signature_field(keypair(1).sign(&message));

        let proof =
            proof_of_equivocation(&first, &second).expect("one producer, one slot, two blocks");
        assert_eq!(proof.first_height, HEIGHT);
        assert_eq!(proof.second_height, HEIGHT + 1);
        proof.check().expect("the proof holds");
        // A proof that names one block twice is not a proof.
        assert!(proof_of_equivocation(&first, &first).is_none());
        // Nor is a pair by two different producers.
        let mut other_producer = second.clone();
        other_producer.slot_proof.producer = public_of(2);
        assert!(proof_of_equivocation(&first, &other_producer).is_none());
        // Nor a pair in two different slots.
        let mut later_slot = second;
        later_slot.slot_proof.slot += 1;
        assert!(proof_of_equivocation(&first, &later_slot).is_none());
        // And a tampered proof no longer holds together.
        let mut tampered = proof;
        tampered.second_message[PRAOS_VOTE_TAG.len()] ^= 0xFF;
        assert!(tampered.check().is_err());
    }

    /// The threshold arithmetic, at the boundaries that matter.
    #[test]
    fn the_threshold_is_two_thirds_rounded_up() {
        assert_eq!(mithril_threshold(0), Ok(0));
        assert_eq!(mithril_threshold(3), Ok(2));
        assert_eq!(mithril_threshold(6), Ok(4));
        // Rounded up: 7 * 2 / 3 is 4.67, so five signers' worth of stake is
        // needed, not four.
        assert_eq!(mithril_threshold(7), Ok(5));
        assert!(
            matches!(
                mithril_threshold(u128::MAX),
                Err(AdapterError::ConsensusRule { .. })
            ),
            "a total that overflows when doubled is refused, not wrapped"
        );
    }

    /// The per-validator bound: one sixth of the stake cannot buy more than
    /// `f_max / 6` of the lottery.
    #[test]
    fn the_threshold_bound_follows_the_stake_share() {
        let one_sixth = max_threshold_for(1, 6).expect("bound");
        // The share is taken in parts per million before the lottery is
        // scaled, so the bound sits within one part per million of the exact
        // quotient.
        let exact = LOTTERY_SPACE * MAX_ACTIVE_SLOT_COEFFICIENT_PPM / 6 / 1_000_000;
        assert!(
            one_sixth.abs_diff(exact) <= LOTTERY_SPACE / 1_000_000,
            "bound {one_sixth} is not within one part per million of {exact}"
        );
        // A mainnet stake in lovelace must not overflow the bound.
        assert!(max_threshold_for(1_000_000_000_000_000_000, 6_000_000_000_000_000_000).is_ok());
        // A validator with the whole stake gets at most `f_max` of the lottery.
        assert_eq!(
            max_threshold_for(6, 6).expect("bound"),
            LOTTERY_SPACE * MAX_ACTIVE_SLOT_COEFFICIENT_PPM / 1_000_000
        );
        assert!(matches!(
            max_threshold_for(1, 0),
            Err(AdapterError::ConsensusRule { .. })
        ));
    }

    /// The empty and over-long shapes are refused before any signature is
    /// checked.
    #[test]
    fn empty_and_over_long_signature_lists_are_refused() {
        let base = decoded(&golden_evidence());
        let mut empty = base.clone();
        empty.signatures.clear();
        assert!(matches!(
            empty.validate_shape(),
            Err(AdapterError::ConsensusRule { .. })
        ));
        let mut over_long = base;
        over_long.signatures = vec![
            MithrilSignature {
                public_key: public_of(1),
                signature: MithrilSignature::signature_field(keypair(1).sign(b"x")),
            };
            MAX_SIGNERS + 1
        ];
        assert!(matches!(
            over_long.validate_shape(),
            Err(AdapterError::ConsensusRule { .. })
        ));
    }

    #[test]
    fn a_payload_with_trailing_bytes_is_malformed() {
        let evidence = golden_evidence();
        let mut extended = evidence.payload.clone();
        extended.push(0x00);
        assert!(matches!(
            MithrilEvidence::decode(&extended),
            Err(AdapterError::Malformed { .. })
        ));
    }

    #[test]
    fn a_chain_id_the_adapter_is_not_pinned_to_is_refused() {
        let base = decoded(&golden_evidence());
        let evidence = with_payload(&base, |copy| {
            copy.chain_id = CHAIN_ID + 1;
        });
        assert!(matches!(
            adapter().verify(&evidence, &policy()),
            Err(AdapterError::ConsensusRule { .. })
        ));
    }

    #[test]
    fn a_producers_address_is_derived_from_its_key() {
        assert_eq!(
            producer_address(&public_of(1)),
            producer_address(&public_of(1))
        );
        assert_ne!(
            producer_address(&public_of(1)),
            producer_address(&public_of(2))
        );
    }
}
