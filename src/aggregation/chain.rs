//! The doors between the chain and the aggregation layer.
//!
//! The rest of the module knows claims, frames and digests. This file knows
//! a [`Transaction`] and a [`Block`]: which claim an account asks for, how a
//! signed transaction turns into a claimed one and its object, what the
//! claims of a block must look like and who pays for them.
//!
//! [`ChainBackend`] is the backend of a chain: the aggregator of a node
//! proves with it and block validation verifies with it. [`claim_signature`]
//! is where a signed transaction enters the layer: the node splits it into
//! the object for `agg/object` and the transaction the claim stands for.
//!
//! Phase 1 claims ML-DSA-87 signatures of V5 transactions only. The
//! composite formats (V7, V8) and the V6 multi-signature keep their inline
//! witness until their schemes are in the scheme table of this layer.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::backend::{AggBackend, AggError, TickCtx};
use super::block::{check_block_claims, claim_payers, TxClaims};
use super::claim::Claim;
use super::envelope::{Envelope, ObjectKind};
use super::fees::{settle, ClaimSettlement};
use super::frame::{ClaimFrame, FrameLimits};
use super::hash::h;
use super::params::{AggMode, AggParams};
use super::pool::PoolItem;
use crate::core::block::Block;
use crate::core::chain_config::Network;
use crate::core::transaction::{Transaction, SIGNATURE_VERSION_V5};
use crate::crypto::scheme::{SchemeId, SchemeStatusRegistry};
use crate::domain::types::{DomainId, Hash32};

/// The largest frame the wire and the block store decode. The consensus
/// limits of a chain sit at or below these and are checked by the block
/// rules; this ceiling only bounds what a decoder allocates before the
/// rules run.
const WIRE_FRAME_LIMITS: FrameLimits = FrameLimits {
    max_claims: 65_536,
    max_proof_bytes: crate::network::protocol::MAX_MESSAGE_SIZE,
};

/// The largest proof a chain may allow in a block: a third of the block
/// size limit of consensus.
const MAX_BLOCK_PROOF_BYTES: usize = crate::consensus::MAX_BLOCK_SIZE / 3;

/// The parameter set of the native devnet/test backend of a chain. A proof
/// made under another value is refused.
#[cfg(any(test, feature = "agg-native-backend"))]
const NATIVE_PARAMETER_SET: u32 = 1;

/// The parameter set active in this build (devnet/test native id 1, production
/// STARK id 2).
#[cfg(any(test, feature = "agg-native-backend"))]
const ACTIVE_PARAMETER_SET: u32 = NATIVE_PARAMETER_SET;
#[cfg(not(any(test, feature = "agg-native-backend")))]
const ACTIVE_PARAMETER_SET: u32 = super::stark::STARK_PARAMETER_SET;

/// Tag of the commitment to the consensus parameters of the layer.
const TAG_AGG_PARAMS: &[u8] = b"BDLM_AGG_PARAMS_V1";

/// Decode the claim frame of a block from the wire. Empty bytes are a block
/// without a frame.
///
/// # Errors
///
/// A message naming why the bytes are not a frame.
pub fn decode_wire_frame(bytes: &[u8]) -> Result<Option<ClaimFrame>, String> {
    if bytes.is_empty() {
        return Ok(None);
    }
    ClaimFrame::decode(bytes, &WIRE_FRAME_LIMITS)
        .map(Some)
        .map_err(|e| format!("Invalid block claim_frame: {e}"))
}

/// The bytes a frame takes in the JSON form of a block, which is what the
/// block size limit of consensus counts: the hex of its canonical encoding
/// and the quotes around it.
#[must_use]
pub fn frame_block_bytes(frame: &ClaimFrame) -> usize {
    frame.encode().len().saturating_mul(2).saturating_add(2)
}

/// The largest object payload the wire decodes: the largest object of any
/// kind under the default parameters. The admission rules of the pool apply
/// the limit of the kind and the scheme afterwards.
pub const WIRE_OBJECT_BYTES: usize = 262_144;

/// Decode a frame that arrived on `agg/frame`.
///
/// # Errors
///
/// A message naming why the bytes are not a frame.
pub fn decode_gossip_frame(bytes: &[u8]) -> Result<ClaimFrame, String> {
    ClaimFrame::decode(bytes, &WIRE_FRAME_LIMITS).map_err(|e| format!("Invalid claim frame: {e}"))
}

/// Decode the envelope of an object that arrived on `agg/object`.
///
/// # Errors
///
/// A message naming why the bytes are not an envelope.
pub fn decode_gossip_object(bytes: &[u8]) -> Result<Envelope, String> {
    Envelope::decode(bytes, WIRE_OBJECT_BYTES).map_err(|e| e.to_string())
}

/// A frame is stored and sent as its canonical bytes: one encoding, and the
/// decoder checks every length before it allocates. A human-readable format
/// (the JSON of the RPC) shows the same bytes as hex.
impl Serialize for ClaimFrame {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = self.encode();
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(bytes))
        } else {
            serializer.serialize_bytes(&bytes)
        }
    }
}

impl<'de> Deserialize<'de> for ClaimFrame {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = if deserializer.is_human_readable() {
            let text = String::deserialize(deserializer)?;
            hex::decode(text).map_err(serde::de::Error::custom)?
        } else {
            serde_bytes_buf(deserializer)?
        };
        Self::decode(&bytes, &WIRE_FRAME_LIMITS).map_err(serde::de::Error::custom)
    }
}

/// Read a byte string from a binary format.
fn serde_bytes_buf<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    struct Bytes;
    impl serde::de::Visitor<'_> for Bytes {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "the bytes of a claim frame")
        }

        fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
            Ok(v.to_vec())
        }

        fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
            Ok(v)
        }
    }
    deserializer.deserialize_byte_buf(Bytes)
}

/// The domain the claims of a chain are made for: its chain id. `None` when
/// the id does not fit a domain id; such a chain cannot turn the layer on.
#[must_use]
pub fn claim_domain(chain_id: u64) -> Option<DomainId> {
    DomainId::try_from(chain_id).ok()
}

/// Whether this build can check the proof of a frame.
///
/// Production builds use [`super::stark::StarkBackend`] (Phase 3); devnet and
/// test builds may opt into the native backend via `agg-native-backend`.
#[must_use]
const fn backend_available() -> bool {
    true
}

/// Whether the account of a transaction signs with a scheme this layer
/// claims. Phase 1: ML-DSA-87, which is a V5 transaction.
const fn is_claimable(tx: &Transaction) -> bool {
    tx.signature_version == SIGNATURE_VERSION_V5 && tx.authorization.is_none()
}

/// The claim the account rule asks for: `Claim::Sig { scheme of the
/// account, signer: tx.from, msg_hash: tx.signing_hash() }`. `None` when the
/// account cannot be authorized by a claim.
#[must_use]
pub fn account_claim(tx: &Transaction) -> Option<Claim> {
    is_claimable(tx).then(|| Claim::Sig {
        scheme: SchemeId::ML_DSA_87,
        signer: tx.from,
        msg_hash: tx.signing_hash(),
    })
}

/// Turn a signed V5 transaction into its claimed form and the object that
/// goes to the aggregators: the transaction keeps its id and loses its
/// signature and key, the envelope carries both.
///
/// `None` when the transaction is not a signed V5 transaction or the chain
/// has no claim domain.
#[must_use]
pub fn claim_signature(tx: &Transaction) -> Option<(Transaction, Envelope)> {
    let domain = claim_domain(tx.chain_id)?;
    let claim = account_claim(tx)?;
    let signature = tx.signature.as_ref()?;
    if tx.signer_public_key.is_empty() || tx.is_claimed() {
        return None;
    }
    let mut payload = tx.signer_public_key.clone();
    payload.extend_from_slice(signature);
    let envelope = Envelope {
        kind: ObjectKind::Signature,
        scheme: SchemeId::ML_DSA_87,
        payload,
        tx_hash: tx.signing_hash(),
        domain,
    };
    let mut claimed = tx.clone();
    claimed.signature = None;
    claimed.signer_public_key = Vec::new();
    claimed.auth_claim = Some(claim.digest(domain));
    Some((claimed, envelope))
}

/// What the block rules need to know about the transactions of a block.
struct TxView {
    claimed: Option<Hash32>,
    account_claim: Option<Hash32>,
    quantum_safe: bool,
}

fn views(domain: DomainId, block: &Block) -> Vec<TxView> {
    block
        .transactions
        .iter()
        .map(|tx| TxView {
            claimed: tx.auth_claim,
            account_claim: account_claim(tx).map(|claim| claim.digest(domain)),
            quantum_safe: is_claimable(tx),
        })
        .collect()
}

fn tx_claims<'a>(views: &[TxView], block: &'a Block) -> Vec<TxClaims<'a>> {
    views
        .iter()
        .zip(&block.transactions)
        .map(|(view, tx)| TxClaims {
            claimed: view.claimed,
            account_claim: view.account_claim,
            quantum_safe: view.quantum_safe,
            claim_refs: &tx.claim_refs,
        })
        .collect()
}

/// The backend of a chain: native in test or devnet builds, none in production.
///
/// Production builds stay without a backend until the STARK backend lands
/// (phase 3). Without a backend nothing is proven and no frame verifies, which
/// is why [`validate_params`] refuses `On` there.
#[derive(Debug, Clone)]
pub struct ChainBackend {
    params: AggParams,
    registry: SchemeStatusRegistry,
}

impl ChainBackend {
    /// The backend under the limits of `params` and the scheme table
    /// `registry`.
    #[must_use]
    pub fn new(params: &AggParams, registry: &SchemeStatusRegistry) -> Self {
        Self {
            params: *params,
            registry: registry.clone(),
        }
    }

    #[cfg(any(test, feature = "agg-native-backend"))]
    fn native(&self) -> super::native::NativeBackend {
        super::native::NativeBackend::new(
            self.registry.clone(),
            FrameLimits::from(&self.params),
            NATIVE_PARAMETER_SET,
        )
    }

    #[cfg(not(any(test, feature = "agg-native-backend")))]
    fn stark(&self) -> super::stark::StarkBackend {
        super::stark::StarkBackend::new(
            self.registry.clone(),
            FrameLimits::from(&self.params),
            super::stark::STARK_PARAMETER_SET,
        )
    }
}

impl AggBackend for ChainBackend {
    fn prove_tick(&self, ctx: &TickCtx, items: &[PoolItem]) -> Result<ClaimFrame, AggError> {
        #[cfg(any(test, feature = "agg-native-backend"))]
        return self.native().prove_tick(ctx, items);
        #[cfg(not(any(test, feature = "agg-native-backend")))]
        return self.stark().prove_tick(ctx, items);
    }

    fn prove_merge(&self, left: &ClaimFrame, right: &ClaimFrame) -> Result<Vec<u8>, AggError> {
        #[cfg(any(test, feature = "agg-native-backend"))]
        return self.native().prove_merge(left, right);
        #[cfg(not(any(test, feature = "agg-native-backend")))]
        return self.stark().prove_merge(left, right);
    }

    fn verify(&self, frame: &ClaimFrame, domain: DomainId) -> Result<(), AggError> {
        #[cfg(any(test, feature = "agg-native-backend"))]
        return self.native().verify(frame, domain);
        #[cfg(not(any(test, feature = "agg-native-backend")))]
        return self.stark().verify(frame, domain);
    }
}

/// The commitment to the consensus parameters of the layer on one chain:
/// the claim domain, the two block limits, the claim fee, the aggregator
/// share and the backend parameter set. Every field has a fixed width.
#[must_use]
fn params_commitment(params: &AggParams, domain: DomainId) -> Hash32 {
    let max_claims = u64::try_from(params.max_claims_per_block).unwrap_or(u64::MAX);
    let max_proof = u64::try_from(params.max_proof_bytes).unwrap_or(u64::MAX);
    h(&[
        TAG_AGG_PARAMS,
        &domain.to_be_bytes(),
        &max_claims.to_be_bytes(),
        &max_proof.to_be_bytes(),
        &params.claim_fee_per_byte.to_be_bytes(),
        &params.agg_share_bps.to_be_bytes(),
        &ACTIVE_PARAMETER_SET.to_be_bytes(),
    ])
}

/// The genesis `frame_hash` commitment when the aggregation layer is enabled.
///
/// Returns the consensus parameter commitment when `params.mode == AggMode::On`,
/// and `None` otherwise so chains that keep aggregation off preserve their
/// original genesis hash.
#[must_use]
pub fn genesis_commitment(params: &AggParams, chain_id: u64) -> Option<Hash32> {
    if params.mode != AggMode::On {
        return None;
    }
    claim_domain(chain_id).map(|domain| params_commitment(params, domain))
}

/// Whether a chain may start with these parameters.
///
/// # Errors
///
/// A message naming the parameter that cannot stand.
pub fn validate_params(params: &AggParams, chain_id: u64) -> Result<(), String> {
    if params.agg_share_bps > 10_000 {
        return Err(format!(
            "aggregation: agg_share_bps {} is over 10000",
            params.agg_share_bps
        ));
    }
    let claims_exceed_wire = params.max_claims_per_block > WIRE_FRAME_LIMITS.max_claims;
    let proof_exceeds_wire = params.max_proof_bytes > WIRE_FRAME_LIMITS.max_proof_bytes;
    if claims_exceed_wire || proof_exceeds_wire {
        return Err(format!(
            "aggregation: block limits ({} claims, {} proof bytes) are over what the wire carries \
             ({} claims, {} proof bytes)",
            params.max_claims_per_block,
            params.max_proof_bytes,
            WIRE_FRAME_LIMITS.max_claims,
            WIRE_FRAME_LIMITS.max_proof_bytes
        ));
    }
    if params.mode != AggMode::On {
        return Ok(());
    }
    // A block counts its frame as hex, so a proof at the limit takes twice
    // its bytes of the block. Past a third of the block size it leaves no
    // room for the claims and the transactions the frame is carried for.
    if params.max_proof_bytes > MAX_BLOCK_PROOF_BYTES {
        return Err(format!(
            "aggregation: max_proof_bytes {} is over what a block can carry next to its \
             transactions ({MAX_BLOCK_PROOF_BYTES})",
            params.max_proof_bytes
        ));
    }
    // The only backend is the native one, whose proof is the objects
    // themselves. The main network waits for the STARK backend.
    if Network::from_chain_id(chain_id) == Some(Network::Mainnet) {
        return Err("aggregation: the main network does not turn the layer on yet".into());
    }
    if claim_domain(chain_id).is_none() {
        return Err(format!(
            "aggregation: chain id {chain_id} does not fit a claim domain"
        ));
    }
    if !backend_available() {
        return Err(
            "aggregation: mode `on` needs a build with a backend (feature agg-native-backend)"
                .into(),
        );
    }
    Ok(())
}

/// Whether a transaction may wait in the mempool of a chain and go into a
/// block that carries no claim frame.
///
/// While the layer is not on, no transaction may use it: a block that held
/// one would be refused by every validator. While it is on, a quantum-safe
/// signature may not travel inline (block rule), and a transaction that
/// uses a claim needs a block frame, which the producer of this node does
/// not build yet.
///
/// # Errors
///
/// A message naming why the transaction cannot be taken.
pub fn check_pool_transaction(params: &AggParams, tx: &Transaction) -> Result<(), String> {
    if params.mode != AggMode::On {
        return if tx.uses_claims() {
            Err("aggregation is not on: a transaction may not use claims".into())
        } else {
            Ok(())
        };
    }
    if tx.uses_claims() {
        return Err(
            "aggregation: a transaction that uses claims enters with its object, not through the mempool"
                .into(),
        );
    }
    if is_claimable(tx) {
        return Err(
            "aggregation is on: an ML-DSA-87 signature travels as a claim, not inline".into(),
        );
    }
    Ok(())
}

/// Check the claims of a block: the ten block rules under `On`, and under
/// any other mode that the block does not use the layer at all.
///
/// The genesis block carries no frame; its `frame_hash` slot must hold the
/// parameter commitment of the chain.
///
/// # Errors
///
/// A message naming the rule the block breaks.
pub fn check_block(
    params: &AggParams,
    registry: &SchemeStatusRegistry,
    block: &Block,
) -> Result<(), String> {
    if block.index == 0 {
        let expected = genesis_commitment(params, block.chain_id);
        if block.claim_frame.is_some() || block.frame_hash != expected {
            return Err("aggregation: the genesis block does not commit to the parameters".into());
        }
        return Ok(());
    }
    // Under `On` the domain exists (the parameters were validated); under
    // any other mode it is not read.
    let domain = match (params.mode, claim_domain(block.chain_id)) {
        (_, Some(domain)) => domain,
        (AggMode::On, None) => {
            return Err("aggregation: the chain has no claim domain".into());
        }
        (_, None) => 0,
    };
    let views = views(domain, block);
    let txs = tx_claims(&views, block);
    check_block_claims(
        params,
        domain,
        block.frame_hash.as_ref(),
        block.claim_frame.as_ref(),
        &txs,
        &ChainBackend::new(params, registry),
    )
    .map(|_| ())
    .map_err(|e| format!("aggregation: {e}"))
}

/// The claim fees of a block: what every paying transaction is charged,
/// which transactions fail and who is paid.
///
/// This checks no proof. The caller either ran [`check_block`] on the block
/// or replays a block the chain accepted earlier. A block without a frame,
/// and every block while the layer is not on, settles nothing.
///
/// # Errors
///
/// A message when the transactions and the frame do not fit each other; a
/// block that passed [`check_block`] never does that.
pub fn settlement_of(params: &AggParams, block: &Block) -> Result<ClaimSettlement, String> {
    let Some(frame) = block.claim_frame.as_ref() else {
        return Ok(ClaimSettlement::default());
    };
    if params.mode != AggMode::On || block.index == 0 {
        return Ok(ClaimSettlement::default());
    }
    let domain = claim_domain(block.chain_id)
        .ok_or_else(|| "aggregation: the chain has no claim domain".to_string())?;
    let digests: Vec<Hash32> = frame.claims.iter().map(|c| c.digest(domain)).collect();
    let views = views(domain, block);
    let txs = tx_claims(&views, block);
    let payers = claim_payers(&digests, &txs).map_err(|e| format!("aggregation: {e}"))?;
    let fees: Vec<u64> = block.transactions.iter().map(|tx| tx.fee).collect();
    Ok(settle(params, frame, &payers, &fees))
}
