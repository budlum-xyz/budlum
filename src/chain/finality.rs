use crate::core::address::Address;
use crate::registry::SlashingReport;
use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    G1Affine, G1Projective, G2Affine, G2Projective, Scalar,
};
use serde::{Deserialize, Serialize};
use sha2_010::Sha256;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

use crate::core::chain_config::{
    FINALITY_CHECKPOINT_INTERVAL, FINALITY_QUORUM_DENOMINATOR, FINALITY_QUORUM_NUMERATOR,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSetSnapshot {
    pub epoch: u64,
    pub validators: Vec<ValidatorEntry>,
    pub set_hash: String,
    pub total_stake: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorEntry {
    pub address: Address,
    pub stake: u64,
    #[serde(default)]
    pub bls_public_key: Vec<u8>,
    #[serde(default)]
    pub pop_signature: Vec<u8>,
    #[serde(default)]
    pub pq_public_key: Vec<u8>,
}

impl ValidatorSetSnapshot {
    pub fn new(epoch: u64, validators: Vec<ValidatorEntry>) -> Self {
        // `total_stake` is a summary for exports and readers; it saturates.
        // The quorum is measured against `stake_sum`, which does not.
        let total_stake = validators
            .iter()
            .fold(0u64, |acc, v| acc.saturating_add(v.stake));
        let set_hash = Self::compute_hash(&validators);
        ValidatorSetSnapshot {
            epoch,
            validators,
            set_hash,
            total_stake,
        }
    }

    pub fn compute_hash(validators: &[ValidatorEntry]) -> String {
        let mut sorted_validators = validators.to_vec();
        sorted_validators.sort_by_key(|v| v.address);

        let mut hasher = Sha3_256::new();
        for v in sorted_validators {
            hasher.update(v.address.0);
            hasher.update(v.stake.to_le_bytes());
            // Length-prefixed, and the loop is why: without lengths the last
            // field of one validator and the first of the next could trade
            // bytes across the boundary. See
            // `crate::crypto::key_set_preimage`.
            crate::crypto::key_set_preimage::update_consensus_keys_sha3(
                &mut hasher,
                None,
                &v.bls_public_key,
                &v.pop_signature,
                &v.pq_public_key,
            );
        }
        hex::encode(hasher.finalize())
    }

    /// Validates that `set_hash` and `total_stake` match the computed values from `validators`.
    pub fn validate_metadata(&self) -> Result<(), String> {
        let computed_hash = Self::compute_hash(&self.validators);
        if self.set_hash != computed_hash {
            return Err(format!(
                "ValidatorSetSnapshot set_hash mismatch: claimed {}, computed {}",
                self.set_hash, computed_hash
            ));
        }
        let sum: u128 = self.validators.iter().map(|v| u128::from(v.stake)).sum();
        let expected_total = sum.min(u128::from(u64::MAX)) as u64;
        if self.total_stake != expected_total {
            return Err(format!(
                "ValidatorSetSnapshot total_stake mismatch: claimed {}, computed sum {}",
                self.total_stake, expected_total
            ));
        }
        Ok(())
    }

    pub fn find_validator(&self, address: &Address) -> Option<&ValidatorEntry> {
        self.validators.iter().find(|v| &v.address == address)
    }

    pub fn validator_index(&self, address: &Address) -> Option<usize> {
        self.validators.iter().position(|v| &v.address == address)
    }

    /// Exact stake held by the whole set.
    ///
    /// Summed in `u128`, so a set whose stakes add up past `u64::MAX` keeps
    /// its real total. `total_stake` saturates there, and a threshold taken
    /// from a saturated total was met by a saturated partial sum: with stakes
    /// `[MAX, MAX, 1, 1, 1, 1]`, four signers holding `MAX + 3` of a real
    /// `2 * MAX + 4` compared as `MAX >= MAX` and finalized with a third of
    /// the stake. Every quorum comparison sums in `u128` for the same reason.
    fn stake_sum(&self) -> u128 {
        self.validators.iter().map(|v| u128::from(v.stake)).sum()
    }

    /// The stake a certificate has to carry: strictly more than two thirds
    /// of the summed validator stake. Exact, never saturated: `saturating_mul` on
    /// `u64` clamped the product to `u64::MAX` and the division then handed
    /// back a third of the range, a threshold a minority could pass.
    pub fn quorum_stake(&self) -> u128 {
        (self.stake_sum() * u128::from(FINALITY_QUORUM_NUMERATOR))
            / u128::from(FINALITY_QUORUM_DENOMINATOR)
            + 1
    }

    /// Hybrid finality requires both stake quorum and validator-count quorum.
    /// This prevents a highly concentrated stake minority of identities from
    /// Finalizing alone. Count quorum is ceil(2n/3): three validators require
    /// Two signers, four validators require three.
    pub fn quorum_count(&self) -> usize {
        self.validators
            .len()
            .saturating_mul(FINALITY_QUORUM_NUMERATOR as usize)
            .div_ceil(FINALITY_QUORUM_DENOMINATOR as usize)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prevote {
    pub epoch: u64,
    pub checkpoint_height: u64,
    pub checkpoint_hash: String,
    /// The chain this vote is signed for, folded into the signing preimage.
    ///
    /// A BLS key reused across two Budlum chains produces a legitimate vote on
    /// each of them for the same `(epoch, checkpoint_height)`. Without the
    /// chain id those two genuine signatures look exactly like an equivocation,
    /// so a block producer could put them in a `Prevote` double-sign report and
    /// have the honest validator slashed on the chain it is being framed on.
    /// Every verifier rebuilds the preimage with *its own* chain id (never the
    /// one carried here), so a signature minted for another chain simply fails
    /// verification. `#[serde(default)]` keeps older wire shapes decodable;
    /// they fail the signature gate instead of being trusted.
    #[serde(default)]
    pub chain_id: u64,
    pub voter_id: Address,
    pub sig_bls: Vec<u8>,
    /// BLG-0083 (P04-F01): an authentication signature over
    /// [`Prevote::auth_signing_message`] under the voter's registered key.
    /// A vote without a valid `auth_sig` is dropped WITHOUT counting an
    /// invalid-vote tick against anyone: garbage cannot be attributed to a
    /// keyholder. `#[serde(default)]` so old wire shapes deserialize; they
    /// simply fail the auth gate.
    #[serde(default)]
    pub auth_sig: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Precommit {
    pub epoch: u64,
    pub checkpoint_height: u64,
    pub checkpoint_hash: String,
    /// Chain binding; see [`Prevote::chain_id`].
    #[serde(default)]
    pub chain_id: u64,
    pub voter_id: Address,
    pub sig_bls: Vec<u8>,
    /// BLG-0083 (P04-F01): the vote-authentication signature; see
    /// [`Prevote::auth_sig`].
    #[serde(default)]
    pub auth_sig: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityCert {
    pub epoch: u64,
    pub checkpoint_height: u64,
    pub checkpoint_hash: String,
    /// Chain binding of the aggregated precommit signatures; see
    /// [`Prevote::chain_id`]. The certificate is the aggregate of votes, so it
    /// must commit to the same chain id they signed.
    #[serde(default)]
    pub chain_id: u64,
    pub agg_sig_bls: Vec<u8>,
    pub bitmap: Vec<u8>,
    pub set_hash: String,
}

/// Build the domain-separated, length-framed preimage signed by a validator's
/// vote-authentication key (`BUDLUM_VOTE_AUTH_V3`).
///
/// Both `vote_msg` and `sig_bls` are variable-length on the wire, so each
/// carries an explicit little-endian `u64` byte length. Without those length
/// prefixes, shifting trailing characters of `checkpoint_hash` into the front
/// of `sig_bls` preserved the concatenated preimage and allowed one captured
/// honest vote to mint invalid-vote ticks against the signer (CWE-347).
pub fn vote_auth_signing_message(vote_msg: &[u8], sig_bls: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(19 + 8 + vote_msg.len() + 8 + sig_bls.len());
    msg.extend_from_slice(b"BUDLUM_VOTE_AUTH_V3");
    msg.extend_from_slice(&(vote_msg.len() as u64).to_le_bytes());
    msg.extend_from_slice(vote_msg);
    msg.extend_from_slice(&(sig_bls.len() as u64).to_le_bytes());
    msg.extend_from_slice(sig_bls);
    msg
}

/// Extract the canonical epoch committed inside a domain-separated `Prevote` or
/// `Precommit` signing preimage, returning `None` for any non-vote byte string.
pub fn vote_message_epoch(vote_msg: &[u8]) -> Option<u64> {
    let after_chain = vote_preimage_after_chain_id(vote_msg)?;
    let epoch_bytes: [u8; 8] = after_chain.get(..8)?.try_into().ok()?;
    Some(u64::from_le_bytes(epoch_bytes))
}

/// Extract the canonical chain id committed inside a domain-separated
/// `Prevote` or `Precommit` signing preimage, returning `None` for any non-vote
/// byte string.
///
/// The epoch reader below deliberately stops after the epoch, and the
/// `InvalidSignatureSpam` proof carried only that: a vote sample minted on
/// another chain with the same epoch satisfied every other check there. The
/// chain id sits directly before the epoch in the preimage, so the two readers
/// walk the same prefix through `vote_preimage_after_chain_id` and cannot drift
/// apart.
pub fn vote_message_chain_id(vote_msg: &[u8]) -> Option<u64> {
    let scheme = BLS_SCHEME_RFC9380_V1.as_bytes();
    let rest = vote_msg
        .strip_prefix(PREVOTE_DOMAIN)
        .or_else(|| vote_msg.strip_prefix(PRECOMMIT_DOMAIN))?;
    let after_scheme = rest.strip_prefix(scheme)?;
    let chain_bytes: [u8; 8] = after_scheme.get(..8)?.try_into().ok()?;
    Some(u64::from_le_bytes(chain_bytes))
}

fn vote_preimage_after_chain_id(vote_msg: &[u8]) -> Option<&[u8]> {
    let scheme = BLS_SCHEME_RFC9380_V1.as_bytes();
    let rest = vote_msg
        .strip_prefix(PREVOTE_DOMAIN)
        .or_else(|| vote_msg.strip_prefix(PRECOMMIT_DOMAIN))?;
    let after_scheme = rest.strip_prefix(scheme)?;
    after_scheme.get(8..)
}

impl Prevote {
    /// Bytes a validator signs to endorse a checkpoint.
    ///
    /// # Why the chain id is stated, not derived
    ///
    /// The cross-chain replay question (could a prevote signed on Testnet be
    /// replayed on mainnet?) used to be answered indirectly: `checkpoint_hash`
    /// is a block hash and `Block::calculate_hash_bytes` folds `chain_id` into
    /// its `BDLM_BLOCK_V4` preimage, so the signature did not verify against
    /// another chain's checkpoint.
    ///
    /// That argument only rules out *replaying* one signature. It does not
    /// rule out *presenting two genuine signatures*: a validator running the
    /// same BLS key on two chains signs one legitimate vote per chain for the
    /// same `(epoch, checkpoint_height)`, and the two hashes differ. Nothing in
    /// that pair looks like equivocation to a verifier that cannot see which
    /// chain each vote belongs to, so the pair could be filed as a `Prevote`
    /// double-sign report and slash the honest validator.
    ///
    /// The chain id is therefore part of the preimage (`BUDLUM_PREVOTE_V2`),
    /// and every verifier rebuilds it with its own chain id. A vote signed for
    /// another chain is refused by the signature check itself.
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(PREVOTE_DOMAIN);
        msg.extend_from_slice(BLS_SCHEME_RFC9380_V1.as_bytes());
        msg.extend_from_slice(&self.chain_id.to_le_bytes());
        msg.extend_from_slice(&self.epoch.to_le_bytes());
        msg.extend_from_slice(&self.checkpoint_height.to_le_bytes());
        msg.extend_from_slice(self.checkpoint_hash.as_bytes());
        msg
    }

    /// BLG-0083 (P04-F01): the message the voter authenticates with their
    /// registered key. Domain-separated from the vote message so one
    /// signature cannot serve as the other.
    ///
    /// V3 frames both variable-length inputs (`signing_message` and `sig_bls`)
    /// with explicit 8-byte lengths via [`vote_auth_signing_message`].
    pub fn auth_signing_message(&self) -> Vec<u8> {
        vote_auth_signing_message(&self.signing_message(), &self.sig_bls)
    }
}

impl Precommit {
    pub fn signing_message(&self) -> Vec<u8> {
        checkpoint_signing_message(
            self.chain_id,
            self.epoch,
            self.checkpoint_height,
            &self.checkpoint_hash,
        )
    }

    /// BLG-0083 (P04-F01): the vote-authentication message; shares the exact
    /// length-framed V3 encoding with [`Prevote::auth_signing_message`].
    pub fn auth_signing_message(&self) -> Vec<u8> {
        vote_auth_signing_message(&self.signing_message(), &self.sig_bls)
    }
}

pub fn is_checkpoint_height(height: u64) -> bool {
    height > 0 && height.is_multiple_of(FINALITY_CHECKPOINT_INTERVAL)
}

pub fn is_checkpoint_height_for_chain(height: u64, chain_id: u64) -> bool {
    let interval = crate::core::chain_config::finality_checkpoint_interval_for_chain_id(chain_id);
    height > 0 && height.is_multiple_of(interval)
}

/// Decode a block-hash string into 32 bytes, or `None` when the string is
/// not 32-byte hex. Used by the settlement finality window, which skips
/// what it cannot decode - deterministically, since every node holds the
/// same string.
fn hash32_from_hex(s: &str) -> Option<crate::domain::Hash32> {
    let bytes = hex::decode(s).ok()?;
    let mut out = [0u8; 32];
    if bytes.len() != 32 {
        return None;
    }
    out.copy_from_slice(&bytes);
    Some(out)
}

/// The settlement finality window (F-7): the hashes of a chain's
/// checkpoint blocks that are buried at least the finality horizon
/// ([`crate::cross_domain::nonce::FINALITY_PRUNE_DEPTH`]) deep and no
/// deeper than the settled-row retention
/// (`SETTLED_RETENTION_BLOCKS`, private to the bridge module).
///
/// Pure derivation over `(height, block hash)` pairs: every checkpoint
/// height in `[tip - SETTLED_RETENTION_BLOCKS, tip - FINALITY_PRUNE_DEPTH]`
/// whose hash decodes to 32 bytes is in, in height order; the genesis
/// height, non-checkpoint heights and malformed hashes are skipped. The
/// settlement root folded into the state root is therefore a function of
/// the blocks a node already holds, never of when this particular node
/// happened to see a finality certificate - two honest nodes cannot split
/// over it.
pub fn settlement_finality_window_from<'a>(
    heights_and_hashes: impl Iterator<Item = (u64, &'a str)>,
    interval: u64,
    tip: u64,
) -> Vec<crate::domain::Hash32> {
    if interval == 0 {
        return Vec::new();
    }
    let newest = tip.saturating_sub(crate::cross_domain::nonce::FINALITY_PRUNE_DEPTH);
    let oldest = tip.saturating_sub(crate::cross_domain::bridge::SETTLED_RETENTION_BLOCKS);
    let mut window = Vec::new();
    for (height, hash) in heights_and_hashes {
        if height == 0 || height % interval != 0 || height < oldest || height > newest {
            continue;
        }
        if let Some(decoded) = hash32_from_hex(hash) {
            window.push(decoded);
        }
    }
    window
}

/// Precommit (and finality-certificate) preimage: the precommit vote and the
/// certificate that aggregates those votes must sign the same bytes.
///
/// The chain id is the first field, exactly as for [`Prevote::signing_message`],
/// so a vote or certificate produced on one chain can never be verified on
/// another. See [`Prevote::signing_message`] for why this is stated rather
/// than derived from the block hash.
pub fn checkpoint_signing_message(chain_id: u64, epoch: u64, height: u64, hash: &str) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(PRECOMMIT_DOMAIN);
    msg.extend_from_slice(BLS_SCHEME_RFC9380_V1.as_bytes());
    msg.extend_from_slice(&chain_id.to_le_bytes());
    msg.extend_from_slice(&epoch.to_le_bytes());
    msg.extend_from_slice(&height.to_le_bytes());
    msg.extend_from_slice(hash.as_bytes());
    msg
}

/// Proof-of-possession input from the IETF BLS PoP ciphersuite: the canonical
/// Serialized public key. Chain/address binding is provided separately by the
/// Validator's signed `RegisterConsensusKeys` transaction.
pub fn pop_signing_message(chain_id: u64, address: &Address, bls_pk: &[u8]) -> Vec<u8> {
    // R11: a proof of possession over only the public key replays across
    // chains and accounts: the same PoP produced for chain A is accepted
    // for chain B, so an operator slashed on one chain can re-register the
    // same key elsewhere without a fresh possession proof. Bind the message
    // to the chain id and the account address it is registered for. The
    // fields are fixed-length (8 + 32 + 96), so the encoding is injective
    // without length prefixes; the domain tag keeps it distinct from any
    // other BLS message in the tree.
    let mut msg = Vec::with_capacity(14 + 8 + 32 + bls_pk.len());
    msg.extend_from_slice(b"BDLM_BLS_POP_V1");
    msg.extend_from_slice(&chain_id.to_le_bytes());
    msg.extend_from_slice(address.as_bytes());
    msg.extend_from_slice(bls_pk);
    msg
}

/// Wire-visible identifier for the RFC 9380 random-oracle suite used by all
/// Live Budlum BLS signatures. Public keys are in G2 and signatures are in G1.
pub const BLS_SCHEME_RFC9380_V1: &str = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

/// Domain tag of the chain-bound prevote preimage.
const PREVOTE_DOMAIN: &[u8] = b"BUDLUM_PREVOTE_V2";
/// Domain tag of the chain-bound precommit (and finality certificate) preimage.
const PRECOMMIT_DOMAIN: &[u8] = b"BUDLUM_PRECOMMIT_V2";
/// The pre-migration construction exposed H(m)'s discrete logarithm. Its ID is
/// Retained only for handshake rejection and historical tooling; it must never
/// Be used to validate a live vote or certificate.
pub const BLS_SCHEME_LEGACY_SCALAR_V0: &str = "BUDLUM_BLS_SCALAR_SHA3_V0";
/// Mainnet has not launched, so the safe single-epoch migration point is the
/// Genesis epoch. There is no live epoch in which the forgeable scheme is valid.
pub const BLS_RFC9380_ACTIVATION_EPOCH: u64 = 0;

const BLS_SIGNATURE_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
const BLS_POP_DST: &[u8] = b"BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
/// Ethereum's BLS suite (`EIP-2537` / consensus spec) hashes signatures in G2.
///
/// The G2 `SSWU_RO` map is used by the Ethereum sync-committee interop path
/// in `cross_domain::evm::sync_committee`, where public keys are 48-byte G1
/// points and signatures are 96-byte G2 points.
const BLS_SIGNATURE_G2_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

fn hash_to_g1(msg: &[u8]) -> G1Affine {
    // RFC 9380 §8.8.1: hash_to_curve, expand_message_xmd(SHA-256), Simplified
    // SWU, random-oracle encoding. Unlike the removed scalar-times-generator
    // Construction, the discrete logarithm of this point is not known.
    G1Affine::from(
        <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
            std::iter::once(msg),
            BLS_SIGNATURE_DST,
        ),
    )
}

/// Hash to G2 under Ethereum's signature DST.
///
/// Same RFC 9380 construction as the G1 variant (`hash_to_g1`), on the G2 group: `H(m)` for
/// a 96-byte G2 signature.
#[must_use]
pub fn hash_to_g2(msg: &[u8]) -> G2Affine {
    G2Affine::from(
        <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
            std::iter::once(msg),
            BLS_SIGNATURE_G2_DST,
        ),
    )
}

pub fn hash_pop_to_g1(msg: &[u8]) -> G1Affine {
    G1Affine::from(
        <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
            std::iter::once(msg),
            BLS_POP_DST,
        ),
    )
}

pub fn sign_bls(sk: &Scalar, msg: &[u8]) -> Vec<u8> {
    let h_msg = hash_to_g1(msg);
    let sig = G1Affine::from(G1Projective::from(h_msg) * sk);
    sig.to_compressed().to_vec()
}

pub fn sign_bls_pop(sk: &Scalar, msg: &[u8]) -> Vec<u8> {
    let h_msg = hash_pop_to_g1(msg);
    let sig = G1Affine::from(G1Projective::from(h_msg) * sk);
    sig.to_compressed().to_vec()
}

pub fn verify_bls_sig(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), String> {
    let pk_bytes: [u8; 96] = pk
        .try_into()
        .map_err(|_| "Invalid BLS public key length".to_string())?;
    // `CtOption::unwrap` panics on `None`, and these bytes arrive from the
    // network. The `is_none` check above made that unreachable, but the
    // guarantee sat one statement away; `into_option` fuses the check and the
    // read so a malformed key can only ever become an `Err`.
    // bls12_381 0.9's `from_compressed` already guarantees subgroup
    // membership; decode unchecked anyway and gate explicitly below, so the
    // refusal that names the subgroup does not depend on the decoder's
    // contract (which is exactly what changed under the 0.8 -> 0.9 bump).
    let pk_affine = G2Affine::from_compressed_unchecked(&pk_bytes)
        .into_option()
        .ok_or_else(|| "Invalid BLS public key encoding".to_string())?;
    if !bool::from(pk_affine.is_on_curve()) {
        return Err("Invalid BLS public key encoding".to_string());
    }

    // (security audit §5) enforce that the public key is
    // Actually in the correct prime-order subgroup. Without this
    // Check an attacker can supply a small-subgroup point as the
    // Public key, which makes the pairing produce values in a
    // Sub-group that pairs to identity for any message, bypassing
    // The BLS signature scheme entirely. The bls12_381 crate
    // Exposes `is_torsion_free` for exactly this check.
    let is_on_curve_pk: bool = pk_affine.is_torsion_free().into();
    if !is_on_curve_pk || bool::from(pk_affine.is_identity()) {
        return Err("BLS public key is identity or not in the prime-order subgroup".to_string());
    }

    let sig_bytes: [u8; 48] = sig
        .try_into()
        .map_err(|_| "Invalid BLS signature length".to_string())?;
    let sig_affine = G1Affine::from_compressed_unchecked(&sig_bytes)
        .into_option()
        .ok_or_else(|| "Invalid BLS signature encoding".to_string())?;
    if !bool::from(sig_affine.is_on_curve()) {
        return Err("Invalid BLS signature encoding".to_string());
    }

    // Same subgroup check on the signature: a small-subgroup
    // Signature would also make the pairing produce values in a
    // Sub-group that pairs to identity for the chosen message.
    let is_on_curve_sig: bool = sig_affine.is_torsion_free().into();
    if !is_on_curve_sig || bool::from(sig_affine.is_identity()) {
        return Err("BLS signature is identity or not in the prime-order subgroup".to_string());
    }

    let h_msg = hash_to_g1(msg);
    let g2_gen_neg = -G2Affine::generator();

    let pairing_result = bls12_381::multi_miller_loop(&[
        (&sig_affine, &g2_gen_neg.into()),
        (&h_msg, &pk_affine.into()),
    ])
    .final_exponentiation();

    if pairing_result != bls12_381::Gt::identity() {
        return Err("BLS signature verification failed".into());
    }
    Ok(())
}

pub fn verify_pop(entry: &ValidatorEntry, chain_id: u64) -> bool {
    if entry.bls_public_key.is_empty() || entry.pop_signature.is_empty() {
        return false;
    }

    // Parse BLS Public Key
    let pk_bytes: [u8; 96] = match entry.bls_public_key.as_slice().try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let Some(pk_affine) = G2Affine::from_compressed_unchecked(&pk_bytes).into_option() else {
        return false;
    };
    // (security audit §5) subgroup check on the PoP
    // Public key (see `verify_bls_sig` for the full rationale).
    let is_on_curve: bool = pk_affine.is_torsion_free().into();
    if !is_on_curve || !bool::from(pk_affine.is_on_curve()) || bool::from(pk_affine.is_identity()) {
        return false;
    }

    // Parse PoP Signature
    let sig_bytes: [u8; 48] = match entry.pop_signature.as_slice().try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let Some(sig_affine) = G1Affine::from_compressed_unchecked(&sig_bytes).into_option() else {
        return false;
    };
    // (security audit §5) subgroup check on the PoP
    // Signature (see `verify_bls_sig` for the full rationale).
    let is_on_curve: bool = sig_affine.is_torsion_free().into();
    if !is_on_curve || !bool::from(sig_affine.is_on_curve()) || bool::from(sig_affine.is_identity())
    {
        return false;
    }

    // Verify PoP: e(sig, G2_gen) == e(H(pop_msg), pk)
    let msg = pop_signing_message(chain_id, &entry.address, &entry.bls_public_key);
    let h_msg = hash_pop_to_g1(&msg);

    let g2_gen_neg = -G2Affine::generator();
    let pairing_result = bls12_381::multi_miller_loop(&[
        (&sig_affine, &g2_gen_neg.into()),
        (&h_msg, &pk_affine.into()),
    ])
    .final_exponentiation();

    pairing_result == bls12_381::Gt::identity()
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AggregatorState {
    pub active: bool,
    pub epoch: u64,
    pub checkpoint_height: u64,
    pub checkpoint_hash: String,
    pub prevote_quorum_reached: bool,
    pub precommit_quorum_reached: bool,
    pub prevote_count: usize,
    pub precommit_count: usize,
}

impl AggregatorState {
    pub fn inactive() -> Self {
        AggregatorState {
            active: false,
            epoch: 0,
            checkpoint_height: 0,
            checkpoint_hash: String::new(),
            prevote_quorum_reached: false,
            precommit_quorum_reached: false,
            prevote_count: 0,
            precommit_count: 0,
        }
    }
}

#[derive(Debug)]
pub struct FinalityAggregator {
    pub epoch: u64,
    pub checkpoint_height: u64,
    pub checkpoint_hash: String,
    pub prevotes: HashMap<Address, Prevote>,
    pub precommits: HashMap<Address, Precommit>,
    /// The set every vote is checked against. Required at construction: an
    /// aggregator without a snapshot used to skip membership and BLS checks
    /// and could still emit consensus-verified equivocation reports.
    pub validator_snapshot: ValidatorSetSnapshot,
    pub prevote_quorum_reached: bool,
    pub precommit_quorum_reached: bool,
    /// Equivocation (double-sign) evidence detected while ingesting votes.
    ///
    ///: when a validly-signed vote conflicts with one we already
    /// Recorded from the same voter, we package both into a canonical
    /// [`SlashingReport`] here. The `Blockchain` drains this after each
    /// `add_prevote`/`add_precommit` and routes it through the SAME
    /// `submit_registry_slashing_report` path as every other consensus-verified
    /// Report - no second slashing path is opened.
    pub detected_equivocations: Vec<SlashingReport>,
    /// First validly-signed prevote (hash, signature) seen per voter, used to
    /// Detect a later conflicting-hash vote regardless of arrival order.
    seen_prevotes: HashMap<Address, (String, Vec<u8>)>,
    /// First validly-signed precommit (hash, signature) seen per voter.
    seen_precommits: HashMap<Address, (String, Vec<u8>)>,
    /// Voters already flagged for equivocation, to avoid duplicate reports.
    flagged_equivocators: std::collections::HashSet<Address>,
}

impl FinalityAggregator {
    pub fn new(
        epoch: u64,
        checkpoint_height: u64,
        checkpoint_hash: String,
        validator_snapshot: ValidatorSetSnapshot,
    ) -> Self {
        FinalityAggregator {
            epoch,
            checkpoint_height,
            checkpoint_hash,
            prevotes: HashMap::new(),
            precommits: HashMap::new(),
            validator_snapshot,
            prevote_quorum_reached: false,
            precommit_quorum_reached: false,
            detected_equivocations: Vec::new(),
            seen_prevotes: HashMap::new(),
            seen_precommits: HashMap::new(),
            flagged_equivocators: std::collections::HashSet::new(),
        }
    }

    /// Drain any equivocation evidence detected since the last call. The caller
    /// (`Blockchain`) routes each report through the existing
    /// `submit_registry_slashing_report` flow.
    pub fn take_detected_equivocations(&mut self) -> Vec<SlashingReport> {
        std::mem::take(&mut self.detected_equivocations)
    }

    pub fn add_prevote(&mut self, vote: Prevote) -> Result<(), String> {
        if vote.epoch != self.epoch {
            return Err("Prevote epoch mismatch".into());
        }
        if vote.checkpoint_height != self.checkpoint_height {
            return Err("Prevote checkpoint height mismatch".into());
        }

        // Membership + ingest-time BLS signature verification (
        // Option A). The signature is checked over the vote's OWN signing
        // Message (which binds its own checkpoint_hash), so a conflicting-hash
        // Vote is only ever treated as equivocation if it is itself validly
        // Signed. A garbage/forged signature is rejected here and never enters
        // The aggregate, guaranteeing that an honest subset can always finalize.
        let entry = self
            .validator_snapshot
            .find_validator(&vote.voter_id)
            .ok_or("Voter not in validator set")?;
        verify_bls_sig(
            &entry.bls_public_key,
            &vote.signing_message(),
            &vote.sig_bls,
        )
        .map_err(|e| format!("Invalid prevote signature: {e}"))?;

        // Equivocation detection . A validly-signed vote for a
        // DIFFERENT checkpoint hash than one already seen from this voter is a
        // Double-sign - record canonical evidence once (order-independent).
        self.detect_prevote_equivocation(&vote);

        if vote.checkpoint_hash != self.checkpoint_hash {
            // Validly signed but for a non-canonical checkpoint: cannot count
            // Toward this aggregator's target. Evidence (if any) is recorded.
            return Err("Prevote checkpoint hash mismatch".into());
        }

        if self.prevotes.contains_key(&vote.voter_id) {
            return Err("Duplicate prevote".into());
        }

        self.prevotes.insert(vote.voter_id, vote);
        self.check_prevote_quorum();
        Ok(())
    }

    pub fn add_precommit(&mut self, vote: Precommit) -> Result<(), String> {
        if vote.epoch != self.epoch {
            return Err("Precommit epoch mismatch".into());
        }
        if vote.checkpoint_height != self.checkpoint_height {
            return Err("Precommit checkpoint height mismatch".into());
        }

        if !self.prevote_quorum_reached {
            return Err("Cannot precommit before prevote quorum".into());
        }

        // Membership + ingest-time BLS signature verification .
        let entry = self
            .validator_snapshot
            .find_validator(&vote.voter_id)
            .ok_or("Voter not in validator set")?;
        verify_bls_sig(
            &entry.bls_public_key,
            &vote.signing_message(),
            &vote.sig_bls,
        )
        .map_err(|e| format!("Invalid precommit signature: {e}"))?;

        // Equivocation detection .
        self.detect_precommit_equivocation(&vote);

        if vote.checkpoint_hash != self.checkpoint_hash {
            return Err("Precommit checkpoint hash mismatch".into());
        }

        if self.precommits.contains_key(&vote.voter_id) {
            return Err("Duplicate precommit".into());
        }

        self.precommits.insert(vote.voter_id, vote);
        self.check_precommit_quorum();
        Ok(())
    }

    /// Detect a prevote that conflicts (different checkpoint hash) with an
    /// Earlier validly-signed prevote from the same voter, and package the two
    /// Signatures into a canonical [`SlashingReport`]. Deduplicated per voter.
    fn detect_prevote_equivocation(&mut self, vote: &Prevote) {
        match self.seen_prevotes.get(&vote.voter_id) {
            Some((prev_hash, prev_sig)) if prev_hash != &vote.checkpoint_hash => {
                self.record_equivocation(
                    vote.voter_id,
                    (prev_hash.clone(), prev_sig.clone()),
                    (vote.checkpoint_hash.clone(), vote.sig_bls.clone()),
                    crate::registry::evidence::DoubleSignKind::Prevote,
                    vote.epoch,
                );
            }
            Some(_) => { /* same hash: not equivocation (duplicate handled later) */ }
            None => {
                self.seen_prevotes.insert(
                    vote.voter_id,
                    (vote.checkpoint_hash.clone(), vote.sig_bls.clone()),
                );
            }
        }
    }

    /// Precommit counterpart of [`Self::detect_prevote_equivocation`].
    fn detect_precommit_equivocation(&mut self, vote: &Precommit) {
        match self.seen_precommits.get(&vote.voter_id) {
            Some((prev_hash, prev_sig)) if prev_hash != &vote.checkpoint_hash => {
                self.record_equivocation(
                    vote.voter_id,
                    (prev_hash.clone(), prev_sig.clone()),
                    (vote.checkpoint_hash.clone(), vote.sig_bls.clone()),
                    crate::registry::evidence::DoubleSignKind::Precommit,
                    vote.epoch,
                );
            }
            Some(_) => {}
            None => {
                self.seen_precommits.insert(
                    vote.voter_id,
                    (vote.checkpoint_hash.clone(), vote.sig_bls.clone()),
                );
            }
        }
    }

    /// Build and queue a consensus-verified double-sign report for `voter`.
    /// Deduplicated: one report per voter for the lifetime of this aggregator
    /// (a single actionable report is enough - the registry jails on it).
    ///
    /// Provenance is [`ProofProvenance::ConsensusVerified`](crate::registry::ProofProvenance)
    /// Because BOTH signatures were verified at ingest against the voter's BLS
    /// Key from the validator snapshot - the aggregator has full context to
    /// Prove the double-sign, so no re-verification is needed downstream.
    fn record_equivocation(
        &mut self,
        voter: Address,
        (hash_1, sig_1): (String, Vec<u8>),
        (hash_2, sig_2): (String, Vec<u8>),
        kind: crate::registry::evidence::DoubleSignKind,
        epoch: u64,
    ) {
        if !self.flagged_equivocators.insert(voter) {
            return;
        }
        let report = SlashingReport::consensus_double_sign(
            voter,
            crate::registry::evidence::SlashingProof::DoubleSign {
                height: self.checkpoint_height,
                // BLG-0196 (P10-F06): the kind and the epoch travel with the
                // evidence so any third party can rebuild the signed root and
                // re-open both signatures; a report that stands only on the
                // local ConsensusVerified label is not a proof.
                kind,
                epoch: Some(epoch),
                block_hash_1: hash_1,
                block_hash_2: hash_2,
                signature_1: sig_1,
                signature_2: sig_2,
            },
            None,
        );
        self.detected_equivocations.push(report);
    }

    fn check_prevote_quorum(&mut self) {
        let snapshot = &self.validator_snapshot;
        let mut voted_stake: u128 = 0;
        let mut voted_count: usize = 0;
        for validator in self
            .prevotes
            .keys()
            .filter_map(|addr| snapshot.find_validator(addr))
        {
            voted_stake += u128::from(validator.stake);
            voted_count += 1;
        }
        if voted_stake >= snapshot.quorum_stake() && voted_count >= snapshot.quorum_count() {
            self.prevote_quorum_reached = true;
        }
    }

    fn check_precommit_quorum(&mut self) {
        let snapshot = &self.validator_snapshot;
        let mut voted_stake: u128 = 0;
        let mut voted_count: usize = 0;
        for validator in self
            .precommits
            .keys()
            .filter_map(|addr| snapshot.find_validator(addr))
        {
            voted_stake += u128::from(validator.stake);
            voted_count += 1;
        }
        if voted_stake >= snapshot.quorum_stake() && voted_count >= snapshot.quorum_count() {
            self.precommit_quorum_reached = true;
        }
    }

    pub fn try_produce_cert(&self) -> Option<FinalityCert> {
        if !self.precommit_quorum_reached {
            return None;
        }

        let snapshot = &self.validator_snapshot;

        let mut bitmap = vec![0u8; snapshot.validators.len().div_ceil(8)];
        let mut agg_sig = G1Projective::identity();

        for (addr, precommit) in &self.precommits {
            if let Some(idx) = snapshot.validator_index(addr) {
                // The bit is set only once the signature is in the aggregate:
                // a claimed signer whose contribution is missing makes the
                // pairing fail with no diagnostic. Every recorded precommit
                // was verified at ingest, so neither branch fires in
                // practice, but the certificate must stay consistent if it
                // ever does.
                let Ok(sig_bytes) = <[u8; 48]>::try_from(precommit.sig_bls.as_slice()) else {
                    continue;
                };
                let Some(sig_affine) = G1Affine::from_compressed(&sig_bytes).into_option() else {
                    continue;
                };
                agg_sig += G1Projective::from(sig_affine);
                bitmap[idx / 8] |= 1 << (idx % 8);
            }
        }

        // The certificate commits to the chain its precommits were signed
        // for, so it is taken from those votes rather than assumed: every
        // precommit that reached this aggregator passed the chain check, and
        // a hardcoded id here would silently diverge on any other network.
        let chain_id = self
            .precommits
            .values()
            .next()
            .map_or(0, |precommit| precommit.chain_id);
        Some(FinalityCert {
            chain_id,
            epoch: self.epoch,
            checkpoint_height: self.checkpoint_height,
            checkpoint_hash: self.checkpoint_hash.clone(),
            agg_sig_bls: G1Affine::from(agg_sig).to_compressed().to_vec(),
            bitmap,
            set_hash: snapshot.set_hash.clone(),
        })
    }

    pub fn get_state(&self) -> AggregatorState {
        AggregatorState {
            active: true,
            epoch: self.epoch,
            checkpoint_height: self.checkpoint_height,
            checkpoint_hash: self.checkpoint_hash.clone(),
            prevote_quorum_reached: self.prevote_quorum_reached,
            precommit_quorum_reached: self.precommit_quorum_reached,
            prevote_count: self.prevotes.len(),
            precommit_count: self.precommits.len(),
        }
    }
}

impl FinalityCert {
    pub fn verify(&self, snapshot: &ValidatorSetSnapshot) -> Result<(), String> {
        if self
            .epoch
            .checked_sub(BLS_RFC9380_ACTIVATION_EPOCH)
            .is_none()
        {
            return Err(
                "Pre-activation BLS certificates are historical records and cannot be applied to live finality"
                    .into(),
            );
        }
        if self.set_hash != snapshot.set_hash {
            return Err("Validator set hash mismatch".into());
        }
        if self.epoch != snapshot.epoch {
            return Err("Epoch mismatch".into());
        }

        // The bitmap has one canonical shape per snapshot. Padding bytes or
        // out-of-range bits do not change the pairing, but they make
        // byte-distinct certificates for one checkpoint, and `FinalityCert`
        // is compared and stored by value.
        let expected_bitmap_len = snapshot.validators.len().div_ceil(8);
        if self.bitmap.len() != expected_bitmap_len {
            return Err(format!(
                "Non-canonical finality certificate bitmap length: {} bytes, expected {}",
                self.bitmap.len(),
                expected_bitmap_len
            ));
        }
        let trailing_bits = snapshot.validators.len() % 8;
        if trailing_bits != 0 {
            if let Some(last) = self.bitmap.last() {
                if last >> trailing_bits != 0 {
                    return Err("Finality certificate bitmap has out-of-range signer bits".into());
                }
            }
        }

        let mut voted_stake: u128 = 0;
        let mut voted_count: usize = 0;
        let mut signers_pks = Vec::new();
        for (idx, validator) in snapshot.validators.iter().enumerate() {
            let byte_idx = idx / 8;
            let bit_idx = idx % 8;
            if (self.bitmap[byte_idx] & (1 << bit_idx)) != 0 {
                voted_stake += u128::from(validator.stake);
                voted_count += 1;

                let pk_bytes: [u8; 96] =
                    validator
                        .bls_public_key
                        .as_slice()
                        .try_into()
                        .map_err(|_| {
                            format!("Invalid BLS public key length for {}", validator.address)
                        })?;
                let pk = G2Affine::from_compressed(&pk_bytes)
                    .into_option()
                    .ok_or_else(|| {
                        format!("Invalid BLS public key encoding for {}", validator.address)
                    })?;
                // (security audit §5) subgroup check on
                // Every bitmap-claimed signer (see `verify_bls_sig`
                // For the full rationale). Without this, a
                // Malicious snapshot could insert a small-subgroup
                // Public key that would silently contribute to the
                // Aggregate without actually representing a real
                // Stake holder.
                let is_on_curve: bool = pk.is_torsion_free().into();
                if !is_on_curve || bool::from(pk.is_identity()) {
                    return Err(format!(
                        "Bitmap signer {} has an identity key or a key outside the prime-order subgroup",
                        validator.address
                    ));
                }
                signers_pks.push(G2Projective::from(pk));
            }
        }

        if voted_stake < snapshot.quorum_stake() {
            return Err(format!(
                "Insufficient quorum: {} < {} (need {}/{})",
                voted_stake,
                snapshot.quorum_stake(),
                FINALITY_QUORUM_NUMERATOR,
                FINALITY_QUORUM_DENOMINATOR
            ));
        }

        if voted_count < snapshot.quorum_count() {
            return Err(format!(
                "Insufficient signer count quorum: {} < {} (need {}/{})",
                voted_count,
                snapshot.quorum_count(),
                FINALITY_QUORUM_NUMERATOR,
                FINALITY_QUORUM_DENOMINATOR
            ));
        }

        if signers_pks.is_empty() {
            return Err("No signers in bitmap".into());
        }

        // Aggregate Public Keys
        let mut agg_pk = G2Projective::identity();
        for pk in signers_pks {
            agg_pk += pk;
        }
        let agg_pk_affine = G2Affine::from(agg_pk);
        if bool::from(agg_pk_affine.is_identity()) {
            return Err("Aggregated BLS public key is identity".into());
        }

        // Parse Aggregated Signature
        let sig_bytes: [u8; 48] = self
            .agg_sig_bls
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid aggregated BLS signature length".to_string())?;
        let sig_affine = G1Affine::from_compressed(&sig_bytes)
            .into_option()
            .ok_or_else(|| "Invalid aggregated BLS signature encoding".to_string())?;
        if bool::from(sig_affine.is_identity()) {
            return Err("Aggregated BLS signature is identity".into());
        }

        // Hash message to G1
        let msg = self.signing_message();
        let h_msg = hash_to_g1(&msg);

        // Verify pairing: e(sig, G2_gen) == e(H(msg), agg_pk)
        // Which is equivalent to: e(sig, -G2_gen) + e(H(msg), agg_pk) == 0 (identity)
        let g2_gen_neg = -G2Affine::generator();

        let pairing_result = bls12_381::multi_miller_loop(&[
            (&sig_affine, &g2_gen_neg.into()),
            (&h_msg, &agg_pk_affine.into()),
        ])
        .final_exponentiation();

        if pairing_result != bls12_381::Gt::identity() {
            return Err("BLS aggregate signature verification failed".into());
        }

        Ok(())
    }

    pub fn signing_message(&self) -> Vec<u8> {
        checkpoint_signing_message(
            self.chain_id,
            self.epoch,
            self.checkpoint_height,
            &self.checkpoint_hash,
        )
    }

    pub fn signer_count(&self, validator_count: usize) -> usize {
        let mut count = 0;
        for idx in 0..validator_count {
            let byte_idx = idx / 8;
            let bit_idx = idx % 8;
            if byte_idx < self.bitmap.len() && (self.bitmap[byte_idx] & (1 << bit_idx)) != 0 {
                count += 1;
            }
        }
        count
    }

    pub fn signer_indices(&self, validator_count: usize) -> Vec<usize> {
        let mut indices = Vec::new();
        for idx in 0..validator_count {
            let byte_idx = idx / 8;
            let bit_idx = idx % 8;
            if byte_idx < self.bitmap.len() && (self.bitmap[byte_idx] & (1 << bit_idx)) != 0 {
                indices.push(idx);
            }
        }
        indices
    }
}

#[cfg(test)]
mod tests {

    /// The bytes the Mikoriza slasher (`contracts/mikoriza/BudlumSlasher.sol`)
    /// verifies must be the bytes this node signs. The Solidity test
    /// `test_the_slasher_signs_the_rust_checkpoint_message` asserts the same
    /// literal, so a change to the domain, the scheme name or the field order
    /// on either side fails the other side's test instead of silently
    /// stranding every restaked operator.
    #[test]
    fn the_checkpoint_preimage_is_the_one_the_slasher_golden_vector_pins() {
        let message = checkpoint_signing_message(45_261, 3, 40, "ab");
        assert_eq!(
            hex::encode(&message),
            "4255444c554d5f505245434f4d4d49545f5632424c535f5349475f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f504f505fcdb0000000000000030000000000000028000000000000006162"
        );
    }
    use super::*;

    fn make_test_key(seed: u8) -> (Scalar, Vec<u8>, Vec<u8>) {
        let mut sk_bytes = [0u8; 64];
        sk_bytes[0] = seed + 1;
        let sk = Scalar::from_bytes_wide(&sk_bytes);

        let pk = G2Affine::from(G2Projective::generator() * sk);
        let pk_compressed = pk.to_compressed().to_vec();

        (sk, pk_compressed, vec![])
    }

    fn sign_msg(sk: Scalar, msg: &[u8]) -> Vec<u8> {
        let h_msg = hash_to_g1(msg);
        let sig = G1Affine::from(G1Projective::from(h_msg) * sk);
        sig.to_compressed().to_vec()
    }

    fn legacy_hash_scalar(msg: &[u8]) -> Scalar {
        let mut hasher_lo = Sha3_256::new();
        hasher_lo.update(b"BUDLUM_BLS_SIG_DST_LO");
        hasher_lo.update(msg);
        let h_lo = hasher_lo.finalize();

        let mut hasher_hi = Sha3_256::new();
        hasher_hi.update(b"BUDLUM_BLS_SIG_DST_HI");
        hasher_hi.update(msg);
        let h_hi = hasher_hi.finalize();

        let mut scalar_bytes = [0u8; 64];
        scalar_bytes[..32].copy_from_slice(&h_lo);
        scalar_bytes[32..].copy_from_slice(&h_hi);
        Scalar::from_bytes_wide(&scalar_bytes)
    }

    #[test]
    fn rfc9380_bls12381g1_sha256_vector_matches() {
        // RFC 9380 Appendix J.9.1, msg="", random-oracle suite.
        let expected = concat!(
            "052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4",
            "e8cf62d9c09db0fac349612b759e79a108ba738453bfed09cb546dbb0783dbb3",
            "a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265"
        );
        let point = <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
            std::iter::once(&b""[..]),
            b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_",
        );
        assert_eq!(
            hex::encode(G1Affine::from(point).to_uncompressed()),
            expected
        );
    }

    #[test]
    fn legacy_scalar_ratio_forgery_is_rejected_by_rfc9380_verifier() {
        let msg_a = b"checkpoint-a";
        let msg_b = b"checkpoint-b";
        let scalar_a = legacy_hash_scalar(msg_a);
        let scalar_b = legacy_hash_scalar(msg_b);
        let inverse_a = Option::<Scalar>::from(scalar_a.invert()).expect("non-zero test scalar");

        let mut sk_bytes = [0u8; 64];
        sk_bytes[0] = 42;
        let sk = Scalar::from_bytes_wide(&sk_bytes);
        let pk = G2Affine::from(G2Projective::generator() * sk)
            .to_compressed()
            .to_vec();

        let legacy_sig_a = G1Projective::generator() * scalar_a * sk;
        let forged_legacy_sig_b = legacy_sig_a * (scalar_b * inverse_a);
        let expected_legacy_sig_b = G1Projective::generator() * scalar_b * sk;
        assert_eq!(forged_legacy_sig_b, expected_legacy_sig_b);

        let forged = G1Affine::from(forged_legacy_sig_b).to_compressed().to_vec();
        assert!(verify_bls_sig(&pk, msg_b, &forged).is_err());
    }

    /// Build a validly-signed prevote for validator `i` in the snapshot.
    fn signed_prevote(
        snap: &ValidatorSetSnapshot,
        sks: &[Scalar],
        i: usize,
        epoch: u64,
        height: u64,
        hash: &str,
    ) -> Prevote {
        let mut v = Prevote {
            chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
            epoch,
            checkpoint_height: height,
            checkpoint_hash: hash.to_string(),
            voter_id: snap.validators[i].address,
            sig_bls: vec![],
            auth_sig: Vec::new(),
        };
        v.sig_bls = sign_msg(sks[i], &v.signing_message());
        v
    }

    fn make_snapshot_with_keys(n: usize, stake_each: u64) -> (ValidatorSetSnapshot, Vec<Scalar>) {
        let mut sks = Vec::new();
        let validators: Vec<ValidatorEntry> = (0..n)
            .map(|i| {
                let (sk, pk_bytes, _) = make_test_key(i as u8);
                sks.push(sk);
                let mut addr_bytes = [0u8; 32];
                addr_bytes[0] = (i + 1) as u8;
                let addr = Address::from(addr_bytes);

                let pop_msg = pop_signing_message(
                    crate::core::transaction::DEFAULT_CHAIN_ID,
                    &addr,
                    &pk_bytes,
                );
                let pop_sig = sign_bls_pop(&sk, &pop_msg);

                ValidatorEntry {
                    address: addr,
                    stake: stake_each,
                    bls_public_key: pk_bytes,
                    pop_signature: pop_sig,
                    pq_public_key: Vec::new(),
                }
            })
            .collect();
        (ValidatorSetSnapshot::new(1, validators), sks)
    }

    #[test]
    fn test_validator_set_snapshot() {
        let (snap, _) = make_snapshot_with_keys(4, 1000);
        assert_eq!(snap.total_stake, 4000);
        assert_eq!(snap.quorum_stake(), 2667);
        assert_eq!(snap.quorum_count(), 3);
    }

    #[test]
    fn validator_set_hash_binds_pop_keys() {
        let (snapshot, _) = make_snapshot_with_keys(1, 1_000);
        let mut changed_pop = snapshot.validators.clone();
        changed_pop[0].pop_signature[0] ^= 1;
        assert_ne!(
            snapshot.set_hash,
            ValidatorSetSnapshot::compute_hash(&changed_pop)
        );
    }

    #[test]
    fn test_verify_pop() {
        let (snap, _) = make_snapshot_with_keys(1, 1000);
        assert!(verify_pop(
            &snap.validators[0],
            crate::core::transaction::DEFAULT_CHAIN_ID,
        ));

        let mut invalid = snap.validators[0].clone();
        invalid.pop_signature[0] ^= 0xFF;
        assert!(!verify_pop(
            &invalid,
            crate::core::transaction::DEFAULT_CHAIN_ID,
        ));
    }

    #[test]
    fn test_checkpoint_height() {
        assert!(!is_checkpoint_height(0));
        assert!(is_checkpoint_height(10));
    }

    #[test]
    fn test_prevote_signing_message() {
        let vote = Prevote {
            chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
            epoch: 1,
            checkpoint_height: 10,
            checkpoint_hash: "abc".into(),
            voter_id: Address::zero(),
            sig_bls: vec![],
            auth_sig: Vec::new(),
        };
        let msg = vote.signing_message();
        assert!(msg.starts_with(b"BUDLUM_PREVOTE_V2"));
    }

    #[test]
    fn test_aggregator_prevote_flow() {
        let (snap, sks) = make_snapshot_with_keys(4, 1000);
        let mut agg = FinalityAggregator::new(1, 10, "cp_hash".into(), snap.clone());

        for i in 0..3 {
            let vote = signed_prevote(&snap, &sks, i, 1, 10, "cp_hash");
            agg.add_prevote(vote).unwrap();
        }
        assert!(agg.prevote_quorum_reached);
    }

    #[test]
    fn test_aggregator_rejects_duplicate() {
        let (snap, sks) = make_snapshot_with_keys(4, 1000);
        let mut agg = FinalityAggregator::new(1, 10, "cp_hash".into(), snap.clone());

        let vote = signed_prevote(&snap, &sks, 0, 1, 10, "cp_hash");
        agg.add_prevote(vote.clone()).unwrap();
        assert!(agg.add_prevote(vote).is_err());
    }

    #[test]
    fn test_aggregator_rejects_wrong_epoch() {
        let (snap, sks) = make_snapshot_with_keys(4, 1000);
        let mut agg = FinalityAggregator::new(1, 10, "cp_hash".into(), snap.clone());

        // Wrong epoch: rejected before signature check.
        let vote = signed_prevote(&snap, &sks, 0, 99, 10, "cp_hash");
        assert!(agg.add_prevote(vote).is_err());
    }

    #[test]
    fn test_aggregator_rejects_invalid_signature() {
        // (Option A) a garbage signature is rejected AT INGEST and
        // Never enters the aggregate.
        let (snap, _) = make_snapshot_with_keys(4, 1000);
        let mut agg = FinalityAggregator::new(1, 10, "cp_hash".into(), snap.clone());

        let vote = Prevote {
            chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
            epoch: 1,
            checkpoint_height: 10,
            checkpoint_hash: "cp_hash".into(),
            voter_id: snap.validators[0].address,
            sig_bls: vec![0u8; 48], // not a valid BLS signature
            auth_sig: Vec::new(),
        };
        let err = agg
            .add_prevote(vote)
            .expect_err("garbage sig must be rejected");
        assert!(err.contains("Invalid prevote signature"), "got: {err}");
        assert_eq!(agg.prevotes.len(), 0);
    }

    #[test]
    fn test_precommit_requires_prevote_quorum() {
        let (snap, sks) = make_snapshot_with_keys(4, 1000);
        let mut agg = FinalityAggregator::new(1, 10, "cp_hash".into(), snap.clone());

        // No prevote quorum yet: rejected before signature check.
        let pc = Precommit {
            chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
            epoch: 1,
            checkpoint_height: 10,
            checkpoint_hash: "cp_hash".into(),
            voter_id: snap.validators[0].address,
            sig_bls: sign_msg(
                sks[0],
                &checkpoint_signing_message(
                    crate::core::transaction::DEFAULT_CHAIN_ID,
                    1,
                    10,
                    "cp_hash",
                ),
            ),
            auth_sig: Vec::new(),
        };
        assert!(agg.add_precommit(pc).is_err());
    }

    #[test]
    fn test_full_finality_flow() {
        let (snap, sks) = make_snapshot_with_keys(4, 1000);
        let mut agg = FinalityAggregator::new(1, 10, "cp_hash".into(), snap.clone());

        for i in 0..3 {
            let vote = signed_prevote(&snap, &sks, i, 1, 10, "cp_hash");
            agg.add_prevote(vote).unwrap();
        }
        assert!(agg.prevote_quorum_reached);

        let mut agg_sig = G1Projective::identity();
        for (i, sk) in sks.iter().enumerate().take(3) {
            let pc = Precommit {
                chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
                epoch: 1,
                checkpoint_height: 10,
                checkpoint_hash: "cp_hash".into(),
                voter_id: snap.validators[i].address,
                sig_bls: vec![],
                auth_sig: Vec::new(),
            };

            let sig_bytes = sign_msg(*sk, &pc.signing_message());
            let mut pc_signed = pc;
            pc_signed.sig_bls = sig_bytes.clone();

            agg.add_precommit(pc_signed).unwrap();

            let sig_affine = G1Affine::from_compressed(&sig_bytes.try_into().unwrap()).unwrap();
            agg_sig += G1Projective::from(sig_affine);
        }
        assert!(agg.precommit_quorum_reached);

        let mut cert = agg.try_produce_cert().expect("Should produce cert");
        cert.agg_sig_bls = G1Affine::from(agg_sig).to_compressed().to_vec();

        assert_eq!(cert.epoch, 1);
        assert_eq!(cert.checkpoint_height, 10);
        assert_eq!(cert.checkpoint_hash, "cp_hash");
        assert_eq!(cert.set_hash, snap.set_hash);
        assert_eq!(cert.signer_count(4), 3);

        assert!(cert.verify(&snap).is_ok());

        // The same signers with a padded bitmap or an out-of-range bit are a
        // different byte string for the same checkpoint; refused as
        // non-canonical rather than accepted as a second valid certificate.
        let mut padded = cert.clone();
        padded.bitmap.push(0);
        assert!(padded.verify(&snap).unwrap_err().contains("bitmap length"));
        let mut stray = cert.clone();
        stray.bitmap[0] |= 1 << 4; // validator index 4 does not exist in a set of 4
        assert!(stray.verify(&snap).unwrap_err().contains("out-of-range"));
    }

    /// The quorum is measured against the exact stake sum, not the
    /// saturated `total_stake` summary.
    ///
    /// Two validators of `2^63` each add up to `2^64`, one past `u64::MAX`.
    /// The summary saturates; the threshold does not, and a single signer
    /// holding half the stake stays below it. With `[MAX, MAX, 1, 1, 1, 1]`
    /// the saturated comparison let four signers holding `MAX + 3` of a real
    /// `2 * MAX + 4` finalize as `MAX >= MAX`; the exact one refuses them and
    /// accepts the four that really hold more than two thirds.
    #[test]
    fn quorum_stake_is_exact_past_the_u64_range() {
        let (snap, _) = make_snapshot_with_keys(2, u64::MAX / 2 + 1);
        assert_eq!(snap.total_stake, u64::MAX, "the summary saturates");
        assert_eq!(snap.stake_sum(), 1u128 << 64);
        assert_eq!(snap.quorum_stake(), 12_297_829_382_473_034_411);
        assert!(u128::from(snap.validators[0].stake) < snap.quorum_stake());

        let stakes = [u64::MAX, u64::MAX, 1, 1, 1, 1];
        let validators: Vec<ValidatorEntry> = stakes
            .iter()
            .enumerate()
            .map(|(i, stake)| {
                let (_, pk_bytes, _) = make_test_key(i as u8);
                let mut addr_bytes = [0u8; 32];
                addr_bytes[0] = (i + 1) as u8;
                ValidatorEntry {
                    address: Address::from(addr_bytes),
                    stake: *stake,
                    bls_public_key: pk_bytes,
                    pop_signature: Vec::new(),
                    pq_public_key: Vec::new(),
                }
            })
            .collect();
        let snap = ValidatorSetSnapshot::new(1, validators);
        let real_total = 2 * u128::from(u64::MAX) + 4;
        assert_eq!(snap.stake_sum(), real_total);
        assert_eq!(snap.quorum_stake(), real_total * 2 / 3 + 1);
        let minority = u128::from(u64::MAX) + 3;
        assert!(
            minority < snap.quorum_stake(),
            "MAX + 3 is a third, not two"
        );
        let majority = 2 * u128::from(u64::MAX) + 2;
        assert!(majority >= snap.quorum_stake());

        let (small, _) = make_snapshot_with_keys(3, 1000);
        assert_eq!(small.quorum_stake(), 2001);
    }

    #[test]
    fn test_cert_verify_rejects_insufficient_quorum() {
        let (snap, sks) = make_snapshot_with_keys(4, 1000);
        let pc = Precommit {
            chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
            epoch: 1,
            checkpoint_height: 10,
            checkpoint_hash: "cp_hash".into(),
            voter_id: snap.validators[0].address,
            sig_bls: vec![],
            auth_sig: Vec::new(),
        };
        let sig_bytes = sign_msg(sks[0], &pc.signing_message());

        let cert = FinalityCert {
            chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
            epoch: 1,
            checkpoint_height: 10,
            checkpoint_hash: "cp_hash".into(),
            agg_sig_bls: sig_bytes,
            bitmap: vec![0b0000_0001],
            set_hash: snap.set_hash.clone(),
        };
        let result = cert.verify(&snap);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Insufficient quorum"));
    }

    /// The bounded harness in `kani/src/lib.rs` proves facts about
    /// `bitmap_voted_stake`, a copy of the walk in `FinalityCert::verify`.
    /// This test holds the copy and production in step: for every bitmap over
    /// a four validator set it compares the copy's sum with the stake that
    /// `verify` reports, including stakes that overflow a `u64` when added.
    #[test]
    fn bitmap_stake_accounting_matches_the_kani_mirror() {
        // Mirrors `kani/src/lib.rs::bitmap_voted_stake`, kept literal on purpose.
        fn kani_mirror(stakes: &[u64; 4], n: usize, bitmap: &[u8; 1]) -> u128 {
            let mut voted_stake: u128 = 0;
            let mut idx = 0;
            while idx < n {
                let byte_idx = idx / 8;
                let bit_idx = idx % 8;
                if byte_idx < bitmap.len() && (bitmap[byte_idx] & (1 << bit_idx)) != 0 {
                    voted_stake += u128::from(stakes[idx]);
                }
                idx += 1;
            }
            voted_stake
        }

        let stakes = [u64::MAX, u64::MAX - 7, 5, 1];
        let (base, _) = make_snapshot_with_keys(4, 1);
        let validators: Vec<ValidatorEntry> = base
            .validators
            .iter()
            .zip(stakes)
            .map(|(v, stake)| ValidatorEntry { stake, ..v.clone() })
            .collect();
        let snap = ValidatorSetSnapshot::new(1, validators);
        let quorum = snap.quorum_stake();

        for bits in 1u8..16 {
            let cert = FinalityCert {
                chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
                epoch: 1,
                checkpoint_height: 10,
                checkpoint_hash: "cp_hash".into(),
                agg_sig_bls: vec![0u8; 48],
                bitmap: vec![bits],
                set_hash: snap.set_hash.clone(),
            };
            let mirrored = kani_mirror(&stakes, 4, &[bits]);
            let err = cert
                .verify(&snap)
                .expect_err("an unsigned certificate never verifies");
            if mirrored < quorum {
                assert!(
                    err.starts_with(&format!("Insufficient quorum: {mirrored} <")),
                    "bitmap {bits:#06b}: verify reported {err}, the mirror sums {mirrored}"
                );
            } else {
                assert!(
                    !err.starts_with("Insufficient quorum"),
                    "bitmap {bits:#06b}: the mirror reaches quorum but verify said {err}"
                );
            }
        }
    }

    #[test]
    fn finality_cert_requires_validator_count_quorum_even_with_large_stake() {
        let mut sks = Vec::new();
        let stakes = [4_000u64, 1, 1, 1];
        let validators: Vec<ValidatorEntry> = stakes
            .iter()
            .enumerate()
            .map(|(i, stake)| {
                let (sk, pk_bytes, _) = make_test_key(i as u8);
                sks.push(sk);
                let mut addr_bytes = [0u8; 32];
                addr_bytes[0] = (i + 1) as u8;
                let addr = Address::from(addr_bytes);
                let pop_msg = pop_signing_message(
                    crate::core::transaction::DEFAULT_CHAIN_ID,
                    &addr,
                    &pk_bytes,
                );
                ValidatorEntry {
                    address: addr,
                    stake: *stake,
                    bls_public_key: pk_bytes,
                    pop_signature: sign_bls_pop(&sk, &pop_msg),
                    pq_public_key: Vec::new(),
                }
            })
            .collect();
        let snap = ValidatorSetSnapshot::new(1, validators);
        assert!(u128::from(snap.validators[0].stake) >= snap.quorum_stake());
        assert_eq!(snap.quorum_count(), 3);

        let pc = Precommit {
            chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
            epoch: 1,
            checkpoint_height: 10,
            checkpoint_hash: "cp_hash".into(),
            voter_id: snap.validators[0].address,
            sig_bls: vec![],
            auth_sig: Vec::new(),
        };
        let sig_bytes = sign_msg(sks[0], &pc.signing_message());
        let cert = FinalityCert {
            chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
            epoch: 1,
            checkpoint_height: 10,
            checkpoint_hash: "cp_hash".into(),
            agg_sig_bls: sig_bytes,
            bitmap: vec![0b0000_0001],
            set_hash: snap.set_hash.clone(),
        };

        let err = cert
            .verify(&snap)
            .expect_err("count quorum must be enforced");
        assert!(
            err.contains("Insufficient signer count quorum"),
            "got: {err}"
        );
    }

    #[test]
    fn test_cert_verify_rejects_wrong_set_hash() {
        let (snap, _) = make_snapshot_with_keys(4, 1000);
        let cert = FinalityCert {
            chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
            epoch: 1,
            checkpoint_height: 10,
            checkpoint_hash: "cp_hash".into(),
            agg_sig_bls: vec![1; 48],
            bitmap: vec![0b0000_1111],
            set_hash: "wrong_hash".into(),
        };
        let result = cert.verify(&snap);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("set hash mismatch"));
    }

    /// A genuine on-curve small-subgroup G2 encoding (BLG-0200 / P10-F10).
    ///
    /// Perturbs the payload bytes of the canonical generator encoding until
    /// one decodes to a curve point that is NOT in the prime-order subgroup.
    /// That point is the actual attack object: it survives the decoder, so
    /// only the torsion gate can stop it. All-zero or non-decodable blobs -
    /// what the older test fed in - merely exercise the decoder.
    fn small_subgroup_g2_encoding() -> [u8; 96] {
        let base = G2Affine::generator().to_compressed();
        for i in 1..96usize {
            for delta in 1u8..=12u8 {
                let mut cand = base;
                cand[i] = cand[i].wrapping_add(delta);
                // bls12_381 0.9's `from_compressed` guarantees subgroup
                // membership, so the attack object can only be materialized
                // through the unchecked decoder (which still checks the
                // curve equation). The point of the test stands: these BYTES
                // decode to an on-curve point outside the prime-order
                // subgroup, and whatever production decodes them must refuse.
                if let Some(p) = G2Affine::from_compressed_unchecked(&cand).into_option() {
                    if bool::from(p.is_on_curve())
                        && !bool::from(p.is_identity())
                        && !bool::from(p.is_torsion_free())
                    {
                        return cand;
                    }
                }
            }
        }
        panic!("payload perturbations produced no on-curve non-torsion-free G2 point")
    }

    /// (security audit §5) `verify_bls_sig` must reject
    /// Public keys and signatures that are not in the prime-order
    /// Subgroup. Without the subgroup check an attacker can supply
    /// A small-subgroup point as the public key, which makes the
    /// Pairing check trivially pass for any message.
    #[test]
    fn verify_bls_sig_rejects_subgroup_attack_on_public_key() {
        // All-zero G2 compressed bytes do NOT decode (BLS12-381
        // Uses a special flag for the identity), so this confirms
        // The trivial identity-point attack stays blocked even
        // After the subgroup check was added.
        let zero_pk = [0u8; 96];
        let sk_bytes = [7u8; 64];
        let sk = Scalar::from_bytes_wide(&sk_bytes);
        let msg = b"test_message";
        let sig = sign_msg(sk, msg);
        let result = verify_bls_sig(&zero_pk, msg, &sig);
        assert!(
            result.is_err(),
            "all-zero (non-decodable) public key must be rejected"
        );

        let identity_pk = G2Affine::identity().to_compressed();
        let identity_sig = G1Affine::identity().to_compressed();
        assert!(
            verify_bls_sig(&identity_pk, msg, &identity_sig).is_err(),
            "identity key/signature encodings must be rejected"
        );

        // Sanity: a valid pubkey+sig still passes after the
        // Subgroup check was added (the existing test suite covers
        // Many such cases, this is just a smoke test that the new
        // Check is wired in without breaking the happy path).
        let (sk2, pk2, _) = make_test_key(42);
        let msg2 = b"another_message";
        let sig2 = sign_msg(sk2, msg2);
        assert!(
            verify_bls_sig(&pk2, msg2, &sig2).is_ok(),
            "valid pubkey+sig must pass the new subgroup check"
        );

        // BLG-0200 (P10-F10): the case the check exists for - a small-subgroup
        // point that DECODES. A pairing with it collapses to a subgroup that
        // verifies against any message, so the gate must reject it by name.
        let attack_pk = small_subgroup_g2_encoding();
        let err = verify_bls_sig(&attack_pk, msg2, &sig2)
            .expect_err("on-curve small-subgroup key must be rejected");
        assert!(
            err.contains("subgroup"),
            "small-subgroup key must fail with the subgroup rejection, got: {err}"
        );
    }

    /// (security audit §5) `verify_pop` must reject PoP
    /// Entries whose public key is not in the prime-order
    /// Subgroup. The same subgroup check that protects
    /// `verify_bls_sig` must protect `verify_pop`, otherwise a
    /// Malicious validator could register a small-subgroup public
    /// Key, get it through the PoP gate, and then use it to make
    /// Votes aggregate against a forged finality certificate.
    #[test]
    fn verify_pop_rejects_subgroup_attack_on_public_key() {
        // An entry whose BLS public key is all-zero bytes (which
        // Does not decode to a valid G2 point) must be rejected.
        // This protects against the trivial identity-point attack.
        let entry = ValidatorEntry {
            address: Address::from([1u8; 32]),
            stake: 1000,
            bls_public_key: vec![0u8; 96],
            pop_signature: vec![0u8; 48],
            pq_public_key: Vec::new(),
        };
        assert!(
            !verify_pop(&entry, crate::core::transaction::DEFAULT_CHAIN_ID),
            "verify_pop must reject an entry with a non-decodable BLS public key"
        );

        let identity_entry = ValidatorEntry {
            address: Address::from([2u8; 32]),
            stake: 1000,
            bls_public_key: G2Affine::identity().to_compressed().to_vec(),
            pop_signature: G1Affine::identity().to_compressed().to_vec(),
            pq_public_key: Vec::new(),
        };
        assert!(
            !verify_pop(&identity_entry, crate::core::transaction::DEFAULT_CHAIN_ID,),
            "verify_pop must reject identity key/signature encodings"
        );

        // BLG-0200 (P10-F10): the case the gate exists for. Both encodings
        // below decode to valid points, so a rejection can only come from the
        // torsion check - exactly the branch that stops a validator from
        // registering a small-subgroup key and farming trivially-passing
        // aggregates.
        let attack_pk = small_subgroup_g2_encoding();
        let attack_entry = ValidatorEntry {
            address: Address::from([3u8; 32]),
            stake: 1000,
            bls_public_key: attack_pk.to_vec(),
            pop_signature: G1Affine::generator().to_compressed().to_vec(),
            pq_public_key: Vec::new(),
        };
        let attack_point = G2Affine::from_compressed_unchecked(&attack_pk)
            .into_option()
            .expect("the attack key must survive decoding, or the test proves nothing");
        assert!(
            bool::from(attack_point.is_on_curve()) && !bool::from(attack_point.is_torsion_free()),
            "the attack key must be an on-curve point outside the prime-order subgroup"
        );
        assert!(
            !verify_pop(&attack_entry, crate::core::transaction::DEFAULT_CHAIN_ID),
            "verify_pop must reject an on-curve key outside the prime-order subgroup"
        );
    }

    /// A checkpoint signature must not verify on another network.
    ///
    /// The preimage commits to the chain id as its own fixed-width field, so
    /// two votes over the same epoch, height and checkpoint hash still differ
    /// when they were signed for two different chains. The block hash keeps
    /// folding `chain_id` in as well; that is now the second line of defence,
    /// not the only one.
    #[test]
    fn prevote_and_precommit_bind_the_chain() {
        use crate::core::block::Block;

        let mut mainnet = Block::new_with_chain_id(10, "0".repeat(64), vec![], 45260);
        mainnet.hash = mainnet.calculate_hash();
        let mut testnet = mainnet.clone();
        testnet.chain_id = 45261;
        testnet.hash = testnet.calculate_hash();

        assert_ne!(
            mainnet.hash, testnet.hash,
            "chain_id must stay in the block preimage"
        );

        // Same epoch, height and hash; only the chain id differs.
        let a = checkpoint_signing_message(45260, 3, 10, &mainnet.hash);
        let b = checkpoint_signing_message(45261, 3, 10, &mainnet.hash);
        assert_ne!(
            a, b,
            "identical epoch, height and hash on two networks must still \
             produce different signing messages"
        );

        // The same property for the two vote types that sign this preimage
        // themselves, so neither can drift from the certificate construction.
        let voter = crate::core::address::Address::default();
        let prevote = |chain_id: u64| Prevote {
            chain_id,
            epoch: 3,
            checkpoint_height: 10,
            checkpoint_hash: mainnet.hash.clone(),
            voter_id: voter,
            sig_bls: Vec::new(),
            auth_sig: Vec::new(),
        };
        assert_ne!(
            prevote(45260).signing_message(),
            prevote(45261).signing_message(),
            "a prevote preimage must name the chain it was minted for"
        );

        let precommit = |chain_id: u64| Precommit {
            chain_id,
            epoch: 3,
            checkpoint_height: 10,
            checkpoint_hash: mainnet.hash.clone(),
            voter_id: voter,
            sig_bls: Vec::new(),
            auth_sig: Vec::new(),
        };
        assert_ne!(
            precommit(45260).signing_message(),
            precommit(45261).signing_message(),
            "a precommit preimage must name the chain it was minted for"
        );
    }

    #[test]
    fn vote_auth_v3_rejects_hash_to_signature_boundary_shift() {
        let (snap, sks) = make_snapshot_with_keys(1, 1000);
        let sk = sks[0];
        let pk = snap.validators[0].bls_public_key.clone();
        let voter_id = snap.validators[0].address;
        let hash = "a1b2c3d4".repeat(8);
        let prevote_msg = {
            let pv = Prevote {
                chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
                epoch: 5,
                checkpoint_height: 100,
                checkpoint_hash: hash.clone(),
                voter_id,
                sig_bls: Vec::new(),
                auth_sig: Vec::new(),
            };
            pv.signing_message()
        };
        let sig_bls = sign_bls(&sk, &prevote_msg);
        let honest_prevote = Prevote {
            chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
            epoch: 5,
            checkpoint_height: 100,
            checkpoint_hash: hash.clone(),
            voter_id,
            sig_bls: sig_bls.clone(),
            auth_sig: sign_bls(&sk, &vote_auth_signing_message(&prevote_msg, &sig_bls)),
        };
        assert!(verify_bls_sig(
            &pk,
            &honest_prevote.auth_signing_message(),
            &honest_prevote.auth_sig
        )
        .is_ok());
        for split in 1..hash.len() {
            let mut shifted_sig = hash.as_bytes()[split..].to_vec();
            shifted_sig.extend_from_slice(&sig_bls);
            let forged_prevote = Prevote {
                chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
                checkpoint_hash: hash[..split].to_string(),
                sig_bls: shifted_sig,
                ..honest_prevote.clone()
            };
            assert_ne!(
                forged_prevote.auth_signing_message(),
                honest_prevote.auth_signing_message()
            );
            assert!(verify_bls_sig(
                &pk,
                &forged_prevote.auth_signing_message(),
                &forged_prevote.auth_sig
            )
            .is_err());
        }

        let pc_msg =
            checkpoint_signing_message(crate::core::transaction::DEFAULT_CHAIN_ID, 5, 100, &hash);
        let pc_sig = sign_bls(&sk, &pc_msg);
        let honest_precommit = Precommit {
            chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
            epoch: 5,
            checkpoint_height: 100,
            checkpoint_hash: hash.clone(),
            voter_id,
            sig_bls: pc_sig.clone(),
            auth_sig: sign_bls(&sk, &vote_auth_signing_message(&pc_msg, &pc_sig)),
        };
        for split in 1..hash.len() {
            let mut shifted_sig = hash.as_bytes()[split..].to_vec();
            shifted_sig.extend_from_slice(&pc_sig);
            let forged_precommit = Precommit {
                chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
                checkpoint_hash: hash[..split].to_string(),
                sig_bls: shifted_sig,
                ..honest_precommit.clone()
            };
            assert_ne!(
                forged_precommit.auth_signing_message(),
                honest_precommit.auth_signing_message()
            );
            assert!(verify_bls_sig(
                &pk,
                &forged_precommit.auth_signing_message(),
                &forged_precommit.auth_sig
            )
            .is_err());
        }
    }
}
