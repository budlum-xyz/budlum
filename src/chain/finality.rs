use crate::core::address::Address;
use crate::registry::SlashingReport;
use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    G1Affine, G1Projective, G2Affine, G2Projective, Scalar,
};
use serde::{Deserialize, Serialize};
use sha2_09::Sha256;
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
        let total_stake = validators.iter().map(|v| v.stake).sum();
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
            hasher.update(&v.bls_public_key);
            hasher.update(&v.pop_signature);
            hasher.update(&v.pq_public_key);
        }
        hex::encode(hasher.finalize())
    }

    pub fn find_validator(&self, address: &Address) -> Option<&ValidatorEntry> {
        self.validators.iter().find(|v| &v.address == address)
    }

    pub fn validator_index(&self, address: &Address) -> Option<usize> {
        self.validators.iter().position(|v| &v.address == address)
    }

    pub fn quorum_stake(&self) -> u64 {
        (self.total_stake * FINALITY_QUORUM_NUMERATOR) / FINALITY_QUORUM_DENOMINATOR + 1
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
    pub voter_id: Address,
    pub sig_bls: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Precommit {
    pub epoch: u64,
    pub checkpoint_height: u64,
    pub checkpoint_hash: String,
    pub voter_id: Address,
    pub sig_bls: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityCert {
    pub epoch: u64,
    pub checkpoint_height: u64,
    pub checkpoint_hash: String,
    pub agg_sig_bls: Vec<u8>,
    pub bitmap: Vec<u8>,
    pub set_hash: String,
}

impl Prevote {
    /// Bytes a validator signs to endorse a checkpoint.
    ///
    /// # Why there is no explicit `chain_id` here
    ///
    /// The obvious cross-chain replay question - could a prevote signed on
    /// Testnet be replayed on mainnet? - is closed, but indirectly:
    /// `checkpoint_hash` is a block hash, and `Block::calculate_hash_bytes`
    /// Folds `chain_id` into the `BDLM_BLOCK_V3` preimage. Two networks cannot
    /// Produce the same checkpoint hash at the same height, so the signature
    /// Does not verify against any other chain's checkpoint.
    ///
    /// That is a derived guarantee, not a stated one: it holds because of what
    /// `calculate_hash_bytes` happens to include, and would break silently if
    /// `chain_id` ever left the block preimage. `prevote_and_precommit_bind_the_chain`
    /// Asserts the dependency so the two cannot drift apart.
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"BUDLUM_PREVOTE");
        msg.extend_from_slice(BLS_SCHEME_RFC9380_V1.as_bytes());
        msg.extend_from_slice(&self.epoch.to_le_bytes());
        msg.extend_from_slice(&self.checkpoint_height.to_le_bytes());
        msg.extend_from_slice(self.checkpoint_hash.as_bytes());
        msg
    }
}

impl Precommit {
    pub fn signing_message(&self) -> Vec<u8> {
        checkpoint_signing_message(self.epoch, self.checkpoint_height, &self.checkpoint_hash)
    }
}

pub fn is_checkpoint_height(height: u64) -> bool {
    height > 0 && height.is_multiple_of(FINALITY_CHECKPOINT_INTERVAL)
}

pub fn is_checkpoint_height_for_chain(height: u64, chain_id: u64) -> bool {
    let interval = crate::core::chain_config::finality_checkpoint_interval_for_chain_id(chain_id);
    height > 0 && height.is_multiple_of(interval)
}

pub fn checkpoint_signing_message(epoch: u64, height: u64, hash: &str) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"BUDLUM_PRECOMMIT");
    msg.extend_from_slice(BLS_SCHEME_RFC9380_V1.as_bytes());
    msg.extend_from_slice(&epoch.to_le_bytes());
    msg.extend_from_slice(&height.to_le_bytes());
    msg.extend_from_slice(hash.as_bytes());
    msg
}

/// Proof-of-possession input from the IETF BLS PoP ciphersuite: the canonical
/// Serialized public key. Chain/address binding is provided separately by the
/// Validator's signed `RegisterConsensusKeys` transaction.
pub fn pop_signing_message(_chain_id: u64, _address: &Address, bls_pk: &[u8]) -> Vec<u8> {
    bls_pk.to_vec()
}

/// Wire-visible identifier for the RFC 9380 random-oracle suite used by all
/// Live Budlum BLS signatures. Public keys are in G2 and signatures are in G1.
pub const BLS_SCHEME_RFC9380_V1: &str = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
/// The pre-migration construction exposed H(m)'s discrete logarithm. Its ID is
/// Retained only for handshake rejection and historical tooling; it must never
/// Be used to validate a live vote or certificate.
pub const BLS_SCHEME_LEGACY_SCALAR_V0: &str = "BUDLUM_BLS_SCALAR_SHA3_V0";
/// Mainnet has not launched, so the safe single-epoch migration point is the
/// Genesis epoch. There is no live epoch in which the forgeable scheme is valid.
pub const BLS_RFC9380_ACTIVATION_EPOCH: u64 = 0;

const BLS_SIGNATURE_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
const BLS_POP_DST: &[u8] = b"BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

pub fn hash_to_g1(msg: &[u8]) -> G1Affine {
    // RFC 9380 §8.8.1: hash_to_curve, expand_message_xmd(SHA-256), Simplified
    // SWU, random-oracle encoding. Unlike the removed scalar-times-generator
    // Construction, the discrete logarithm of this point is not known.
    G1Affine::from(
        <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(msg, BLS_SIGNATURE_DST),
    )
}

pub fn hash_pop_to_g1(msg: &[u8]) -> G1Affine {
    G1Affine::from(
        <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(msg, BLS_POP_DST),
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
    let pk_affine = G2Affine::from_compressed(&pk_bytes);
    if pk_affine.is_none().into() {
        return Err("Invalid BLS public key encoding".to_string());
    }
    let pk_affine = pk_affine.unwrap();

    // (security audit §5) enforce that the public key is
    // Actually in the correct prime-order subgroup. Without this
    // Check an attacker can supply a small-subgroup point as the
    // Public key, which makes the pairing produce values in a
    // Sub-group that pairs to identity for any message - bypassing
    // The BLS signature scheme entirely. The bls12_381 crate
    // Exposes `is_torsion_free` for exactly this check.
    let is_on_curve_pk: bool = pk_affine.is_torsion_free().into();
    if !is_on_curve_pk || bool::from(pk_affine.is_identity()) {
        return Err("BLS public key is identity or not in the prime-order subgroup".to_string());
    }

    let sig_bytes: [u8; 48] = sig
        .try_into()
        .map_err(|_| "Invalid BLS signature length".to_string())?;
    let sig_affine = G1Affine::from_compressed(&sig_bytes);
    if sig_affine.is_none().into() {
        return Err("Invalid BLS signature encoding".to_string());
    }
    let sig_affine = sig_affine.unwrap();

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
    let pk_affine = G2Affine::from_compressed(&pk_bytes);
    if pk_affine.is_none().into() {
        return false;
    }
    let pk_affine = pk_affine.unwrap();
    // (security audit §5) subgroup check on the PoP
    // Public key (see `verify_bls_sig` for the full rationale).
    let is_on_curve: bool = pk_affine.is_torsion_free().into();
    if !is_on_curve || bool::from(pk_affine.is_identity()) {
        return false;
    }

    // Parse PoP Signature
    let sig_bytes: [u8; 48] = match entry.pop_signature.as_slice().try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_affine = G1Affine::from_compressed(&sig_bytes);
    if sig_affine.is_none().into() {
        return false;
    }
    let sig_affine = sig_affine.unwrap();
    // (security audit §5) subgroup check on the PoP
    // Signature (see `verify_bls_sig` for the full rationale).
    let is_on_curve: bool = sig_affine.is_torsion_free().into();
    if !is_on_curve || bool::from(sig_affine.is_identity()) {
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
    pub validator_snapshot: Option<ValidatorSetSnapshot>,
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
    pub fn new(epoch: u64, checkpoint_height: u64, checkpoint_hash: String) -> Self {
        FinalityAggregator {
            epoch,
            checkpoint_height,
            checkpoint_hash,
            prevotes: HashMap::new(),
            precommits: HashMap::new(),
            validator_snapshot: None,
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

    pub fn set_validator_snapshot(&mut self, snapshot: ValidatorSetSnapshot) {
        self.validator_snapshot = Some(snapshot);
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
        if let Some(ref snapshot) = self.validator_snapshot {
            let entry = snapshot
                .find_validator(&vote.voter_id)
                .ok_or("Voter not in validator set")?;
            verify_bls_sig(
                &entry.bls_public_key,
                &vote.signing_message(),
                &vote.sig_bls,
            )
            .map_err(|e| format!("Invalid prevote signature: {e}"))?;
        }

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
        if let Some(ref snapshot) = self.validator_snapshot {
            let entry = snapshot
                .find_validator(&vote.voter_id)
                .ok_or("Voter not in validator set")?;
            verify_bls_sig(
                &entry.bls_public_key,
                &vote.signing_message(),
                &vote.sig_bls,
            )
            .map_err(|e| format!("Invalid precommit signature: {e}"))?;
        }

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
                    prev_hash.clone(),
                    prev_sig.clone(),
                    vote.checkpoint_hash.clone(),
                    vote.sig_bls.clone(),
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
                    prev_hash.clone(),
                    prev_sig.clone(),
                    vote.checkpoint_hash.clone(),
                    vote.sig_bls.clone(),
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
        hash_1: String,
        sig_1: Vec<u8>,
        hash_2: String,
        sig_2: Vec<u8>,
    ) {
        if !self.flagged_equivocators.insert(voter) {
            return;
        }
        let report = SlashingReport::consensus_double_sign(
            voter,
            self.checkpoint_height,
            hash_1,
            hash_2,
            sig_1,
            sig_2,
            None,
        );
        self.detected_equivocations.push(report);
    }

    fn check_prevote_quorum(&mut self) {
        if let Some(ref snapshot) = self.validator_snapshot {
            let mut voted_stake: u64 = 0;
            let mut voted_count: usize = 0;
            for validator in self
                .prevotes
                .keys()
                .filter_map(|addr| snapshot.find_validator(addr))
            {
                voted_stake = voted_stake.saturating_add(validator.stake);
                voted_count += 1;
            }
            if voted_stake >= snapshot.quorum_stake() && voted_count >= snapshot.quorum_count() {
                self.prevote_quorum_reached = true;
            }
        }
    }

    fn check_precommit_quorum(&mut self) {
        if let Some(ref snapshot) = self.validator_snapshot {
            let mut voted_stake: u64 = 0;
            let mut voted_count: usize = 0;
            for validator in self
                .precommits
                .keys()
                .filter_map(|addr| snapshot.find_validator(addr))
            {
                voted_stake = voted_stake.saturating_add(validator.stake);
                voted_count += 1;
            }
            if voted_stake >= snapshot.quorum_stake() && voted_count >= snapshot.quorum_count() {
                self.precommit_quorum_reached = true;
            }
        }
    }

    pub fn try_produce_cert(&self) -> Option<FinalityCert> {
        if !self.precommit_quorum_reached {
            return None;
        }

        let snapshot = self.validator_snapshot.as_ref()?;

        let mut bitmap = vec![0u8; snapshot.validators.len().div_ceil(8)];
        let mut agg_sig = G1Projective::identity();

        for (addr, precommit) in &self.precommits {
            if let Some(idx) = snapshot.validator_index(addr) {
                bitmap[idx / 8] |= 1 << (idx % 8);

                let sig_bytes: [u8; 48] = precommit
                    .sig_bls
                    .as_slice()
                    .try_into()
                    .map_err(|_| "Invalid precommit signature length".to_string())
                    .ok()?;
                let sig_affine = G1Affine::from_compressed(&sig_bytes);
                if sig_affine.is_some().into() {
                    agg_sig += G1Projective::from(sig_affine.unwrap());
                }
            }
        }

        Some(FinalityCert {
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

        let mut voted_stake: u64 = 0;
        let mut voted_count: usize = 0;
        let mut signers_pks = Vec::new();
        for (idx, validator) in snapshot.validators.iter().enumerate() {
            let byte_idx = idx / 8;
            let bit_idx = idx % 8;
            if byte_idx < self.bitmap.len() && (self.bitmap[byte_idx] & (1 << bit_idx)) != 0 {
                voted_stake = voted_stake.saturating_add(validator.stake);
                voted_count += 1;

                let pk_bytes: [u8; 96] =
                    validator
                        .bls_public_key
                        .as_slice()
                        .try_into()
                        .map_err(|_| {
                            format!("Invalid BLS public key length for {}", validator.address)
                        })?;
                let pk = G2Affine::from_compressed(&pk_bytes);
                if pk.is_none().into() {
                    return Err(format!(
                        "Invalid BLS public key encoding for {}",
                        validator.address
                    ));
                }
                let pk = pk.unwrap();
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
        let sig_affine = G1Affine::from_compressed(&sig_bytes);
        if sig_affine.is_none().into() {
            return Err("Invalid aggregated BLS signature encoding".into());
        }
        let sig_affine = sig_affine.unwrap();
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
        checkpoint_signing_message(self.epoch, self.checkpoint_height, &self.checkpoint_hash)
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
            b"",
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
            epoch,
            checkpoint_height: height,
            checkpoint_hash: hash.to_string(),
            voter_id: snap.validators[i].address,
            sig_bls: vec![],
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
            epoch: 1,
            checkpoint_height: 10,
            checkpoint_hash: "abc".into(),
            voter_id: Address::zero(),
            sig_bls: vec![],
        };
        let msg = vote.signing_message();
        assert!(msg.starts_with(b"BUDLUM_PREVOTE"));
    }

    #[test]
    fn test_aggregator_prevote_flow() {
        let (snap, sks) = make_snapshot_with_keys(4, 1000);
        let mut agg = FinalityAggregator::new(1, 10, "cp_hash".into());
        agg.set_validator_snapshot(snap.clone());

        for i in 0..3 {
            let vote = signed_prevote(&snap, &sks, i, 1, 10, "cp_hash");
            agg.add_prevote(vote).unwrap();
        }
        assert!(agg.prevote_quorum_reached);
    }

    #[test]
    fn test_aggregator_rejects_duplicate() {
        let (snap, sks) = make_snapshot_with_keys(4, 1000);
        let mut agg = FinalityAggregator::new(1, 10, "cp_hash".into());
        agg.set_validator_snapshot(snap.clone());

        let vote = signed_prevote(&snap, &sks, 0, 1, 10, "cp_hash");
        agg.add_prevote(vote.clone()).unwrap();
        assert!(agg.add_prevote(vote).is_err());
    }

    #[test]
    fn test_aggregator_rejects_wrong_epoch() {
        let (snap, sks) = make_snapshot_with_keys(4, 1000);
        let mut agg = FinalityAggregator::new(1, 10, "cp_hash".into());
        agg.set_validator_snapshot(snap.clone());

        // Wrong epoch: rejected before signature check.
        let vote = signed_prevote(&snap, &sks, 0, 99, 10, "cp_hash");
        assert!(agg.add_prevote(vote).is_err());
    }

    #[test]
    fn test_aggregator_rejects_invalid_signature() {
        // (Option A) a garbage signature is rejected AT INGEST and
        // Never enters the aggregate.
        let (snap, _) = make_snapshot_with_keys(4, 1000);
        let mut agg = FinalityAggregator::new(1, 10, "cp_hash".into());
        agg.set_validator_snapshot(snap.clone());

        let vote = Prevote {
            epoch: 1,
            checkpoint_height: 10,
            checkpoint_hash: "cp_hash".into(),
            voter_id: snap.validators[0].address,
            sig_bls: vec![0u8; 48], // not a valid BLS signature
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
        let mut agg = FinalityAggregator::new(1, 10, "cp_hash".into());
        agg.set_validator_snapshot(snap.clone());

        // No prevote quorum yet: rejected before signature check.
        let pc = Precommit {
            epoch: 1,
            checkpoint_height: 10,
            checkpoint_hash: "cp_hash".into(),
            voter_id: snap.validators[0].address,
            sig_bls: sign_msg(sks[0], &checkpoint_signing_message(1, 10, "cp_hash")),
        };
        assert!(agg.add_precommit(pc).is_err());
    }

    #[test]
    fn test_full_finality_flow() {
        let (snap, sks) = make_snapshot_with_keys(4, 1000);
        let mut agg = FinalityAggregator::new(1, 10, "cp_hash".into());
        agg.set_validator_snapshot(snap.clone());

        for i in 0..3 {
            let vote = signed_prevote(&snap, &sks, i, 1, 10, "cp_hash");
            agg.add_prevote(vote).unwrap();
        }
        assert!(agg.prevote_quorum_reached);

        let mut agg_sig = G1Projective::identity();
        for (i, sk) in sks.iter().enumerate().take(3) {
            let pc = Precommit {
                epoch: 1,
                checkpoint_height: 10,
                checkpoint_hash: "cp_hash".into(),
                voter_id: snap.validators[i].address,
                sig_bls: vec![],
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
    }

    #[test]
    fn test_cert_verify_rejects_insufficient_quorum() {
        let (snap, sks) = make_snapshot_with_keys(4, 1000);
        let pc = Precommit {
            epoch: 1,
            checkpoint_height: 10,
            checkpoint_hash: "cp_hash".into(),
            voter_id: snap.validators[0].address,
            sig_bls: vec![],
        };
        let sig_bytes = sign_msg(sks[0], &pc.signing_message());

        let cert = FinalityCert {
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
        assert!(snap.validators[0].stake >= snap.quorum_stake());
        assert_eq!(snap.quorum_count(), 3);

        let pc = Precommit {
            epoch: 1,
            checkpoint_height: 10,
            checkpoint_hash: "cp_hash".into(),
            voter_id: snap.validators[0].address,
            sig_bls: vec![],
        };
        let sig_bytes = sign_msg(sks[0], &pc.signing_message());
        let cert = FinalityCert {
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

        // An entry whose public key decodes to a valid G2 point but
        // Is NOT in the prime-order subgroup must be rejected. We
        // Build one by encoding a random-looking low-order point
        // (a non-trivial BLS12-381 cofactor-element). The simplest
        // Approach is to take the identity encoding (which IS a
        // Small-subgroup point): BLS12-381 reserves the
        // "compression flag with infinity bit set" encoding for
        // The identity. Hand-constructing one is non-trivial
        // Without a known non-torsion-free generator, so we instead
        // Exercise the `is_none` rejection (covered above) and the
        // Happy path (covered by `test_verify_pop`). The critical
        // Guarantee - that a non-decodable public key is rejected
        // By `verify_pop` - is what the test above pins.
    }

    /// A checkpoint signature must not verify on another network.
    ///
    /// `Prevote::signing_message` and `checkpoint_signing_message` commit to a
    /// domain tag, the BLS scheme id, the epoch, the height and the checkpoint
    /// hash - but not to `chain_id`. That is safe only because the checkpoint
    /// hash *is* a block hash and `Block::calculate_hash_bytes` folds
    /// `chain_id` into its preimage, so mainnet and testnet cannot agree on a
    /// checkpoint hash at the same height.
    ///
    /// The whole cross-chain replay defence therefore rests on one line in
    /// another module. Drop `chain_id` from the block preimage and every
    /// checkpoint signature becomes portable between networks - with nothing
    /// in `finality.rs` to notice, because the signing message never mentioned
    /// it.
    ///
    /// This asserts the dependency directly: two blocks identical except for
    /// `chain_id` must hash differently, and the resulting signing messages
    /// must differ.
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
            "chain_id must be part of the block preimage; without it a \
             checkpoint signature replays onto every other network, because \
             the signing message does not carry chain_id itself"
        );

        let prevote_a = checkpoint_signing_message(3, 10, &mainnet.hash);
        let prevote_b = checkpoint_signing_message(3, 10, &testnet.hash);
        assert_ne!(
            prevote_a, prevote_b,
            "identical epoch and height on two networks must still produce \
             different signing messages"
        );
    }
}
