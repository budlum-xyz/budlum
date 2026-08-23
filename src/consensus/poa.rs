use super::{ConsensusEngine, ConsensusError};
use crate::core::account::{AccountState, Validator};
use crate::core::address::Address;
use crate::core::block::Block;
use tracing::{info, warn};

/// Leader-election entropy derived from a block hash string.
///
/// Block hash fields are plain `String`s carried over the wire, so a peer
/// Controls their contents. The previous code did
/// `hex::decode(h).unwrap_or_else(|_| h.as_bytes.to_vec)` in three separate
/// Places, which fed the raw bytes of a malformed string into the proposer
/// Selection. Two nodes seeing the same block could then compute different
/// Expected proposers - one accepts the block, the other rejects it as
/// Wrong-leader. That is a consensus split reachable by any peer.
///
/// A malformed hash now maps to a single fixed sentinel on every node, so the
/// Derivation stays deterministic and identical across the network. Callers on
/// Both the propose and the verify path must use this helper so the two sides
/// Can never disagree about the entropy.
fn leader_entropy(hash: &str) -> Vec<u8> {
    match hex::decode(hash) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        // Domain-separated sentinel: distinct from any well-formed 32-byte hash.
        _ => vec![0xFFu8; 32],
    }
}
#[derive(Debug, Clone)]
pub struct PoAConfig {
    pub block_period: u64,
    pub epoch_length: u64,
    pub quorum_ratio: f64,
    pub validators_file: Option<String>,
    /// Which permissioned domain this engine gates on.
    ///
    /// Configured rather than hardcoded because developers create their own
    /// permissioned domains, each with its own admin and its own admitted
    /// set. An engine pointed at the wrong domain would read someone else's
    /// admission decisions, so the domain is stated where the engine is
    /// configured and nowhere else.
    pub domain: crate::domain::types::DomainId,
}
impl Default for PoAConfig {
    fn default() -> Self {
        PoAConfig {
            block_period: 5,
            epoch_length: 30000,
            quorum_ratio: 0.67,
            validators_file: None,
            domain: 0,
        }
    }
}

use crate::crypto::primitives::KeyPair;
use crate::crypto::signer::ConsensusSigner;
use std::sync::Arc;

pub struct PoAEngine {
    pub config: PoAConfig,
    keypair: Option<KeyPair>,
    signer: Option<Arc<dyn ConsensusSigner>>,
    /// Optional isolated PoA authority set. When non-empty, only these
    /// Addresses can be considered for PoA leadership even if other validators
    /// Are active in the permissionless state.
    authorities: Vec<Address>,
}

impl PoAEngine {
    pub fn new(config: PoAConfig, keypair: Option<KeyPair>) -> Self {
        PoAEngine {
            config,
            keypair,
            signer: None,
            authorities: Vec::new(),
        }
    }

    pub fn with_signer(
        config: PoAConfig,
        keypair: Option<KeyPair>,
        signer: Arc<dyn ConsensusSigner>,
    ) -> Self {
        PoAEngine {
            config,
            keypair,
            signer: Some(signer),
            authorities: Vec::new(),
        }
    }
    pub fn with_config(
        config: PoAConfig,
        validators: Vec<Address>,
        keypair: Option<KeyPair>,
    ) -> Self {
        PoAEngine {
            config,
            keypair,
            signer: None,
            authorities: validators,
        }
    }

    pub fn with_authorities(mut self, authorities: Vec<Address>) -> Self {
        self.authorities = authorities;
        self
    }

    /// Validators allowed to lead or validate in this PoA domain right now.
    ///
    /// Admission is decided by [`crate::registry::poa_onboarding`], recomputed
    /// at each block close and held in [`AccountState`] so every node agrees.
    /// Two gates, both required: a validator must be active in the
    /// permissionless set **and** hold a live admission record. A live record
    /// means an unexpired KYC horizon, so stale approval stops authorising
    /// blocks on its own, without anyone acting.
    ///
    /// The engine's own `authorities` vector, when non-empty, narrows further;
    /// it never widens. An operator-local list cannot admit an account the
    /// chain has not admitted.
    ///
    /// **Fail-closed, once the domain has said it is permissioned.** An empty
    /// admitted set used to mean "no filter", so a chain whose authority list
    /// was never populated ran wide open and looked healthy doing it. In a
    /// permissioned domain the absence of an admission decision is not
    /// permission: it is the absence of permission, and the domain produces
    /// no blocks until someone is admitted. A silent halt is recoverable; a
    /// silent opening is not.
    ///
    /// # Why "has an admin" and not "has records"
    ///
    /// The first attempt treated an empty admission registry as "nobody is
    /// admitted", which is right for a permissioned domain and wrong for
    /// every other chain: a plain PoA devnet that never opted into admission
    /// control would have been unable to produce its first block. Two
    /// different situations - *gated and nobody let in* versus *not gated* -
    /// had been collapsed into the same silence.
    ///
    /// A domain declares itself permissioned by having an admin. That is a
    /// deliberate act by whoever set the domain up, it is visible in state,
    /// and it cannot happen by omission. Before that act, admission control
    /// is not in force; after it, it is in force completely, and it cannot be
    /// switched back off by removing records - only by removing the admin,
    /// which is as deliberate as adding one.
    fn active_authorities<'a>(&self, state: &'a AccountState) -> Vec<&'a Validator> {
        let active = state.get_active_validators();
        if !state.poa_is_permissioned(self.config.domain) {
            return self.narrow_to_operator_list(active);
        }
        let admitted = state.poa_admitted_addresses(self.config.domain);
        let chain_admitted: Vec<&'a Validator> = active
            .into_iter()
            .filter(|validator| admitted.contains(&validator.address))
            .collect();
        self.narrow_to_operator_list(chain_admitted)
    }

    /// Apply the engine's own authority list, which narrows and never widens.
    ///
    /// An operator-local list cannot admit an account the chain has not
    /// admitted; it can only decline to use one the chain did admit. Kept as
    /// its own step so that ordering is not something a future edit can get
    /// subtly wrong: whatever the chain decided is computed first, and this
    /// only ever removes from it.
    fn narrow_to_operator_list<'a>(&self, validators: Vec<&'a Validator>) -> Vec<&'a Validator> {
        if self.authorities.is_empty() {
            return validators;
        }
        validators
            .into_iter()
            .filter(|validator| self.authorities.contains(&validator.address))
            .collect()
    }

    /// Deterministic leader selection for PoA.
    ///
    /// Replaces pure round-robin (`block_index % n`) with a hash mix over
    /// `block_index` and the active validator set fingerprint so the next
    /// Leader is not a trivial sequential prediction. Still fully
    /// Deterministic (all nodes agree); full VRF can replace this later.
    pub fn expected_proposer<'a>(
        &self,
        block_index: u64,
        active_validators: &'a [&Validator],
    ) -> Option<&'a Validator> {
        self.expected_proposer_with_entropy(block_index, active_validators, &[0u8; 32])
    }

    /// Expected proposer with external entropy for unpredictability.
    pub fn expected_proposer_with_entropy<'a>(
        &self,
        block_index: u64,
        active_validators: &'a [&Validator],
        entropy: &[u8],
    ) -> Option<&'a Validator> {
        if active_validators.is_empty() {
            return None;
        }
        let slot = Self::leader_slot_with_entropy(block_index, active_validators, entropy);
        Some(active_validators[slot])
    }

    /// VRF-like leader slot selection in `[0, n)`.
    /// Added previous_block_hash as an
    /// Entropy source. Previously the leader was fully deterministic from
    /// Public inputs (block_index + validator set), allowing DoS/bribery
    /// Attacks. Now the leader is unpredictable until the previous block
    /// Is produced, since its hash is unknown beforehand.
    pub fn leader_slot(block_index: u64, active_validators: &[&Validator]) -> usize {
        Self::leader_slot_with_entropy(block_index, active_validators, &[0u8; 32])
    }

    /// Leader selection with external entropy (e.g., previous block hash).
    pub fn leader_slot_with_entropy(
        block_index: u64,
        active_validators: &[&Validator],
        entropy: &[u8],
    ) -> usize {
        use sha2::{Digest, Sha256};
        let n = active_validators.len();
        debug_assert!(n > 0);
        let mut hasher = Sha256::new();
        hasher.update(b"BUDLUM_POA_LEADER_V2");
        hasher.update(block_index.to_le_bytes());
        // V5-SECURITY-12: Mix in external entropy (previous block hash).
        // This makes the leader unpredictable until the previous block
        // Is durably committed - preventing pre-computation attacks.
        hasher.update(entropy);
        // Fingerprint the ordered set (callers pass address-sorted active set).
        hasher.update((n as u64).to_le_bytes());
        for v in active_validators {
            hasher.update(v.address.as_bytes());
            hasher.update(v.stake.to_le_bytes());
        }
        let digest = hasher.finalize();
        let mut seed = [0u8; 8];
        seed.copy_from_slice(&digest[..8]);
        let pick = u64::from_le_bytes(seed);
        (pick % n as u64) as usize
    }

    pub fn active_validator_count(&self, state: &AccountState) -> usize {
        self.active_authorities(state).len()
    }

    fn prepare_common(
        &self,
        block: &mut Block,
        state: &AccountState,
    ) -> Result<Option<Address>, ConsensusError> {
        let active_refs = self.active_authorities(state);
        // V5-SECURITY-12: Use previous block hash as entropy for leader selection.
        // This makes the leader unpredictable until the previous block is committed.
        let prev_hash_bytes = leader_entropy(&block.previous_hash);
        let expected_signer_addr = if let Some(expected) =
            self.expected_proposer_with_entropy(block.index, &active_refs, &prev_hash_bytes)
        {
            expected.address
        } else if block.index == 0 {
            Address::zero()
        } else {
            return Err(ConsensusError("No active validators found".into()));
        };

        if expected_signer_addr == Address::zero() {
            return Ok(None);
        }

        if let Some(signer) = &self.signer {
            let our_addr = signer.address();
            if our_addr == expected_signer_addr {
                block.producer = Some(our_addr);
                return Ok(Some(our_addr));
            }
        }

        if let Some(kp) = &self.keypair {
            let our_addr = Address::from(kp.public_key_bytes());
            if our_addr == expected_signer_addr {
                block.producer = Some(our_addr);
                return Ok(Some(our_addr));
            }
        }

        if block.producer.is_none() || block.producer == Some(Address::zero()) {
            block.producer = Some(expected_signer_addr);
        }

        Ok(block.producer)
    }
}

impl ConsensusEngine for PoAEngine {
    fn preview_block(&self, block: &mut Block, state: &AccountState) -> Result<(), ConsensusError> {
        let _ = self.prepare_common(block, state)?;
        Ok(())
    }

    fn prepare_block(&self, block: &mut Block, state: &AccountState) -> Result<(), ConsensusError> {
        let expected_signer_addr = self.prepare_common(block, state)?;

        if let Some(expected_signer_addr) = expected_signer_addr {
            info!(
                "PoA: Block {} should be proposed by: {}",
                block.index, expected_signer_addr
            );

            if let Some(signer) = &self.signer {
                if signer.address() == expected_signer_addr {
                    block
                        .sign_with_signer(signer.as_ref())
                        .map_err(|e| ConsensusError(format!("HSM block signing failed: {e}")))?;
                    info!(
                        "PoA: Block {} signed via HSM ({})",
                        block.index, expected_signer_addr
                    );
                }
            } else if let Some(kp) = &self.keypair {
                let our_addr = Address::from(kp.public_key_bytes());
                if our_addr == expected_signer_addr {
                    block.sign(kp);
                    info!(
                        "PoA: Block {} signed by us ({})",
                        block.index, expected_signer_addr
                    );
                }
            } else {
                warn!("PoA: No keypair configured, cannot sign block");
            }
        }

        if block.signature.is_none() {
            block.hash = block.calculate_hash();
        }

        info!("PoA: Block {} prepared", block.index);
        Ok(())
    }

    fn validate_block(
        &self,
        block: &Block,
        chain: &[Block],
        state: &AccountState,
    ) -> Result<(), ConsensusError> {
        if block.index == 0 {
            if block.hash != block.calculate_hash() {
                return Err(ConsensusError("Invalid genesis block hash".into()));
            }
            return Ok(());
        }
        if let Some(prev_block) = chain.last() {
            if block.previous_hash != prev_block.hash {
                return Err(ConsensusError(format!(
                    "Previous hash mismatch. Expected: {}, Got: {}",
                    prev_block.hash, block.previous_hash
                )));
            }
        }

        let active_refs = self.active_authorities(state);
        if !active_refs.is_empty() {
            // V5-SECURITY-12: Use previous block hash as entropy for leader verification.
            // Must match the entropy used in prepare_block/prepare_common.
            let prev_hash_bytes = if let Some(prev) = chain.last() {
                leader_entropy(&prev.hash)
            } else {
                leader_entropy(&block.previous_hash)
            };
            let expected = self
                .expected_proposer_with_entropy(block.index, &active_refs, &prev_hash_bytes)
                .ok_or_else(|| ConsensusError("No proposer for this slot".into()))?;

            let producer = block
                .producer
                .as_ref()
                .ok_or_else(|| ConsensusError("Block has no producer".into()))?;

            // One call rather than two checks in sequence. The pair that used
            // to be here, "is this the expected proposer" then "is the
            // signature good", is exactly what
            // `verify_signature_with_pubkey` is, and keeping a second copy of
            // it at the call site meant the two could drift: a caller that
            // remembered the signature and forgot the proposer would accept a
            // validly signed block from the wrong authority for that slot.
            // The function existed and nothing reached it.
            if !block.verify_signature_with_pubkey(&expected.address) {
                return Err(ConsensusError(format!(
                    "Block {} is not a valid signature from the expected proposer {}, got {}",
                    block.index, expected.address, producer
                )));
            }

            info!(
                "PoA: Block {} signature verified (producer: {})",
                block.index, producer
            );
        } else {
            return Err(ConsensusError(
                "No active PoA authorities; refusing hash-only PoA block".into(),
            ));
        }
        Ok(())
    }
    fn consensus_type(&self) -> &'static str {
        "PoA"
    }
    fn signer(&self) -> Option<&dyn ConsensusSigner> {
        self.signer.as_ref().map(|s| s.as_ref())
    }
    fn info(&self) -> String {
        format!(
            "PoA (validators: in-state, quorum: {:.0}%)",
            self.config.quorum_ratio * 100.0
        )
    }

    fn fork_choice_score(&self, chain: &[Block]) -> u128 {
        chain.len() as u128
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::account::{AccountState, Validator};
    use crate::core::address::Address;
    use crate::crypto::primitives::KeyPair;

    #[test]
    fn test_proposer_rotation() {
        let mut state = AccountState::new();
        let alice = KeyPair::generate().unwrap();
        let bob = KeyPair::generate().unwrap();
        let alice_addr = Address::from(alice.public_key_bytes());
        let bob_addr = Address::from(bob.public_key_bytes());

        state
            .validators
            .insert(alice_addr, Validator::new(alice_addr, 0));
        state
            .validators
            .insert(bob_addr, Validator::new(bob_addr, 0));

        state.validators.get_mut(&alice_addr).unwrap().active = true;
        state.validators.get_mut(&bob_addr).unwrap().active = true;

        let engine = PoAEngine::new(PoAConfig::default(), None);

        let active_refs = state.get_active_validators();

        if active_refs.len() < 2 {
            return;
        }

        // Deterministic: same inputs → same leader.
        let p1 = engine.expected_proposer(1, &active_refs).unwrap();
        let p1b = engine.expected_proposer(1, &active_refs).unwrap();
        assert_eq!(p1.address, p1b.address);

        // Hash mix is not pure round-robin: over many heights both leaders
        // Appear, and consecutive heights are not forced to alternate.
        let mut seen = std::collections::HashSet::new();
        for h in 0..64u64 {
            let p = engine.expected_proposer(h, &active_refs).unwrap();
            seen.insert(p.address);
        }
        assert_eq!(
            seen.len(),
            2,
            "hash mix should hit both validators over 64 heights"
        );
    }

    /// Leader slot is not `block_index % n`.
    #[test]
    fn leader_not_pure_round_robin() {
        let mut state = AccountState::new();
        // Three fixed addresses so set order is stable.
        for i in 1..=3u8 {
            let mut b = [0u8; 32];
            b[0] = i;
            let addr = Address::from(b);
            state.validators.insert(addr, Validator::new(addr, 1000));
            state.validators.get_mut(&addr).unwrap().active = true;
        }
        let active_refs = state.get_active_validators();
        assert_eq!(active_refs.len(), 3);

        let engine = PoAEngine::new(PoAConfig::default(), None);
        let mut mismatches = 0u32;
        for h in 0..32u64 {
            let hash_leader = engine.expected_proposer(h, &active_refs).unwrap().address;
            let rr_leader = active_refs[(h as usize) % active_refs.len()].address;
            if hash_leader != rr_leader {
                mismatches += 1;
            }
        }
        assert!(
            mismatches > 0,
            "hash-based leader must differ from pure round-robin for some heights"
        );
        // Explicit slot helper matches expected_proposer.
        for h in 0..8u64 {
            let slot = PoAEngine::leader_slot(h, &active_refs);
            let p = engine.expected_proposer(h, &active_refs).unwrap();
            assert_eq!(p.address, active_refs[slot].address);
        }
    }

    #[test]
    fn poa_rejects_hash_only_block_when_authority_set_empty() {
        let state = AccountState::new();
        let engine = PoAEngine::new(PoAConfig::default(), None);
        let mut block = Block::new(1, "0".repeat(64), vec![]);
        block.hash = block.calculate_hash();

        let err = engine
            .validate_block(&block, &[], &state)
            .expect_err("hash-only PoA block must fail closed");
        assert!(err.0.contains("No active PoA authorities"), "got: {err}");
    }

    #[test]
    fn poa_explicit_authorities_filter_permissionless_active_set() {
        let authority = KeyPair::generate().unwrap();
        let outsider = KeyPair::generate().unwrap();
        let authority_addr = Address::from(authority.public_key_bytes());
        let outsider_addr = Address::from(outsider.public_key_bytes());

        let mut state = admitted_state(&[authority_addr, outsider_addr]);

        let engine = PoAEngine::with_config(PoAConfig::default(), vec![authority_addr], None);
        assert_eq!(engine.active_validator_count(&state), 1);
        let active_refs = engine.active_authorities(&state);
        assert_eq!(active_refs.len(), 1);
        assert_eq!(active_refs[0].address, authority_addr);

        // The operator list narrows, it never widens: revoking the chain's
        // admission of `authority_addr` must remove it even though the
        // operator still names it.
        //
        // Revoked, not wiped. Clearing the whole registry would also remove
        // the domain's admin, and a domain with no admin is not a
        // permissioned domain at all: the assertion would then pass for the
        // wrong reason, proving nothing about operator lists.
        let admin = Address::from([9u8; 32]);
        state
            .poa_onboarding
            .revoke(0, admin, authority_addr, 1, "test")
            .expect("admin revokes its own admission");
        state.refresh_poa_admissions(1);
        assert!(
            state.poa_is_permissioned(0),
            "the domain must still be permissioned, or this proves nothing"
        );
        assert!(
            engine.active_authorities(&state).is_empty(),
            "an operator-local list admitted an account the chain did not"
        );
        // And the outsider the chain still admits stays out, because the
        // operator list does not name it.
        assert!(
            state.poa_admitted_addresses(0).contains(&outsider_addr),
            "the chain still admits the outsider"
        );
    }

    /// A state where every listed address is an active validator *and* holds a
    /// live PoA admission record in domain 0.
    fn admitted_state(addrs: &[Address]) -> AccountState {
        let mut state = AccountState::new();
        for a in addrs {
            state.validators.insert(*a, Validator::new(*a, 1_000));
            if let Some(v) = state.validators.get_mut(a) {
                v.active = true;
            }
        }
        admit_all(&mut state, 0, addrs, 10_000);
        state
    }

    /// Make `domain` permissioned and admit every listed address.
    ///
    /// Admission is a two-step lifecycle - the candidate applies with a KYC
    /// commitment, then an admin approves - and this helper walks both steps,
    /// because a test that skipped the application would exercise a path
    /// production cannot reach.
    fn admit_all(state: &mut AccountState, domain: u32, addrs: &[Address], horizon: u64) {
        let admin = Address::from([9u8; 32]);
        state.poa_onboarding.registry_mut().add_admin(domain, admin);
        for (i, a) in addrs.iter().enumerate() {
            let mut kyc = [0u8; 32];
            // Any non-zero commitment; an all-zero one is refused.
            kyc[0] = u8::try_from(i % 250).unwrap_or(0).saturating_add(1);
            state
                .poa_onboarding
                .submit_application(domain, *a, kyc, 1)
                .expect("applicant submits a KYC commitment");
            state
                .poa_onboarding
                .approve(domain, admin, *a, 1, horizon)
                .expect("admin approves into its own domain");
        }
        state.refresh_poa_admissions(1);
    }

    #[test]
    fn no_admission_means_no_blocks_not_an_open_door() {
        let v = KeyPair::generate().unwrap();
        let addr = Address::from(v.public_key_bytes());
        let mut state = AccountState::new();
        state.validators.insert(addr, Validator::new(addr, 1_000));
        if let Some(val) = state.validators.get_mut(&addr) {
            val.active = true;
        }
        // The domain is permissioned - it has an admin - but nobody has been
        // admitted yet. Before this change an empty admitted set meant "no
        // filter" and this validator produced blocks in a permissioned domain
        // nobody had admitted it to.
        state
            .poa_onboarding
            .registry_mut()
            .add_admin(0, Address::from([9u8; 32]));
        state.refresh_poa_admissions(1);

        let engine = PoAEngine::new(PoAConfig::default(), None);
        assert!(
            engine.active_authorities(&state).is_empty(),
            "a validator with no admission record was authorised: fail-open"
        );
    }

    #[test]
    fn a_chain_that_never_opted_into_admission_control_still_produces_blocks() {
        // The counterpart to the test above, and the distinction the first
        // version of this gate got wrong. "Gated and nobody let in" and "not
        // gated at all" are different situations; collapsing them into the
        // same empty registry stopped every plain PoA chain at genesis.
        let v = KeyPair::generate().unwrap();
        let addr = Address::from(v.public_key_bytes());
        let mut state = AccountState::new();
        state.validators.insert(addr, Validator::new(addr, 1_000));
        if let Some(val) = state.validators.get_mut(&addr) {
            val.active = true;
        }
        state.refresh_poa_admissions(1);

        assert!(
            !state.poa_is_permissioned(0),
            "a domain with no admin must not count as permissioned"
        );
        let engine = PoAEngine::new(PoAConfig::default(), None);
        assert_eq!(
            engine.active_authorities(&state).len(),
            1,
            "a chain that never opted into admission control was halted by it"
        );
    }

    #[test]
    fn appointing_an_admin_turns_the_gate_on_for_everyone_already_there() {
        // Admission control must not grandfather anyone in. A validator that
        // was producing blocks before the domain became permissioned has to
        // be admitted like anyone else, or the gate would be weakest exactly
        // at the moment it is switched on.
        let v = KeyPair::generate().unwrap();
        let addr = Address::from(v.public_key_bytes());
        let mut state = AccountState::new();
        state.validators.insert(addr, Validator::new(addr, 1_000));
        if let Some(val) = state.validators.get_mut(&addr) {
            val.active = true;
        }
        state.refresh_poa_admissions(1);
        let engine = PoAEngine::new(PoAConfig::default(), None);
        assert_eq!(engine.active_authorities(&state).len(), 1);

        state
            .poa_onboarding
            .registry_mut()
            .add_admin(0, Address::from([9u8; 32]));
        state.refresh_poa_admissions(2);
        assert!(
            engine.active_authorities(&state).is_empty(),
            "an incumbent validator was grandfathered past admission control"
        );
    }

    #[test]
    fn an_expired_kyc_stops_authorising_without_anyone_acting() {
        let v = KeyPair::generate().unwrap();
        let addr = Address::from(v.public_key_bytes());
        let admin = Address::from([9u8; 32]);
        let mut state = AccountState::new();
        state.validators.insert(addr, Validator::new(addr, 1_000));
        if let Some(val) = state.validators.get_mut(&addr) {
            val.active = true;
        }
        let _ = admin;
        admit_all(&mut state, 0, &[addr], 100);

        let engine = PoAEngine::new(PoAConfig::default(), None);
        state.refresh_poa_admissions(50);
        assert_eq!(
            engine.active_authorities(&state).len(),
            1,
            "a live approval must authorise"
        );

        // Nobody revokes anything; the horizon simply passes.
        state.refresh_poa_admissions(500);
        assert!(
            engine.active_authorities(&state).is_empty(),
            "a stale KYC dossier kept producing blocks"
        );
    }

    #[test]
    fn one_domains_admin_cannot_admit_into_another() {
        let v = KeyPair::generate().unwrap();
        let addr = Address::from(v.public_key_bytes());
        let admin_of_one = Address::from([1u8; 32]);
        let mut state = AccountState::new();
        state.validators.insert(addr, Validator::new(addr, 1_000));
        if let Some(val) = state.validators.get_mut(&addr) {
            val.active = true;
        }
        // Admin of domain 1 only. Domain 2 is made permissioned by a
        // different admin, so the question is genuinely about isolation and
        // not about domain 2 simply being ungated.
        state
            .poa_onboarding
            .registry_mut()
            .add_admin(1, admin_of_one);
        state
            .poa_onboarding
            .registry_mut()
            .add_admin(2, Address::from([2u8; 32]));
        let cross = state
            .poa_onboarding
            .submit_application(2, addr, [7u8; 32], 1)
            .and_then(|()| {
                state
                    .poa_onboarding
                    .approve(2, admin_of_one, addr, 1, 10_000)
            });
        assert!(
            cross.is_err(),
            "an admin of one domain admitted into another: domains are not isolated"
        );

        state.refresh_poa_admissions(1);
        let engine_two = PoAEngine::new(
            PoAConfig {
                domain: 2,
                ..PoAConfig::default()
            },
            None,
        );
        assert!(
            engine_two.active_authorities(&state).is_empty(),
            "domain 2 authorised an account only domain 1's admin touched"
        );
    }

    #[test]
    fn test_poa_signing() {
        let keypair = KeyPair::generate().unwrap();
        let pubkey = Address::from(keypair.public_key_bytes());

        let mut state = AccountState::new();
        state.validators.insert(pubkey, Validator::new(pubkey, 0));
        state.validators.get_mut(&pubkey).unwrap().active = true;

        let engine = PoAEngine::new(PoAConfig::default(), Some(keypair));

        let mut block = Block::new(1, "prev".into(), vec![]);

        engine.prepare_block(&mut block, &state).unwrap();

        assert!(block.producer.is_some());
        assert_eq!(block.producer.as_ref().unwrap(), &pubkey);
        assert!(block.signature.is_some());
        assert!(block.verify_signature());

        // The bound check the validation path now makes in one call: a valid
        // signature from the expected proposer passes, and the same valid
        // signature checked against a different authority does not. Without
        // the second half, a validly signed block from the wrong authority
        // for that slot would be accepted.
        assert!(block.verify_signature_with_pubkey(&pubkey));
        let someone_else = Address([0xAB; 32]);
        assert!(
            !block.verify_signature_with_pubkey(&someone_else),
            "a good signature from the wrong authority must still be refused"
        );
    }
}
