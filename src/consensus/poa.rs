use super::{ConsensusEngine, ConsensusError};
use crate::core::account::{AccountState, Validator};
use crate::core::address::Address;
use crate::core::block::Block;
use tracing::{info, warn};
#[derive(Debug, Clone)]
pub struct PoAConfig {
    pub block_period: u64,
    pub epoch_length: u64,
    pub quorum_ratio: f64,
    pub validators_file: Option<String>,
}
impl Default for PoAConfig {
    fn default() -> Self {
        PoAConfig {
            block_period: 5,
            epoch_length: 30000,
            quorum_ratio: 0.67,
            validators_file: None,
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
}

impl PoAEngine {
    pub fn new(config: PoAConfig, keypair: Option<KeyPair>) -> Self {
        PoAEngine {
            config,
            keypair,
            signer: None,
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
        }
    }
    pub fn with_config(
        config: PoAConfig,
        _validators: Vec<Address>,
        keypair: Option<KeyPair>,
    ) -> Self {
        PoAEngine {
            config,
            keypair,
            signer: None,
        }
    }

    /// Deterministic leader selection for PoA (Task 0.338 / A6).
    ///
    /// Replaces pure round-robin (`block_index % n`) with a hash mix over
    /// `block_index` and the active validator set fingerprint so the next
    /// leader is not a trivial sequential prediction. Still fully
    /// deterministic (all nodes agree); full VRF can replace this later.
    pub fn expected_proposer<'a>(
        &self,
        block_index: u64,
        active_validators: &'a [&Validator],
    ) -> Option<&'a Validator> {
        if active_validators.is_empty() {
            return None;
        }
        let slot = Self::leader_slot(block_index, active_validators);
        Some(active_validators[slot])
    }

    /// Hash-mix slot index in `[0, n)`.
    pub fn leader_slot(block_index: u64, active_validators: &[&Validator]) -> usize {
        use sha2::{Digest, Sha256};
        let n = active_validators.len();
        debug_assert!(n > 0);
        let mut hasher = Sha256::new();
        hasher.update(b"BUDLUM_POA_LEADER_V1");
        hasher.update(block_index.to_le_bytes());
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
        state.get_active_validators().len()
    }

    fn prepare_common(
        &self,
        block: &mut Block,
        state: &AccountState,
    ) -> Result<Option<Address>, ConsensusError> {
        let active_refs = state.get_active_validators();
        let expected_signer_addr =
            if let Some(expected) = self.expected_proposer(block.index, &active_refs) {
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

        let active_refs = state.get_active_validators();
        if !active_refs.is_empty() {
            let expected = self
                .expected_proposer(block.index, &active_refs)
                .ok_or_else(|| ConsensusError("No proposer for this slot".into()))?;

            let producer = block
                .producer
                .as_ref()
                .ok_or_else(|| ConsensusError("Block has no producer".into()))?;

            if producer != &expected.address {
                return Err(ConsensusError(format!(
                    "Wrong proposer. Expected: {}, Got: {}",
                    expected.address, producer
                )));
            }

            if !block.verify_signature() {
                return Err(ConsensusError("Invalid block signature".into()));
            }

            info!(
                "PoA: Block {} signature verified (producer: {})",
                block.index, producer
            );
        } else {
            if block.hash != block.calculate_hash() {
                return Err(ConsensusError("Invalid block hash".into()));
            }
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
        // appear, and consecutive heights are not forced to alternate.
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

    /// Task 0.338 / A6: leader slot is not `block_index % n`.
    #[test]
    fn tur119_leader_not_pure_round_robin() {
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
    }
}
