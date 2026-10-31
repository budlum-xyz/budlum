//! Regression canary tests - they run on the CI runner, to avoid the sandbox
//! OOM.

#[cfg(test)]
mod tests {
    use crate::consensus::pos::{PoSConfig, PoSEngine};
    use crate::domain::registry::ConsensusDomainRegistry;

    /// Canary: `ConsensusDomainRegistry::new` starts empty. Inside `try_reorg`
    /// there is an assignment `domain_registry = ConsensusDomainRegistry::new`,
    /// so stale state is cleared.
    #[test]
    fn domain_registry_new_is_empty_after_reorg_reset() {
        let registry = ConsensusDomainRegistry::new();
        // No domain is registered, so nothing stale survives the reorg. There is
        // no `iter` method; the existing `domains` (a Vec<ConsensusDomain>) is
        // used.
        assert!(
            registry.domains().is_empty(),
            "fresh ConsensusDomainRegistry must be empty"
        );
    }

    /// A domain registered on the abandoned chain is gone after a reorg.
    #[test]
    fn a_reorg_clears_a_domain_registered_on_the_abandoned_chain() {
        use crate::chain::blockchain::Blockchain;
        use crate::consensus::pow::PoWEngine;
        use crate::core::address::Address;
        use crate::domain::plugin::default_domain;
        use crate::domain::ConsensusKind;
        use std::sync::Arc;

        let consensus = Arc::new(PoWEngine::new(0));
        let mut chain_a = Blockchain::new(consensus.clone(), None, 45262, None);
        let mut chain_b = Blockchain::new(consensus, None, 45262, None);
        let producer = Address::from([0x50; 32]);

        let domain = default_domain(7, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 0);
        chain_a
            .register_consensus_domain(domain)
            .expect("domain registers");
        assert!(chain_a.domain_registry.domains().iter().any(|d| d.id == 7));

        for _ in 0..3 {
            let _ = chain_a.produce_block(producer);
        }
        for _ in 0..5 {
            let _ = chain_b.produce_block(producer);
        }
        chain_a
            .try_reorg(chain_b.chain.clone())
            .expect("the longer chain is adopted");

        assert!(
            !chain_a.domain_registry.domains().iter().any(|d| d.id == 7),
            "a domain from the abandoned chain must not survive the reorg"
        );
    }

    /// Canary: calculate_seed deterministic + non-zero verir.
    /// Poison path (Err→fallback hash) kodda mevcut; bu test temel
    /// It verifies determinism. The poison itself is a separate integration
    /// test.
    #[test]
    fn pos_seed_is_deterministic_and_nonzero() {
        let config = PoSConfig::default();
        let engine = PoSEngine::new(config, None);

        let seed1 = engine.calculate_seed(1, 1, 0, "validators_hash_1");
        let seed2 = engine.calculate_seed(1, 1, 0, "validators_hash_1");
        let seed3 = engine.calculate_seed(1, 2, 0, "validators_hash_1");

        // The same inputs give the same seed - deterministic.
        assert_eq!(seed1, seed2, "same inputs must produce same seed");
        // A different epoch gives a different seed.
        assert_ne!(seed1, seed3, "different epoch must produce different seed");
        // The seed can never be zero, including on the poison fallback.
        assert_ne!(seed1, [0u8; 32], "seed must never be all-zero");
    }
}
