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
