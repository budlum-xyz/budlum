//! Regression canary tests - CI runner'da çalışır (sandbox OOM kaçınımı).

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::consensus::pos::{PoSConfig, PoSEngine};
    use crate::domain::registry::ConsensusDomainRegistry;

    /// Canary: ConsensusDomainRegistry::new boş başlar.
    /// Try_reorg içinde domain_registry = ConsensusDomainRegistry::new
    /// Ataması var - stale state temizlenir.
    #[test]
    fn domain_registry_new_is_empty_after_reorg_reset() {
        let registry = ConsensusDomainRegistry::new();
        // Kayıtlı domain yok → reorg sonrası stale kalmaz.
        // `iter` metodu yok; mevcut `domains` (Vec<ConsensusDomain>) kullanılır.
        assert!(
            registry.domains().is_empty(),
            "fresh ConsensusDomainRegistry must be empty"
        );
    }

    /// Canary: calculate_seed deterministic + non-zero verir.
    /// Poison path (Err→fallback hash) kodda mevcut; bu test temel
    /// Determinism'i doğrular. Poison'un kendisi ayrı bir integration test.
    #[test]
    fn pos_seed_is_deterministic_and_nonzero() {
        let config = PoSConfig::default();
        let engine = PoSEngine::new(config, None);

        let seed1 = engine.calculate_seed(1, 1, 0, "validators_hash_1");
        let seed2 = engine.calculate_seed(1, 1, 0, "validators_hash_1");
        let seed3 = engine.calculate_seed(1, 2, 0, "validators_hash_1");

        // Aynı girdiler → aynı seed (deterministic).
        assert_eq!(seed1, seed2, "same inputs must produce same seed");
        // Farklı epoch → farklı seed.
        assert_ne!(seed1, seed3, "different epoch must produce different seed");
        // Seed sıfır olamaz (poison fallback dahil).
        assert_ne!(seed1, [0u8; 32], "seed must never be all-zero");
    }
}
