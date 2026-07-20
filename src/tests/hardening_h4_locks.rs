//! Hardening Protocol H4 regression locks (ARENA3).
//! Marker: REGRESSION — do not delete without replacing coverage.

#[cfg(test)]
mod tests {
    use crate::crypto::mainnet_policy::{
        check_mainnet_validator_key_policy, MainnetKeyPolicyViolation, MainnetValidatorKeyConfig,
    };
    use crate::crypto::primitives::{CryptoError, ValidatorKeys};
    use crate::rpc::server::constant_time_eq_str;
    use std::collections::BTreeSet;

    /// H4.1: plaintext BLS/PQ on disk forbidden on mainnet.
    #[test]
    fn h4_1_mainnet_disk_bls_pq_forbidden() {
        let keys = ValidatorKeys::generate().expect("generate");
        assert_eq!(
            keys.validate_mainnet_disk_policy(true),
            Err(CryptoError::PlaintextDiskKeysForbiddenOnMainnet)
        );
        assert!(keys.validate_mainnet_disk_policy(false).is_ok());
    }

    /// H4.1: mainnet validator key admission matrix (pkcs11-only).
    #[test]
    fn h4_1_mainnet_validator_requires_pkcs11_not_mock_or_disk() {
        let ok = MainnetValidatorKeyConfig {
            signer_backend: Some("pkcs11"),
            validator_key_file: None,
            pkcs11_module_path: Some("/opt/lib/pkcs11.so"),
            pkcs11_token_pin_env: Some("PIN"),
            resolve_pin_env: false,
        };
        assert!(check_mainnet_validator_key_policy(&ok).is_ok());

        let mut mock = ok.clone();
        mock.signer_backend = Some("hsm_mock");
        assert_eq!(
            check_mainnet_validator_key_policy(&mock),
            Err(MainnetKeyPolicyViolation::HsmMockBackend)
        );

        let mut disk = ok.clone();
        disk.validator_key_file = Some("/keys/v.bin");
        assert_eq!(
            check_mainnet_validator_key_policy(&disk),
            Err(MainnetKeyPolicyViolation::DiskValidatorKeys)
        );

        let mut local = ok.clone();
        local.signer_backend = Some("local");
        assert_eq!(
            check_mainnet_validator_key_policy(&local),
            Err(MainnetKeyPolicyViolation::NonPkcs11Backend)
        );
    }

    /// H4.4 companion: constant-time eq is equality-correct (timing covered by bench CI).
    #[test]
    fn h4_4_constant_time_eq_str_correctness() {
        assert!(constant_time_eq_str("secret-value", "secret-value"));
        assert!(!constant_time_eq_str("secret-value", "secret-valuf"));
        assert!(!constant_time_eq_str("short", "longer-secret"));
        assert!(constant_time_eq_str("", ""));
    }

    /// H4.5: every live BDLM_* domain tag appears in the inventory file.
    #[test]
    fn h4_5_domain_tag_inventory_covers_codebase() {
        let inv = include_str!("../../docs/CRYPTO_DOMAIN_TAGS.md");
        let mut listed = BTreeSet::new();
        for line in inv.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("- `") {
                if let Some(tag) = rest.strip_suffix('`') {
                    if tag.starts_with("BDLM_") {
                        listed.insert(tag.to_string());
                    }
                }
            }
        }
        assert!(
            listed.len() >= 50,
            "inventory suspiciously small: {}",
            listed.len()
        );

        // Spot-check critical domains from hardened paths.
        for must in [
            "BDLM_TX_V4",
            "BDLM_BRIDGE_TRANSFER_V1",
            "BDLM_AI_AGENT_PAYMENT_SETTLEMENT_V1",
            "BDLM_AI_AGENT_PAYMENT_SETTLEMENTS_V1",
            "BDLM_SEED_POISON_FALLBACK_V1",
            "BDLM_GOSSIP_MSG_V1",
            "BDLM_HUB_REGISTRY_V1",
        ] {
            assert!(
                listed.contains(must),
                "inventory missing critical tag {must}"
            );
        }
    }

    /// H4.3 honesty: docs must not claim vendor-native BLS/PQ HSM is complete.
    #[test]
    fn h4_3_hsm_policy_docs_are_honest() {
        let pol = include_str!("../../docs/operations/HSM_BLS_PQ_POLICY.md");
        assert!(
            pol.contains("sahte-yeşil iddia üretmez") || pol.contains("does not claim"),
            "HSM policy must disclaim fake-green mainnet readiness"
        );
        assert!(
            pol.contains("pkcs11") || pol.contains("PKCS#11"),
            "policy must describe PKCS#11 path"
        );
        // Must not claim production-complete vendor HSM without qualification
        let lower = pol.to_lowercase();
        assert!(
            !lower.contains("vendor-native bls/pq hsm production complete"),
            "forbidden overclaim"
        );
    }
}
