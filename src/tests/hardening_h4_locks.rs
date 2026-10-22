//! Hardening Protocol H4 regression locks.
//! Marker: REGRESSION - do not delete without replacing coverage.

#[cfg(test)]
mod tests {
    use crate::crypto::mainnet_policy::{
        check_mainnet_validator_key_policy, MainnetKeyPolicyViolation, MainnetValidatorKeyConfig,
    };
    use crate::crypto::primitives::{CryptoError, ValidatorKeys};
    use crate::crypto::{CRITICAL_DOMAIN_TAGS, DOMAIN_TAGS};
    use crate::rpc::server::constant_time_eq_str;
    use std::collections::BTreeSet;

    /// Plaintext BLS/PQ on disk forbidden on mainnet.
    #[test]
    fn mainnet_disk_bls_pq_forbidden() {
        let keys = ValidatorKeys::generate().expect("generate");
        assert_eq!(
            keys.validate_mainnet_disk_policy(true),
            Err(CryptoError::PlaintextDiskKeysForbiddenOnMainnet)
        );
        assert!(keys.validate_mainnet_disk_policy(false).is_ok());
    }

    /// Mainnet validator key admission matrix (pkcs11-only).
    #[test]
    fn mainnet_validator_requires_pkcs11_not_mock_or_disk() {
        let ok = MainnetValidatorKeyConfig {
            signer_backend: Some("pkcs11"),
            raw_signer_backend: Some("pkcs11"),
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

        // SoftHSM is a PKCS#11 provider, so it reaches this policy wearing the
        // same name a hardware token does. `canonical_signer_backend` folds
        // `softhsm` into `pkcs11` before admission runs, which is right for
        // choosing a signer implementation and wrong for deciding whether the
        // key is in hardware. testnet.toml ships `backend = "softhsm"`; before
        // this lock, promoting that profile by editing one `network =` line
        // started a mainnet validator whose signing key lives in a software
        // token on the same disk the policy refuses to read keys from.
        let mut soft_raw = ok.clone();
        soft_raw.raw_signer_backend = Some("softhsm");
        assert_eq!(
            check_mainnet_validator_key_policy(&soft_raw),
            Err(MainnetKeyPolicyViolation::SoftwareHsmBackend),
            "a canonicalised softhsm config must be refused on its raw spelling"
        );

        // And when nothing canonicalised it - `--signer-backend softhsm` on the
        // command line never passes through the config-file path, the
        // canonical field still carries the operator's word.
        let mut soft_direct = ok.clone();
        soft_direct.signer_backend = Some("softhsm");
        soft_direct.raw_signer_backend = None;
        assert_eq!(
            check_mainnet_validator_key_policy(&soft_direct),
            Err(MainnetKeyPolicyViolation::SoftwareHsmBackend),
            "an unnormalised softhsm backend must be refused too"
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

    /// Constant-time eq is equality-correct (timing covered by bench CI).
    #[test]
    fn constant_time_eq_str_correctness() {
        assert!(constant_time_eq_str("secret-value", "secret-value"));
        assert!(!constant_time_eq_str("secret-value", "secret-valuf"));
        assert!(!constant_time_eq_str("short", "longer-secret"));
        assert!(constant_time_eq_str("", ""));
    }

    /// The inventory is sorted and free of duplicates.
    ///
    /// A duplicate entry is the interesting failure: it means two call sites
    /// Believe they own the same separation tag, so a hash or signature made
    /// For one of them verifies for the other.
    #[test]
    fn domain_tag_inventory_is_sorted_and_unique() {
        let unique: BTreeSet<&str> = DOMAIN_TAGS.iter().copied().collect();
        assert_eq!(
            unique.len(),
            DOMAIN_TAGS.len(),
            "duplicate domain tag in inventory: {:?}",
            DOMAIN_TAGS
                .iter()
                .filter(|t| DOMAIN_TAGS.iter().filter(|o| o == t).count() > 1)
                .collect::<BTreeSet<_>>()
        );

        let sorted: Vec<&str> = unique.into_iter().collect();
        assert_eq!(
            sorted, DOMAIN_TAGS,
            "inventory must stay sorted so diffs stay reviewable"
        );
    }

    /// Every tag is well-formed: prefixed, upper snake case, non-empty body.
    #[test]
    fn domain_tags_are_well_formed() {
        for tag in DOMAIN_TAGS {
            let body = tag
                .strip_prefix("BDLM_")
                .unwrap_or_else(|| panic!("tag must carry the BDLM_ prefix: {tag}"));
            assert!(!body.is_empty(), "tag has no body: {tag}");
            assert!(
                body.chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'),
                "tag must be upper snake case: {tag}"
            );
        }
    }

    /// Both legacy-prefixed lists follow the same discipline: sorted, unique,
    /// well formed; and the two lists do not intersect (a tag cannot also count
    /// as a non-domain literal).
    #[test]
    fn legacy_prefix_lists_are_sorted_unique_and_well_formed() {
        use crate::crypto::{BUDLUM_PREFIXED_DOMAIN_TAGS, BUDLUM_PREFIXED_NON_DOMAIN_LITERALS};
        for list in [
            BUDLUM_PREFIXED_DOMAIN_TAGS,
            BUDLUM_PREFIXED_NON_DOMAIN_LITERALS,
        ] {
            let unique: BTreeSet<&str> = list.iter().copied().collect();
            assert_eq!(unique.len(), list.len(), "repeated entry: {list:?}");
            let sorted: Vec<&str> = unique.into_iter().collect();
            assert_eq!(sorted, list, "the list must stay sorted: diff readability");
            for tag in list {
                let body = tag
                    .strip_prefix("BUDLUM_")
                    .unwrap_or_else(|| panic!("tag must carry the BUDLUM_ prefix: {tag}"));
                assert!(!body.is_empty(), "tag has no body: {tag}");
                assert!(
                    body.chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'),
                    "tag must be upper snake case: {tag}"
                );
            }
        }
        let overlap: Vec<&&str> = BUDLUM_PREFIXED_DOMAIN_TAGS
            .iter()
            .filter(|t| BUDLUM_PREFIXED_NON_DOMAIN_LITERALS.contains(t))
            .collect();
        assert!(
            overlap.is_empty(),
            "the two lists must not intersect: {overlap:?}"
        );
    }

    /// The consensus- and custody-critical tags are still in the inventory.
    ///
    /// Named individually so dropping one fails with the tag in the message,
    /// Rather than only moving a total.
    #[test]
    fn critical_domain_tags_are_present() {
        for must in CRITICAL_DOMAIN_TAGS {
            assert!(
                DOMAIN_TAGS.contains(must),
                "inventory missing critical tag {must}"
            );
        }
    }
}
