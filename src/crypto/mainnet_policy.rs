//! Mainnet validator key / HSM admission policy (Hardening H4).
//!
//! Pure checks - no process exit - so CI can lock the fail-closed surface.
//! Runtime CLI (`NodeConfig::validate_strict_rules`) and `main` map these
//! violations to hard process termination.

use std::collections::BTreeSet;

use crate::crypto::{pq, scheme::SchemeId};
use crate::settlement::anchor_ledger::{ANCHOR_KEY_COUNT, MIN_ANCHOR_VENDORS};

/// Known software PKCS#11 tokens, including the PKCS#11 3.2 CI token.
fn is_software_token(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("softhsm") || lower.contains("kryoptic")
}

/// Whether a PKCS#11 module path names a software token (SoftHSM or
/// kryoptic). Case insensitive, and the symlink target counts too.
#[must_use]
pub fn is_software_token_path(path: &str) -> bool {
    if is_software_token(path) {
        return true;
    }
    std::fs::canonicalize(path)
        .ok()
        .and_then(|resolved| resolved.to_str().map(is_software_token))
        .unwrap_or(false)
}

/// SHA3-256 digests of the PKCS#11 module files a mainnet release sanctions
/// for custody.
///
/// A file-name denylist cannot establish hardware custody. `p11-kit-proxy.so`
/// is a dispatcher that hands the token to whatever module the operator
/// registers, a software token copied to a neutral file name keeps its keys in
/// software, and a bare soname is resolved by the dynamic loader after this
/// check has run. What a release *can* pin is bytes: the module file it built,
/// reviewed and tested against.
///
/// Empty means nothing is sanctioned. Mainnet then refuses to start a validator
/// or an anchor keystore until a release fills this in, which is the
/// fail-closed direction: an unpinned module is an unknown module, not a
/// probably-hardware one.
pub const SANCTIONED_MODULE_DIGESTS: &[[u8; 32]] = &[];

/// Whether `digest` is one of the module digests the release sanctions.
///
/// Split from [`is_sanctioned_module_path`] so the membership rule can be
/// tested without a module file on disk.
#[must_use]
pub fn module_digest_is_sanctioned(digest: &[u8; 32], sanctioned: &[[u8; 32]]) -> bool {
    sanctioned.iter().any(|pinned| pinned == digest)
}

/// SHA3-256 of the file `path` resolves to, following symlinks, or `None` when
/// the file cannot be read.
///
/// The digest is taken over the *resolved* file so a symlink, a copy or a
/// renamed module is judged by its bytes and not by its name.
#[must_use]
pub fn module_digest(path: &str) -> Option<[u8; 32]> {
    use sha3::Digest;
    let resolved = std::fs::canonicalize(path).ok()?;
    let bytes = std::fs::read(resolved).ok()?;
    let hash = sha3::Sha3_256::digest(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    Some(out)
}

/// Whether the PKCS#11 module at `path` is a module the release sanctions.
///
/// This is the custody gate on the mainnet validator and anchor key paths. It
/// answers `false` for anything the release has not pinned, including every
/// module while [`SANCTIONED_MODULE_DIGESTS`] is empty.
#[must_use]
pub fn is_sanctioned_module_path(path: &str) -> bool {
    module_digest(path).is_some_and(|digest| module_digest_is_sanctioned(&digest, SANCTIONED_MODULE_DIGESTS))
}

/// Why a mainnet validator configuration is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainnetKeyPolicyViolation {
    /// `signer.backend` is not `pkcs11` (includes missing, `local`, `hsm_mock`).
    NonPkcs11Backend,
    /// Explicit mock HSM backend attempted on mainnet.
    HsmMockBackend,
    /// A software HSM (`SoftHSM`) was named on mainnet.
    ///
    /// Distinct from `NonPkcs11Backend` because `SoftHSM` *is* a PKCS#11
    /// provider: it speaks the same interface a hardware token does, and the
    /// CLI canonicalises `softhsm` to `pkcs11` before this check ever runs. So
    /// the string never reaches the policy, and a testnet profile promoted to
    /// mainnet by changing one `network =` line keeps its software keys.
    SoftwareHsmBackend,
    /// Disk-backed `ValidatorKeys` path configured.
    DiskValidatorKeys,
    /// PKCS#11 module path empty.
    MissingPkcs11ModulePath,
    /// The PKCS#11 module is not one the release sanctions.
    ///
    /// Distinct from `SoftwareHsmBackend`: that one is a name match against a
    /// known software token, while this one says the module's bytes are not in
    /// the release's pin table at all - which covers every evasion of the name
    /// test (a dispatcher, a renamed copy, an unpinned vendor build).
    UnsignedPkcs11Module,
    /// PKCS#11 PIN env var name empty.
    MissingPkcs11PinEnv,
    /// Named PIN environment variable missing or empty.
    EmptyPkcs11Pin,
    /// No validator ML-DSA-65 public key is announced by the HSM.
    MissingValidatorPqKey,
    /// The HSM's validator public key is not an ML-DSA-65 key.
    InvalidValidatorPqKey,
    /// The ML-DSA-65 key cannot sign inside the HSM without software fallback.
    ValidatorPqNotInHsm,
    /// The anchor must have exactly three HSM-backed keys.
    AnchorKeyCount,
    /// An anchor HSM has no vendor label.
    AnchorVendorMissing,
    /// A software token cannot hold an anchor key on mainnet.
    AnchorSoftwareToken,
    /// Three anchor HSM keys must span at least two vendors.
    AnchorVendorDiversity,
}

impl std::fmt::Display for MainnetKeyPolicyViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonPkcs11Backend => {
                write!(f, "mainnet validators require signer.backend = 'pkcs11'")
            }
            Self::HsmMockBackend => {
                write!(f, "hsm_mock is forbidden for mainnet validators")
            }
            Self::SoftwareHsmBackend => write!(
                f,
                "software PKCS#11 tokens (softhsm/kryoptic) are forbidden on mainnet; signing keys must be held by hardware"
            ),
            Self::DiskValidatorKeys => write!(
                f,
                "mainnet validators must not load ValidatorKeys from disk"
            ),
            Self::MissingPkcs11ModulePath => {
                write!(f, "mainnet validators require pkcs11 module_path")
            }
            Self::MissingPkcs11PinEnv => {
                write!(f, "mainnet validators require pkcs11 token_pin_env")
            }
            Self::EmptyPkcs11Pin => {
                write!(f, "pkcs11 PIN environment variable is missing or empty")
            }
            Self::MissingValidatorPqKey => write!(f, "mainnet validator HSM has no ML-DSA-65 public key"),
            Self::InvalidValidatorPqKey => write!(f, "mainnet validator HSM public key is not ML-DSA-65"),
            Self::ValidatorPqNotInHsm => write!(f, "mainnet validator ML-DSA-65 signing must be performed inside the HSM"),
            Self::AnchorKeyCount => write!(f, "mainnet anchors require exactly three HSM keys"),
            Self::AnchorVendorMissing => write!(f, "mainnet anchor HSM vendor labels must not be empty"),
            Self::AnchorSoftwareToken => write!(f, "software tokens cannot hold mainnet anchor keys"),
            Self::AnchorVendorDiversity => write!(f, "mainnet anchor keys require at least two HSM vendors"),
        }
    }
}

/// Inputs for mainnet validator key-path admission (no I/O except optional pin lookup).
#[derive(Debug, Clone)]
pub struct MainnetValidatorKeyConfig<'a> {
    pub signer_backend: Option<&'a str>,
    /// The backend exactly as the operator wrote it, before the CLI's
    /// `canonical_signer_backend` folds `softhsm` into `pkcs11`.
    ///
    /// Without this the policy cannot tell the two apart: by the time it runs,
    /// a `SoftHSM` configuration is indistinguishable from a hardware one. Leave
    /// as `None` when there is no separate raw value to report.
    pub raw_signer_backend: Option<&'a str>,
    pub validator_key_file: Option<&'a str>,
    pub pkcs11_module_path: Option<&'a str>,
    pub pkcs11_token_pin_env: Option<&'a str>,
    /// When `Some`, the env var is looked up; `None` skips live env check (unit tests).
    pub resolve_pin_env: bool,
}

/// Fail-closed admission for **mainnet + role=validator**.
///
/// Callers that are not mainnet validators must not invoke this.
///
/// # Errors
///
/// Returns the first [`MainnetKeyPolicyViolation`] the configuration trips:
/// a software or mock backend, a non-PKCS#11 backend, a disk-backed key file,
/// a missing module path or PIN environment variable, or an empty PIN.
pub fn check_mainnet_validator_key_policy(
    cfg: &MainnetValidatorKeyConfig<'_>,
) -> Result<(), MainnetKeyPolicyViolation> {
    let backend = cfg.signer_backend.unwrap_or("");
    // Check the operator's own spelling first, then the canonical form. The
    // canonicaliser maps `softhsm` onto `pkcs11`, which is right for wiring up
    // a signer and wrong for deciding whether the key is in hardware.
    // When no raw value was recorded - the operator passed `--signer-backend`
    // directly, so nothing canonicalised it - the canonical field still holds
    // their spelling and the loop below checks it either way.
    let raw = cfg.raw_signer_backend.unwrap_or(backend);
    for candidate in [raw, backend] {
        if candidate.eq_ignore_ascii_case("hsm_mock") || candidate.eq_ignore_ascii_case("mock") {
            return Err(MainnetKeyPolicyViolation::HsmMockBackend);
        }
        if is_software_token(candidate) {
            return Err(MainnetKeyPolicyViolation::SoftwareHsmBackend);
        }
    }
    if backend != "pkcs11" {
        return Err(MainnetKeyPolicyViolation::NonPkcs11Backend);
    }
    if cfg.validator_key_file.is_some_and(|s| !s.is_empty()) {
        return Err(MainnetKeyPolicyViolation::DiskValidatorKeys);
    }
    let module = cfg.pkcs11_module_path.unwrap_or("");
    if module.is_empty() {
        return Err(MainnetKeyPolicyViolation::MissingPkcs11ModulePath);
    }
    // The module's configured and resolved names must both reject software
    // tokens: a neutral symlink must not hide libsofthsm or libkryoptic.
    // The loader handles a nonexistent path itself.
    let resolved = std::fs::canonicalize(module).ok();
    if is_software_token(module)
        || resolved
            .as_deref()
            .and_then(std::path::Path::to_str)
            .is_some_and(is_software_token)
    {
        return Err(MainnetKeyPolicyViolation::SoftwareHsmBackend);
    }
    let pin_env = cfg.pkcs11_token_pin_env.unwrap_or("");
    if pin_env.is_empty() {
        return Err(MainnetKeyPolicyViolation::MissingPkcs11PinEnv);
    }
    if cfg.resolve_pin_env {
        match std::env::var(pin_env) {
            Ok(pin) if !pin.is_empty() => {}
            _ => return Err(MainnetKeyPolicyViolation::EmptyPkcs11Pin),
        }
    }
    // Bytes, not names: the release pins the module it tested. A denylist can
    // only name the software tokens somebody thought of.
    if !is_sanctioned_module_path(module) {
        return Err(MainnetKeyPolicyViolation::UnsignedPkcs11Module);
    }
    Ok(())
}

/// Admit an HSM-backed validator PQ key after the signer has proven it can
/// sign the startup binding challenge in strict (no-fallback) HSM mode.
///
/// A mechanism ID or an operator-supplied public key alone does not prove
/// custody. The caller must set `hsm_binding_verified` only after a signature
/// from the strict HSM path verifies against the announced key.
pub fn check_mainnet_validator_pq_hsm_policy(
    pq_public_key: Option<&[u8]>,
    hsm_binding_verified: bool,
) -> Result<(), MainnetKeyPolicyViolation> {
    let key = pq_public_key.ok_or(MainnetKeyPolicyViolation::MissingValidatorPqKey)?;
    pq::validate_public_key(SchemeId::ML_DSA_65, key)
        .map_err(|_| MainnetKeyPolicyViolation::InvalidValidatorPqKey)?;
    if !hsm_binding_verified {
        return Err(MainnetKeyPolicyViolation::ValidatorPqNotInHsm);
    }
    Ok(())
}

/// Check the anchor ceremony's three HSM vendor declarations.
/// Separate physical devices must also be attested by the ceremony; vendor
/// labels alone cannot establish physical separation.
pub fn check_mainnet_anchor_vendor_policy(
    vendors: &[&str],
) -> Result<(), MainnetKeyPolicyViolation> {
    if vendors.len() != ANCHOR_KEY_COUNT {
        return Err(MainnetKeyPolicyViolation::AnchorKeyCount);
    }
    if vendors.iter().any(|vendor| vendor.trim().is_empty()) {
        return Err(MainnetKeyPolicyViolation::AnchorVendorMissing);
    }
    if vendors.iter().any(|vendor| is_software_token(vendor)) {
        return Err(MainnetKeyPolicyViolation::AnchorSoftwareToken);
    }
    // A case or surrounding whitespace change does not create a new vendor.
    if vendors
        .iter()
        .map(|vendor| vendor.trim().to_ascii_lowercase())
        .collect::<BTreeSet<_>>()
        .len()
        < MIN_ANCHOR_VENDORS
    {
        return Err(MainnetKeyPolicyViolation::AnchorVendorDiversity);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> MainnetValidatorKeyConfig<'static> {
        MainnetValidatorKeyConfig {
            signer_backend: Some("pkcs11"),
            raw_signer_backend: Some("pkcs11"),
            validator_key_file: None,
            // A hardware module path. The fixture used to name
            // libsofthsm2.so, which made the "accepts a full pkcs11 config"
            // test assert that a software token is acceptable on mainnet.
            pkcs11_module_path: Some("/opt/nfast/toolkits/pkcs11/libcknfast.so"),
            pkcs11_token_pin_env: Some("BUD_HSM_PIN"),
            resolve_pin_env: false,
        }
    }

    /// The fixture path is a hardware module by name, and a full, otherwise
    /// valid PKCS#11 configuration now stops at the pin table: no release
    /// sanctions it, so nothing is admitted. Before the digest gate this test
    /// asserted `is_ok()` and that assertion was the hole.
    #[test]
    fn refuses_a_module_no_release_pins() {
        assert_eq!(
            check_mainnet_validator_key_policy(&base()),
            Err(MainnetKeyPolicyViolation::UnsignedPkcs11Module)
        );
    }

    #[test]
    fn the_pin_table_is_a_membership_rule_over_digests() {
        let pinned = [[0x11u8; 32], [0x22u8; 32]];
        assert!(module_digest_is_sanctioned(&[0x11u8; 32], &pinned));
        assert!(!module_digest_is_sanctioned(&[0x33u8; 32], &pinned));
        // Nothing pinned means nothing admitted, including on an empty table.
        assert!(!module_digest_is_sanctioned(&[0u8; 32], &[]));
        assert!(!is_sanctioned_module_path("/nonexistent/libpkcs11.so"));
    }

    #[test]
    fn rejects_missing_backend() {
        let mut c = base();
        c.signer_backend = None;
        assert_eq!(
            check_mainnet_validator_key_policy(&c),
            Err(MainnetKeyPolicyViolation::NonPkcs11Backend)
        );
    }

    #[test]
    fn rejects_local_backend() {
        let mut c = base();
        c.signer_backend = Some("local");
        assert_eq!(
            check_mainnet_validator_key_policy(&c),
            Err(MainnetKeyPolicyViolation::NonPkcs11Backend)
        );
    }

    #[test]
    fn rejects_hsm_mock_backend() {
        let mut c = base();
        c.signer_backend = Some("hsm_mock");
        assert_eq!(
            check_mainnet_validator_key_policy(&c),
            Err(MainnetKeyPolicyViolation::HsmMockBackend)
        );
    }

    #[test]
    fn rejects_disk_validator_keys() {
        let mut c = base();
        c.validator_key_file = Some("/var/lib/budlum/validator.keys");
        assert_eq!(
            check_mainnet_validator_key_policy(&c),
            Err(MainnetKeyPolicyViolation::DiskValidatorKeys)
        );
    }

    #[test]
    fn rejects_empty_module_path() {
        let mut c = base();
        c.pkcs11_module_path = Some("");
        assert_eq!(
            check_mainnet_validator_key_policy(&c),
            Err(MainnetKeyPolicyViolation::MissingPkcs11ModulePath)
        );
    }

    #[test]
    fn rejects_empty_pin_env_name() {
        let mut c = base();
        c.pkcs11_token_pin_env = Some("");
        assert_eq!(
            check_mainnet_validator_key_policy(&c),
            Err(MainnetKeyPolicyViolation::MissingPkcs11PinEnv)
        );
    }

    #[test]
    fn rejects_softhsm_in_module_path() {
        let mut c = base();
        c.pkcs11_module_path = Some("/usr/lib/softhsm/libsofthsm2.so");
        assert_eq!(
            check_mainnet_validator_key_policy(&c),
            Err(MainnetKeyPolicyViolation::SoftwareHsmBackend)
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_softhsm_behind_neutral_symlink() {
        // BLG-0044: a symlink with a neutral name must not hide a software
        // token, so the resolved path is checked too.
        let dir = std::env::temp_dir().join(format!("bud_softhsm_link_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let real = dir.join("libsofthsm2.so");
        std::fs::write(&real, b"fake").unwrap();
        let link = dir.join("neutral-name.so");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let path_str = link.to_str().unwrap().to_string();
        let cfg = MainnetValidatorKeyConfig {
            signer_backend: Some("pkcs11"),
            raw_signer_backend: Some("pkcs11"),
            validator_key_file: None,
            pkcs11_module_path: Some(path_str.as_str()),
            pkcs11_token_pin_env: Some("BUD_HSM_PIN"),
            resolve_pin_env: false,
        };
        let outcome = check_mainnet_validator_key_policy(&cfg);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(outcome, Err(MainnetKeyPolicyViolation::SoftwareHsmBackend));
    }

    #[test]
    fn rejects_missing_pin_when_resolve_enabled() {
        let mut c = base();
        c.pkcs11_token_pin_env = Some("BUD_HSM_PIN_DOES_NOT_EXIST_XYZ");
        c.resolve_pin_env = true;
        assert_eq!(
            check_mainnet_validator_key_policy(&c),
            Err(MainnetKeyPolicyViolation::EmptyPkcs11Pin)
        );
    }

    #[test]
    fn rejects_softhsm_backend_in_any_case() {
        for spelling in ["softhsm", "SoftHSM", "SOFTHSM"] {
            let mut c = base();
            c.signer_backend = Some("pkcs11");
            c.raw_signer_backend = Some(spelling);
            assert_eq!(
                check_mainnet_validator_key_policy(&c),
                Err(MainnetKeyPolicyViolation::SoftwareHsmBackend),
                "{spelling}"
            );
        }
        let mut c = base();
        c.signer_backend = Some("softhsm");
        c.raw_signer_backend = None;
        assert_eq!(
            check_mainnet_validator_key_policy(&c),
            Err(MainnetKeyPolicyViolation::SoftwareHsmBackend)
        );
    }

    #[test]
    fn rejects_mock_alias_in_any_case() {
        for spelling in ["mock", "Mock", "MOCK"] {
            let mut c = base();
            c.signer_backend = Some(spelling);
            c.raw_signer_backend = None;
            assert_eq!(
                check_mainnet_validator_key_policy(&c),
                Err(MainnetKeyPolicyViolation::HsmMockBackend),
                "{spelling}"
            );
        }
    }

    #[test]
    fn rejects_softhsm_module_path_in_any_case() {
        for module in [
            "/usr/lib/softhsm/libsofthsm2.so",
            "/usr/lib/SoftHSM/LIBSOFTHSM2.SO",
        ] {
            let mut c = base();
            c.pkcs11_module_path = Some(module);
            assert_eq!(
                check_mainnet_validator_key_policy(&c),
                Err(MainnetKeyPolicyViolation::SoftwareHsmBackend),
                "{module}"
            );
        }
    }

    #[test]
    fn refuses_kryoptic_software_token_under_pkcs11() {
        for backend in ["kryoptic", "KRYOPTIC"] {
            let mut c = base();
            c.raw_signer_backend = Some(backend);
            assert_eq!(
                check_mainnet_validator_key_policy(&c),
                Err(MainnetKeyPolicyViolation::SoftwareHsmBackend)
            );
        }
        for module in ["/usr/lib/libkryoptic_pkcs11.so", "/usr/lib/KRYOPTIC.so"] {
            let mut c = base();
            c.pkcs11_module_path = Some(module);
            assert_eq!(
                check_mainnet_validator_key_policy(&c),
                Err(MainnetKeyPolicyViolation::SoftwareHsmBackend)
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn refuses_kryoptic_hidden_behind_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("libkryoptic.so");
        std::fs::write(&real, b"not an actual token").unwrap();
        let link = dir.path().join("neutral.so");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let link = link.to_str().unwrap();
        let mut c = base();
        c.pkcs11_module_path = Some(link);
        assert_eq!(
            check_mainnet_validator_key_policy(&c),
            Err(MainnetKeyPolicyViolation::SoftwareHsmBackend)
        );
    }

    #[test]
    fn validator_requires_hsm_bound_ml_dsa_65() {
        let key = vec![0u8; pq::public_key_len(SchemeId::ML_DSA_65).unwrap()];
        assert_eq!(
            check_mainnet_validator_pq_hsm_policy(None, true),
            Err(MainnetKeyPolicyViolation::MissingValidatorPqKey)
        );
        assert_eq!(
            check_mainnet_validator_pq_hsm_policy(Some(&key[..key.len() - 1]), true),
            Err(MainnetKeyPolicyViolation::InvalidValidatorPqKey)
        );
        assert_eq!(
            check_mainnet_validator_pq_hsm_policy(Some(&key), false),
            Err(MainnetKeyPolicyViolation::ValidatorPqNotInHsm)
        );
        assert!(check_mainnet_validator_pq_hsm_policy(Some(&key), true).is_ok());
    }

    #[test]
    fn anchor_requires_three_keys_across_two_hardware_vendors() {
        assert!(check_mainnet_anchor_vendor_policy(&["nfast", "nfast", "utimaco"]).is_ok());
        assert_eq!(
            check_mainnet_anchor_vendor_policy(&["nfast", "utimaco"]),
            Err(MainnetKeyPolicyViolation::AnchorKeyCount)
        );
        assert_eq!(
            check_mainnet_anchor_vendor_policy(&["nfast", " ", "utimaco"]),
            Err(MainnetKeyPolicyViolation::AnchorVendorMissing)
        );
        assert_eq!(
            check_mainnet_anchor_vendor_policy(&["nfast", "nfast", "nfast"]),
            Err(MainnetKeyPolicyViolation::AnchorVendorDiversity)
        );
        assert_eq!(
            check_mainnet_anchor_vendor_policy(&["nfast", "NFAST ", "nFast"]),
            Err(MainnetKeyPolicyViolation::AnchorVendorDiversity)
        );
        for token in ["kryoptic", "SoftHSM"] {
            assert_eq!(
                check_mainnet_anchor_vendor_policy(&["nfast", "utimaco", token]),
                Err(MainnetKeyPolicyViolation::AnchorSoftwareToken)
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_symlink_that_hides_softhsm() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("libsofthsm2.so");
        std::fs::write(&real, b"x").unwrap();
        let link = dir.path().join("libvendor.so");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let link_str = link.to_str().unwrap().to_string();
        let mut c: MainnetValidatorKeyConfig<'_> = base();
        c.pkcs11_module_path = Some(&link_str);
        assert_eq!(
            check_mainnet_validator_key_policy(&c),
            Err(MainnetKeyPolicyViolation::SoftwareHsmBackend)
        );
    }
}
