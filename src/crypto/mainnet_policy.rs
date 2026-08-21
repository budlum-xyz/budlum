//! Mainnet validator key / HSM admission policy (Hardening H4).
//!
//! Pure checks - no process exit - so CI can lock the fail-closed surface.
//! Runtime CLI (`NodeConfig::validate_strict_rules`) and `main` map these
//! Violations to hard process termination.

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
    /// PKCS#11 PIN env var name empty.
    MissingPkcs11PinEnv,
    /// Named PIN environment variable missing or empty.
    EmptyPkcs11Pin,
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
                "softhsm is a software token and is forbidden for mainnet \
                 validators; the signing key must be held by hardware"
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
        if candidate.eq_ignore_ascii_case("softhsm") {
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
    // Güvenlik denetimi (HIGH): SoftHSM modül YOLU (libsofthsm2.so)
    // `pkcs11` backend'iyle geçebiliyordu; "softhsm" backend reddi tek
    // başına yetersizdi. Yolda softhsm geçiyorsa aynı ihlaldir.
    if module.to_ascii_lowercase().contains("softhsm") {
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

    #[test]
    fn accepts_full_pkcs11_config() {
        assert!(check_mainnet_validator_key_policy(&base()).is_ok());
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
    fn rejects_missing_pin_when_resolve_enabled() {
        let mut c = base();
        c.pkcs11_token_pin_env = Some("BUD_HSM_PIN_DOES_NOT_EXIST_XYZ");
        c.resolve_pin_env = true;
        assert_eq!(
            check_mainnet_validator_key_policy(&c),
            Err(MainnetKeyPolicyViolation::EmptyPkcs11Pin)
        );
    }
}
