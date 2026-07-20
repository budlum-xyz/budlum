//! Mainnet validator key / HSM admission policy (Hardening H4).
//!
//! Pure checks — no process exit — so CI can lock the fail-closed surface.
//! Runtime CLI (`NodeConfig::validate_strict_rules`) and `main` map these
//! violations to hard process termination.

/// Why a mainnet validator configuration is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainnetKeyPolicyViolation {
    /// `signer.backend` is not `pkcs11` (includes missing, `local`, `hsm_mock`).
    NonPkcs11Backend,
    /// Explicit mock HSM backend attempted on mainnet.
    HsmMockBackend,
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
    pub validator_key_file: Option<&'a str>,
    pub pkcs11_module_path: Option<&'a str>,
    pub pkcs11_token_pin_env: Option<&'a str>,
    /// When `Some`, the env var is looked up; `None` skips live env check (unit tests).
    pub resolve_pin_env: bool,
}

/// Fail-closed admission for **mainnet + role=validator**.
///
/// Callers that are not mainnet validators must not invoke this.
pub fn check_mainnet_validator_key_policy(
    cfg: &MainnetValidatorKeyConfig<'_>,
) -> Result<(), MainnetKeyPolicyViolation> {
    let backend = cfg.signer_backend.unwrap_or("");
    if backend.eq_ignore_ascii_case("hsm_mock") || backend.eq_ignore_ascii_case("mock") {
        return Err(MainnetKeyPolicyViolation::HsmMockBackend);
    }
    if backend != "pkcs11" {
        return Err(MainnetKeyPolicyViolation::NonPkcs11Backend);
    }
    if cfg
        .validator_key_file
        .map(|s| !s.is_empty())
        .unwrap_or(false)
    {
        return Err(MainnetKeyPolicyViolation::DiskValidatorKeys);
    }
    let module = cfg.pkcs11_module_path.unwrap_or("");
    if module.is_empty() {
        return Err(MainnetKeyPolicyViolation::MissingPkcs11ModulePath);
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
            validator_key_file: None,
            pkcs11_module_path: Some("/usr/lib/softhsm/libsofthsm2.so"),
            pkcs11_token_pin_env: Some("BUD_HSM_PIN"),
            resolve_pin_env: false,
        }
    }

    #[test]
    fn h4_accepts_full_pkcs11_config() {
        assert!(check_mainnet_validator_key_policy(&base()).is_ok());
    }

    #[test]
    fn h4_rejects_missing_backend() {
        let mut c = base();
        c.signer_backend = None;
        assert_eq!(
            check_mainnet_validator_key_policy(&c),
            Err(MainnetKeyPolicyViolation::NonPkcs11Backend)
        );
    }

    #[test]
    fn h4_rejects_local_backend() {
        let mut c = base();
        c.signer_backend = Some("local");
        assert_eq!(
            check_mainnet_validator_key_policy(&c),
            Err(MainnetKeyPolicyViolation::NonPkcs11Backend)
        );
    }

    #[test]
    fn h4_rejects_hsm_mock_backend() {
        let mut c = base();
        c.signer_backend = Some("hsm_mock");
        assert_eq!(
            check_mainnet_validator_key_policy(&c),
            Err(MainnetKeyPolicyViolation::HsmMockBackend)
        );
    }

    #[test]
    fn h4_rejects_disk_validator_keys() {
        let mut c = base();
        c.validator_key_file = Some("/var/lib/budlum/validator.keys");
        assert_eq!(
            check_mainnet_validator_key_policy(&c),
            Err(MainnetKeyPolicyViolation::DiskValidatorKeys)
        );
    }

    #[test]
    fn h4_rejects_empty_module_path() {
        let mut c = base();
        c.pkcs11_module_path = Some("");
        assert_eq!(
            check_mainnet_validator_key_policy(&c),
            Err(MainnetKeyPolicyViolation::MissingPkcs11ModulePath)
        );
    }

    #[test]
    fn h4_rejects_empty_pin_env_name() {
        let mut c = base();
        c.pkcs11_token_pin_env = Some("");
        assert_eq!(
            check_mainnet_validator_key_policy(&c),
            Err(MainnetKeyPolicyViolation::MissingPkcs11PinEnv)
        );
    }

    #[test]
    fn h4_rejects_missing_pin_when_resolve_enabled() {
        let mut c = base();
        c.pkcs11_token_pin_env = Some("BUD_HSM_PIN_DOES_NOT_EXIST_XYZ");
        c.resolve_pin_env = true;
        assert_eq!(
            check_mainnet_validator_key_policy(&c),
            Err(MainnetKeyPolicyViolation::EmptyPkcs11Pin)
        );
    }
}
