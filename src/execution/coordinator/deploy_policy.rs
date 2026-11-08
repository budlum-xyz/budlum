//! Per-environment contract deployment policy (`--enable-ee-deploy`).
//!
//! Section 8.15.2 freezes new contract deployments on `WASM`, `SVM`, and `Move`
//! in Phase 1 unless explicitly enabled via `--enable-ee-deploy=wasm,svm,move`,
//! while `EVM` and `BudZero` deployments are open and existing contracts in all
//! environments continue to execute normally.

use budlum_uel_abi::{EeId, EeRefusal, RefusalCode};

/// Per-environment deployment switchboard for the Execution Coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeployPolicy {
    pub evm: bool,
    pub wasm: bool,
    pub svm: bool,
    pub move_vm: bool,
    pub budzero: bool,
}

impl Default for DeployPolicy {
    fn default() -> Self {
        Self::phase1_default()
    }
}

impl DeployPolicy {
    /// Phase-1 production default: `EVM` and `BudZero` open; `WASM`, `SVM`, `Move` frozen.
    #[must_use]
    pub const fn phase1_default() -> Self {
        Self {
            evm: true,
            wasm: false,
            svm: false,
            move_vm: false,
            budzero: true,
        }
    }

    /// Enable deployments across all five execution environments (for tests/devnets).
    ///
    /// Convenience: exposed for integration tests and devnet node configurations.
    #[must_use]
    pub const fn allow_all() -> Self {
        Self {
            evm: true,
            wasm: true,
            svm: true,
            move_vm: true,
            budzero: true,
        }
    }

    /// Parse `--enable-ee-deploy=wasm,svm,move` on top of [`Self::phase1_default`].
    ///
    /// Convenience: exposed for CLI flag parsing in node startup.
    pub fn from_cli_csv(csv: &str) -> Result<Self, String> {
        let mut policy = Self::phase1_default();
        for raw in csv.split(',') {
            let token = raw.trim();
            if token.is_empty() {
                continue;
            }
            match token {
                "evm" => policy.evm = true,
                "wasm" | "cosmwasm" => policy.wasm = true,
                "svm" => policy.svm = true,
                "move" => policy.move_vm = true,
                "budzero" => policy.budzero = true,
                other => {
                    return Err(format!(
                        "unknown execution environment `{other}` in --enable-ee-deploy"
                    ));
                }
            }
        }
        Ok(policy)
    }

    /// Returns whether new contract deployments are enabled in `ee`.
    #[must_use]
    pub const fn is_deploy_enabled(&self, ee: EeId) -> bool {
        match ee {
            EeId::EVM => self.evm,
            EeId::WASM => self.wasm,
            EeId::SVM => self.svm,
            EeId::MOVE => self.move_vm,
            EeId::BUDZERO => self.budzero,
            _ => false,
        }
    }

    /// Deterministic refusal when a deploy targets a frozen environment.
    ///
    /// Convenience: called by the execution coordinator before `validate_deploy` / `Deploy`.
    pub fn check_deploy_allowed(&self, ee: EeId) -> Result<(), EeRefusal> {
        if self.is_deploy_enabled(ee) {
            Ok(())
        } else {
            Err(EeRefusal {
                code: RefusalCode::Denied,
                message: format!(
                    "contract deployment in environment 0x{:02x} is disabled by policy",
                    ee.0
                ),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ee_feature_flag_freezes_new_deploys() {
        let p = DeployPolicy::phase1_default();
        assert!(p.check_deploy_allowed(EeId::EVM).is_ok());
        assert!(p.check_deploy_allowed(EeId::BUDZERO).is_ok());
        assert_eq!(
            p.check_deploy_allowed(EeId::WASM).unwrap_err().code,
            RefusalCode::Denied
        );
        assert_eq!(
            p.check_deploy_allowed(EeId::SVM).unwrap_err().code,
            RefusalCode::Denied
        );
        assert_eq!(
            p.check_deploy_allowed(EeId::MOVE).unwrap_err().code,
            RefusalCode::Denied
        );

        let opened = DeployPolicy::from_cli_csv("wasm,svm,move").unwrap();
        assert!(opened.check_deploy_allowed(EeId::WASM).is_ok());
        assert!(opened.check_deploy_allowed(EeId::SVM).is_ok());
        assert!(opened.check_deploy_allowed(EeId::MOVE).is_ok());
        assert!(DeployPolicy::from_cli_csv("unknown_vm").is_err());
    }
}
