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
    pub move_sui: bool,
    pub cairo: bool,
    pub near_wasm: bool,
    pub polkavm: bool,
    pub tvm: bool,
    pub utxo: bool,
    pub plutus: bool,
}

impl Default for DeployPolicy {
    fn default() -> Self {
        Self::phase1_default()
    }
}

impl DeployPolicy {
    /// Phase-1 mainnet default: `EVM` and `BudZero` open; expansion environments frozen.
    #[must_use]
    pub const fn phase1_default() -> Self {
        Self {
            evm: true,
            wasm: false,
            svm: false,
            move_vm: false,
            budzero: true,
            move_sui: false,
            cairo: false,
            near_wasm: false,
            polkavm: false,
            tvm: false,
            utxo: false,
            plutus: false,
        }
    }

    /// Enable deployments across all execution environments (for testnet/devnet/tests).
    ///
    /// Convenience: exposed for integration tests and testnet/devnet node configurations.
    #[must_use]
    pub const fn allow_all() -> Self {
        Self {
            evm: true,
            wasm: true,
            svm: true,
            move_vm: true,
            budzero: true,
            move_sui: true,
            cairo: true,
            near_wasm: true,
            polkavm: true,
            tvm: true,
            utxo: true,
            plutus: true,
        }
    }

    /// Network-aware deployment policy: open across all EEs on Testnet
    /// (`45261`) and Devnet (`45262`); Phase-1 default on Mainnet (`45260`).
    #[must_use]
    pub fn for_chain_id(chain_id: u64) -> Self {
        use crate::core::chain_config::Network;
        if chain_id == Network::Testnet.chain_id().value()
            || chain_id == Network::Devnet.chain_id().value()
        {
            Self::allow_all()
        } else {
            Self::phase1_default()
        }
    }

    /// Parse `--enable-ee-deploy=wasm,svm,move` on top of [`Self::phase1_default`].
    ///
    /// Convenience: exposed for CLI flag parsing in node startup.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
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
                "move-sui" | "sui" => policy.move_sui = true,
                "cairo" | "starknet" => policy.cairo = true,
                "near" | "near-wasm" => policy.near_wasm = true,
                "polkavm" | "pvm" => policy.polkavm = true,
                "tvm" | "ton" => policy.tvm = true,
                "utxo" | "btc" => policy.utxo = true,
                "plutus" | "cardano" => policy.plutus = true,
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
            EeId::MOVE_SUI => self.move_sui,
            EeId::CAIRO => self.cairo,
            EeId::NEAR_WASM => self.near_wasm,
            EeId::POLKAVM => self.polkavm,
            EeId::TVM => self.tvm,
            EeId::UTXO => self.utxo,
            EeId::PLUTUS => self.plutus,
            _ => false,
        }
    }

    /// Deterministic refusal when a deploy targets a frozen environment.
    ///
    /// Convenience: called by the execution coordinator before `validate_deploy` / `Deploy`.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
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

        let opened = DeployPolicy::from_cli_csv(
            "wasm,svm,move,move-sui,cairo,near,polkavm,tvm,utxo,plutus",
        )
        .unwrap();
        assert!(opened.check_deploy_allowed(EeId::WASM).is_ok());
        assert!(opened.check_deploy_allowed(EeId::SVM).is_ok());
        assert!(opened.check_deploy_allowed(EeId::MOVE).is_ok());
        assert!(opened.check_deploy_allowed(EeId::MOVE_SUI).is_ok());
        assert!(opened.check_deploy_allowed(EeId::CAIRO).is_ok());
        assert!(opened.check_deploy_allowed(EeId::NEAR_WASM).is_ok());
        assert!(opened.check_deploy_allowed(EeId::POLKAVM).is_ok());
        assert!(opened.check_deploy_allowed(EeId::TVM).is_ok());
        assert!(opened.check_deploy_allowed(EeId::UTXO).is_ok());
        assert!(opened.check_deploy_allowed(EeId::PLUTUS).is_ok());
        assert!(DeployPolicy::from_cli_csv("unknown_vm").is_err());

        let testnet_policy = DeployPolicy::for_chain_id(45_261);
        for id in [
            EeId::BUDZERO,
            EeId::EVM,
            EeId::WASM,
            EeId::SVM,
            EeId::MOVE,
            EeId::MOVE_SUI,
            EeId::CAIRO,
            EeId::NEAR_WASM,
            EeId::POLKAVM,
            EeId::TVM,
            EeId::UTXO,
            EeId::PLUTUS,
        ] {
            assert!(testnet_policy.check_deploy_allowed(id).is_ok());
        }
    }
}
