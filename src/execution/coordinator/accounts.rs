//! Unified account and deterministic alias derivations across UEL environments.
//!
//! Section 8.4 defines three account kinds on the single Budlum ledger:
//!
//! * `Local`: 32-byte post-quantum Address V3 (`ML-DSA-87`).
//! * `Foreign`: `SHA3-256(BDLM_FOREIGN_ACCOUNT_V1 || scheme || len_le || native_id)`.
//! * `Contract`: `SHA3-256(BDLM_CONTRACT_ACCOUNT_V1 || ee || len_le || native_addr)`.
//!
//! A local account derives a deterministic, key-free alias in every execution
//! environment (`EVM`, `WASM`, `SVM`, `Move`, `BudZero`) and registers it in
//! `uel/alias` upon first use.

use std::fmt;

use budlum_uel_abi::EeId;
use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest as _, Sha256};
use sha3::{Keccak256, Sha3_256};

use crate::core::address::Address;
use crate::object_layer::family::encoding::bech32_encode;

/// Classical signature scheme families accepted by foreign transaction envelopes.
///
/// Convenience: exposed for foreign envelope verifiers and coordinator lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ForeignScheme {
    /// Ethereum 20-byte `secp256k1` address.
    EvmSecp256k1 = 0x01,
    /// Solana 32-byte `Ed25519` public key.
    SvmEd25519 = 0x02,
    /// Aptos 32-byte account address / authentication key digest.
    AptosAuth = 0x03,
    /// Cosmos 20-byte `secp256k1` account address bytes.
    CosmosSecp256k1 = 0x04,
    /// Sui 32-byte `BLAKE2b-256(0x00 || ed25519_pk)` address.
    SuiEd25519 = 0x05,
}

impl ForeignScheme {
    /// Expected byte width of `native_id` for this foreign scheme.
    #[must_use]
    pub const fn expected_len(self) -> usize {
        match self {
            Self::EvmSecp256k1 | Self::CosmosSecp256k1 => 20,
            Self::SvmEd25519 | Self::AptosAuth | Self::SuiEd25519 => 32,
        }
    }
}

/// Quantum security classification of a unified ledger account.
///
/// Convenience: exposed for PQ custody isolation checks in the coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuantumClass {
    /// Post-quantum Address V3 (`ML-DSA`).
    PostQuantum,
    /// Classical signature lane (`secp256k1` or `Ed25519`); cannot touch PQ holdings.
    Classical,
    /// Smart contract account controlled strictly by code.
    Contract,
}

/// Account origin on the unified execution ledger.
///
/// Convenience: exposed for account-origin classification across UEL lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountKind {
    /// Native post-quantum wallet account.
    Local,
    /// Auto-created foreign envelope account.
    Foreign { scheme: ForeignScheme },
    /// Deployed contract account inside `ee`.
    Contract { ee: EeId },
}

impl AccountKind {
    /// Quantum security posture of this account kind.
    ///
    /// Convenience: exposed for PQ custody isolation checks in the coordinator.
    #[must_use]
    pub const fn quantum_class(self) -> QuantumClass {
        match self {
            Self::Local => QuantumClass::PostQuantum,
            Self::Foreign { .. } => QuantumClass::Classical,
            Self::Contract { .. } => QuantumClass::Contract,
        }
    }
}

/// Refusal reasons for account and alias derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountModelError {
    /// Native foreign identity length did not match the scheme's fixed width.
    InvalidForeignIdentityLength {
        scheme: ForeignScheme,
        expected: usize,
        actual: usize,
    },
    /// Native contract or asset reference was empty or exceeded bounds.
    InvalidNativeReference,
    /// Unknown execution environment id.
    UnknownEnvironment(EeId),
    /// Exhausted all 256 seeds without finding an off-curve `Ed25519` digest.
    SvmOffCurveExhausted,
}

impl fmt::Display for AccountModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidForeignIdentityLength {
                scheme,
                expected,
                actual,
            } => write!(
                f,
                "foreign scheme 0x{:02x} expects {expected} bytes, got {actual}",
                *scheme as u8
            ),
            Self::InvalidNativeReference => write!(f, "empty or oversized native reference"),
            Self::UnknownEnvironment(ee) => {
                write!(f, "unknown execution environment 0x{:02x}", ee.0)
            }
            Self::SvmOffCurveExhausted => {
                write!(f, "no off-curve SVM alias found across 256 seeds")
            }
        }
    }
}

impl std::error::Error for AccountModelError {}

/// Derive the canonical 32-byte Budlum `Address` of a foreign account:
/// `SHA3-256(BDLM_FOREIGN_ACCOUNT_V1 || scheme || len_le_u64 || native_id)`.
///
/// Convenience: called by foreign envelope verification and `uel/alias` guards.
pub fn derive_foreign_account(
    scheme: ForeignScheme,
    native_id: &[u8],
) -> Result<Address, AccountModelError> {
    let expected = scheme.expected_len();
    if native_id.len() != expected {
        return Err(AccountModelError::InvalidForeignIdentityLength {
            scheme,
            expected,
            actual: native_id.len(),
        });
    }
    let mut h = Sha3_256::new();
    h.update(b"BDLM_FOREIGN_ACCOUNT_V1");
    h.update([scheme as u8]);
    h.update((native_id.len() as u64).to_le_bytes());
    h.update(native_id);
    Ok(Address(h.finalize().into()))
}

/// Derive the canonical 32-byte Budlum `Address` of a deployed contract:
/// `SHA3-256(BDLM_CONTRACT_ACCOUNT_V1 || ee || len_le_u64 || native_addr)`.
///
/// Convenience: called by the execution coordinator upon contract deployment.
pub fn derive_contract_account(
    ee: EeId,
    native_addr: &[u8],
) -> Result<Address, AccountModelError> {
    if native_addr.is_empty() || native_addr.len() > budlum_uel_abi::MAX_IDENTITY_BYTES {
        return Err(AccountModelError::InvalidNativeReference);
    }
    let mut h = Sha3_256::new();
    h.update(b"BDLM_CONTRACT_ACCOUNT_V1");
    h.update([ee.0]);
    h.update((native_addr.len() as u64).to_le_bytes());
    h.update(native_addr);
    Ok(Address(h.finalize().into()))
}

/// Derive the deterministicUniversal Asset Registry id (`asset_id`):
/// `SHA3-256(BDLM_UEL_ASSET_V1 || home_ee || len_le_u64 || home_ref)`.
pub(crate) fn derive_asset_id(
    home_ee: EeId,
    home_ref: &[u8],
) -> Result<[u8; 32], AccountModelError> {
    if home_ref.is_empty() || home_ref.len() > 128 {
        return Err(AccountModelError::InvalidNativeReference);
    }
    let mut h = Sha3_256::new();
    h.update(b"BDLM_UEL_ASSET_V1");
    h.update([home_ee.0]);
    h.update((home_ref.len() as u64).to_le_bytes());
    h.update(home_ref);
    Ok(h.finalize().into())
}

/// Canonical 33-byte key `(local_addr_32 || ee_u8)` under namespace `uel/alias`.
#[must_use]
pub(crate) fn alias_namespace_key(local: &Address, ee: EeId) -> [u8; 33] {
    let mut key = [0u8; 33];
    if let Some((prefix, tail)) = key.split_at_mut_checked(32) {
        prefix.copy_from_slice(&local.0);
        if let Some(slot) = tail.first_mut() {
            *slot = ee.0;
        }
    }
    key
}

/// Check whether 32 bytes decompress to a valid `Ed25519` curve point.
#[must_use]
pub(crate) fn is_ed25519_on_curve(bytes: &[u8; 32]) -> bool {
    CompressedEdwardsY(*bytes).decompress().is_some()
}

/// Derive the deterministic alias of `local` inside `ee` (Section 8.4.2).
///
/// For `SVM`, searches `seed = 255` down to `0` and picks the first off-curve
/// 32-byte `SHA-256(BDLM_SVM_ALIAS_V1 || addr32 || seed)` digest so no private
/// `Ed25519` key exists for the alias.
pub fn derive_local_alias(local: &Address, ee: EeId) -> Result<Vec<u8>, AccountModelError> {
    match ee {
        EeId::EVM => {
            let mut h = Keccak256::new();
            h.update(b"BDLM_EVM_ALIAS_V1");
            h.update(local.0);
            let digest: [u8; 32] = h.finalize().into();
            let (_, tail20) = digest
                .split_at_checked(12)
                .ok_or(AccountModelError::InvalidNativeReference)?;
            Ok(tail20.to_vec())
        }
        EeId::WASM => Ok(bech32_encode("bud", &local.0).into_bytes()),
        EeId::SVM => {
            for seed in (0..=255u8).rev() {
                let mut h = Sha256::new();
                h.update(b"BDLM_SVM_ALIAS_V1");
                h.update(local.0);
                h.update([seed]);
                let candidate: [u8; 32] = h.finalize().into();
                if !is_ed25519_on_curve(&candidate) {
                    return Ok(candidate.to_vec());
                }
            }
            Err(AccountModelError::SvmOffCurveExhausted)
        }
        EeId::MOVE | EeId::MOVE_SUI => {
            let mut h = Sha3_256::new();
            h.update(local.0);
            h.update([0xBD]);
            let digest: [u8; 32] = h.finalize().into();
            Ok(digest.to_vec())
        }
        EeId::BUDZERO => Ok(local.0.to_vec()),
        EeId::CAIRO
        | EeId::NEAR_WASM
        | EeId::POLKAVM
        | EeId::TVM
        | EeId::UTXO
        | EeId::PLUTUS => {
            let mut h = Sha3_256::new();
            h.update(b"BDLM_EXT_ALIAS_V1");
            h.update([ee.0]);
            h.update(local.0);
            let digest: [u8; 32] = h.finalize().into();
            Ok(digest.to_vec())
        }
        other => Err(AccountModelError::UnknownEnvironment(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_derivations_and_aliases_are_deterministic_and_domain_separated() {
        let local = Address([0x42; 32]);
        assert_eq!(AccountKind::Local.quantum_class(), QuantumClass::PostQuantum);
        assert_eq!(
            AccountKind::Foreign {
                scheme: ForeignScheme::EvmSecp256k1
            }
            .quantum_class(),
            QuantumClass::Classical
        );
        assert_eq!(
            AccountKind::Contract { ee: EeId::EVM }.quantum_class(),
            QuantumClass::Contract
        );

        let evm_alias = derive_local_alias(&local, EeId::EVM).unwrap();
        assert_eq!(evm_alias.len(), 20);

        let wasm_alias = derive_local_alias(&local, EeId::WASM).unwrap();
        let wasm_str = String::from_utf8(wasm_alias).unwrap();
        assert!(wasm_str.starts_with("bud1"));

        let svm_alias = derive_local_alias(&local, EeId::SVM).unwrap();
        assert_eq!(svm_alias.len(), 32);
        let svm_arr: [u8; 32] = svm_alias.try_into().unwrap();
        assert!(
            !is_ed25519_on_curve(&svm_arr),
            "SVM alias must lie off the Ed25519 curve"
        );

        let move_alias = derive_local_alias(&local, EeId::MOVE).unwrap();
        assert_eq!(move_alias.len(), 32);

        let bz_alias = derive_local_alias(&local, EeId::BUDZERO).unwrap();
        assert_eq!(bz_alias, local.0);

        let f_evm = derive_foreign_account(ForeignScheme::EvmSecp256k1, &[0x11; 20]).unwrap();
        let f_cos = derive_foreign_account(ForeignScheme::CosmosSecp256k1, &[0x11; 20]).unwrap();
        assert_ne!(f_evm, f_cos, "foreign schemes must be domain-separated");

        let c_evm = derive_contract_account(EeId::EVM, &[0x11; 20]).unwrap();
        assert_ne!(f_evm, c_evm, "foreign and contract accounts cannot collide");
    }
}
