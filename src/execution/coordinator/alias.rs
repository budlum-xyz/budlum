//! Unified account identities and deterministic per-environment aliases.
//!
//! Implements section 8.4:
//! - Native accounts (32-byte PQ Address V3)
//! - Foreign accounts (`BDLM_FOREIGN_ACCOUNT_V1`, classical Compatibility Lane)
//! - Contract accounts (`BDLM_CONTRACT_ACCOUNT_V1`, deployed code)
//! - Deterministic aliases for EVM (`BDLM_EVM_ALIAS_V1`), WASM (`bud1...`),
//!   SVM (`BDLM_SVM_ALIAS_V1`, guaranteed off the Ed25519 curve), Move
//!   (`SHA3-256(addr32 || 0xBD)`) and BudZero (`addr32`).

use crate::core::address::Address;
use crate::object_layer::family::encoding::bech32_encode;
use budlum_uel_abi::EeId;
use curve25519_dalek::edwards::CompressedEdwardsY;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha3::{Digest, Keccak256, Sha3_256};

/// Namespace holding registered aliases (`(addr32, ee_u8) -> alias_bytes`).
pub const ALIAS_NAMESPACE: &str = "uel/alias";
/// Move authentication-key scheme byte reserved for Budlum UEL aliases.
pub const MOVE_ALIAS_SCHEME_BYTE: u8 = 0xBD;

/// Signature/origin family of a foreign Compatibility Lane account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum ForeignScheme {
    /// Ethereum 20-byte secp256k1 address.
    EthereumSecp256k1 = 1,
    /// Solana 32-byte Ed25519 public key.
    SolanaEd25519 = 2,
    /// Aptos 32-byte account address.
    Aptos = 3,
    /// Cosmos 20-byte secp256k1 address.
    CosmosSecp256k1 = 4,
}

/// Quantum security classification of an account in the unified model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountQuantumClass {
    /// Post-quantum native Budlum account (ML-DSA / Address V3).
    PostQuantum,
    /// Classical foreign account restricted to Compatibility Lane holdings.
    Classical,
    /// Deployed contract account (code-governed, no signing key).
    Contract,
}

impl AccountQuantumClass {
    /// Returns `true` when `actor` may mutate holdings of `target_owner` (K-3 / Y-7).
    ///
    /// A classical foreign account may never touch holdings owned by a PQ account.
    /// exposed for: foreign envelope admission and UEL asset/UOL guards (`WP-27`).
    #[must_use]
    pub const fn may_touch(self, target_owner: Self) -> bool {
        !matches!((self, target_owner), (Self::Classical, Self::PostQuantum))
    }
}

/// Derives the 32-byte Budlum `Address` of a foreign Compatibility Lane account:
/// `SHA3-256("BDLM_FOREIGN_ACCOUNT_V1" || scheme || len_le64 || local_id)`.
///
/// exposed for: foreign transaction admission (`WP-27`, `WP-29`, `WP-31`, `WP-32`).
#[must_use]
pub fn derive_foreign_account(scheme: ForeignScheme, local_id: &[u8]) -> Address {
    let mut h = Sha3_256::new();
    h.update(b"BDLM_FOREIGN_ACCOUNT_V1");
    h.update([scheme as u8]);
    h.update((local_id.len() as u64).to_le_bytes());
    h.update(local_id);
    let digest: [u8; 32] = h.finalize().into();
    Address::from(digest)
}

/// Derives the 32-byte Budlum `Address` of a deployed contract account:
/// `SHA3-256("BDLM_CONTRACT_ACCOUNT_V1" || ee || len_le64 || local_addr)`.
#[must_use]
/// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
pub fn derive_contract_account(ee: EeId, local_addr: &[u8]) -> Address {
    let mut h = Sha3_256::new();
    h.update(b"BDLM_CONTRACT_ACCOUNT_V1");
    h.update([ee.0]);
    h.update((local_addr.len() as u64).to_le_bytes());
    h.update(local_addr);
    let digest: [u8; 32] = h.finalize().into();
    Address::from(digest)
}

/// Deterministic 20-byte EVM alias of a native 32-byte account:
/// `keccak256("BDLM_EVM_ALIAS_V1" || addr32)[12..32]`.
#[must_use]
/// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
pub fn derive_evm_alias(addr: &Address) -> [u8; 20] {
    let mut h = Keccak256::new();
    h.update(b"BDLM_EVM_ALIAS_V1");
    h.update(addr.0);
    let digest: [u8; 32] = h.finalize().into();
    let [_, _, _, _, _, _, _, _, _, _, _, _, tail @ ..] = digest;
    tail
}

/// Deterministic CosmWasm bech32 alias (`bud1...`) of a native 32-byte account.
#[must_use]
/// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
pub fn derive_wasm_alias(addr: &Address) -> String {
    bech32_encode("bud", &addr.0)
}

/// Deterministic CosmWasm bech32 address (`bud1...`) of a 20-byte Cosmos account.
#[must_use]
/// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
pub fn derive_foreign_cosmos_bech32(addr20: &[u8; 20]) -> String {
    bech32_encode("bud", addr20)
}

/// Deterministic CosmWasm bech32 contract address (`bud1...`) from a 32-byte digest.
#[must_use]
/// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
pub fn bech32_contract_addr(digest32: &[u8; 32]) -> String {
    bech32_encode("bud", digest32)
}

/// Deterministic off-curve 32-byte SVM alias of a native account:
/// `SHA256("BDLM_SVM_ALIAS_V1" || addr32 || seed)`, trying `seed` from `255`
/// down to `0` and picking the first digest that does not decompress onto the
/// Ed25519 curve, paired with the winning `seed`.
///
/// Returns `Err` only in the astronomically unreachable `2^-256` case where all
/// 256 seeds land on the curve.
/// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
pub fn derive_svm_alias(addr: &Address) -> Result<([u8; 32], u8), String> {
    for step in 0u8..=255u8 {
        let seed = 255u8.wrapping_sub(step);
        let mut h = Sha256::new();
        h.update(b"BDLM_SVM_ALIAS_V1");
        h.update(addr.0);
        h.update([seed]);
        let candidate: [u8; 32] = h.finalize().into();
        if !is_ed25519_on_curve(&candidate) {
            return Ok((candidate, seed));
        }
    }
    Err(String::from(
        "no off-curve SVM alias found across all 256 seeds",
    ))
}

/// Returns `true` iff `bytes` is the canonical encoding of a point on Ed25519.
#[must_use]
/// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
pub fn is_ed25519_on_curve(bytes: &[u8; 32]) -> bool {
    CompressedEdwardsY(*bytes).decompress().is_some()
}

/// Deterministic 32-byte Move (Aptos) alias of a native account:
/// `SHA3-256(addr32 || 0xBD)`.
#[must_use]
/// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
pub fn derive_move_alias(addr: &Address) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(addr.0);
    h.update([MOVE_ALIAS_SCHEME_BYTE]);
    h.finalize().into()
}

/// Deterministic 32-byte BudZero alias of an account (`addr32` itself).
#[must_use]
/// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
pub const fn derive_budzero_alias(addr: &Address) -> [u8; 32] {
    addr.0
}

/// Derives the raw alias bytes for `addr` in environment `ee`.
/// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
pub fn derive_alias_bytes(addr: &Address, ee: EeId) -> Result<Vec<u8>, String> {
    match ee {
        EeId::BUDZERO => Ok(derive_budzero_alias(addr).to_vec()),
        EeId::EVM => Ok(derive_evm_alias(addr).to_vec()),
        EeId::WASM => Ok(derive_wasm_alias(addr).into_bytes()),
        EeId::SVM => derive_svm_alias(addr).map(|(pk, _)| pk.to_vec()),
        EeId::MOVE => Ok(derive_move_alias(addr).to_vec()),
        other => Err(format!("unsupported execution environment 0x{:02x}", other.0)),
    }
}

/// Canonical 33-byte storage key `(addr32 || ee_u8)` in `uel/alias`.
#[must_use]
/// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
pub fn alias_storage_key(addr: &Address, ee: EeId) -> [u8; 33] {
    let mut out = [0u8; 33];
    if let Some(prefix) = out.get_mut(..32) {
        prefix.copy_from_slice(&addr.0);
    }
    if let Some(last) = out.get_mut(32) {
        *last = ee.0;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uel_svm_alias_is_off_curve() {
        for i in 0u16..512u16 {
            let mut raw = [0u8; 32];
            raw[0..2].copy_from_slice(&i.to_le_bytes());
            raw[31] = (i & 0xff) as u8;
            let addr = Address::from(raw);
            let (svm_pk, _seed) = derive_svm_alias(&addr).expect("off-curve alias");
            assert!(
                !is_ed25519_on_curve(&svm_pk),
                "SVM alias at index {i} must lie off the Ed25519 curve"
            );
        }
    }

    #[test]
    fn account_derivations_separate_domains_and_quantum_classes() {
        let evm_id = [0x11u8; 20];
        let cosmos_id = [0x11u8; 20];
        let f_evm = derive_foreign_account(ForeignScheme::EthereumSecp256k1, &evm_id);
        let f_cos = derive_foreign_account(ForeignScheme::CosmosSecp256k1, &cosmos_id);
        assert_ne!(f_evm, f_cos);

        let c_evm = derive_contract_account(EeId::EVM, &evm_id);
        let c_wasm = derive_contract_account(EeId::WASM, &evm_id);
        assert_ne!(c_evm, c_wasm);
        assert_ne!(c_evm, f_evm);

        assert!(!AccountQuantumClass::Classical.may_touch(AccountQuantumClass::PostQuantum));
        assert!(AccountQuantumClass::Classical.may_touch(AccountQuantumClass::Classical));
        assert!(AccountQuantumClass::PostQuantum.may_touch(AccountQuantumClass::PostQuantum));
    }
}
