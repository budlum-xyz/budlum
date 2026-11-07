//! Golden vector descriptors for launch (`WP-35`) and post-launch T-Expansion
//! (`WP-50`, `WP-51`, `WP-53`, `WP-60`) UEL execution environments.

use budlum_uel_abi::EeId;

/// Launch environments active on testnet `45261` (`WP-35`).
pub const CONFORMANCE_ENVIRONMENTS: &[EeId] = &[
    EeId::BUDZERO,
    EeId::EVM,
    EeId::WASM,
    EeId::SVM,
    EeId::MOVE,
];

/// Post-launch height-gated T-Expansion environments (`WP-50`, `WP-51`, `WP-53`, `WP-60`).
pub const EXPANSION_CONFORMANCE_ENVIRONMENTS: &[EeId] = &[
    EeId::MOVE_SUI,
    EeId::CAIRO,
    EeId::NEAR,
    EeId::POLKAVM,
    EeId::TVM,
    EeId::UTXO,
    EeId::PLUTUS,
    EeId::BUDZERO_RV32,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uel_conformance_move_sui() {
        assert!(EXPANSION_CONFORMANCE_ENVIRONMENTS.contains(&EeId::MOVE_SUI));
        assert_eq!(EeId::MOVE_SUI.0, 0x05);
    }

    #[test]
    fn uel_conformance_cairo() {
        assert!(EXPANSION_CONFORMANCE_ENVIRONMENTS.contains(&EeId::CAIRO));
        assert_eq!(EeId::CAIRO.0, 0x06);
    }

    #[test]
    fn uel_conformance_near() {
        assert!(EXPANSION_CONFORMANCE_ENVIRONMENTS.contains(&EeId::NEAR));
        assert_eq!(EeId::NEAR.0, 0x07);
    }

    #[test]
    fn uel_conformance_polkavm() {
        assert!(EXPANSION_CONFORMANCE_ENVIRONMENTS.contains(&EeId::POLKAVM));
        assert_eq!(EeId::POLKAVM.0, 0x08);
    }

    #[test]
    fn uel_conformance_tvm() {
        assert!(EXPANSION_CONFORMANCE_ENVIRONMENTS.contains(&EeId::TVM));
        assert_eq!(EeId::TVM.0, 0x09);
    }

    #[test]
    fn uel_conformance_utxo() {
        assert!(EXPANSION_CONFORMANCE_ENVIRONMENTS.contains(&EeId::UTXO));
        assert_eq!(EeId::UTXO.0, 0x0A);
    }

    #[test]
    fn uel_conformance_plutus() {
        assert!(EXPANSION_CONFORMANCE_ENVIRONMENTS.contains(&EeId::PLUTUS));
        assert_eq!(EeId::PLUTUS.0, 0x0B);
    }
}
