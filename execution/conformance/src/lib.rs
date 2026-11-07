//! Golden vector descriptors for the five UEL execution environments (`WP-35`).

use budlum_uel_abi::EeId;

/// Registered environments covered by the UEL conformance suite.
pub const CONFORMANCE_ENVIRONMENTS: &[EeId] = &[
    EeId::BUDZERO,
    EeId::EVM,
    EeId::WASM,
    EeId::SVM,
    EeId::MOVE,
];
