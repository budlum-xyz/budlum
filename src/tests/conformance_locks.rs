//! Cross-workspace locks for the execution limits table and block gas budget.
//!
//! The external conformance runner is a separate Cargo workspace. These tests
//! keep its block limit, the native coordinator and BudZero's soft limit in
//! agreement without introducing a dependency cycle between those workspaces.

use crate::execution::coordinator::gas::{
    soft_limit_for_ee, BLOCK_BGU_LIMIT, EVM_SOFT_BGU_LIMIT, MOVE_SOFT_BGU_LIMIT,
    SVM_SOFT_BGU_LIMIT, WASM_SOFT_BGU_LIMIT,
};
use crate::execution::executor::Executor;
use crate::execution::zkvm::{DEFAULT_CONTRACT_GAS_LIMIT, MAX_BLOCK_CONTRACT_GAS};
use budlum_uel_abi::EeId;

const LIMITS_DOC: &str = include_str!("../../docs/EXECUTION_LIMITS.md");
const CONFORMANCE_RUNNER: &str = include_str!("../../execution/conformance/src/lib.rs");

fn source_u64(source: &str, name: &str) -> u64 {
    let marker = format!("const {name}: u64 = ");
    let Some((_, tail)) = source.split_once(&marker) else {
        panic!("missing source constant {name}");
    };
    let literal = tail.split(';').next().unwrap_or_default().trim();
    assert!(
        literal
            .chars()
            .all(|character| character.is_ascii_digit() || character == '_'),
        "invalid {name} literal {literal:?}"
    );
    let digits: String = literal
        .chars()
        .filter(|character| character.is_ascii_digit())
        .collect();
    digits
        .parse::<u64>()
        .unwrap_or_else(|error| panic!("invalid {name} literal {literal:?}: {error}"))
}

#[test]
fn budzero_soft_budget_equals_the_hard_block_limit() {
    assert_eq!(BLOCK_BGU_LIMIT, 60_000_000);
    assert_eq!(MAX_BLOCK_CONTRACT_GAS, BLOCK_BGU_LIMIT);
    assert_eq!(soft_limit_for_ee(EeId::BUDZERO), Some(BLOCK_BGU_LIMIT));
    assert!(DEFAULT_CONTRACT_GAS_LIMIT <= MAX_BLOCK_CONTRACT_GAS);
    assert_eq!(MAX_BLOCK_CONTRACT_GAS / DEFAULT_CONTRACT_GAS_LIMIT, 60);
}

#[test]
fn every_native_soft_budget_fits_inside_the_block() {
    for (environment, limit) in [
        (EeId::EVM, EVM_SOFT_BGU_LIMIT),
        (EeId::WASM, WASM_SOFT_BGU_LIMIT),
        (EeId::SVM, SVM_SOFT_BGU_LIMIT),
        (EeId::MOVE, MOVE_SOFT_BGU_LIMIT),
        (EeId::BUDZERO, MAX_BLOCK_CONTRACT_GAS),
    ] {
        assert!(limit <= BLOCK_BGU_LIMIT);
        assert_eq!(soft_limit_for_ee(environment), Some(limit));
    }
}

#[test]
fn the_sixty_first_full_budzero_call_is_refused_before_execution() {
    assert!(Executor::check_contract_call_count(60).is_ok());
    let error = Executor::check_contract_call_count(61)
        .expect_err("61 full calls price 61,000,000 BGU and must not fit a 60,000,000 BGU block");
    assert!(error.message().contains("block budget"), "{}", error.message());
}

#[test]
fn external_conformance_runner_uses_the_native_block_limit() {
    assert_eq!(
        source_u64(CONFORMANCE_RUNNER, "BLOCK_GAS_LIMIT_BGU"),
        BLOCK_BGU_LIMIT
    );
}

#[test]
fn execution_limits_table_does_not_restore_the_oversized_budget() {
    assert!(LIMITS_DOC.contains("| Maximum block gas | `60,000,000` |"));
    assert!(LIMITS_DOC.contains("| BudZero per-block soft contract gas | `60,000,000` |"));
    assert!(!LIMITS_DOC.contains("| Maximum block gas | `30,000,000` |"));
    assert!(!LIMITS_DOC.contains("| BudZero per-block soft contract gas | `64,000,000` |"));
    assert!(LIMITS_DOC.contains("BLG-302"));
}
