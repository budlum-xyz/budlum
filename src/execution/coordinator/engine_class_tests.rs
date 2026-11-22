//! A receipt does not say which engine produced it, so the host has to know.
//!
//! Every one of the thirteen environments this node registers by default is an
//! in-tree interpreter: `EvmEe`, `WasmEe`, `SvmEe` and the rest are written to
//! the same ABI as the engines they stand in for, and an `EeOutcome` from
//! `EvmEe` is shaped exactly like an `EeOutcome` from the `revm` worker behind
//! `budlum-ee-evm`. Nothing on the receipt distinguishes them, so a chain that
//! never spawns a worker cannot tell from its own output that no engine ran.
//!
//! These tests fix both halves of that seam: the class is derived from the
//! endpoint (never declared by the environment), and a chain that requires real
//! engines refuses the block before the first write instead of executing it on
//! the stand-in and publishing the result.

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::execution::coordinator::gas::MIN_UEL_BASE_FEE_ATTOS;
use crate::execution::coordinator::worker::EngineClass;
#[cfg(unix)]
use crate::execution::coordinator::worker::WorkerEndpoint;
use crate::execution::coordinator::{
    CoordinatorError, ExecutionCoordinator, UelAction, UelTx, UelTxAuth,
};
use budlum_uel_abi::{BlockContext, EeId};

fn ctx() -> BlockContext {
    BlockContext {
        height: 10,
        timestamp_ms: 1_700_200_000_000,
        chain_id: crate::core::chain_config::Network::Testnet
            .chain_id()
            .value(),
    }
}

const SEED: [u8; 32] = [0xB7; 32];

fn funded_state() -> Result<(AccountState, Address, Address), String> {
    let sender = UelTx::signer_address_from_seed(&SEED)?;
    let proposer = Address::from([0xB8; 32]);
    let mut state = AccountState::new();
    state.add_balance(&sender, 50_000);
    state.add_balance(&proposer, 50_000);
    Ok((state, sender, proposer))
}

/// A deploy that the default EVM interpreter accepts on its own terms, so the
/// only reason a refusal can appear is the engine gate.
fn signed_evm_deploy(sender: Address) -> Result<UelTx, String> {
    UelTx {
        tx_hash: [0xB9; 32],
        sender,
        nonce: 0,
        ee: EeId::EVM,
        action: UelAction::Deploy {
            // PUSH1 0 PUSH1 0 RETURN: deploys empty runtime code.
            code: vec![0x60, 0x00, 0x60, 0x00, 0xf3],
            salt: [0xBA; 32],
        },
        value_attos: 0,
        gas_limit_bgu: 250_000,
        max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
        max_priority_fee_per_bgu_attos: 100,
        auth: UelTxAuth::default(),
    }
    .signed_with_seed(ctx().chain_id, &SEED)
}

/// The default coordinator answers for thirteen environments and none of them
/// is reached over a worker socket, so every class it reports is `Model`.
///
/// This is the state the feature matrix has to publish: an environment whose
/// class is `Model` may be executed, but its answer is not the engine's answer.
#[test]
fn every_built_in_environment_reports_model_engine() {
    let coord = ExecutionCoordinator::new();
    let registered = coord.supervisor().registered_engines();
    assert_eq!(
        registered.len(),
        13,
        "the default coordinator registers one endpoint per catalog environment"
    );
    for (ee, class) in &registered {
        assert_eq!(
            *class,
            EngineClass::Model,
            "EE 0x{:02x} is in-process, so it is the stand-in",
            ee.0
        );
    }
    assert_eq!(
        coord
            .supervisor()
            .registered_engines()
            .into_iter()
            .filter(|(_, class)| *class == EngineClass::Model)
            .count(),
        13,
        "every default endpoint is in-process, so every class is Model"
    );
    assert_eq!(coord.engine_class(EeId::EVM), Some(EngineClass::Model));
}

/// The class comes from the endpoint, not from the environment: registering the
/// socket-backed worker for one environment moves exactly that environment.
#[cfg(unix)]
#[test]
fn a_socket_backed_environment_reports_the_real_engine() {
    let mut coord = ExecutionCoordinator::new();
    // Registration only builds the endpoint record; nothing connects until a
    // block actually routes work to it, so no worker binary is needed here.
    coord.register_worker(WorkerEndpoint::unix_socket(
        EeId::EVM,
        std::path::PathBuf::from("/nonexistent/budlum-ee-evm.sock"),
        None,
    ));
    assert_eq!(coord.engine_class(EeId::EVM), Some(EngineClass::Real));
    assert_eq!(coord.engine_class(EeId::WASM), Some(EngineClass::Model));
    assert_eq!(
        coord
            .supervisor()
            .registered_engines()
            .into_iter()
            .filter(|(_, class)| *class == EngineClass::Model)
            .count(),
        12,
        "registering the engine for one environment moves exactly that one"
    );
}

/// Requiring real engines refuses a block that needs a stand-in, and the
/// refusal happens before the first write: sender balance, aliases and the
/// execution root are untouched.
#[test]
fn requiring_real_engines_refuses_a_model_block_without_writing() {
    let (mut state, sender, proposer) = funded_state().expect("funded state");
    let tx = signed_evm_deploy(sender).expect("signed deploy");
    let root_before = state.state_root_body();
    let balance_before = state.get_balance(&sender);

    let mut strict = ExecutionCoordinator::new();
    strict.set_require_real_engines(true);
    assert_eq!(strict.first_refused_environment(&[tx.clone()]), Some(EeId::EVM));

    let refused = strict.execute_block(&mut state, ctx(), proposer, &[tx.clone()]);
    assert_eq!(
        refused,
        Err(CoordinatorError::ModelEngineRefused { ee: EeId::EVM }),
        "a chain that requires real engines must not execute on the stand-in"
    );
    assert_eq!(state.state_root_body(), root_before);
    assert_eq!(state.get_balance(&sender), balance_before);
}

/// The gate is opt-in: with the default coordinator the same deploy executes,
/// which is what makes the previous test's refusal a decision and not a broken
/// transaction.
#[test]
fn the_gate_is_opt_in_and_the_default_still_executes() {
    let (mut state, sender, proposer) = funded_state().expect("funded state");
    let tx = signed_evm_deploy(sender).expect("signed deploy");

    let mut devnet = ExecutionCoordinator::new();
    assert_eq!(devnet.first_refused_environment(&[tx.clone()]), None);
    let receipts = devnet
        .execute_block(&mut state, ctx(), proposer, &[tx])
        .expect("the stand-in still executes when the chain allows it");
    assert_eq!(receipts.len(), 1);
}

/// An environment with no endpoint is refused by the same gate: "nobody is
/// registered" is not an engine either.
#[test]
fn an_unregistered_environment_is_never_treated_as_real() {
    let mut coord = ExecutionCoordinator::new();
    coord.set_require_real_engines(true);
    assert_eq!(coord.engine_class(EeId::UTXO), Some(EngineClass::Model));
    let (_, sender, _) = funded_state().expect("funded state");
    let mut tx = signed_evm_deploy(sender).expect("signed deploy");
    tx.ee = EeId(0x0D);
    assert_eq!(coord.first_refused_environment(&[tx]), Some(EeId(0x0D)));
}
