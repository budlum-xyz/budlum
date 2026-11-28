//! UEL security invariant tests (`THE_BUDLUM_CEO_DIREKTIF` K3-I, Y-I.2..Y-I.6).
//!
//! Every invariant is driven through the public crate surface only, so the
//! test file is an executable copy of the directive rows:
//! - Y-I.2: a classical foreign account never moves a PQ account's holdings,
//!   checked per envelope (Ethereum, Solana, Aptos, Cosmos) and per scheme.
//! - Y-I.3: cross-EE reentrancy stays forbidden at the overlay entry point and
//!   the universal-call depth cap holds.
//! - Y-I.4: asset pointers hold no balance in any environment.
//! - Y-I.5: a deterministic engine panic becomes a `Fault` receipt and the
//!   block continues; a non-deterministic worker death rejects the whole
//!   block after 3 retries and leaves state untouched.
//! - Y-I.6: the deploy policy is a chain parameter, pinned per chain id and
//!   enforced before any code decoding.

use budlum_core::core::account::AccountState;
use budlum_core::core::address::Address;
use budlum_core::core::transaction::Transaction;
use budlum_core::execution::coordinator::alias::{
    derive_foreign_account, AccountQuantumClass, ForeignScheme,
};
use budlum_core::execution::coordinator::assets::{
    decode_pointer_bytecode, deploy_asset_pointer, derive_pointer_address, read_registered_asset,
    register_asset_entry, AssetStandard,
};
use budlum_core::execution::coordinator::deploy_policy::DeployPolicy;
use budlum_core::execution::coordinator::foreign::aptos::{
    sign_aptos_ed25519_tx, AptosPayloadKind, BUDLUM_APTOS_CHAIN_ID,
};
use budlum_core::execution::coordinator::foreign::cosmos::{
    sign_cosmos_tx_direct, BUDLUM_COSMOS_CHAIN_ID,
};
use budlum_core::execution::coordinator::foreign::ethereum::{
    evm_address_from_secret_key, sign_eip1559_tx, BUDLUM_EVM_CHAIN_ID,
};
use budlum_core::execution::coordinator::foreign::solana::{
    sign_solana_tx, SolanaCompiledInstruction,
};
use budlum_core::execution::coordinator::foreign::{ForeignTx, VerifiedForeignOutcome};
use budlum_core::execution::coordinator::gas::MIN_UEL_BASE_FEE_ATTOS;
use budlum_core::execution::coordinator::overlay::TxOverlay;
use budlum_core::execution::coordinator::stateful_contract::{
    execute_stateful_contract_tx, StatefulContractEnvelope,
};
use budlum_core::execution::coordinator::worker::WorkerEndpoint;
use budlum_core::execution::coordinator::{
    CoordinatorError, ExecutionCoordinator, UelAction, UelReceiptStatus, UelTx, UelTxAuth,
};
use budlum_uel_abi::{
    panic_digest, BlockContext, CodeInfo, EeCall, EeFault, EeId, EeOutcome, EeQuery, EeRefusal,
    ExecutionEnvironment, HostApi, HostError, HostRead, RefusalCode,
};

fn ctx(height: u64) -> BlockContext {
    BlockContext {
        chain_id: BUDLUM_EVM_CHAIN_ID,
        height,
        timestamp_ms: 1_762_000_000_000 + height * 2_000,
    }
}

fn funded(addrs: &[Address]) -> AccountState {
    let mut s = AccountState::new();
    for a in addrs {
        s.add_balance(a, 10_000);
    }
    s
}

fn signed_tx(seed: &[u8; 32], nonce: u64, ee: EeId, action: UelAction) -> UelTx {
    UelTx {
        tx_hash: [nonce as u8; 32],
        sender: Address::zero(),
        nonce,
        ee,
        action,
        value_attos: 0,
        gas_limit_bgu: 200_000,
        max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
        max_priority_fee_per_bgu_attos: 0,
        auth: UelTxAuth::default(),
    }
    .signed_with_seed(BUDLUM_EVM_CHAIN_ID, seed)
    .expect("sign uel tx")
}

// ---------------------------------------------------------------------------
// Y-I.2: classical signature limit (K-6), per envelope
// ---------------------------------------------------------------------------

/// Admits one classical envelope per foreign scheme and asserts the sender is
/// classified `Classical` and can never touch a PQ account's holdings.
fn assert_classical_envelope_cannot_indebt_pq(
    state: &mut AccountState,
    coord: &mut ExecutionCoordinator,
    pq_owner: &Address,
    tx: &ForeignTx,
    label: &str,
) -> Address {
    let now_secs = 1_700_000_000u64;
    let out = coord
        .process_foreign_envelope(state, tx, now_secs)
        .unwrap_or_else(|e| panic!("{label} envelope must be admitted at Level 0: {e:?}"));
    let sender = match out {
        VerifiedForeignOutcome::Ethereum { budlum_sender, .. }
        | VerifiedForeignOutcome::Solana { budlum_sender, .. }
        | VerifiedForeignOutcome::Aptos { budlum_sender, .. }
        | VerifiedForeignOutcome::Cosmos { budlum_sender, .. } => budlum_sender,
        other => panic!("{label}: unexpected outcome {other:?}"),
    };
    let lane = &state.execution_state.foreign_lane;
    assert_eq!(
        lane.quantum_class_of(&sender),
        AccountQuantumClass::Classical,
        "{label}: admitted foreign sender must be Classical"
    );
    assert!(
        lane.authorize_holding_access(&sender, pq_owner).is_err(),
        "{label}: classical account must never debit PQ holdings"
    );
    assert!(
        lane.authorize_holding_access(&sender, &sender).is_ok(),
        "{label}: classical account keeps access to its own holdings"
    );
    sender
}

#[test]
fn classical_accounts_cannot_indebt_pq_accounts_in_every_envelope() {
    let mut state = AccountState::new();
    let mut coord = ExecutionCoordinator::new();
    let pq_owner = Address::from([0x99u8; 32]);
    state.add_balance(&pq_owner, 100);
    state
        .execution_state
        .foreign_lane
        .register_native_pq_account(pq_owner);

    // Ethereum (secp256k1).
    let eth_sk = [0x21u8; 32];
    let eth_raw = sign_eip1559_tx(
        &eth_sk,
        BUDLUM_EVM_CHAIN_ID,
        0,
        (1_000_000_000, 2_000_000_000, 21_000),
        Some([0xAB; 20]),
        0,
        (&[], &[]),
    )
    .expect("sign eth");
    let eth_sender = assert_classical_envelope_cannot_indebt_pq(
        &mut state,
        &mut coord,
        &pq_owner,
        &ForeignTx::Ethereum {
            raw_rlp: eth_raw,
            direct_native_pq_recipient: None,
        },
        "ethereum",
    );
    assert_eq!(
        eth_sender,
        derive_foreign_account(
            ForeignScheme::EthereumSecp256k1,
            &evm_address_from_secret_key(&eth_sk).expect("eth addr")
        ),
        "ethereum sender must be the scheme-derived foreign account"
    );

    // Solana (Ed25519).
    let bh = [0x77u8; 32];
    state.execution_state.foreign_lane.record_blockhash(bh);
    let sol_seed = [0x41u8; 32];
    let sol_ix = vec![SolanaCompiledInstruction {
        program_id_index: 1,
        accounts: vec![0],
        data: vec![1, 2, 3],
    }];
    let sol_raw = sign_solana_tx(&sol_seed, true, bh, &[[0x98u8; 32]], &sol_ix);
    assert_classical_envelope_cannot_indebt_pq(
        &mut state,
        &mut coord,
        &pq_owner,
        &ForeignTx::Solana {
            raw_wire: sol_raw,
            direct_native_pq_recipient: None,
        },
        "solana",
    );

    // Aptos (Ed25519).
    let aptos_seed = [0x51u8; 32];
    let payload = AptosPayloadKind::EntryFunction {
        module_address: [0u8; 32],
        module_name: String::from("aptos_account"),
        function_name: String::from("transfer"),
        args_bcs: vec![1, 2, 3, 4],
    };
    let aptos_raw = sign_aptos_ed25519_tx(
        &aptos_seed,
        0,
        &payload,
        100_000,
        100,
        1_700_000_000 + 60,
        BUDLUM_APTOS_CHAIN_ID,
    );
    assert_classical_envelope_cannot_indebt_pq(
        &mut state,
        &mut coord,
        &pq_owner,
        &ForeignTx::Aptos {
            raw_bcs: aptos_raw,
            direct_native_pq_recipient: None,
        },
        "aptos",
    );

    // Cosmos (secp256k1, SIGN_MODE_DIRECT).
    let cosmos_sk = [0x31u8; 32];
    let cosmos_raw = sign_cosmos_tx_direct(
        &cosmos_sk,
        BUDLUM_COSMOS_CHAIN_ID,
        0,
        0,
        200_000,
        500,
        vec![(
            String::from("/cosmos.bank.v1beta1.MsgSend"),
            b"send-payload".to_vec(),
        )],
    )
    .expect("sign cosmos");
    assert_classical_envelope_cannot_indebt_pq(
        &mut state,
        &mut coord,
        &pq_owner,
        &ForeignTx::Cosmos {
            tx_raw_bytes: cosmos_raw,
            chain_id: String::from(BUDLUM_COSMOS_CHAIN_ID),
            account_number: 0,
            direct_native_pq_recipient: None,
        },
        "cosmos",
    );

    // Direct-PQ rescue fails closed when the recipient is not a proven PQ account.
    let eth_raw2 = sign_eip1559_tx(
        &eth_sk,
        BUDLUM_EVM_CHAIN_ID,
        1,
        (1_000_000_000, 2_000_000_000, 21_000),
        Some([0xAB; 20]),
        0,
        (&[], &[]),
    )
    .expect("sign eth 2");
    assert!(
        coord
            .process_foreign_envelope(
                &mut state,
                &ForeignTx::Ethereum {
                    raw_rlp: eth_raw2,
                    direct_native_pq_recipient: Some(Address::from([0x55u8; 32])),
                },
                1_700_000_000,
            )
            .is_err(),
        "direct PQ rescue to an unregistered recipient must fail closed"
    );

    // The may_touch matrix itself: only (Classical -> PostQuantum) is denied.
    assert!(!AccountQuantumClass::Classical.may_touch(AccountQuantumClass::PostQuantum));
    assert!(AccountQuantumClass::Classical.may_touch(AccountQuantumClass::Classical));
    assert!(AccountQuantumClass::PostQuantum.may_touch(AccountQuantumClass::PostQuantum));
    assert!(AccountQuantumClass::PostQuantum.may_touch(AccountQuantumClass::Classical));

    // Every scheme derivation is deterministic and domain-separated.
    let id = [0x11u8; 20];
    let schemes = [
        ForeignScheme::EthereumSecp256k1,
        ForeignScheme::SolanaEd25519,
        ForeignScheme::Aptos,
        ForeignScheme::CosmosSecp256k1,
        ForeignScheme::SuiEd25519,
    ];
    let mut derived = Vec::new();
    for scheme in schemes {
        let a = derive_foreign_account(scheme, &id);
        let b = derive_foreign_account(scheme, &id);
        assert_eq!(a, b, "scheme {scheme:?} derivation must be deterministic");
        derived.push(a);
    }
    derived.sort();
    derived.dedup();
    assert_eq!(derived.len(), schemes.len(), "schemes must not collide");

    // Unknown addresses fail closed as Classical.
    let lane = &state.execution_state.foreign_lane;
    let unknown = Address::from([0xEEu8; 32]);
    assert_eq!(
        lane.quantum_class_of(&unknown),
        AccountQuantumClass::Classical
    );
    assert!(lane.authorize_holding_access(&unknown, &pq_owner).is_err());
}

// ---------------------------------------------------------------------------
// Y-I.3: cross-EE reentrancy and depth cap
// ---------------------------------------------------------------------------

#[test]
fn cross_ee_reentrancy_is_forbidden_and_depth_is_capped() {
    let state = AccountState::new();
    let mut overlay = TxOverlay::new(&state, EeId::EVM, 1_000_000);

    // Same-EE re-entry from the root frame is denied by name.
    let err = overlay
        .push_universal_frame(&state, EeId::EVM, false)
        .expect_err("same-EE reentrancy must be forbidden");
    match err {
        HostError::Denied(msg) => assert_eq!(msg, "ReentrancyForbidden"),
        other => panic!("expected ReentrancyForbidden, got {other:?}"),
    }

    // Eight distinct nested environments fit; the ninth exceeds the cap even
    // though no EE repeats.
    let chain = [
        EeId::WASM,
        EeId::SVM,
        EeId::MOVE,
        EeId::BUDZERO,
        EeId::MOVE_SUI,
        EeId::CAIRO,
        EeId::NEAR_WASM,
        EeId::POLKAVM,
    ];
    for ee in chain {
        overlay
            .push_universal_frame(&state, ee, false)
            .unwrap_or_else(|e| panic!("frame into {ee:?} must open: {e:?}"));
    }
    assert_eq!(overlay.universal_depth(), 8);
    assert!(
        matches!(
            overlay.push_universal_frame(&state, EeId::TVM, false),
            Err(HostError::DepthExceeded)
        ),
        "depth 9 must exceed the universal-call cap"
    );

    // Re-entry against a mid-stack EE is also denied, not just the root:
    // pop POLKAVM, then try to re-enter CAIRO which is still on the stack.
    let mut scratch = AccountState::new();
    overlay.rollback_universal_frame(&mut scratch);
    assert_eq!(overlay.universal_depth(), 7);
    let err = overlay
        .push_universal_frame(&state, EeId::CAIRO, false)
        .expect_err("mid-stack reentrancy must be forbidden");
    assert!(matches!(err, HostError::Denied(m) if m == "ReentrancyForbidden"));
}

// ---------------------------------------------------------------------------
// Y-I.4: asset pointers hold no balance
// ---------------------------------------------------------------------------

#[test]
fn asset_pointers_hold_no_balance_in_any_environment() {
    let mut state = AccountState::new();
    let home_ref = [0xAAu8; 20];
    let asset = register_asset_entry(
        &mut state,
        EeId::EVM,
        &home_ref,
        AssetStandard::Fungible,
        6,
        String::from("PTR"),
        String::from("PointerAsset"),
    )
    .expect("register home asset");
    let asset_id = asset.asset_id;

    // Devnet opens every pointer target; testnet/mainnet only EVM+WASM.
    let devnet = budlum_uel_abi::BUDLUM_DEVNET_CHAIN_ID;
    for target in [EeId::WASM, EeId::SVM, EeId::MOVE] {
        let ptr = deploy_asset_pointer(&mut state, devnet, &asset_id, target)
            .unwrap_or_else(|e| panic!("pointer into {target:?}: {e}"));
        let expected = derive_pointer_address(&asset_id, target).expect("derive");
        assert_eq!(
            ptr, expected,
            "{target:?} pointer address must be deterministic"
        );

        // A 32-byte pointer maps to a Budlum account that must hold zero BUD:
        // value lives only in the home environment.
        if ptr.len() == 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&ptr);
            assert_eq!(
                state.get_attos_balance(&Address::from(bytes)),
                0,
                "{target:?} pointer account must hold no balance"
            );
        }
    }

    // The registry row records every pointer and still points home.
    let registered = read_registered_asset(&state, &asset_id)
        .expect("read")
        .expect("asset");
    assert_eq!(registered.home_ee, EeId::EVM.0);
    assert_eq!(registered.pointers.len(), 3);
    for target in [EeId::WASM, EeId::SVM, EeId::MOVE] {
        assert_eq!(
            registered.pointers.get(&target.0).map(Vec::as_slice),
            Some(
                derive_pointer_address(&asset_id, target)
                    .expect("derive")
                    .as_slice()
            )
        );
    }

    // Home-EE pointer and duplicate pointers are refused.
    assert!(deploy_asset_pointer(&mut state, devnet, &asset_id, EeId::EVM).is_err());
    assert!(deploy_asset_pointer(&mut state, devnet, &asset_id, EeId::WASM).is_err());
    // Testnet keeps the closed pointer set: SVM pointers are refused there.
    assert!(deploy_asset_pointer(&mut state, BUDLUM_EVM_CHAIN_ID, &asset_id, EeId::SVM).is_err());
    // BudZero never hosts pointers.
    assert!(derive_pointer_address(&asset_id, EeId::BUDZERO).is_err());

    // Pointer bytecode carries the reserved prefix and round-trips its descriptor.
    let desc_src = budlum_core::execution::coordinator::assets::PointerDescriptor {
        asset_id,
        home_ee: EeId::EVM.0,
        home_ref: home_ref.to_vec(),
        standard: AssetStandard::Fungible,
        decimals: 6,
        symbol: String::from("PTR"),
        name: String::from("PointerAsset"),
    };
    let code = budlum_core::execution::coordinator::assets::encode_pointer_bytecode(&desc_src)
        .expect("encode");
    let decoded = decode_pointer_bytecode(&code).expect("decode");
    assert_eq!(decoded.asset_id, asset_id);
    assert_eq!(decoded.home_ee, EeId::EVM.0);
}

// ---------------------------------------------------------------------------
// Y-I.5: deterministic panic -> Fault receipt; worker death -> block rejected
// ---------------------------------------------------------------------------

struct PanickingSvmEe;

impl ExecutionEnvironment for PanickingSvmEe {
    fn id(&self) -> EeId {
        EeId::SVM
    }
    fn validate_deploy(&self, _code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        Err(EeRefusal {
            code: RefusalCode::InvalidCode,
            message: String::from("panicking worker refuses deploys"),
        })
    }
    fn execute(
        &mut self,
        _ctx: &BlockContext,
        _call: &EeCall,
        _host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        panic!("integration-injected-panic");
    }
    fn query(
        &self,
        _ctx: &BlockContext,
        _q: &EeQuery,
        _h: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        Err(EeRefusal {
            code: RefusalCode::Unsupported,
            message: String::from("panicking worker"),
        })
    }
}

#[test]
fn deterministic_panic_becomes_a_fault_receipt_and_the_block_continues() {
    let seed = [0x61u8; 32];
    let sender = UelTx::signer_address_from_seed(&seed).expect("sender");
    let proposer = Address::from([0x62u8; 32]);
    let mut state = funded(&[sender, proposer]);
    let mut coord = ExecutionCoordinator::new();
    coord.register_worker(WorkerEndpoint::in_process(|| Box::new(PanickingSvmEe)));

    let panic_tx = signed_tx(
        &seed,
        0,
        EeId::SVM,
        UelAction::Call {
            target: vec![0u8; 32],
            input: vec![1, 2, 3],
        },
    );
    // A healthy EVM deploy after the panic proves the block continued.
    let deploy_tx = signed_tx(
        &seed,
        1,
        EeId::EVM,
        UelAction::Deploy {
            code: vec![0x00],
            salt: [0x63u8; 32],
        },
    );

    let receipts = state
        .execute_uel_block(&mut coord, ctx(1), proposer, &[panic_tx, deploy_tx])
        .expect("panic must not kill the block");
    assert_eq!(receipts.len(), 2);
    assert_eq!(
        receipts[0].status,
        UelReceiptStatus::Fault {
            ee: EeId::SVM.0,
            panic_digest: panic_digest(EeId::SVM, "integration-injected-panic"),
        },
        "the deterministic panic digest must land in the receipt"
    );
    assert_eq!(receipts[1].status, UelReceiptStatus::Success);
}

#[test]
fn nondeterministic_worker_death_rejects_the_whole_block() {
    let seed = [0x71u8; 32];
    let sender = UelTx::signer_address_from_seed(&seed).expect("sender");
    let proposer = Address::from([0x72u8; 32]);
    let mut state = funded(&[sender, proposer]);
    let root_before = state.calculate_state_root();
    let mut coord = ExecutionCoordinator::new();
    // A socket worker whose socket never appears: every attempt dies in transport.
    coord.register_worker(WorkerEndpoint::unix_socket(
        EeId::SVM,
        std::path::PathBuf::from("/tmp/budlum-integration-dead-worker.sock"),
        None,
    ));

    let tx = signed_tx(
        &seed,
        0,
        EeId::SVM,
        UelAction::Call {
            target: vec![0u8; 32],
            input: vec![9],
        },
    );
    let err = state
        .execute_uel_block(&mut coord, ctx(1), proposer, &[tx])
        .expect_err("worker death across all retries must reject the block");
    match err {
        CoordinatorError::WorkerHalt { attempts, .. } => assert_eq!(attempts, 3),
        other => panic!("expected WorkerHalt after 3 attempts, got {other:?}"),
    }
    assert_eq!(
        state.calculate_state_root(),
        root_before,
        "a rejected block must leave state byte-identical"
    );
}

// ---------------------------------------------------------------------------
// Y-I.6: deploy policy is a chain parameter
// ---------------------------------------------------------------------------

#[test]
fn deploy_policy_is_pinned_per_chain_id_and_enforced_before_decoding() {
    // Chain ids: mainnet freezes everything except EVM+BudZero; testnet and
    // devnet are open.
    let mainnet = DeployPolicy::for_chain_id(45_260);
    assert_eq!(mainnet, DeployPolicy::phase1_default());
    assert_eq!(
        DeployPolicy::for_chain_id(45_261),
        DeployPolicy::allow_all()
    );
    assert_eq!(
        DeployPolicy::for_chain_id(45_262),
        DeployPolicy::allow_all()
    );

    let frozen = [
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
    ];
    for ee in frozen {
        match mainnet.check_deploy_allowed(ee) {
            Err(refusal) => assert_eq!(refusal.code, RefusalCode::Denied),
            Ok(()) => panic!("EE 0x{:02x} must be frozen on mainnet phase 1", ee.0),
        }
    }
    assert!(mainnet.check_deploy_allowed(EeId::EVM).is_ok());
    assert!(mainnet.check_deploy_allowed(EeId::BUDZERO).is_ok());
    for ee in frozen {
        assert!(DeployPolicy::allow_all().check_deploy_allowed(ee).is_ok());
    }

    // The CLI flag opens exactly the named environments on top of phase 1.
    let opened = DeployPolicy::from_cli_csv("wasm, svm ,move").expect("csv");
    assert!(opened.wasm && opened.svm && opened.move_vm);
    assert!(!opened.cairo && !opened.tvm);
    assert!(DeployPolicy::from_cli_csv("nope").is_err());

    // Enforcement happens before code decoding: with BudZero frozen the policy
    // message surfaces even though the payload is garbage; with BudZero open
    // the same garbage fails later, in decoding.
    let mut state = AccountState::new();
    let alice = Address::from([0x81u8; 32]);
    let mut tx = Transaction::new(
        alice,
        Address::zero(),
        0,
        StatefulContractEnvelope::Deploy {
            code: vec![0xFF, 0xFF],
            init_slots: vec![],
        }
        .encode(),
    );
    tx.nonce = 1;
    let closed = DeployPolicy {
        budzero: false,
        ..DeployPolicy::phase1_default()
    };
    let err = execute_stateful_contract_tx(&tx, &mut state, &closed)
        .expect_err("frozen BudZero must refuse before decoding");
    assert!(
        err.contains("disabled by policy"),
        "policy refusal must come first, got: {err}"
    );
    let err_open = execute_stateful_contract_tx(&tx, &mut state, &DeployPolicy::phase1_default())
        .expect_err("garbage code must fail decoding");
    assert!(
        !err_open.contains("disabled by policy"),
        "with BudZero open the failure must be a decode error, got: {err_open}"
    );
}

// ---------------------------------------------------------------------------
// R-21 freeze door: a frozen EE keeps executing but never deploys
// ---------------------------------------------------------------------------

#[test]
fn frozen_ee_deploy_yields_deploy_frozen_receipt_without_writing_code() {
    let seed = [0x91u8; 32];
    let sender = UelTx::signer_address_from_seed(&seed).expect("sender");
    let proposer = Address::from([0x92u8; 32]);
    let mut state = funded(&[sender, proposer]);
    state.execution_state.set_deploy_enabled(EeId::WASM, false);
    let mut coord = ExecutionCoordinator::new();

    let tx = signed_tx(
        &seed,
        0,
        EeId::WASM,
        UelAction::Deploy {
            code: vec![1, 2, 3],
            salt: [0x93u8; 32],
        },
    );
    let receipts = state
        .execute_uel_block(&mut coord, ctx(1), proposer, &[tx])
        .expect("frozen deploy is a receipt, not a block error");
    assert_eq!(receipts[0].status, UelReceiptStatus::DeployFrozen);
    assert!(receipts[0].contract_address.is_none());
    assert!(receipts[0].logs.is_empty());
}
