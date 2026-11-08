use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::execution::coordinator::alias::{derive_svm_alias, is_ed25519_on_curve};
use crate::execution::coordinator::gas::MIN_UEL_BASE_FEE_ATTOS;
use crate::execution::coordinator::move_ee::{
    MoveCallEnvelope, MoveEe, MoveRuntimeConfig, MOVE_BINARY_MAGIC,
};
use crate::execution::coordinator::state::NS_WASM_STORE;
use crate::execution::coordinator::svm_ee::{
    derive_associated_token_address, svm_universal_program_id, SvmEe, SvmInstructionEnvelope,
    SvmRuntimeConfig, FORBIDDEN_SVM_STAKE_PROGRAM_ID, FORBIDDEN_SVM_VOTE_PROGRAM_ID,
    SVM_SPL_TOKEN_PROGRAM_ID,
};
use crate::execution::coordinator::wasm_ee::build_valid_cosmwasm_module;
use crate::execution::coordinator::{
    ExecutionCoordinator, UelAction, UelReceiptStatus, UelTx,
};
use budlum_uel_abi::{BlockContext, BudAmount, EeId, ExecutionEnvironment};

fn sample_ctx() -> BlockContext {
    BlockContext {
        height: 77,
        timestamp_ms: 1_700_000_077_000,
        chain_id: 45_261,
        randao: [0x5A; 32],
        base_fee: BudAmount(MIN_UEL_BASE_FEE_ATTOS),
    }
}

fn funded(addrs: &[Address]) -> AccountState {
    let mut s = AccountState::new();
    for a in addrs {
        s.credit_account(a, 10_000);
    }
    s
}

#[test]
fn svm_jit_is_disabled() {
    let svm = SvmEe::new();
    assert!(!svm.config().jit_enabled, "SBPF JIT must default to false");

    let bad_cfg = SvmRuntimeConfig {
        jit_enabled: true,
        ..SvmRuntimeConfig::default()
    };
    let err = SvmEe::with_config(bad_cfg).expect_err("enabling SBPF JIT must be refused");
    assert!(err.contains("JIT"));

    // Verify ELF SBPF deploy validation succeeds in interpreter mode.
    let mut valid_elf = vec![0x7f, b'E', b'L', b'F'];
    valid_elf.extend_from_slice(&[0x02, 0x01, 0x01, 0x00]);
    svm.validate_deploy(&valid_elf).expect("valid ELF accepted");
    assert!(svm.validate_deploy(b"NOPE").is_err());
}

#[test]
fn svm_spl_token_and_vote_stake_refusal_and_universal_cpi() {
    let alice = Address::from([0x71; 32]);
    let bob = Address::from([0x72; 32]);
    let proposer = Address::from([0x73; 32]);
    let mut state = funded(&[alice, bob, proposer]);
    let mut coord = ExecutionCoordinator::new();

    let (alice_svm, _) = derive_svm_alias(&alice).expect("alice off-curve svm alias");
    let (bob_svm, _) = derive_svm_alias(&bob).expect("bob off-curve svm alias");
    let mint = [0x99u8; 32];
    let ata = derive_associated_token_address(&alice_svm, &mint).expect("ata");
    assert!(!is_ed25519_on_curve(&ata));

    // 1. Initialize SPL Mint, MintTo 500 to Alice, Transfer 200 to Bob.
    let init_ix = serde_json::to_vec(&SvmInstructionEnvelope::SplInitializeMint {
        mint,
        decimals: 6,
        mint_authority: alice_svm,
        is_token_2022: false,
    })
    .expect("json");
    let mint_ix = serde_json::to_vec(&SvmInstructionEnvelope::SplMintTo {
        mint,
        dest_owner: alice_svm,
        amount: 500,
    })
    .expect("json");
    let xfer_ix = serde_json::to_vec(&SvmInstructionEnvelope::SplTransfer {
        mint,
        to_owner: bob_svm,
        amount: 200,
    })
    .expect("json");

    let recs = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[
                UelTx {
                    tx_hash: [0x61; 32],
                    sender: alice,
                    nonce: 0,
                    ee: EeId::SVM,
                    action: UelAction::Call {
                        target: SVM_SPL_TOKEN_PROGRAM_ID.to_vec(),
                        input: init_ix,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 200_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
                UelTx {
                    tx_hash: [0x62; 32],
                    sender: alice,
                    nonce: 1,
                    ee: EeId::SVM,
                    action: UelAction::Call {
                        target: SVM_SPL_TOKEN_PROGRAM_ID.to_vec(),
                        input: mint_ix,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 200_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
                UelTx {
                    tx_hash: [0x63; 32],
                    sender: alice,
                    nonce: 2,
                    ee: EeId::SVM,
                    action: UelAction::Call {
                        target: SVM_SPL_TOKEN_PROGRAM_ID.to_vec(),
                        input: xfer_ix,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 200_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
            ],
        )
        .expect("spl block");
    assert!(recs.iter().all(|r| r.status == UelReceiptStatus::Success));

    // 2. Vote and Stake programs MUST be refused (section 8.15).
    for (idx, forbidden_prog) in [FORBIDDEN_SVM_VOTE_PROGRAM_ID, FORBIDDEN_SVM_STAKE_PROGRAM_ID]
        .iter()
        .enumerate()
    {
        let r = state
            .execute_uel_block(
                &mut coord,
                sample_ctx(),
                proposer,
                &[UelTx {
                    tx_hash: [0x64 + idx as u8; 32],
                    sender: alice,
                    nonce: 3 + idx as u64,
                    ee: EeId::SVM,
                    action: UelAction::Call {
                        target: forbidden_prog.to_vec(),
                        input: b"{}".to_vec(),
                    },
                    value_attos: 0,
                    gas_limit_bgu: 100_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                }],
            )
            .expect("forbidden prog block");
        assert_eq!(r[0].status, UelReceiptStatus::Revert);
    }

    // 3. SVM Universal Call builtin CPI into WASM contract!
    let cw_wasm = build_valid_cosmwasm_module(&["instantiate", "execute", "query"], &[0x01]);
    let dep = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0x66; 32],
                sender: alice,
                nonce: 5,
                ee: EeId::WASM,
                action: UelAction::Deploy {
                    code: cw_wasm,
                    salt: [0x44; 32],
                },
                value_attos: 0,
                gas_limit_bgu: 200_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
            }],
        )
        .expect("deploy wasm");
    let wasm_contract = dep[0].output.clone();

    let wasm_put = serde_json::to_vec(&serde_json::json!({
        "execute": { "put": { "key": "from_svm", "value": "ok" } }
    }))
    .expect("json");
    let cpi_ix = serde_json::to_vec(&SvmInstructionEnvelope::UniversalCpi {
        target_ee: EeId::WASM.0,
        target: wasm_contract.clone(),
        input: wasm_put,
        value_attos: 0,
        gas_limit_bgu: 150_000,
        is_static: false,
    })
    .expect("json");
    let cpi_rec = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0x67; 32],
                sender: alice,
                nonce: 6,
                ee: EeId::SVM,
                action: UelAction::Call {
                    target: svm_universal_program_id().to_vec(),
                    input: cpi_ix,
                },
                value_attos: 0,
                gas_limit_bgu: 300_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
            }],
        )
        .expect("svm universal cpi");
    assert_eq!(cpi_rec[0].status, UelReceiptStatus::Success);

    let mut store_k = wasm_contract;
    store_k.extend_from_slice(b":kv:from_svm");
    assert_eq!(
        state.execution_state.read(NS_WASM_STORE, &store_k).expect("r"),
        Some(b"ok".to_vec())
    );
}

#[test]
fn move_sequential_randomness_staking_refusal_and_universal_call() {
    // Block-STM parallel execution must be refused.
    assert!(MoveEe::with_config(MoveRuntimeConfig {
        block_stm_parallel: true,
        max_value_nest_depth: 128,
    })
    .is_err());

    let alice = Address::from([0x81; 32]);
    let proposer = Address::from([0x82; 32]);
    let mut state = funded(&[alice, proposer]);
    let mut coord = ExecutionCoordinator::new();

    // 1. Deploy valid Move binary module (`0xa11ceb0b` magic).
    let mut module_bytes = MOVE_BINARY_MAGIC.to_vec();
    module_bytes.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]);
    let dep = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0x70; 32],
                sender: alice,
                nonce: 0,
                ee: EeId::MOVE,
                action: UelAction::Deploy {
                    code: module_bytes,
                    salt: [0x55; 32],
                },
                value_attos: 0,
                gas_limit_bgu: 200_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
            }],
        )
        .expect("deploy move module");
    assert_eq!(dep[0].status, UelReceiptStatus::Success);

    // 2. Staking & Governance modules (`0x1::stake`, `0x1::aptos_governance`) are refused.
    for (i, mod_id) in ["0x1::stake", "0x1::aptos_governance"].iter().enumerate() {
        let payload = serde_json::to_vec(&MoveCallEnvelope::EntryFunction {
            module_id: String::from(*mod_id),
            function_name: String::from("initialize"),
            args: Vec::new(),
        })
        .expect("json");
        let rec = state
            .execute_uel_block(
                &mut coord,
                sample_ctx(),
                proposer,
                &[UelTx {
                    tx_hash: [0x71 + i as u8; 32],
                    sender: alice,
                    nonce: 1 + i as u64,
                    ee: EeId::MOVE,
                    action: UelAction::Call {
                        target: vec![0x01; 32],
                        input: payload,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 200_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                }],
            )
            .expect("call forbidden move module");
        assert_eq!(rec[0].status, UelReceiptStatus::Revert);
    }

    // 3. `0x1::randomness` binds deterministically to `BlockContext.randao`.
    let rand_call = serde_json::to_vec(&MoveCallEnvelope::EntryFunction {
        module_id: String::from("0x1::randomness"),
        function_name: String::from("u256_integer"),
        args: Vec::new(),
    })
    .expect("json");
    let r1 = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0x73; 32],
                sender: alice,
                nonce: 3,
                ee: EeId::MOVE,
                action: UelAction::Call {
                    target: vec![0x01; 32],
                    input: rand_call,
                },
                value_attos: 0,
                gas_limit_bgu: 200_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
            }],
        )
        .expect("randomness");
    assert_eq!(r1[0].status, UelReceiptStatus::Success);
    assert_eq!(r1[0].output.len(), 32);

    // 4. `0x1::budlum_universal::call` invokes WASM contract atomically!
    let cw_wasm = build_valid_cosmwasm_module(&["instantiate", "execute", "query"], &[0x01]);
    let wdep = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0x74; 32],
                sender: alice,
                nonce: 4,
                ee: EeId::WASM,
                action: UelAction::Deploy {
                    code: cw_wasm,
                    salt: [0x66; 32],
                },
                value_attos: 0,
                gas_limit_bgu: 200_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
            }],
        )
        .expect("deploy wasm");
    let wasm_target = wdep[0].output.clone();

    let put_msg = serde_json::to_vec(&serde_json::json!({
        "execute": { "put": { "key": "from_move", "value": "aptos_ok" } }
    }))
    .expect("json");
    let ucall_env = serde_json::to_vec(&MoveCallEnvelope::BudlumUniversalCall {
        target_ee: EeId::WASM.0,
        target: wasm_target.clone(),
        input: put_msg,
        value_octas: 0,
        gas_bgu: 150_000,
        is_static: false,
    })
    .expect("json");
    let r_ucall = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0x75; 32],
                sender: alice,
                nonce: 5,
                ee: EeId::MOVE,
                action: UelAction::Call {
                    target: vec![0x01; 32],
                    input: ucall_env,
                },
                value_attos: 0,
                gas_limit_bgu: 300_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
            }],
        )
        .expect("move universal call");
    assert_eq!(r_ucall[0].status, UelReceiptStatus::Success);

    let mut store_k = wasm_target;
    store_k.extend_from_slice(b":kv:from_move");
    assert_eq!(
        state.execution_state.read(NS_WASM_STORE, &store_k).expect("r"),
        Some(b"aptos_ok".to_vec())
    );
}
