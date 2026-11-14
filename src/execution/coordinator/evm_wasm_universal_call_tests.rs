use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::execution::coordinator::alias::{
    derive_evm_alias, derive_foreign_cosmos_bech32, derive_move_alias, derive_svm_alias,
    derive_wasm_alias,
};
use crate::execution::coordinator::assets::{
    deploy_asset_pointer, derive_pointer_address, register_asset_entry, AssetStandard,
    MovePointerFlavor, MovePointerOp, SplPointerOp,
};
use crate::execution::coordinator::evm_ee::{
    encode_std_evm_token_code, solidity_selector, StdEvmTokenSpec, EVM_STORAGE_ENTRY_BYTES,
};
use crate::execution::coordinator::gas::MIN_UEL_BASE_FEE_ATTOS;
use crate::execution::coordinator::move_ee::{MoveCallEnvelope, MOVE_BINARY_MAGIC};
use crate::execution::coordinator::state::{
    derive_uel_asset_id, NS_EVM_STORAGE, NS_MOVE_STATE, NS_SVM_ACCOUNT, NS_WASM_STORE,
};
use crate::execution::coordinator::svm_ee::SvmInstructionEnvelope;
use crate::execution::coordinator::universal_call::{
    encode_precompile_call, universal_call_executed_topic0, EVM_UNIVERSAL_PRECOMPILE,
};
use crate::execution::coordinator::wasm_ee::{
    build_valid_cosmwasm_module, validate_cosmwasm_bytecode, WasmEe,
};
use crate::execution::coordinator::{ExecutionCoordinator, UelAction, UelReceiptStatus, UelTx};
use budlum_uel_abi::{BlockContext, EeId, ExecutionEnvironment};

fn sample_ctx() -> BlockContext {
    BlockContext {
        height: 42,
        timestamp_ms: 1_700_000_000_000,
        chain_id: 45_261,
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
fn evm_state_growth_is_metered() {
    let sender = Address::from([0x11; 32]);
    let proposer = Address::from([0x12; 32]);
    let mut state = funded(&[sender, proposer]);
    let mut coord = ExecutionCoordinator::new();

    // Runtime EVM bytecode: CALLDATALOAD(0) -> val, PUSH1 0x07 -> slot, SSTORE, STOP
    // `60 00 35 60 07 55 00`
    let runtime_code = vec![0x60, 0x00, 0x35, 0x60, 0x07, 0x55, 0x00];
    let deploy_tx = UelTx {
        tx_hash: [0x01; 32],
        sender,
        nonce: 0,
        ee: EeId::EVM,
        action: UelAction::Deploy {
            code: runtime_code,
            salt: [0xAA; 32],
        },
        value_attos: 0,
        gas_limit_bgu: 200_000,
        max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
        max_priority_fee_per_bgu_attos: 100,
    };
    let r_deploy = state
        .execute_uel_block(&mut coord, sample_ctx(), proposer, &[deploy_tx])
        .expect("deploy block");
    assert_eq!(r_deploy[0].status, UelReceiptStatus::Success);
    let contract20 = r_deploy[0].output.clone();
    assert_eq!(contract20.len(), 20);
    assert_eq!(state.execution_state.namespace_bytes(NS_EVM_STORAGE), 0);

    // 1. Fresh zero-to-nonzero SSTORE grows `ee/evm/storage` by 84 bytes (52 key + 32 val).
    let mut word_nonzero = [0u8; 32];
    word_nonzero[31] = 0x42;
    let set_tx = UelTx {
        tx_hash: [0x02; 32],
        sender,
        nonce: 1,
        ee: EeId::EVM,
        action: UelAction::Call {
            target: contract20.clone(),
            input: word_nonzero.to_vec(),
        },
        value_attos: 0,
        gas_limit_bgu: 200_000,
        max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
        max_priority_fee_per_bgu_attos: 100,
    };
    let r_set = state
        .execute_uel_block(&mut coord, sample_ctx(), proposer, &[set_tx])
        .expect("sstore set");
    assert_eq!(r_set[0].status, UelReceiptStatus::Success);
    assert_eq!(
        state.execution_state.namespace_bytes(NS_EVM_STORAGE),
        EVM_STORAGE_ENTRY_BYTES
    );

    // 2. Nonzero-to-nonzero update charges lower reset gas and adds 0 new storage bytes.
    let mut word_update = [0u8; 32];
    word_update[31] = 0x99;
    let upd_tx = UelTx {
        tx_hash: [0x03; 32],
        sender,
        nonce: 2,
        ee: EeId::EVM,
        action: UelAction::Call {
            target: contract20.clone(),
            input: word_update.to_vec(),
        },
        value_attos: 0,
        gas_limit_bgu: 200_000,
        max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
        max_priority_fee_per_bgu_attos: 100,
    };
    let r_upd = state
        .execute_uel_block(&mut coord, sample_ctx(), proposer, &[upd_tx])
        .expect("sstore update");
    assert_eq!(r_upd[0].status, UelReceiptStatus::Success);
    assert!(r_set[0].gas_used_bgu >= r_upd[0].gas_used_bgu);
    assert_eq!(
        state.execution_state.namespace_bytes(NS_EVM_STORAGE),
        EVM_STORAGE_ENTRY_BYTES
    );

    // 3. Clearing slot to zero deletes the entry, returning `namespace_bytes` to 0.
    let clr_tx = UelTx {
        tx_hash: [0x04; 32],
        sender,
        nonce: 3,
        ee: EeId::EVM,
        action: UelAction::Call {
            target: contract20,
            input: [0u8; 32].to_vec(),
        },
        value_attos: 0,
        gas_limit_bgu: 200_000,
        max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
        max_priority_fee_per_bgu_attos: 100,
    };
    let r_clr = state
        .execute_uel_block(&mut coord, sample_ctx(), proposer, &[clr_tx])
        .expect("sstore clear");
    assert_eq!(r_clr[0].status, UelReceiptStatus::Success);
    assert_eq!(state.execution_state.namespace_bytes(NS_EVM_STORAGE), 0);
}

#[test]
fn wasm_float_code_refused() {
    let wasm_ee = WasmEe::new();
    let clean = build_valid_cosmwasm_module(&["instantiate", "execute", "query"], &[0x01]);
    wasm_ee
        .validate_deploy(&clean)
        .expect("integer-only CosmWasm module passes");

    // Inject `f64.add` (`0xa0`) into the WASM code body.
    let float_op = build_valid_cosmwasm_module(&["execute"], &[0xa0]);
    let err = wasm_ee
        .validate_deploy(&float_op)
        .expect_err("floating-point WASM opcode must be refused");
    assert!(err.message.contains("floating-point"));

    // Inject `f32` (`0x7d`) parameter type in Type section.
    let mut float_type = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    float_type.extend_from_slice(&[0x01, 0x05, 0x01, 0x60, 0x01, 0x7d, 0x00]);
    assert!(validate_cosmwasm_bytecode(&float_type).is_err());
}

#[test]
fn wasm_ibc_entry_points_refused() {
    let wasm_ee = WasmEe::new();
    let ibc_wasm = build_valid_cosmwasm_module(&["instantiate", "ibc_packet_receive"], &[0x01]);
    let err = wasm_ee
        .validate_deploy(&ibc_wasm)
        .expect_err("IBC export must be refused");
    assert!(err.message.contains("IBC"));

    // Also verify runtime refusal of `StakingMsg`, `DistributionMsg`, `GovMsg`, `IbcMsg`.
    let sender = Address::from([0x21; 32]);
    let proposer = Address::from([0x22; 32]);
    let mut state = funded(&[sender, proposer]);
    let mut coord = ExecutionCoordinator::new();
    let valid_wasm = build_valid_cosmwasm_module(&["instantiate", "execute", "query"], &[0x01]);
    let deploy_tx = UelTx {
        tx_hash: [0x10; 32],
        sender,
        nonce: 0,
        ee: EeId::WASM,
        action: UelAction::Deploy {
            code: valid_wasm,
            salt: [0x01; 32],
        },
        value_attos: 0,
        gas_limit_bgu: 200_000,
        max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
        max_priority_fee_per_bgu_attos: 100,
    };
    let dep = state
        .execute_uel_block(&mut coord, sample_ctx(), proposer, &[deploy_tx])
        .expect("deploy wasm");
    let contract_id = dep[0].output.clone();

    for (i, forbidden_key) in ["staking", "distribution", "gov", "ibc"].iter().enumerate() {
        let payload = serde_json::to_vec(&serde_json::json!({
            "execute": { (*forbidden_key): { "action": "blocked" } }
        }))
        .expect("json");
        let tx = UelTx {
            tx_hash: [0x11 + i as u8; 32],
            sender,
            nonce: 1 + i as u64,
            ee: EeId::WASM,
            action: UelAction::Call {
                target: contract_id.clone(),
                input: payload,
            },
            value_attos: 0,
            gas_limit_bgu: 200_000,
            max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
            max_priority_fee_per_bgu_attos: 100,
        };
        let rec = state
            .execute_uel_block(&mut coord, sample_ctx(), proposer, &[tx])
            .expect("run forbidden msg");
        assert_eq!(
            rec[0].status,
            UelReceiptStatus::Revert,
            "`{forbidden_key}` message must revert"
        );
    }
}

/// EVM router: `calldata[0..32]` = revert flag (`0` commit, non-zero revert after `0x...B001`);
/// `calldata[32..]` = ABI-encoded `IBudlumUniversal.call(...)` payload.
fn build_evm_atomic_router_bytecode() -> Vec<u8> {
    vec![
        // Copy calldata[32..] to mem[0..]:
        0x60, 0x20, 0x36, 0x03, // size = CALLDATASIZE - 32
        0x60, 0x20, // offset = 32
        0x60, 0x00, // destOffset = 0
        0x37, // CALLDATACOPY
        // Invoke 0x...B001 with mem[0..CALLDATASIZE-32] and write 64-byte head to mem[0..64]
        0x60, 0x40, // retLen = 64
        0x60, 0x00, // retOff = 0
        0x60, 0x20, 0x36, 0x03, // argsLen = CALLDATASIZE - 32
        0x60, 0x00, // argsOff = 0
        0x60, 0x00, // val = 0
        0x61, 0xb0, 0x01, // addr = 0x0000...B001
        0x62, 0x04, 0x93, 0xe0, // gas = 300_000
        0xf1, // CALL
        0x15, // ISZERO (1 if CALL failed)
        0x60, 0x2c, // JUMPI to revert_label (pc = 44 = 0x2c)
        0x57,
        // Load revert flag from calldata[0..32]: if != 0 jump to revert_label (0x2c)
        0x60, 0x00, 0x35, // CALLDATALOAD(0)
        0x60, 0x2c, // dest = 0x2c
        0x57, // JUMPI
        // Commit path: RETURN(0, 64)
        0x60, 0x40, 0x60, 0x00, 0xf3, // 0x2c: JUMPDEST -> REVERT(0, 0)
        0x5b, 0x60, 0x00, 0x60, 0x00, 0xfd,
    ]
}

#[test]
fn uel_evm_calls_wasm_atomically() {
    let sender = Address::from([0x31; 32]);
    let proposer = Address::from([0x32; 32]);
    let mut state = funded(&[sender, proposer]);
    let mut coord = ExecutionCoordinator::new();

    // 1. Deploy EVM atomic router contract.
    let router_dep = UelTx {
        tx_hash: [0x20; 32],
        sender,
        nonce: 0,
        ee: EeId::EVM,
        action: UelAction::Deploy {
            code: build_evm_atomic_router_bytecode(),
            salt: [0x01; 32],
        },
        value_attos: 0,
        gas_limit_bgu: 400_000,
        max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
        max_priority_fee_per_bgu_attos: 100,
    };
    let r_router = state
        .execute_uel_block(&mut coord, sample_ctx(), proposer, &[router_dep])
        .expect("deploy router");
    assert_eq!(r_router[0].status, UelReceiptStatus::Success);
    let router_evm20: [u8; 20] = r_router[0].output.as_slice().try_into().expect("20b");
    let router_wasm_alias = derive_foreign_cosmos_bech32(&router_evm20);

    // 2. Deploy CW20 contract on WASM and instantiate 1_000 tokens to `router_wasm_alias`.
    let cw_wasm = build_valid_cosmwasm_module(&["instantiate", "execute", "query"], &[0x01]);
    let cw_dep = UelTx {
        tx_hash: [0x21; 32],
        sender,
        nonce: 1,
        ee: EeId::WASM,
        action: UelAction::Deploy {
            code: cw_wasm,
            salt: [0x02; 32],
        },
        value_attos: 0,
        gas_limit_bgu: 300_000,
        max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
        max_priority_fee_per_bgu_attos: 100,
    };
    let r_cw = state
        .execute_uel_block(&mut coord, sample_ctx(), proposer, &[cw_dep])
        .expect("deploy cw20");
    let cw20_id = r_cw[0].output.clone();

    let init_msg = serde_json::to_vec(&serde_json::json!({
        "execute": {
            "instantiate_cw20": {
                "name": "Budlum Atom",
                "symbol": "BATM",
                "decimals": 6,
                "initial_balances": [
                    { "address": router_wasm_alias, "amount": "1000" }
                ]
            }
        }
    }))
    .expect("init json");
    let init_tx = UelTx {
        tx_hash: [0x22; 32],
        sender,
        nonce: 2,
        ee: EeId::WASM,
        action: UelAction::Call {
            target: cw20_id.clone(),
            input: init_msg,
        },
        value_attos: 0,
        gas_limit_bgu: 300_000,
        max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
        max_priority_fee_per_bgu_attos: 100,
    };
    state
        .execute_uel_block(&mut coord, sample_ctx(), proposer, &[init_tx])
        .expect("init cw20");

    let recipient_wasm = "bud1recipient000000000000000000000000";
    let cw_transfer = serde_json::to_vec(&serde_json::json!({
        "execute": {
            "transfer": { "recipient": recipient_wasm, "amount": "250" }
        }
    }))
    .expect("transfer json");
    let precompile_payload = encode_precompile_call(EeId::WASM, &cw20_id, &cw_transfer, 0, 200_000);

    // 3. First invoke router with revert_flag = 1: EVM calls WASM (250 CW20 moved),
    // then EVM reverts -> CW20 balances MUST remain 1000 / 0!
    let mut revert_input = vec![0u8; 32];
    revert_input[31] = 1;
    revert_input.extend_from_slice(&precompile_payload);
    let tx_revert = UelTx {
        tx_hash: [0x23; 32],
        sender,
        nonce: 3,
        ee: EeId::EVM,
        action: UelAction::Call {
            target: router_evm20.to_vec(),
            input: revert_input,
        },
        value_attos: 0,
        gas_limit_bgu: 500_000,
        max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
        max_priority_fee_per_bgu_attos: 100,
    };
    let r_rev = state
        .execute_uel_block(&mut coord, sample_ctx(), proposer, &[tx_revert])
        .expect("execute reverting cross-ee tx");
    assert_eq!(r_rev[0].status, UelReceiptStatus::Revert);
    assert!(
        r_rev[0].output.is_empty(),
        "must revert via clean REVERT(0,0) after 0x...B001 succeeded"
    );

    let mut rcpt_key = cw20_id.clone();
    rcpt_key.extend_from_slice(format!(":cw20:bal:{recipient_wasm}").as_bytes());
    assert_eq!(
        state
            .execution_state
            .read(NS_WASM_STORE, &rcpt_key)
            .expect("read"),
        None,
        "CW20 transfer must roll back when outer EVM frame reverts"
    );

    // 4. Now invoke router with revert_flag = 0: EVM commits -> CW20 balances become 750 / 250!
    let mut commit_input = vec![0u8; 32];
    commit_input.extend_from_slice(&precompile_payload);
    let tx_commit = UelTx {
        tx_hash: [0x24; 32],
        sender,
        nonce: 4,
        ee: EeId::EVM,
        action: UelAction::Call {
            target: router_evm20.to_vec(),
            input: commit_input,
        },
        value_attos: 0,
        gas_limit_bgu: 500_000,
        max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
        max_priority_fee_per_bgu_attos: 100,
    };
    let r_ok = state
        .execute_uel_block(&mut coord, sample_ctx(), proposer, &[tx_commit])
        .expect("execute committing cross-ee tx");
    assert_eq!(r_ok[0].status, UelReceiptStatus::Success);
    assert_eq!(
        state
            .execution_state
            .read(NS_WASM_STORE, &rcpt_key)
            .expect("read"),
        Some(b"250".to_vec())
    );
}

#[test]
fn universal_call_log_is_visible_to_evm_indexers() {
    let sender = Address::from([0x41; 32]);
    let proposer = Address::from([0x42; 32]);
    let mut state = funded(&[sender, proposer]);
    let mut coord = ExecutionCoordinator::new();

    let cw_wasm = build_valid_cosmwasm_module(&["instantiate", "execute", "query"], &[0x01]);
    let dep = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[
                UelTx {
                    tx_hash: [0x30; 32],
                    sender,
                    nonce: 0,
                    ee: EeId::EVM,
                    action: UelAction::Deploy {
                        code: build_evm_atomic_router_bytecode(),
                        salt: [0x05; 32],
                    },
                    value_attos: 0,
                    gas_limit_bgu: 400_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
                UelTx {
                    tx_hash: [0x31; 32],
                    sender,
                    nonce: 1,
                    ee: EeId::WASM,
                    action: UelAction::Deploy {
                        code: cw_wasm,
                        salt: [0x06; 32],
                    },
                    value_attos: 0,
                    gas_limit_bgu: 300_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
            ],
        )
        .expect("deploy both");
    let router20 = dep[0].output.clone();
    let wasm_target = dep[1].output.clone();

    let auth_msg = serde_json::to_vec(&serde_json::json!({
        "execute": { "authorize_caller": { "caller": String::from_utf8_lossy(&router20) } }
    }))
    .expect("json");
    let put_msg = serde_json::to_vec(&serde_json::json!({
        "execute": { "put": { "key": "hello", "value": "world" } }
    }))
    .expect("json");
    let precompile_cd = encode_precompile_call(EeId::WASM, &wasm_target, &put_msg, 0, 200_000);
    let mut router_cd = vec![0u8; 32];
    router_cd.extend_from_slice(&precompile_cd);

    let call_rec = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[
                UelTx {
                    tx_hash: [0x31; 32],
                    sender,
                    nonce: 2,
                    ee: EeId::WASM,
                    action: UelAction::Call {
                        target: wasm_target,
                        input: auth_msg,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 200_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
                UelTx {
                    tx_hash: [0x32; 32],
                    sender,
                    nonce: 3,
                    ee: EeId::EVM,
                    action: UelAction::Call {
                        target: router20,
                        input: router_cd,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 500_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
            ],
        )
        .expect("call router");
    assert_eq!(call_rec[0].status, UelReceiptStatus::Success);
    assert_eq!(call_rec[1].status, UelReceiptStatus::Success);
    let expected_topic0 = universal_call_executed_topic0();
    let found = call_rec[1].logs.iter().any(|(ee, log)| {
        *ee == EeId::EVM
            && log.emitter.id == EVM_UNIVERSAL_PRECOMPILE
            && log.topics == vec![expected_topic0]
    });
    assert!(
        found,
        "EVM receipt must carry UniversalCallExecuted log from 0x...B001"
    );
}

#[test]
fn asset_id_is_deterministic() {
    let ref_a = [0xAAu8; 20];
    let id1 = derive_uel_asset_id(EeId::EVM, &ref_a);
    let id2 = derive_uel_asset_id(EeId::EVM, &ref_a);
    let id_wasm = derive_uel_asset_id(EeId::WASM, &ref_a);
    assert_eq!(id1, id2);
    assert_ne!(id1, id_wasm);

    let ptr_evm_1 = derive_pointer_address(&id_wasm, EeId::EVM).expect("evm ptr");
    let ptr_evm_2 = derive_pointer_address(&id_wasm, EeId::EVM).expect("evm ptr");
    assert_eq!(ptr_evm_1, ptr_evm_2);
    assert_eq!(ptr_evm_1.len(), 20);

    let ptr_wasm = derive_pointer_address(&id1, EeId::WASM).expect("wasm ptr");
    assert!(String::from_utf8_lossy(&ptr_wasm).starts_with("bud1"));
    assert!(derive_pointer_address(&id1, EeId::SVM).is_ok());
    assert!(derive_pointer_address(&id1, EeId::MOVE).is_ok());
    assert!(derive_pointer_address(&id1, EeId::BUDZERO).is_err());
}

#[test]
fn uel_pointer_holds_no_balance() {
    let alice = Address::from([0x51; 32]);
    let bob = Address::from([0x52; 32]);
    let proposer = Address::from([0x53; 32]);
    let mut state = funded(&[alice, bob, proposer]);
    let mut coord = ExecutionCoordinator::new();

    let alice_evm20 = derive_evm_alias(&alice);
    let bob_evm20 = derive_evm_alias(&bob);
    let alice_wasm = derive_foreign_cosmos_bech32(&alice_evm20);
    let bob_wasm = derive_foreign_cosmos_bech32(&bob_evm20);

    // 1. Deploy home CW20 on WASM with 500 tokens owned by `alice_wasm`.
    let cw_wasm = build_valid_cosmwasm_module(&["instantiate", "execute", "query"], &[0x01]);
    let dep = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0x40; 32],
                sender: alice,
                nonce: 0,
                ee: EeId::WASM,
                action: UelAction::Deploy {
                    code: cw_wasm,
                    salt: [0x10; 32],
                },
                value_attos: 0,
                gas_limit_bgu: 300_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
            }],
        )
        .expect("deploy cw20");
    let cw20_home = dep[0].output.clone();

    let init_msg = serde_json::to_vec(&serde_json::json!({
        "execute": {
            "instantiate_cw20": {
                "name": "HomeCW",
                "symbol": "HCW",
                "decimals": 6,
                "initial_balances": [{ "address": alice_wasm, "amount": "500" }]
            }
        }
    }))
    .expect("json");
    state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0x41; 32],
                sender: alice,
                nonce: 1,
                ee: EeId::WASM,
                action: UelAction::Call {
                    target: cw20_home.clone(),
                    input: init_msg,
                },
                value_attos: 0,
                gas_limit_bgu: 300_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
            }],
        )
        .expect("instantiate cw20");

    // 2. Register asset in `uel/assets` and deploy its ERC-20 pointer on EVM.
    let asset = register_asset_entry(
        &mut state,
        EeId::WASM,
        &cw20_home,
        AssetStandard::Fungible,
        6,
        String::from("HCW"),
        String::from("HomeCW"),
    )
    .expect("register asset");
    let ptr_evm = deploy_asset_pointer(&mut state, &asset.asset_id, EeId::EVM)
        .expect("deploy ERC-20 pointer");
    assert_eq!(state.execution_state.namespace_bytes(NS_EVM_STORAGE), 0);

    // 3. Call `transfer(bob_evm20, 120)` on the ERC-20 pointer from `alice`.
    let mut transfer_cd = solidity_selector("transfer(address,uint256)").to_vec();
    let mut bob_word = [0u8; 32];
    bob_word[12..32].copy_from_slice(&bob_evm20);
    let mut amt_word = [0u8; 32];
    amt_word[16..32].copy_from_slice(&120u128.to_be_bytes());
    transfer_cd.extend_from_slice(&bob_word);
    transfer_cd.extend_from_slice(&amt_word);

    let r_ptr = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0x42; 32],
                sender: alice,
                nonce: 2,
                ee: EeId::EVM,
                action: UelAction::Call {
                    target: ptr_evm,
                    input: transfer_cd,
                },
                value_attos: 0,
                gas_limit_bgu: 400_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
            }],
        )
        .expect("call pointer transfer");
    assert_eq!(r_ptr[0].status, UelReceiptStatus::Success);

    // fixed-commitment custody slots in `ee/evm/storage`: the pointer holds NO balance!
    assert_eq!(state.execution_state.namespace_bytes(NS_EVM_STORAGE), 0);

    // Home CW20 balances updated to 380 / 120!
    let mut k_alice = cw20_home.clone();
    k_alice.extend_from_slice(format!(":cw20:bal:{alice_wasm}").as_bytes());
    let mut k_bob = cw20_home;
    k_bob.extend_from_slice(format!(":cw20:bal:{bob_wasm}").as_bytes());
    assert_eq!(
        state
            .execution_state
            .read(NS_WASM_STORE, &k_alice)
            .expect("r"),
        Some(b"380".to_vec())
    );
    assert_eq!(
        state
            .execution_state
            .read(NS_WASM_STORE, &k_bob)
            .expect("r"),
        Some(b"120".to_vec())
    );
}

#[test]
fn pointer_allowance_lives_at_home() {
    let owner = Address::from([0x61; 32]);
    let spender = Address::from([0x62; 32]);
    let proposer = Address::from([0x63; 32]);
    let mut state = funded(&[owner, spender, proposer]);
    let mut coord = ExecutionCoordinator::new();

    let owner_evm20 = derive_evm_alias(&owner);
    let spender_evm20 = derive_evm_alias(&spender);
    let owner_wasm = derive_foreign_cosmos_bech32(&owner_evm20);
    let spender_wasm = derive_foreign_cosmos_bech32(&spender_evm20);

    // Direction A: Home CW20 on WASM -> ERC-20 pointer `approve` on EVM writes home allowance!
    let cw_wasm = build_valid_cosmwasm_module(&["instantiate", "execute", "query"], &[0x01]);
    let dep = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0x50; 32],
                sender: owner,
                nonce: 0,
                ee: EeId::WASM,
                action: UelAction::Deploy {
                    code: cw_wasm,
                    salt: [0x20; 32],
                },
                value_attos: 0,
                gas_limit_bgu: 300_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
            }],
        )
        .expect("deploy cw20");
    let cw20_home = dep[0].output.clone();

    let asset_cw = register_asset_entry(
        &mut state,
        EeId::WASM,
        &cw20_home,
        AssetStandard::Fungible,
        6,
        String::from("ALW"),
        String::from("AllowanceHome"),
    )
    .expect("reg");
    let ptr_erc20 = deploy_asset_pointer(&mut state, &asset_cw.asset_id, EeId::EVM).expect("ptr");

    let mut approve_cd = solidity_selector("approve(address,uint256)").to_vec();
    let mut sp_w = [0u8; 32];
    sp_w[12..32].copy_from_slice(&spender_evm20);
    let mut amt_w = [0u8; 32];
    amt_w[16..32].copy_from_slice(&777u128.to_be_bytes());
    approve_cd.extend_from_slice(&sp_w);
    approve_cd.extend_from_slice(&amt_w);

    let r_app = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0x51; 32],
                sender: owner,
                nonce: 1,
                ee: EeId::EVM,
                action: UelAction::Call {
                    target: ptr_erc20,
                    input: approve_cd,
                },
                value_attos: 0,
                gas_limit_bgu: 400_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
            }],
        )
        .expect("approve via pointer");
    assert_eq!(r_app[0].status, UelReceiptStatus::Success);
    assert_eq!(
        state.execution_state.namespace_bytes(NS_EVM_STORAGE),
        0,
        "ERC-20 pointer must not maintain a second allowance ledger in EVM storage"
    );

    let mut alw_key = cw20_home;
    alw_key.extend_from_slice(format!(":cw20:alw:{owner_wasm}:{spender_wasm}").as_bytes());
    assert_eq!(
        state
            .execution_state
            .read(NS_WASM_STORE, &alw_key)
            .expect("r"),
        Some(b"777".to_vec())
    );

    // Direction B: Home ERC-20 on EVM -> CW20 pointer on WASM holds zero WASM store keys!
    let erc20_code = encode_std_evm_token_code(&StdEvmTokenSpec {
        standard: AssetStandard::Fungible,
        name: String::from("NativeERC"),
        symbol: String::from("NERC"),
        decimals: 18,
        initial_holder: owner_evm20,
        initial_supply_or_token_id: 10_000,
        base_uri: String::new(),
    })
    .expect("std erc20");
    let dep_erc = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0x52; 32],
                sender: owner,
                nonce: 2,
                ee: EeId::EVM,
                action: UelAction::Deploy {
                    code: erc20_code,
                    salt: [0x30; 32],
                },
                value_attos: 0,
                gas_limit_bgu: 400_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
            }],
        )
        .expect("deploy home erc20");
    let home_erc20 = dep_erc[0].output.clone();
    let asset_erc = register_asset_entry(
        &mut state,
        EeId::EVM,
        &home_erc20,
        AssetStandard::Fungible,
        18,
        String::from("NERC"),
        String::from("NativeERC"),
    )
    .expect("reg erc20");
    let ptr_cw20 = deploy_asset_pointer(&mut state, &asset_erc.asset_id, EeId::WASM).expect("ptr");
    let wasm_bytes_before = state.execution_state.namespace_bytes(NS_WASM_STORE);

    let cw_inc = serde_json::to_vec(&serde_json::json!({
        "execute": {
            "increase_allowance": { "spender": spender_wasm, "amount": "333" }
        }
    }))
    .expect("json");
    let r_cw_app = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0x53; 32],
                sender: owner,
                nonce: 3,
                ee: EeId::WASM,
                action: UelAction::Call {
                    target: ptr_cw20,
                    input: cw_inc,
                },
                value_attos: 0,
                gas_limit_bgu: 400_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
            }],
        )
        .expect("approve via cw20 pointer");
    assert_eq!(r_cw_app[0].status, UelReceiptStatus::Success);
    assert_eq!(
        state.execution_state.namespace_bytes(NS_WASM_STORE),
        wasm_bytes_before,
        "CW20 pointer must not write any allowance key into ee/wasm/store"
    );
}

#[test]
fn svm_pointer_holds_no_balance() {
    let alice = Address::from([0x71; 32]);
    let bob = Address::from([0x72; 32]);
    let proposer = Address::from([0x73; 32]);
    let mut state = funded(&[alice, bob, proposer]);
    let mut coord = ExecutionCoordinator::new();

    let alice_evm20 = derive_evm_alias(&alice);
    let bob_evm20 = derive_evm_alias(&bob);
    state
        .execution_state
        .ensure_alias_registered(&bob, EeId::EVM)
        .expect("register bob evm alias");

    // 1. Deploy home ERC-20 on EVM with 1,000 units held by Alice.
    let erc20_code = encode_std_evm_token_code(&StdEvmTokenSpec {
        standard: AssetStandard::Fungible,
        name: String::from("HomeSvmAsset"),
        symbol: String::from("HSVM"),
        decimals: 6,
        initial_holder: alice_evm20,
        initial_supply_or_token_id: 1_000,
        base_uri: String::new(),
    })
    .expect("std erc20");
    let dep = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0x81; 32],
                sender: alice,
                nonce: 0,
                ee: EeId::EVM,
                action: UelAction::Deploy {
                    code: erc20_code,
                    salt: [0x81; 32],
                },
                value_attos: 0,
                gas_limit_bgu: 400_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
            }],
        )
        .expect("deploy home erc20");
    let home_erc20 = dep[0].output.clone();

    // 2. Register asset & deploy stateless SPL pointer on SVM.
    let asset = register_asset_entry(
        &mut state,
        EeId::EVM,
        &home_erc20,
        AssetStandard::Fungible,
        6,
        String::from("HSVM"),
        String::from("HomeSvmAsset"),
    )
    .expect("reg");
    let ptr_svm = deploy_asset_pointer(&mut state, &asset.asset_id, EeId::SVM).expect("svm ptr");
    let svm_bytes_before = state.execution_state.namespace_bytes(NS_SVM_ACCOUNT);

    // 3. Alice transfers 250 units via SVM SPL pointer and approves Bob for 300.
    let xfer_in = serde_json::to_vec(&SplPointerOp::Transfer {
        to: bob.0,
        amount: 250,
    })
    .expect("json");
    let appr_in = serde_json::to_vec(&SplPointerOp::Approve {
        delegate: bob.0,
        amount: 300,
    })
    .expect("json");
    let res = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[
                UelTx {
                    tx_hash: [0x82; 32],
                    sender: alice,
                    nonce: 1,
                    ee: EeId::SVM,
                    action: UelAction::Call {
                        target: ptr_svm.clone(),
                        input: xfer_in,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 400_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
                UelTx {
                    tx_hash: [0x83; 32],
                    sender: alice,
                    nonce: 2,
                    ee: EeId::SVM,
                    action: UelAction::Call {
                        target: ptr_svm.clone(),
                        input: appr_in,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 400_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
            ],
        )
        .expect("svm ptr calls");
    assert_eq!(res[0].status, UelReceiptStatus::Success);
    assert_eq!(res[1].status, UelReceiptStatus::Success);

    // Zero shadow balances or allowance accounts in `ee/svm/account`.
    assert_eq!(
        state.execution_state.namespace_bytes(NS_SVM_ACCOUNT),
        svm_bytes_before,
        "SVM pointer must hold zero balance or allowance state"
    );

    // Query balanceOf(bob) through the SVM pointer: must read 250 live from EVM home.
    let bal_q = serde_json::to_vec(&SplPointerOp::BalanceOf { owner: bob.0 }).expect("json");
    let alw_q = serde_json::to_vec(&SplPointerOp::Allowance {
        owner: alice.0,
        delegate: bob.0,
    })
    .expect("json");
    state
        .execution_state
        .ensure_alias_registered(&alice, EeId::EVM)
        .expect("alice alias");
    let q_res = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[
                UelTx {
                    tx_hash: [0x84; 32],
                    sender: bob,
                    nonce: 0,
                    ee: EeId::SVM,
                    action: UelAction::Call {
                        target: ptr_svm.clone(),
                        input: bal_q,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 400_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
                UelTx {
                    tx_hash: [0x85; 32],
                    sender: bob,
                    nonce: 1,
                    ee: EeId::SVM,
                    action: UelAction::Call {
                        target: ptr_svm,
                        input: alw_q,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 400_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
            ],
        )
        .expect("svm ptr queries");
    assert_eq!(q_res[0].status, UelReceiptStatus::Success);
    assert_eq!(q_res[0].output, 250u128.to_le_bytes());
    assert_eq!(q_res[1].status, UelReceiptStatus::Success);
    assert_eq!(q_res[1].output, 300u128.to_le_bytes());

    // Confirm Bob's home ERC-20 balance on EVM via balanceOf.
    let mut bal_cd = solidity_selector("balanceOf(address)").to_vec();
    let mut bob_w = [0u8; 32];
    bob_w[12..32].copy_from_slice(&bob_evm20);
    bal_cd.extend_from_slice(&bob_w);
    let evm_q = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0x86; 32],
                sender: bob,
                nonce: 2,
                ee: EeId::EVM,
                action: UelAction::Call {
                    target: home_erc20,
                    input: bal_cd,
                },
                value_attos: 0,
                gas_limit_bgu: 200_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
            }],
        )
        .expect("evm bal");
    assert_eq!(
        evm_q[0].output.get(16..32),
        Some(&250u128.to_be_bytes()[..])
    );
}

#[test]
fn move_pointer_holds_no_balance() {
    let alice = Address::from([0x91; 32]);
    let bob = Address::from([0x92; 32]);
    let proposer = Address::from([0x93; 32]);
    let mut state = funded(&[alice, bob, proposer]);
    let mut coord = ExecutionCoordinator::new();

    let alice_evm20 = derive_evm_alias(&alice);
    state
        .execution_state
        .ensure_alias_registered(&bob, EeId::EVM)
        .expect("register bob evm alias");
    let _ = derive_move_alias(&alice);

    // 1. Deploy home ERC-20 on EVM with 2,000 units held by Alice.
    let erc20_code = encode_std_evm_token_code(&StdEvmTokenSpec {
        standard: AssetStandard::Fungible,
        name: String::from("HomeMoveAsset"),
        symbol: String::from("HMA"),
        decimals: 8,
        initial_holder: alice_evm20,
        initial_supply_or_token_id: 2_000,
        base_uri: String::new(),
    })
    .expect("std erc20");
    let dep = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0x91; 32],
                sender: alice,
                nonce: 0,
                ee: EeId::EVM,
                action: UelAction::Deploy {
                    code: erc20_code,
                    salt: [0x91; 32],
                },
                value_attos: 0,
                gas_limit_bgu: 400_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
            }],
        )
        .expect("deploy home erc20");
    let home_erc20 = dep[0].output.clone();

    // 2. Register asset & deploy stateless Move pointer
    // (`ee/move/state` holds only pointer bytecode).
    let asset = register_asset_entry(
        &mut state,
        EeId::EVM,
        &home_erc20,
        AssetStandard::Fungible,
        8,
        String::from("HMA"),
        String::from("HomeMoveAsset"),
    )
    .expect("reg");
    let ptr_move = deploy_asset_pointer(&mut state, &asset.asset_id, EeId::MOVE).expect("move ptr");
    let move_bytes_before = state.execution_state.namespace_bytes(NS_MOVE_STATE);

    // 3. Alice approves Bob 450 via Move pointer (`FungibleAsset` flavor),
    // then Bob runs `transferFrom` 150.
    let appr_in = serde_json::to_vec(&MovePointerOp::Approve {
        flavor: MovePointerFlavor::FungibleAsset,
        spender: bob.0,
        amount: 450,
    })
    .expect("json");
    let xfer_from_in = serde_json::to_vec(&MovePointerOp::TransferFrom {
        flavor: MovePointerFlavor::Coin,
        owner: alice.0,
        to: bob.0,
        amount: 150,
    })
    .expect("json");
    state
        .execution_state
        .ensure_alias_registered(&alice, EeId::EVM)
        .expect("alice alias");
    let r1 = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[
                UelTx {
                    tx_hash: [0x92; 32],
                    sender: alice,
                    nonce: 1,
                    ee: EeId::MOVE,
                    action: UelAction::Call {
                        target: ptr_move.clone(),
                        input: appr_in,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 400_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
                UelTx {
                    tx_hash: [0x93; 32],
                    sender: bob,
                    nonce: 0,
                    ee: EeId::MOVE,
                    action: UelAction::Call {
                        target: ptr_move.clone(),
                        input: xfer_from_in,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 400_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
            ],
        )
        .expect("move ptr ops");
    assert_eq!(r1[0].status, UelReceiptStatus::Success);
    assert_eq!(r1[1].status, UelReceiptStatus::Success);

    // Move pointer wrote zero CoinStore / FungibleStore / allowance state into `ee/move/state`.
    assert_eq!(
        state.execution_state.namespace_bytes(NS_MOVE_STATE),
        move_bytes_before,
        "Move pointer must hold zero balance or allowance resources"
    );

    // Query live balance & remaining allowance (450 - 150 = 300) via Move pointer.
    let bal_q = serde_json::to_vec(&MovePointerOp::Balance {
        flavor: MovePointerFlavor::Coin,
        owner: bob.0,
    })
    .expect("json");
    let alw_q = serde_json::to_vec(&MovePointerOp::Allowance {
        flavor: MovePointerFlavor::FungibleAsset,
        owner: alice.0,
        spender: bob.0,
    })
    .expect("json");
    let q_res = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[
                UelTx {
                    tx_hash: [0x94; 32],
                    sender: bob,
                    nonce: 1,
                    ee: EeId::MOVE,
                    action: UelAction::Call {
                        target: ptr_move.clone(),
                        input: bal_q,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 400_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
                UelTx {
                    tx_hash: [0x95; 32],
                    sender: bob,
                    nonce: 2,
                    ee: EeId::MOVE,
                    action: UelAction::Call {
                        target: ptr_move,
                        input: alw_q,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 400_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
            ],
        )
        .expect("move ptr queries");
    assert_eq!(q_res[0].status, UelReceiptStatus::Success);
    assert_eq!(q_res[0].output, 150u128.to_le_bytes());
    assert_eq!(q_res[1].status, UelReceiptStatus::Success);
    assert_eq!(q_res[1].output, 300u128.to_le_bytes());
}

#[test]
fn home_svm_and_move_pointers_work_cross_ee_and_refuse_unauthorized_mint() {
    let alice = Address::from([0xA1; 32]);
    let bob = Address::from([0xA2; 32]);
    let proposer = Address::from([0xA3; 32]);
    let mut state = funded(&[alice, bob, proposer]);
    let mut coord = ExecutionCoordinator::new();

    let alice_move = derive_move_alias(&alice);
    let (alice_svm, _) = derive_svm_alias(&alice).expect("alice svm alias");
    state
        .execution_state
        .ensure_alias_registered(&alice, EeId::EVM)
        .expect("alice evm");
    state
        .execution_state
        .ensure_alias_registered(&bob, EeId::EVM)
        .expect("bob evm");
    state
        .execution_state
        .ensure_alias_registered(&bob, EeId::MOVE)
        .expect("bob move");
    state
        .execution_state
        .ensure_alias_registered(&bob, EeId::SVM)
        .expect("bob svm");
    let bob_wasm = derive_wasm_alias(&bob);
    let bob_evm20 = derive_evm_alias(&bob);

    // 1. Deploy home Move module, mint as Alice, and verify Bob cannot mint.
    let mut move_code = MOVE_BINARY_MAGIC.to_vec();
    move_code.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    let dep_move = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0xE1; 32],
                sender: alice,
                nonce: 0,
                ee: EeId::MOVE,
                action: UelAction::Deploy {
                    code: move_code,
                    salt: [0xE1; 32],
                },
                value_attos: 0,
                gas_limit_bgu: 300_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
            }],
        )
        .expect("deploy move home");
    let move_home = dep_move[0].output.clone();

    let mint_ok = serde_json::to_vec(&MoveCallEnvelope::EntryFunction {
        module_id: String::from("0x1::fungible_asset"),
        function_name: String::from("mint"),
        args: vec![
            format!("0x{}", hex::encode(alice_move)),
            String::from("1500"),
        ],
    })
    .expect("json");
    let mint_bad = serde_json::to_vec(&MoveCallEnvelope::EntryFunction {
        module_id: String::from("0x1::fungible_asset"),
        function_name: String::from("mint"),
        args: vec![format!("0x{}", hex::encode(bob.0)), String::from("9999")],
    })
    .expect("json");
    let mint_res = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[
                UelTx {
                    tx_hash: [0xE2; 32],
                    sender: alice,
                    nonce: 1,
                    ee: EeId::MOVE,
                    action: UelAction::Call {
                        target: move_home.clone(),
                        input: mint_ok,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 300_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
                UelTx {
                    tx_hash: [0xE3; 32],
                    sender: bob,
                    nonce: 0,
                    ee: EeId::MOVE,
                    action: UelAction::Call {
                        target: move_home.clone(),
                        input: mint_bad,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 300_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
            ],
        )
        .expect("move mint checks");
    assert_eq!(mint_res[0].status, UelReceiptStatus::Success);
    assert_eq!(mint_res[1].status, UelReceiptStatus::Revert);

    // 2. Register Move home asset and deploy stateless CW20 pointer on WASM.
    let asset_move = register_asset_entry(
        &mut state,
        EeId::MOVE,
        &move_home,
        AssetStandard::Fungible,
        8,
        String::from("HMV"),
        String::from("HomeMove"),
    )
    .expect("reg move");
    let ptr_wasm = deploy_asset_pointer(&mut state, &asset_move.asset_id, EeId::WASM)
        .expect("deploy wasm ptr for move");
    let wasm_before = state.execution_state.namespace_bytes(NS_WASM_STORE);

    let cw_xfer = serde_json::to_vec(&serde_json::json!({
        "execute": { "transfer": { "recipient": bob_wasm, "amount": "400" } }
    }))
    .expect("json");
    let cw_q = serde_json::to_vec(&serde_json::json!({
        "query": { "balance": { "address": bob_wasm } }
    }))
    .expect("json");
    let wasm_res = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[
                UelTx {
                    tx_hash: [0xE4; 32],
                    sender: alice,
                    nonce: 2,
                    ee: EeId::WASM,
                    action: UelAction::Call {
                        target: ptr_wasm.clone(),
                        input: cw_xfer,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 400_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
                UelTx {
                    tx_hash: [0xE5; 32],
                    sender: bob,
                    nonce: 1,
                    ee: EeId::WASM,
                    action: UelAction::Call {
                        target: ptr_wasm,
                        input: cw_q,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 400_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
            ],
        )
        .expect("wasm ptr over move home");
    assert_eq!(wasm_res[0].status, UelReceiptStatus::Success);
    assert_eq!(wasm_res[1].status, UelReceiptStatus::Success);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&wasm_res[1].output).expect("bal")["balance"],
        "400"
    );
    assert_eq!(
        state.execution_state.namespace_bytes(NS_WASM_STORE),
        wasm_before
    );

    // 3. Initialize & mint SVM SPL home asset, then operate via stateless EVM pointer.
    let mint_pk = [0xD1u8; 32];
    let init_ix = serde_json::to_vec(&SvmInstructionEnvelope::SplInitializeMint {
        mint: mint_pk,
        decimals: 6,
        mint_authority: alice_svm,
        is_token_2022: false,
    })
    .expect("json");
    let mint_ix = serde_json::to_vec(&SvmInstructionEnvelope::SplMintTo {
        mint: mint_pk,
        dest_owner: alice_svm,
        amount: 900,
    })
    .expect("json");
    let svm_setup = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[
                UelTx {
                    tx_hash: [0xE6; 32],
                    sender: alice,
                    nonce: 3,
                    ee: EeId::SVM,
                    action: UelAction::Call {
                        target: mint_pk.to_vec(),
                        input: init_ix,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 300_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
                UelTx {
                    tx_hash: [0xE7; 32],
                    sender: alice,
                    nonce: 4,
                    ee: EeId::SVM,
                    action: UelAction::Call {
                        target: mint_pk.to_vec(),
                        input: mint_ix,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 300_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
            ],
        )
        .expect("svm setup");
    assert_eq!(svm_setup[0].status, UelReceiptStatus::Success);
    assert_eq!(svm_setup[1].status, UelReceiptStatus::Success);

    let asset_svm = register_asset_entry(
        &mut state,
        EeId::SVM,
        &mint_pk,
        AssetStandard::Fungible,
        6,
        String::from("HSPL"),
        String::from("HomeSPL"),
    )
    .expect("reg svm");
    let ptr_evm = deploy_asset_pointer(&mut state, &asset_svm.asset_id, EeId::EVM)
        .expect("deploy evm ptr for svm");
    let evm_before = state.execution_state.namespace_bytes(NS_EVM_STORAGE);

    let mut xfer_cd = solidity_selector("transfer(address,uint256)").to_vec();
    let mut bob_w = [0u8; 32];
    bob_w[12..32].copy_from_slice(&bob_evm20);
    let mut amt_w = [0u8; 32];
    amt_w[16..32].copy_from_slice(&200u128.to_be_bytes());
    xfer_cd.extend_from_slice(&bob_w);
    xfer_cd.extend_from_slice(&amt_w);
    let mut bal_cd = solidity_selector("balanceOf(address)").to_vec();
    bal_cd.extend_from_slice(&bob_w);

    let evm_res = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[
                UelTx {
                    tx_hash: [0xE8; 32],
                    sender: alice,
                    nonce: 5,
                    ee: EeId::EVM,
                    action: UelAction::Call {
                        target: ptr_evm.clone(),
                        input: xfer_cd,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 400_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
                UelTx {
                    tx_hash: [0xE9; 32],
                    sender: bob,
                    nonce: 2,
                    ee: EeId::EVM,
                    action: UelAction::Call {
                        target: ptr_evm,
                        input: bal_cd,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 400_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                },
            ],
        )
        .expect("evm ptr over svm home");
    assert_eq!(evm_res[0].status, UelReceiptStatus::Success);
    assert_eq!(evm_res[1].status, UelReceiptStatus::Success);
    assert_eq!(
        evm_res[1].output.get(16..32),
        Some(&200u128.to_be_bytes()[..])
    );
    assert_eq!(
        state.execution_state.namespace_bytes(NS_EVM_STORAGE),
        evm_before
    );
}
