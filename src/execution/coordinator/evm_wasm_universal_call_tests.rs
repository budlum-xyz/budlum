use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::execution::coordinator::alias::{
    derive_evm_alias, derive_foreign_cosmos_bech32,
};
use crate::execution::coordinator::assets::{
    deploy_asset_pointer, derive_pointer_address, register_asset_entry, AssetStandard,
};
use crate::execution::coordinator::evm_ee::{
    encode_std_evm_token_code, solidity_selector, StdEvmTokenSpec, EVM_STORAGE_ENTRY_BYTES,
};
use crate::execution::coordinator::gas::MIN_UEL_BASE_FEE_ATTOS;
use crate::execution::coordinator::state::{
    derive_uel_asset_id, NS_EVM_STORAGE, NS_WASM_STORE,
};
use crate::execution::coordinator::universal_call::{
    encode_precompile_call, universal_call_executed_topic0, EVM_UNIVERSAL_PRECOMPILE,
};
use crate::execution::coordinator::wasm_ee::{
    build_valid_cosmwasm_module, validate_cosmwasm_bytecode, WasmEe,
};
use crate::execution::coordinator::{
    ExecutionCoordinator, UelAction, UelReceiptStatus, UelTx,
};
use budlum_uel_abi::{BlockContext, BudAmount, EeId, ExecutionEnvironment};

fn sample_ctx() -> BlockContext {
    BlockContext {
        height: 42,
        timestamp_ms: 1_700_000_000_000,
        chain_id: 45_261,
        randao: [0xAB; 32],
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
        0x60, 0x40, 0x60, 0x00, 0xf3,
        // 0x2c: JUMPDEST -> REVERT(0, 0)
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
    let precompile_payload =
        encode_precompile_call(EeId::WASM, &cw20_id, &cw_transfer, 0, 200_000);

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
        state.execution_state.read(NS_WASM_STORE, &rcpt_key).expect("read"),
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
            &[UelTx {
                tx_hash: [0x32; 32],
                sender,
                nonce: 2,
                ee: EeId::EVM,
                action: UelAction::Call {
                    target: router20,
                    input: router_cd,
                },
                value_attos: 0,
                gas_limit_bgu: 500_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
            }],
        )
        .expect("call router");
    assert_eq!(call_rec[0].status, UelReceiptStatus::Success);
    let expected_topic0 = universal_call_executed_topic0();
    let found = call_rec[0].logs.iter().any(|(ee, log)| {
        *ee == EeId::EVM
            && log.address == EVM_UNIVERSAL_PRECOMPILE
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
    assert!(derive_pointer_address(&id1, EeId::SVM).is_err());
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

    // Zero storage slots in `ee/evm/storage`: the pointer holds NO balance!
    assert_eq!(state.execution_state.namespace_bytes(NS_EVM_STORAGE), 0);

    // Home CW20 balances updated to 380 / 120!
    let mut k_alice = cw20_home.clone();
    k_alice.extend_from_slice(format!(":cw20:bal:{alice_wasm}").as_bytes());
    let mut k_bob = cw20_home;
    k_bob.extend_from_slice(format!(":cw20:bal:{bob_wasm}").as_bytes());
    assert_eq!(
        state.execution_state.read(NS_WASM_STORE, &k_alice).expect("r"),
        Some(b"380".to_vec())
    );
    assert_eq!(
        state.execution_state.read(NS_WASM_STORE, &k_bob).expect("r"),
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
        state.execution_state.read(NS_WASM_STORE, &alw_key).expect("r"),
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
