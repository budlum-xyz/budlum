//! Security regression tests for `budlum-ee-plutus`:
//! 1. `decode_plutus_blob` refuses ASTs exceeding `MAX_UPLC_DEPTH` and empty versions at deploy time.
//! 2. `Call` input size is bounded (prevents multi-megabyte redeemer abuse).
//! 3. `UplcTerm::Sha256` charges proportional per-block hashing gas.

use budlum_ee_plutus::{
    decode_plutus_blob, encode_plutus_blob, PlutusSpendInput, PlutusValidatorProgram, PlutusWorker,
    UplcTerm, BUDLUM_TESTNET_CHAIN_ID,
};
use budlum_uel_abi::mock::MemoryHost;
use budlum_uel_abi::{
    BlockContext, BudAmount, EeCall, EeCallKind, EeId, EeIdentity, ExecutionEnvironment,
    OutcomeStatus,
};

fn ctx() -> BlockContext {
    BlockContext {
        chain_id: BUDLUM_TESTNET_CHAIN_ID,
        height: 10,
        timestamp_ms: 1_700_000_000_000,
    }
}

#[test]
fn decode_plutus_blob_refuses_excessive_ast_depth_and_empty_version() {
    let mut deep = UplcTerm::ConstInt(1);
    for _ in 0..70 {
        deep = UplcTerm::TraceUnit(Box::new(deep));
    }
    let blob = encode_plutus_blob(&PlutusValidatorProgram {
        uplc_version: "1.1.0".into(),
        initial_datum_int: 0,
        validator: deep,
    })
    .expect("encodes");
    assert!(
        decode_plutus_blob(&blob).is_err(),
        "AST deeper than MAX_UPLC_DEPTH (64) must fail at decode/deploy"
    );

    let empty_ver = encode_plutus_blob(&PlutusValidatorProgram {
        uplc_version: String::new(),
        initial_datum_int: 0,
        validator: UplcTerm::ConstInt(1),
    })
    .expect("encodes");
    assert!(
        decode_plutus_blob(&empty_ver).is_err(),
        "empty uplc_version must fail closed"
    );
}

#[test]
fn plutus_sha256_charges_per_block_gas_and_bounds_call_input() {
    let mut worker = PlutusWorker::with_activation_height(Some(0));
    let mut host = MemoryHost::new(2_000_000);
    let prog = PlutusValidatorProgram {
        uplc_version: "1.1.0".into(),
        initial_datum_int: 0,
        validator: UplcTerm::TraceUnit(Box::new(UplcTerm::Sha256(Box::new(
            UplcTerm::RedeemerBytes,
        )))),
    };
    let blob = encode_plutus_blob(&prog).unwrap();
    let deploy = EeCall {
        kind: EeCallKind::Deploy,
        caller: EeIdentity {
            ee: EeId::PLUTUS,
            id: vec![0xAA; 32],
        },
        target: EeIdentity {
            ee: EeId::PLUTUS,
            id: vec![0x00; 32],
        },
        value: BudAmount(0),
        input: blob,
        gas_limit: 500_000,
        depth: 0,
        tx_hash: [0x11; 32],
    };
    let dep = worker.execute(&ctx(), &deploy, &mut host).unwrap();
    assert_eq!(dep.status, OutcomeStatus::Success);
    let script_hash = dep.output;

    // 1. Oversized PlutusSpendInput (> 64 KiB JSON) must revert.
    let huge = PlutusSpendInput {
        new_datum_int: None,
        redeemer_int: 0,
        redeemer_bytes: vec![0xAB; 40_000], // JSON array > 120 KiB
    };
    let call_huge = EeCall {
        kind: EeCallKind::Call,
        caller: EeIdentity {
            ee: EeId::PLUTUS,
            id: vec![0xBB; 32],
        },
        target: EeIdentity {
            ee: EeId::PLUTUS,
            id: script_hash.clone(),
        },
        value: BudAmount(0),
        input: serde_json::to_vec(&huge).unwrap(),
        gas_limit: 500_000,
        depth: 0,
        tx_hash: [0x12; 32],
    };
    let res_huge = worker.execute(&ctx(), &call_huge, &mut host).unwrap();
    assert_eq!(
        res_huge.status,
        OutcomeStatus::Revert,
        "oversized PlutusSpendInput must revert"
    );

    // 2. 16 KiB redeemer hashed via Sha256 requires proportional gas (256 blocks * 12 = 3_072 + base > 3_500);
    // a 2_500 gas budget must hit OutOfGas.
    let medium = PlutusSpendInput {
        new_datum_int: None,
        redeemer_int: 0,
        redeemer_bytes: vec![0x01; 16_384],
    };
    let call_tight = EeCall {
        input: serde_json::to_vec(&medium).unwrap(),
        gas_limit: 2_500,
        tx_hash: [0x13; 32],
        ..call_huge
    };
    let res_tight = worker.execute(&ctx(), &call_tight, &mut host).unwrap();
    assert_eq!(
        res_tight.status,
        OutcomeStatus::OutOfGas,
        "16 KiB Sha256 must charge per-block hashing gas and exhaust a 2_500 gas budget"
    );
}
