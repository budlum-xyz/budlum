use crate::execution::coordinator::conformance::{
    calibrate_bgu_schedule, run_budzero_conformance, run_evm_conformance, run_move_conformance,
    run_svm_conformance, run_wasm_conformance, CalibratedBguSchedule, TARGET_MAX_NS_PER_BGU_P95,
};
use budlum_uel_abi::EeId;

#[test]
fn uel_conformance_evm() {
    let r1 = run_evm_conformance().expect("evm conformance");
    let r2 = run_evm_conformance().expect("evm conformance repeat");
    assert_eq!(r1.ee, EeId::EVM);
    assert!(r1.passed_vectors >= 4);
    assert!(r1.documented_limit_refusals >= 1);
    assert_eq!(r1.final_execution_root, r2.final_execution_root);
}

#[test]
fn uel_conformance_wasm() {
    let r1 = run_wasm_conformance().expect("wasm conformance");
    let r2 = run_wasm_conformance().expect("wasm conformance repeat");
    assert_eq!(r1.ee, EeId::WASM);
    assert!(r1.passed_vectors >= 3);
    assert_eq!(r1.documented_limit_refusals, 2);
    assert_eq!(r1.final_execution_root, r2.final_execution_root);
}

#[test]
fn uel_conformance_svm() {
    let r1 = run_svm_conformance().expect("svm conformance");
    let r2 = run_svm_conformance().expect("svm conformance repeat");
    assert_eq!(r1.ee, EeId::SVM);
    assert!(r1.passed_vectors >= 3);
    assert_eq!(r1.documented_limit_refusals, 2);
    assert_eq!(r1.final_execution_root, r2.final_execution_root);
}

#[test]
fn uel_conformance_move() {
    let r1 = run_move_conformance().expect("move conformance");
    let r2 = run_move_conformance().expect("move conformance repeat");
    assert_eq!(r1.ee, EeId::MOVE);
    assert!(r1.passed_vectors >= 2);
    assert_eq!(r1.documented_limit_refusals, 2);
    assert_eq!(r1.final_execution_root, r2.final_execution_root);
}

#[test]
fn uel_conformance_budzero() {
    let r1 = run_budzero_conformance().expect("budzero conformance");
    let r2 = run_budzero_conformance().expect("budzero conformance repeat");
    assert_eq!(r1.ee, EeId::BUDZERO);
    assert!(r1.passed_vectors >= 2);
    assert_eq!(r1.final_execution_root, r2.final_execution_root);
}

#[test]
fn uel_gas_calibration_bound() {
    let (p95_ns, sched) = calibrate_bgu_schedule(25).expect("calibrate");
    // Effective ns per calibrated BGU (`p95_ns / sched.evm_gas_to_bgu`) never exceeds 16 ns!
    let effective_ns_per_bgu = p95_ns / sched.evm_gas_to_bgu.max(1);
    assert!(
        effective_ns_per_bgu <= TARGET_MAX_NS_PER_BGU_P95,
        "calibrated effective ns/BGU ({effective_ns_per_bgu}) exceeded 16 ns target"
    );
    assert_eq!(CalibratedBguSchedule::recalibrate_factor(1, 16), 1);
    assert_eq!(CalibratedBguSchedule::recalibrate_factor(1, 17), 2);
    assert_eq!(CalibratedBguSchedule::recalibrate_factor(100, 32), 200);
}

#[test]
fn redeploy_over_existing_contract_is_refused_across_all_ees() {
    use crate::execution::budzero_ee::BudZeroEe;
    use crate::execution::coordinator::evm_ee::EvmEe;
    use crate::execution::coordinator::expansion_ee::CairoEe;
    use crate::execution::coordinator::move_ee::{MoveEe, MOVE_BINARY_MAGIC};
    use crate::execution::coordinator::svm_ee::{SvmEe, ELF_MAGIC};
    use crate::execution::coordinator::wasm_ee::{build_valid_cosmwasm_module, WasmEe};
    use bud_isa::{Instruction, Opcode};
    use budlum_uel_abi::mock::MemoryHost;
    use budlum_uel_abi::{
        BlockContext, BudAmount, EeCall, EeCallKind, EeIdentity, ExecutionEnvironment,
        OutcomeStatus,
    };

    let ctx = BlockContext {
        height: 42,
        timestamp_ms: 1_700_000_000_000,
        chain_id: 45_261,
    };

    // 1. EVM top-level Deploy must refuse overwriting existing code.
    let mut host = MemoryHost::new(10_000_000);
    let mut evm = EvmEe::new();
    let evm_call = |code: Vec<u8>| EeCall {
        kind: EeCallKind::Deploy,
        caller: EeIdentity {
            ee: EeId::EVM,
            id: vec![0x11; 20],
        },
        target: EeIdentity {
            ee: EeId::EVM,
            id: vec![0x22; 20],
        },
        value: BudAmount(0),
        input: code,
        gas_limit: 500_000,
        depth: 0,
        tx_hash: [0x01; 32],
    };
    assert_eq!(
        evm.execute(&ctx, &evm_call(vec![0x00]), &mut host)
            .expect("first evm deploy")
            .status,
        OutcomeStatus::Success
    );
    let second_evm = evm
        .execute(&ctx, &evm_call(vec![0x5f, 0x00]), &mut host)
        .expect("second evm deploy");
    assert!(!matches!(second_evm.status, OutcomeStatus::Success));
    assert_eq!(
        second_evm.status,
        OutcomeStatus::Revert,
        "EvmEe must refuse overwriting an already-deployed contract"
    );

    // 2. WASM Deploy must refuse overwriting existing contract metadata/code.
    let mut wasm = WasmEe::new();
    let wasm_code_a = build_valid_cosmwasm_module(&["instantiate", "execute", "query"], &[0x01]);
    let wasm_code_b = build_valid_cosmwasm_module(&["instantiate", "execute", "query"], &[0x02]);
    let wasm_call = |code: Vec<u8>| EeCall {
        kind: EeCallKind::Deploy,
        caller: EeIdentity {
            ee: EeId::WASM,
            id: b"bud1creator".to_vec(),
        },
        target: EeIdentity {
            ee: EeId::WASM,
            id: b"bud1targetcontract".to_vec(),
        },
        value: BudAmount(0),
        input: code,
        gas_limit: 500_000,
        depth: 0,
        tx_hash: [0x02; 32],
    };
    assert_eq!(
        wasm.execute(&ctx, &wasm_call(wasm_code_a), &mut host)
            .expect("first wasm deploy")
            .status,
        OutcomeStatus::Success
    );
    assert_eq!(
        wasm.execute(&ctx, &wasm_call(wasm_code_b), &mut host)
            .expect("second wasm deploy")
            .status,
        OutcomeStatus::Revert,
        "WasmEe must refuse overwriting an already-deployed contract"
    );

    // 3. SVM Deploy must refuse overwriting an existing account/program.
    let mut svm = SvmEe::new();
    let mut elf_a = ELF_MAGIC.to_vec();
    elf_a.extend_from_slice(&[1, 2, 3, 4]);
    let mut elf_b = ELF_MAGIC.to_vec();
    elf_b.extend_from_slice(&[5, 6, 7, 8]);
    let svm_call = |code: Vec<u8>| EeCall {
        kind: EeCallKind::Deploy,
        caller: EeIdentity {
            ee: EeId::SVM,
            id: vec![0x31; 32],
        },
        target: EeIdentity {
            ee: EeId::SVM,
            id: vec![0x32; 32],
        },
        value: BudAmount(0),
        input: code,
        gas_limit: 500_000,
        depth: 0,
        tx_hash: [0x03; 32],
    };
    assert_eq!(
        svm.execute(&ctx, &svm_call(elf_a), &mut host)
            .expect("first svm deploy")
            .status,
        OutcomeStatus::Success
    );
    assert_eq!(
        svm.execute(&ctx, &svm_call(elf_b), &mut host)
            .expect("second svm deploy")
            .status,
        OutcomeStatus::Revert,
        "SvmEe must refuse overwriting an existing account/program"
    );

    // 4. Move Deploy must refuse overwriting an existing module/resource account.
    let mut mv = MoveEe::new();
    let mut mv_a = MOVE_BINARY_MAGIC.to_vec();
    mv_a.extend_from_slice(&[0xAA, 0xBB]);
    let mut mv_b = MOVE_BINARY_MAGIC.to_vec();
    mv_b.extend_from_slice(&[0xCC, 0xDD]);
    let mv_call = |code: Vec<u8>| EeCall {
        kind: EeCallKind::Deploy,
        caller: EeIdentity {
            ee: EeId::MOVE,
            id: vec![0x41; 32],
        },
        target: EeIdentity {
            ee: EeId::MOVE,
            id: vec![0x42; 32],
        },
        value: BudAmount(0),
        input: code,
        gas_limit: 500_000,
        depth: 0,
        tx_hash: [0x04; 32],
    };
    assert_eq!(
        mv.execute(&ctx, &mv_call(mv_a), &mut host)
            .expect("first move deploy")
            .status,
        OutcomeStatus::Success
    );
    assert_eq!(
        mv.execute(&ctx, &mv_call(mv_b), &mut host)
            .expect("second move deploy")
            .status,
        OutcomeStatus::Revert,
        "MoveEe must refuse overwriting an already-deployed module"
    );

    // 5. Expansion EE Deploy must refuse overwriting an existing code key.
    let dev_ctx = BlockContext {
        height: 42,
        timestamp_ms: 1_700_000_000_000,
        chain_id: crate::core::chain_config::Network::Devnet
            .chain_id()
            .value(),
    };
    let mut cairo = CairoEe;
    let cairo_call = |code: Vec<u8>| EeCall {
        kind: EeCallKind::Deploy,
        caller: EeIdentity {
            ee: EeId::CAIRO,
            id: vec![0x51; 32],
        },
        target: EeIdentity {
            ee: EeId::CAIRO,
            id: vec![0x52; 32],
        },
        value: BudAmount(0),
        input: code,
        gas_limit: 500_000,
        depth: 0,
        tx_hash: [0x05; 32],
    };
    assert_eq!(
        cairo
            .execute(&dev_ctx, &cairo_call(vec![0xCA, 0xFE]), &mut host)
            .expect("first cairo deploy")
            .status,
        OutcomeStatus::Success
    );
    assert_eq!(
        cairo
            .execute(&dev_ctx, &cairo_call(vec![0xBE, 0xEF]), &mut host)
            .expect("second cairo deploy")
            .status,
        OutcomeStatus::Revert,
        "ExpansionEe must refuse overwriting an existing contract"
    );

    // 6. BudZeroEe Deploy must refuse overwriting an existing program.
    let mut bz = BudZeroEe::new();
    let halt_bytes = Instruction {
        opcode: Opcode::Halt,
        rd: 0,
        rs1: 0,
        rs2: 0,
        imm: 0,
    }
    .encode()
    .to_le_bytes()
    .to_vec();
    let bz_call = || EeCall {
        kind: EeCallKind::Deploy,
        caller: EeIdentity {
            ee: EeId::BUDZERO,
            id: vec![0x61; 32],
        },
        target: EeIdentity {
            ee: EeId::BUDZERO,
            id: vec![0x62; 32],
        },
        value: BudAmount(0),
        input: halt_bytes.clone(),
        gas_limit: 500_000,
        depth: 0,
        tx_hash: [0x06; 32],
    };
    assert_eq!(
        bz.execute(&ctx, &bz_call(), &mut host)
            .expect("first budzero deploy")
            .status,
        OutcomeStatus::Success
    );
    assert_eq!(
        bz.execute(&ctx, &bz_call(), &mut host)
            .expect("second budzero deploy")
            .status,
        OutcomeStatus::Revert,
        "BudZeroEe must refuse overwriting an already-deployed program"
    );
}

#[test]
fn forged_or_misplaced_pointer_bytecode_is_refused() {
    use crate::execution::coordinator::assets::{
        encode_pointer_bytecode, AssetStandard, PointerDescriptor, POINTER_BYTECODE_PREFIX,
    };
    use crate::execution::coordinator::evm_ee::{solidity_selector, EvmEe};
    use crate::execution::coordinator::state::derive_uel_asset_id;
    use crate::execution::coordinator::state::NS_EVM_CODE;
    use crate::execution::coordinator::wasm_ee::{validate_cosmwasm_bytecode, WasmEe};
    use budlum_uel_abi::mock::MemoryHost;
    use budlum_uel_abi::{
        BlockContext, BudAmount, EeCall, EeCallKind, EeIdentity, ExecutionEnvironment, HostApi,
        Namespace, OutcomeStatus,
    };
    use sha3::{Digest, Keccak256};

    let home_ref = b"bud1hometoken".to_vec();
    let forged_desc = PointerDescriptor {
        asset_id: derive_uel_asset_id(EeId::WASM, &home_ref),
        home_ee: EeId::WASM.0,
        home_ref,
        standard: AssetStandard::Fungible,
        decimals: 6,
        symbol: "FAKE".into(),
        name: "Forged Pointer".into(),
    };
    let forged_code = encode_pointer_bytecode(&forged_desc).expect("encode pointer");

    // 1. User WASM validation & deploy must reject POINTER_BYTECODE_PREFIX.
    assert!(
        validate_cosmwasm_bytecode(&forged_code).is_err(),
        "user WASM deploy validation must reject system pointer prefix"
    );
    let wasm = WasmEe::new();
    assert!(
        wasm.validate_deploy(&forged_code).is_err(),
        "WasmEe::validate_deploy must reject system pointer prefix"
    );

    // 2. User EVM deploy validation & runtime deploy must reject POINTER_BYTECODE_PREFIX.
    let mut evm = EvmEe::new();
    assert!(
        evm.validate_deploy(&forged_code).is_err(),
        "EvmEe::validate_deploy must reject system pointer prefix"
    );

    let ctx = BlockContext {
        height: 50,
        timestamp_ms: 1_700_000_000_000,
        chain_id: 45_261,
    };
    let mut host = MemoryHost::new(5_000_000);
    let evm_deploy = evm
        .execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Deploy,
                caller: EeIdentity {
                    ee: EeId::EVM,
                    id: vec![0x01; 20],
                },
                target: EeIdentity {
                    ee: EeId::EVM,
                    id: vec![0x99; 20],
                },
                value: BudAmount(0),
                input: forged_code.clone(),
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x10; 32],
            },
            &mut host,
        )
        .expect("evm deploy");
    assert_ne!(
        evm_deploy.status,
        OutcomeStatus::Success,
        "EvmEe::execute(Deploy) must reject system pointer prefix"
    );

    // 3. Even if pointer bytecode is manually injected at a non-canonical EVM address,
    //    calling it must fail closed with Revert rather than spoofing the pointer.
    let rogue_addr = [0x77u8; 20];
    let ch: [u8; 32] = Keccak256::digest(&forged_code).into();
    host.write(
        &Namespace::new(NS_EVM_CODE).expect("ns"),
        &ch,
        Some(&forged_code),
    )
    .expect("write rogue code");
    host.write(
        &Namespace::new("ee/evm/account").expect("ns"),
        &rogue_addr,
        Some(
            &serde_json::to_vec(&serde_json::json!({"nonce": 1, "code_hash": hex::encode(ch)}))
                .expect("json"),
        ),
    )
    .expect("write rogue account");
    let mut supply_calldata = solidity_selector("totalSupply()").to_vec();
    supply_calldata.resize(4, 0);
    let rogue_call = evm
        .execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Call,
                caller: EeIdentity {
                    ee: EeId::EVM,
                    id: vec![0x01; 20],
                },
                target: EeIdentity {
                    ee: EeId::EVM,
                    id: rogue_addr.to_vec(),
                },
                value: BudAmount(0),
                input: supply_calldata,
                gas_limit: 200_000,
                depth: 0,
                tx_hash: [0x11; 32],
            },
            &mut host,
        )
        .expect("rogue call");
    assert_eq!(
        rogue_call.status,
        OutcomeStatus::Revert,
        "calling pointer bytecode at a non-canonical address must revert"
    );

    // 4. Corrupt POINTER_BYTECODE_PREFIX must revert rather than executing prefix bytes as EVM opcodes.
    let mut corrupt_code = POINTER_BYTECODE_PREFIX.to_vec();
    corrupt_code.extend_from_slice(b"{not-valid-json");
    let corrupt_addr = [0x78u8; 20];
    let ch_bad: [u8; 32] = Keccak256::digest(&corrupt_code).into();
    host.write(
        &Namespace::new(NS_EVM_CODE).expect("ns"),
        &ch_bad,
        Some(&corrupt_code),
    )
    .expect("write corrupt code");
    host.write(
        &Namespace::new("ee/evm/account").expect("ns"),
        &corrupt_addr,
        Some(
            &serde_json::to_vec(&serde_json::json!({"nonce": 1, "code_hash": hex::encode(ch_bad)}))
                .expect("json"),
        ),
    )
    .expect("write corrupt account");
    let corrupt_call = evm
        .execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Call,
                caller: EeIdentity {
                    ee: EeId::EVM,
                    id: vec![0x01; 20],
                },
                target: EeIdentity {
                    ee: EeId::EVM,
                    id: corrupt_addr.to_vec(),
                },
                value: BudAmount(0),
                input: Vec::new(),
                gas_limit: 200_000,
                depth: 0,
                tx_hash: [0x12; 32],
            },
            &mut host,
        )
        .expect("corrupt call");
    assert_eq!(
        corrupt_call.status,
        OutcomeStatus::Revert,
        "corrupt system pointer prefix must revert fail-closed"
    );
}

#[test]
fn move_randomness_binds_tx_hash_and_malformed_amounts_revert() {
    use crate::execution::coordinator::move_ee::{MoveCallEnvelope, MoveEe};
    use budlum_uel_abi::mock::MemoryHost;
    use budlum_uel_abi::{
        BlockContext, BudAmount, EeCall, EeCallKind, EeIdentity, ExecutionEnvironment,
        OutcomeStatus,
    };

    let ctx = BlockContext {
        height: 100,
        timestamp_ms: 1_700_000_000_000,
        chain_id: 45_261,
    };
    let mut host = MemoryHost::new(5_000_000);
    let mut mv = MoveEe::new();
    let signer = EeIdentity {
        ee: EeId::MOVE,
        id: vec![0xAA; 32],
    };
    let rand_payload = serde_json::to_vec(&MoveCallEnvelope::EntryFunction {
        module_id: String::from("0x1::randomness"),
        function_name: String::from("u256_integer"),
        args: Vec::new(),
    })
    .expect("json");

    let r1 = mv
        .execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Call,
                caller: signer.clone(),
                target: signer.clone(),
                value: BudAmount(0),
                input: rand_payload.clone(),
                gas_limit: 200_000,
                depth: 0,
                tx_hash: [0x01; 32],
            },
            &mut host,
        )
        .expect("rand 1");
    let r2 = mv
        .execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Call,
                caller: signer.clone(),
                target: signer.clone(),
                value: BudAmount(0),
                input: rand_payload,
                gas_limit: 200_000,
                depth: 0,
                tx_hash: [0x02; 32],
            },
            &mut host,
        )
        .expect("rand 2");
    assert_eq!(r1.status, OutcomeStatus::Success);
    assert_eq!(r2.status, OutcomeStatus::Success);
    assert_ne!(
        r1.output, r2.output,
        "distinct transactions in the same block must not receive identical Move randomness"
    );

    // Malformed / overflowing mint and transfer amounts must revert instead of silently coercing to 0.
    for bad_amount in [
        "-1",
        "not_a_number",
        "99999999999999999999999999999999999999999",
    ] {
        let bad_mint = serde_json::to_vec(&MoveCallEnvelope::EntryFunction {
            module_id: String::from("0x1::fungible_asset"),
            function_name: String::from("mint"),
            args: vec![hex::encode([0xBB; 32]), bad_amount.to_string()],
        })
        .expect("json");
        let mint_out = mv
            .execute(
                &ctx,
                &EeCall {
                    kind: EeCallKind::Call,
                    caller: signer.clone(),
                    target: signer.clone(),
                    value: BudAmount(0),
                    input: bad_mint,
                    gas_limit: 200_000,
                    depth: 0,
                    tx_hash: [0x03; 32],
                },
                &mut host,
            )
            .expect("bad mint");
        assert_eq!(
            mint_out.status,
            OutcomeStatus::Revert,
            "Move mint must revert on malformed/overflowing amount `{bad_amount}`"
        );

        let bad_transfer = serde_json::to_vec(&MoveCallEnvelope::EntryFunction {
            module_id: String::from("0x1::aptos_account"),
            function_name: String::from("transfer"),
            args: vec![hex::encode([0xBB; 32]), bad_amount.to_string()],
        })
        .expect("json");
        let transfer_out = mv
            .execute(
                &ctx,
                &EeCall {
                    kind: EeCallKind::Call,
                    caller: signer.clone(),
                    target: signer.clone(),
                    value: BudAmount(0),
                    input: bad_transfer,
                    gas_limit: 200_000,
                    depth: 0,
                    tx_hash: [0x04; 32],
                },
                &mut host,
            )
            .expect("bad transfer");
        assert_eq!(
            transfer_out.status,
            OutcomeStatus::Revert,
            "Move transfer must revert on malformed/overflowing amount `{bad_amount}`"
        );
    }
}
