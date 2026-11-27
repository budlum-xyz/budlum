//! Security regression tests for `budlum-ee-utxo`:
//! 1. `unlock_ops` must be push-only (`SCRIPT_VERIFY_SIGPUSHONLY`).
//! 2. Script termination must leave a clean stack (`SCRIPT_VERIFY_CLEANSTACK`).
//! 3. Zero payout recipient (`[0u8; 32]`) is refused.
//! 4. `OpCheckMultiSigHash` charges per-pubkey ECDSA verification gas.

use budlum_ee_utxo::{
    encode_utxo_script, ScriptOp, UtxoLockScript, UtxoScriptWorker, UtxoSpendWitness,
    BUDLUM_TESTNET_CHAIN_ID,
};
use budlum_uel_abi::mock::MemoryHost;
use budlum_uel_abi::{
    BlockContext, BudAmount, EeCall, EeCallKind, EeId, EeIdentity, ExecutionEnvironment,
    OutcomeStatus,
};
use k256::ecdsa::SigningKey;

fn ctx() -> BlockContext {
    BlockContext {
        chain_id: BUDLUM_TESTNET_CHAIN_ID,
        height: 10,
        timestamp_ms: 1_700_000_000_000,
    }
}

fn deploy_script(
    worker: &mut UtxoScriptWorker,
    host: &mut MemoryHost,
    lock: UtxoLockScript,
) -> [u8; 32] {
    let Ok(code) = encode_utxo_script(&lock) else {
        panic!("encode UTXO script failed");
    };
    let deploy = EeCall {
        kind: EeCallKind::Deploy,
        caller: EeIdentity {
            ee: EeId::UTXO,
            id: vec![0xAA; 32],
        },
        target: EeIdentity {
            ee: EeId::UTXO,
            id: vec![0x00; 32],
        },
        value: BudAmount(0),
        input: code,
        gas_limit: 500_000,
        depth: 0,
        tx_hash: [0x11; 32],
    };
    let Ok(out) = worker.execute(&ctx(), &deploy, host) else {
        panic!("deploy UTXO script failed");
    };
    assert_eq!(out.status, OutcomeStatus::Success);
    let Ok(id) = <[u8; 32]>::try_from(out.output) else {
        panic!("expected 32-byte utxo id");
    };
    id
}

#[test]
fn utxo_rejects_non_push_unlock_ops_dirty_stack_and_zero_recipient() {
    let mut worker = UtxoScriptWorker::with_activation_height(Some(0));
    let mut host = MemoryHost::new(2_000_000);
    let utxo_id = deploy_script(
        &mut worker,
        &mut host,
        UtxoLockScript {
            witness_ops: vec![],
            lock_ops: vec![ScriptOp::PushNum(42), ScriptOp::OpEqual],
            value_atoms: 1_000,
        },
    );

    // 1. Non-push opcode inside unlock_ops (OpDup) must be refused (SIGPUSHONLY).
    let non_push_witness = UtxoSpendWitness {
        unlock_ops: vec![ScriptOp::PushNum(42), ScriptOp::OpDup, ScriptOp::OpDrop],
        recipient: [0x22; 32],
    };
    let call_non_push = EeCall {
        kind: EeCallKind::Call,
        caller: EeIdentity {
            ee: EeId::UTXO,
            id: vec![0xBB; 32],
        },
        target: EeIdentity {
            ee: EeId::UTXO,
            id: utxo_id.to_vec(),
        },
        value: BudAmount(0),
        input: serde_json::to_vec(&non_push_witness).unwrap(),
        gas_limit: 500_000,
        depth: 0,
        tx_hash: [0x22; 32],
    };
    let res1 = worker.execute(&ctx(), &call_non_push, &mut host).unwrap();
    assert_eq!(
        res1.status,
        OutcomeStatus::Revert,
        "non-push unlock_ops must revert"
    );

    // 2. Dirty stack (extra leftover element underneath the truthy top) must revert (CLEANSTACK).
    let dirty_stack_witness = UtxoSpendWitness {
        unlock_ops: vec![ScriptOp::PushNum(999), ScriptOp::PushNum(42)],
        recipient: [0x22; 32],
    };
    let call_dirty = EeCall {
        input: serde_json::to_vec(&dirty_stack_witness).unwrap(),
        tx_hash: [0x23; 32],
        ..call_non_push.clone()
    };
    let res2 = worker.execute(&ctx(), &call_dirty, &mut host).unwrap();
    assert_eq!(
        res2.status,
        OutcomeStatus::Revert,
        "non-clean stack must revert"
    );

    // 3. Zero payout recipient must revert.
    let zero_recip_witness = UtxoSpendWitness {
        unlock_ops: vec![ScriptOp::PushNum(42)],
        recipient: [0x00; 32],
    };
    let call_zero = EeCall {
        input: serde_json::to_vec(&zero_recip_witness).unwrap(),
        tx_hash: [0x24; 32],
        ..call_non_push.clone()
    };
    let res3 = worker.execute(&ctx(), &call_zero, &mut host).unwrap();
    assert_eq!(
        res3.status,
        OutcomeStatus::Revert,
        "zero recipient must revert"
    );

    // 4. Clean push-only spend to non-zero recipient succeeds.
    let honest_witness = UtxoSpendWitness {
        unlock_ops: vec![ScriptOp::PushNum(42)],
        recipient: [0x22; 32],
    };
    let call_ok = EeCall {
        input: serde_json::to_vec(&honest_witness).unwrap(),
        tx_hash: [0x25; 32],
        ..call_non_push
    };
    let res4 = worker.execute(&ctx(), &call_ok, &mut host).unwrap();
    assert_eq!(res4.status, OutcomeStatus::Success);
}

#[test]
fn multisig_charges_per_pubkey_ecdsa_gas() {
    let mut worker = UtxoScriptWorker::with_activation_height(Some(0));
    let mut host = MemoryHost::new(2_000_000);
    let pubkeys: Vec<Vec<u8>> = (1u8..=10)
        .map(|seed| {
            let sk = SigningKey::from_slice(&[seed; 32]).unwrap();
            sk.verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec()
        })
        .collect();
    let utxo_id = deploy_script(
        &mut worker,
        &mut host,
        UtxoLockScript {
            witness_ops: vec![],
            lock_ops: vec![ScriptOp::OpCheckMultiSigHash {
                threshold: 1,
                pubkeys,
            }],
            value_atoms: 1_000,
        },
    );

    // 10 pubkeys * 3_000 gas = 30_000 gas required; a tight 5_000 gas budget must hit OutOfGas.
    let witness = UtxoSpendWitness {
        unlock_ops: vec![ScriptOp::PushBytes(vec![0x11; 64])],
        recipient: [0x33; 32],
    };
    let call = EeCall {
        kind: EeCallKind::Call,
        caller: EeIdentity {
            ee: EeId::UTXO,
            id: vec![0xBB; 32],
        },
        target: EeIdentity {
            ee: EeId::UTXO,
            id: utxo_id.to_vec(),
        },
        value: BudAmount(0),
        input: serde_json::to_vec(&witness).unwrap(),
        gas_limit: 5_000,
        depth: 0,
        tx_hash: [0x26; 32],
    };
    let out = worker.execute(&ctx(), &call, &mut host).unwrap();
    assert_eq!(
        out.status,
        OutcomeStatus::OutOfGas,
        "10-key multisig must charge per-pubkey ECDSA gas and exhaust a 5_000 gas budget"
    );
}
