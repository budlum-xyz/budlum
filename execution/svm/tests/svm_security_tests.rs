//! Security regression tests for `budlum-ee-svm`:
//! 1. `SystemProgram::Transfer` requires `accounts[0]` to be the authenticated
//!    writable signer and refuses zero-address recipients.
//! 2. `SystemProgram::CreateAccount` charges proportional per-byte storage CU
//!    and checks `call.gas_limit` BEFORE mutating host state (no OutOfGas leak).

use budlum_ee_svm::programs::{
    SvmAccountMeta, SvmInstructionEnvelope, ATTOS_PER_LAMPORT, SYSTEM_PROGRAM_ID,
};
use budlum_ee_svm::SvmWorker;
use budlum_uel_abi::mock::MemoryHost;
use budlum_uel_abi::{
    BlockContext, BudAmount, EeCall, EeCallKind, EeId, EeIdentity, ExecutionEnvironment, HostRead,
    OutcomeStatus,
};

fn ctx() -> BlockContext {
    BlockContext {
        chain_id: 45_261,
        height: 10,
        timestamp_ms: 1_700_000_000_000,
    }
}

fn system_transfer_data(lamports: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    data
}

fn create_account_data(lamports: u64, space: u64, owner: [u8; 32]) -> Vec<u8> {
    let mut data = Vec::with_capacity(52);
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    data.extend_from_slice(&space.to_le_bytes());
    data.extend_from_slice(&owner);
    data
}

#[test]
fn svm_system_transfer_enforces_signer_meta_non_zero_recipient_and_pre_mutation_gas_limit() {
    let mut worker = SvmWorker;
    let mut host = MemoryHost::new(2_000_000);
    let caller = [0xAAu8; 32];
    let recip = [0xBBu8; 32];
    let caller_id = EeIdentity {
        ee: EeId::SVM,
        id: caller.to_vec(),
    };
    let recip_id = EeIdentity {
        ee: EeId::SVM,
        id: recip.to_vec(),
    };
    host.balances
        .insert(caller_id.clone(), 1_000 * ATTOS_PER_LAMPORT);

    // 1. Source account meta is not the authenticated caller / not a signer -> MUST revert.
    let bad_from_ix = SvmInstructionEnvelope {
        accounts: vec![
            SvmAccountMeta {
                pubkey: [0xCCu8; 32],
                is_signer: false,
                is_writable: false,
            },
            SvmAccountMeta {
                pubkey: recip,
                is_signer: false,
                is_writable: true,
            },
        ],
        data: system_transfer_data(10),
    };
    let Ok(bad_in) = serde_json::to_vec(&bad_from_ix) else {
        panic!("ser");
    };
    let base_call = EeCall {
        kind: EeCallKind::Call,
        caller: caller_id.clone(),
        target: EeIdentity {
            ee: EeId::SVM,
            id: SYSTEM_PROGRAM_ID.to_vec(),
        },
        value: BudAmount(0),
        input: bad_in,
        gas_limit: 100_000,
        depth: 0,
        tx_hash: [0x11; 32],
    };
    let Ok(r1) = worker.execute(&ctx(), &base_call, &mut host) else {
        panic!("exec");
    };
    assert_eq!(
        r1.status,
        OutcomeStatus::Revert,
        "SystemProgram::Transfer with wrong/unsigned source meta must revert"
    );

    // 2. Zero recipient pubkey -> MUST revert.
    let zero_to_ix = SvmInstructionEnvelope {
        accounts: vec![
            SvmAccountMeta {
                pubkey: caller,
                is_signer: true,
                is_writable: true,
            },
            SvmAccountMeta {
                pubkey: [0u8; 32],
                is_signer: false,
                is_writable: true,
            },
        ],
        data: system_transfer_data(10),
    };
    let Ok(zero_in) = serde_json::to_vec(&zero_to_ix) else {
        panic!("ser");
    };
    let Ok(r2) = worker.execute(
        &ctx(),
        &EeCall {
            input: zero_in,
            tx_hash: [0x12; 32],
            ..base_call.clone()
        },
        &mut host,
    ) else {
        panic!("exec");
    };
    assert_eq!(
        r2.status,
        OutcomeStatus::Revert,
        "SystemProgram::Transfer to zero pubkey must revert"
    );

    // 3. Call gas_limit (50) < 150 CU required -> MUST return OutOfGas WITHOUT transferring balance!
    let honest_ix = SvmInstructionEnvelope {
        accounts: vec![
            SvmAccountMeta {
                pubkey: caller,
                is_signer: true,
                is_writable: true,
            },
            SvmAccountMeta {
                pubkey: recip,
                is_signer: false,
                is_writable: true,
            },
        ],
        data: system_transfer_data(10),
    };
    let Ok(honest_in) = serde_json::to_vec(&honest_ix) else {
        panic!("ser");
    };
    let Ok(r3) = worker.execute(
        &ctx(),
        &EeCall {
            input: honest_in.clone(),
            gas_limit: 50,
            tx_hash: [0x13; 32],
            ..base_call.clone()
        },
        &mut host,
    ) else {
        panic!("exec");
    };
    assert_eq!(
        r3.status,
        OutcomeStatus::OutOfGas,
        "Transfer exceeding call.gas_limit must return OutOfGas"
    );
    assert_eq!(
        host.bud_balance(&recip_id).ok().map(|b| b.0),
        Some(0),
        "OutOfGas Transfer must NOT have mutated recipient balance"
    );

    // 4. Honest transfer within gas_limit succeeds.
    let Ok(r4) = worker.execute(
        &ctx(),
        &EeCall {
            input: honest_in,
            gas_limit: 100_000,
            tx_hash: [0x14; 32],
            ..base_call
        },
        &mut host,
    ) else {
        panic!("exec");
    };
    assert_eq!(r4.status, OutcomeStatus::Success);
    assert_eq!(
        host.bud_balance(&recip_id).ok().map(|b| b.0),
        Some(10 * ATTOS_PER_LAMPORT)
    );
}

#[test]
fn svm_create_account_meters_storage_space_and_rejects_underfunded_gas_before_write() {
    let mut worker = SvmWorker;
    let mut host = MemoryHost::new(2_000_000);
    let caller = [0xDDu8; 32];
    let ix = SvmInstructionEnvelope {
        accounts: vec![
            SvmAccountMeta {
                pubkey: caller,
                is_signer: true,
                is_writable: true,
            },
            SvmAccountMeta {
                pubkey: caller,
                is_signer: true,
                is_writable: true,
            },
        ],
        data: create_account_data(0, 10_000, SYSTEM_PROGRAM_ID),
    };
    let Ok(input) = serde_json::to_vec(&ix) else {
        panic!("ser");
    };
    // 10_000 bytes * 25 = 250_000 CU; gas_limit 5_000 MUST hit OutOfGas before persisting account!
    let call = EeCall {
        kind: EeCallKind::Call,
        caller: EeIdentity {
            ee: EeId::SVM,
            id: caller.to_vec(),
        },
        target: EeIdentity {
            ee: EeId::SVM,
            id: SYSTEM_PROGRAM_ID.to_vec(),
        },
        value: BudAmount(0),
        input,
        gas_limit: 5_000,
        depth: 0,
        tx_hash: [0x15; 32],
    };
    let Ok(out) = worker.execute(&ctx(), &call, &mut host) else {
        panic!("exec");
    };
    assert_eq!(
        out.status,
        OutcomeStatus::OutOfGas,
        "10 KiB CreateAccount must charge per-byte storage CU and reject a 5_000 gas budget"
    );
}
