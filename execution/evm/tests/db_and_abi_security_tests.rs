//! Security regression tests for `budlum-ee-evm::{db, abi}`:
//! 1. `HostDb::code_by_hash` refuses missing bytecode and bytecode whose
//!    `keccak256` disagrees with `code_hash` (never falls back to empty EOA).
//! 2. `abi::decode_precompile_call` refuses head-aliasing dynamic offsets
//!    (`rel < head_bytes`) and `target` lengths exceeding `MAX_IDENTITY_BYTES`.
//! 3. `abi::decode_uol_offer_bytes` enforces `UOL_TAKER_LEN` (`0` or `20`).
//! 4. `db::commit_evm_state` fails closed if `host_settled_debits` exceeds an
//!    account's original balance.

use budlum_ee_evm::abi::{
    decode_precompile_call, decode_uol_offer_bytes, encode_universal_call_input,
    encode_uol_offer_bytes, UolOfferRecord, SEL_UNIVERSAL_CALL,
};
use budlum_ee_evm::db::{commit_evm_state, HostDb, NS_EVM_CODE};
use budlum_uel_abi::mock::MemoryHost;
use budlum_uel_abi::{HostApi, Namespace};
use revm::database_interface::Database;
use revm::primitives::{keccak256, Address, B256, U256};
use revm::state::{Account, AccountInfo, AccountStatus, EvmState};
use std::collections::BTreeMap;

#[test]
fn host_db_code_by_hash_refuses_missing_and_tampered_bytecode() {
    let mut host = MemoryHost::new(1_000_000);
    let real_code = vec![0x60, 0x00, 0x60, 0x00, 0xf3];
    let expected_hash: B256 = keccak256(&real_code);

    // 1. Non-empty code_hash missing from ee/evm/code MUST error instead of returning empty EOA code.
    {
        let mut db = HostDb::new(&mut host, 45_261);
        assert!(
            db.code_by_hash(expected_hash).is_err(),
            "missing bytecode for non-empty code_hash must fail closed"
        );
    }

    // 2. Tampered bytes stored under expected_hash MUST fail integrity check.
    let Ok(ns_code) = Namespace::new(NS_EVM_CODE) else {
        panic!("ns");
    };
    let tampered = vec![0x00, 0xfe];
    assert!(host
        .write(&ns_code, expected_hash.as_slice(), Some(&tampered))
        .is_ok());
    {
        let mut db = HostDb::new(&mut host, 45_261);
        assert!(
            db.code_by_hash(expected_hash).is_err(),
            "bytecode whose keccak256 mismatches code_hash must fail closed"
        );
    }

    // 3. Honest bytecode matching expected_hash succeeds.
    assert!(host
        .write(&ns_code, expected_hash.as_slice(), Some(&real_code))
        .is_ok());
    {
        let mut db = HostDb::new(&mut host, 45_261);
        let loaded = db.code_by_hash(expected_hash).expect("honest code loads");
        assert_eq!(loaded.original_byte_slice(), real_code.as_slice());
    }
}

#[test]
fn abi_refuses_head_aliasing_offset_oversized_target_and_bad_offer_taker_len() {
    // 1. Head-aliasing offset (target offset = 0, pointing back inside the 5-word head).
    let mut aliased = Vec::new();
    aliased.extend_from_slice(&SEL_UNIVERSAL_CALL);
    // Word 0: target_ee = 1 (also read as length = 1 if rel=0!)
    let mut w0 = [0u8; 32];
    w0[31] = 1;
    aliased.extend_from_slice(&w0);
    // Word 1: target offset = 0 (points into head word 0!)
    aliased.extend_from_slice(&[0u8; 32]);
    // Word 2: input offset = 160
    let mut w2 = [0u8; 32];
    w2[31] = 160;
    aliased.extend_from_slice(&w2);
    // Word 3: value = 0
    aliased.extend_from_slice(&[0u8; 32]);
    // Word 4: gas = 1000
    let mut w4 = [0u8; 32];
    w4[30] = 0x03;
    w4[31] = 0xe8;
    aliased.extend_from_slice(&w4);
    // Tail at 160: input len = 0
    aliased.extend_from_slice(&[0u8; 32]);
    assert!(
        decode_precompile_call(&aliased).is_none(),
        "head-aliasing ABI offset (< 160) must be refused"
    );

    // 2. Target exceeding MAX_IDENTITY_BYTES (64) must be refused.
    let oversized_target = encode_universal_call_input(1, &[0xAB; 65], &[], 0, 10_000);
    assert!(
        decode_precompile_call(&oversized_target).is_none(),
        "target > 64 bytes must be refused"
    );

    // 3. Offer record with invalid taker length (e.g. 7 bytes, neither 0 nor 20) must be refused.
    let bad_offer = UolOfferRecord {
        maker: [1u8; 20],
        class_id: [2u8; 32],
        asset_id: [3u8; 32],
        taker: vec![0xAA; 7],
        payment: vec![0xBB; 4],
        amount: 100,
        expiry: 500,
    };
    let raw = encode_uol_offer_bytes(&bad_offer).expect("encodes");
    assert!(
        decode_uol_offer_bytes(&raw).is_none(),
        "taker length other than 0 or 20 must fail closed"
    );
}

#[test]
fn commit_evm_state_refuses_host_settled_debits_exceeding_original_balance() {
    let mut host = MemoryHost::new(1_000_000);
    let addr = Address::from([0x44u8; 20]);
    let mut state = EvmState::default();
    let mut acc = Account::from(AccountInfo {
        balance: U256::from(100u64),
        nonce: 1,
        ..AccountInfo::default()
    });
    acc.info.balance = U256::ZERO;
    acc.status = AccountStatus::Touched;
    state.insert(addr, acc);

    let mut settled = BTreeMap::new();
    settled.insert(addr, U256::from(500u64)); // > original balance 100!

    assert!(
        commit_evm_state(&mut host, &state, &[], &settled).is_err(),
        "host_settled_debits > original balance must fail closed instead of saturating to 0"
    );
}
