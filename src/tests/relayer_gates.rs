// (kullanıcı kararı Q-A 2026-07-16) L1 relayer proof
// Kriptografik doğrulama + M5 budlumxyz anti-sybil ücret + M4 BNS ücret regresyonu.
//
// Bu dosya, "boş kontrol yeterli" döneminin bittiğini kodlar:
// - RelayerResult artık bincode(MerkleProof) + result-fact leaf + root
//   Anchoring gerektirir (executor::TransactionType::RelayerResult kolu).
// - BudlumxyzRegisterApp artık BUDLUMXYZ_REGISTER_MIN_FEE zorunluluğu taşır.
// - BnsRegister ücret kontrolü (H1/executor) regresyon olarak mühürlenir.

use crate::core::account::AccountState;
use crate::core::address::Address;

use crate::core::transaction::{
    ExternalChain, RelayerExternalResult, Transaction, TransactionType,
};
use crate::cross_domain::event_tree::MerkleProof;
use crate::execution::executor::Executor;

const CHAIN_ID: u64 = 45262;

fn relayer_addr() -> Address {
    Address::from([0x0A; 32])
}

fn make_result(tx_hash: &str) -> RelayerExternalResult {
    RelayerExternalResult {
        chain: ExternalChain::Ethereum,
        tx_hash: tx_hash.to_string(),
        success: true,
        message: None,
        receipt_proof: Vec::new(),
        external_state_root: [0u8; 32],
    }
}

/// Tek-yaprak ağaç: leaf == root, boş siblings — executor kapısıyla aynı şema.
fn seal_single_leaf(res: &mut RelayerExternalResult) {
    let leaf = res.result_leaf();
    let proof = MerkleProof {
        leaf,
        index: 0,
        siblings: Vec::new(),
    };
    res.external_state_root = leaf;
    res.receipt_proof = bincode::serialize(&proof).expect("proof serialize");
}

fn relayer_tx(res: RelayerExternalResult, fee: u64) -> Transaction {
    Transaction::new_with_chain_id(
        relayer_addr(),
        Address::zero(),
        0,
        fee,
        0,
        Vec::new(),
        CHAIN_ID,
        TransactionType::RelayerResult(res),
    )
}

#[test]
fn test_relayer_result_valid_single_leaf_proof_accepted() {
    let mut state = AccountState::new();
    state.add_balance(&relayer_addr(), 1_000);
    let mut res = make_result("0xREAL_HASH");
    seal_single_leaf(&mut res);
    let tx = relayer_tx(res, 1);
    let root = match &tx.tx_type {
        TransactionType::RelayerResult(result) => result.external_state_root,
        _ => unreachable!(),
    };
    state
        .external_roots
        .insert(ExternalChain::Ethereum.domain_id(), root);
    Executor::apply_transaction(&mut state, &tx).expect("anchored proof must pass");
    assert_eq!(state.get_balance(&relayer_addr()), 999);
}

#[test]
fn test_relayer_result_tampered_facts_leaf_mismatch_rejected() {
    let mut state = AccountState::new();
    state.add_balance(&relayer_addr(), 1_000);
    let mut res = make_result("0xREAL_HASH");
    seal_single_leaf(&mut res);
    state
        .external_roots
        .insert(ExternalChain::Ethereum.domain_id(), res.external_state_root);
    // Proof başka olgular için üretildi — tx_hash'i sonradan değiştirirsek
    // Leaf uyuşmazlığı çıkmalı.
    res.tx_hash = "0xFORGED_HASH".to_string();
    let tx = relayer_tx(res, 1);
    let err = Executor::apply_transaction(&mut state, &tx).expect_err("must reject");
    assert!(err.contains("does not match the declared result facts"));
}

#[test]
fn test_relayer_result_wrong_root_rejected() {
    let mut state = AccountState::new();
    state.add_balance(&relayer_addr(), 1_000);
    let mut res = make_result("0xREAL_HASH");
    seal_single_leaf(&mut res);
    // The finalized anchor is the original root; changing the submitted root
    // Must fail before any bridge/economic transition.
    let anchored_root = res.external_state_root;
    state
        .external_roots
        .insert(ExternalChain::Ethereum.domain_id(), anchored_root);
    res.external_state_root = [0x42; 32];
    let tx = relayer_tx(res, 1);
    let err = Executor::apply_transaction(&mut state, &tx).expect_err("must reject");
    assert!(err.contains("no finalized light-client anchor"));
}

#[test]
fn test_relayer_result_malformed_proof_rejected() {
    let mut state = AccountState::new();
    state.add_balance(&relayer_addr(), 1_000);
    let mut res = make_result("0xREAL_HASH");
    res.receipt_proof = vec![1, 2, 3]; // bincode(MerkleProof) değil
    res.external_state_root = [0x11; 32];
    let tx = relayer_tx(res, 1);
    let err = Executor::apply_transaction(&mut state, &tx).expect_err("must reject");
    // Bincode hata metni sürüme göre değişir — reddedildiği ve bakiyenin
    // Dokunulmadığı doğrulanır.
    assert!(!err.is_empty(), "hata metni boş olmamalı");
    assert_eq!(state.get_balance(&relayer_addr()), 1_000);
}

#[test]
fn test_relayer_result_empty_proof_and_zero_root_regressions() {
    let mut state = AccountState::new();
    state.add_balance(&relayer_addr(), 1_000);
    // Boş proof (C4 öncesi tek kontroldü — regresyon kalmalı).
    let empty_proof = make_result("0xH");
    let tx = relayer_tx(empty_proof, 1);
    let err = Executor::apply_transaction(&mut state, &tx).expect_err("empty must reject");
    assert!(err.contains("Receipt proof cannot be empty"));
    // Sıfır root.
    let mut zero_root = make_result("0xH2");
    zero_root.receipt_proof = vec![9];
    let tx = relayer_tx(zero_root, 1);
    let err = Executor::apply_transaction(&mut state, &tx).expect_err("zero root must reject");
    assert!(err.contains("External state root cannot be zero"));
}

fn budlumxyz_tx(amount: u64, fee: u64) -> Transaction {
    Transaction::new_with_chain_id(
        relayer_addr(),
        Address::zero(),
        amount,
        fee,
        0,
        Vec::new(),
        CHAIN_ID,
        TransactionType::BudlumxyzRegisterApp {
            name: "my-dapp".to_string(),
            category: crate::budlumxyz::types::AppCategory::Other,
            website_url: "https://example.org".to_string(),
            manifest_id: None,
        },
    )
}

#[test]
fn test_hub_register_app_below_min_fee_rejected() {
    let mut state = AccountState::new();
    state.add_balance(&relayer_addr(), 10_000);
    let tx = budlumxyz_tx(crate::budlumxyz::BUDLUMXYZ_REGISTER_MIN_FEE - 1, 1);
    let err = Executor::apply_transaction(&mut state, &tx).expect_err("must reject");
    assert!(err.contains("App registration requires"));
    assert!(
        state.budlumxyz.apps.is_empty(),
        "reddedilen kayıt düşmemeli"
    );
}

#[test]
fn test_hub_register_app_exact_min_fee_deducted_and_registered() {
    let mut state = AccountState::new();
    state.add_balance(&relayer_addr(), 1_000);
    let tx = budlumxyz_tx(crate::budlumxyz::BUDLUMXYZ_REGISTER_MIN_FEE, 1);
    Executor::apply_transaction(&mut state, &tx).expect("min fee must pass");
    assert_eq!(state.budlumxyz.apps.len(), 1, "app kaydedilmeli");
    // H1 deseni: tam fee + tam registration cost, görevlası değil.
    let expected = 1_000 - 1 - crate::budlumxyz::BUDLUMXYZ_REGISTER_MIN_FEE;
    assert_eq!(state.get_balance(&relayer_addr()), expected);
}

#[test]
fn test_bns_register_fee_enforced_regression_m4() {
    // M4 kaydı executor H1 fix'iyle zaten kapalıydı — burada
    // Regresyon olarak mühürlenir: 4-harfli isim, duration 1 → cost > amount.
    let mut state = AccountState::new();
    state.add_balance(&relayer_addr(), 10_000);
    let name = "abcd".to_string();
    let cost = state.bns_registry.calculate_cost(&name, 1);
    assert!(cost > 0);
    let data = bincode::serialize(&(name.clone(), 1u64)).expect("ser");
    let tx = Transaction::new_with_chain_id(
        relayer_addr(),
        Address::zero(),
        cost - 1, // bir eksik ödeme
        1,
        0,
        data,
        CHAIN_ID,
        TransactionType::BnsRegister,
    );
    let err = Executor::apply_transaction(&mut state, &tx).expect_err("must reject");
    assert!(err.contains("Required:") && err.contains("provided:"));
    assert!(
        state
            .bns_registry
            .resolve(&name, state.epoch_index)
            .is_none(),
        "eksik ödemeli isim kaydedilmemeli"
    );
}
