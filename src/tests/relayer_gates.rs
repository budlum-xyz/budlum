// Task 8.9 / Dalga 5 (kullanıcı kararı Q-A 2026-07-16): L1 relayer proof
// kriptografik doğrulama + M5 hub anti-sybil ücret + M4 BNS ücret regresyonu.
//
// Bu dosya, "boş kontrol yeterli" döneminin bittiğini kodlar:
// - RelayerResult artık bincode(MerkleProof) + result-fact leaf + root
//   anchoring gerektirir (executor::TransactionType::RelayerResult kolu).
// - HubRegisterApp artık HUB_REGISTER_MIN_FEE zorunluluğu taşır.
// - BnsRegister ücret kontrolü (H1/executor) regresyon olarak mühürlenir.

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::transaction::{
    ExternalChain, RelayerExternalResult, Transaction, TransactionType,
};
use crate::cross_domain::event_tree::MerkleProof;
use crate::execution::executor::Executor;

const CHAIN_ID: u64 = 1337;

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
    Executor::apply_transaction(&mut state, &tx).expect("valid proof must pass");
    assert_eq!(state.get_balance(&relayer_addr()), 999);
}

#[test]
fn test_relayer_result_tampered_facts_leaf_mismatch_rejected() {
    let mut state = AccountState::new();
    state.add_balance(&relayer_addr(), 1_000);
    let mut res = make_result("0xREAL_HASH");
    seal_single_leaf(&mut res);
    // Proof başka olgular için üretildi — tx_hash'i sonradan değiştirirsek
    // leaf uyuşmazlığı çıkmalı.
    res.tx_hash = "0xFORGED_HASH".to_string();
    let tx = relayer_tx(res, 1);
    let err = Executor::apply_transaction(&mut state, &tx).expect_err("must reject");
    assert!(
        err.contains("does not match the declared result facts"),
        "beklenen leaf_mismatch, gelen: {err}"
    );
}

#[test]
fn test_relayer_result_wrong_root_rejected() {
    let mut state = AccountState::new();
    state.add_balance(&relayer_addr(), 1_000);
    let mut res = make_result("0xREAL_HASH");
    seal_single_leaf(&mut res);
    // Root'u değiştir: kanıt artık bu köke bağlanamaz.
    res.external_state_root = [0x42; 32];
    let tx = relayer_tx(res, 1);
    let err = Executor::apply_transaction(&mut state, &tx).expect_err("must reject");
    assert!(
        err.contains("does not anchor to the declared external state root"),
        "beklenen proof_invalid, gelen: {err}"
    );
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
    // bincode hata metni sürüme göre değişir — reddedildiği ve bakiyenin
    // dokunulmadığı doğrulanır.
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
    assert!(
        err.contains("Receipt proof cannot be empty"),
        "gelen: {err}"
    );
    // Sıfır root.
    let mut zero_root = make_result("0xH2");
    zero_root.receipt_proof = vec![9];
    let tx = relayer_tx(zero_root, 1);
    let err = Executor::apply_transaction(&mut state, &tx).expect_err("zero root must reject");
    assert!(
        err.contains("External state root cannot be zero"),
        "gelen: {err}"
    );
}

fn hub_tx(amount: u64, fee: u64) -> Transaction {
    Transaction::new_with_chain_id(
        relayer_addr(),
        Address::zero(),
        amount,
        fee,
        0,
        Vec::new(),
        CHAIN_ID,
        TransactionType::HubRegisterApp {
            name: "my-dapp".to_string(),
            category: crate::hub::types::AppCategory::Other,
            website_url: "https://example.org".to_string(),
            manifest_id: None,
        },
    )
}

#[test]
fn test_hub_register_app_below_min_fee_rejected() {
    let mut state = AccountState::new();
    state.add_balance(&relayer_addr(), 10_000);
    let tx = hub_tx(crate::hub::HUB_REGISTER_MIN_FEE - 1, 1);
    let err = Executor::apply_transaction(&mut state, &tx).expect_err("must reject");
    assert!(
        err.contains("App registration requires"),
        "beklenen hub insufficient-fee mesajı, gelen: {err}"
    );
    assert!(state.hub.apps.is_empty(), "reddedilen kayıt düşmemeli");
}

#[test]
fn test_hub_register_app_exact_min_fee_deducted_and_registered() {
    let mut state = AccountState::new();
    state.add_balance(&relayer_addr(), 1_000);
    let tx = hub_tx(crate::hub::HUB_REGISTER_MIN_FEE, 1);
    Executor::apply_transaction(&mut state, &tx).expect("min fee must pass");
    assert_eq!(state.hub.apps.len(), 1, "app kaydedilmeli");
    // H1 deseni: tam fee + tam registration cost, görevlası değil.
    let expected = 1_000 - 1 - crate::hub::HUB_REGISTER_MIN_FEE;
    assert_eq!(state.get_balance(&relayer_addr()), expected);
}

#[test]
fn test_bns_register_fee_enforced_regression_m4() {
    // M4 kaydı (ARENA3 §8) executor H1 fix'iyle zaten kapalıydı — burada
    // regresyon olarak mühürlenir: 4-harfli isim, duration 1 → cost > amount.
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
    assert!(
        err.contains("Required:") && err.contains("provided:"),
        "beklenen bns insufficient-payment mesajı, gelen: {err}"
    );
    assert!(
        state
            .bns_registry
            .resolve(&name, state.epoch_index)
            .is_none(),
        "eksik ödemeli isim kaydedilmemeli"
    );
}
