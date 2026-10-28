// (Q-A 2026-07-16) chain relayer proof
// Cryptographic verification, the M5 budlumxyz anti-sybil fee and the M4 BNS fee
// regression.
//
// This file encodes the end of the era in which "an emptiness check is enough":
// - RelayerResult now carries bincode(MerkleProof) plus a result-fact leaf and a root
//   anchoring (the executor::TransactionType::RelayerResult arm).
// - BudlumxyzRegisterApp now carries the BUDLUMXYZ_REGISTER_MIN_FEE requirement.
// - The BnsRegister fee check (H1, executor) is sealed as a regression.

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
        // The generic result-fact gate is intentionally tested with a
        // non-Ethereum custom chain. Ethereum must use the full
        // DepositProofPackage path and is refused below until that path is
        // wired into consensus.
        chain: ExternalChain::Custom(0xC0DE),
        tx_hash: tx_hash.to_string(),
        success: true,
        message: None,
        receipt_proof: Vec::new(),
        external_state_root: [0u8; 32],
    }
}

/// Build a two-leaf Merkle path for the result fact. A root equal to the leaf
/// with no siblings is not evidence of a tree and is refused by the executor.
fn seal_result_proof(res: &mut RelayerExternalResult) {
    let leaf = res.result_leaf();
    let sibling = [0x5au8; 32];
    let root = crate::core::hash::hash_fields_bytes(&[b"BDLM_MERKLE_NODE_V1", &leaf, &sibling]);
    let proof = MerkleProof {
        leaf,
        index: 0,
        siblings: vec![sibling],
    };
    res.external_state_root = root;
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
fn test_relayer_result_valid_merkle_proof_accepted() {
    let mut state = AccountState::new();
    state.add_balance(&relayer_addr(), 1_000);
    let mut res = make_result("0xREAL_HASH");
    seal_result_proof(&mut res);
    let tx = relayer_tx(res, 1);
    let root = match &tx.tx_type {
        TransactionType::RelayerResult(result) => result.external_state_root,
        _ => unreachable!(),
    };
    state
        .external_roots
        .insert(ExternalChain::Custom(0xC0DE).domain_id(), root);
    Executor::apply_transaction(&mut state, &tx).expect("anchored proof must pass");
    assert_eq!(state.get_balance(&relayer_addr()), 999);
}

#[test]
fn ethereum_generic_result_is_refused_until_full_proof_package_is_wired() {
    let mut state = AccountState::new();
    state.add_balance(&relayer_addr(), 1_000);
    let mut result = RelayerExternalResult {
        chain: ExternalChain::Ethereum,
        tx_hash: "0xREAL_HASH".to_string(),
        success: true,
        message: None,
        receipt_proof: Vec::new(),
        external_state_root: [0u8; 32],
    };
    seal_result_proof(&mut result);
    state.external_roots.insert(
        ExternalChain::Ethereum.domain_id(),
        result.external_state_root,
    );
    let tx = relayer_tx(result, 1);
    let err = Executor::apply_transaction_checked(&mut state, &tx)
        .expect_err("Ethereum must not use the weaker generic result-fact proof");
    assert_eq!(err.code(), "relayer_evm_package_required");
    assert_eq!(state.get_balance(&relayer_addr()), 1_000);
}

#[test]
fn test_relayer_result_empty_sibling_path_is_rejected() {
    let mut state = AccountState::new();
    state.add_balance(&relayer_addr(), 1_000);
    let mut result = make_result("0xNO_PATH");
    let proof = MerkleProof {
        leaf: result.result_leaf(),
        index: 0,
        siblings: Vec::new(),
    };
    result.external_state_root = proof.leaf;
    result.receipt_proof = bincode::serialize(&proof).expect("proof serialize");
    state.external_roots.insert(
        ExternalChain::Custom(0xC0DE).domain_id(),
        result.external_state_root,
    );
    let tx = relayer_tx(result, 1);
    let err = Executor::apply_transaction_checked(&mut state, &tx)
        .expect_err("a self-repeating leaf is not a receipt path");
    assert_eq!(err.code(), "relayer_proof_path");
    assert_eq!(state.get_balance(&relayer_addr()), 1_000);
}

#[test]
fn test_relayer_result_tampered_facts_leaf_mismatch_rejected() {
    let mut state = AccountState::new();
    state.add_balance(&relayer_addr(), 1_000);
    let mut res = make_result("0xREAL_HASH");
    seal_result_proof(&mut res);
    state.external_roots.insert(
        ExternalChain::Custom(0xC0DE).domain_id(),
        res.external_state_root,
    );
    // The proof was produced for other facts, so changing tx_hash afterwards has
    // to produce a leaf mismatch.
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
    seal_result_proof(&mut res);
    // The finalized anchor is the original root; changing the submitted root
    // Must fail before any bridge/economic transition.
    let anchored_root = res.external_state_root;
    state
        .external_roots
        .insert(ExternalChain::Custom(0xC0DE).domain_id(), anchored_root);
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
    res.receipt_proof = vec![1, 2, 3]; // not a bincode(MerkleProof)
    res.external_state_root = [0x11; 32];
    // The root is anchored, so the refusal comes from the proof decode.
    state
        .external_roots
        .insert(ExternalChain::Custom(0xC0DE).domain_id(), [0x11; 32]);
    let tx = relayer_tx(res, 1);
    let err = Executor::apply_transaction_checked(&mut state, &tx).expect_err("must reject");
    assert_eq!(err.code(), "relayer_proof_malformed");
    assert_eq!(state.get_balance(&relayer_addr()), 1_000);
}

#[test]
fn test_relayer_result_empty_tx_hash_is_rejected() {
    let mut state = AccountState::new();
    state.add_balance(&relayer_addr(), 1_000);
    let mut result = make_result("");
    seal_result_proof(&mut result);
    state.external_roots.insert(
        ExternalChain::Custom(0xC0DE).domain_id(),
        result.external_state_root,
    );
    let tx = relayer_tx(result, 1);
    let err = Executor::apply_transaction(&mut state, &tx).expect_err("empty hash must reject");
    assert!(err.contains("Transaction hash cannot be empty"));
    assert_eq!(state.get_balance(&relayer_addr()), 1_000);
}

#[test]
fn test_relayer_result_oversized_proof_is_rejected_before_decode() {
    let mut state = AccountState::new();
    state.add_balance(&relayer_addr(), 1_000);
    let mut result = make_result("0xOVERSIZED");
    result.receipt_proof = vec![0u8; 4 * 1024 + 1];
    result.external_state_root = [0x11; 32];
    let tx = relayer_tx(result, 1);
    let err = Executor::apply_transaction_checked(&mut state, &tx)
        .expect_err("oversized proof must reject");
    assert_eq!(err.code(), "relayer_proof_malformed");
    assert_eq!(state.get_balance(&relayer_addr()), 1_000);
}

#[test]
fn test_relayer_result_empty_proof_and_zero_root_regressions() {
    let mut state = AccountState::new();
    state.add_balance(&relayer_addr(), 1_000);
    // An empty proof: before C4 this was the only check, and it stays as a regression.
    let empty_proof = make_result("0xH");
    let tx = relayer_tx(empty_proof, 1);
    let err = Executor::apply_transaction(&mut state, &tx).expect_err("empty must reject");
    assert!(err.contains("Receipt proof cannot be empty"));
    // A zero root.
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
        "a refused record must not be deducted"
    );
}

#[test]
fn test_hub_register_app_exact_min_fee_deducted_and_registered() {
    let mut state = AccountState::new();
    state.add_balance(&relayer_addr(), 1_000);
    let tx = budlumxyz_tx(crate::budlumxyz::BUDLUMXYZ_REGISTER_MIN_FEE, 1);
    Executor::apply_transaction(&mut state, &tx).expect("min fee must pass");
    assert_eq!(
        state.budlumxyz.apps.len(),
        1,
        "the app has to be registered"
    );
    // The H1 pattern: the exact fee plus the exact registration cost, not an approximation.
    let expected = 1_000 - 1 - crate::budlumxyz::BUDLUMXYZ_REGISTER_MIN_FEE;
    assert_eq!(state.get_balance(&relayer_addr()), expected);
}

#[test]
fn test_bns_register_fee_enforced_regression_m4() {
    // The M4 record was already closed by the executor H1 fix; it is sealed here
    // as a regression: a four-letter name with duration 1 gives cost > amount.
    let mut state = AccountState::new();
    state.add_balance(&relayer_addr(), 10_000);
    let name = "abcd".to_string();
    let cost = state.bns_registry.calculate_cost(&name, 1);
    assert!(cost > 0);
    let data = bincode::serialize(&(name.clone(), 1u64)).expect("ser");
    let tx = Transaction::new_with_chain_id(
        relayer_addr(),
        Address::zero(),
        cost - 1, // one short of the payment
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
        "a name with an underpayment must not be registered"
    );
}

/// The bridge mint inside a `RelayerResult` asks the supply ceiling.
///
/// A transfer row opened by a local lock cannot be settled through a bare
/// `RelayerResult`.
///
/// The `RelayerResult` handler used to mint from its own message field plus
/// any transfer row carrying that message id, gated only by the external-root
/// anchor map. Nothing bound the message to a lock the source chain actually
/// emitted: any account could open a row with its own outbound
/// `BridgeTx::Lock` (owner and recipient its own, amount debited) and then
/// settle the same lock back to itself here, crediting the units on Budlum
/// while the lock's claim on the target domain stayed live - the same locked
/// units spent twice. Value effects now go only through the door that proves
/// the domain event against a committed block hash, so this path refuses the
/// message outright: the row stays locked, the replay id stays unspent and
/// neither the recipient nor the relayer is credited.
#[test]
fn a_transfer_row_opened_by_a_local_lock_cannot_be_minted_through_a_relayer_result() {
    use crate::cross_domain::bridge::AssetId;

    let owner = Address::from([0x0B; 32]);
    let recipient = Address::from([0x0C; 32]);
    let mut state = AccountState::new();
    let asset = AssetId([0x7A; 32]);
    state
        .bridge_state
        .register_asset(asset, 1)
        .expect("asset registers");
    let (_transfer, lock_event) = state
        .bridge_state
        .lock(1, 2, 20, 0, asset, owner, recipient, 100, 1_000)
        .expect("lock succeeds");
    let message = lock_event.message.expect("lock carries its message");

    state.add_balance(&owner, 1_000);
    // The gate refusal only surfaces for a transaction that passes the
    // balance check first: the relayer is the signer here, so the fixture
    // funds it the way the accepting tests do.
    state.add_balance(&relayer_addr(), 1_000);
    let recipient_before = state.get_balance(&recipient);
    let relayer_before = state.get_balance(&relayer_addr());

    let mut res = make_result("0xLOCK_ON_ETHEREUM");
    res.message = Some(message.clone());
    seal_result_proof(&mut res);
    let tx = relayer_tx(res, 1);
    let root = match &tx.tx_type {
        TransactionType::RelayerResult(result) => result.external_state_root,
        _ => unreachable!(),
    };
    state
        .external_roots
        .insert(ExternalChain::Custom(0xC0DE).domain_id(), root);

    let err = Executor::apply_transaction_checked(&mut state, &tx)
        .expect_err("a local lock cannot be settled through a relayer result");
    assert_eq!(
        err.code(),
        "relayer_bridge_effect_requires_domain_event",
        "the refusal must come from the domain-event gate, got: {}",
        err.message()
    );
    let transfer = state
        .bridge_state
        .get_transfer(&message.message_id)
        .expect("the transfer row stays");
    assert!(
        matches!(
            transfer.status,
            crate::cross_domain::bridge::BridgeStatus::Locked { .. }
        ),
        "the lock is still open"
    );
    assert!(
        !state.bridge_state.replay.is_processed(
            message.source_domain,
            message.target_domain,
            &message.sender,
            message.nonce
        ),
        "the replay high water is not advanced by a refused mint"
    );
    assert_eq!(
        state.get_balance(&recipient),
        recipient_before,
        "recipient untouched"
    );
    assert_eq!(
        state.get_balance(&relayer_addr()),
        relayer_before,
        "the relayer is not credited by the refused effect"
    );
}

/// A custom, self-anchored domain cannot settle value through a relayer
/// result either.
///
/// The anchor map entry only says which 32-byte root the domain's light
/// client finalized; the result's message stays the caller's own field. For
/// a `BridgeBurn` (the unlock side of the value bridge) the handler would
/// have correlated the caller's message against an existing row and released
/// the refund from nothing but that row - no domain event, no committed
/// source block. The fail-closed gate refuses the message kind before any
/// bridge state moves: with the chain's own anchor registered and a row
/// present, the unlock still does not happen and no balance changes.
#[test]
fn a_custom_domain_cannot_settle_value_through_a_relayer_result() {
    use crate::cross_domain::bridge::{AssetId, BridgeStatus};
    use crate::cross_domain::message::{CrossDomainMessage, CrossDomainMessageParams};

    let owner = Address::from([0x1B; 32]);
    let recipient = Address::from([0x1C; 32]);
    let mut state = AccountState::new();
    let asset = AssetId([0x7B; 32]);
    state
        .bridge_state
        .register_asset(asset, 1)
        .expect("asset registers");
    let (transfer, lock_event) = state
        .bridge_state
        .lock(1, 2, 20, 0, asset, owner, recipient, 100, 1_000)
        .expect("lock succeeds");
    let _message = lock_event.message.expect("lock carries its message");
    state.add_balance(&owner, 1_000);
    // The gate refusal only surfaces for a transaction that passes the
    // balance check first: the relayer signs this transaction, so the
    // fixture funds it before the apply.
    state.add_balance(&relayer_addr(), 1_000);
    let owner_before = state.get_balance(&owner);
    let recipient_before = state.get_balance(&recipient);

    let burn = CrossDomainMessage::new_correlated(
        CrossDomainMessageParams {
            source_domain: 1,
            target_domain: ExternalChain::Custom(0xC0DE).domain_id(),
            source_height: 9,
            event_index: 0,
            nonce: 0,
            sender: owner,
            recipient,
            payload_hash: [0u8; 32],
            kind: crate::cross_domain::message::MessageKind::BridgeBurn,
            expiry_height: 0,
        },
        transfer.message_id,
    );
    let mut res = make_result("0xBURN_ON_ETHEREUM");
    res.message = Some(burn);
    seal_result_proof(&mut res);
    let tx = relayer_tx(res, 1);
    let root = match &tx.tx_type {
        TransactionType::RelayerResult(result) => result.external_state_root,
        _ => unreachable!(),
    };
    // The anchor the light client would have registered: consensus-owned in
    // production, and still not enough to settle value from a result alone.
    state
        .external_roots
        .insert(ExternalChain::Custom(0xC0DE).domain_id(), root);

    let err = Executor::apply_transaction_checked(&mut state, &tx)
        .expect_err("a burn carried by a relayer result cannot unlock value");
    assert_eq!(
        err.code(),
        "relayer_bridge_effect_requires_domain_event",
        "the refusal must come from the domain-event gate, got: {}",
        err.message()
    );
    let kept = state
        .bridge_state
        .get_transfer(&transfer.message_id)
        .expect("the transfer row stays");
    assert!(
        matches!(kept.status, BridgeStatus::Locked { .. }),
        "the lock is untouched"
    );
    assert_eq!(state.get_balance(&owner), owner_before, "owner untouched");
    assert_eq!(
        state.get_balance(&recipient),
        recipient_before,
        "recipient untouched"
    );
}

/// The supply gate reads every file that mints, not only the two it started with.
///
/// `minting-paths-are-counted` proves the ceiling by listing every
/// `try_add_balance` call in production code and requiring a written reason
/// why each one moves money instead of creating it. It once read only
/// `src/chain/blockchain.rs` and `src/core/account.rs`; the executor also
/// credits a bridge mint, so a mint that bypassed the ceiling there was
/// invisible to the gate. The gate now scans the whole `src` tree, and its
/// justification list must still name the executor explicitly - a tree-wide
/// scan without the executor's written accounting would read the file
/// without ever asking what its credits are.
#[test]
fn minting_gate_reads_the_executor() {
    let gate = include_str!("../../xtask/gates/src/gates/minting_paths_are_counted.rs");
    assert!(
        gate.contains("const SCAN_ROOT: &str = \"src\""),
        "minting-paths-are-counted must scan the whole src tree, the executor included"
    );
    let list_at = gate
        .find("const TRANSFER_JUSTIFICATIONS")
        .expect("the gate must keep its justification list");
    let list_end = gate[list_at..]
        .find("\n];")
        .map(|end| list_at + end)
        .expect("justification list must close");
    let list = &gate[list_at..list_end];
    assert!(
        list.contains("src/execution/executor.rs"),
        "minting-paths-are-counted must account for src/execution/executor.rs; it credits bridge mints"
    );
}
