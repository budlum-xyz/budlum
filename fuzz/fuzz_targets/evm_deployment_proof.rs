#![no_main]

use budlum_core::cross_domain::evm::mpt;
use budlum_core::cross_domain::evm::rlp::{self, Item};
use budlum_core::execution::coordinator::migration::{verify_deployment, DeploymentProof};
use libfuzzer_sys::fuzz_target;

// The input becomes the proven transaction, not an unchecked side input. This
// reaches legacy and typed transaction decoding, signature recovery, and the
// receipt path under the same MPT structure the production verifier consumes.
fuzz_target!(|data: &[u8]| {
    if data.len() > 8192 {
        return;
    }
    let key = rlp::encode(&Item::String(Vec::new()));
    let path = mpt::hp_encode(&mpt::to_nibbles(&key), true);
    let transaction_node = rlp::encode(&Item::List(vec![
        Item::String(path.clone()),
        Item::String(data.to_vec()),
    ]));
    let receipt = rlp::encode(&Item::List(vec![
        Item::String(vec![1]),
        Item::String(Vec::new()),
        Item::String(vec![0; 256]),
        Item::List(Vec::new()),
    ]));
    let receipt_node = rlp::encode(&Item::List(vec![
        Item::String(path),
        Item::String(receipt),
    ]));
    let proof = DeploymentProof {
        deployment_block: 0,
        transaction_index: 0,
        transaction: data.to_vec(),
        transaction_proof: vec![transaction_node.clone()],
        transactions_root: mpt::keccak256(&transaction_node),
        receipt_proof: vec![receipt_node.clone()],
        receipts_root: mpt::keccak256(&receipt_node),
    };
    let _ = verify_deployment(&proof, 11_155_111);
});
