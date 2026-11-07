//! Fuzz harness for EVM migration deployment, account, and storage MPT proofs ().

#![no_main]

use budlum_core::cross_domain::evm::account_proof::{check_code, verify_account, verify_storage};
use budlum_core::execution::coordinator::migration::{
    dependency_report, verify_deployment, DeploymentProof,
};
use libfuzzer_sys::fuzz_target;

const MAX_NODES: usize = 32;
const MAX_NODE_BYTES: usize = 128;

fn split_nodes(mut raw: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while !raw.is_empty() && out.len() < MAX_NODES {
        let Some((&len_byte, rest)) = raw.split_first() else {
            break;
        };
        let n = usize::from(len_byte).min(MAX_NODE_BYTES).min(rest.len());
        if let Some(chunk) = rest.get(..n) {
            out.push(chunk.to_vec());
        }
        raw = rest.get(n..).unwrap_or_default();
    }
    out
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 120 {
        return;
    }
    let Some(tx_root_s) = data.get(0..32) else {
        return;
    };
    let Some(rec_root_s) = data.get(32..64) else {
        return;
    };
    let Some(state_root_s) = data.get(64..96) else {
        return;
    };
    let Some(addr_s) = data.get(96..116) else {
        return;
    };
    let Ok(transactions_root) = <[u8; 32]>::try_from(tx_root_s) else {
        return;
    };
    let Ok(receipts_root) = <[u8; 32]>::try_from(rec_root_s) else {
        return;
    };
    let Ok(state_root) = <[u8; 32]>::try_from(state_root_s) else {
        return;
    };
    let Ok(contract) = <[u8; 20]>::try_from(addr_s) else {
        return;
    };
    let tail = data.get(116..).unwrap_or_default();
    let nodes = split_nodes(tail);

    let proof = DeploymentProof {
        deployment_block: 1,
        transaction_index: 0,
        transaction: tail.iter().copied().take(512).collect(),
        transaction_proof: nodes.clone(),
        transactions_root,
        receipt_proof: nodes.clone(),
        receipts_root,
        factory: None,
    };
    let _ = verify_deployment(&proof, 11_155_111);
    let _ = verify_account(&nodes, &state_root, &contract);
    let _ = verify_storage(&nodes, &state_root, &transactions_root);
    let _ = check_code(tail, &receipts_root);
    let _ = dependency_report(tail);
});
