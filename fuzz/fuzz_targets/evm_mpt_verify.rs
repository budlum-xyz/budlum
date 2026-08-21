#![no_main]

//! F10.1 EVM Merkle-Patricia proof verifier robustness target.
//!
//! Input layout is intentionally simple and bounded:
//! - bytes 0..32: claimed trie root;
//! - byte 32: key length (bounded by remaining input);
//! - following bytes: key;
//! - remaining bytes: proof nodes split into at most 64 chunks of 128 bytes.
//!
//! Arbitrary proofs normally return `MptError`. The oracle is memory safety and
//! Panic freedom, not proof acceptance.

use budlum_core::cross_domain::evm::mpt;
use libfuzzer_sys::fuzz_target;

const ROOT_BYTES: usize = 32;
const MAX_KEY_BYTES: usize = 255;
const MAX_NODES: usize = 64;
const NODE_CHUNK_BYTES: usize = 128;

fuzz_target!(|data: &[u8]| {
    if data.len() < ROOT_BYTES + 1 {
        return;
    }

    let mut root = [0u8; ROOT_BYTES];
    root.copy_from_slice(&data[..ROOT_BYTES]);

    let declared_key_len = data[ROOT_BYTES] as usize;
    let remaining = &data[ROOT_BYTES + 1..];
    let key_len = declared_key_len.min(MAX_KEY_BYTES).min(remaining.len());
    let key = &remaining[..key_len];
    let proof_nodes = remaining[key_len..]
        .chunks(NODE_CHUNK_BYTES)
        .take(MAX_NODES)
        .map(|chunk| chunk.to_vec())
        .collect::<Vec<_>>();

    let _ = mpt::verify(&proof_nodes, &root, key);
});
