//! Differential tests against real chain fixtures.
//!
//! Source: `config/fixtures/real-chain.json` (the single-source rule - the
//! tests and the `fixture-integrity` gate read the same file). The fixtures
//! were pulled live from api.blockchair.com on 2026-08-14 and cross-checked
//! against independent sources (the BTC height against mempool.space, the ETH
//! height against blockcypher).
//!
//! These tests use no production runtime data and have no dependency on a
//! third-party API. The purpose is to prove that our own hash, merkle and RLP
//! implementations match real chain values exactly; endianness, double-SHA and
//! field-order mistakes are caught here.

use crate::cross_domain::evm::rlp::{self, Item};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BtcMerkleBlock {
    height: u64,
    merkle_root: String,
    txids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BtcHalving {
    height: u64,
    generation_sat: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EthHeaderFixture {
    name: String,
    expected_hash: String,
    parent_hash: String,
    ommers_hash: String,
    beneficiary: String,
    state_root: String,
    transactions_root: String,
    receipts_root: String,
    logs_bloom: String,
    difficulty: u64,
    number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: String,
    mix_hash: String,
    nonce: String,
    base_fee_per_gas: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RealChainFixture {
    btc_merkle_blocks: Vec<BtcMerkleBlock>,
    btc_halvings: Vec<BtcHalving>,
    eth_headers: Vec<EthHeaderFixture>,
}

fn fixture() -> RealChainFixture {
    let raw = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/config/fixtures/real-chain.json"
    ));
    serde_json::from_str(raw).expect("real-chain.json parse edilemeli")
}

fn from_hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("the fixture hex fields have to decode")
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let first = sha2::Sha256::digest(data);
    let second = sha2::Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(second.as_slice());
    out
}

/// The Bitcoin merkle root: display-hex txids, reversed into internal byte
/// order, become the leaves (a txid is already sha256d and is not rehashed),
/// then pairwise hashing (an odd last leaf is duplicated) gives the display-hex
/// root.
fn btc_merkle_root(txids: &[String]) -> String {
    let mut leaves: Vec<[u8; 32]> = txids
        .iter()
        .map(|t| {
            let mut b = from_hex(t);
            b.reverse(); // display → internal
            let mut leaf = [0u8; 32];
            leaf.copy_from_slice(&b);
            leaf
        })
        .collect();
    while leaves.len() > 1 {
        if leaves.len() % 2 == 1 {
            let last = *leaves.last().expect("tek eleman garantili");
            leaves.push(last);
        }
        let mut next = Vec::with_capacity(leaves.len() / 2);
        for pair in leaves.chunks(2) {
            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(&pair[0]);
            buf.extend_from_slice(&pair[1]);
            next.push(sha256d(&buf));
        }
        leaves = next;
    }
    let mut root = leaves[0];
    root.reverse(); // internal → display
    hex::encode(root)
}

/// The minimal big-endian bytes for RLP scalar encoding (0 becomes empty).
fn min_bytes(n: u64) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }
    let be = n.to_be_bytes();
    let start = be.iter().position(|&b| b != 0).expect("n>0");
    be[start..].to_vec()
}

/// Build the RLP of the real header in Yellow Paper field order.
/// Pre-London 15 fields; London+ adds the 16th, `baseFeePerGas`.
fn build_header_rlp(h: &EthHeaderFixture) -> Vec<u8> {
    let mut items = vec![
        Item::String(from_hex(&h.parent_hash)),       // 1. parentHash
        Item::String(from_hex(&h.ommers_hash)),       // 2. ommersHash (sha3Uncles)
        Item::String(from_hex(&h.beneficiary)),       // 3. beneficiary (20B)
        Item::String(from_hex(&h.state_root)),        // 4. stateRoot
        Item::String(from_hex(&h.transactions_root)), // 5. transactionsRoot
        Item::String(from_hex(&h.receipts_root)),     // 6. receiptsRoot
        Item::String(from_hex(&h.logs_bloom)),        // 7. logsBloom (256B)
        Item::String(min_bytes(h.difficulty)),        // 8. difficulty
        Item::String(min_bytes(h.number)),            // 9. number
        Item::String(min_bytes(h.gas_limit)),         // 10. gasLimit
        Item::String(min_bytes(h.gas_used)),          // 11. gasUsed
        Item::String(min_bytes(h.timestamp)),         // 12. timestamp
        Item::String(from_hex(&h.extra_data)),        // 13. extraData
        Item::String(from_hex(&h.mix_hash)),          // 14. mixHash
        Item::String(from_hex(&h.nonce)),             // 15. nonce (8B)
    ];
    if let Some(bf) = h.base_fee_per_gas {
        items.push(Item::String(min_bytes(bf))); // 16. baseFeePerGas (London+)
    }
    rlp::encode(&Item::List(items))
}

#[test]
fn btc_merkle_reconstruction_matches_real_blocks() {
    let fx = fixture();
    assert!(
        fx.btc_merkle_blocks.len() >= 3,
        "the fixture has to contain at least 3 merkle blocks"
    );
    for block in &fx.btc_merkle_blocks {
        let computed = btc_merkle_root(&block.txids);
        assert_eq!(
            computed, block.merkle_root,
            "block {}: our merkle computation has to match the real chain root \
             (an endianness or pairing mistake was caught)",
            block.height
        );
    }
}

#[test]
fn eth_header_hash_matches_real_mainnet_blocks() {
    let fx = fixture();
    assert!(
        fx.eth_headers.len() >= 2,
        "the fixture has to contain at least 2 headers"
    );
    for h in &fx.eth_headers {
        let rlp_bytes = build_header_rlp(h);
        // decode_header parses the RLP, reads the fields and computes
        // hash = keccak256(raw). This test verifies both our RLP encoder and
        // the decoder against the real chain hash.
        let decoded = crate::cross_domain::evm::header::decode_header(&rlp_bytes)
            .unwrap_or_else(|e| panic!("{}: decode_header reddetti: {e}", h.name));
        assert_eq!(
            hex::encode(decoded.hash),
            h.expected_hash,
            "{}: keccak256(rlp(header)) has to match the real block hash",
            h.name
        );
        assert_eq!(
            decoded.number, h.number,
            "{}: number does not match",
            h.name
        );
        assert_eq!(
            hex::encode(decoded.parent_hash),
            h.parent_hash,
            "{}: parent_hash does not match",
            h.name
        );
    }
}

#[test]
fn post_merge_header_carries_zero_difficulty_and_ommers_constant() {
    let fx = fixture();
    let pm = fx
        .eth_headers
        .iter()
        .find(|h| h.name.contains("post_merge"))
        .expect("the post-merge fixture has to be present");
    // The on-chain signatures of the PoS transition: difficulty=0 and
    // ommersHash equal to the keccak256(rlp([])) constant. The fixture itself
    // is verified to carry these invariants - in production the EVM adapter's
    // PoS/PoW distinction rests on these signals.
    assert_eq!(
        pm.difficulty, 0,
        "a post-merge header has to have difficulty=0"
    );
    assert_eq!(
        pm.ommers_hash, "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "ommersHash has to equal the keccak256(rlp([])) constant"
    );
    assert!(
        pm.base_fee_per_gas.is_some(),
        "a post-merge header has to carry baseFeePerGas (London and later)"
    );
    let rlp_bytes = build_header_rlp(pm);
    let decoded = crate::cross_domain::evm::header::decode_header(&rlp_bytes)
        .expect("the post-merge RLP has to decode");
    assert_eq!(hex::encode(decoded.hash), pm.expected_hash);
}

#[test]
fn btc_halving_series_follows_210k_rule() {
    let fx = fixture();
    assert_eq!(fx.btc_halvings.len(), 4);
    for w in fx.btc_halvings.windows(2) {
        let (prev, next) = (&w[0], &w[1]);
        assert_eq!(
            next.height - prev.height,
            210_000,
            "there have to be exactly 210,000 blocks between halvings"
        );
        assert_eq!(
            next.generation_sat,
            prev.generation_sat / 2,
            "h={}: the reward has to halve exactly",
            next.height
        );
    }
    // The ends of the series: 25 BTC down to 3.125 BTC. These are the
    // reference points of the fixed-supply model (data for Budlum's own 100M
    // $BUD fixed-supply design discussion).
    assert_eq!(fx.btc_halvings[0].generation_sat, 2_500_000_000);
    assert_eq!(fx.btc_halvings[3].generation_sat, 312_500_000);
}

#[test]
fn fixture_file_parses_and_fields_are_well_formed() {
    let fx = fixture();
    for block in &fx.btc_merkle_blocks {
        assert_eq!(
            block.merkle_root.len(),
            64,
            "merkle_root has to be 64 hex characters"
        );
        assert!(
            !block.txids.is_empty(),
            "every block has to contain at least 1 txid"
        );
        for t in &block.txids {
            assert_eq!(t.len(), 64, "a txid has to be 64 hex characters");
        }
    }
    for h in &fx.eth_headers {
        for f in [
            &h.expected_hash,
            &h.parent_hash,
            &h.ommers_hash,
            &h.state_root,
            &h.transactions_root,
            &h.receipts_root,
            &h.mix_hash,
        ] {
            assert_eq!(
                f.len(),
                64,
                "{}: a hash field has to be 64 hex characters",
                h.name
            );
        }
        assert_eq!(h.beneficiary.len(), 40, "{}: beneficiary 20 bytes", h.name);
        assert_eq!(h.nonce.len(), 16, "{}: nonce 8 bytes", h.name);
        assert_eq!(h.logs_bloom.len(), 512, "{}: logsBloom 256 bytes", h.name);
    }
}
