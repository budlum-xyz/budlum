//! Gerçek zincir fixture'larıyla differential testler.
//!
//! Kaynak: `config/fixtures/gercek-zincir.json` (tek kaynak kuralı - test ve
//! `fixture-integrity` gate'i aynı dosyayı okur). Fixture'lar 2026-08-14'te
//! api.blockchair.com'dan canlı çekildi ve bağımsız kaynaklarla çapraz
//! doğrulandı (BTC yükseklik mempool.space, ETH yükseklik blockcypher).
//!
//! Bu testler production runtime verisi kullanmaz; üçüncü taraf API'ye hiçbir
//! bağımlılık yoktur. Amaç: kendi hash/merkle/RLP uygulamalarımızın gerçek
//! zincir değerleriyle birebir eşleştiğini kanıtlamak (endianness, çift-SHA,
//! alan sırası hataları burada yakalanır).

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
        "/config/fixtures/gercek-zincir.json"
    ));
    serde_json::from_str(raw).expect("gercek-zincir.json parse edilemeli")
}

fn from_hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("fixture hex alanları çözülebilmeli")
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let first = sha2::Sha256::digest(data);
    let second = sha2::Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(second.as_slice());
    out
}

/// Bitcoin Merkle kökü: display-hex txid'ler → iç bayt sırası (ters) →
/// yapraklar (txid zaten sha256d'dir - yeniden hashlenmez) → ikili eşleme
/// (tek sayıda son yaprak kopyalanır) → display-hex kök.
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

/// RLP skaler kodlaması için minimal big-endian baytlar (0 → boş).
fn min_bytes(n: u64) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }
    let be = n.to_be_bytes();
    let start = be.iter().position(|&b| b != 0).expect("n>0");
    be[start..].to_vec()
}

/// Yellow Paper alan sırasıyla gerçek header'ın RLP'sini kur.
/// Pre-London 15 alan; London+ 16. alan `baseFeePerGas`.
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
        "fixture en az 3 merkle bloğu içermeli"
    );
    for block in &fx.btc_merkle_blocks {
        let computed = btc_merkle_root(&block.txids);
        assert_eq!(
            computed, block.merkle_root,
            "blok {}: bizim merkle hesabımız gerçek zincir köküyle eşleşmeli \
             (endianness/eşleme hatası yakalandı)",
            block.height
        );
    }
}

#[test]
fn eth_header_hash_matches_real_mainnet_blocks() {
    let fx = fixture();
    assert!(fx.eth_headers.len() >= 2, "fixture en az 2 header içermeli");
    for h in &fx.eth_headers {
        let rlp_bytes = build_header_rlp(h);
        // decode_header: RLP'yi çözer, alanları okur ve hash = keccak256(raw)
        // hesaplar. Bu test hem bizim RLP encoder'ımızı hem decoder'ı gerçek
        // zincir hash'ine karşı doğrular.
        let decoded = crate::cross_domain::evm::header::decode_header(&rlp_bytes)
            .unwrap_or_else(|e| panic!("{}: decode_header reddetti: {e}", h.name));
        assert_eq!(
            hex::encode(decoded.hash),
            h.expected_hash,
            "{}: keccak256(rlp(header)) gerçek blok hash'iyle eşleşmeli",
            h.name
        );
        assert_eq!(decoded.number, h.number, "{}: number uyuşmuyor", h.name);
        assert_eq!(
            hex::encode(decoded.parent_hash),
            h.parent_hash,
            "{}: parent_hash uyuşmuyor",
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
        .expect("post-merge fixture'ı bulunmalı");
    // PoS geçişinin zincir üstü imzaları: difficulty=0 ve ommersHash =
    // keccak256(rlp([])) sabiti. Fixture'ın kendisinin bu değişmezleri
    // taşıdığı doğrulanır - üretimde EVM adapter'ın PoS/PoW ayrımı bu
    // sinyallere dayanır.
    assert_eq!(pm.difficulty, 0, "post-merge header difficulty=0 olmalı");
    assert_eq!(
        pm.ommers_hash, "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "ommersHash, keccak256(rlp([])) sabitine eşit olmalı"
    );
    assert!(
        pm.base_fee_per_gas.is_some(),
        "post-merge header baseFeePerGas taşımalı (London+)"
    );
    let rlp_bytes = build_header_rlp(pm);
    let decoded = crate::cross_domain::evm::header::decode_header(&rlp_bytes)
        .expect("post-merge RLP'si decode edilmeli");
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
            "halving'ler arası tam 210.000 blok olmalı"
        );
        assert_eq!(
            next.generation_sat,
            prev.generation_sat / 2,
            "h={}: ödül tam yarılanmalı",
            next.height
        );
    }
    // Serinin uçları: 25 BTC → 3.125 BTC. Sabit-arz modelinin referans
    // noktaları (Budlum'un 100M $BUD sabit arz tasarım tartışmasına veri).
    assert_eq!(fx.btc_halvings[0].generation_sat, 2_500_000_000);
    assert_eq!(fx.btc_halvings[3].generation_sat, 312_500_000);
}

#[test]
fn fixture_file_parses_and_fields_are_well_formed() {
    let fx = fixture();
    for block in &fx.btc_merkle_blocks {
        assert_eq!(block.merkle_root.len(), 64, "merkle_root 64 hex olmalı");
        assert!(!block.txids.is_empty(), "her blok en az 1 txid içermeli");
        for t in &block.txids {
            assert_eq!(t.len(), 64, "txid 64 hex olmalı");
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
            assert_eq!(f.len(), 64, "{}: hash alanı 64 hex olmalı", h.name);
        }
        assert_eq!(h.beneficiary.len(), 40, "{}: beneficiary 20 bayt", h.name);
        assert_eq!(h.nonce.len(), 16, "{}: nonce 8 bayt", h.name);
        assert_eq!(h.logs_bloom.len(), 512, "{}: logsBloom 256 bayt", h.name);
    }
}
