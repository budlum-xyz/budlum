//! (2026-07-21 - kullanıcı görev listesi "CI sertleştirme")
//! **Cross-platform consensus determinism digest'i.**
//!
//! Kullanıcı maddesi: "Cross-platform determinism matrix (Linux/macOS/Windows
//! Arası consensus çıktısı birebir aynı mı)".
//!
//! Yöntem: Sabit tohumlu anahtarlar + sabit genesis_time + sabit işlem planı
//! Ile 4 blokluk bir senaryo koşulur. Her blok sonrası `calculate_state_root`
//! Ve bloğun işlem sırası kaydedilir; ayrıca final hesap durumu (bakiye+nonce)
//! Sabit adres listesi üzerinden dökülür. Tüm gözlemler SHA-256 ile tek bir
//! 64-hex digest'e indirgenir ve `CONSENSUS_DIGEST=<hex>` olarak stdout'a
//! Yazılır (`--nocapture` ile). `determinism.yml` üç işletim sisteminde bu
//! Satırı artefakt olarak toplayıp `consensus-digest-compare` job'unda byte
//! Eşitliği ister - fark çıkarsa platformlar arası consensus sapması
//! FAIL olunur (sahte-yeşil yok: `if-no-files-found: error`).
//!
//! Determinizm sınırları (bilinçli):
//!   * `genesis_time` sabitlenir (`Blockchain::new` aksi halde duvar saatini
//!     Okur; `produce_block` timestamp'i `genesis_time + slot*SLOT_MS`'tir).
//!   * İşlemler Ed25519 ile imzalanır (RFC 8032 - deterministik imza).
//!   * Senaryo aynı-fee tie çifti (bob/carol, fee=9) içerir: mempool tie-break
//!     `BTreeSet<(fee, hash)>` kuralıyla canonik olduğundan dahil olma sırası
//!     Platformdan bağımsızdır (bkz. `src/mempool/pool.rs` yaması).
//!   * Digest'e yalnız consensus çıktıları girer: state root, işlem sırası,
//!     Bakiye/nonce. Duvar saati, float, artalan thread'i yok.

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;
use crate::core::transaction::Transaction;
use crate::crypto::primitives::KeyPair;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const SCENARIO_CHAIN_ID: u64 = 45262;
/// Digest normalizasyonu için sabit genesis zamanı (ms). Değer keyfidir ama
/// HER platformda ve HER koşuda aynıdır; değiştirilmesi digest'i değiştirir
/// (bu kasıtlıdır: sabit, dokümante bir çapa).
const SCENARIO_GENESIS_TIME_MS: u128 = 1_700_000_000_000;

/// Senaryonun tamamını koşar ve platform-bağımsız gözlem vektörünü üretir.
/// Aynı vektör iki kez üretilir; fark çıkarsa süreç-içi nondeterminizm bir
/// Test hatası olarak yüzeye çıkar (retry/mask yok).
fn run_scenario() -> Vec<String> {
    let consensus = Arc::new(PoWEngine::new(0));
    let mut chain = Blockchain::new(consensus, None, SCENARIO_CHAIN_ID, None);
    chain.genesis_time = SCENARIO_GENESIS_TIME_MS;

    // Sabit tohumlar: platform/koşu bağımsız aynı anahtar bitleri.
    let alice_kp = KeyPair::from_seed(&[0xA1; 32]).expect("seed alice");
    let bob_kp = KeyPair::from_seed(&[0xB2; 32]).expect("seed bob");
    let carol_kp = KeyPair::from_seed(&[0xC3; 32]).expect("seed carol");
    let alice = Address::from(alice_kp.public_key_bytes());
    let bob = Address::from(bob_kp.public_key_bytes());
    let carol = Address::from(carol_kp.public_key_bytes());
    let miner = alice; // blok üreticisi sabit (digest'in parçası değil ama sabit tutulur)

    // Başlangıç dağılımı (test fikstürü; genesis hash'ini ETKİLEMEZ - bu state
    // Genesis block sonrası test scaffold'udur, mainnet genesis config değil).
    chain.state.add_balance(&alice, 100_000);
    chain.state.add_balance(&bob, 50_000);
    chain.state.add_balance(&carol, 25_000);

    let mut observations: Vec<String> = Vec::new();
    observations.push(format!(
        "genesis_root={}",
        chain.state.calculate_state_root()
    ));

    // İşlem planı: (gönderen_idx, alıcı_idx, amount, fee) - 3 tur x 3-4 tx.
    // Tur 2'de bob/carol aynı fee (9) ile tie üretir (canonik sıralama sınavı).
    // Sender indeksleri: 0=alice,1=bob,2=carol
    let rounds: [&[(usize, usize, u64, u64)]; 4] = [
        &[(0, 1, 100, 7), (1, 2, 50, 11), (0, 2, 25, 13)],
        &[(1, 0, 10, 9), (2, 0, 15, 9), (0, 1, 40, 5)],
        &[(2, 1, 5, 3), (0, 2, 60, 21), (1, 0, 30, 17), (2, 0, 1, 2)],
        &[(0, 1, 3, 4), (1, 2, 2, 6), (2, 1, 4, 8)],
    ];

    let kps = [&alice_kp, &bob_kp, &carol_kp];
    let addrs = [alice, bob, carol];
    let mut nonces = [0u64; 3];

    for plan in rounds.iter() {
        for &(from_i, to_i, amount, fee) in plan.iter() {
            let mut tx = Transaction::new_with_fee(
                addrs[from_i],
                addrs[to_i],
                amount,
                fee,
                nonces[from_i],
                Vec::new(),
            );
            nonces[from_i] += 1;
            tx.timestamp = 0; // duvar saati normalizasyonu (genesis kalıbı)
            tx.max_fee = fee;
            tx.priority_fee = 0;
            tx.sign(kps[from_i]);
            chain
                .add_transaction(tx)
                .unwrap_or_else(|e| panic!("scenario tx admission failed: {e}"));
        }
        let (block, _events) = chain
            .produce_block(miner)
            .expect("scenario block production must succeed");
        let tx_order: Vec<String> = block.transactions.iter().map(|t| t.hash.clone()).collect();
        observations.push(format!("block{}_tx_count={}", block.index, tx_order.len()));
        observations.push(format!(
            "block{}_tx_order={}",
            block.index,
            tx_order.join(",")
        ));
        observations.push(format!(
            "block{}_state_root={}",
            block.index,
            chain.state.calculate_state_root()
        ));
    }

    // Final durum: sabit adres listesi üzerinden deterministik döküm.
    for (name, addr) in [("alice", alice), ("bob", bob), ("carol", carol)] {
        let acc = chain.state.accounts.get(&addr).expect("scenario account");
        observations.push(format!("final_{}={}:{}", name, acc.balance, acc.nonce));
    }
    observations.push(format!("final_supply={}", chain.state.circulating_supply()));
    observations
}

/// Gözlem vektörünü tek SHA-256 digest'e indirger.
fn digest_of(observations: &[String]) -> String {
    let mut hasher = Sha256::new();
    for line in observations {
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// CI cross-platform digest üretimi. `--nocapture` ile koşulur; workflow
    /// `CONSENSUS_DIGEST=` satırını toplar. Test içi iki-tur eşitlik
    /// Assert'i süreç-içi nondeterminizmi (ör. HashMap/HashSet iteration)
    /// Yerinde yakalar; platformlar arası eşitlik determinism.yml'in
    /// Compare job'unun işi.
    #[test]
    fn consensus_scenario_digest_cross_platform() {
        let pass1 = run_scenario();
        let pass2 = run_scenario();
        assert_eq!(
            pass1, pass2,
            "process-internal nondeterminism: iki senaryo koşusu farklı gözlem üretti"
        );
        let digest = digest_of(&pass1);
        println!("CONSENSUS_DIGEST={digest}");
        // Sahte-yeşil kilidi: digest sabit uzunlukta ve boş olamaz.
        assert_eq!(digest.len(), 64);
        // Minimum senaryo kanıtı: 4 blok + genesis + final hesap + supply
        // Gözlemleri üretilmiş olmalı (eksik üretim sessizce geçemez).
        assert!(
            pass1.len() > 1 + 4 * 3 + 3,
            "scenario observation vector too short: {}",
            pass1.len()
        );
    }
}
