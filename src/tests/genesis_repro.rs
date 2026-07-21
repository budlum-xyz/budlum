//! ADIM-1 (ARENA2, 2026-07-21 — kullanıcı görev listesi "CI sertleştirme"):
//! **Genesis reproducibility sondası (CI Genişletme Madde 1).**
//!
//! Arka plan: `.github/workflows/determinism.yml` içindeki
//! `Genesis Reproducibility (Madde 1)` job'u `genesis_hash_deterministic`
//! adlı bir testin `GENESIS_HASH=<hex>` satırını iki temiz build'de
//! karşılaştırıyor. ADIM-1 sertleştirmesine kadar job boş hash'i boş
//! hash'le karşılaştırıyordu (vacuous-pass); çünkü bu isimde bir test
//! repoda YOKTU. Bu modül sondanın gerçek gövdesidir.
//!
//! Ne ölçülür (platform/koşu bağımsız olması GEREKENLER):
//!   * Üç ağ çözümlemesi (Mainnet=1, Testnet=42, Devnet=1337) + tanımsız
//!     chain_id fallback'i (`GenesisConfig::new`): genesis blok hash'i,
//!     timestamp, tx_root, validator_set_hash, state root, hesap sayısı,
//!     toplam dolaşım.
//!   * Bloktaki `state_root` ile `build_state()` root'unun eşitliği
//!     (node'un boot'taki fail-closed genesis/DB doğrulamasının aynası —
//!     bkz. `Blockchain::new_with_genesis` startup kontrolü).
//!   * Tam kurucu yolu: `Blockchain::new(...)` ile üretilen zincirin
//!     genesis bloğu, doğrudan `build_genesis_block()` çıktısıyla birebir
//!     aynı olmalı.
//!
//! Tüm gözlemler tek SHA-256 digest'e indirgenir ve
//! `GENESIS_HASH=<64hex>` olarak stdout'a yazılır (`--nocapture`).
//! Test içinde her gözlem iki bağımsız inşadan üretilir ve eşitlik
//! assert'lenir: süreç-içi nondeterminizm (HashMap iteration, duvar saati
//! sızıntısı vb.) yerinde kırmızı olur. Buildler-arası eşitlik CI job'unun
//! işi (aynı test iki `cargo clean` sonrası build'de koşar).

use crate::chain::blockchain::Blockchain;
use crate::chain::genesis::GenesisConfig;
use crate::consensus::pow::PoWEngine;
use crate::core::chain_config::Network;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Bir chain_id için genesis gözlem vektörü. `Blockchain::new_with_genesis`
/// içindeki çözümleme yolunun aynası: network biliniyorsa `for_network`,
/// yoksa `GenesisConfig::new` fallback'i.
fn probe_chain(chain_id: u64) -> Vec<String> {
    let config = Network::from_chain_id(chain_id)
        .map(GenesisConfig::for_network)
        .unwrap_or_else(|| GenesisConfig::new(chain_id));

    let block = config.build_genesis_block();
    let mut rebuilt_state = config.build_state();
    let rebuilt_root = rebuilt_state.calculate_state_root();

    // Boot fail-closed kontrolünün statik ikizi: blok içi state_root ile
    // taze build_state() root'u aynı kalmalı (ayrışma = boot'ta CRITICAL
    // mismatch riski demektir).
    assert_eq!(
        block.state_root, rebuilt_root,
        "genesis state_root({chain_id}) != build_state() root — boot doğrulaması kırılır"
    );

    // Tam kurucu round-trip: kütüphane kurucusunun ürettiği zincirin genesis
    // bloğu, doğrudan build çıktısına birebir eşit olmalı.
    let chain = Blockchain::new(Arc::new(PoWEngine::new(0)), None, chain_id, None);
    assert_eq!(
        chain.chain.len(),
        1,
        "fresh chain must hold exactly genesis"
    );
    assert_eq!(
        chain.chain[0].hash, block.hash,
        "Blockchain::new genesis hash != build_genesis_block hash (chain_id={chain_id})"
    );

    let mut obs = Vec::new();
    obs.push(format!("chain_id={chain_id}"));
    obs.push(format!("genesis_hash={}", block.hash));
    obs.push(format!("genesis_timestamp={}", block.timestamp));
    obs.push(format!("genesis_tx_root={}", block.tx_root));
    obs.push(format!("genesis_state_root={}", block.state_root));
    obs.push(format!(
        "genesis_validator_set_hash={}",
        block.validator_set_hash
    ));
    obs.push(format!("genesis_tx_count={}", block.transactions.len()));
    if let Some(genesis_tx) = block.transactions.first() {
        obs.push(format!("genesis_tx_hash={}", genesis_tx.hash));
    }
    obs.push(format!("built_accounts={}", rebuilt_state.accounts.len()));
    obs.push(format!(
        "built_supply={}",
        rebuilt_state.circulating_supply()
    ));
    obs.push(format!("boot_chain_hash={}", chain.chain[0].hash));
    obs
}

fn digest_of(observations: &[String]) -> String {
    let mut hasher = Sha256::new();
    for line in observations {
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CI Madde 1 sondası. determinism.yml bu testi iki ayrı temiz build'de
    /// koşup `GENESIS_HASH=` satırlarını karşılaştırır. İç assert'ler
    /// süreç-içi nondeterminizmi yakalar; buildler-arası eşitliği CI denetler.
    #[test]
    fn genesis_hash_deterministic() {
        // Mainnet=1 (asal hedef), Testnet=42, Devnet=1337, fallback=9999.
        let chain_ids = [1u64, 42, 1337, 9999];
        let mut observations = Vec::new();
        for &chain_id in &chain_ids {
            let run_a = probe_chain(chain_id);
            let run_b = probe_chain(chain_id);
            assert_eq!(
                run_a, run_b,
                "process-internal nondeterminism in genesis construction (chain_id={chain_id})"
            );
            observations.extend(run_a);
        }

        let digest = digest_of(&observations);
        println!("GENESIS_HASH={digest}");

        // Sahte-yeşil kilitleri: digest sabit uzunlukta; gözlem vektörü
        // 4 chain x en az 10 satır olmadan sessizce geçemez.
        assert_eq!(digest.len(), 64);
        assert!(
            observations.len() >= chain_ids.len() * 10,
            "genesis observation vector too short: {}",
            observations.len()
        );
    }
}
