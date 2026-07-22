# D3 — Legacy Declared-Depth Proof Kaldırma: Uygulama Planı (2026-07-22)

**Karar (Ayaz):** Legacy self-declared PoW proof yolunu **tamamen kaldır**.
**Hazırlayan:** ARENA1 · **Durum:** ✅ **STAGE 1 (fonksiyonel kaldırma) TAMAM — CI yeşil (`f74a6b9`, 33/0).** Legacy `PoWFinalityAdapter` always-reject. Full dead-code removal (variant/struct silme) opsiyonel follow-up (yüksek test-churn, güvenlik kazancı yok — adapter zaten inert).

---

## 0. Güvenlik hedefi ZATEN karşılanmış

`src/chain/blockchain.rs:1151-1154` — bridge mint yalnızca `POW_HEADER_CHAIN_ADAPTER` ("pow-header-chain-v1") kabul eder:
```
&& domain.finality_adapter != POW_HEADER_CHAIN_ADAPTER
→ "Bridge mint from PoW domains requires pow-header-chain-v1 finality"
```
Legacy "pow-confirmation-depth" (self-declared) **halihazırda mint yetkisi alamaz**. D3'ün kalan değeri: legacy adapter'ın **finalize yeteneğini** (mint dışı commitment finality) ve dead code'u kaldırmak.

## 1. Serileştirme bulgusu (risk düşürüldü)

- `DomainCommitment` kalıcı storage'a yazılır (`src/storage/db.rs:644 save_domain_commitment`).
- AMA commitment yalnızca `finality_proof_hash: Hash32` saklar — **FinalityProof'un kendisi persist edilmez** (verify edilip hash alınır, proof atılır).
- Sonuç: `FinalityProof::PoW` variant'ı silmek **persist verisini bozmaz**. (Yine de RPC/wire uyumsuzluğu için bincode variant index kayması not edilmeli — pre-mainnet kabul edilebilir.)

## 2. Legacy = ne, yeni = ne

| | Legacy (kaldırılacak) | Yeni (kalır) |
|---|---|---|
| Proof variant | `FinalityProof::PoW { confirmations, total_work_hint, declared_head_hash, declared_cumulative_work }` | `FinalityProof::PoWHeaderChain { headers }` |
| Adapter struct | `PoWFinalityAdapter` | `PoWHeaderChainFinalityAdapter` |
| Adapter adı | `"pow-confirmation-depth"` | `"pow-header-chain-v1"` (const `POW_HEADER_CHAIN_ADAPTER`) |
| Doğrulama | self-declared work+depth | bounded contiguous header chain recompute |

## 3. Etkilenen dosyalar (tam liste)

### Üretim kodu
| Dosya | Değişiklik |
|---|---|
| `src/domain/finality_adapter.rs` | `FinalityProof::PoW` variant + `PoWFinalityAdapter` struct+impl + ilgili testler kaldır |
| `src/chain/blockchain.rs:22` | `PoWFinalityAdapter` import'u kaldır; dispatch'te "pow-confirmation-depth" arm'ı kaldır (:597, :905 çevresi) |
| `src/main.rs:684` | `ConsensusType::PoW => (PoW, "pow-confirmation-depth", 64)` → `"pow-header-chain-v1"` + pow_parameters |
| `src/chain/genesis.rs:44` | varsayılan `finality_adapter: "pow-confirmation-depth"` → yeni adapter + pow_parameters |
| `src/rpc/api.rs:202` | "Legacy operator helper for a prover bond" referansı güncelle |

### Test fixture'ları (~20 dosya, "pow-confirmation-depth" → "pow-header-chain-v1" + pow_parameters)
- `src/tests/`: bridge_lifecycle, byzantine_settlement, chaos, distributed_settlement, settlement_prod, pow_light_client (+ diğerleri)
- `src/rpc/tests.rs:206`, `src/domain/finality_adapter.rs` testleri
- `pow_light_client.rs:31` `tur13_5_..._legacy_does_not` → legacy artık yok, test yeniden tasarlanmalı

⚠️ **Risk:** pow-header-chain-v1 `pow_parameters` (min/max difficulty, max_headers, min_cumulative_work) ister. Fixture'lar bu parametreleri + gerçek mine edilmiş header zinciri sağlamalı — mevcut self-declared fixture'lardan daha karmaşık. Bazı testler finality'yi BYPASS ediyorsa (doğrudan commitment insert) daha az etkilenir.

## 4. Önerilen uygulama sırası (CI-iteratif, kör DEĞİL)

1. **Önce blockchain.rs dispatch + import** (derleme hatası verir → hangi testlerin bağımlı olduğunu CI gösterir).
2. Test fixture'larını tek tek güncelle (her push CI'da doğrulanır).
3. main.rs/genesis.rs varsayılan + pow_parameters.
4. pow_light_client + finality_adapter testleri yeniden tasarla.
5. rpc/api.rs doc.

## 5. Neden kör tek-push yapılmıyor

Sandbox 2GB → `cargo test` codegen OOM. D3 ~25 dosyayı etkiler; kör push = çoklu CI-kırmızı iterasyon (her run 15-20dk) = green-CI önceliğine aykırı. CI runner yegâne doğrulayıcı olduğundan, değişiklikler **küçük staging commit'lerle** (her biri CI yeşil) ilerlemeli.

## 6. Alternatif (düşük risk): fonksiyonel kaldırma

Eğer tam variant/struct silinmesi çok riskliyse:
- `PoWFinalityAdapter::verify_finality` → her zaman `Rejected("legacy PoW finality removed")` döndür (adapter ölü, finalize edemez).
- Variant + struct bincode uyumu için inert tutulur (dead code).
- Varsayılan adapter pow-header-chain-v1'e çevrilir.
- Bu, `pow_finality_requires_...` testi (Finalized bekler) dahil birkaç testi kırar ama ~20 fixture'dan çok daha az.
- **Öneri:** güvenlik hedefi zaten karşılandığı için, v1 için fonksiyonel kaldırma + belgeleme yeterli; tam dead-code temizliği v1 sonrası.

---

*Karar Ayaz'ın. Bu plan ARENA1'in derin araştırmasıdır. Tam silme vs fonksiyonel kaldırma, CI-iterasyon maliyetine bağlı olarak Ayaz/ARENA1 kararı.*
