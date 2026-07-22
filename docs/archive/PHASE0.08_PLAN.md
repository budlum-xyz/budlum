# Phase 5 — Evrensel Mutabakat ve Teknik Olgunlaşma

> **Phase 5 = Phase 0.46 (Budlum Evrensel Geçiş Kapısı)**
> **Hazırlayan:** ARENA1
> **Tarih:** 2026-07-16
> **Durum:** Aktif Geliştirme (Kullanıcı Olumlu Feedback'i ile Başlatıldı)

---

## 1. Phase 5 Hedefleri

### 1.1 Ana Hedef
Budlum'un **"Evrensel Mutabakat Katmanı"** kimliğini teknik olarak tamamlamak; dış zincirler (EVM, Solana vb.) ile olan bağı kurmak ve mobil cihazların ağdaki egemenliğini pekiştirmek.

### 1.2 Alt Hedefler

| # | Hedef | Kapsam | Sahip |
|---|-------|--------|-------|
| 5.1 | Universal Relayer (Master Key) | Dış zincir işlemleri için imza şablonları | ARENA1 |
| 5.2 | Mobil B.U.D. Light Node | Düşük kaynaklı cihazlarda depolama mantığı | ARENA1 |
| 5.3 | SocialFi Hard Pruning Worker | NFT yakılınca fiziksel veri silme | ARENA1 |
| 5.4 | Felaket Tatbikatı (Chaos v2) | Chain-halt senaryosu ve kurtarma | ARENA2/3 |
| 5.5 | AI Data Marketplace Beta | Veri satış kontratları | ARENA1 |

---

## 2. Görev Detayları

### 2.1 Görev 5.1: Universal Relayer - Master Key
**Dosya:** `src/core/transaction.rs`, `src/cross_domain/`

**Yapılacaklar:**
1. `ExternalChain` enum'u ekle (Ethereum, Solana, Bitcoin, etc.).
2. `ExternalTransaction` yapısı oluştur: Budlum cüzdanı ile imzalanan, relayer tarafından dış zincire basılan payload.
3. RPC metodu: `bud_relayerPrepareExternalTx`.

### 2.2 Görev 5.2: Mobil B.U.D. Light Node
**Dosya:** `budzero/bud-node/src/sharding.rs`

**Yapılacaklar:**
1. `MobileConfig` ile batarya ve Wi-Fi dostu depolama limitleri getir.
2. `ShardManager`'da "Kendi Verim" (Self-Host) önceliğini kodla.

### 2.3 Görev 5.3: SocialFi Hard Pruning Worker
**Dosya:** `src/network/node.rs`

**Yapılacaklar:**
1. `Node::run` içinde `NftBurn` olaylarını dinleyen bir worker ekle.
2. Sinyal geldiğinde `storage_node.store().delete(cid)` çağrısı yap.

---

## 3. Phase 5 Başlangıç Kaydı (STATUS_ONLINE)

Ajanlar Phase 5 görev dağılımına göre çalışmaya başlamıştır. Kullanıcı onayı (olumlu feedback) kesintisiz ilerleme için temel alınmıştır.

---

**Not:** Bu belge Phase 5 sürecinin yol haritasıdır.
Force-push YASAK.
