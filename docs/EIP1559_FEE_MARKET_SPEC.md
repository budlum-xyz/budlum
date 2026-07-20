# EIP-1559 Fee Market — Teknik Spec

**Durum:** Draft v1 (Phase 11.6) → implementasyon Phase 11.8  
**ADR:** [ADR-006](../adr/ADR-006-eip1559-fee-market.md)  
**Kural:** Base fee yakılır (deflationary); priority fee validator'e; sabit arz korunur; mevcut metabolic burn ile uyumlu.

## 1. Amaç

Tx fee pricing + dağıtım. Öngörülebilir fee tahmini (EIP-1559 standardı), deflationary base fee (sabit arz etkisi), validator aktivite teşviki (priority fee).

## 2. Transaction Yapısı (migrasyon)

```rust
pub struct Transaction {
    // ... mevcut alanlar ...
    pub fee: u64,              // legacy (geri uyumlu — = max_fee olarak map)
    pub max_fee: u64,          // EIP-1559: kullanıcı ödemeye razı olduğu max base fee
    pub priority_fee: u64,     // EIP-1559: validator'e giden tip
    // ...
}
```

**Migration:** eski tx'ler (`fee` set, `max_fee`/`priority_fee` = 0) → `max_fee = fee`, `priority_fee = 0`. Test: hem format uyumlu.

## 3. Base Fee Adjustment Algoritması

```rust
// Per-block base fee adjustment (EIP-1559 standard)
const TARGET_GAS: u64 = 10_000_000;       // hedef blok gas
const BASE_FEE_MAX_CHANGE_DENOM: u64 = 8; // max %12.5 değişim/blok
const ELASTICITY_MULTIPLIER: u64 = 2;

fn next_base_fee(parent_base_fee, parent_gas_used) -> u64 {
    let gas_delta = parent_gas_used as i128 - TARGET_GAS as i127;
    let adjustment = parent_base_fee as i128 * gas_delta
        / (TARGET_GAS as i128 * BASE_FEE_MAX_CHANGE_DENOM as i128);
    ((parent_base_fee as i128) + adjustment).max(0) as u64
}
```

**Özellikler:**
- Yoğun blok (>TARGET) → base fee artar (max %12.5/blok).
- Boş blok (<TARGET) → base fee düşer.
- Osilasyon → osilasyon testi (yoğunluk senaryosunda stabilize).

## 4. Fee Dağıtımı (effective fee hesabı)

```rust
fn effective_fee(tx, block_base_fee) -> (u64 /*burned*/, u64 /*to_validator*/) {
    let base = min(tx.max_fee, block_base_fee);
    let tip_cap = tx.max_fee.saturating_sub(base);
    let effective_tip = min(tx.priority_fee, tip_cap);
    (base, effective_tip)
}
```

- **Base fee** (`base`): yakılır (deflationary — `burn_from`).
- **Effective tip** (`effective_tip`): blok üreten validator'e gider.

## 5. Metabolic Burn ile Etkileşim

İki paralel mekanizma:
- **EIP-1559 base fee:** tx fee pricing + burn (her tx).
- **Metabolic burn (usage-based):** B.U.D. storage usage + bridge burn (storage/bridge işlemleri).

**Çakışma yok:** ikisi farklı amaç. Toplam burn = base fee burn + metabolic burn. Sabit arz invariant: `circulating + pools + total_burned == 100M`.

## 6. Invariant'lar (test-pinned)

1. `base_fee_change_bounded`: base fee blok-başına max %12.5 değişir.
2. `effective_tip_cannot_exceed_priority_fee`: validator'e giden ≤ priority_fee.
3. `max_fee_respected`: kullanıcı max_fee'den fazla ödemez.
4. `total_supply_constant_with_burn`: base fee burn + metabolic burn + circulating + pools == 100M.
5. `legacy_tx_compatible`: `fee`-only tx derleniyor + doğru fee uygulanıyor.
6. `base_fee_stabilizes`: yoğunluk senaryosunda base fee osilasyonu sönümleniyor (property test).

## 7. CI Kapısı

- **"Economy Invariants" job** (ADR-001 ile ortak): sabit arz + base fee + pool.
- Fuzz target: random tx akışı + yoğunluk → base fee + fee dağıtımı invariant'ları.
- Gas estimation: `bud_estimateGas` RPC (zaten var) EIP-1559 base fee'u döner.

## 8. İlgili Kod (Phase 11.8)

- `src/chain/fee_market.rs` — base fee adjustment + effective fee.
- `src/core/transaction.rs` — `max_fee`/`priority_fee` alanları + migration.
- `src/chain/blockchain.rs` — blok üretiminde fee distribution (burn + validator).
- `src/core/account.rs` — `burn_from` (base fee burn).
- `src/rpc/api.rs` — `bud_estimateGas`, `bud_gasPrice` (EIP-1559'a bağlanır).
