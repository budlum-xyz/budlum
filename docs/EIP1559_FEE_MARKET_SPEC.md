# EIP-1559 Fee Market — Teknik Spec

**Durum:** Final v1 (Task 11.6) → implementasyon Task 11.8
**ADR:** [ADR-006](adr/ADR-006-eip1559-fee-market.md)
**SPEC_REVIEW:** [EIP1559_FEE_MARKET_SPEC_REVIEW.md](spec-review/EIP1559_FEE_MARKET_SPEC_REVIEW.md)
**INTERFACE_FROZEN:** true
**Kural:** Base fee yakılır; priority fee blok üreticisine/validator'e gider; sabit arz korunur; metabolic burn ile çakışmaz.

---

## 0. Interface Freeze (Task 11.6)

Bu spec Task 11.6 sonunda **interface-frozen** kabul edilir. Task 11.8 implementasyonu aşağıdaki transaction alanlarını, fee hesap fonksiyonlarını ve invariant isimlerini değiştiremez; değişiklik gerekiyorsa yeni ADR açılır.

### 0.1 Transaction alanları

```rust
pub struct Transaction {
    pub fee: u64,          // legacy alan; migration'da max_fee'ye map edilir
    pub max_fee: u64,      // kullanıcı toplam gas başına ödemeyi kabul ettiği üst sınır
    pub priority_fee: u64, // validator/blok üreticisi tip üst sınırı
}
```

Legacy transaction kuralı: `max_fee == 0 && priority_fee == 0` ise `max_fee = fee`, `priority_fee = 0` kabul edilir. Yeni EIP-1559 transaction'larda `max_fee` zorunludur.

### 0.2 Fee market interface

```rust
pub struct FeeMarketParams {
    pub target_gas: u64,
    pub elasticity_multiplier: u64,
    pub base_fee_max_change_denominator: u64,
    pub min_base_fee: u64,
}

pub struct EffectiveFee {
    pub base_fee_burned: u64,
    pub priority_fee_paid: u64,
}

pub fn next_base_fee(parent_base_fee: u64, parent_gas_used: u64, params: &FeeMarketParams) -> u64;

pub fn effective_fee(tx: &Transaction, block_base_fee: u64) -> Result<EffectiveFee, FeeError>;
```

`effective_fee` `tx.max_fee < block_base_fee` durumunda işlemi reddeder; base fee asla `min(max_fee, base_fee)` ile düşürülmez.

## 1. Amaç

Tx fee pricing + dağıtım. Öngörülebilir fee tahmini (EIP-1559 standardı), deflationary base fee (sabit arz etkisi), validator aktivite teşviki (priority fee).

## 2. Transaction Migration

- Eski tx: `fee` alanı korunur; `max_fee = fee`, `priority_fee = 0`.
- Yeni tx: `max_fee >= block_base_fee` olmak zorunda; aksi halde mempool ve block validation reddeder.
- `priority_fee` yalnız `max_fee - block_base_fee` kadar ödenebilir.

## 3. Base Fee Adjustment Algoritması

```rust
const TARGET_GAS: u64 = 10_000_000;
const BASE_FEE_MAX_CHANGE_DENOM: u64 = 8; // max %12.5 değişim/blok
const ELASTICITY_MULTIPLIER: u64 = 2;

fn next_base_fee(parent_base_fee: u64, parent_gas_used: u64) -> u64 {
    let gas_delta = parent_gas_used as i128 - TARGET_GAS as i128;
    let adjustment = parent_base_fee as i128 * gas_delta
        / (TARGET_GAS as i128 * BASE_FEE_MAX_CHANGE_DENOM as i128);
    ((parent_base_fee as i128) + adjustment).max(0) as u64
}
```

**Özellikler:** yoğun blokta base fee artar; boş blokta düşer; blok başına değişim bounded; `min_base_fee` parametresi istenirse sıfırın üstünde taban sağlar.

## 4. Fee Dağıtımı

```rust
fn effective_fee(tx: &Transaction, block_base_fee: u64) -> Result<EffectiveFee, FeeError> {
    if tx.max_fee < block_base_fee {
        return Err(FeeError::MaxFeeBelowBaseFee);
    }
    let tip_cap = tx.max_fee.saturating_sub(block_base_fee);
    let priority_fee_paid = tx.priority_fee.min(tip_cap);
    Ok(EffectiveFee {
        base_fee_burned: block_base_fee,
        priority_fee_paid,
    })
}
```

- **Base fee:** yakılır (`AccountState::burn_from` veya dedicated burn path); validator'e gitmez.
- **Priority fee:** blok üreticisine/validator'e gider.
- **Toplam kullanıcı maliyeti:** `base_fee_burned + priority_fee_paid`, `max_fee` değerini görevz.

## 5. Metabolic Burn ile Etkileşim

İki paralel mekanizma vardır:

- **EIP-1559 base fee:** tx fee pricing + burn.
- **Metabolic burn:** storage/bridge kullanımından doğan ayrı ekonomik yakım.

Çakışma yoktur; toplam burn = base fee burn + metabolic burn. Sabit arz invariant'ı V144 sonrası denominator ile hesaplanır: `circulating + staked + unbonding + pools + total_burned <= 100M * BUD_UNIT`.

## 6. Invariant'lar (test-pinned)

1. `base_fee_change_bounded`: base fee blok başına max %12.5 değişir.
2. `max_fee_below_base_fee_rejected`: base fee'yi karşılamayan tx reddedilir.
3. `effective_tip_cannot_exceed_priority_fee`: validator'e giden ≤ priority_fee.
4. `max_fee_respected`: kullanıcı max_fee'den görevla ödemez.
5. `base_fee_burned_not_paid_to_validator`: base fee validator bakiyesine eklenmez.
6. `total_supply_constant_with_burn`: base fee burn + metabolic burn arzı artırmaz.
7. `legacy_tx_compatible`: `fee`-only tx migration ile kabul edilir.
8. `base_fee_stabilizes`: yoğunluk senaryosunda base fee osilasyonu bounded kalır.

## 7. CI Kapısı

Task 11.6 spec kapısı: `scripts/check-spec-coverage.sh` bu dosyada `INTERFACE_FROZEN: true` marker'ını ve review kaydını zorunlu tutar. Task 11.8 kod kapısı: Economy Invariants job'u random tx akışı + base fee + pool + burn invariant'larını koşar.

## 8. İlgili Kod (Task 11.8)

- `src/chain/fee_market.rs` — base fee adjustment + effective fee.
- `src/core/transaction.rs` — `max_fee`/`priority_fee` alanları + migration.
- `src/chain/blockchain.rs` — blok üretiminde fee distribution.
- `src/core/account.rs` — burn accounting.
- `src/rpc/api.rs` — `bud_estimateGas`, `bud_gasPrice` EIP-1559'a bağlanır.
