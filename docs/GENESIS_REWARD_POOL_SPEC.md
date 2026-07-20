# Genesis Validation Reward Pool — Teknik Spec

**Durum:** Draft v1 (Phase 11.6) → implementasyon Phase 11.8  
**ADR:** [ADR-001](../adr/ADR-001-genesis-reward-pool.md)  
**Kural:** Sabit 100M arz korunur; emisyon = 0; pool pre-allocate ile finanse edilir.

## 1. Amaç

PoS validator'lerine öngörülebilir güvenlik bütçesi sağlamak. Sabit arz + iki burn mekanizması olduğu için ödül yeni emisyonla finanse edilemez; bunun yerine genesis'te ayrılmış bir havuzdan epoch-bazlı dağıtılır.

## 2. Parametreler (config/mainnet-genesis.json)

```json
{
  "tokenomics": {
    "total_supply": 100_000_000,
    "validation_reward_pool": 10_000_000,   // %10 (ADR-001: %8-12 aralığı)
    "validation_pool_epochs": 100_000,      // ~yaklaşık X yıl
    "treasury_pool": 2_000_000              // %2 (governance/treasury)
  }
}
```

**Sabit arz kanıtı:** `circulating + pool + treasury + burned = 100M` her epoch'ta (invariant test).

## 3. Dağıtım Algoritması

```rust
// Per-epoch distribution
fn distribute_rewards(state, epoch) {
    let per_epoch = validation_reward_pool / validation_pool_epochs;
    let active_validators = state.registry.active_validators();
    let total_stake = active_validators.iter().map(|v| v.stake).sum();
    for v in active_validators {
        let share = per_epoch * v.stake / total_stake;  // stake-orantılı
        state.credit(&v.address, share);
        state.validation_reward_pool -= share;
    }
}
```

**Özellikler:**
- **Stake-orantılı:** büyük validator daha çok alır (PoS standardı).
- **Active-only:** inactive/unbonding validator pay almaz.
- **Slashed dahil değil:** slashed validator o epoch'ta pay almaz.
- **Pool tükenince:** dağıtım durur, economy fee-only'a geçer (ADR-006 priority fee).

## 4. Slash / Penalty Etkileşimi

- Slashed validator'un o epoch reward payı pool'a geri döner (kaybolmaz).
- Slash miktarı (`RegistryParams::malicious_slash_ratio_fixed`, şu an %100) ayrı — pool'dan değil validator stake'inden düşülür.

## 5. Invariant'lar (test-pinned)

1. `total_supply_constant`: her epoch sonrası `circulating + pool + treasury + burned == 100M`.
2. `pool_non_negative`: pool asla negatif olamaz (saturating dağıtım).
3. `slashed_gets_no_reward`: slashed validator pay almaz.
4. `inactive_gets_no_reward`: unbonding validator pay almaz.
5. `stake_proportional`: pay, stake ile orantılı (±1 rounding).
6. `pool_exhaustion_halts`: pool = 0 iken dağıtım durur.

## 6. Migration / Geçiş

- **Pre-mainnet (testnet):** küçük pool, hızlı epochs (geçiş testi).
- **Pool tükenince (yıllar sonra):** economy fee-only'a geçiş — priority fee (ADR-006) validator ödülünü devralır. Geçiş sürekli (sert geçiş yok) çünkü priority fee zaten dağıtılıyor.

## 7. CI Kapısı

- **"Economy Invariants" job:** 10K epoch simülasyonu — sabit arz + pool tükenmesi + slash etkileşimi.
- Fuzz target: random stake distribution + slashing → invariant'lar bozulmuyor.

## 8. İlgili Kod (Phase 11.8)

- `src/tokenomics/reward_pool.rs` — dağıtım schedule'ı.
- `config/mainnet-genesis.json` — pre-allocation.
- `src/core/account.rs` — pool bakiyesi (state root'ta).
- `src/chain/blockchain.rs` — epoch transition'da `distribute_rewards`.
