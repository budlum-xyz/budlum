# Genesis Validation Reward Pool — Teknik Spec

**Durum:** Final v1 (Phase 11.6) → implementasyon Phase 11.8
**ADR:** [ADR-001](adr/ADR-001-genesis-reward-pool.md)
**SPEC_REVIEW:** [GENESIS_REWARD_POOL_SPEC_REVIEW.md](spec-review/GENESIS_REWARD_POOL_SPEC_REVIEW.md)
**INTERFACE_FROZEN:** true
**Kural:** Sabit 100M arz korunur; emisyon = 0; pool pre-allocation ile finanse edilir.

---

## 0. Interface Freeze (Phase 11.6)

Bu spec Phase 11.6 sonunda **interface-frozen** kabul edilir. Phase 11.8 implementasyonu aşağıdaki alan adlarını, invariant isimlerini ve dağıtım semantiğini değiştiremez; değişiklik gerekiyorsa yeni ADR açılır.

### 0.1 Genesis config alanları

`config/mainnet-genesis.json` altında mevcut `bud_tokenomics` bloğu genişletilir. Tüm miktarlar base-unit cinsindendir (`BUD_UNIT = 10^6`).

```json
{
  "bud_tokenomics": {
    "total_supply": 100000000000000,
    "validation_reward_pool": 10000000000000,
    "validation_pool_epochs": 100000,
    "treasury_pool": 2000000000000,
    "reward_pool_start_epoch": 0
  }
}
```

**Donmuş alanlar:** `validation_reward_pool`, `validation_pool_epochs`, `treasury_pool`, `reward_pool_start_epoch`. Mevcut Phase 11.2 `bud_tokenomics` alanları geriye uyumlu kalır; migration yoksa alanlar explicit default ile okunur.

### 0.2 Runtime interface

```rust
pub struct RewardPoolSchedule {
    pub validation_reward_pool: u64,
    pub validation_pool_epochs: u64,
    pub treasury_pool: u64,
    pub reward_pool_start_epoch: u64,
}

pub fn reward_for_epoch(
    schedule: &RewardPoolSchedule,
    epoch: u64,
    active_validator_stakes: &[(Address, u64)],
) -> Vec<(Address, u64)>;

pub fn apply_epoch_rewards(state: &mut AccountState, epoch: u64) -> Result<(), RewardPoolError>;
```

`reward_for_epoch` saf/deterministik olmalıdır; state'e dokunmaz. `apply_epoch_rewards` yalnız epoch geçişinde çağrılır.

## 1. Amaç

PoS validator'lerine öngörülebilir güvenlik bütçesi sağlamak. Sabit arz + burn mekanizmaları olduğu için ödül yeni emisyonla finanse edilemez; bunun yerine genesis'te ayrılmış bir havuzdan epoch-bazlı dağıtılır.

## 2. Parametreler

- **Pre-allocation oranı:** toplam arzın %10'u varsayılan; kabul edilebilir aralık %8-12.
- **Dağıtım schedule'ı:** `validation_pool_epochs` boyunca sabit per-epoch bütçe; rounding artığı son epoch'lara veya deterministik ilk validator'a dağıtılır.
- **Treasury pool:** toplam arzın %2'si; governance parametre değişiklikleri için kaynak, validator reward pool ile karıştırılmaz.

**Sabit arz kanıtı:** `total_bud_committed = circulating + staked + unbonding + validation_reward_pool + treasury_pool + total_burned` her epoch'ta `100_000_000 * BUD_UNIT` değerini aşamaz. V144 sonrası staked/unbonding arz hesabına dahildir.

## 3. Dağıtım Algoritması

```rust
fn reward_for_epoch(schedule, epoch, active_validator_stakes) -> Vec<(Address, u64)> {
    if epoch < schedule.reward_pool_start_epoch { return vec![]; }
    if schedule.validation_reward_pool == 0 { return vec![]; }
    if active_validator_stakes.is_empty() { return vec![]; }

    let per_epoch = schedule.validation_reward_pool / schedule.validation_pool_epochs;
    let total_stake: u128 = active_validator_stakes.iter().map(|(_, s)| *s as u128).sum();
    let mut remainder = per_epoch;
    let mut out = Vec::new();
    for (addr, stake) in active_validator_stakes {
        let share = ((per_epoch as u128) * (*stake as u128) / total_stake) as u64;
        remainder = remainder.saturating_sub(share);
        out.push((*addr, share));
    }
    if let Some((_, first_share)) = out.first_mut() {
        *first_share = first_share.saturating_add(remainder);
    }
    out
}
```

**Özellikler:** active-only, stake-orantılı, deterministik rounding, pool tükenince sıfır ödül.

## 4. Slash / Penalty Etkileşimi

- Slashed validator epoch reward listesine dahil edilmez.
- O epoch'ta dağıtılmayan pay pool'da kalır; yakılmaz.
- Slash miktarı validator stake'inden düşülür; reward pool'dan düşülmez.
- Slashed stake'in yakım/treasury akışı Phase 11.8 economy invariant testinde ayrıca kanıtlanır.

## 5. Treasury Governance Interface

Treasury pool yalnız minimal on-chain governance ile parametrelenir (ADR-004). Governance şu alanları değiştirebilir: `validation_pool_epochs`, `reward_pool_start_epoch`, per-epoch dağıtım üst sınırı. Governance **toplam arzı artıramaz**, permissionless/PoA izolasyon kurallarını değiştiremez.

## 6. Invariant'lar (test-pinned)

1. `total_supply_constant`: epoch sonrası `total_bud_committed + total_burned <= 100M * BUD_UNIT`.
2. `pool_non_negative`: pool asla negatif olamaz.
3. `slashed_gets_no_reward`: slashed validator pay almaz.
4. `inactive_gets_no_reward`: inactive/unbonding validator pay almaz.
5. `stake_proportional`: pay stake ile orantılıdır (±1 rounding).
6. `pool_exhaustion_halts`: pool = 0 iken dağıtım durur.
7. `treasury_not_validator_reward`: treasury pool validator reward olarak dağıtılamaz.

## 7. Migration / Geçiş

- **Pre-mainnet/testnet:** küçük pool ve hızlı epoch ayarıyla dry-run.
- **Mainnet ceremony:** gerçek treasury/reward pool adresleri ceremony dosyasında hash'e girer; placeholder plan alanları hash'e girmez.
- **Pool tükenince:** priority fee (ADR-006) validator teşvikini devralır; yeni emisyon yok.

## 8. CI Kapısı

Phase 11.6 spec kapısı: `scripts/check-spec-coverage.sh` bu dosyada `INTERFACE_FROZEN: true` marker'ını ve review kaydını zorunlu tutar. Phase 11.8 kod kapısı: Economy Invariants job'u 10K epoch simülasyonu + random stake/slash property testlerini koşar.

## 9. İlgili Kod (Phase 11.8)

- `src/tokenomics/reward_pool.rs` — dağıtım schedule'ı.
- `config/mainnet-genesis.json` — pre-allocation.
- `src/core/account.rs` — supply denominator ve pool bakiyesi.
- `src/chain/blockchain.rs` — epoch transition'da `apply_epoch_rewards`.
