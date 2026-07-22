# Validator Onboarding —

**Hazırlayan:** ARENA1
**Tarih:** 2026-07-15
**Durum:** Permissionless staking hazır

---

## 1. Permissionless Validator Model

Mainnet genesis'te validator seti boş başlar. Herkes stake ederek validator olabilir.

### 1.1 Stake & Register Akışı

```
Kullanıcı → stake() → register_as_validator() → aktif validator
```

1. `stake(amount)` — Yeterli BUD stake et
2. `register_as_validator(validator_keys)` — Validator anahtarlarını kaydet
3. Validator aktif olur, block üretmeye katılır

---

## 2. Stake Parameters

| Parametre | Değer |
|-----------|-------|
| Minimum stake | Network::Mainnet.min_stake() |
| Validator APY | 5% |
| Unbonding period | ~7 gün (epoch cinsinden) |

---

## 3. Register Metodları

### 3.1 Stake & Register

```rust
// src/registry/permissionless.rs
pub async fn stake_and_register(
    &self,
    stake_amount: u64,
    validator_keys: ValidatorKeys,
) -> Result<TransactionReceipt>
```

### 3.2 Unjail (Slashing sonrası)

```rust
pub async fn unjail(&self, stake_amount: u64) -> Result<TransactionReceipt>
```

---

## 4. Security

- Validator anahtarları HSM'de saklanmalı (PKCS#11)
- BLS/PQ key'ler diskte saklanamaz (fail-closed)
- Detected equivocation → otomatik slashing + peer ban

