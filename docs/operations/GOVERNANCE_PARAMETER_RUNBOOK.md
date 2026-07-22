# Governance Parameter Rollout — Task 11.16

**Status:** ADIM 5 — operational runbook.
**Purpose:** Parameter change rollout, voter education, emergency procedures.
**Gate:** `scripts/check-governance-invariants.sh` — yeni marker.
**Budlumdevnet:** salt-okunur; dokunulmadı.

---

## 1. Giriş

Task 11.16 governance: whitelist-bound parameter proposals + activation timelock.
Bu belge, parametre değişikliği rollout adımlarını, voter eğitimini ve acil
durum prosedürlerini tanımlar.

## 2. Parameter whitelist

Yalnızca aşağıdaki parametreler governance ile güncellenebilir:

| Parameter | Min | Max | Açıklama |
|---|---|---|---|
| `min_stake` | 1 | — | Minimum validator stake |
| `unbonding_epochs` | 1 | 100_000 | Unbonding süresi |
| `double_sign_slash_ratio_fixed` | 1 | 10_000 | Double-sign slash oranı (FIXED_POINT_SCALE) |
| `liveness_slash_ratio_fixed` | 1 | 10_000 | Liveness slash oranı |
| `malicious_slash_ratio_fixed` | 1 | 10_000 | Malicious slash oranı |
| `base_fee` | 1 | 1_000_000 | Minimum işlem ücreti |
| `block_reward` | 0 | 10_000 * BUD_UNIT | Blok ödülü |

## 3. Rollout adımları

1. **Proposal oluştur:** `ProposalType::ParameterUpdate(key, value)`
2. **Vote periyodu:** `end_epoch` (min 10, max 100_000 epoch)
3. **Activation timelock:** `GOVERNANCE_PARAMETER_ACTIVATION_DELAY_EPOCHS`
4. **Execute:** `advance_epoch` sonrası `activation_ready(current_epoch)` kontrolü
5. **Verify:** `validate_governance_parameter_update` ile yeni değer kontrolü

## 4. Voter eğitim

- **Vote weight:** Stake miktarına orantılı. Transfer sonrası eski weight snapshot.
- **Quorum:** 33% stake gerekir.
- **Proposal limit:** Aktif maksimum 100 proposal (`MAX_ACTIVE_PROPOSALS`).
- **Emergency halt:** `GOVERNANCE_PARAMETER_WHITELIST` dışındaki parametreler
  güncellemeye çalışıldığında fail-closed.

## 5. Acil durum prosedürleri

### 5.1 Parameter değişikliği saldırısı
- Etkilenen parametre hemen eski değerine döndürülır.
- `apply_registry_parameter_update` bounds kontrolü zaten var.

### 5.2 Proposal spam
- `MAX_ACTIVE_PROPOSALS = 100` limiti.
- Aşım durumunda yeni proposal oluşturma reddedilir.

## 6. Gate Marker

Bu dosya, `scripts/check-governance-invariants.sh` tarafından doğrulanır:

```bash
check_contains "$root/docs/operations/GOVERNANCE_PARAMETER_RUNBOOK.md" "Governance Parameter Rollout"
check_contains "$root/docs/operations/GOVERNANCE_PARAMETER_RUNBOOK.md" "Parameter whitelist"
```

---

*Bu dosya, `Governance Invariants (Task 11.16)` CI gate'i tarafından doğrulanır.*
