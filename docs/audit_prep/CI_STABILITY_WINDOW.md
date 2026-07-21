# CI Stability Window — Phase 11.20 Launch Lock

**Purpose:** 7 günlük launch-lock stabilite penceresi için günlük kayıt.  
**Gate:** `Audit Prep (Phase 11.20)` CI job'u bu dosyanın markerlarını doğrular.  
**Kural:** CI tek hakemdir. Lokal kontrol yalnızca ön doğrulama sayılır.  
**Budlumdevnet:** salt-okunur; bu pencere dışındaki tüm değişikliklerden etkilenmez.

---

## 1. Giriş

Mainnet launch onayı için `MAINNET_LOCKDOWN_CHECKLIST.md` şartı: **7 ardışık gün boyunca main branch required + extended tüm gate'leri yeşil**. Bu dosya, o pencerenin günlük kanıtlarını tutar.

## 2. Günlük Kayıt Formatı

Her gün, aşağıdaki tabloya bir satır ekleyin:

| Tarih (UTC) | main SHA | Check-run summary | Failure list | Aksiyon | Sorumlu |
|---|---|---|---|---|---|

### Örnek:

| Tarih (UTC) | main SHA | Check-run summary | Failure list | Aksiyon | Sorumlu |
|---|---|---|---|---|---|
| 2026-07-21 | `01c8be2` | 28/28 success, 0 failure | — | Pencerenin gün 1 | ARENA3 |

## 3. Günlük Stabilite Tablosu

| Gün | Tarih (UTC) | main SHA | Summary | Failures | Aksiyon | Sorumlu |
|---|---|---|---|---|---|---|
| 1 | 2026-07-21 | `01c8be2` | 28/28 success, 0 failure | — | Pencerenin gün 1 — ARENA3 kontrolü | ARENA3 |

## 4. Kırmızı Senaryosu ve Root-Cause Zinciri

Eğer bir gün kırmızı çıkarsa, aşağıdaki formatı kullanın:

```md
### [Gün N — YYYY-MM-DD] KIRMIZI: <job adı>

**SHA:** `<sha>`
**Failure:** `<job>` — `<conclusion>`
**Root cause:** ...
**Fix commit:** `<sha>` — `<commit subject>`
**Ne bekliyor:** fix push + CI SLEEP
**Kim karar verecek:** CI
```

## 5. Gate Marker

Bu dosya varlığı, `scripts/check-audit-prep-gate.sh` tarafından doğrulunur:

```bash
check_contains "$root/docs/audit_prep/CI_STABILITY_WINDOW.md" "CI Stability Window"
check_contains "$root/docs/audit_prep/CI_STABILITY_WINDOW.md" "7 günlük launch-lock stabilite penceresi"
```

## 6. Güncel Durum

- **Pencerenin başlangıç tarihi:** 2026-07-21
- **Gün 1 (2026-07-21):** `01c8be2` — 28/28 success, 0 failure ✅
- **Gün 2 (2026-07-21):** `6b88ed6` — CI çalışıyor (docs-only değişiklik)
- **Hedef gün:** 2026-07-28 (7. gün)
- **Durum:** 🟡 Pencerenin gün 1-2'si yeşil

---

*Bu dosya `docs/audit_prep/` altında, `Audit Prep (Phase 11.20)` CI gate'i tarafından doğrulanır.*
