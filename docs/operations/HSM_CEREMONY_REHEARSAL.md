# HSM Ceremony Rehearsal — Task 11.20

**Status:** ADIM 2 rehearsal ledger.
**Hardware standard:** YubiHSM 2 (PKCS#11).
**Purpose:** Key ceremony dry-run kanıtı — mock geçmez, local disk geçmez, YubiHSM path geçer.
**Gate:** `Audit Prep (Task 11.20)` CI job'u bu dosyanın markerlarını doğrular.
**Budlumdevnet:** salt-okunur; dokunulmadı.

---

## 1. Giriş

Mainnet validator signing keys **yalnızca** YubiHSM 2 / PKCS#11 donanımsal sınırı içinde
oluşturulabilir. Bu belge, ceremony rehearsal'ın kanıtlarını tutar: mock geçmez,
local disk geçmez, gerçek YubiHSM path geçer.

## 2. Ceremony adımları ve kanıtlar

| Adım | Açıklama | Kanıt / Doğrulama | Durum |
|---|---|---|---|
| 2.1 | YubiHSM 2 cihaz envanteri | Seri numarası, firmware versiyonu, slot ID | ⏳ bekliyor |
| 2.2 | PKCS#11 mechanism ID doğrulaması | `test_pkcs11_parse_mechanism_hex_and_dec` testi | ✅ `src/crypto/pkcs11.rs` |
| 2.3 | PIN custody akışı | `BUD_HSM_PIN` env → `secrecy::Secret` → loglanmaz | ✅ `src/crypto/pkcs11.rs` |
| 2.4 | Backup quorum tatbikatı | 2/3 bağımsız custodian, encrypted backup | ⏳ bekliyor |
| 2.5 | Key rotation dry-run | Yeni key HSM içinde, eski key devre dışı | ⏳ bekliyor |
| 2.6 | BLS/PQ capability metadata | Vendor-native mekanizma ID'leri doğrulandı | ⏳ bekliyor |

## 3. Mock geçmez kanıtı

`src/crypto/mainnet_policy.rs` — `check_mainnet_validator_key_policy`:

```rust
// mainnet validator: yalnızca pkcs11 backend kabul edilir
match backend {
    "pkcs11" => { /* PIN env zorunlu */ },
    "hsm_mock" | "disk" | "local" => {
        return Err(MainnetKeyPolicyViolation::HsmMockBackend);
    }
    _ => return Err(MainnetKeyPolicyViolation::UnknownBackend),
}
```

**Kanıt:** `task11_20_mainnet_rejects_mock_and_disk_backends` testi
(`src/crypto/mainnet_policy.rs`) — `hsm_mock`, `disk`, ve boş backend
değerleri `MainnetKeyPolicyViolation` ile reddedilir.

## 4. PKCS#11 mechanism parsing

`src/crypto/pkcs11.rs` — `parse_mechanism`:

- Hex format (`0x...`) ve decimal format desteklenir.
- Vendor-native BLS/PQ mechanism ID'leri (ör: YubiHSM 2 için `0x00000001`-`0x000000FF` aralığı)
  güvenli çözülür.
- `test_pkcs11_parse_mechanism_hex_and_dec` testi ile doğrulandı.

## 5. PIN custody

- PIN `BUD_HSM_PIN` ortam değişkeni üzerinden okunur.
- `secrecy::Secret<String>` ile bellekte saklanır.
- PIN asla loglanmaz, disk dosyasına yazılmaz, hata mesajına dahil edilmez.
- `src/crypto/pkcs11.rs` PIN handling kodu bu kurallara uygundur.

## 6. Backup quorum

- Backup material yalnızca HSM recovery için şifreli saklanır.
- En az 2 bağımsız custodian gerekir.
- Lost HSM senaryosu: validator pause → incident ticket → replacement ceremony.

## 7. Key rotation dry-run

1. Yeni key HSM içinde generate edilir (export edilemez).
2. Public identity validator onboarding flow ile kaydedilir.
3. Eski key devre dışı bırakılır (silinmez, export edilemez).
4. Rotation kanıtı audit paketine eklenir.

## 8. BLS/PQ capability metadata

- `src/crypto/pkcs11.rs` `Mechanism::VendorDefined` ile native BLS/PQ imza desteği.
- Capability metadata, signer yapılandırmasına bağlanır.
- `task11_20_mainnet_rejects_unsupported_bls_pq_capability` testi ile doğrulandı.

## 9. Rehearsal sonrası kontrol listesi

- [ ] YubiHSM 2 cihazı envanterlendi (seri, firmware, slot)
- [ ] PKCS#11 mechanism ID'leri doğrulandı
- [ ] PIN custody akışı test edildi
- [ ] Backup quorum tatbikatı yapıldı
- [ ] Key rotation dry-run tamamlandı
- [ ] BLS/PQ capability metadata doğrulandı
- [ ] Tüm kanıtlar `docs/audit_prep/` altına kaydedildi

## 10. Gate Marker

Bu dosya, `scripts/check-audit-prep-gate.sh` tarafından doğrulanır:

```bash
check_contains "$root/docs/operations/HSM_CEREMONY_REHEARSAL.md" "HSM Ceremony Rehearsal"
check_contains "$root/docs/operations/HSM_CEREMONY_REHEARSAL.md" "Mock geçmez kanıtı"
```

---

*Bu dosya, `Audit Prep (Task 11.20)` CI gate'i tarafından doğrulanır.*
