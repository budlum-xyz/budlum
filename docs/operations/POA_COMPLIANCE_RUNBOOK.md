# PoA Compliance Runbook — Task 11.18

**Status:** ADIM 6 — operational runbook.
**Scope:** MASAK/AML compliance hooks for PoA domain only.
**Gate:** `scripts/check-poa-compliance-gate.sh` — yeni marker.
**Budlumdevnet:** salt-okunur; dokunulmadı.

---

## 1. Giriş

PoA domain, kurumsal/regüle taraflar için permissioned bir alt-alandır.
`src/registry/poa_compliance.rs` bu domain'e özel compliance hook'ları
içerir. Bu belge, bu hook'ların operasyonel kullanımını, off-chain oracle
entegrasyonunu ve admin auth akışını tanımlar.

## 2. Off-chain sanctions/watchlist oracle güven modeli

- **Oracle kaynağı:** Harici sanctions list (ör: OFAC SDN, MASAK).
- **Güncelleme frekansı:** Her 1000 blok (≈ 1 gün).
- **Güvenlik modeli:** Oracle sadece hash referansı sağlar;
  `oracle_reference_hash` zincirde saklanır. Raw liste hash olarak değil,
  hash setleri olarak kaydedilir.
- **Fail-closed:** Oracle erişilemezse, yeni screening güncellemeleri
  reddedilir; mevcut freeze kayıtları etkin kalır.

## 3. Admin authorization

- PoA admin listesi, `PoaComplianceRegistry::authorized_admins` içinde
  `BTreeMap<Address, ()>` olarak saklanır.
- `screen_address` ve `freeze_suspicious` yalnızca authorized admin
  tarafından çağrılabilir.
- Admin yetkisi, `ComplianceDomainKind::PoA` için geçerlidir;
  permissionless domain'de her zaman fail-closed döner.

## 4. Export privacy

- `export_audit_csv` / `export_audit_json` yalnızca hash/root verir.
- Raw KYC/passport/national_id verisi **asla** zincire yazılmaz.
- Export endpoint'leri read-only'dir; state değiştirmez.

## 5. Cross-domain/RPC integration tests

- `is_frozen(Permissionless, addr)` PoA freeze state'ini asla yansıtmaz.
- `screen_address(Permissionless, addr)` her zaman fail-closed döner.
- RPC `bud_poaScreenAddress` yalnızca PoA domain için geçerlidir.

## 6. Gate Marker

Bu dosya, `scripts/check-poa-compliance-gate.sh` tarafından doğrulanır:

```bash
check_contains "$root/docs/operations/POA_COMPLIANCE_RUNBOOK.md" "PoA Compliance Runbook"
check_contains "$root/docs/operations/POA_COMPLIANCE_RUNBOOK.md" "off-chain oracle"
```

---

*Bu dosya, `PoA Compliance Isolation (Task 11.18)` CI gate'i tarafından doğrulanır.*
