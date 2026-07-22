# ADR-009: MASAK / Uyum — PoA Domain'e İzole

**Durum:** Kabul Edildi
**Tarih:** 2026-07-20
**Karar Verici:** Kullanıcı (onay) —  karar turu q8

## Bağlam
Türkiye finansal regülasyonu (MASAK AML), PoA domain banka pilotu için kritik. Soru: ağ geneli mi, PoA'ya izole mi? Ağ geneli compliance permissionless ilkesini bozar, sansür vektörü.

## Karar
**MASAK AML hook'ları + audit trail, SADECE PoA (regüle) domain'e izole:**
- **Address screening** (blacklist/sanction check — off-chain oracle).
- **Suspicious tx freeze** (PoA admin yetkili — permissionless'te değil).
- **Travel rule metadata** (off-chain, hash-on-chain).
- **Audit trail:** tüm PoA tx'ler append-only audit log (indeksli rapor), compliance report generator (CSV/JSON export).
- **PoA↔permissionless izolasyon mührü:** MASAK hook'ları PoA'dan permissionless'e sızıyor mu test-pinned.

## Sonuçlar
- **Pozitif:** PoA banka pilotu için regülasyon uyumu; permissionless ilkesi korunur; izolasyon tutarlı.
- **Negatif:** Sadece PoA domain compliance → permissionless tarafında AML yok (exchange'ler off-chain yapar).
- **Risk:** PoA admin freeze yetkisi kötüye kullanım → admin rotation + audit zorunlu.

## Uygunluk
Master-context (PoA izolasyonu, permissionless) ile tam uyumlu — MASAK PoA'da, permissionless'e sızma yok.

## İlgili
- `src/registry/poa_compliance.rs`, `src/registry/poa_audit.rs` (implementasyon — )
- ADR-004 (governance — PoA admin yetkisi)
- PoA Isolation CI kapısı (CI Madde 9) — genişletilir
