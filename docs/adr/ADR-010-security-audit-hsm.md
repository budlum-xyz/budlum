# ADR-010: Güvenlik — Threat Model + Audit Prep + HSM (Mainnet Öncesi)

**Durum:** Kabul Edildi
**Tarih:** 2026-07-20
**Karar Verici:** Kullanıcı (onay) — Task 11.6 karar turu q10

## Bağlam
Bug bounty + V-bulgu süreci aktif ama bağımsız denetim hazırlığı, sistemli tehdit modeli, validator operatör HSM politikası eksik. Bunlar itibar + güvenlik için mainnet öncesi zorunlu.

## Karar
**Üçü birden, mainnet öncesi zorunlu:**
1. **Threat model dokümanı** (STRIDE): consensus, p2p, wallet, bridge tehdit senaryoları. v1 Task 11.6'da, v2 (tüm görevların azaltmalarıyla) Task 11.20'de.
2. **Audit prep paketi** (`docs/audit_prep/`): spec/test/fuzz evidence derlemi, bağımsız auditör için index, bilinen sınırlar + kabul edilmiş riskler.
3. **HSM key policy** (`docs/VALIDATOR_KEY_MANAGEMENT.md`): validator operatörleri için HSM zorunluluğu (mainnet'te), soft launch → HSM migration yolu, anahtar rotasyonu/yedekleme/kayıp senaryosu.

## Sonuçlar
- **Pozitif:** Bağımsız denetime hazır; sistemli güvenlik analizi; operatör anahtar güvenliği.
- **Negatif:** Dokümantasyon + dry-run review süresi.
- **Risk:** Threat model eksikse blind spot kalır → sürekli güncellenmeli (v1→v2).

## Uygunluk
Master-context (CI-tek-otorite, no-CI-bypass) ile uyumlu — audit prep CI evidence'ına dayanır.

## İlgili
- `docs/THREAT_MODEL.md` (v1 Task 11.6, v2 Task 11.20)
- `docs/audit_prep/` (Task 11.20)
- `docs/VALIDATOR_KEY_MANAGEMENT.md` (Task 11.20)
- Bug bounty (`SECURITY.md`, `docs/BUG_BOUNTY.md`) — sürekli
