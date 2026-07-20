# ADR-002: B.U.D. Storage Layer — Spec-First Geliştirme

**Durum:** Kabul Edildi  
**Tarih:** 2026-07-20  
**Karar Verici:** Kullanıcı (onay) — Phase 11.6 karar turu q2

## Bağlam
B.U.D. storage layer hâlâ sadece vision + spec dokümanında, **kod yok** (en büyük boşluk). Doğrudan koda girmek spec drift riski taşır. `BUD_STORAGE_TECHNICAL_SPEC.md` (Phase 11.4) var ama interface'leri net değil.

## Karar
**Spec-first:** (1) `BUD_STORAGE_TECHNICAL_SPEC.md` finalize edilir + CI spec-review kapısı bağlanır. (2) Storage provider trait (interface) çekirdeğe eklenir. (3) Mock impl + fuzz target ile spec doğrulanır. (4) Sıra ile gerçek implementasyon.

Kod yazmadan önce spec'i dondurmak geri-dönüş maliyetini düşürür.

## Sonuçlar
- **Pozitif:** Spec drift önlenir; bağımsız auditör spec'i okuyabilir; CI spec-coverage kapısı spec↔kod uyumsuzluğunu yakalar.
- **Negatif:** Spec yazma süresi (kod gecikmesi).
- **Risk:** Spec çok soyut olursa implementasyon zoru — interface'ler somut olmalı.

## Uygunluk
Master-context nötr (storage, konsensüs değil).

## İlgili
- `docs/BUD_STORAGE_TECHNICAL_SPEC.md` (finalize — Phase 11.6)
- ADR-003 (node sınıflandırması — pruning)
- `src/storage/provider.rs` (implementasyon — Phase 11.10)
- `scripts/check-spec-coverage.sh` (CI kapısı)
