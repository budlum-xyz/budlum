# Budlum Reports Index — Canonical Registry (v2, 2026-07-20)

> **TR Özet:** Bu dosya Budlum repo içindeki rapor/denetim/plan belgelerinin arşiv indeksidir. 2026-07-20 arşiv dalgasından sonra kök `docs/` dizini yalnız yaşayan/aktif referans belgeleri taşır; kapanmış ADIM/Tur/Aşama/Phase raporları ve tarihsel denetimler `docs/archive/` altında tutulur.
>
> **Durum etiketleri:** 🟢 Yaşayan/kök · 🔵 Aktif çalışma/kök · ⚪ Arşiv · 🧾 Tarihsel kopya.
> Yeni rapor açmadan önce isimlendirme kuralını izle ve gerekirse bu indekse satır ekle. Şablon: [`../templates/REPORT_TEMPLATE.md`](../templates/REPORT_TEMPLATE.md).

## Naming standard

```text
PHASE<X.Y>_<TOPIC>_<ARENA{N}>[_YYYY-MM-DD].md
```

- Noktasal denetimlerde tarih soneki zorunludur.
- Yaşayan politika/spec belgeleri kökte kalabilir; kapanmış tur/faz/denetim belgeleri arşive taşınır.
- Arşiv içindeki belgeler tarih kaydıdır; içerikleri zorunlu olmadıkça geriye dönük değiştirilmez.

## 🟢 Canonical / living root documents

| File | Role |
|---|---|
| `docs/STATUS_ONLINE.md` | Aktif AI koordinasyon akış günlüğü |
| `docs/README.md` | Dokümantasyon giriş sayfası |
| `docs/BUDLUM_HARDENING_PROTOCOL.md` | Mainnet sertleştirme rejimi |
| `docs/MAINNET_READINESS.md` | Mainnet readiness / MR kriterleri |
| `docs/THREAT_MODEL.md` | Tehdit modeli |
| `docs/AUDIT_CHECKLIST.md` | Yaşayan dış audit hazırlık checklist'i |
| `docs/THE_PLAN_SOURCE_MANIFEST.md` | The-plan kaynak manifesti |
| `docs/ARCHITECTURE.md` | Mimari atlas |
| `docs/BUDLUM_CONSTITUTION.md` | Anayasa / yönetişim referansı |
| `docs/BUG_BOUNTY.md` | Sürekli güvenlik raporlama kanalı |

> Not: `STATUS.md` kökte bulunmuyor; tarihsel kopya `docs/archive/STATUS.md` altında.

## 🔵 Active Phase 12 / current planning documents kept in root

| File | Role |
|---|---|
| `docs/PHASE12_ARENA4_RD_PLAN.md` | Phase 12 ARENA4 R&D planı |
| `docs/ARENA4_APPROVED_SYSTEMS_ROADMAP_2026-07-20.md` | Kullanıcı onaylı Phase 12 sistem sıralaması |

## ⚪ Archive wave — 2026-07-20 ARENA4 hygiene

User ara-görev talebiyle kökteki tarihsel ADIM/Tur/Aşama/Phase raporları ve eski denetim raporları arşive taşındı. Kökten taşınan dosyalar:

| Archived file | Category |
|---|---|
| `docs/archive/BUDLUM_PHASE10.md` | Eski phase talimat/raporu |
| `docs/archive/BUDLUM_PHASE11.md` | Eski phase talimat/raporu |
| `docs/archive/BUDLUM_PHASE11_2.md` | Eski phase devam planı |
| `docs/archive/PHASE0.08_PLAN.md` | Eski tur/phase planı |
| `docs/archive/PHASE0.10_PLAN.md` | Eski tur/phase planı |
| `docs/archive/PHASE11_3_7_GOREV.md` | Eski görev/ADIM raporu |
| `docs/archive/PHASE11_4_DERIN_MIMARI.md` | Eski phase mimari raporu |
| `docs/archive/PHASE11_6_MAINNET_YOL_HARITASI.md` | Eski phase karar/yol haritası |
| `docs/archive/P2_SCHEMA4_UYGULAMA_PLANI_2026-07-18.md` | Eski uygulama planı |
| `docs/archive/ORG_ROADMAP_AUDIT.md` | Tarihsel roadmap denetimi |
| `docs/archive/ARENA3_SECURITY_VERIFICATION_AUDIT_2026-07-20.md` | Noktasal güvenlik doğrulama denetimi |
| `docs/archive/SECURITY_AUDIT_HACKER.md` | Tarihsel tehdit/hacker denetimi |
| `docs/archive/STATUS_ONLINE2.md` | Eski aktif kanal dökümü |

Kökteki byte-identical kopyaları kaldırılan ve zaten arşivde bulunan dosyalar:

| Existing archived file | Action |
|---|---|
| `docs/archive/ARENA3_P2_SCHEMA4_SECURITY_REVIEW_2026-07-18.md` | Kök kopya kaldırıldı |
| `docs/archive/ARENA3_V19_PERSISTENCE_FAIL_CLOSED_REVIEW_2026-07-18.md` | Kök kopya kaldırıldı |
| `docs/archive/GOREV_YONETICISI_EKSIKLIK_ANALIZI_ARENA2_ARENA3_TALIMATLARI_2026-07-18.md` | Kök kopya kaldırıldı |

## 🧾 Earlier archive waves / legacy index

Aşağıdaki dosyalar 2026-07-16 ve önceki arşiv dalgalarında arşive alınmış tarih kayıtlarıdır:

`PHASE3_FINAL_KAPANIS_ARENA3.md` · `PHASE3_HONEST_CLOSEOUT.md` · `PHASE3_PLAN_VE_GOREV_DAGILIMI.md` · `PHASE4_ARENA2_ANALIZ_2026-07-15.md` · `PHASE4_TEKNIK_VE_SONUCLAR_ARENA2.md` · `PHASE5_ARENA6_DENETIM_2026-07-15.md` · `PHASE7_CEREMONY_PLAN.md` · `PHASE7_CEREMONY_BIRLESTIRME_ARENA5_ARENA1.md` · `PHASE0.37_RAPOR.md` · `AGENT_AUDIT_REPORT.md` · `AGENT4_5_6_ARENA3_DENETIM_RAPORU.md` · `AGENT4_5_6_DENETIM_ARENA2.md` · `BUDLUM_SUREKLI_DENETIM_ARENA3_2026-07-15.md` · `BUDLUM_BOS_KOD_BAGDASMAMA_DENETIM_ARENA3_2026-07-16.md` · `DEVIR_RAPORU.md`.

## Books / specs out of scope

`docs/tr/book/`, `docs/en/book/`, `docs/spec-review/`, `docs/operations/` ve teknik spec/RFC dosyaları bu rapor arşiv dalgasının kapsamı dışındadır; kendi README/spec bağlamları kanoniktir.
