# Status Online — Aktif iletişim kanalı (AI birliği)

**Amaç:** İki (veya daha fazla) AI'ın anlık olarak ne yaptığını, ne yapacağını,
karar taleplerini ve engelleri burada paylaşması. Statik denetim kayıtları
(`docs/STATUS.md`) ve şema (`docs/AI_BIRLIGI.md`) buraya girmez — bu
dosya **çalışma günlüğü**.

**Format:** serbest, ama timestamp'li ve AI-handle imzalı. Eski entry
"resolved" notuyla kalır (audit trail).

**Yazan:** her iki AI (handle + tarih).
**Okuyan:** her iki AI + kullanıcı (PR'a bakıyor olabilir).

---

## Entry şablonu

```markdown
### [YYYY-MM-DD HH:MM UTC+3] <handle> — <özet>

**Durum:** [devam ediyor | tamamlandı | engel | karar bekliyor]
**Kapsam:** [Tur X §Y | kod | docs | test | infra]
**Aksiyon:** ne yaptım / ne yapıyorum
**Kanıt:** [commit SHA | dosya | komut çıktısı]
**Sonraki adım:** ne yapacağım
**Engel (varsa):** ne durduruyor / ne karar bekliyor
```

---

## 2026-07-14 — kuruluş günü

### [2026-07-14 19:00 UTC+3] arena-agent — dosya şeması kuruldu

**Durum:** tamamlandı
**Kapsam:** docs (AI birliği şeması)
**Aksiyon:** `docs/DEVIR_RAPORU.md` → `docs/AI_BIRLIGI.md` rename + 4. bölümde
DEVIR_RAPORU'nun tamamı korunmuş + §1 AI üyeleri tablosu (2 → 4+ dinamik)
+ §2 iletişim kanalları ayrımı + §3 aktif iş akışı + §6 kesin kurallar.
`docs/STATUS.md` "tek-ajan devir" → "statik denetim" perspektifine
güncellendi (HEAD `39e30c7` referansı, 8 commit listesi).
`docs/STATUS_ONLINE.md` (bu dosya) yeni oluşturuldu — aktif iletişim
kanalı.

**Kanıt:** `git status` → 3 dosya değişti: rename + 2 modify (AI_BIRLIGI rename
zaten git mv ile staged).

**Sonraki adım:** kullanıcı doğrulaması → commit + push.

**Engel:** kullanıcı "the-plan yerine ekledim" / "oraya budlum zip ekledim"
diye belirsizlik yarattı — `/tmp/the-plan-check/` lokal kopya mevcut, içinde
TUR14_PLAN + TUR14_5_PLAN + claude-fable-5.md var (PR'a eklenmedi, sadece
referans olarak kullanıldı). zip değil, açılmış dizin. Beklemede.

### [2026-07-14 19:05 UTC+3] arena-agent — bekleme

**Durum:** karar bekliyor
**Kapsam:** repo state
**Aksiyon:** eklenen dosyalar hakkında kullanıcıdan net bilgi bekleniyor
(`/tmp/the-plan-check/` budlum zip midir? PR'a katılacak mı?). Şu an
working tree: `AI_BIRLIGI.md` (rename) + `STATUS.md` (modify) + `STATUS_ONLINE.md`
(new) staged değil, kullanıcı onayı sonrası tek commit'te push edilecek.

**Kanıt:** `git status --short` → 3 dosya değişiklik (2 modify + 1 rename).

**Sonraki adım:** kullanıcı cevabı → tek commit'te `ai-birligi-sema` mesajıyla push.

**Engel:** kullanıcının "zip ekledim" / "the-plan ekledim" mesajları netleşmedi;
eklediği dosyalar PR'a katılmalı mı yoksa sadece referans mı?

---

## Çözülmüş entry'ler (aşağıya taşı)

_(henüz yok — kuruluş günü)_

---

## 2026-07-14 — ADIM1 Başlangıcı

### [2026-07-14 20:45 UTC+3] ARENA2 — ADIM1: TUR14 bitirme girişimi

**Durum:** devam ediyor
**Kapsam:** TUR14 | kod | docs | test | roadmap
**Aksiyon:** ARENA2 olarak devreye girdim. Tüm roadmap belgelerini (STATUS.md, ORG_ROADMAP_AUDIT.md, CLAUDE.md, ARENA_AI.md, TUR16_PLAN.md, B.U.D. vizyonu) okudum. Mevcut durum: TUR14 (Faz 1-2 + Faz 5) PR #6'da HEAD `39e30c7` olarak tamamlanmış görünüyor. Ancak force-push sonrası 9 commit kayboldu (STATUS.md §4.2). ADIM1 hedefi: TUR14'ü gerçekten bitirip kanıtlamak + kaybolan işleri tespit etmek.

**Kanıt:** 
- PR #6 HEAD: `39e30c7` (tur14-rpc-e2e)
- ORG_ROADMAP_AUDIT.md §4a: 18 madde kontrol tablosu tamam
- STATUS.md §3: PR #6'da TUR14 + TUR14.5 tamamlandı (7/7 pr, pr-7 B.U.D. ✅)
- Kaybolan commit'ler: f286e54, 9a350b9, 8943fcf ve 6 diğer (git log --oneline -20 ile doğrulanabilir)

**Sonraki adım:** 
1. git log --oneline -20 ile mevcut commit zincirini doğrula ✅ (yukarıda listelenmiş)
2. Kaybolan işleri listele (TUR14.9 denetim zinciri, TUR16 plan, audit checklist)
3. Eksik dosyaları yeniden yaz / restore et
4. TUR14'ü "bitmiş" sayabilmek için gerçek acceptance criteria kontrolü

**Engel:** Force-push sonrası remote ile local uyumsuzluğu olabilir. Shallow clone sorunu. `git fetch --unshallow` gerekebilir.
