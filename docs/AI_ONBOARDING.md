# AI Onboarding — Birliğe Yeni Katılanlar İçin START-HERE

> **Standing rule (kullanıcı emri, 2026-07-18):** Bu dosya **her phase'de güncellenir.**
> Phase açılışında "Bugün neredeyiz" (§5) ve görev tablosu (§2) tazelenir; phase
> kapanışında mühür satırı işlenir. Güncellemeyi unutan, dosyanın başındaki bu
> notla kendini ele verir — STATUS_ONLINE'da da aynı kural kayıtlıdır.

**Hedef kitle:** ARENA1 (cross_domain) · ARENA2-halef (chain/snapshot/rpc) · yeni katılan herhangi bir AI.
**Hazırlayan:** ARENA3 · **Tarih:** 2026-07-18 · **Durum:** Phase 9.5 mühürlü, Phase 10 Sprint-1 kapalı, Sprint-2 sürüyor.

---

## 1. Okuma sırası (30 dakikada hizalanma)

1. **`ARENA_AI.md` — “Budlum Zorunlu Çalışma Protokolü” bölümü:** Her karar kapısında seçenekli soru sorulur; yanıt alınca süreç devam eder. Hızlı sonuç, kanıt/CI/sahiplik kontrolünün yerine geçmez.
1. **`docs/STATUS_ONLINE.md` — son 4 girdi** (aktif iletişim kanalı; burada timestamp'li girdi AÇMADAN kod yazma):
   - P10 açılış + kod doğrulama raporu (RPC 7→9, ContentManifest owner YOK, RoleId deseni)
   - Sprint-1 kapanışı (modül dashboard + BNS gate + 16 zorunlu check)
   - Phase 9.5 mühür envanteri
   - HALEF EL KİTABI bölümü (ARENA2'ye özel devir notları)
2. **`docs/ARENA3_BACKLOG_2026-07-18.md`** — bekleyen işler (her satır sahip+koşul etiketli; kendi kalemini buradan sahiplen).
3. **`docs/BUDLUM_PHASE10.md`** — mevcut fazın talimat dokümanı (4 bölüm). **Bölüm 3.0 dürüstlük notunu oku:** doküman README bazlı; benim kaynak-doğrulamam STATUS_ONLINE'daki P10 girdisinde (9 RPC, owner YOK, 755 lib — dokümandaki 452 güncel değil).
4. **`docs/RFC_GAP1_SNAPSHOT_MANIFEST_SIGNATURE.md`** — açık RFC (Sprint-2'de AccessGrant RFC ile birleşik revize edilecek).
5. **`docs/ARENA_GOREV_DAGILIMI_2026-07-17.md`** — orijinal görev dağılımı (hâlâ geçerli temel; aşağıdaki güncellemelerle birlikte oku).

## 2. Görev sınırları (güncel)

| AI | Domain | Not |
|---|---|---|
| ARENA1 | `cross_domain/**` (bridge/message/relayer) | P10 teması: B.U.D. asset ↔ input_ref köprülemesi (gerekirse) |
| ARENA2-halef | `chain/snapshot/rpc` + V3 backlog (**DONDURULMUŞ — dokunma**) | P10: AI Inference layer zincir tipleri + `bud_ai_request` host-call (aday — kullanıcı onayı backlog #2) |
| ARENA3 | `fuzz/`, `workflows/`, chaos + CI kök-neden + PR/dependabot triyaj + HSM/kripto + P10 süreç sahibi | Kullanıcı yetkisiyle şu an tüm süreç koordinasyonu |

**Kesişim kuralı:** başkasının domain'ine dokunacaksan STATUS_ONLINE'da önceden ilan et + sahibinin onayı; main kırmızıyken kolektif onarım istisnasıdır (committe şeffaf belirt).

## 3. Mutlak kurallar (ihlal = incident; ARENA2-v1 dosyası STATUS'ta)

- **Force-push YASAK** (kendi PR dalında bile; rebase yerine `git merge origin/main`).
- **devnet repo (`budlum-xyz/budlumdevnet`) salt-okunur** — asla değiştirilmez.
- **CI tek hakem:** lokalde "derlendi sanma" (çoğu ortamda toolchain yok); push sonrası CI bekle (~12 dk/SHA duvar süresi), kırmızıysa düzeltmeden yeni iş açma.
- **Test sayısı yalnız CI summary satırından** — "N test hedefi" yazma; sayı raporla (güncel: Core 755 lib / BudZero 124 / B.U.D. 12 kapılı / BNS 8 kapılı).
- **Başkasının commit'ini CI kanıtı görmeden "trivial/zararsız" sayma** (3a1eebf özeleştirisi STATUS'ta).
- Commit trailer: `Co-authored-by: ARENAX <arenax@budlum.xyz>`; identity repo-local (`git config user.name/email` — `.git/config` kalıcı değildir, her oturumda kur).
- Push öncesi `git fetch`; çalışma ağacında sahipsiz değişiklik bırakma (`git reset --hard` commit'siz işi SİLER — pre-push-check.sh kaybı STATUS'ta kayıtlı).

## 4. Repo haritası (hızlı)

- İş akışları: `.github/workflows/` — `ci.yml` (13 job + badge-bot), docker smoke + multinode (ayrı workflow), nightly fuzz, supply-chain extra.
- Kapı scriptleri: `scripts/check-bud-e2e.sh`, `scripts/check-bns-gate.sh` (vacuous-gate kanaryalı desen — yeni gate bunu kopyalar).
- Modül README'leri: kök `README.md` (SADECE dashboard), `budzero/README.md`, `src/storage/README.md` (B.U.D.), `src/bns/README.md` (BNS).
- Badge hattı: `budlum-ci[bot]` main'e README badge commit'i atar (PAT derogasyonlu, koruma-uyumlu); sayı değişirse otomatik.

## 5. Bugün neredeyiz

- **Phase 9.5 KAPALI** (mühür listesi STATUS'ta) — o iş kalemlerine yeni satır açma.
- **Phase 10 Sprint-1 KAPALI** (Bölüm 4 modül ayrımı: dashboard + modül README'leri + BNS gate 8/8 + protection 16 check).
- **Sprint-2 AÇIK:** AccessGrant RFC taslağı (ARENA3) → major PR triyajı (#36-#45; #45 toml YEŞİL aday, diğerleri KIRMIZI değerlendirme) → AI Inference layer tipleri (BÖLÜM 1, halef adaylığı).
- **Açık alert: 0** · main tam yeşil (`dd7d865`).

**İlk mesajın:** STATUS_ONLINE'a "okudum + hizalandım + sahiplendiğim kalem" girdisi. Sorular kanala; cevap timestamp'li gelir.

---

*Co-authored-by: ARENA3 <arena3@budlum.xyz>*
