# Budlum Core — CI/CD Güvenlik Sertleştirme Planı

**Depo:** github.com/budlum-xyz/budlum
**Tarih:** 23 Temmuz 2026

**Yöntem notu:** Bu plan, deponun herkese açık GitHub sayfaları (README, SECURITY.md, Cargo.toml, Dockerfile) incelenerek hazırlandı. GitHub'ın robots.txt kısıtlaması `.github/` ve `scripts/` dizinlerinin otomatik olarak taranmasını engellediğinden, mevcut `ci.yml` içeriğini birebir okuyamadım. Aşağıdaki "zaten var" tespitleri README ve Cargo.toml'daki açık ifadelerden çıkarıldı; uygulamaya geçmeden önce gerçek workflow dosyalarınızla karşılaştırmanızı öneririm.

---

## 1. Zaten sahip olduklarınız (tekrar önerilmeyecek)

Çoğu projede bunlar eksiktir — sizde zaten mevcut, bu yüzden plan buradan yukarı inşa ediyor:

| Alan | Mevcut durum |
|---|---|
| Format/Lint/Test kapısı | `cargo fmt`, `cargo clippy -D warnings`, `cargo test` — hem ana crate hem `budzero/` workspace için ayrı ayrı |
| Lisans/bağımlılık politikası | `cargo-deny` entegre (`unlicensed = "deny"` kuralı, Cargo.toml'da Phase 8.2 notu) |
| Sabit-zaman (constant-time) regresyonu | `benches/micro/timing_safe.rs`, `harness=false`, CI kapısı olarak çalışıyor (Phase 8.6) — dudect yaklaşımına benzer bir yöntem |
| Fuzzing altyapısı | `fuzz/` dizini mevcut |
| Bağımlılık denetim script'i | `scripts/audit-deps.sh` |
| SBOM üretimi | `scripts/generate-sbom.sh` |
| Denetim (audit) checklist'i | `docs/AUDIT_CHECKLIST.md`, harici denetime hazırlık için |
| Bug bounty planı | SECURITY.md'de kademeli ödül tablosu, mainnet sonrası Immunefi planı, iyi niyetli araştırmacı koruması metni |
| Hassas kod yolları tanımı | SECURITY.md'de consensus/execution/rpc gibi kritik dizinler açıkça listelenmiş |
| Docker sertleştirme | Multi-stage build, base image'lar sha256 digest ile pinlenmiş, `cargo build --locked`, root olmayan kullanıcı, minimal paket kurulumu |
| Property-based test | `proptest` dev-dependency olarak kullanılıyor |
| Tekrarlanabilir geliştirme ortamı | Nix flake (`flake.nix` / `flake.lock`) |

## 2. Yol geçerken fark edilenler

- README'deki CI/Test rozetleri hâlâ kişisel bir hesaba (org'a taşınmadan önceki depoya) işaret ediyor gibi görünüyor; org'a taşındıysa rozet linklerini güncellemek küçük ama faydalı bir düzeltme.
- Cargo.toml'daki `domain_throughput` benchmark'ı, tanımlanmamış bir feature'a bağlı olduğu için pratikte hiçbir zaman çalışmıyor gibi görünüyor — aşağıdaki "performans regresyonu" bölümüyle birlikte yeniden ele almaya değer.
- Dockerfile'ın varsayılan başlatma komutu doğrudan mainnet moduna işaret ediyor. Proje henüz denetlenmemiş/mainnet için hazır olmadığını kendi belgelerinizde açıkça belirttiğinden, varsayılanı devnet yapıp mainnet'i yalnızca açık bir bayrakla etkinleştirmek, yanlışlıkla üretim moduna girme riskini azaltır.

---

## 3. Eklenebilecek ileri seviye / marjinal denetimler

Her madde için: **ne işe yarar**, **bu projeye neden özellikle uygun**, **PR'ı bloklamalı mı yoksa zamanlanmış/bilgilendirici mi kalmalı**.

### 3.1 CI'ın kendisini sertleştirme (meta-güvenlik)
GitHub Actions'ın kendisi bir saldırı yüzeyidir. 2025'te yaşanan `tj-actions/changed-files` tedarik zinciri saldırısı gibi olaylar, pinlenmemiş action'ların teorik değil gerçek bir risk olduğunu gösterdi.

- **zizmor** — GitHub Actions workflow'ları için statik analiz aracı; template injection, aşırı yetkili token kullanımı, pinlenmemiş action gibi sorunları tespit eder ve sonucu SARIF formatında Code Scanning'e yükleyebilir. *(PR kapısı olarak kullanılabilir)*
- **actionlint** — workflow YAML'larında syntax ve mantık hatalarını yakalar. *(Ucuz, PR kapısı)*
- Üçüncü parti action'ları etiket yerine **commit hash'ine pinleyin**; Dependabot'un `github-actions` ekosistemini de takip ettiğinden emin olun.
- Workflow seviyesinde varsayılan `permissions: contents: read`, iş bazında ihtiyaç kadar yetki yükseltme.
- Branch protection: imzalı commit zorunluluğu, en az iki onaylayıcı, eski onayların yeni push'ta düşmesi, force-push yasağı, release tag'leri için tag koruması.
- CODEOWNERS dosyasını SECURITY.md'de zaten tanımladığınız hassas dizin listesiyle birebir eşleştirin — bu yollara dokunan her PR otomatik olarak ilgili güvenlik incelemesini zorunlu kılsın.

### 3.2 Bağımlılık ve tedarik zinciri (Dependabot'un ötesi)
- Dependabot yapılandırmasının **cargo + github-actions + docker** ekosistemlerinin üçünü de kapsadığını doğrulayın; kritik crate'leri (tokio, libp2p, pqcrypto ailesi, PKCS#11 bağlayıcısı) ayrı grupta tutup manuel incelemeye ayırın.
- **`actions/dependency-review-action`** — PR diff'inde yeni eklenen bağımlılıkları lisans/CVE eşiğine göre anında engeller; public repo'da ücretsizdir ve Dependabot'tan farklı olarak PR anında, GitHub arayüzünde çalışır. *(PR kapısı)*
- `cargo-deny` yapılandırmanızı derinleştirin: `bans` bölümüyle yinelenen/çakışan sürüm tespiti, `sources` ile yalnızca crates.io ve izin verilen git kaynaklarına izin verme, lisans allow-list'ini (MIT/Apache-2.0/BSD gibi) açıkça sayıp geri kalanı reddetme.
- **cargo-vet** (veya cargo-crev) — özellikle FFI/unsafe barındıran crate'ler (post-kuantum imza kütüphaneleri, PKCS#11 bağlayıcısı) için tedarik zinciri güven denetimi. *(Kademeli benimsenebilir, bilgilendirici)*
- SBOM üretim script'inizi her release'de otomatik çalıştırıp çıktıyı release artifact'ı olarak ekleyin; mümkünse imzalayın.
- `cargo-outdated` veya benzeri bir dashboard — bloklamayan, yalnızca bilgilendirici güncellik takibi.

### 3.3 Statik analiz (SAST) — Rust'a özel
- **CodeQL for Rust** — Ekim 2025'te genel kullanıma (GA) açıldı, artık beta değil; default veya advanced setup ile Code Scanning'e ekleyebilirsiniz. Nightly-only özellikleri desteklemiyor, ancak ana crate stable Rust hedeflediği için bu bir sorun oluşturmamalı. *(PR kapısı, önem derecesine göre)*
- **cargo-geiger** — kod tabanınızdaki `unsafe` bloklarının oranını izler; ZKVM yürütme motoru gibi kritik alanlarda artış olursa PR'da görünür kılın. *(Bilgilendirici + baseline artışında uyarı)*
- **Miri** (`cargo +nightly miri test`) — FFI sınırındaki tanımsız davranışları (undefined behavior) yakalar; ağ/syscall gerektirmeyen kripto ve serileştirme modülleriyle sınırlı tutup nightly zamanlanmış bir job olarak çalıştırın.
- Sanitizer build'leri (AddressSanitizer/ThreadSanitizer) — fuzz hedefleri ve kritik modüller için haftalık zamanlanmış job.
- **MSRV job'u** (`cargo +1.94.0 check --locked`) — Cargo.toml'da beyan ettiğiniz minimum Rust sürümünün sessizce eskimediğini garanti eder; sık atlanan ama ucuz bir kontrol.
- **cargo-hack** ile özellik matrisi testi — post-kuantum imza özelliklerinizin (varsayılan ve opsiyonel) her kombinasyonda ayrı ayrı derlendiğini doğrulayın.

### 3.4 Fuzzing olgunlaştırma
- Mevcut fuzz hedeflerinizi **ClusterFuzzLite** ile PR-tetiklemeli sürekli fuzzing'e bağlayın (corpus kalıcılığı ile); açık kaynak bir proje olduğunuz için **OSS-Fuzz** başvurusu da bir seçenek (kabul süreci gerektirir, ücretsizdir).
- RPC ve P2P mesaj ayrıştırıcıları için yapı-farkında (structure-aware) fuzz corpus'unu genişletin.
- Bulunan crash'lerin corpus'a eklenip kalıcı regresyon testi haline getirilmesini standart bir süreç yapın.

### 3.5 Konsensüse özgü determinizm ve doğruluk denetimleri
Bunlar genel geçer değil, doğrudan çoklu-konsensüs uzlaşma katmanı mimarinize özel:

- **Çapraz mimari determinizm testi** — aynı durum geçişi/hash sonuçlarının x86_64 ve arm64'te birebir eşleştiğini doğrulayan bir job. GitHub'ın arm64 runner'ları public repo'larda Ağustos 2025'ten beri ücretsiz ve genel kullanıma açık — maliyetsiz eklenebilir, zincir bölünmesi (chain split) riskine karşı yüksek değerli bir kontrol.
- **Bilinen-cevap (known-answer) test paketi** — imza ve Merkle işlemleriniz için referans test vektörlerine karşı doğrulama yapan bir job; kripto kütüphanesi sürüm yükseltmelerinde sessiz regresyonları yakalar.
- Yeniden-organizasyon (reorg) ve replay senaryoları için özel fuzz/property-test hedefi — SECURITY.md'nin kapsamında zaten bu tür durumlar yer alıyor, dedike bir test hedefiyle güçlendirilebilir.
- Kötü niyetli doğrulayıcı senaryoları (çifte oy, oy saklama, ağ bölünmesi) için test matrisi — B.U.D. tarafında uyguladığınız çoklu-aktör bağımsızlığı testi yaklaşımını çekirdek konsensüs katmanına da genişletmek.
- Protokol tanım dosyanız için **buf lint + buf breaking** — mesaj formatında yanlışlıkla geriye dönük uyumsuz bir değişiklik yapılmasını PR aşamasında yakalar.

### 3.6 Formal doğrulama (TLA+'a tamamlayıcı, şimdiden başlanabilir)
Yol haritanızda TLA+ henüz başlamamış bir araştırma kalemi olarak duruyor. Aşağıdakiler kod seviyesinde çok daha düşük maliyetle şimdi devreye alınabilir:

- **Kani** (sınırlı model denetimi / bounded model checking) — header-chain doğrulama, Merkle proof kontrolü, RPC girdi ayrıştırma gibi sınırları belirli fonksiyonlarda panik/taşma olmadığının kanıtlanması.
- **cargo-mutants** (mutasyon testi) — mevcut geniş test setinizin gerçekten hata yakalayıp yakalamadığını ölçer; tüm koda uygulamak yavaş olacağından consensus/kripto modülleriyle sınırlı tutup haftalık zamanlanmış job yapın.

### 3.7 Container/runtime sertleştirme (Dockerfile zaten iyi durumda — küçük eklemeler)
- **Trivy** veya **Grype** ile nihai image'ın CVE taraması — build anında ve ayrıca haftalık yeniden tarama (yeni CVE'ler build'den sonra da ortaya çıkar).
- **cosign** ile image imzalama ve `actions/attest-build-provenance` ile SLSA seviye 2 provenance — public repo'da ücretsiz, Sigstore tabanlı, uzun ömürlü anahtar gerektirmeden iki satır YAML ile eklenebilir.
- **Hadolint** — Dockerfile lint aracı.
- `HEALTHCHECK` talimatı ekleyin.
- Nihai image'daki `curl` paketini gözden geçirin — bir RCE sonrası dışarıya veri sızdırma veya ek payload indirme amacıyla kötüye kullanılabilir; ihtiyaç yoksa kaldırın, gerekiyorsa read-only root dosya sistemi ve kapasite kısıtlamalarıyla telafi edin.

### 3.8 Performans regresyonu / DoS bütçesi
- Mevcut criterion benchmark'larınızı bir regresyon takip aracına (ör. github-action-benchmark) bağlayıp belirli bir eşiğin üzerindeki yavaşlamada PR'ı kırın; şu an etkin görünmeyen throughput ölçümünü de bu kapsamda yeniden değerlendirin.
- Mempool ve RPC için büyük payload / kötü niyetli boyut fuzz bütçesi — SECURITY.md'nin kapsamında zaten kaynak tüketimi saldırıları yer alıyor.

### 3.9 Sır (secret) taraması ve tedarik zinciri skor kartı
- GitHub secret scanning ve push protection'ın repo ayarlarında açık olduğunu teyit edin (public repo'da ücretsizdir).
- **gitleaks** veya **trufflehog** ile CI seviyesinde ek tarama — persona konfigürasyon dosyalarınıza ve doğrulayıcı anahtar formatlarınıza özel kurallar tanımlayarak.
- **OpenSSF Scorecard** — branch protection, pinlenmiş bağımlılıklar, SAST/fuzzing varlığı gibi çok sayıda kontrolü tek bir skorda özetler; PR kapısı değil, zamanlanmış bir job olarak.

### 3.10 Governance / GitHub ayarları
- Private vulnerability reporting'in repo ayarlarında açık olduğunu teyit edin.
- Release tag'leri için tag koruması (silme/taşıma engeli).
- Org üyeleri için zorunlu iki faktörlü kimlik doğrulama.

---

## 4. Örnek iskelet: `security-audit.yml`

Aşağıdaki, hızlı kazanımların bir kısmını nasıl bir araya getirebileceğinizi gösteren **taslak** bir workflow. Gerçek `ci.yml` dosyanızın iş yapısını göremediğim için bunu doğrudan kopyalamak yerine kendi kurulumunuza uyarlamanızı, action sürümlerini/hash'lerini güncel ve doğrulanmış olanlarla değiştirmenizi öneririm:

```yaml
name: security-audit
on:
  pull_request:
  schedule:
    - cron: "0 3 * * 1"   # haftalık, Pazartesi 03:00 UTC

permissions:
  contents: read

jobs:
  zizmor:
    permissions:
      contents: read
      actions: read
      security-events: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<pinned-sha>
      - uses: zizmorcore/zizmor-action@<pinned-sha>

  dependency-review:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@<pinned-sha>

  cargo-deny:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<pinned-sha>
      - uses: EmbarkStudios/cargo-deny-action@<pinned-sha>

  trivy-image:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<pinned-sha>
      - run: docker build -t budlum-core:ci .
      - uses: aquasecurity/trivy-action@<pinned-sha>
        with:
          image-ref: budlum-core:ci
          severity: CRITICAL,HIGH

  determinism-cross-arch:
    strategy:
      matrix:
        runner: [ubuntu-24.04, ubuntu-24.04-arm]
    runs-on: ${{ matrix.runner }}
    steps:
      - uses: actions/checkout@<pinned-sha>
      - run: cargo test --locked --lib determinism
```

---

## 5. Öncelik sırası

| Aşama | İçerik | Yaklaşık maliyet |
|---|---|---|
| **Hemen (1-2 hafta)** | zizmor, actionlint, action'ları hash'e pinleme, CodeQL (Rust), dependency-review-action, branch protection + CODEOWNERS, Trivy + Hadolint, HEALTHCHECK, MSRV job, cargo-hack özellik matrisi, gitleaks | Düşük — çoğu hazır GitHub Action, kurulumu yarım güne yakın |
| **Orta vade (~1 ay)** | cargo-deny sıkılaştırma (bans/sources/lisans allow-list), cargo-geiger, Miri (nightly), SBOM otomasyonu + imzalama, cosign + build provenance, çapraz mimari determinizm job'u, bilinen-cevap test paketi, buf lint/breaking, benchmark regresyon botu | Orta — pipeline tasarımı ve baseline oluşturma gerekir |
| **İleri seviye / araştırma** | ClusterFuzzLite veya OSS-Fuzz entegrasyonu, Kani ile seçili modüllerde sınırlı kanıtlama, cargo-mutants (kapsamı daraltılmış, haftalık), sanitizer build'leri, concurrency exhaustive testing, kötü niyetli senaryo test matrisi genişletme, cargo-vet güven ağı | Yüksek — uzman zamanı ve iterasyon gerektirir, ama henüz harici denetimden geçmemiş bir mainnet adayı için en yüksek karşılığı bu katman verir |

---

Bu denetimlerin tamamı, hatayı üretim öncesi yakalama olasılığını artırır ama kendi belgelerinizde de belirttiğiniz gibi bağımsız, profesyonel bir harici denetimin yerini tutmaz — onu tamamlayan bir katman olarak düşünülmeli.
