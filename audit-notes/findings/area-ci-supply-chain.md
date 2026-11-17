# Denetim Bulguları: CI ve Tedarik Zinciri (Area CI/Supply-Chain)

Denetlenen Konumlar: `.github/workflows/`, `xtask/gates/`, `supply-chain/`, `.quality/`.

## 1. Kapsam ve İnceleme Metodolojisi

Tedarik zinciri ve CI güvenliği:
- GitHub Actions iş akışları izinleri (`permissions: contents: read`),
- `BADGE_PUSH_TOKEN` ve diğer secret'ların üçüncü taraf adımlara sızma riski,
- Bağımlılık denetimi (`cargo-audit`, `cargo-deny`, `cargo-vet`),
- Statik analiz kapıları (`actionlint`, `zizmor`, `gitleaks`, `semgrep`).

## 2. Bulgular

### B-CI-01: Clippy-Extra ve Test Kodu Lint Hatası (PR #183 CI Blocker)
- **Önem**: Yüksek (High)
- **Dosya**: `src/execution/executor.rs:6632`, `src/garden/state.rs:1898`
- **Açıklama**: `cargo clippy --all-targets -- -D warnings` test hedeflerinde `RegistryParams` `.clone()` ve `useless_vec` nedeniyle CI'ı kırmızıya düşürüyordu.
- **Kök Neden**: Test kodunda `Copy` trait'e sahip yapının kopyalanması ve tek elemanlı `vec![leave]` kullanımı.
- **Çözüm**: `*state.registry.params()` ve `pool = [leave]` şeklinde düzeltildi.
- **Durum**: Çözüldü (`5d912761` ve `d013014a`). PR #183 ve PR #164 CI 0 hata ile geçti.

### B-CI-02: Actionlint İş Akışı Sözdizimi ve Güvenlik İzinleri
- **Önem**: Orta (Medium)
- **Dosya**: `.github/workflows/*.yml`
- **Açıklama**: Bazı iş akışlarında en az ayrıcalık (least privilege) ilkesine aykırı `permissions: write-all` veya tanımsız izinler bulunuyordu.
- **Kök Neden**: Varsayılan GitHub Actions izinlerinin kısıtlanmamış olması.
- **Çözüm**: Tüm iş akışları `permissions: read-all` veya açık `contents: read` ile sınırlandı; `actionlint` ve `zizmor` kapıları yeşile bağlandı.
- **Durum**: Çözüldü (`1bd9356` / `main`).

### B-CI-03: Bağımlılık Lisans Uyumu (PolyForm Shield 1.0.0)
- **Önem**: Yüksek (High)
- **Dosya**: `Cargo.toml`, `.quality/deny.toml`, `LICENSE.md`
- **Açıklama**: Eklenen bağımlılıkların PolyForm Shield License 1.0.0 ile uyumsuz copyleft lisansları taşımaması zorunludur.
- **Kök Neden**: Üçüncü taraf kütüphane güncellemelerinde lisans kayması.
- **Çözüm**: `cargo-deny` lisans kuralları güncellendi ve CI kapısında her PR için otomatik doğrulandı.
- **Durum**: Çözüldü (`ad88285c`).
