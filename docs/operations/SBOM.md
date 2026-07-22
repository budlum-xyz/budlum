# SBOM (Software Bill of Materials) (Task 2 §1.7)

**Güncelleme:** 2026-07-15
**Araç:** `cargo-cyclonedx` (https://github.com/CycloneDX/cyclonedx-rust-cargo)
**Format:** CycloneDX JSON
**Durum:** Üretim scripti hazır; bu sandbox oturumunda Rust toolchain (`cargo`/`rustc`) bulunmadığı için `sbom.cdx.json` yerelde üretilemedi.

> SBOM harici audit ve mainnet launch hazırlığı için zorunlu supply-chain teslim
> kalemidir. Bu dosya prosedürü ve kabul kriterlerini taşır; gerçek SBOM artifact’i
> yetkili Rust ortamında `./scripts/generate-sbom.sh` ile üretilecektir.

## Kullanım

```bash
./scripts/generate-sbom.sh
```

Beklenen çıktı:

- `sbom.cdx.json` (repo root)
- güncellenmiş `docs/operations/SBOM.md` özeti

## Doğrulama

```bash
python3 -c "import json; json.load(open('sbom.cdx.json'))"
python3 -c "import json; print(len(json.load(open('sbom.cdx.json')).get('components', [])))"
```

Kabul için JSON parse edilmeli ve component sayısı `0`dan büyük olmalıdır.

## Neden SBOM?

- Harici audit firmasına transitive dependency envanteri verir.
- RustSec/CVE triage sürecini dependency graph ile eşleştirir.
- Mainnet öncesi supply-chain risklerini görünür yapar.
- Regülasyon ve kurumsal alım süreçlerinde standart teslim formatı sağlar.

## Kabul kriteri

- [x] `scripts/generate-sbom.sh` mevcut.
- [x] SBOM prosedürü dokümante edildi.
- [ ] Yetkili Rust ortamında `sbom.cdx.json` üretildi.
- [ ] JSON parse doğrulaması geçti.
- [ ] Component sayısı `0`dan büyük.
- [ ] SBOM artifact’i release/audit paketine eklendi.

## İlgili

- `scripts/generate-sbom.sh` — SBOM üretici.
- `docs/operations/DEPENDENCY_AUDIT.md` — dependency audit raporu.
- `fuzz/README.md` — fuzz target seti ve manuel run prosedürü.
- `docs/AUDIT_CHECKLIST.md` — harici audit teslim matrisi.
