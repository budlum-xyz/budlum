# Denetim Bulguları: BudZero ve BudZKVM (Area BudZero/ZKVM)

Denetlenen Konumlar: `budzero/bud-vm/`, `budzero/bud-proof/`, `budzero/bud-compiler/`, `budzero/verifier-registry/`.

## 1. Kapsam ve İnceleme Metodolojisi

BudZero ZK rollup ve ZKVM yürütme katmanı:
- Trace matrisi doğrulaması ve AIR (Algebraic Intermediate Representation) kısıtları,
- Opcode davranışları ve sınır değer taşmaları,
- `VerifyMerkle` 64 derinlik kuralı: **Üretimde kapalı kalması kesin kuraldır** (`xtask/gates`).
- İkili ve çoklu kanıtlayıcı (multi-prover) determinizmi.

## 2. Bulgular

### B-ZKVM-01: VerifyMerkle 64-Depth Üretim Bayrağı
- **Önem**: Kritik (Critical) - Korunan Kapı
- **Dosya**: `budzero/bud-proof/src/predicates.rs`, `xtask/gates/src/gates/zkvm_immune_regeneration.rs`
- **Açıklama**: `VerifyMerkle` derinliği 64 olan kanıtlar aşırı hesaplama maliyeti ve DoS riski nedeniyle üretim zincirinde kesinlikle devre dışı kalmalıdır.
- **Kök Neden**: Test senaryolarında derin Merkle yollarının kullanılabilmesi.
- **Çözüm**: Gate kontrolü (`zkvm_immune_regeneration`) ile `VerifyMerkle 64` kodunun üretim bayraklarında açılamayacağı ve testnet/mainnet konfigürasyonlarında fail-closed olacağı garantilendi.
- **Durum**: Korunuyor ve Doğrulandı (`1bd9356` / `main`).

### B-ZKVM-02: AIR Kısıt Matrisinde Derece Aşımı (Degree Overflow)
- **Önem**: Yüksek (High)
- **Dosya**: `budzero/bud-vm/src/air.rs:310-345`
- **Açıklama**: Çoklu çarpım kısıtlarında AIR kısıt derecesi 3'ü aştığında STARK FRI katlama (folding) aşamasında seslilik (soundness) hatası oluşabiliyordu.
- **Kök Neden**: Ara değişkenlerin yardımcı polinomlar (auxiliary trace) yerine doğrudan tek bir kısıt içine gömülmesi.
- **Çözüm**: Yardımcı sütunlar eklenerek tüm kısıt dereceleri azami 3 ile sınırlandı.
- **Durum**: Çözüldü (`ed5faed7`).

### B-ZKVM-03: Güvenilmeyen Kanıt Türü (Raw Proof Acceptance)
- **Önem**: Kritik (Critical)
- **Dosya**: `src/consensus/zk_verifier.rs`, `src/domain/plugin.rs:442-455`
- **Açıklama**: ZK doğrulayıcı arayüzünün bazı mock ortamlarda `Raw` kanıt kabul etmesi, üretimde sahte durum geçişlerine zemin hazırlayabilirdi.
- **Kök Neden**: Entegrasyon testlerinde ZK kanıt üretimini atlamak için eklenen `ProofMode::Raw` seçeneğinin kapı denetiminden geçmesi.
- **Çözüm**: `ProofMode::Raw` üretim modunda tamamen yasaklandı; yalnızca geçerli STARK veya SNARK kanıtları kabul edilir (`UntrustedProofMode` hatası).
- **Durum**: Çözüldü (`cfc1fc7` + `3c891b5d`).
