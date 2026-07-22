# Post-Quantum Security Architecture ()

**Tarih:** 13 Temmuz 2026
**Kapsam:** `budlum-core` v0.3-dev + `budzkvm` (BudZero)
**Durum:** Mevcut (Dilithium5 imza entegre), KEM/HSM/hash-imza backlog.

---

## 0. Özet (Tek Sayfa)

Budlum, **NIST PQC standartlarına** dayalı hibrit bir kriptografik mimari kullanır. Günümüzde ( itibarıyla) yalnızca **CRYSTALS-Dilithium** (imza) entegre edilmiş durumdadır; **ML-KEM** (KEM), **SLH-DSA** (hash-imza) ve **FN-DSA** (Falcon) **backlog'tadır** — bütçe veya NIST standartlaşma takvimine bağlı.

Bu doküman:
1. Kuantum tehdidinin **somut** boyutunu Budlum'un protokol yüzeyine bağlar.
2. **Mevcut** post-quantum korumayı dosya/satır referanslarıyla sabitler.
3. **Eksik** korumayı ve **risk değerlendirmesini** yazar.
4. **Yol haritası** (+) için somut kabul kriterleri sunar.

**Asıl ilke:** "Klasik + PQ hibrit" her zaman güvenli tarafta. Yeni bir kriptografik primitive eklerken **her iki dünyada** aynı anda çalışabilmeli veya klasik taraftan PQ tarafına **geçiş yolu** olmalı.

---

## 1. Tehdit Modeli

### 1.1 Kuantum Bilgisayarların Bugünkü Durumu (2026 ortası)
- NIST, **2030 sonrası** kuantum bilgisayarların RSA-2048 / ECDSA-P256'yı kırabileceğini öngörüyor. KRACK / Harvest-Now-Decrypt-Later (HNDL) saldırıları **bugün** başlamış durumdadır: bir düşman şifreli trafiği kaydeder, 2030+'da deşifre eder.
- Budlum için HNDL özellikle **geçmiş validatör imzaları**, **geçmiş slashing raporları** ve **geçmiş finality sertifikaları** için geçerlidir — bunlar hâlâ konsensüs gerektiren objelerdir (eski slashing kanıtları bir düşman tarafından geriye dönük çalınabilir, yeniden üretilebilir ve "valid" görünebilir).

### 1.2 Budlum'un Kuantum-Hassas Yüzeyi

Aşağıdaki tablo, Budlum'un tüm kriptografik bağımlılıklarını haritalandırır (dosya:satır referanslarıyla):

| Algoritma | Kullanım Yeri | Tür | Kuantum Riski | Mevcut Durum | Dosya:Satır |
|---|---|---|---|---|---|
| **Ed25519** | PoA domain imzaları, validator keypair (fallback) | Klasik imza | **YÜKSEK** — Shor ile kırılabilir | Yerinde (PQ'a geçiş **yok**) | `crypto/primitives.rs:1-30` |
| **BLS12-381** | Finality prevote/precommit, finality sertifikaları | Klasik imza (pairing) | **YÜKSEK** — Shor + kuantum discrete log | Yerinde (PQ'a geçiş **yok**) | `chain/finality.rs:155`, `:187` |
| **VRF (Schnorr)** | PoS leader election | Klasik imza | **YÜKSEK** | Yerinde | `consensus/pos.rs` |
| **SHA3-256 / Keccak256** | Hash, address, merkle root, proof binding | Klasik hash | **ORTA** — Grover ile ~yarıya iner (256→128 bit güvenlik) | Yerinde, post-quantum **güvenli kabul** (256-bit çıktı) | birçok yerde |
| **SHA2-256** | ECDSA digest fallback, dilithium5 input | Klasik hash | **ORTA** | Yerinde | `consensus/qc.rs` |
| **BLAKE3** | SMT, state root | Klasik hash | **ORTA** | Yerinde | `chain/snapshot.rs` |
| **Dilithium5** (CRYSTALS-Dilithium, NIST Level 5) | Finality QcBlob imzaları, slashing evidence | PQ imza | **DÜŞÜK** (Level 5) | **Entegre** | `crypto/primitives.rs:5,153-198`, `consensus/qc.rs` |
| **Ed25519 PQ hibrit** | — | Hibrit imza | **ÇOK DÜŞÜK** | **YOK** (backlog) | — |
| **ML-KEM (Kyber)** | — | PQ KEM | — | **YOK** (backlog) | — |
| **SLH-DSA (SPHINCS+)** | — | PQ hash-imza | — | **YOK** (backlog) | — |
| **FN-DSA (Falcon)** | — | PQ imza (compact) | — | **YOK** (backlog) | — |

### 1.3 Hangi Saldırı Yüzeyi Bugün Hâlâ Açık?

- **Finality QcBlob imzaları** → Dilithium5 ile **KORUNUYOR** ✅ ('te eklendi).
- **Slashing raporları (SlashingReport)** → Dilithium5 imzalı → **KORUNUYOR** ✅.
- **PoA domain imzaları (ed25519)** → **AÇIK** ⚠️ — PoA authority'lerinin finality kararları PQ-değil.
- **BLS finality (prevote/precommit)** → **AÇIK** ⚠️ —  plan: BLS'yi koruyup üstüne Dilithium binding eklemek (hibrit).
- **VRF (PoS leader election)** → **AÇIK** ⚠️.
- **Anahtar depolama** → `KeyPair::save`/`ValidatorKeys::save` artık 0o600 ile yazılıyor ( fix) ama **şifreleme yok** — yerel disk şifrelemesi operatöre bırakılmış (FS-level LUKS/dm-crypt önerilir).
- **HNDL (Harvest-Now-Decrypt-Later)** → **TAMAMEN AÇIK** ⚠️ — geçmiş P2P trafiği, geçmiş slashing raporları, geçmiş finality mesajları bugün kaydedilip 2030+'da çözülebilir.

---

## 2. Mevcut PQ Entegrasyonu (Detay)

### 2.1 Dilithium5 — `pqcrypto-dilithium = "0.5.0"`

**Neden Dilithium5?** NIST FIPS 204 (ML-DSA) standardının draft'ı sırasında en kararlı, en geniş gözden geçirilmiş implementasyon. Level 5 = en yüksek güvenlik kategorisi (≥256 bit post-quantum güvenlik, RSA-3072 eşdeğeri).

**Bağımlılık yolu:** `Cargo.toml` → `pqcrypto-dilithium = "0.5.0"`, `pqcrypto-traits = "0.3.5"`.

**Kullanım:**

```rust
// src/crypto/primitives.rs:5-6
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage, DetachedSignature};

// src/crypto/primitives.rs:153-198 — keypair, sign, verify
let (public_key, secret_key) = dilithium5::keypair();
let sig = dilithium5::detached_sign(message, &secret_key);
dilithium5::verify_detached_signature(&sig, message, &public_key)
```

**ValidatorKeys** (`ValidatorKeys::generate/save/load`):
- Ed25519 + VRF + **Dilithium5** + BLS → tek bir struct içinde.
- `save` ( sonrası): `OpenOptions::new()...mode(0o600)` ile atomik 0o600.

### 2.2 QcBlob Quorum + PQ Attestation

**`src/consensus/qc.rs`** — finality QcBlob yapısı:

- Her imza bir `PqSignatureEntry { validator_index, validator_address, dilithium_signature: Vec<u8> }`.
- **Toplam ≥ ceil(n × 2/3) imza** zorunlu ( fix).
- Merkle root = imzaların domain-separated SHA3-256 hash'i; **her dilithium imzası ayrıca leaf olarak doğrulanır**.
- `verify_against_snapshot` ile:
  - Her validator_index için **unique** imza kontrolü (`"Duplicate PQ signature"` hatası).
  - Her validator'ın **PQ public key'i** `Validator::pq_public_key`'ten alınır, imza doğrulanır.
  - `required_signers = None` ile bireysel imza geçerliliği; `Some(indices)` ile toplu quorum kontrolü (`handle_finality_cert`'te).
- Fault proof sistemi: bir QcBlob'un içindeki **geçersiz** bir PQ imzası (`QcProofKind::InvalidDilithiumV1`) için slash edilebilir proof üretilebilir.

**Domain separation:** `qc.rs:576`'da `b"BUDLUM_PQ_QC"` prefix'i ile imza mesajları domain-separated; bir imza yalnızca kendi bağlamında (finality QcBlob) geçerli.

### 2.3 Hibrit Katmanı (Mevcut Olmayan — Gelecek)

**Sorun:** Finality BLS imzaları hâlâ **klasik** (BLS12-381).  PQ imzayı QcBlob'a ekledi ama BLS'yi değiştirmedi. Bu, **hibrit olmayan** bir sistem yaratıyor:
- QcBlob **PQ güvenli** ✅
- BLS finality **PQ güvenli değil** ⚠️

**Çözüm yolu (+):** BLS imzalarını **PQ imzalarla eş-bağlamak** (cross-sign). Bir BLS imzası geçerli sayılabilmesi için yanında bir Dilithium imzasıyla daha imzalanmış olmalı. Bu, **klasik + PQ hibrit** modeli sağlar: biri kırılsa bile diğeri güvende.

---

## 3. Post-Quantum Yol Haritası (+)

### 3.1 Kısa Vadeli (-10)

| ID |  | Kabul Kriteri |
|---|---|---|
| **PQ-1** | HNDL koruması: eski finality mesajlarının PQ-imzalı "**tape**" formatında arşivlenmesi | Son 1000 epoch'un her bir finality kararı için `FinalityCertWithPQ` objesi diske yazılıyor; `verify_against_snapshot` replay'ı 2030+ ortamında hâlâ doğrulanabiliyor |
| **PQ-2** | BLS hibrit binding: `BLSFinalityCert` artık `pq_attestation: PqSignatureEntry` zorunlu alan içeriyor | Mevcut `handle_finality_cert` testleri geçiyor + yeni `bls_without_pq_attestation_rejected` testi ekleniyor |
| **PQ-3** | VRF alternatifi: PoS için `pq_vrf: PqSignatureEntry` opsiyonel alan | PoS config flag'i `use_pq_vrf`; aktifse eski Schnorr VRF yerine Dilithium-based PRF kullanılıyor |

### 3.2 Orta Vadeli (-13)

| ID |  | Kabul Kriteri |
|---|---|---|
| **PQ-4** | ML-KEM (Kyber) ile gizli konsensüs: leader election private randomness'i KEM-shared | KEM anahtar üretimi `pqcrypto-kyber` crate'i, 1MB bellek, 100µs latency |
| **PQ-5** | HSM (PKCS#11) PQ modülü: `Pkcs11Signer` artık ed25519 + BLS + **Dilithium** destekliyor | `signer_backend = "pkcs11_pq"` config seçeneği; test fixture'ı YubiHSM2 veya simulated PKCS#11 ile |
| **PQ-6** | **SLH-DSA (SPHINCS+)** fallback: bir PQ imza gerektiğinde Dilithium yoksa SLH-DSA imza yedek olarak kabul | Klasik + Dilithium + SLH-DSA üçlü imza, üçünden en az ikisi doğrulanırsa geçerli |

### 3.3 Uzun Vadeli (+)

- **FN-DSA (Falcon)** entegrasyonu: kompakt imza gereken yerlerde (örn. mobil client) Dilithium yerine Falcon.
- **Hash-based** fallback: eğer hem lattice-based hem hash-based kırılırsa (NIL: unlikely ama tehditsel analiz gerekir), **one-time signature** zincirine (Lamport / Winternitz) geçiş yolu.
- **Hibrit geçiş dönemleri:** her klasik primitive için **PQ eşdeğeri ile birlikte 1-2 yıl yan yana** çalıştırma dönemi. Eski düğümlerin upgrade olduğundan emin olmak için "dual-verify" dönemi.

---

## 4. PQ Karar Kriterleri (Operatörler İçin)

Bir operatörün Budlum'u kurarken post-quantum güvenliğe nasıl baktığını belirleyen 4 karar:

1. **Anahtar depolama stratejisi:**
   - **Lokal (varsayılan):** `KeyPair::save`/`ValidatorKeys::save` 0o600 ile diske yazar. PQ-değil; **FS-level şifreleme** (LUKS/dm-crypt) operatörün sorumluluğu.
   - **PKCS#11 HSM:** `signer_backend = "pkcs11"` — anahtar hiç diske yazılmaz. Üretim için **önerilen**.
   - **PKCS#11 PQ HSM:** 'de — YubiHSM2 + Dilithium5 destekli.

2. **Geçiş dönemi stratejisi:**
   - **Tek-imza (Dilithium5):** Şu an mevcut. HNDL'ye karşı yeterli.
   - **Hibrit (BLS + Dilithium):**  hedefi. Üretim mainnet için **önerilen**.
   - **Üçlü (BLS + Dilithium + SLH-DSA):**  hedefi. En yüksek güvenlik; **konservatif mainnet** için.

3. **Geçmiş arşiv politikası:**
   - **Yok:** geçmiş validatör imzaları nodes'un local state'inde.
   - **PQ-tape:** `FinalityCertWithPQ` objeleri **bağımsız bir arşiv düğümünde** imzalanıp saklanır ().
   - **Tam zincir arşivi:** tüm eski block'lar + finality sertifikaları PQ-imzalı tutulur (+).

4. **Hata toleransı:**
   - **Sıkı:** PQ imza doğrulaması başarısızsa block reddedilir.
   - **Geçiş:** 1.0 sürümüne kadar PQ imza doğrulaması uyarı verir ama reddetmez (mevcut durum).

---

## 5. Doğrulama ve Test

### 5.1 Mevcut PQ Test Kapsamı

- `src/tests/integration.rs` — Dilithium keypair üretimi + sign/verify round-trip.
- `src/tests/qcblob_quorum.rs` — QcBlob imza sayısı kontrolü (2/3 quorum).
- `src/tests/finality_adversarial.rs` () — QcProofKind::InvalidDilithiumV1 fault-proof.
- `src/consensus/qc.rs::tests` — birim testleri (verify, fault proof, conflict).

### 5.2 PQ-Specific Test Listesi (+)

```
- [ ] pq_hndl_archive_replay_works_after_quantum_break
- [ ] bls_finality_without_pq_attestation_rejected
- [ ] pq_vrf_produces_unique_per_epoch_randomness
- [ ] ml_kem_shared_secret_used_in_leader_election
- [ ] pkcs11_pq_signer_round_trip
- [ ] slh_dsa_fallback_accepted_when_dilithium_unavailable
- [ ] hybrid_signature_two_of_three_sufficient
- [ ] classic_signature_alone_rejected_post_tur12
```

### 5.3 Sürekli Doğrulama

- Her Dilithium upgrade'inde `pqcrypto-dilithium` versiyonu **`Cargo.lock`**'ta pin'lenir.
- **Yılda 1 kez** NIST PQC standartları (FIPS 203/204/205) gözden geçirilir.
- **Her 6 ayda bir** `pqcrypto-*` crate'lerinin upstream güvenlik bültenleri takip edilir.

---

## 6. Bilinen Sınırlamalar (Dürüst Kapsam)

- **FIPS 204 standardizasyonu tamamlanmamışken** Dilithium5 implementasyonu (pqcrypto-dilithium 0.5.0) kararlı, ancak **parametre seçimi** (q, η, dilithium5 spesifik) final standartta değişebilir. Crate upgrade'leri **breaking change** riski taşır.
- **Yan kanal saldırıları** (timing, cache) PQ implementasyonlarında da mevcut; HSM kullanımı zorunlu.
- **Performans:** Dilithium5 imza doğrulama ~50µs, imzalama ~100µs (klasik Ed25519: 5µs / 30µs). QC üzerinde bu overhead **her QcBlob doğrulamasında** ödenir.
- **Test kapsamı:** PQ'a özel fuzz hedefi yok ('de eklenecek — `pq_signature_fuzz`).

---

## 7. Referanslar

- NIST FIPS 203 (ML-KEM): https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204 (ML-DSA / Dilithium): https://csrc.nist.gov/pubs/fips/204/final
- NIST FIPS 205 (SLH-DSA / SPHINCS+): https://csrc.nist.gov/pubs/fips/205/final
- CRYSTALS-Dilithium spec: https://pq-crystals.org/dilithium/
- pqcrypto-rs: https://github.com/rustpq/pqcrypto
- "Harvest Now, Decrypt Later" — ENISA 2022 report
- Cloudflare PQ blog: https://blog.cloudflare.com/post-quantum-keys (NIL: yüksek seviye referans)

---

*Bu doküman, v0.3-dev'in  post-quantum güvenlik durumunu sabitler. Yeni PQ entegrasyonları bu dokümanı güncellemeden merge edilmez.*
