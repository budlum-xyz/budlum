# Kalan İşler — Budlum

**Güncelleme:** 2026-07-22 · Teknik kapanmamış işler (gorev dili yok).

---

## AI execution layer

Zincir-üzeri AI çalıştırma katmanı tasarlanmadı. Lubot inference (model kayıt,
attestation, soft incentive) var; ancak on-chain AI execution (modelin zincirde
koşması + kanıtlanması) araştırma gorevsında — kod yok.

## Z-B: BudZKVM VerifyMerkle 64-depth soundness

Production ISA'da gate'li (kapalı). 64-derinlik pozitif/negatif test kanıtı yok →
"proof-of-storage" iddiası yapılamıyor. Gate ancak bu kanıt yeşil olunca kaldırılır.

## BLS/PQ HSM vendor-native

Ed25519 PKCS#11 var; BLS/Dilithium için sadece mock backend. Gerçek HSM vendor
entegrasyonu (YubiHSM/Thales/AWS CloudHSM ile BLS/PQ imzalama) yok.

## Gizlilik katmanı — AIR constraint'leri

Opcode iskeleti var (PrivacyCommit/NullifierCheck/SumConservation 0x20-0x22) +
note registry + TEE toggle. **AIR constraint'leri YOK** → zk-proof soundness yok.
En kritik yarım iş.

## Gizlilik katmanı — E2E test

commit → nullifier → sum-conservation uçtan uca akış testi (AIR constraint'leri
tamamlandıktan sonra).
