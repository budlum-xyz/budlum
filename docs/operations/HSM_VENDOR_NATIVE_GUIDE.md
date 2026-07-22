# BLS/PQ HSM Vendor-Native Entegrasyon Rehberi (Task 4, Q: add_doc)

**Durum:** Taslak, 2026-07-16
**Karar:** Q hsm_next = keep_real_only (sadece gerçek PKCS#11), mock yok. Vendor-native audit item.
**Kaynak:** `src/crypto/pkcs11.rs`, `src/crypto/signer.rs`, `docs/operations/HSM_BLS_PQ_POLICY.md`

## Mevcut Durum
- Ed25519: Gerçek PKCS#11 HSM via cryptoki CKM_EDDSA
- BLS12-381: BUD_BLS_KEY data object + software sign
- PQ: BUD_PQ_KEY data object + software sign
- Policy: mainnet validator backend=pkcs11 only, disk keys fail-closed

## Vendor-Native Ne Demek?
PKCS#11 standardında BLS/Dilithium mechanism yok. Vendor extension ile CKM_VENDOR_BLS_SIGN, CKM_VENDOR_DILITHIUM_SIGN. Private key non-extractable (CKA_EXTRACTABLE=false, CKA_SENSITIVE=true).

## Entegrasyon
- Module discovery: pkcs11-tool --list-mechanisms | grep -i BLS/DILITHIUM
- Key generation non-extractable
- Signing HSM içinde: session.sign(mech, key_handle, msg)

## Audit Checklist
- [ ] Token info + mechanism listesi
- [ ] Private key extractable=false
- [ ] Signing HSM içinde, secret dışarı çıkmıyor
- [ ] Mainnet validator pkcs11 only fail-closed
- [ ] Disk ValidatorKeys reddediliyor
- [ ] PIN env var boş ise exit 1

## Sonraki Adım
Vendor HSM temin edilince Mechanism enum'ına vendor mechanism ekle, generate_bls_key non-extractable, bls_sign/pq_sign HSM sign kullan, harici audit + TLA+.
