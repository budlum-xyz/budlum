# Kalan İşler — Budlum

**Güncelleme:** 2026-07-22 (ARENA2) · Teknik kapanmamış / kısmen kapanmış işler.

---

## AI execution layer

Zincir-üzeri AI **execution** (modelin BudZKVM guest olarak koşması + STARK kanıt)
hâlâ araştırma. Lubot attestation / AiRegistry / soft-incentive **mevcut**.

- İskelet: `docs/AI_ONCHAIN_EXECUTION_RESEARCH.md` (ARENA2).
- VerifyInference (0x1F) execution stub (rd=0); AIR/proof envelope binding açık.
- **Kapanış kriteri:** bounded model-class RFC + mini MLP prove/verify + 0x1F AIR.

## Z-B: BudZKVM VerifyMerkle 64-depth soundness

✅ **KAPANDI (kod + test + CI):** `proves_verify_merkle_valid_64_depth` yeşil.
**Mainnet kapısı** `MainnetActivation::verify_merkle_enabled` default off
(ceremony). Proof-of-storage ürünleştirmesi B.U.D. entegrasyonuna bağlı.

## BLS/PQ HSM vendor-native

Kısmen kapandı (kod ajanı donanımı kapatamaz):

- ✅ Ed25519 PKCS#11 native
- ✅ Vendor mechanism parse + `CKM_VENDOR_DEFINED` altı fail-closed
- ✅ `Pkcs11VendorCapabilities` advertisement
- ⏳ Gerçek vendor HSM non-extractable BLS/Dilithium keygen + harici audit
  (**Ayaz tedarik / donanım**)

## Gizlilik katmanı — AIR + E2E + cüzdan wire

✅ **KAPANDI:**

| Parça | Kanıt |
|---|---|
| AIR selectors + Poseidon gadget | `bud-proof` `d2_proves_*` |
| VM semantik | `bud-vm` privacy opcodes |
| Note registry | `bud-state` |
| Cüzdan opt-in config | `WalletPrivacyConfig` |
| **Wallet-bound wire** | `Wallet::{set_privacy_config, build_private_transfer, sign_with_privacy}` |
| TEE fail-closed | `TeeRuntime` + `UnavailableTeeRuntime` (enklav yokken plaintext yok) |
| View-key | `ensure_view_key` / disclosure export |
| Private transfer intent | `PrivateTransferIntent` (relayer'a imzalı public half) |

⏳ **Operasyonel kalan (kod dışı / ayrı hat):**

- Gerçek SGX/Nitro `TeeRuntime` implementasyonu (SDK + cihaz)
- Relayer/mempool'un `PrivateTransferIntent` → zincir tx montajı
- MainnetActivation privacy opcode flip (ceremony)

---

*Mainnet kapıları (MainnetActivation, HSM hardware, TEE enclave) Ayaz +
donanım/operasyon. Bu dosya teknik kod kapanışını izler.*
