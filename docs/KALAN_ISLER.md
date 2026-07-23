# Kalan İşler — Budlum

**Güncelleme:** 2026-07-22 (ARENA2) · main

---

## AI execution layer

✅ **Hardened skeleton:** host MLP eval, domain commitments, guest v2, structural+STARK envelope checks, `require_execution_proof` finalization gate, `prove_mlp_inference`, `try_finalize_with_proofs`.

✅ **VerifyInference AIR binding (ARENA2 2026-07-23):** 5 column (373-377), selector↔opcode 0x1F binding, rd=0 fail-closed, expansion row commitment consistency, VM next_pc fix, soundness test.

✅ **Dense matmul host bit-exact:** `eval_fixed_point_mlp` i32 MAC host'ta; guest sadece Poseidon commitment bind.

✅ **Full matmul-in-guest AIR (ARENA2 2026-07-23):** `build_matmul_guest_program()` — MLP forward pass BudZKVM instruction'larında (Load/Mul/Add/Sub/Lt/Jnz/Poseidon/Halt). Register allocation, ReLU conditional, MAX_GUEST_OPS guard. 7 test.

✅ **Production gas metering (ARENA2 2026-07-23):** `estimate_structural_gas`, `estimate_full_gas`, `validate_gas_budget`. Executor `AiAttachExecutionProof` path'inde proof size vs execution class limit kontrolü.

📋 **LLM / float:** mainnet v1 scope dışı — `docs/AI_ONCHAIN_EXECUTION_RESEARCH.md`.

## Pre-mortem güvenlik audit düzeltmeleri (ARENA2 2026-07-23)

✅ **R2 (KRİTİK):** Bridge RPC auth — mint/burn/unlock/unlock_verified → `require_operator()` (5 method)
✅ **S1 (KRİTİK):** PrivacyCommit blinding u32 truncation → register-based full u64 (VM + wallet-core + callers)
✅ **S2 (YÜKSEK):** SumConservation u64 vs field comparison → Goldilocks P bound check
✅ **S4 (YÜKSEK):** Poseidon constants element-wise lock test (MDS + RC matrix)
✅ **S5 (YÜKSEK):** VerifyMerkle env var gate kaldırıldı → hard-coded `MainnetActivation::full()`
✅ **B2 (KRİTİK):** Bridge mint payload_hash amount verification
✅ **B3 (YÜKSEK):** ReplayNonceStore pruning (MAX_PROCESSED_MESSAGES = 65536)

### Kapanan audit bulguları (önceki agentlar tarafından):
- A4: Unbonding queue → `retain()` ile zaten prune ediliyor (audit yanlış)
- N2: Snapshot chunk DoS → MAX bounds zaten mevcut

✅ **E1 (KISMİ — kritik path'ler):** Transfer receiver checked_add + bridge mint try_add_balance
✅ **W1:** Wallet seed/mnemonic zeroize on drop (zeroize crate)

### Kalan audit bulguları (mainnet öncesi):
- ⏳ E1 (kalan ~100 saturating instance): kademeli checked arithmetic geçişi
- ⏳ S6: Syscall result AIR constraint (public input binding)
- ⏳ C1: BLS hash_to_g1 RFC 9380 (kripto değişiklik)
✅ **C3 (KISMİ):** Validator consensus key readiness check + warning log + 4 test
- ⏳ H1: PKCS#11 BLS/PQ non-extractable (donanım/audit)

## Intent → zincir (private transfer)

✅ L1NoteRegistry + PrivateTransferSubmit path.

## Z-B / HSM / TEE / Ceremony

Z-B ✅ · HSM ⏳ donanım · TEE ⏳ SDK · Ceremony ⏳ Ayaz.

---
*CI tek hakem.*
