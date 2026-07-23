# Kalan İşler — Budlum

**Güncelleme:** 2026-07-22 (ARENA2) · main

---

## AI execution layer

✅ **Hardened skeleton:** host MLP eval, domain commitments, guest v2, structural+STARK envelope checks, `require_execution_proof` finalization gate, `prove_mlp_inference`, `try_finalize_with_proofs`.

✅ **VerifyInference AIR binding (ARENA2 2026-07-23):** 5 column (373-377), selector↔opcode 0x1F binding, rd=0 fail-closed, expansion row commitment consistency, VM next_pc fix, soundness test.

✅ **Dense matmul host bit-exact:** `eval_fixed_point_mlp` i32 MAC host'ta; guest sadece Poseidon commitment bind.

📋 **LLM / float:** mainnet v1 scope dışı — `docs/AI_ONCHAIN_EXECUTION_RESEARCH.md`.

⏳ Full matmul-in-guest AIR (MLP forward pass tamamen BudZKVM instruction'larında); production gas metering calibration.

## Intent → zincir (private transfer)

✅ L1NoteRegistry + PrivateTransferSubmit path.

## Z-B / HSM / TEE / Ceremony

Z-B ✅ · HSM ⏳ donanım · TEE ⏳ SDK · Ceremony ⏳ Ayaz.

---
*CI tek hakem.*
