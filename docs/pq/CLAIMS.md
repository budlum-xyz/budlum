# Post-quantum claims register

Every statement about quantum computers anywhere in the repository (the READMEs, `docs/`, the
crate READMEs) carries a claim id from this file, and the claim has to be backed. The
`pq_claims_are_backed` gate (INV-11) enforces both. A claim is backed when its status reaches
its rung and every piece of evidence it names exists in the tree.

This file is the only place a rung sentence can be raised. A rung is reached when its phases are
`DONE` in `STATUS.md`; until then its claim stays at status `none` and no document may cite it.

## How to read a row

| Column | Meaning |
|---|---|
| ID | The claim id. Documents cite it as `<!-- claim:ID -->` at the end of the line that makes the statement. |
| Layer | The layer the claim is about. |
| Rung | The rung of the claim ladder its sentence needs, `I-0` to `I-4`. |
| Status | The rung its evidence reaches today: `none` or `I-0` to `I-4`. The gate refuses a citation when Status is below Rung. |
| Evidence | The tests that carry the claim. `test:NAME` is a Rust function in the tree, `gate:NAME` a registered gate, `tool:NAME` a registered tool. `planned:TASK` is allowed only while the Status is `none`. |
| Statement | The sentence, in English. |

Words that are never used: "unbreakable", "quantum-proof", "100% quantum safe", and a "quantum-resistant"
that names no layer. The gate refuses them.

## The claim ladder

The team uses only the sentence of the rung that has been reached.

| ID | Layer | Rung | Status | Evidence | Statement |
|---|---|---|---|---|---|
| S-I0 | plan | I-0 | I-0 | `test:sign_and_verify_roundtrip`, `test:verify_rejects_wrong_message`, `gate:pq-claims-are-backed` | Budlum approaches the quantum threat with a complete plan. Every layer has a defined solution, a metric and a completion gate. The Budlum wallet core signs today with NIST FIPS 204 ML-DSA-87. |
| S-I1 | signatures | I-1 | none | `planned: `, `planned: `, `planned: `, `planned: ` | Every signature Budlum produces rests on NIST post-quantum standards. A classical signature is used only as extra assurance, together with a post-quantum signature. Needs phases 1, 2, 3 and 5 DONE. |
| S-I2 | transport and data | I-2 | none | `planned: `, `planned: ` | Budlum network traffic and data sharing use NIST ML-KEM based hybrid key exchange. Needs I-1 and phase 6 DONE. |
| S-I3 | all layers | I-3 | none | `planned: `, `planned: `, `planned: `, `planned: ` | The signature, key exchange, randomness and proof layers of Budlum rest on NIST post-quantum standards or on hash assumptions only. External networks that use classical cryptography are marked in the profile. When a break is proven on chain, those networks are isolated automatically. Needs I-2 and phases 4, 7, 8, 10 and 11 DONE. |
| S-I4 | audit | I-4 | none | `planned: ` | The I-3 sentence, and: these layers have passed an independent audit. Needs I-3 and the phase 12 audits closed. |

## Layer facts that are true today

These are narrower than the ladder sentences. They describe what the code does now, one layer at a
time, and they do not stand in for a rung.

| ID | Layer | Rung | Status | Evidence | Statement |
|---|---|---|---|---|---|
| L-WALLET-01 | wallet | I-0 | I-0 | `test:sign_and_verify_roundtrip`, `test:verify_rejects_wrong_message` | The wallet core derives its key and signs with NIST FIPS 204 ML-DSA-87 (security Category 5). ML-DSA rests on module lattices, not on factoring or discrete logarithms, so Shor's algorithm does not apply to the wallet key. |
| L-FINALITY-01 | finality | I-0 | I-0 | `test:test_qc_blob_verify_against_snapshot`, `test:c3_validator_with_vrf_and_bls_still_needs_pq` | Finality is attested with BLS12-381 aggregate signatures together with a quorum certificate blob of ML-DSA-65 signatures, verified against the validator-set snapshot. A validator registration needs a post-quantum key. |
| L-PROOF-01 | proofs | I-0 | I-0 | `tool:stark-soundness` | BudZero STARK proofs reach at least 128 bits of provable security, with no assumption, under the parameters in `MEASUREMENTS.md`. The assumed and the quantum readings are stated there too; the quantum reading of the provable value is lower. |
| L-PROOF-02 | proofs | I-0 | I-0 | `gate:no-pairing-snark-in-verification-path` | No pairing-based SNARK (Groth16, KZG-based PLONK, anything over BN254) sits on a Budlum verification path. |
| L-HASH-01 | signatures | I-0 | I-0 | `test:the_canonical_backend_is_shake256_and_not_poseidon2`, `test:kat_rows_are_frozen` | The canonical hash of the BPQS research signature is SHAKE-256. Poseidon2 is a research backend only. The production anchor slot for BPQS stays reserved and fails closed. |
| L-MERKLE-01 | proofs | I-3 | none | `test:proves_verify_merkle_over_256_bit_nodes`, `test:verify_merkle_compares_every_word_of_the_root`, `test:rejects_verify_merkle_with_a_forged_result`, `test:the_shared_permutation_matches_plonky3_on_pseudorandom_states` | The VerifyMerkle opcode compresses 256-bit nodes with the Poseidon parameter set, and the VM and the AIR agree on the result. |
| L-PRIVACY-01 | proofs | I-3 | none | `planned: ` | Privacy note commitments are 256 bits wide, and the wallet computes them with the same function as the VM. |
| L-CODE-01 | code | I-0 | I-0 | `gate:no-constant-security-verdicts` | No function named like a security verdict returns a constant. |

## Invariants

Every invariant is protected by a test. The test is named here. An invariant whose test is not written
yet carries `planned:` and status `none`.

| ID | Layer | Rung | Status | Evidence | Statement |
|---|---|---|---|---|---|
| INV-01 | signatures | I-1 | none | `planned: ` | No transaction, block, vote, evidence, anchor, certificate or snapshot is accepted on a classical signature alone on mainnet. |
| INV-02 | signatures | I-1 | none | `planned: ` | Every signed payload signs its scheme id, its suite and its domain tag. |
| INV-03 | signatures | I-1 | none | `planned: ` | A scheme is never inferred from a length. |
| INV-04 | hashes | I-1 | none | `planned: ` | Every hash output that binds security is at least 256 bits wide. |
| INV-05 | signatures | I-1 | none | `planned: ` | Consensus ML-DSA verification gives the same decision on every platform. |
| INV-06 | storage | I-1 | none | `planned: ` | A witness is deleted only after finality and the retention period. |
| INV-07 | signatures | I-1 | none | `planned: ` | The recovery path is open only while the ML-DSA family is `Disabled`. |
| INV-08 | transport | I-2 | none | `planned: ` | No TLS or Noise session on mainnet is established with X25519 alone. |
| INV-09 | consensus | I-3 | none | `planned: ` | A verified canary proof changes the state in the same block on every node. |
| INV-10 | consensus | I-1 | none | `planned: ` | An anchor and a handover certificate are never accepted with fewer signatures than the threshold. |
| INV-11 | claims | I-0 | I-0 | `gate:pq-claims-are-backed` | No quantum claim stands in the repository without a claim id. |
| INV-12 | code | I-0 | I-0 | `gate:no-constant-security-verdicts` | No security verdict function returns a constant result. |
| INV-13 | regeneration | I-3 | none | `planned: ` | A regeneration target is only a stage that matches a post-quantum seal valid under the current alarm state. |
| INV-14 | regeneration | I-3 | none | `planned: ` | Regeneration never deletes a canonical block, a sealable block or a valid mempool transaction. |
