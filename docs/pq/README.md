# Post-quantum program

This directory is the working record of the post-quantum security program.
Every file here is English. Nothing in this directory is a claim by itself:
a claim becomes citable only through `CLAIMS.md` (once it exists), and only up
to the rung its evidence reaches.

| File | Content |
|---|---|
| `DECISIONS.md` | The fixed decisions to. They are not reopened. |
| `INVENTORY.md` | The live code inventory, one row per surface, each with `file:line@SHA` evidence. A refuted row stays and keeps its evidence. |
| `STATUS.md` | One line per task, with a status value and the commit and CI evidence for DONE. |
| `classical_allowlist.toml` | The allow list read by the `classical-crypto-is-paired` gate. |
| `MEASUREMENTS.md` | Output of the measurement tools. |
| `CLAIMS.md` | The claims register. |
| `THREAT_MODEL.md` | The attacker model. |
| `AUDIT_SCOPE.md` | The audit packages. |
| `RECURSION_PLAN.md` | The BudZero recursion plan. |

## Layout of the cryptographic core (Phase 1)

| Module | Role |
|---|---|
| `src/crypto/scheme.rs` | `SchemeId`, suites, the status machine and `SchemeStatusRegistry`. A scheme is never inferred from a length. |
| `src/crypto/ctx.rs` | FIPS 204 and FIPS 205 context strings. Mirrored in `domain_tags.rs`. |
| `src/crypto/pq.rs` | The verification facade. ML-DSA is verified by two libraries and both must accept. SLH-DSA has one library and mandatory ACVP vectors. |
| `src/crypto/composite.rs` | The composite signature: a post-quantum component plus Ed25519 over one message representative. |

`pq.rs`, `scheme.rs`, `ctx.rs` and `composite.rs` have no dependency on the rest of
the node, so `crates/wallet-core` mounts the same source files and the same test vectors run
on the wallet build (including wasm32).

Test vectors live in `tests/vectors/pq/`. Their provenance and the extraction recipe are in
the README of that directory.
