# Provenance notes

A map for reviewers, not a clearance. This file records, per module, what a
non-trivial implementation appears to be based on, a paper, a specification,
or an existing crate, and marks the cases where the origin could not be
established.

**What this file is not.** It is not a similarity scan and it makes no claim
that the tree is free of copyright problems. Establishing that requires a
snippet-level provenance tool (FOSSA, Black Duck, ScanCode) run by people who
can act on the result. Nothing below should be read as "cleared". Where the
origin is unclear the entry says so rather than guessing.

Method: read the source, the doc comments, and the dependency graph; where a
module resembled an upstream crate, the upstream was fetched and compared line
by line. Findings that rest on a measurement quote the measurement.

---

## Requires attribution: action needed

### `budzero/bud-proof/src/bud_stark/`: derived from Plonky3 `p3-uni-stark`

Not merely "follows the approach of". Compared against `p3-uni-stark 0.6.2`
(fetched 2026-07-27):

| file | p3-uni-stark | bud_stark | shared unique lines |
|---|---|---|---|
| `verifier.rs` | 551 | 545 | 261 / 378 (~69%) |
| `prover.rs` | 555 | 576 | 277 / 419 (~66%) |
| `folder.rs` | 226 | 337 | - |
| `symbolic.rs` | 241 | 231 | - |
| `config.rs` | 87 | 96 | - |
| `sub_builder.rs` | present | present | - |
| `preprocessed.rs` | present | present | - |

The file layout is identical and several doc comments match verbatim
("A minimal univariate STARK framework.", "STARK-specific quotient polynomial
degree calculations."). This is a fork with local modifications, not an
independent implementation.

- **Upstream licence:** `MIT OR Apache-2.0`. Budlum now distributes under
  PolyForm Shield 1.0.0. Taking the upstream MIT option keeps this compatible:
  MIT permits redistribution under different terms provided the MIT notice is
  retained, which `NOTICE` does. No licence conflict.
- **Gap:** there is currently **no attribution anywhere in the tree**, no
  header, no `NOTICE`, no mention in the crate docs. Apache-2.0 §4 requires
  retaining attribution notices for derivative works. This should be fixed
  before mainnet; it is a paperwork gap, not a legal blocker, but it is the
  clearest actionable item in this file.
- Upstream: <https://github.com/Plonky3/Plonky3>

---

## Based on a public specification

These follow a published spec closely enough that the spec, not any particular
implementation, is the source. Independent re-implementation from a spec is the
normal case and carries no attribution obligation, but a reviewer should check
conformance rather than novelty.

| module | specification |
|---|---|
| `src/cross_domain/evm/rlp.rs` | Ethereum Yellow Paper, Appendix B (RLP). Stated in the module docs. In-tree by decision, no `alloy`/`ethers`. |
| `src/cross_domain/evm/mpt.rs` | Ethereum Yellow Paper, Appendix D (Merkle-Patricia Trie). Verify-only; proof construction lives in the relayer. |
| `src/cross_domain/evm/sync_committee.rs` | Ethereum consensus specs, Altair sync-committee light client (512 validators, ~27h period, BLS12-381 aggregate). |
| `src/cross_domain/evm/receipt.rs` | Ethereum receipt RLP schema + `receiptsRoot` proof. |
| `wallet-core/src/bip39_wordlist.rs` | BIP-39 English wordlist, 2048 words. Reproduced verbatim by necessity: any deviation breaks interoperability with every standard wallet. The list is a specification artefact. |
| `wallet-core/` key derivation | BIP-32 / BIP-39 derivation. Conformance should be checked against the BIP test vectors. |

## Standard cryptographic constructions via audited crates

Not implemented in-tree. Budlum calls the crate; the algorithm's provenance is
the crate's.

- Ed25519: `ed25519-dalek`
- BLS12-381 signatures and pairings, `bls12_381`, `blst`
- Post-quantum signatures, `ml-dsa` (ML-DSA-65 validator / ML-DSA-87 wallet, FIPS 204 NIST final; DEFAULT), `pqcrypto-dilithium` (Dilithium5, round-3 legacy - migration only)
- SHA-2 / SHA-3 / Keccak / BLAKE2: `sha2`, `sha3`, `blake2`
- AES-GCM, ChaCha20-Poly1305, `aes-gcm`, `chacha20poly1305`
- sr25519 / VRF: `schnorrkel`
- PKCS#11 HSM, `cryptoki`
- Poseidon / Poseidon2 permutations: `p3-poseidon1`, `p3-poseidon2` (constants come from Plonky3, locked by a test)

## Origin unclear or original: flagged for the audit

Marked because they could not be traced to a known source, **not** because they
are believed to be original. These are where an external reviewer should look
hardest: they are consensus-critical and have no upstream to compare against.

| module | note |
|---|---|
| `src/consensus/poa.rs` | Leader election from block-hash entropy. No source comment. The `leader_entropy()` helper and its domain-tagged sentinel were written here, in response to a fork-primitive finding. **Origin unclear.** |
| `src/consensus/pos.rs` | Epoch randomness, slot seeds, cache-poison fallback. Resembles the general shape of Ethereum-style epoch randomness but matches no specific spec that could be identified. **Origin unclear.** |
| `src/consensus/qc.rs` | Quorum certificates and equivocation fault proofs. The QC pattern is standard BFT literature (HotStuff/Tendermint family); this particular formulation was not traced to one. **Origin unclear.** |
| `src/domain/fork_choice.rs` | Per-domain fork choice. Deliberately pure/deterministic. Not matched to a published rule such as LMD-GHOST. **Origin unclear.** |
| `src/consensus/pow.rs` | Bounded PoW with binary difficulty check. Conventional, but no specific source. **Origin unclear.** |
| `budzero/bud-isa`, `budzero/bud-vm` | Instruction set and VM semantics. The zkVM shape is a well-trodden area (RISC-V-like ISAs proved with AIR constraints), but the opcode set and trace layout are project-specific. **Origin unclear.** |
| `budzero/bud-proof/src/plonky3_air.rs`, `plonky3_prover.rs` | AIR constraints for the Budlum VM, written against the Plonky3 API. The constraints are project-specific; the framework they target is Plonky3. |
| `src/core/block.rs`, `src/core/account.rs` | Block hashing and state-root folding, domain-separated with `BDLM_*` tags. Structure is conventional Merkle accounting; the specific layout is project-specific. **Origin unclear.** |
| `src/tokenomics/` | Fixed-supply emission, vesting, burn. Economic design, not a ported algorithm. **Original as far as can be determined.** |

## Design references (idea level, no code copied)

Studied projects that influenced a design decision. They are recorded here
and in `docs/NOTICE` so the names are stated where attribution belongs.
The `no_upstream_brands` gate keeps these names out of code and
identifiers; this file is on the gate's attribution exemption list for
that reason.

| module | studied project | licence | what was taken | what was not taken |
|---|---|---|---|---|
| `crates/ai-inference/crates/ai-serve/src/residency.rs` | JustVugg/colibri, pure C on-device MoE engine (https://github.com/JustVugg/colibri) | Apache-2.0 | The placement principle: keep the dense part of a mixture-of-experts model resident, stage the routed experts across a VRAM/RAM/disk hierarchy, and let placement never change semantics. | The runtime: colibri's streaming, prefetch, heat maps and eviction live in C runtime code that is not present in the tree. The in-tree module is a Rust planner that plans placements and refuses to change the semantic profile. Different language, different layer, no shared lines. |
| bounded-buffer and ceiling behaviour, `docs/ARCHITECTURE.md` | 1jehuang/jcode, coding agent (https://github.com/1jehuang/jcode) | MIT | The memory discipline: bounded buffers and explicit ceilings as the default, and a ceiling that silently turns a feature off being treated as a design failure. | jcode is a JavaScript agent. The in-tree behaviour is Rust RPC and proof-cache code written in this tree. No shared code. |
| `crates/ai-inference/crates/ai-core/src/system_prompt.rs` | a corpus of published system prompts (consulted for structure; not redistributed, no single upstream named) | n/a | The discipline of stating machine-checkable limits inside the prompt itself. | The prompt text is original: it states this protocol's own admission limits and is checked against the tree by the `ai-inference-prompt-is-true` gate. No prompt text was reproduced. |

---

## Not reviewed here

`src/ai/`, `src/pollen/`, `src/socialfi/`, `src/storage/`, `src/hub/`,
`src/bns/`: application-layer modules. They were skipped because this pass was
scoped to cryptography, proving and consensus, which is where a provenance
problem would be both hardest to spot and most damaging. They are not implied
to be clean.

---

## Follow-ups

1. **Add attribution for `bud_stark`.** A `NOTICE` file plus a header in
   `bud_stark/mod.rs` naming Plonky3 and its `MIT OR Apache-2.0` licence.
   Tracked as the one concrete gap this pass found.
2. **Snippet-level scan before mainnet.** Out of scope for CI and out of scope
   for what an assistant can assert. Needs FOSSA / Black Duck / ScanCode.
3. **Conformance tests over novelty review** for the spec-based modules: RLP
   and MPT against Ethereum test vectors, BIP-39/32 against the BIP vectors.
4. **The "origin unclear" table is the audit's starting point**, particularly
   the consensus modules, no upstream exists to diff them against, so
   correctness has to be argued from the code and its tests.

Generated 2026-07-27 against commit `f92774b`.
