# Budlum Architecture Mastery — Arena Skill Reference (Hardened)

**Purpose:** Arena's existing process-skill covers *how* to work (pre-task clarification, TDD, four-phase debugging, verification, multi-agent coordination, security checklist). This file covers *what to build* in Budlum's six unresolved architecture blockers. It is written as a hardened reference: MUST/MUST NOT, not suggestions. Every subsystem below now has a named, professional-grade upstream implementation to study, adapt from, or vendor — not just papers.

**Non-negotiable rule:** touching any of these six subsystems is an architectural decision under the traffic-light framework. Arena MUST NOT silently pick a design and merge it. Arena MUST name which reference pattern was chosen, why alternatives were rejected, and stop for Ayaz's confirmation before merge — exactly like any other legitimate stop condition.

**Non-negotiable rule on external code:** every repository named below is a candidate to study or vendor, not a green light to `cargo add` unaudited. Any crate pulled from these references MUST clear Budlum's existing security tooling gate before it touches `main`: cargo-audit, cargo-deny, Semgrep, cargo-geiger, SBOM regeneration, OpenSSF Scorecard check, and a license check consistent with Budlum's Apache 2.0 base. CI (fmt + clippy -D warnings + test) remains the sole authoritative verifier — no exceptions for "it's just a reference implementation."

---

## 1. BudZKVM VerifyMerkle 64-depth (blocks real Proof-of-Storage)

**Verdict:** do not hand-roll the recursive verifier. Evaluate `Plonky3-recursion` first; only build custom if it can't be adapted.

- Plonky3 is under active development and is **not** fully audited for arbitrary configurations. Any "production-ready" claim about a Plonky3-based component MUST be checked against the actual audit scope, not assumed.
- Least Authority's audit of Plonky3 found a real Fiat-Shamir soundness bug: the challenger wasn't absorbing public inputs, FRI config, or polynomial degree — letting a malicious prover tamper with unabsorbed data. **Hard requirement:** any custom VerifyMerkle implementation MUST have its Fiat-Shamir transcript construction independently reviewed against this exact failure class before it is considered done.
- Field/hash: BabyBear + Poseidon2 is the current production-proven combination (used by SP1). Mersenne31/KoalaBear are promising but less battle-tested — do not pick them for the 64-depth verifier without a stated reason.

**GitHub references (study/adapt/vendor, in this priority order):**
| Repo | Why |
|---|---|
| https://github.com/Plonky3/Plonky3-recursion | In-circuit STARK verifier for both `p3-uni-stark` and `p3-batch-stark`, supports recursive composition — the direct building block for VerifyMerkle. |
| https://github.com/Plonky3/Plonky3 | Core toolkit; read `fri/` and `uni-stark/verifier.rs` before writing anything custom. |
| https://github.com/succinctlabs/sp1 | Production zkVM built on Plonky3 with BabyBear+Poseidon2 — reference for the "boring, proven" field/hash choice. |
| https://github.com/Plonky3/awesome-plonky3 | Curated ecosystem list; check before assuming no prior art exists. |
| leastauthority.com — Plonky3 audit report (PDF, linked from their site) | Read the Fiat-Shamir finding directly, don't rely on secondhand summaries. |

**Action items:** (a) run the Fiat-Shamir absorption check against Least Authority's finding before VerifyMerkle is marked done; (b) file a written comparison of `plonky3-recursion` vs. hand-rolled before choosing; (c) budget an external audit scoped specifically to Budlum's VerifyMerkle circuit — Plonky3 core being audited does not cover this.

## 2. Multi-consensus architecture (PoW + PoS + BFT + isolated PoA)

**Verdict:** Budlum's PoW/PoS/BFT split is not a novel problem — Polkadot runs this exact pattern (probabilistic block production + separate BFT finality gadget) in production, in Rust. Study it before designing from scratch.

- Two dominant hybrid lineages exist. Budlum MUST explicitly declare which one each domain follows — this is not implementation detail, it changes what security proofs are required:
  - PoW-elected-committee-then-BFT (Byzcoin-style)
  - PoS-finality-gadget-checkpointing-PoW (Casper FFG-style, same shape as Polkadot's BABE+GRANDPA)
- The isolated PoA layer is architecturally a permissioned sub-network bridged to a permissionless base — treat it as a bridge-trust problem (§3), not a fourth independent consensus mechanism.
- **Hard requirement:** hybrid protocols need one restated global adversarial-fraction bound across the composed system, not four independent per-domain bounds assumed to compose safely. This MUST be written down before mainnet, not inferred.

**GitHub references:**
| Repo | Why |
|---|---|
| https://github.com/paritytech/polkadot-sdk | Production hybrid consensus: BABE (block production) + GRANDPA (BFT finality gadget) running together, in Rust, at scale. Closest real-world analog to Budlum's design. |
| https://github.com/paritytech/finality-grandpa | Standalone BFT finality gadget crate, decoupled from the rest of Substrate — study for how a finality layer is cleanly separated from block production. |

**References (papers):** ACM Computing Surveys, "A Survey of Blockchain Consensus Protocols"; "Hybrid Consensus Mechanisms in Blockchain: A Comprehensive Review"; arXiv 2207.08392, "Bitcoin-Enhanced Proof-of-Stake Security."

## 3. Relayer trust model (blocking RPC work)

**Verdict:** do not default to attestation/multisig because it's cheapest to build. State the trust model per bridge explicitly and justify it against the three families below.

- Three canonical trust-model families:
  1. **Light-client / trustless** — verifies source-chain proofs on-chain. Strongest security, most expensive per destination chain.
  2. **Liquidity/relay network** — bonded relayers, optimistic execution, challenge window. Fast, adds bonded-trust + liveness assumption.
  3. **Attestation/committee (MPC/HSM/multisig)** — weakest trust-minimization; a threshold-signed committee is still a trusted third party regardless of signature scheme.
- Nearly all catastrophic bridge losses (Ronin's ~$540M included) trace to compromised relayer/validator keys, not broken cryptography. **This makes §3 and §4 (HSM) the same problem** — do not schedule them as independent workstreams.
- **Hard requirement regardless of model chosen:** rate limits, delayed settlement above an abnormal-flow threshold, independent monitoring, and an explicit pause/exit authority. A relayer without these is selling insurance without reserves.
- **Concrete recommendation:** PoA↔permissionless bridging can use attestation (the PoA layer already implies a trusted committee — don't pretend otherwise). PoW/PoS/BFT inter-domain relaying is adversarial-facing and MUST lean light-client-style.

**GitHub references:**
| Repo | Why |
|---|---|
| https://github.com/informalsystems/hermes | Production light-client-based IBC relayer, Rust, Apache 2.0. Direct reference for the light-client trust model recommended above for the adversarial-facing domains. |
| https://github.com/paritytech/polkadot-sdk (see `substrate/client/consensus/beefy`) | BEEFY — a consensus protocol purpose-built for efficient trustless bridging, designed to be light-client-friendly even for restricted verifier environments (e.g. an on-chain state transition function). Read this before designing Budlum's cross-domain relayer. |

**References (papers/analysis):** 1kxnetwork, "Blockchain Bridges"; Spark, "Blockchain Bridge Security Comparison"; arXiv 2607.06593, "Blockchain Attacks and Defenses."

## 4. HSM native-only vendor integration

**Verdict:** the native-only lock-in is a self-inflicted wound. Fix it with the PKCS#11 standard, not a second vendor SDK.

- **PKCS#11 (Cryptoki)** is the vendor-neutral standard API for HSM access — supported by Thales, Utimaco, AWS CloudHSM, and others. This is the direct fix, not a nice-to-have.
- Choose one integration layer and state why: direct PKCS#11 (lowest latency, most control, most expertise required) vs. a KMIP-compliant abstraction / HashiCorp Vault PKCS#11 secrets engine (unified audit logging, easier lifecycle management, extra latency).
- For validator signing: active-active/active-passive HSM clustering avoids slashing-from-downtime because failover never requires exporting the key. This MUST be the design target, not single-HSM-with-manual-failover.
- **Jurisdictional note directly relevant to Budlum's PoA/institutional layer:** Turkey's MASAK requires local-soil key storage for regulated digital-financial infrastructure. Confirm applicability before finalizing HSM deployment geography — this is a constraint on top of vendor choice, not instead of it.

**GitHub references:**
| Repo | Why |
|---|---|
| https://github.com/parallaxsecond/rust-cryptoki | The Rust-idiomatic PKCS#11 wrapper, maintained under the Linux Foundation's Parsec project. This is the crate to build Budlum's HSM abstraction on — not a single vendor's SDK. |
| https://github.com/softhsm/SoftHSMv2 | Software PKCS#11 implementation for CI/test coverage without physical hardware — required for any HSM-touching code to have real test coverage. |

**Action items:** build a thin PKCS#11 abstraction crate rather than binding to one vendor SDK; wire SoftHSM2 into CI before merging any HSM-touching code, not after.

## 5. On-chain governance scope

**Verdict:** do not ship one token-vote-for-everything. Split governance-action types into separate quorum/threshold tracks from the start — retrofitting this later is a hard-fork-shaped problem.

- Base-layer chains split governance-action types (parameter change vs. treasury vs. constitutional/hard-fork) into different thresholds. Polkadot's OpenGov (tracks + origins, evolved from the older Democracy pallet) is the clearest production reference for this pattern, in Rust.
- **Forcing question Budlum MUST answer before writing governance code:** given four consensus domains plus an isolated PoA layer, is governance itself domain-scoped (PoW miners don't vote on PoA institutional rules)? This mirrors the asymmetry already built into consensus — don't contradict it in governance.
- Progressive-decentralization note: a chain can only responsibly forfeit upgrade keys once the *protocol* has stabilized, even while the *implementation* keeps shipping fixes. Decide now whether Budlum's roadmap ever intends to progressively decentralize upgrade authority — this shapes governance scope today, not later.

**GitHub references:**
| Repo | Why |
|---|---|
| https://github.com/paritytech/polkadot-sdk (see `substrate/frame/referenda` and `substrate/frame/democracy`) | Production tiered-track governance (OpenGov) and its predecessor (Democracy pallet), both in Rust, both running on live chains handling real treasury and upgrade authority. |

**Action items:** draft a governance-action taxonomy (parameter / treasury / protocol-upgrade / emergency-pause) with an explicit quorum per type before writing any governance contract code.

## 6. Real Proof-of-Storage (B.U.D. storage layer)

**Verdict:** items 1 and 6 are one epic. Do not schedule B.U.D.'s real-PoR work independently of VerifyMerkle — it is blocked on it by construction, and pretending otherwise just hides the dependency.

- The current RetrievalChallenge gap (an operator can pass by holding only the requested byte range) is the textbook "outsourcing attack" from the decentralized-storage-network literature — the operator doesn't need the full data, just enough to answer challenges, and can even outsource that.
- Academic baseline for genuine cryptographic proof: Shacham & Waters, "Compact Proofs of Retrievability" (2008) — most later schemes build on this construction. Any custom PoR design MUST be checked against it, not invented independently.
- Production precedent for pairing erasure coding with a real proof: Filecoin's Proof-of-Replication + Proof-of-Space-Time — proves data is uniquely stored *and* stays stored over time.

**GitHub references:**
| Repo | Why |
|---|---|
| https://github.com/filecoin-project/rust-fil-proofs | Official Filecoin Proving Subsystem — Rust reference implementation of PoRep and PoSt. This is the closest production-grade analog to what B.U.D. needs once VerifyMerkle 64-depth lands. |
| https://github.com/libp2p/rust-libp2p (`kad` module) | Official Rust Kademlia DHT implementation, powers IPFS and is used across the Polkadot/Substrate ecosystem — this is the professional-grade base for B.U.D.'s DHT layer rather than a custom implementation. |

**References (papers):** eprint.iacr.org/2024/258, "SoK: Decentralized Storage Network"; arXiv 2310.08403, "Vault: Decentralized Storage Made Durable"; github.com/holybao/awesome-decentralized-storage (curated list, check before assuming no prior art).

---

## 7. Skill-generating systems (meta-tooling for Arena itself)

**Why this belongs here:** Arena's SKILL.md was compiled once from five external repositories. That is a snapshot, not a pipeline. The systems below turn "compile a skill" into a repeatable, evaluable loop instead of a one-time manual synthesis.

| Repo | Why |
|---|---|
| https://github.com/anthropics/skills | Anthropic's official public Skills repository — includes `skill-creator`, the meta-skill that creates, edits, and benchmarks other skills (interviews the user, drafts SKILL.md, runs evals, packages the result). This is the canonical authoring loop, not a third-party reimplementation. |
| https://github.com/huggingface/upskill | Generates and evaluates agent skills directly from agent traces: a teacher model (expensive, capable) produces a skill, a student model (cheap, fast) is benchmarked against it, and the skill is refined until the student performs reliably. Directly applicable to Arena: feed it traces of Arena's own corrected mistakes and it produces a skill addition automatically instead of a human writing one by hand. |
| agentskills.io | The open Agent Skills standard spec that `anthropics/skills`, Claude Code, Codex, Gemini CLI, and Cursor all implement — worth reading once so any skill Arena authors stays portable across harnesses, not Claude-specific by accident. |

**Hard requirement:** the next time Arena's process-skill needs an addition (a new failure mode, a new verification step), it MUST go through an eval loop (skill-creator's benchmarking, or upskill's generate/eval cycle) before being merged into SKILL.md — not appended from a single anecdote. This is the same discipline as CI being the sole authoritative verifier, applied to the skill file itself.

## 8. Codebase memory systems (fixes Arena's stale-context problem at the root)

**Why this belongs here:** the coordination file already documents the actual failure mode — GitHub web_fetch returns cached/stale PR and Actions data, forcing a workaround (zip export → unzip → grep/find/wc). That workaround is a symptom. The tools below are the actual fix: persistent, accurate, queryable codebase state instead of routing around a stale fetch every time.

| Repo | Why |
|---|---|
| https://github.com/oraios/serena | MCP toolkit providing semantic code retrieval and editing via real language servers (not text search), plus a persistent memory system (`.serena/memories/`) that survives across sessions, users, and projects. This is the most-cited, most production-tested option in this category — directly targets "stale internal data must never be trusted" by giving Arena ground-truth structural understanding instead of a snapshot that goes stale. |
| https://github.com/Aider-AI/aider | Its repo-map system (tree-sitter-based, graph-ranked, token-budgeted) is the mature reference for how to summarize a large codebase's structure without stuffing full files into context — worth studying even if Serena is adopted, since it's a different tradeoff (static map vs. live language-server queries). |

**Concrete recommendation:** pilot Serena as an MCP tool inside Arena's harness for one task cycle. If it holds up, it replaces the zip-export-then-grep workaround as the default analysis path — live semantic queries instead of periodic manual re-exports. This is an architectural decision under the traffic-light rule (changes Arena's core tooling) — confirm with Ayaz before making it the default, not just the fallback.

---

## Using this file

- Consult §1–6 before touching BudZKVM, consensus composition, the relayer/RPC layer, HSM/key management, governance contracts, or B.U.D. storage. Consult §7–8 when improving Arena's own tooling — they are not Budlum architecture blockers, they are how Arena gets better at all of the above.
- **Blocker pairs, not six independent items:** (1, 6) share one root dependency; (3, 4) are the same key-compromise problem from two ends. Plan sprints against four real problems, not six.
- Every GitHub reference above is Apache 2.0 or MIT/comparable and Rust-native or Rust-wrapped — chosen to be license-compatible and idiomatically adoptable, not just conceptually relevant.
- Any adopted dependency still goes through the full security-tooling gate (cargo-audit, cargo-deny, Semgrep, cargo-geiger, SBOM, OpenSSF Scorecard, license scan) before merge. This file names *what* to build against — it does not pre-clear anything for `main`.
