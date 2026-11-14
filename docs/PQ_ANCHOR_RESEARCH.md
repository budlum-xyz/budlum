# PQ Anchor Research & Emission Slice Planning

**Status:** research/decision record, brought in line with the fixed decisions of the
PQ program. The sibling anchor record and its
committee rotation channel are landed (`src/settlement/pq_anchor.rs`, commit `a5caaf3`). The
emission slice and the Budlum-BPQS variant are open design work. The decisions this record follows are listed in section 0.

## 0. Decisions this record follows

| Decision | What it fixes for the anchor |
|---|---|
| 1 | Operation: 2-of-3 ML-DSA-87 keys on three separate HSMs from at least two vendors. Frequency: one anchor per 360 blocks. Root Seal: one SLH-DSA-SHAKE-256s signature per 3,600 blocks. Cold committee: 3-of-6 SLH-DSA-SHAKE-256s. The anchor signature is made over a local SHA3 Merkle root, so VerifyMerkle does not run on this path and anchor production does not depend on the VerifyMerkle audit. Only the `stark_root` path does. |
| 2 | The anchor, the certificate and the rotation channel never stand on a classical signature alone. The cold committee moves from Ed25519 to SLH-DSA. |
| 3 | Every signature carries a scheme id and a FIPS 204 or 205 context string. A scheme is never inferred from a length. |
| 4 | HSMs are used through the PKCS#11 3.2 standard mechanisms first. A software token is rejected on mainnet. |
| 5 | A hash that binds security is at least 256 bits. An algebraic hash such as Poseidon is never the hash of a long-lived signature. Inside the VM the Poseidon parameter set is Goldilocks, width 12, 8 full and 22 partial rounds, capacity 4, output 4 elements. |
| 6 | BudZero proofs give at least 128 bits provable security. No pairing-based SNARK sits on a verification path. |

## 1. Landed groundwork

- `PqAnchor` is a sibling record next to `GlobalBlockHeader`, not a
  header field change. It commits to height, aggregate finality root,
  optional stark/crossdomain roots and the key epoch, signed by the
  anchor keybook.
- Live signature family today: ML-DSA-87 (FIPS 204) over the wallet hedged
  signing path. The SPHINCS+ slot
  and the Budlum-BPQS slot are reserved algorithm slots that fail closed in
  verification until implemented. The target operation is the 2-of-3 threshold of,
  which replaces the single signature of the landed record.
- Emergency rotation channel: a cold committee certifies the rotation over a payload
  binding `height + epoch + hash(reason)`, the certificate checked by the single quorum
  predicate (`cold_quorum::verify_quorum`), so the security rule is not forked. The
  committee is 3-of-6 today with classical Ed25519 members; and move it to
  SLH-DSA-SHAKE-256s so the rotation channel is not the weak edge of the anchor.
- Production is gated twice today: `AnchorMode::ProductionApproved` errors while the
  VerifyMerkle third-party opcode audit is pending, and the HSM/PKCS#11 backend stub fails
  closed until a vendor integration lands. narrows the first gate: anchor production
  signs a local SHA3 Merkle root and does not depend on VerifyMerkle, so the audit gate stays
  only on the `stark_root` path. The second gate stays until the PKCS#11 3.2 integration
 lands.

## 2. Anchor-emission slice (design draft)

- `Blockchain::settlement_finality_window()` stays a pure function of
  blocks both honest nodes already hold (burial-depth deduction, no
  arrival-time inputs). The emission slice reads that window outside
  consensus, calls `pq_anchor::assemble_anchor`, and propagates the
  anchor record on devnet first. The cadence is one anchor per 360 blocks and one Root Seal
  per 3,600 blocks.
- Candidate leaf widening: today's window leaves are bare block hashes
  (`hash32_from_hex(block.hash)`). Committing richer finality context
  (anchor_leaf_digest composition over a payload digest) changes the
  header's Merkle baggage and therefore requires a
  `BDLM_GLOBAL_BLOCK` V5 -> V6 domain bump. Under the pre-launch bump
  rule this is permissible, but it is a
  deliberate consensus-surface change and must ship as its own commit with its own
  justification, not folded into the emission slice.
- Light-verifier contract (`verify_anchor_light`): today one keybooked signature over a
  supported family suffices, which let the emergency channel rotate to the dormant family
  without a header format change. That is not enough under: the light verifier must
  require the threshold (2 of 3) and must not accept any signature (INV-10), and the
  full mode additionally demands the ML-DSA-87 quorum.

## 3. Budlum-BPQS variant (research line F2)

Goal: an in-house hash-based signature family that can be promoted
to a live second anchor family once it passes the acceptance bar.

- **Decided shape (user decisions 2026-09-19, pinned in the workspace
  repo's 2026-09-19 BPQS F2 design pre-registration):** epoch-chained
  Winternitz few-time signatures. Epochs run on chain tempo (the
  settlement window; no calendar), q_max = 1 minted signature per epoch (the 2026-09-19 decision was
  4; decision item 7 of 2026-09-22 - the bar-1 record - moved the posture
  to one-time after the few-time domination hunt was priced; see
  crates/bpqs/SECURITY-ARGUMENT.md section 6)
  (quota breach = loud protocol fault, signer fail-closed), dual-budget
  parameter rows: canonical L5 (n=32, w=16, T=2^16) plus a transportable
  L3 (n=24). Scope pinned to the cold-committee anchor flow; the
  reserved `BudlumBpqsReserved` slot stays fail-closed throughout.
- **Canonical hash backend:** SHAKE-256, a FIPS 202 member. The Poseidon2 backend
  stays in the crate only as a research backend for in-VM verification experiments; an algebraic
  hash is never the hash of a long-lived signature or commitment. The older record that named
  Poseidon2 the primary backend is superseded.
- **Promotion bar (to live family):**
  1. documented security argument at NIST level 5 (WRITTEN: crates/bpqs/SECURITY-ARGUMENT.md; decision item 7 landed 2026-09-22 - PRF-derived per-call randomizer + Q_MAX=1, the few-time pricing of section 6 - so the item is closed at the in-family level; the family question it left open rides with bar 3 as named question 2),
  2. reference implementation plus differential tests against the
     incumbent crates - LANDED (see below),
  3. at least one independent review,
  4. the verify chain must be auditable. With SHAKE-256 canonical, verification is a Keccak
     computation that runs natively and does not run inside the VerifyMerkle opcode, which also
     keeps the anchor path independent of that opcode's audit. The VerifyMerkle
     expressibility analysis (`crates/bpqs/VERIFYMERKLE-EXPRESSIBILITY.md`) now concerns the
     research Poseidon2 backend only.
- **Working home (decided 2026-09-19):** in-tree, feature-gated crate
  `crates/bpqs` behind the non-default `bpqs-research` cargo feature; a
  separate crate repository was explicitly rejected.
- **Bar item 2 status:**
  - M1: no_std+alloc reference implementation (Winternitz core,
    epoch-bound Merkle key evolution, quota-bounded signing), 31-test
    battery, SHA3-256 reference backend behind the `BpqsHash` seam.
  - M2: SHAKE-256 XOF backend on the vetted `keccak` permutation
    (FIPS 202 suffix 0x1F, Python-hashlib cross vectors), canonical since;
    Poseidon2-Goldilocks-16 research backend (p3 parameters,
    straightline in-crate port, upstream known-answer vector pinned); the three-way
    backend differential battery (same scheme, three hash families);
    frozen KAT vector file `crates/bpqs/kat/bpqs-kat-v1.txt`; the
    differential bench example against the same ml-dsa 0.1.1 the root
    links and the slh-dsa crate (68-library-test battery total). The
    fuzz harness `bpqs_wots_reject` is wired into the quick gate and
    the nightly schedule. Remaining route to green on item 2: repeat
    the findings after the first independent read (feeds item 3).

## 4. Open follow-ups

- [ ] anchor-emission slice (devnet) - depends on this doc's section 2
- [ ] V6 header bump decision (leaf widening) - separate commit
- [ ] 2-of-3 ML-DSA-87 anchor with three HSMs, Root Seal and the SLH-DSA cold committee
- [ ] HSM/PKCS#11 3.2 vendor integration design
- [ ] VerifyMerkle third-party opcode audit - blocks only the `stark_root` path; queue manifest
      pinned at crates/bpqs/VERIFYMERKLE-EXPRESSIBILITY.md section 5. The node
      width and the Poseidon parameter set of the opcode are the set
- [ ] BPQS bar item 1: written security argument at NIST L5
- [ ] BPQS bar item 3: independent review call
- [x] BPQS reference implementation kick-off (section 3) - M1 (2026-09-22
      `51ec637`) + M2 backends/differential/KAT/fuzz
- [x] BPQS canonical backend is SHAKE-256
