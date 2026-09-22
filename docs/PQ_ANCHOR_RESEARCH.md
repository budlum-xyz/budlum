# Post-Quantum Anchor Research & Emission Slice Planning

**Status:** research/decision record - the sibling anchor record and its
committee rotation channel are landed (`src/settlement/pq_anchor.rs`,
commit `a5caaf3`); the emission slice and the Budlum-BPQS variant are
open design work. Decision record: workspace
`KARARLAR-2026-09-17-AYAZ.md` (items 1, 2, 5, 6).

## 1. Landed groundwork

- `PqAnchor` is a sibling record next to `GlobalBlockHeader`, not a
  header field change. It commits to height, aggregate finality root,
  optional stark/crossdomain roots and the key epoch, signed by the
  anchor keybook.
- Live signature family: ML-DSA-87 (FIPS-204) over the wallet hedged
  signing path; SPHINCS+ (FIPS-205) and Budlum-BPQS are reserved
  algorithm slots that fail closed in verification until implemented.
- Emergency rotation channel: 3-of-6 cold committee certifies the
  rotation over a payload binding `height + epoch + hash(reason)`, the
  certificate checked by the single quorum predicate
  (`cold_quorum::verify_quorum`) - the security rule is not forked.
- Production is gated twice: `AnchorMode::ProductionApproved` always
  errors while the VerifyMerkle third-party opcode audit is pending,
  and the HSM/PKCS#11 backend stub fails closed until a vendor
  integration lands.

## 2. Anchor-emission slice (design draft)

- `Blockchain::settlement_finality_window()` stays a pure function of
  blocks both honest nodes already hold (burial-depth deduction, no
  arrival-time inputs). The emission slice reads that window outside
  consensus, calls `pq_anchor::assemble_anchor`, and propagates the
  anchor record on devnet first.
- Candidate leaf widening: today's window leaves are bare block hashes
  (`hash32_from_hex(block.hash)`). Committing richer finality context
  (anchor_leaf_digest composition over a payload digest) changes the
  header's Merkle baggage and therefore requires a
  `BDLM_GLOBAL_BLOCK` V5 -> V6 domain bump. Under the pre-launch bump
  rule this is permissible, but it is a deliberate consensus-surface
  change and must ship as its own commit with its own justification -
  not folded into the emission slice.
- Light-verifier contract (`verify_anchor_light`): threshold-of-
  algorithms - one keybooked signature over a supported family
  suffices, which is what lets the emergency channel rotate to the
  dormant family without a header format change. Full mode
  additionally demands ML-DSA-87 presence.

## 3. Budlum-BPQS variant (research line F2)

Goal: an in-house post-quantum signature family that can be promoted
to a live second anchor family once it passes the acceptance bar.

- **Decided shape (user decisions 2026-09-19, pinned in the workspace
  repo's 2026-09-19 BPQS F2 design pre-registration):** epoch-chained
  Winternitz few-time signatures. Epochs run on chain tempo (the
  settlement window; no calendar), q_max = 4 minted signatures per epoch
  (quota breach = loud protocol fault, signer fail-closed), dual-budget
  parameter rows: canonical L5 (n=32, w=16, T=2^16) plus a transportable
  L3 (n=24). Scope pinned to the cold-committee anchor flow; the
  reserved `BudlumBpqsReserved` slot stays fail-closed throughout.
- **Promotion bar (to live family):**
  1. documented security argument at NIST level 5 (WRITTEN: crates/bpqs/SECURITY-ARGUMENT.md; one open decision item inside - the few-time domination-hunt pricing, section 6 - so the item is not marked complete until that decision lands),
  2. reference implementation plus differential tests against the
     incumbent PQ crates - LANDED (see below),
  3. at least one independent review,
  4. the verify chain must be expressible within the VerifyMerkle
     opcode audit scope so the anchor verification stays auditable.
- **Working home (decided 2026-09-19):** in-tree, feature-gated crate
  `crates/bpqs` behind the non-default `bpqs-research` cargo feature; a
  separate crate repository was explicitly rejected.
- **Bar item 2 status (milestones as of 2026-09-22):**
  - M1: no_std+alloc reference implementation (Winternitz core,
    epoch-bound Merkle key evolution, quota-bounded signing), 31-test
    battery, SHA3-256 reference backend behind the `BpqsHash` seam.
  - M2: canonical Poseidon2-Goldilocks-16 backend (p3 parameters,
    straightline in-crate port, upstream known-answer vector pinned);
    SHAKE-256 XOF cross-check backend on the vetted `keccak` permutation
    (FIPS 202 suffix 0x1F, Python-hashlib cross vectors); the three-way
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
- [ ] HSM/PKCS#11 vendor integration design
- [ ] VerifyMerkle third-party opcode audit (production blocker) -
      queue manifest now pinned at crates/bpqs/VERIFYMERKLE-EXPRESSIBILITY.md
      section 5 (items M-1..M-5): the BPQS expressibility analysis found the
      AIR-vs-BPQS width mismatch (width-8 constrained vs width-16 canonical)
      and routes it through the same engagement
- [ ] BPQS bar item 1: written security argument at NIST L5
- [ ] BPQS bar item 3: independent review call
- [x] BPQS reference implementation kick-off (section 3) - M1 (2026-09-22
      `51ec637`) + M2 canonical backend/differential/KAT/fuzz
