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

- **Shape candidates:** degree-2/3 hash-chain families rather than a
  WOTS+/XMSS derivative - tentatively called a "backbone-paired quorum
  signature" design: each committee device keeps an independent
  one-time-signature chain, which composes naturally with the 3-of-6
  cold-committee context.
- **Hard boundary:** statefulness is the known failure class (chain
  state loss = signature stream corruption), so the target is
  stateless - the same boundary SPHINCS+ opererates under. The
  reserved `BudlumBpqsReserved` slot stays fail-closed throughout.
- **Promotion bar (to live family):**
  1. documented security argument at NIST level 5,
  2. reference implementation plus differential tests against the
     SPHINCS+ parameter sets,
  3. at least one independent review,
  4. the verify chain must be expressible within the VerifyMerkle
     opcode audit scope so the anchor verification stays auditable.
- **Working home:** either a separate `budlum-bpqs` crate repository
  (candidate) or a feature-gated module inside budlum - decided at
  implementation time, not now.

## 4. Open follow-ups

- [ ] anchor-emission slice (devnet) - depends on this doc's section 2
- [ ] V6 header bump decision (leaf widening) - separate commit
- [ ] HSM/PKCS#11 vendor integration design
- [ ] VerifyMerkle third-party opcode audit (production blocker)
- [ ] BPQS reference implementation kick-off (section 3)
