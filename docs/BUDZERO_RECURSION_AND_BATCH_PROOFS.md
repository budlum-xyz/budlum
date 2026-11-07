# BudZero Binary Segment Recursion, Block Batch Proofs, & Phase-A Dual Finality (WP-60)

## 1. Segment Chunking & Binary Recursion (`src/cross_domain/external/phase_a_dual.rs`)

- Execution traces exceeding `MAX_SEGMENT_ROWS = 2^20` (`1,048,576` rows) split
  into contiguous segments (`SegmentBoundary`).
- `fold_segment_tree` aggregates adjacent segment commitments into a binary
  recursion tree while enforcing exact `program_hash`, contiguous
  `segment_index`, `end_pc == start_pc`, and `final_state_root == initial_state_root`
  continuity (`TS9`).
- A single-bit flip in any inner segment proof alters the root
  `aggregate_digest` (`TS8`).

---

## 2. Block Aggregate Proofs & `D = 8` Light-Client Status (`TA4`, `TA5`)

- `BlockBatchProof` commits a contiguous window `[start_height..=proven_height]`
  of inner proof digests into `proof_root`; mutating any inner digest invalidates
  `matches_root()` (`TA4`).
- `classify_root_proof_status` enforces the `MAX_BATCH_PROOF_DELAY_BLOCKS = 8`
  window (`TA5`):
  - `block_height <= proven_height` -> `RootProofStatus::Proven`.
  - `1..=8` blocks ahead -> `RootProofStatus::PendingProof { blocks_behind }`
    (never displayed as proven).
  - `> 8` blocks ahead -> `RootProofStatus::DelayExceeded { blocks_behind }`.

---

## 3. Phase-A Authoritative Native + Secondary zkVM Freeze Gate (`TA8`)

- During Phase A, native external-domain verification remains authoritative while
  the zkVM finality guest executes as a shadow path (`evaluate_phase_a_dual`).
- Any divergence in verdict (`accepted`) or `state_root` between the native
  adapter and the zkVM proof immediately emits
  `PhaseAVerdict::FreezeAndAlarm { domain_id }` (`TA8`).
