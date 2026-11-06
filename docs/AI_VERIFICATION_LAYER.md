# AI Verification Layer & Answer Proof Bundle Specification (WP-57)

## 1. Verification Levels (`VL-0`..`VL-3`)

`crates/ai-inference/crates/ai-core/src/verification.rs` defines the monotonic
verification hierarchy (`TAI8`):

- `VL-0`: Unverified inference output.
- `VL-1`: Delayed-seed (`e + 1`) commit-reveal committee quorum (`n = 5, k = 4`,
  100-block challenge window, 1% secondary audit sampling).
- `VL-2`: Activation-checkpointed optimistic execution (minimum required floor
  for all value-bearing AI flows).
- `VL-3`: Full cryptographic BudZero STARK proof.

Level transitions never decrease; fraud proof success transitions an active
record to `VerificationState::Refuted { prior_level, disputed_step }` without
erasing `prior_level`.

---

## 2. Deterministic Inference Profile (`DIP`) & `64 x 64` Tile Proofs

- `DeterministicInferenceProfile` binds `model_id`, `weights_root`,
  `tokenizer_digest`, `runtime_digest`, `prompt_digest`, `sampling_seed`, and
  integer quantization (`Int8Symmetric` / `Int4Group128`), requiring
  `fixed_tree_reduction` and `batch_invariant_kernels` (`TAI3`, `TAI4`).
- `TileStepProof` proves and verifies `64 x 64` (`4096`-cell) fixed-order
  integer matrix multiplications bound to `(request_id, step_index, weights_root)`
  (`TAI6`, `TAI10`, `TAI12`), closing interactive bisection disputes in
  `ceil(log2(steps))` rounds (`TAI5`).

---

## 3. Answer Proof Bundle (`APB`, `TY1`..`TY6`)

- Every sentence must carry an explicit `ApbSentenceKind` (`CitedFact`,
  `ToolProof`, or `Synthesis`); untyped claims are rejected (`TY1`).
- Citations without `has_consent_proof` strip `excerpt` bytes so only existence
  metadata is emitted (`TY4`).
- `upgrade_level` elevates `VL-x` monotonically while keeping `prose_body()`
  byte-identical (`TY5`), rendering a single Markdown document with an embedded
  `apb` code block (`TY6`).
