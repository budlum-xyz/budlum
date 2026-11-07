# Parallel Execution Scheduler & Block-STM Mode (WP-59)

## 1. Architecture (`src/execution/coordinator/scheduler/`)

Budlum's deterministic block scheduler partitions transactions into conflict-free
execution waves while preserving strict sequential equivalence (`Y-2`, `G-2`):

1. **Conservative Access Sets (`access_set`)**:
   - Unsponsored native `Transfer` transactions declare `writes = {Account(from), Account(to)}`.
   - Any transaction with non-empty `authorization` or global/validator state side
     effects (`Stake`, Universal Calls, governance, storage) receives
     `AccessSet::global()`, acting as a full barrier wave.
2. **Deterministic Wave Planner (`plan`)**:
   - Uses ordered `BTreeMap` / `BTreeSet` structures exclusively (zero hash seeds,
     zero threads, zero floating point), guaranteeing identical wave plans across
     `x86_64` and `aarch64` (`parallel_scheduler_is_deterministic_across_arch`).
3. **Flag-Gated Intra-Environment Block-STM (`BlockStmConfig`)**:
   - Disabled by default (`BlockStmConfig { enabled: false }`).
   - When enabled (`enabled: true`), `execute_planned_block` speculatively evaluates
     key-scoped transactions against the pre-block snapshot, validates every touched
     account's `(balance, nonce)` version against the committed prefix, and falls
     back to sequential execution (`block_stm_replays`) whenever a read/write
     version conflict is observed.

## 2. Verification Suite

- `parallel_schedule_equals_sequential_root`: randomized `proptest` blocks mixing
  valid, overdrawn, and self-transfers with `Stake` barriers verify byte-identical
  state roots under reverse-wave order.
- `block_stm_and_wave_executor_equal_sequential_root`: randomized `proptest` blocks
  verify byte-identical state roots across sequential execution, default wave
  execution, and `BlockStmConfig { enabled: true }`.
- `parallel_scheduler_is_deterministic_across_arch`: pins canonical wave layout
  `PINNED_WAVES` across architectures.
