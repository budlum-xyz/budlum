# Deterministic Parallel Block Execution (WP-59)


## 0. Wiring status

The coordinator's production entry point is `execute_block_with_policy`, and its scheduler activation is closed at launch. The scoped-thread `execute_block_checked` path described below is opt-in and is not selected by the coordinator yet. These design and regression locks are therefore not evidence that multithreaded execution is active on testnet or mainnet. Worker panic and missing-result accounting fail the checked block rather than silently skipping a transaction.

## 1. Design and Determinism Invariants (`G-2`, `Y-2`, `Y-3`)

`src/execution/coordinator/scheduler/` schedules and executes intra-block transactions across worker threads while preserving a single total transaction order (`Y-2`), all-or-nothing block atomicity (`Y-3`, `G-4`), and byte-identical state roots across `x86_64` and `aarch64` (`G-2`):

1. **Pure `AccessSet` wave planner (`plan`)**:
   - Uses ordered collections (`BTreeMap`, `BTreeSet`) with zero floating-point arithmetic, zero hash seeds, and zero wall-clock inputs.
   - Disjoint `Transfer` transactions are grouped into concurrent waves; transactions whose read/write state keys are not statically enumerable carry `AccessSet::global()` and form strict sequential barriers.
2. **Scoped multithreaded execution (`execute_block_checked`)**:
   - Multi-transaction disjoint waves run across bounded OS worker threads (`std::thread::scope`, capped by `ParallelExecutionConfig::worker_threads`) over isolated per-transaction account slices (`burn_reserve_address`, `team_vesting`, `epoch_index`, `base_fee`, and touched `{from, to}` accounts).
   - Worker results are merged back in canonical block order, followed by `Executor::finalize_block_checked` (metabolic fee burn, application/protocol fee split, and passed governance actions).
   - Any refusal in any wave discards the candidate state and leaves the caller's `AccountState` byte-for-byte unchanged (`multithreaded_wave_rolls_back_atomically_on_later_failure`).
3. **Separate Block-STM intra-environment flag (`block_stm_enabled`)**:
   - Controlled independently via `ParallelExecutionConfig::block_stm_enabled` (`false` by default until calibration benchmarks sign off).
   - Tracks touched account keys across optimistic lanes and falls back deterministically to sequential execution (`ScheduleReport::block_stm_fallbacks`) whenever an overlap occurs.

---

## 2. Verification Locks

- `parallel_schedule_equals_sequential_root`: property test over randomized mixed blocks (`Transfer` + `Stake` barriers, self-transfers, overdrawn refusals, and live block-producer fee splits) asserting `seq_state.calculate_state_root() == par_state.calculate_state_root() == stm_state.calculate_state_root()`.
- `parallel_scheduler_is_deterministic_across_arch`: pins the exact wave decomposition string (`PINNED_WAVES`) so cross-architecture builds cannot diverge.
- `multithreaded_wave_rolls_back_atomically_on_later_failure`: proves failure-atomic block rollback across parallel worker waves.
