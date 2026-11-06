# Testnet Launch Gate Report (TLG)

## Conditional Feature Decisions (TLG-27)

| Feature | Placeholder | Testnet (`45261`) Status | Proof / Regression Locks | Rationale |
|---|---|---|---|---|
| Cross-domain Bridge (`lock`, `mint`, `burn`, `unlock`) | `{{tlg:bridge}}` | `Open` | `bridge_e2e_lock_mint_burn_unlock`, `blg_043_bridge_unlock_returns_exact_burned_amount`, `blg_057_bridge_lock_and_burn_reject_fee_overflow`, `blg_105_bridge_lock_and_burn_enforce_vesting_and_debit_burner`, `blg_194_relay_proof_rolls_back_ledger_on_supply_ceiling_refusal` | All four launch blockers (`BLG-043`, `BLG-057`, `BLG-105`, `BLG-194`) are closed: `unlock` credits exact recorded `burned_amount`, `lock` and `burn_with_event` enforce `spendable_balance` vesting locks and checked `amount + fee` arithmetic, and `submit_relay_proof` atomically rolls back the relay ledger if supply-ceiling or balance checks refuse. |
| Ethereum Sync Committee External Finality | `ethereum_sync_committee` | `Closed` | `ethereum_sync_committee_is_closed_on_testnet`, `blg_235_ethereum_sync_committee_refused_on_testnet_chain_id` | Closed on testnet (`45261`) per WP-44 / `BLG-235` until finality-branch verification lands in WP-60. |
| Shared Security (`shared_security`) | `shared_security` | `Closed` | `shared_security_is_closed_on_testnet` | Closed on testnet (`45261`) until end-to-end Sepolia verification passes (`docs/SHARED_SECURITY.md`). |
| Remote App Binding (`app_binding`) | `app_binding` | `Closed` | `app_binding_is_closed_on_testnet` | Closed on testnet (`45261`) pending post-WP-49 activation (`docs/APP_BINDING.md`). |

## Instant Duty Handover and Disaster Recovery Mode (WP-14 / R-03)

- **Instant Duty Handover (`src/validators/handover.rs`, `src/storage/bud3/{custody,repair}.rs`, `src/consensus/pos.rs`)**: All nine Section 7.6 duty rows are wired with deterministic latency ceilings: proposer round handover (`3,000 ms`), finality seat handover (`2` missed checkpoints, `ceil(S/10)` per checkpoint, `V-2` Full-only), custody share read (`2,000 ms`), custody durability (`24 h` Full / `168 h` Mobile), new custody assignment (`3` epochs), segment repair task (`20` blocks), upload gateway (`0` block failover), relay reservation (`0` block failover), and presence aggregation (`1` block fallback).
- **Disaster Recovery Mode (`budlum_finality_stalled`)**: When `head_height - finalized_height >= 40` (`8` checkpoint intervals), `Blockchain` enters recovery mode and exports `budlum_finality_stalled = 1` on Prometheus scrapes; after `1` full epoch in recovery mode without finality, the recovery committee is derived from available-chain presence records (`ValidatorClass::Full` only, preserving `V-2`).
- **Residual Risk `R-03`**: Under a network partition lasting longer than one epoch in which both partitions continue producing blocks, each side may derive an independent recovery committee from its own available chain (the same safety/liveness trade-off class as Ethereum's inactivity leak), requiring post-partition operator reconciliation if conflicting checkpoints finalize.

