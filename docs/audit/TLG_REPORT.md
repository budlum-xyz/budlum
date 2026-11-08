# Testnet Launch Gate Report (TLG)

## Conditional Feature Decisions (TLG-27)

| Feature | Placeholder | Testnet (`45261`) Status | Proof / Regression Locks | Rationale |
|---|---|---|---|---|
| Cross-domain Bridge (`lock`, `mint`, `burn`, `unlock`) | `{{tlg:bridge}}` | `Open` | `bridge_e2e_lock_mint_burn_unlock`, `bridge_unlock_returns_exact_burned_amount`, `bridge_lock_and_burn_reject_fee_overflow`, `bridge_lock_and_burn_enforce_vesting_and_debit_burner`, `relay_proof_rolls_back_ledger_on_supply_ceiling_refusal` | All four launch blockers (`BLG-043`, `BLG-057`, `BLG-105`, `BLG-194`) are closed: `unlock` credits exact recorded `burned_amount`, `lock` and `burn_with_event` enforce `spendable_balance` vesting locks and checked `amount + fee` arithmetic, and `submit_relay_proof` atomically rolls back the relay ledger if supply-ceiling or balance checks refuse. |
| Ethereum Sync Committee External Finality | `ethereum_sync_committee` | `Closed` | `ethereum_sync_committee_is_closed_on_testnet`, `ethereum_sync_committee_refused_on_testnet_chain_id` | Closed on testnet (`45261`) per WP-44 / `BLG-235` until finality-branch verification lands in WP-60. |
| Shared Security (`shared_security`) | `shared_security` | `Closed` | `shared_security_is_closed_on_testnet` | Closed on testnet (`45261`) until end-to-end Sepolia verification passes (`docs/SHARED_SECURITY.md`). |
| Remote App Binding (`app_binding`) | `app_binding` | `Closed` | `app_binding_is_closed_on_testnet` | Closed on testnet (`45261`) pending post-WP-49 activation (`docs/APP_BINDING.md`). |

## Instant Duty Handover and Disaster Recovery Mode (WP-14 / R-03)

- **Instant Duty Handover (`src/validators/handover.rs`, `src/storage/bud3/{custody,repair}.rs`, `src/consensus/pos.rs`)**: All nine Section 7.6 rows have deterministic rules and drill coverage. Production currently calls the PoS proposer-round helper; seat, custody, repair, gateway, relay and presence helpers remain drill/churn utilities until their state-transition callers adopt them. Their presence in this tree is not production activation evidence.
- **Disaster Recovery Mode (`budlum_finality_stalled`)**: When finality lag reaches `8` chain-specific checkpoint intervals (`40` blocks on testnet), `Blockchain` enters recovery mode and exports `budlum_finality_stalled = 1` on Prometheus scrapes; after `1` full epoch the tracker exposes deterministic Full-only committee derivation from supplied available-chain presence records; automatic consensus adoption of that committee is not wired.
- **Residual Risk `R-03`**: Under a network partition lasting longer than one epoch in which both partitions continue producing blocks, each side may derive an independent recovery committee from its own available chain (the same safety/liveness trade-off class as Ethereum's inactivity leak), requiring post-partition operator reconciliation if conflicting checkpoints finalize.
