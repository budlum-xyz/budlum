# Testnet Launch Gate Report (TLG)

## Conditional Feature Decisions (TLG-27)

| Feature | Placeholder | Testnet (`45261`) Status | Proof / Regression Locks | Rationale |
|---|---|---|---|---|
| Cross-domain Bridge (`lock`, `mint`, `burn`, `unlock`) | `{{tlg:bridge}}` | `Open` | `bridge_e2e_lock_mint_burn_unlock`, `blg_043_bridge_unlock_returns_exact_burned_amount`, `blg_057_bridge_lock_and_burn_reject_fee_overflow`, `blg_105_bridge_lock_and_burn_enforce_vesting_and_debit_burner`, `blg_194_relay_proof_rolls_back_ledger_on_supply_ceiling_refusal` | All four launch blockers (`BLG-043`, `BLG-057`, `BLG-105`, `BLG-194`) are closed: `unlock` credits exact recorded `burned_amount`, `lock` and `burn_with_event` enforce `spendable_balance` vesting locks and checked `amount + fee` arithmetic, and `submit_relay_proof` atomically rolls back the relay ledger if supply-ceiling or balance checks refuse. |
| Ethereum Sync Committee External Finality | `ethereum_sync_committee` | `Closed` | `ethereum_sync_committee_is_closed_on_testnet`, `blg_235_ethereum_sync_committee_refused_on_testnet_chain_id` | Closed on testnet (`45261`) per WP-44 / `BLG-235` until finality-branch verification lands in WP-60. |
| Shared Security (`shared_security`) | `shared_security` | `Closed` | `shared_security_is_closed_on_testnet` | Closed on testnet (`45261`) until end-to-end Sepolia verification passes (`docs/SHARED_SECURITY.md`). |
| Remote App Binding (`app_binding`) | `app_binding` | `Closed` | `app_binding_is_closed_on_testnet` | Closed on testnet (`45261`) pending post-WP-49 activation (`docs/APP_BINDING.md`). |
