# B-0005: Testnet Rehearsal step 9 AppBinding cannot pass on testnet 45261

Severity: high (blocks Testnet Rehearsal CI, both docker and native jobs)
Location: xtask/tools/src/testnet_rehearsal.rs:1309 scenario_app_binding; src/core/chain_config.rs:234; src/settlement/app_binding.rs:556,922
Status: open, root-caused 2026-11-16, no fix pushed yet.

## Evidence
CI run 43860950588, jobs 133277315448 (rehearsal) and 133277314913 (Testnet Native E2E), 2026-11-16 13:28-13:36 UTC:
`FAIL: testnet rehearsal failed at ["9. AppBinding register and pay"]; the AppBinding application did not register within 120 s`

## Trace
1. Scenario registers PoW domain 4242 (`bud domain register-pow --id 4242 --chain-id 4242`), waits for `bud_getDomainInfo registered=true` (passes — domain registration itself works).
2. `bud app-binding register --domain 4242 --origin-app 000...aa --manifest 111...` sends SettlementTx::AppBinding Register.
3. Executor -> `execute_app_binding_tx` (app_binding.rs:922): `if !app_binding_enabled_for_chain_id(ctx.chain_id) { refused("app_binding is not enabled on this chain") }`. Chain is 45261 Testnet; `Network::app_binding_enabled()` is `matches!(Devnet)` only. Refused before registry/balance moves. RPC lookup returns Null forever. Scenario times out.
4. Even if gate 1 opened, gate 2: `ensure_serving_origin` (app_binding.rs:556): domain 4242 kind=PoW, `anchor_recognized_chain(4242)` = None (canonical ids 1..7 only, ANCHOR_RECOGNIZED = Ethereum/Solana/Bitcoin/Avalanche). Refused "permissionless PoW domain cannot serve as an AppBinding trust anchor". Test app_binding.rs:3608 pins this for PoW 42 on devnet.
5. Docs flip-flop: 3ad19c78 "active on testnet", 0961ac7d "closed on testnet, as the code says". Current docs/APP_BINDING.md: closed on testnet. Rehearsal never updated.

## Why not just open the gates
- Opening app_binding on Testnet alone does not fix rehearsal (gate 2 still blocks PoW 4242).
- Weakening gate 2 (allow PoW origin) reintroduces Strix M11 (self-mined PoW roots claim apps). Test at 3608 would need removal — that is a security regression, not a fix.
- Testnet genesis has no bootstrap domains (`testnet_genesis()` bootstrap_domains=vec![]), and CLI only exposes `domain register-pow`. So rehearsal has no way to create a passing domain today.

## Recommended fix (preserves security gates)
1. Enable AppBinding on Testnet: `app_binding_enabled() = matches!(Devnet | Testnet)`, keep Mainnet closed. Update `app_binding_is_closed_on_testnet` -> `app_binding_is_open_on_testnet`, update domains_bridge_settlement assert, update docs/APP_BINDING.md. This follows user directive to put closed features on testnet, and matches shared_security pattern (Testnet+Devnet).
2. Add CLI `bud domain register-bft` (or generic register with kind) using existing SettlementTx::RegisterDomain with kind=Bft, adapter=bft-quorum-commit, bridge_enabled=true, id=4242 (non-canonical, allowed). No new tx type needed.
3. Change rehearsal scenario to use register-bft instead of register-pow for AppBinding domain. Keep PoW gate intact.
4. Add unit test: Bft domain 4242 passes ensure_serving_origin on testnet; PoW 4242 still refused (existing test covers PoW 42).
5. Re-run Testnet Rehearsal CI until step 9 passes.

Alternative considered and rejected: skip scenario 9 on testnet with `app_binding_is_closed_on_testnet` proof. That would make CI green by removing coverage, contradicting user directive and leaving AppBinding untested on testnet.

## Impact if unfixed
Testnet Rehearsal stays red, TLG (Testnet Launch Gate) cannot pass, testnet cannot be declared ready. Every push to testnet branch re-runs and fails at step 9 after ~15 min of build/start.
