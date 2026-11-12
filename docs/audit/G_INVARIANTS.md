# G: invariant and application-binding evidence audit

Inspected repository commit: `9aeec136ec5f43e7ef4e5c006c6cba9b9101307c`.
This is a focused **source inspection**, not a passing CI run, testnet launch
record or a finding-closure decision. No CI run ID was available; none of the
invariants below is marked green. Paths and line numbers refer to the
inspected commit and must be rechecked after a merge.

## What "G" can mean here

The directive uses **G-1 through G-8** for global invariants (Section 3.1,
lines 306-317). Separately, **G4/G5** without hyphens are the logical and
optical B.U.D. 3.0 viewing paths (Section 6.5, lines 794-807). Neither label
is shorthand for **AppBinding**: the CLI's `AppBinding` action and
[remote app binding](../APP_BINDING.md) concern use of an application on a
*different* network from Budlum. `docs/APP_BINDING.md:6-13` says that feature
is **closed on testnet**. `src/core/chain_config.rs:229-236` enables it only
on devnet, and `src/tests/domains_bridge_settlement.rs:333-375` defines an
on-testnet rejection test, including its in-block settlement door. A test
*definition* is not a recorded test pass. If the report is "another network's
application does not work through Budlum", check the intended chain ID and
AppBinding's production path separately; do not assume that a G-1..G-8 gate failure
explains it or promise that AppBinding works on testnet. The AppBinding implementation
is outside this focused audit.

## G-1..G-8: production wiring and limits

| Invariant | Source inspected | What this establishes / what it does not | Status |
|---|---|---|---|
| **G-1: block-only consensus writes** | `src/rpc/method_class.rs:1-24,37-50,74-85` classifies read/transaction/local/refused methods; `xtask/gates/src/gates/no_out_of_block_consensus_writes.rs:12-25,50-102` classifies chain-actor calls, including `produce_block` and snapshot sync; `xtask/gates/src/gates/consensus_state_only_changes_in_blocks.rs:58-114` checks selected nonce/root/bridge doors. | These are actual production classifications and static gates, not proof of every runtime path. A separate RPC exposure blocker (not itself evidence of a G-1 state write) remains: `config/testnet.toml:42-51` requires a public key while `src/main.rs:1819-1846` uses unauthenticated operator default. The proposed split is uncommitted, not shipped evidence. Reconcile it without silently widening operator access, then test each listener and block-only write path. | **Unverified; RPC policy conflict** |
| **G-2: deterministic roots** | `xtask/gates/src/gates/no_float_in_consensus_paths.rs:1-39` scans selected AST paths and explicitly pins seven AI-registry float occurrences; `.github/workflows/determinism.yml:80-99,166-221` configures a Linux/macOS/Windows consensus-digest comparison; lines 230-245 configure an aarch64 **PQ-vector** job. | Configured consensus digest comparison is not the directive's x86_64/aarch64 same-block **state-root and execution-root** equality result. The aarch64 matrix shown is PQ vectors, not the block root comparison; no cross-architecture root artifact/run is cited. Obtain both roots for identical blocks on x86_64 and aarch64, and run the pinned-float gate. | **Unverified; required cross-architecture root evidence absent** |
| **G-3: no unaccounted BUD issuance** | `src/core/account.rs:3128-3155` calls `ensure_mint_headroom` before `try_add_balance`; `xtask/gates/src/gates/minting_paths_are_counted.rs:1-22,48-100` enumerates call-site counts and written transfer rationales, including AppBinding escrow credits. | The gate says explicitly that it **cannot infer** transfer versus mint from source; a rationale and a headroom check are not a supply-conservation proof for every settlement/bridge branch. Need run results plus adversarial supply tests and genesis/escrow accounting before closure. | **Unverified** |
| **G-4: rejection leaves state unchanged** | `xtask/gates/src/gates/refusals_no_mutate.rs:1-12,378-466` scans `self.<field>.remove(...)` followed by `return Err(...)`, with a `PARTIAL: allowed` escape. `src/execution/executor.rs::pay_agreeing_verifiers` previously credited verifiers before checking later balances; commit `a0aec24a` aggregates duplicate recipients and preflights every balance before writing, with a focused refusal regression that has not run here. `src/chain/blockchain.rs:5354-5361` checks transactions against `temp_state` while validating a block. | The static gate does **not** check direct balance writes followed by failure. The identified helper now preflights two-verifier and duplicate-recipient overflow cases and tests state equality after `Err`; these Rust tests could not compile without `protoc`. Other execution and settlement refusal paths still need state-equality verification before claiming the global G-4 invariant. | **Known helper patched; regression and global invariant unverified** |
| **G-5: length-framed hashes and domain tags** | `xtask/gates/src/gates/hash_inputs_are_length_prefixed.rs:36-54,59-71` checks consecutive variable-length hasher updates under `src`, `budzero`, `crates/wallet-core` only; its own comments say helper preimages are not visible. `xtask/gates/src/gates/domain_tags.rs:47-69` inventories `BDLM_`/`BUDLUM_` literals under `src`, `budzero`, `crates`, `bud` and `mobile`. | The first check does not establish that **every** hash input is framed or that code outside its scan roots (including `mobile`, `execution`, `bud`) is framed. The tag gate only inventories recognized literal prefixes; neither check is proof of all hash preimages. Run the gates and review production preimage helpers and uncovered workspaces against the global rule. | **Unverified; static coverage narrower than invariant** |
| **G-6: no unwired capability** | `xtask/gates/src/gates/capability_modules_are_wired.rs:9-19,50-62` only inspects modules with at least three public functions in `src`, `budzero`, `crates/wallet-core`. `xtask/gates/src/gates/no_idle_code.rs:20-40,73-105,121-131` uses a shrinking baseline and permits `WIRING:`, `Convenience:` and `exposed for` documentation exemptions. | A referenced helper or a documented exemption is **not** necessarily a production invocation. In particular, the optional G5 optical helpers in `src/storage/bud3/pipeline.rs:517-531` are declared `Convenience:`; the only direct `decode_optical_path` references found in `src` were that helper and `two_path.rs` tests. Trace actual node and client call sites before asserting optical/view features work. | **Unverified; optical wiring gap identified** |
| **G-7: disabled feature rejects explicitly** | `src/core/chain_config.rs:14-18,229-236` closes privacy and AppBinding on testnet; `src/execution/executor.rs:180-200,286-290` checks feature flags before normal transaction execution; `src/tests/privacy_ai_execution.rs:536-580` and `src/tests/domains_bridge_settlement.rs:333-375` define rejection tests. `xtask/gates/src/gates/rejection_tests.rs:1-16` says its name/negative-assertion check cannot verify that the assertion tests the right behavior. | Individual tests and preflight paths exist, but there is no verified run for **every** closed/conditional feature in directive Section 1.5 and no green TLG-02. The AppBinding testnet refusal is a designed behavior, not proof that cross-network applications work there. | **Unverified** |
| **G-8: domain sovereignty and service independence** | `docs/APP_BINDING.md:6-13,27-38` describes origin apps staying on their network and a signed settlement door; `src/rpc/method_class.rs:99-105` classifies AppBinding reads and refuses direct external-domain registration. | A guide, call classification and in-tree source cannot prove independence from team-run DNS, gateway, relay, faucet or external infrastructure in a live network. Need real operator diversity, origin-network proof/intent execution, failover tests and a rehearsal record before claiming this invariant holds. | **Unverified** |

## Separate G4/G5 storage view paths

`src/storage/bud3/two_path.rs:169-209` implements an optical upload round
trip, and lines 218-239 implement logical/optical **public** decoding. Its
`bud3_logical_equals_optical_including_lossy_channel_and_p1` test at lines
282-310 uses generated frames and simulated frame loss; it is not an
external-camera or live-network run. `src/storage/bud3/pipeline.rs:497-514`
defines the two-path public upload wrapper but the plain upload at lines
167-198 is a separate function. The code search found no callers of
`prepare_public_upload_two_path` or `view_public_optical` outside their
definitions. The operational public fallback instead calls
`fallback_decode_public` from `src/storage/bud3/rpc.rs:242-256` and
`src/storage/bud3/content_gateway.rs:81`; `src/cli/bud3_commands.rs:206`
defines a library logical-view helper, not proof of a wired `bud` CLI command.
Thus **helpers and a synthetic equality test exist; default production
upload/view and real optical G5 client wiring are not established**. Verify camera/client integration, sealed-content
behavior, segment commitment checks and the directive's T5 acceptance test
before claiming G4 and G5 equivalent in the running network.

## Next evidence to collect

1. Reproduce the G-4 two-verifier overflow on `Executor::apply_transaction_checked`
   and test the full state before/after refusal; evaluate both call sites and
   block candidate isolation. Avoid assigning a new BLG number until comparing
   the related existing AI/accounting findings in directive Section 14.
2. Run targeted named G gates and their self-tests on a known SHA, recording
   command, exit status and CI job/run ID; compare results to production call
   sites rather than treating a green lexical gate as a proof of the invariant.
3. Demonstrate identical same-block state/execution roots on x86_64 and
   aarch64; attach actual artifacts. Reconcile the unpublished RPC-auth split
   with an authenticated operator listener and its refusal tests.
4. Test the intended *application-binding* chain ID explicitly. On testnet,
   require its rejection test to pass; on devnet, demonstrate a real
   origin-network application call and verified settlement rather than using a
   unit-level AppBinding result as an end-to-end claim.
