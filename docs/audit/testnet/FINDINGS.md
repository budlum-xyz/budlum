# Findings ledger (testnet directive, section 5.3)

Every finding has one row. A finding is fixed only after it was verified
against the code; a finding reported by a helper agent and not verified here
is not in this file.

Measured at commit `f588d62`. The starting findings B-01 to B-21 were first
measured at `1f7ed99`; each one was measured again at `f588d62` and the line
numbers below are the current ones.

Severity: **S0** consensus split or loss of funds, **S1** testnet blocker,
**S2** mainnet blocker, **S3** quality.

Status: `open`, `fixed` (with the commit that fixed it), `gated` (closed on
purpose, a test pins the refusal), `decision` (waits for a decision recorded
in `DECISIONS.md`), `out-of-scope` (Lubot, section 3.2 of the directive).

## Baseline measurements

Taken at `f588d62` with the commands shown, so a later session can repeat
them.

| Measure | Directive value at `1f7ed99` | Value at `f588d62` | Command |
|---|---|---|---|
| RPC methods | 156 | 156 | `grep -c '#\[method(name = "' src/rpc/api.rs` |
| Operator-only RPC methods | 33 | 33 | `grep -o 'self.require_operator("[A-Za-z_]*")' src/rpc/server.rs \| sort -u \| wc -l` |
| Module-level `//! WIRING: unwired` markers | 29 (method not stated) | 15 files | `git ls-files '*.rs' \| xargs grep -nE '^//! WIRING: unwired'` |
| Lines containing "unwired" in `.rs` files | - | 96 | `git ls-files '*.rs' \| xargs grep -ci unwired` (summed) |
| `#[ignore]` attributes | 31 (method not stated) | 2 | attribute lines starting with `#[ignore` |
| `#[allow(...)]` attributes, all files | 63 (method not stated) | 71 | attribute lines starting with `#[allow(` or `#![allow(` |
| `#[allow(...)]` attributes, Lubot excluded | - | 67 | same, without `src/ai_inference/` and `crates/ai-inference/` |
| Test functions | about 6000 | 5949 | attribute lines `#[test]` and `#[tokio::test]`, all files |
| Gates in the gate binary | - | 128 | `budlum-gates --list` |
| Gates green locally with `--all` | - | 124 of 128 | the four red ones need tools CI installs: cargo-vet, actionlint, typos, zizmor |

The `#[ignore]` and `#[allow]` counts differ from the directive's numbers.
The directive does not state its counting method; the commands above are the
method used here, and later sessions use the same commands.

Baseline CI run number: none exists. `lubothebook/budlum` has zero workflow
runs (GitHub Actions API, 25 October 2026), and `budlum-xyz/budlum` is not
reachable from this session. `ci.yml` runs on pull requests to `main` and
`fix/architecture-tip-adlari` only, so a stacked pull request does not run
it either (see N-09).

## Starting findings (B-01 to B-21)

| ID | Severity | Area | File:line | Evidence | Impact | Fix | Test | Status | PR |
|---|---|---|---|---|---|---|---|---|---|
| B-01 | S1 | Global header | `src/chain/blockchain.rs:2206-2212`, `:2214-2272`, `:2274-2312`; `src/rpc/server.rs:2951-2961` | `apply_block_end_roots` writes `global_header_summary = [0u8; 32]`; `seal_global_header` is reached only from the operator RPC `bud_sealGlobalHeader`; `global_headers` is a node-local `Vec`. | The consensus-of-consensuses header is not a network object. Two nodes can hold different header sequences. | WP-2: build the header deterministically at every finality checkpoint, commit its hash, turn `bud_sealGlobalHeader` into reads. | Four-node equality and restart test (WP-2 acceptance). | open | - |
| B-02 | S0 | State writes | `src/chain/blockchain.rs:2510-2532` (`register_bridge_asset`), `:3767-3830` (`submit_relay_proof`), `:1840-1847` (`submit_verified_domain_commitment`), `:3423-3440` (`submit_external_evidence`); `src/rpc/server.rs:2664-2722`, `:2911-2940` | Each writes consensus state (`bridge_state`, `universal_relayer`, `external_roots`, `domain_registry`, `external_intake`) from an operator RPC, outside block execution. `submit_relay_proof`'s own comment (server.rs:2914-2921) states the fork risk. `submit_verified_domain_commitment` also broadcasts the payload through a gossip side channel (server.rs:2719-2720). | The node that receives the call computes a different state root from every peer. | WP-1: replace each path with a transaction door applied by the executor. | Four-node state-root equality per transaction type. | open | - |
| B-03 | S1 | External domains | `src/chain/blockchain.rs:3374-3389` (refusal), `:3392-3410`, `:3633-3660`, `:3677-3700` (in-block entries) | `register_external_domain` returns `Err` unconditionally. `apply_register_external_domain_in_block`, `apply_slash_external_prover_in_block` and `apply_bond_external_prover_in_block` are marked `WIRING:` and have no production caller. | No external domain can be registered on a running network. | WP-1: a transaction type for registration, bond and slash that calls the in-block entries from the executor. | Registration through a signed transaction in a multi-node test. | open | - |
| B-04 | S1 | Rehearsal | `ops/docker-compose.yml:44-47` (and the same flags for node2 to node4); `xtask/tools/src/multinode_smoke.rs:1-6` | Compose passes `--consensus=pow --difficulty=0` to every node and only node1 has a validator address. The tool's module docs say "PoS docker-compose devnet". | No end-to-end test runs multi-validator PoS. | WP-3 item 9: a PoS smoke with four producers. | The smoke itself, on CI. | open | - |
| B-05 | S1 | Testnet genesis | `config/testnet-genesis.json:14-18`, `:31`; `config/testnet.toml:19-25` | Validators are `0x40..`, `0x41..`, `0x42..` placeholders with no consensus keys; `bud_tokenomics` is `null`; `bootnodes` and `dns_seeds` are empty. | The testnet cannot start with real validators. | WP-3 item 2: the `testnet-genesis` ceremony tool; WP-4 item 4: seed tooling. | `validate_consensus_ceremony` over the tool's output. | open | - |
| B-06 | S1 | RPC | `config/testnet.toml:37-38`; `src/rpc/server.rs:766-790` | `auth_required = true` with `api_key_env`; every public call needs the key. | Wallets and users cannot connect to a public testnet node. | WP-4 item 1: a method class table; the public class keyless on testnet by profile parameter. | Unit test: a public read without a key succeeds on the testnet profile and fails on the mainnet profile. | fixed | `536b9f5` |
| B-07 | S1 | Dev credit | `src/chain/blockchain.rs:5863-5876`, `:5889-5905`; `src/chain/chain_actor.rs:111-112`, `:1500-1530`, `:3728-3735` | `fund_development_account`, `credit_development_account` and `ChainCommand::AddBalance` refuse only on the mainnet chain id. On testnet they credit balances outside consensus. | A testnet node can be made to diverge by a local command. | WP-1 item 6: refuse on every chain id except devnet. | Testnet refusal tests next to the mainnet ones in `src/tests/consensus_bypass_locks.rs`. | fixed | `0a40717` |
| B-08 | S1 | Explorer | `src/rpc/api.rs` (no subscription method), `src/bin/` (no indexer) | No WebSocket subscription, no indexer binary, no explorer API. | A user cannot see a transaction in an explorer. | WP-4 items 3 and 6. | Indexer integration test. | open | - |
| B-09 | S1 | Wallet | `crates/wallet-core/README.md:38`; `src/bin/bud.rs:357-358` | wasm-bindgen and UniFFI are "Planned". `bud tx send` builds the transfer and calls `tx.sign(&keypair)` with an Ed25519 `KeyPair` (V4). The directive's line reference `privacy_crypto.rs:144` now points at Poseidon constants; the file grew by 408 lines after `1f7ed99`. | Users sign with the retiring scheme; mobile and web wallets have no binding. | WP-5: V5 (ML-DSA-87) signing in the CLI through `wallet-core`, bindings in CI. | CLI end-to-end test; node accepts the wasm signature. | open | - |
| B-10 | S1 | Relayer | `src/relayer/policy.rs:1-5`, `:14-47`; `src/main.rs:1648-1657`; `src/bin/budlum-relayer.rs:19-30` | Module is `WIRING: unwired`; no transaction carries an intent; the fee of `UniversalRelay` goes to the block producer; outbound EVM relay is disabled (BLG-0135); the binary states "Neither direction relays anything yet". | Relaying is unpaid and does not happen. | WP-6 relayer intent layer, WP-8 Graft. | Intent settlement test. | open | - |
| B-11 | S1 | Ethereum contracts | `contracts/external-domain/BudlumFinalityVerifier.sol:1`, `:6-17` | The licence line reads `License: Polyfield`. The contract states it is quarantined with F01 to F06 open. | No Ethereum-side verification exists. | WP-11. The licence line is fixed in WP-11 together with the contract work. | Negative test per F01 to F06. | open | - |
| B-12 | S1 | Rewards and delegation | `src/tokenomics/reward_pool.rs:7-9`; `src/core/transaction.rs:284-450` | The pool is `WIRING: unwired`; no `Delegate` transaction exists. | Validators earn only fees; no delegation. | WP-3 item 8 and WP-9. | Supply invariant tests stay green; delegation rehearsal. | open | - |
| B-13 | S2 | HSM | `src/main.rs:846-853` | A mainnet PoS validator exits: "this startup path has no PKCS#11 VRF backend yet". | Mainnet PoS cannot start. | Options in `DECISIONS.md` D-07. | - | decision | - |
| B-14 | S2 | Units | `src/core/chain_config.rs:129`, `:139`, `:149`; `src/tokenomics/mod.rs:27-33`; `src/registry/params.rs:311` | Mainnet `min_stake = 1_000_000` atoms (1 BUD); testnet `10_000` atoms (0.01 BUD); registry floor `1_000` atoms. `src/bin/budlum-relayer.rs:6` calls the floor "1000 $BUD". | Stake floors are a millionth of what the prose says. | E-01: testnet `min_stake` = 1000 BUD written as `bud(1_000)`; mainnet value is Ayaz's (D-03). | Unit test on the parameter. | open | - |
| B-15 | S1 | B.U.D. | `src/main.rs:1266-1268`; `budzero/bud-node/src/store.rs:5`, `:139` | The node uses `MemoryContentStore`; shards are lost on restart. | Storage is not durable. | WP-6 B.U.D.: a persistent `ContentStore`. | Restart test. | open | - |
| B-16 | S3 | Feature flags | `src/cli/commands.rs:292-296`, `:883-891`, `:1178-1181` | `features_governance` and `features_zkvm_contracts` are read from flags and the profile; the only use is the mainnet refusal. Nothing else reads them (`grep -rn features_governance src`). | The flags suggest a switch that does not exist. | WP-6: make each flag gate real behaviour, or remove it. | Test per flag. | open | - |
| B-17 | S1 | BNS | `README.md:443-444`; `src/core/transaction.rs:290-293` | Only `BnsRegister`, `BnsSetContent`, `BnsRegisterSubdomain` and `BnsSetStorage` exist; no transfer or renewal transaction. | Names cannot be transferred or renewed. | WP-6 BNS. | Transfer and renewal tests. | open | - |
| B-18 | S2 | Fees | `src/registry/params.rs:361-367`; no `app_fee_share` anywhere in `src/` | `transfer_fee_ppm`, `swap_fee_ppm` and `bridge_fee_ppm` default to 0; no application revenue share exists. | Protocol fees and the 40 percent application share are not implemented. | E-03 and E-04 as testnet profile parameters; mainnet values are Ayaz's. | Fee distribution tests. | open | - |
| B-19 | S1 | Proof market and domains | `src/settlement/proof_market.rs:639-650`; `src/bin/` (no producer or reporter binary); `src/main.rs:1074-1094` | `fund_escrow` is `WIRING: unwired` ("no transaction door yet"); PoA bootstrap domains are frozen at startup. | No proof market; no domain finality flow on a live network. | WP-6 and WP-7. | Rehearsal scenarios. | open | - |
| B-20 | S2 | Secrets hygiene | `.gitignore:1-9`; `config/testnet.toml:10`, `:18`, `:48` | `.gitignore` does not exclude `secrets/` or `data/`; profiles write keys to `./secrets/` and state to `./data/`. | A validator key can be committed by accident. | WP-4 item 11: add both directories. | `git check-ignore` in the commit description. | fixed | `0d6db9f` |
| B-21 | S3 | Documentation | `docs/CONTRIBUTING.md:5`, `:90-97`, `:155-156`; `README.md:3-12`; `src/bin/budlum-relayer.rs:1` | CONTRIBUTING says "Layer-1" and points at deleted Python scripts (`ops/scripts/*.py`) that `xtask/tools` replaced (`clippy-extra-report`, `step-reachability`); the README opening is not the K15 definition; the relayer binary carries `#![allow(clippy::pedantic, clippy::nursery)]`. The `repo-lubot/` lines (155-156) are Lubot and are left alone. | Readers follow commands that do not exist; public wording contradicts K15. | Rewrite the drifted lines; remove the crate-level allow and fix what it hid. | `tree-is-english`, `typos`, clippy. | fixed | `eba1f64`, `c65929b` |

## New findings

| ID | Severity | Area | File:line | Evidence | Impact | Fix | Test | Status | PR |
|---|---|---|---|---|---|---|---|---|---|
| N-01 | S3 | English tree | `src/core/transaction.rs:477` | A three-word Turkish fragment is left after the English sentence it duplicates. `tree-is-english` passes because none of the three words is in its vocabulary. | K5 violation the gate cannot see. | Delete the fragment. Widening the gate vocabulary is a separate change. | `tree-is-english`. | fixed | `e801c56` |
| N-02 | S3 | Documentation | `README.md:282`; `README.tr.md:286` | Both run `bash ops/scripts/devnet-multinode-smoke.sh`; the script was replaced by `cargo run --manifest-path xtask/tools/Cargo.toml -- devnet-multinode-smoke` (`xtask/tools/src/multinode_smoke.rs:3`). | The documented command fails. | Point both at the xtask tool. | - | fixed | `eba1f64` |
| N-03 | S3 | Documentation | `docs/SECURITY.md:3` | "experimental Layer-1 blockchain infrastructure". | K15 wording. | Rewrite with the K15 definition. | - | fixed | `eba1f64` |
| N-04 | S3 | Genesis | `config/testnet-genesis.json:19`; `src/execution/executor.rs:2841` | `block_reward: 50` is present, but the executor keeps `block_reward` only for snapshot and wire compatibility and mints nothing (`docs/SPECIFICATION.md` section 2.2). | The genesis file suggests emission that does not exist. | Set it to 0 when the testnet genesis is regenerated (WP-3 item 2). | Supply invariant tests. | open | - |
| N-05 | S3 | Privacy | `src/execution/executor.rs:2191-2215` | `PrivacyNoteInsert` inserts any well-formed note commitment for the fee alone. Notes have no path to a public balance and `privacy_transfers_enabled` refuses both privacy arms on mainnet. | No value at risk today; the arm becomes a mint the day a note can be spent into a balance. | Keep refused on mainnet; record the dependency in the privacy module README (WP-6 privacy). | Mainnet refusal test exists in the executor tests. | gated | - |
| N-06 | S3 | Constitution | `src/core/constitution.rs:24-25`, `:106-112`, `:181-189` | `MaxEmergencyHaltEpochs` is documented "for future halt proposals"; no halt proposal type exists (`grep -rn EmergencyHalt src`), and K10 forbids a halt hook. The value folds into the constitution root. | A parameter for a hook the constitution forbids. | Ayaz decides: remove (constitution root change, new genesis) or keep as an inert bound with a test that no halt path exists. See D-08. | - | decision | - |
| N-07 | S3 | Documentation | `src/bin/budlum-relayer.rs:6-7` | "the only gate is `min_stake`, at 1000 $BUD"; the registry floor is `1_000` atoms (`src/registry/params.rs:311`). | Unit confusion, same class as B-14. | Fix with B-14. | - | fixed | `c65929b` |
| N-08 | S3 | Specification | `docs/SPECIFICATION.md` section 3.3 and section 4.1 | The RPC table lists `bud_registerConsensusDomain` and `bud_submitVerifiedDomainCommitment` without saying they are operator-only; section 4.1 names an Ed25519 key file as the testnet signer default. | Spec drift. | Regenerate the RPC table from the method class table (WP-4 item 1). | - | open | - |
| N-10 | S1 | State root | `src/core/account.rs:2827` (fold); `src/chain/blockchain.rs:2240-2241`, `:1136`, `:4014`; `src/chain/chain_actor.rs:3855` | The block `state_root` folds only `AccountState`. The consensus domain registry, the domain commitment registry, the universal relayer ledger, `external_intake` and the sovereign template registry live on `Blockchain`; their roots appear only in the node-local global header or in RPC values. | When B-02 writes make two nodes disagree on these registries, no block root shows it; the nodes diverge later in validation instead. | WP-2: the deterministic global header carries these roots and its hash is committed in the block. | Four-node equality test per registry. | open | - |
| N-11 | S2 | AI layer | `src/ai/registry.rs:1868-1915`; `src/core/account.rs:2119-2126`; `src/execution/executor.rs:2858-2868`; `src/rpc/api.rs:1249-1250` | A passed `ProposalType::WhitelistVerifier` proposal switches the AI verifier set to "permissioned mode": once one address is listed, every other staked verifier is refused (`is_verifier_authorized`). `bud_aiVerifierWhitelist` reports the mode. | A governance whitelist over a permissionless role, against the constitution's no-whitelist rule (K10). | Ayaz decides: remove the whitelist mode, or bind it to the constitution guardrail so it cannot activate. See D-10. | Test that a whitelist proposal cannot exclude a staked verifier. | decision | - |
| N-12 | S0 | Cross domain | `src/rpc/server.rs:2725-2747` (before the fix); `src/network/node.rs:3445-3467` (before the fix); `src/chain/blockchain.rs:3317-3333` (before the fix) | `bud_submitCrossDomainMessage` had no operator gate. It called `submit_relayed_cross_domain_message`, which inserts into `state.message_registry` (folded into the state root through `message_root`) outside block execution, then gossiped the message; every peer inserted it again on arrival, at a different moment relative to its own blocks. | Any active relayer could make nodes compute different `message_root` values at the same height from the public listener: a consensus split. | A transaction door, `RelayCrossDomainMessage`, applied by the executor through `AccountState::register_relayed_cross_domain_message`; the RPC refuses and names the door; the gossip form is dropped; the startup and reorg loads merge stored rows into the replayed registry instead of replacing it, so door-registered messages survive a restart. | `src/tests/relayer_liveness.rs` (door end to end, sender binding, envelope refusal, expiry, slashed and unbonding relayers); `src/rpc/tests.rs` (the RPC refuses). | fixed | `562e47c` |
| N-13 | - | Finality | `src/rpc/server.rs` (`submit_qc_fault_proof`); `src/consensus/qc.rs:578-680` | Classified while building the method table: `bud_submitQcFaultProof` is public and its success path would invalidate this node's finality alone, but both proof kinds refuse in `QcFaultProof::verify_against_blob`, so the path is unreachable today. | None while both kinds refuse. If a proof kind ever verifies, the invalidation must travel to every node (gossip or block), or it becomes a finality split. | Kept as `Refused` in the method table; a change to `verify_against_blob` that returns `Ok` must reclassify it. | The method table pins it as `Refused`. | gated | - |
| N-14 | S3 | Orphan file | `src/core/transaction_v4.txt` | A six-line copy of four `TransactionType` variants; no code, gate or workflow reads it (`grep -rn transaction_v4`). | Dead file in the source tree. | Delete it. | - | fixed | `562e47c` |
| N-15 | S1 | RPC surface | `src/rpc/method_class.rs` | No table said which listener and which effect each of the 156 methods has; the classification had to be rebuilt from handler bodies. | A new method could reach the public listener unclassified. | The method class table, checked by tests against `api.rs` and the `require_operator` calls, and at startup against the methods actually served. A public listener without an API key refuses to start while any public row is a consensus write. | `src/rpc/method_class.rs` tests. | fixed | `562e47c` |
| N-09 | S1 | CI | `.github/workflows/ci.yml:3-7` | `pull_request` runs only for bases `main` and `fix/architecture-tip-adlari`. A stacked pull request on `consensus-of-consensuses` (the directive's base rule while PR #97 is open) gets no `ci.yml` run. | K2 cannot be met for stacked pull requests. | Ayaz decides: add the stacking base to the branch list, or target `main` only. See D-01. | - | decision | - |

## Lubot classification

| ID | Severity | Area | File:line | Evidence | Impact | Fix | Test | Status | PR |
|---|---|---|---|---|---|---|---|---|---|
| L-01 | - | Lubot | `src/core/transaction.rs:388-393`; executor arms for `AiOperatorBond`, `AiOperatorUnbond`, `AiOperatorWithdraw`; `docs/VALIDATOR_ROLES.md` section 3 | `git show b7d4b86 -- src/core/transaction.rs` shows `LubotOperatorBond`, `LubotOperatorUnbond` and `LubotOperatorWithdraw` renamed to the `AiOperator*` names, and "Submit a Lubot inference result by an active bonded RoleId(8) operator" as the old text of `AiInferenceResult`. | The AI_OPERATOR role, its three transactions, the operator-submitted result path and the `ai_inference` economics (80/10/5/5) come from Lubot's retired "operator serves" design. | Not changed by this directive. Reported to Ayaz in `DECISIONS.md` D-09. | - | out-of-scope | - |

## Existing suppressions (K3 inventory)

K3 lists existing suppressions as violations. They are not counted as fixes.
Removing one is a fix only when the code it hid is corrected in the same
change. Measured at `f588d62`, Lubot excluded: 67 `allow` attributes and 2
`ignore` attributes. No live `continue-on-error: true` or `|| true` remains in
`.github/workflows/` (every occurrence is in a comment that records its
removal).

| File:line | Attribute |
|---|---|
| `benches/domain_throughput.rs:4` | `#![allow(clippy::unwrap_used, clippy::expect_used)]` |
| `benches/micro/sig_verify.rs:4` | `#![allow(clippy::unwrap_used, clippy::expect_used)]` |
| `benches/micro/timing_safe.rs:4` | `#![allow(clippy::unwrap_used, clippy::expect_used)]` |
| `benches/single_node/internal_pipeline_tps.rs:4` | `#![allow(clippy::unwrap_used, clippy::expect_used)]` |
| `budzero/bud-cli/tests/toolchain_end_to_end.rs:3` | `#![allow(clippy::unwrap_used, clippy::expect_used)]` |
| `budzero/bud-proof/benches/canonical_programs.rs:20` | `#![allow(clippy::unwrap_used, clippy::expect_used)]` |
| `budzero/bud-proof/benches/proof_baseline.rs:3` | `#![allow(clippy::unwrap_used, clippy::expect_used)]` |
| `budzero/bud-proof/src/bud_stark/prover.rs:21` | `#[allow(` |
| `budzero/bud-proof/src/bud_stark/prover.rs:376` | `#[allow(clippy::expect_used)]` |
| `budzero/bud-proof/src/bud_stark/prover.rs:492` | `#[allow(` |
| `budzero/bud-proof/src/bud_stark/prover.rs:518` | `#[allow(clippy::too_many_arguments)]` |
| `budzero/bud-proof/src/bud_stark/verifier.rs:104` | `#[allow(clippy::too_many_arguments)]` |
| `budzero/bud-proof/src/bud_stark/verifier.rs:186` | `#[allow(clippy::type_complexity)]` |
| `budzero/bud-proof/src/plonky3_prover.rs:1397` | `#[allow(clippy::type_complexity)]` |
| `budzero/bud-proof/src/trace_layout_tests.rs:8` | `#![allow(clippy::unwrap_used, clippy::expect_used)]` |
| `budzero/bud-proof/tests/compiled_branching.rs:3` | `#![allow(clippy::unwrap_used, clippy::expect_used)]` |
| `budzero/bud-proof/tests/fiat_shamir_binding.rs:3` | `#![allow(clippy::unwrap_used, clippy::expect_used)]` |
| `budzero/bud-proof/tests/soundness_negatives.rs:3` | `#![allow(clippy::unwrap_used, clippy::expect_used)]` |
| `budzero/bud-vm/tests/trace_fixtures.rs:3` | `#![allow(clippy::unwrap_used, clippy::expect_used)]` |
| `build.rs:4` | `#![allow(clippy::expect_used)]` |
| `crates/bpqs/src/tests.rs:110` | `#[ignore = "ceremony-scale keygen; run in release on a machine lane"]` |
| `crates/bpqs/src/tests_backends.rs:326` | `#[ignore = "KAT writer: runs on demand, not in the battery"]` |
| `crates/budscan/src/query.rs:110` | `#[allow(clippy::too_many_lines)]` |
| `src/ai/registry.rs:623` | `#[allow(clippy::too_many_arguments)]` |
| `src/bin/bud.rs:325` | `#[allow(clippy::too_many_arguments)]` |
| `src/bin/budlum-relayer.rs:1` | `#![allow(clippy::pedantic, clippy::nursery)]` |
| `src/chain/blockchain.rs:1105` | `#[allow(clippy::expect_used)]` |
| `src/chain/blockchain.rs:2358` | `#[allow(clippy::too_many_arguments)]` |
| `src/chain/blockchain.rs:2534` | `#[allow(clippy::too_many_arguments)]` |
| `src/chain/blockchain.rs:7688` | `#[allow(clippy::too_many_arguments)]` |
| `src/chain/blockchain.rs:7748` | `#[allow(clippy::too_many_arguments)]` |
| `src/chain/chain_actor.rs:1055` | `#[allow(clippy::too_many_arguments)]` |
| `src/chain/chain_actor.rs:1094` | `#[allow(clippy::too_many_arguments)]` |
| `src/chain/chain_actor.rs:2459` | `#[allow(clippy::too_many_arguments)]` |
| `src/chain/chain_actor.rs:2498` | `#[allow(clippy::too_many_arguments)]` |
| `src/core/encoding.rs:98` | `#[allow(clippy::absurd_extreme_comparisons)]` |
| `src/core/transaction.rs:647` | `#[allow(clippy::too_many_arguments)]` |
| `src/cross_domain/evm/sync_committee.rs:1393` | `#[allow(clippy::large_stack_arrays)]` |
| `src/cross_domain/external/registry.rs:188` | `#[allow(clippy::too_many_arguments)]` |
| `src/cross_domain/external/registry.rs:657` | `#[allow(clippy::too_many_arguments)]` |
| `src/crypto/pkcs11.rs:41` | `#[allow(dead_code)]` |
| `src/crypto/primitives.rs:866` | `#[allow(clippy::expect_used)]` |
| `src/domain/storage_deal.rs:2087` | `#[allow(clippy::too_many_arguments)]` |
| `src/domain/storage_deal.rs:2314` | `#[allow(clippy::too_many_arguments)]` |
| `src/domain/storage_deal.rs:2961` | `#[allow(clippy::too_many_arguments)]` |
| `src/domain/storage_deal.rs:3523` | `#[allow(clippy::too_many_arguments)]` |
| `src/light_client/mod.rs:486` | `#[allow(clippy::missing_const_for_fn)]` |
| `src/network/node.rs:88` | `#[allow(clippy::large_enum_variant)]` |
| `src/network/node.rs:2015` | `#[allow(clippy::single_match)]` |
| `src/network/proto_conversions.rs:19` | `#[allow(clippy::all, clippy::pedantic, clippy::nursery)]` |
| `src/pollen/data_rights.rs:142` | `#[allow(clippy::too_many_arguments)]` |
| `src/pollen/data_rights.rs:400` | `#[allow(clippy::too_many_arguments)]` |
| `src/pollen/data_rights.rs:440` | `#[allow(clippy::too_many_arguments)]` |
| `src/pollen/offers.rs:49` | `#[allow(clippy::too_many_arguments)]` |
| `src/pollen/offers.rs:95` | `#[allow(clippy::too_many_arguments)]` |
| `src/pollen/offers.rs:542` | `#[allow(clippy::too_many_arguments)]` |
| `src/pollen/offers.rs:1001` | `#[allow(clippy::too_many_arguments)]` |
| `src/relayer/policy.rs:192` | `#[allow(clippy::too_many_arguments)]` |
| `src/rpc/api.rs:1` | `#![allow(clippy::too_many_arguments)]` |
| `src/rpc/api.rs:8` | `#[allow(clippy::too_many_arguments)]` |
| `src/settlement/pq_anchor.rs:557` | `#[allow(clippy::too_many_arguments)]` |
| `src/storage/pact_binding.rs:38` | `#[allow(clippy::missing_const_for_fn)]` |
| `src/storage/pact_binding.rs:90` | `#[allow(clippy::missing_const_for_fn)]` |
| `src/storage/pact_binding.rs:118` | `#[allow(clippy::missing_const_for_fn)]` |
| `src/tests/bench_performance.rs:14` | `#[allow(dead_code)]` |
| `src/tests/bench_performance.rs:160` | `#[allow(dead_code)]` |
| `xtask/gates/src/gates/ast_security_gates.rs:352` | `#[allow(clippy::struct_excessive_bools)]` |
| `xtask/gates/src/gates/ast_security_gates.rs:562` | `#[allow(clippy::struct_excessive_bools)]` |
| `xtask/gates/src/gates/budscan_patchset.rs:182` | `#[allow(clippy::too_many_lines)]` |
