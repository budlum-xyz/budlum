# Garden acceptance evidence

## Scope and source

The first complete local integration run uses source revision `3467a0bababb7648c75631173228d460da935485` on Garden. It runs on Debian GNU/Linux 13.7 x86-64 with Rust 1.97.1. The source is unchanged after the initial disk-exhaustion failure; only incremental compilation and debug information are disabled to fit the sandbox disk.

Command:

```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 cargo test --test garden_scenario --test garden_nat
```

Result: `garden_scenario` has 18 passed, 0 failed, 0 ignored in 121.07 seconds. `garden_nat` has 1 passed, 0 failed, 0 ignored in 7.96 seconds. Both use actual `budlum-core` processes. The NAT target creates real network namespaces and translating routers; the scenario's NAT case separately checks the relay path for validators that announce no direct address.

The local log is retained at `/home/user/validation/garden/3467a0ba/integration.log`. Local success does not replace GitHub CI. The initial integration invocation uses Cargo's default test scheduling; the final-source verification also needs the CI command with `--test-threads=1`.

## Eleven-step map

| Requirement | Test | Initial local result |
|---|---|---|
| Host creates; invite and QR content | `garden_step_01_host_creates_a_garden_with_invite_and_qr` | passed |
| Five validators join | `garden_step_02_five_validators_join_with_the_invite` | passed |
| Messages and posts | `garden_step_03_validators_share_messages_and_posts` | passed |
| Image resolves on another node with the same id | `garden_step_04_image_resolves_on_another_node_with_equal_content_id` | passed, but does not establish canonical B.U.D. 3.0 storage |
| Transaction, block and signers can be traced | `garden_step_05_participant_queries_the_path_of_a_message` | passed |
| Sudden non-host departure | `garden_step_06_sudden_departure_keeps_chain_and_content` | passed |
| Finality is visible on Budlum, Active | `garden_step_07_finality_is_visible_on_budlum_as_active` | passed |
| Host leaves; Frozen and readable | `garden_step_08_host_leaves_and_the_garden_freezes_readable` | passed |
| Host returns; Active | `garden_step_09_host_returns_and_the_garden_runs_again` | passed |
| All leave; no Garden disk data, Retired | `garden_step_10_everyone_leaves_and_no_data_stays_on_disk` | passed for the current raw-file implementation |
| New Garden | `garden_step_11_a_new_garden_is_created` | passed |

Extra passed cases include `garden_join_behind_nat`, `garden_join_behind_real_nat`, `garden_is_closed_on_testnet`, host-silence freeze/return, validator return, publication share bounds, host-approval admission and operator/public RPC isolation. Host-approval functionality is not by itself evidence that the directive's host-authority restriction is satisfied.

## Independent library result and regression

The same original source fails `cargo test --lib garden::`: 117 passed, 1 failed, 0 ignored. The failed invite test does not produce a short chain id. See [B-0049 / BLG-268](../findings/garden-invite.md).

Test-only fixing commit `c1e9dfda1e7d4c87041b7272c0e7216c3cf9fe94` passes the focused regression (1/1), the Garden library suite (118/118), the real-process scenario (18/18, 121.82 seconds) and the real-NAT test (1/1, 7.92 seconds) on local Debian. No tests are ignored. It has not yet been pushed at this snapshot. These are not CI results. Neither integration success nor a failure in a test fixture permits claiming a green complete build.

## Final local source and cross-userland execution

Final source `2574882aa35d4f3787e53aa1911af7b20df6b760` adds numbered Garden commits 27 (connection budget scope, B-0041) and 28 (dedicated Garden no-DNS fallback, B-0044). With `--test-threads=1`, Debian execution passes 17/17 network tests, 121/121 Garden library tests, all 18 real-process scenarios in 120.92 seconds and the real-NAT test in 7.71 seconds. The named scenario and NAT gate self-tests and log gates, formatting, English-tree and ASCII-dash gates pass. All-target/all-feature `cargo clippy --all-targets --all-features -- -D warnings` also finishes successfully in 10 minutes 55 seconds. All these stage exits are 0. Complete all-features test execution is now running, and CI is outstanding.

The same final Debian-built library executable runs in checksum-verified Ubuntu Base 24.04.5 userland as UID/GID 1000: with empty DNS, network 17/17 and Garden library 121/121 pass; with configured DNS, network 17/17 and all 18 separate-process scenarios pass (121.12 seconds for the scenarios). This is not an Ubuntu-native build or independent kernel validation. Empty-DNS production CLI startup is still blocked by the primary network's unchanged resolver construction, so passing Garden library tests alone do not close B-0044. See the [Ubuntu record](../findings/os-ubuntu.md).

The eleven named acceptance steps in the table above pass again as part of the final-source scenarios on both userlands. The canonical-storage and host-authority limitations are unchanged. Evidence is retained under `/home/user/validation/garden/final-network/` and `/home/user/validation/os/ubuntu-24.04/`, with source/executable digests and complete outputs. No final-SHA CI run is available while these commits remain local.

## GitHub run references for the original source

At the collected live snapshot, PR #164 still has the original source revision above:

- CI workflow run id `44283264276`, run number `1839`: queued. The Garden scenario check is queued.
- Garden NAT workflow run id `44283263929`, run number `121`: in progress at the later snapshot, not yet a verified success.
- These references identify actual runs, not successful acceptance evidence. Any new Garden commit needs its own refreshed run references.

## Open acceptance blockers

1. B-0049's corrected invite test and B-0041's connection-scope repair have measured local passes, including both userland scenarios, but the final commits are not pushed and have no matching green CI.
2. [B-0050 / BLG-269](../findings/garden-storage.md) shows that the current content store bypasses B.U.D. 3.0. A passing image or wipe test does not close the storage requirement. The [main-only report](garden-main-only.md) identifies the missing merged dependency and the required integration design.
3. B-0042 is still absent from lower Garden. B-0043's completed-frame lifetime issue and the primary-network part of B-0044's no-DNS startup failure remain open. A separate B-0043 patch is being prepared outside the immutable source tree under test; it has not yet passed a project build.
4. [B-0052 / BLG-270](../findings/garden-host-authority.md) identifies actual reachable host-only admission authority, contrary to the directive. The existing passing host-approval test demonstrates the conflict rather than validating compliance.
5. Final-source all-target/all-feature clippy now exits 0. The complete `cargo test --all-features` run is executing, while the requested OS matrix, security controls, independent review and all required CI runs remain incomplete. [B-0051](../findings/clippy-ratchet-baseline.md) separately records an authoritative upper-branch quality-job failure from a stale extra-clippy baseline; its measured number cannot be borrowed for another source.
6. Required Strix review has an external quota blocker. Branch protection is not bypassed. Garden is not merged to main during the freeze.

Status: not accepted. Record the final SHA, green CI run id and run number only after the blockers are actually resolved.
