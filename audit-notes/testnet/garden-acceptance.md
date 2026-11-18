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

Test-only fixing commit `c1e9dfda1e7d4c87041b7272c0e7216c3cf9fe94` passes the focused regression (1/1) and the Garden library suite (118/118, 0 ignored) on the local Debian environment. Its scenario and NAT rerun is in progress and it has not yet been pushed at this snapshot. These are not CI results. Neither integration success nor a failure in a test fixture permits claiming a green complete build.

## GitHub run references for the original source

At the collected live snapshot, PR #164 still has the original source revision above:

- CI workflow run id `44283264276`, run number `1839`: queued. The Garden scenario check is queued.
- Garden NAT workflow run id `44283263929`, run number `121`: in progress at the later snapshot, not yet a verified success.
- These references identify actual runs, not successful acceptance evidence. Any new Garden commit needs its own refreshed run references.

## Open acceptance blockers

1. B-0049's corrected library test needs successful execution and final-commit CI.
2. [B-0050 / BLG-269](../findings/garden-storage.md) shows that the current content store bypasses B.U.D. 3.0. A passing image or wipe test does not close the storage requirement. The [main-only report](garden-main-only.md) identifies the missing merged dependency and the required integration design.
3. B-0041 and B-0042 are repaired on an upper branch but absent from this Garden source. B-0043's frame lifetime problem and B-0044's no-DNS startup failure also remain open.
4. The requested OS matrix, final-source clippy/all-features checks, security controls, independent review and all required CI runs remain incomplete.
5. Required Strix review has an external quota blocker. Branch protection is not bypassed. Garden is not merged to main during the freeze.

Status: not accepted. Record the final SHA, green CI run id and run number only after the blockers are actually resolved.
