# Debian execution record

## Environment

- Debian GNU/Linux 13.7 (trixie), x86-64, Linux `6.1.189+`.
- Rust toolchain specified by the repository: `1.97.1`.
- Constrained sandbox: approximately 1.9 GiB RAM, two virtual CPUs and a 6 GiB temporary swap file. Builds use one Cargo job and `mold`.

## Results on the staged Garden tree

- `cargo fmt --all -- --check`: passed.
- `target/debug/deps/budlum_core-15c13943f9744594 --list`: 6,038 default-feature library tests listed.
- `garden::net::tests::`: 16 passed, zero failed.
- `three_node_validator_sentry_public_follower_relays_blocks_while_blocking_direct_access`: one passed.
- `node_sentry_shield_isolates_validator_discovery_and_scrubs_kademlia`: one passed.
- `network_event_loop_has_no_bare_lock_unwrap`: one passed.
- The complete default-feature library test run is in progress. All-features tests, clippy on this final tree, production user journeys and all other operating systems remain to be verified.

## Final local Garden source

Source `2574882aa35d4f3787e53aa1911af7b20df6b760` contains numbered Garden commits 26 through 28. These results supersede neither the original failing invite test nor the separate upper-branch historical runs above; each has its own source identity.

| Command | Result |
|---|---|
| `cargo test --lib garden::net::tests:: -- --test-threads=1` | 17 passed, 0 failed, 5.61 seconds, exit 0 |
| `cargo test --lib garden:: -- --test-threads=1` | 121 passed, 0 failed, 138.25 seconds, exit 0 |
| `cargo test --test garden_scenario -- --test-threads=1` | 18 passed, 0 failed, 120.92 seconds, exit 0 |
| `cargo test --test garden_nat -- --test-threads=1` | 1 passed, 0 failed, 7.71 seconds, exit 0 |
| `cargo fmt --all -- --check` | exit 0 |
| `budlum-gates garden-scenario --self-test` and final-source scenario log check | both exit 0 |
| `budlum-gates garden-nat --self-test` and final-source NAT log check | both exit 0 |
| `budlum-gates tree-is-english` | exit 0; existing baseline only |
| `budlum-gates no-unicode-dashes` | exit 0 |

All listed test runs have zero ignored cases. Scenario and NAT use actual separate production-node processes; the NAT target uses real namespaces and translating routers. Build environment has `CARGO_INCREMENTAL=0`, `CARGO_PROFILE_DEV_DEBUG=0` and `CARGO_PROFILE_TEST_DEBUG=0`. Source digests, exact commands, individual logs and stage exit codes are in `/home/user/validation/garden/final-network/`. All-target/all-feature `cargo clippy --all-targets --all-features -- -D warnings` subsequently finishes with exit 0 in 10 minutes 55 seconds. The complete `cargo test --all-features` invocation is now compiling, with source assertions before and after execution and a separate log under `/home/user/validation/garden/final-all-features/`; no outcome is yet observed. The three commits are still local, so earlier remote CI checks cannot validate this source.

## Limitations

The local results are not GitHub CI and do not establish testnet readiness. No result for Ubuntu, macOS, Windows, Android, iOS, or Alpine is inferred from this Debian run. The separate Ubuntu execution record has its own userland/binary provenance. B-0042, B-0043, the primary-network part of B-0044 and canonical B.U.D. 3.0 integration remain open.
