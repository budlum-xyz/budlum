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

## Limitations

The local results are not GitHub CI and do not establish testnet readiness. No result for Ubuntu, macOS, Windows, Android, iOS, or Alpine is inferred from this Debian run.
