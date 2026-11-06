# Package status record

Directive section 15.5 item 7 keeps one row per work package here: package,
status, pull requests, last commit, CI run numbers, findings closed. The
directive's section 15.3 item 1 opens a GitHub issue per package; issues are
disabled in this repository, so the record lives in the tree and the claim is
repeated in the pull request that does the work.

Status vocabulary: `not started`, `in progress` (a PR is open and the package's
done-criteria are not all met), `merged`, `blocked` (a dependency, a lock
conflict or a stop condition).

| Package | Lane | Layer | Status | Pull requests | Last commit | CI | Findings closed |
|---|---|---|---|---|---|---|---|
| WP-15 | A | T-Launch | in progress (1/3) | this PR | `b15f8fa` | see PR | BLG-033 (P2P decode foot), BLG-034, BLG-205 (P2P decode feet) |

## WP-15: network, NAT traversal and P2P hardening

Card: directive section 15.8. Dependency WP-01; lock paths `src/network/`,
`Cargo.toml` (libp2p features), `config/*.toml` (`[relay]`),
`src/core/chain_config.rs` (`SecurityConfig`).

| Card item | State in this PR |
|---|---|
| 1. Add `relay`, `dcutr`, `autonat` to the libp2p features | **not done** - the three are optional crates of the pinned libp2p revision, so the workspace `Cargo.lock` has to be regenerated with a toolchain; a hand-written lock would have to guess versions the pin then rejects. Part 2 of this package. |
| 2. Relay configuration (`[relay]`, `enable_circuit_relay`) | **not done** - follows item 1. |
| 3. AutoNAT reachability, relay reservation, DCUtR upgrade | **not done** - follows item 1. |
| 4. Every `bincode::deserialize` in `proto_conversions.rs` on a bounded reader | **done** - twelve call sites now decode through `decode_tx_payload`. |
| 5. Subnet diversity, Kademlia private-address policy | **partly done** - the eclipse bucket covers IPv6 `/64` and the IPv4-mapped form, and `Identify` may not insert a private address on a public profile. Outbound-connection subnet diversity keeps its existing semantics. |
| 6. UTF-8 slicing panic (BLG-017) | **already fixed in this snapshot** - `log_prefix` slices by character, locked by `log_prefix_survives_multibyte_input` (`src/network/node.rs`). |
| 7. Metrics `budlum_relay_*`, `budlum_nat_status`, `budlum_dcutr_*` | **not done** - there is no relay to count yet. |

Done-criterion (two NAT-ed nodes meet over a relay and upgrade to a direct
connection) is **not met**: it needs items 1-3. This package therefore stays
`in progress`; the directive's section 15.5 item 10 forbids claiming it
complete.
