# Unified findings ledger - repository record

Directive section 14.1 item 9 keeps new findings here, and item 4 keeps the
per-finding live state in `docs/audit/LIVE_STATUS.md` (WP-04). This file holds
the rows a package closes, with the evidence that closed them: the permanent
regression test, the file that carries the fix, the commit and the CI run.

The ledger numbers, severities and titles come from the directive; this file
does not renumber anything. A finding with a foot in two lanes is closed by two
packages, and each package closes only its own foot.

## Closed rows

| Identity | Severity | Status | Foot this PR closes | Evidence | Test | Closing package |
|---|---|---|---|---|---|---|
| BLG-033 | Critical | Closed (P2P decode foot) | The unauthenticated P2P wire frame decoded transaction-type payloads with bare `bincode::deserialize`, so a `u64` length prefix inside a legal 10 MiB frame asked the allocator for a terabyte before a single byte was read. | `src/network/proto_conversions.rs` `decode_tx_payload`; twelve call sites (ten transaction payloads, two slashing reports) | `p2p_bincode_is_bounded` | WP-15 |
| BLG-034 | High | Closed (eclipse and routing-table feet) | The eclipse bound keyed on an IPv4 `/24` only: an IPv6 peer, or the IPv4-mapped form of the same peer, produced `None`, and `None` is admitted without a bound. Separately, `Identify` inserted every advertised address into Kademlia, so a peer could fill the routing table with addresses nobody can dial. | `src/network/peer_manager.rs` `SubnetKey`; `src/network/node.rs` `subnet_bucket`, `advertised_address_is_allowed`, and the `Identify` handler | `eclipse_bound_covers_ipv6_peers`, `ipv4_mapped_address_is_not_a_new_subnet`, `kademlia_refuses_private_addresses_on_public_network` | WP-15 |
| BLG-205 | Critical | Closed (P2P decode foot) | The same unbounded `bincode::deserialize` set, named by this finding as five further OOM vectors over `Identity`/`Vault`/`Pollen*` payloads. The registry `readmit` foot stays open in WP-44. | `src/network/proto_conversions.rs` `decode_tx_payload` | `p2p_bincode_is_bounded` | WP-15 (registry foot: WP-44) |
| BLG-017 | Critical | Closed (pre-fixed) | The P2P vote logging path sliced a string by byte index, and a multi-byte character at the cut panicked the node. `log_prefix` walks characters instead; the finding is closed in this snapshot, not by this PR. | `src/network/node.rs` `log_prefix` | `log_prefix_survives_multibyte_input` | WP-15 (pre-fixed) |

## Open rows this PR touches but does not close

| Identity | Severity | Why it stays open |
|---|---|---|
| BLG-247 | High | NAT traversal is absent: `relay`, `dcutr` and `autonat` are not in the libp2p feature list and `SecurityConfig::enable_circuit_relay` is `false` on testnet. Wiring them changes the workspace lockfile, so it is WP-15 part 2. |
| BLG-108 | Critical | Gossipsub pre-validation, the RBF penalty, the `GossipDedup` re-ban loop and `SlashingEvidence` reputation farming are untouched by this PR. |

## New rows

None. This PR found nothing that the ledger did not already carry.
