# WP-55, 2/N: live broadcast driver, gateway door and activation height

| Field | Value |
|---|---|
| Date | 2026-11-06 |
| Branch | `arena/0c480ae6-budlum` (PR #96) |
| Carried from | PR #86 (`arena/e607c9b9-budlum`), WP-55 1/N |
| Layer | T-Expansion, WP-55 (directive 1.4, 1.5, 6.16) |
| New paths | `src/storage/bud3/live.rs` (carried), `src/storage/bud3/live_broadcast.rs` (new), `src/storage/bud3/mod.rs` (append-only) |

## 1. The owed work

PR #86's body and PR #93's audit both name the same three undone items of
WP-55: the broadcast driver, the content-gateway door and the activation
height. PR #86 delivered the time-segment state machine, the `prev_object`
chain, the ratioless frame order and `bud3_live_is_closed_on_testnet`, but its
own `ACTIVATION` constant is a bare `None` with no door that reads it and no
driver that turns a frame into an RFC 6330 symbol.

## 2. What this slice delivers

| Item | Implementation |
|---|---|
| Gateway door | `LiveGateway::admit_object` refuses every bit1 object while live is closed; `admit_live_object` additionally refuses a non-live object; `admit_viewer` checks activation before calling the stream's join. The testnet chain id comes from `Network::Testnet.chain_id()`, never from a literal (`chain_id_is_not_hardcoded`). |
| Activation height | `LiveGateway::for_chain` carries `LiveActivation`; below the height the refusal names both heights; on the testnet chain with no height the refusal is `ClosedOnTestnet`. No baseline was raised and no feature flag was opened. |
| Broadcast driver | `BroadcastDriver` maps `RatiolessPlan` frames to `SegmentEncoder` source and repair symbols, keeps source-first order, bounds subscribers (`MAX_LIVE_SUBSCRIBERS`) and each viewer's queue (`MAX_LIVE_PENDING_SYMBOLS`), drops the oldest symbol under backpressure and counts the drops. |

Named tests: `live_stream_is_closed_on_testnet` (directive 16.4 and 1.5),
`bud3_live_gateway_opens_only_at_the_activation_height`,
`bud3_live_viewer_join_goes_through_the_gateway`,
`bud3_live_broadcast_emits_sources_before_repairs`,
`bud3_live_broadcast_queue_is_bounded`,
`bud3_live_broadcast_refuses_too_many_subscribers`, plus the six carried
WP-55 1/N tests.

## 3. Wire formats, field tags and RPC names

None changed. No `TransactionType` variant, domain tag, genesis value,
protobuf field, ABI version or RPC name is added. The two domain tags of
WP-55 1/N (`BDLM_BUD3_LIVE_STREAM_V1`, `BDLM_BUD3_LIVE_END_V1`) are unchanged.
Live segment objects carry P0; the P1 optical profile stays a per-request
transport property (directive 6.17).

## 4. Concept-name counter

Unchanged. `config/naming/concept_map.toml` is untouched.

## 5. Measurements

None. `MAX_LIVE_SUBSCRIBERS` and `MAX_LIVE_PENDING_SYMBOLS` are labelled
TESTNET-DEFAULT starting parameters, not measurements (directive 0.5).

## 6. Wiring and evidence boundary

The module says `WIRING:` in its header: the executor reaches the gateway doors
once the legacy storage transactions are removed, exactly as the rest of
`bud3` is staged. The refusals are real code paths exercised by the tests, not
prose. This workspace has no Rust toolchain, crate registry, rustfmt or
clippy; `cargo test` was not run. Every `.rs` file in the integrated tree was
parsed with the tree-sitter Rust grammar (zero findings) and the
`rust_syntax_is_parseable` replica scanned the tree (zero findings). CI on
this branch is the compiler and test verifier (directive 0.3 item 5). No green
CI run number is claimed.
