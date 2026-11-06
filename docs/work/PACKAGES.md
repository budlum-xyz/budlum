# Work packages

One section per directive work package (`İP-NN`, written `WP-NN` in the
repository and on GitHub). The directive requires this file to be updated by
each package's last pull request (Section 15.5, item 7), because a status that
only lives in a PR description disappears when the PR is squash-merged.

Status values: `not started`, `in progress`, `blocked`, `closed`.

A line here is a claim. Each `closed` package names the commit, the CI run and
the engine for its card's done criterion; a package with no entry has not been
claimed by any PR in this repository.

## WP-41 Faucet and operations (lane D, T-Launch, TLG yes)

Status: `in progress`. Dependent PRs: this one (metrics and alert delivery),
#52 (faucet proof of work, faucet alert rules), #34 (RPC and ops hardening).

Before this delivery the node had no series for seven of the eight alerts the
card makes mandatory (Section 15.8, WP-41 item 6). A rule had to be either
absent or written against a name nothing exports; a rule that cannot fire is
worse than no rule, because a console shows it as green.

The directive allows a series to be exported before its production observer
exists (the PQ facade does the same with its disagreement counter). The
`ee_fault_total` row below says so rather than implying a caller that is not
there yet. An alert rule written against a series that is registered and
exported is honest; one written against a name that does not exist is not.

Delivered here:

| Series | Written by | Meaning |
|---|---|---|
| `budlum_finality_stalled` | `Blockchain::emit_chain_metrics` | `1` when the finalized height is eight checkpoint intervals behind the tip (Section 7.7) |
| `budlum_finality_lag_checkpoints` | same | The same lag in the unit the recovery rule is written in; the checkpoint interval is 5 on the testnet and 10 on mainnet, so a block count would mean two different things |
| `budlum_state_root_mismatch_total` | `Blockchain::validate_candidate_chain`, `Blockchain::replay_reorg_blocks` | A block refused because this node computed a different state root (R-11) |
| `budlum_bud3_segments_at_risk` | `emit_bud3_metrics` from `Bud3Registry::total_segments_at_risk` | Segments with at least one lost share |
| `budlum_bud3_repair_backlog` | `emit_bud3_metrics` from `Bud3Registry::repair_backlog` | Segments past the lazy repair threshold |
| `budlum_bud3_custody_bytes{class}` | `emit_bud3_metrics` from `Bud3Registry::custody_bytes_by_class` | Physical custody bytes, split `full` and `mobile` |
| `budlum_bud3_objects` | `emit_bud3_metrics` | Live objects in the rooted registry |
| `budlum_relay_reservations` | `RelayerWorker::emit_reservation_metrics` | Results submitted and not yet in a finalized block |
| `budlum_relay_inflight_reservations` | same | The subset whose external action is unresolved: needs an operator |
| `budlum_ee_fault_total{ee}` | `execution::ee::record_fault`, folded into the scrape by `Metrics::encode` | Faults an execution environment returned instead of an outcome (R-01) |

Alert rules for every one of them are in `ops/monitoring/alerts.yml` under
`budlum-readiness`, `budlum-bud3`, `budlum-relayer` and `budlum-execution`.
`src/tests/alert_rules_reference_existing_metrics.rs` holds the eight mandatory
names in a test: each must be declared in `src/core/metrics.rs` (so the node
exports it) and queried by a rule (so it is not a metric nobody watches).

Still open in WP-41 and not claimed here: the `ops/rehearsal` profile
(card item 4), the Caddy `explorer.`/`faucet.` sites (item 5), the four
operator guides (item 7) and the backup drill on the new persistence paths
(item 8, blocked on the storage migration).

## WP-20 Storage placement, custody proof and repair (lane B, T-Launch, TLG yes)

Status: `in progress` (dependent PRs #13 and #45 hold the placement, custody and
repair implementation).

The card's item 13 names four measurements. Three of them are live here, in the
storage-health block above, because the registry already carries the state they
describe; the fourth, `budlum_bud3_audit_latency`, needs an audit deadline the
registry does not carry yet and is recorded as unfinished rather than bound to
zero.

## Metric kinds the gate can see

`metrics-are-written` compares a declared type against a fixed list of bare
names, so a field declared as `prometheus::IntCounterVec` is invisible to it. All
metric fields are therefore imported and declared bare. The gate's self-test now
has a labelled-series case (`with_label_values` counts as a write) and records
the qualified-name limit as a case rather than leaving it to be rediscovered.

## Merge order against the live PRs

Read from `gh pr view <n> --json files` for every open PR on 2026-11-06.
`docs/work/PACKAGES.md` is a shared append-only file (Section 15.3, item 4), so
it is not a conflict; everything else in this delivery touches paths no open PR
lists.

| Open PR | Package | Paths this delivery shares | What to do |
|---|---|---|---|
| #52 | WP-16 + WP-41 continuation | `ops/monitoring/alerts.yml` | Both add a group at the end of the file. Keep both; the groups do not name the same alert. |
| #34 | WP-61 / WP-16 / WP-41 | `ops/budlum-core.service` (its file, not this one) | No overlap. |
| #41, #53 | WP-61 | `src/crypto/`, `src/rpc/` | No overlap: this delivery does not touch RPC or crypto. |
| #13, #45 | WP-20 | `src/storage/bud3/` (its modules) | This delivery adds readers to `registry.rs` only, and does not change a share, a root or a rule. |
| #11, #16, #24, #36, #40, #46, #48, #49 | various | `src/chain/blockchain.rs` for #40 only | #40 rewrites chain pages; this delivery adds one private emit method and one counter call. Rebase, do not resolve by hand. |

### Delivery 2: the dashboard half of WP-41 item 6

The card asks for "the dashboards and the alert rules of the new metrics".
Delivery 1 shipped the rules; a rule without a panel is an alarm an operator
cannot explain afterwards.

`ops/monitoring/grafana/budlum-testnet.json` gains eight panels, one per
mandatory readiness series plus the custody split by class: finality stall,
finality lag in checkpoints, state-root mismatches, reserved relay slots, the
two B.U.D. 3.0 health gauges, custody bytes by class, and faults by execution
environment. `the_dashboard_queries_series_the_node_exports` holds the
dashboard to the same inventory as the rules, so a renamed series cannot leave
a blank panel that reads as a quiet network.
