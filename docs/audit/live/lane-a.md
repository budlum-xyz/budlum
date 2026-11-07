# Lane A live status: core

WP-01, slice 1/N. The live status of the findings whose closing package is
WP-08, WP-12, WP-13, WP-14, WP-15, WP-16 or WP-17 (directive section 14.1.4).

| Field | Value |
|---|---|
| Base commit | `20140e87061efc9d8d4076e04305c1318705e348` (`main`) |
| Work branch | `arena/31c78aa9-budlum` |
| Records in scope | 54 |
| Revalidated in this slice | 5 |
| CI run numbers | none: this environment has no `cargo`, `rustc` or `rustfmt` |

## Method

A record is revalidated by reading the live tree, not by trusting the
analysis-base note. Line numbers are never trusted: the evidence below cites
the file and the identifier, so a moved line does not invalidate it. A record
that needs a running network (finality progress, churn, a four-node devnet)
cannot be revalidated here and says so.

Statuses:

- `Confirmed` - open, and the defect is visibly in the tree.
- `Trace present, not proved` - the code that the finding asked for exists,
  but no run proves it closes the finding.
- `Previously fixed` - the fix is visible in the tree and the finding closes
  with a regression test.
- `Not revalidated` - no work on this record yet. The row exists so the
  remaining set can be counted.

## Stop report: BLG-008

Two binding items conflict and the choice is not this package's to make
silently (section 0.3.2, conflicting requirement):

1. The directive's RPC decision (section 12.3 item 2, KR-33) says the public
   testnet listener runs with `auth_required = false` and the operator
   listener with `true`.
2. `src/tests/chain_id_registry_locks.rs` locks every shipped public profile
   to carry a key, with the argument that a keyless listener on a proxy is
   one misconfiguration away from serving the internet.

`docs/TESTNET.md` already documents the keyless surface, so the tree is
inconsistent in two directions and neither file is simply stale. The
proposed resolutions are in the BLG-008 row below. The package does not flip
the flag: opening a public RPC listener is the one change here that cannot be
undone by a later commit, and the environment cannot run the lock test that
would break.

## Rows

| Finding | Severity | Closing package | Live status | Evidence |
|---|---|---|---|---|
| BLG-001 | Critical | WP-12 | Trace present, not proved | `src/consensus/mod.rs:36` defines `MAX_LEADER_ROUNDS = 16` and `src/consensus/mod.rs:104` defines `affordable_leader_round`, which is the leader-round skip the finding asked for. Whether an empty height is skipped end to end needs a four-node run; the trace is not proof (section 14.1.3). |
| BLG-002 | High | WP-16 | Confirmed | `config/testnet.toml` ships no reachable peer source: `bootnodes = []` and `dns_seeds = []`, and the block above them is a placeholder `seeds.<TESTNET_DOMAIN> A 203.0.113.7`. The validator key it names (`./secrets/testnet-validator.key`) is produced by the ceremony, not by the repository. The profile therefore cannot be started as shipped, which is the finding. The tokenomics half of the finding was not revalidated. |
| BLG-003 | High | WP-16 | Not revalidated | No revalidation in this slice. |
| BLG-005 | Medium | WP-16 | Previously fixed | `.gitignore:16` ignores `/secrets/` and `.gitignore:17` ignores `/data/`. The closure is the two lines; the ledger note said the same. |
| BLG-006 | Medium | WP-16 | Not revalidated | No revalidation in this slice. |
| BLG-007 | Medium | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-008 | Medium | WP-16 | Confirmed, blocked on a conflicting requirement | `config/testnet.toml:50` sets `auth_required = true` and its comment says the key is required whatever the bind address. `docs/TESTNET.md:33` says the public RPC needs no API key. Section 12.3 item 2 of the directive decides the case: `auth_required = false` on the public listener and `true` on the operator listener, and KR-33 repeats it. Against the decision, `src/tests/chain_id_registry_locks.rs:166` locks the shipped public profiles as carrying a key (`shipped_profiles_keep_rpc_on_loopback_and_carry_a_key`). Flipping the flag therefore breaks a shipped security lock, and leaving it breaks the documented onboarding. This is a conflicting requirement (section 0.3.2), so it stops here rather than choosing silently. Proposed resolution: keep the API key on the shipped profile and amend the decision to "the public listener is keyless only behind the TLS proxy that sets `trusted_proxies`", or drop the key and add `testnet.toml` to the lock test with the loopback and proxy argument written beside it. |
| BLG-017 | Critical | WP-15 | Not revalidated | No revalidation in this slice. |
| BLG-018 | Critical | WP-12 | Not revalidated | No revalidation in this slice. |
| BLG-019 | Critical | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-020 | Critical | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-021 | Critical | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-023 | Medium | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-027 | High | WP-12 | Not revalidated | No revalidation in this slice. |
| BLG-028 | High | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-031 | Low | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-033 | Critical | WP-15 | Not revalidated | No revalidation in this slice. |
| BLG-034 | High | WP-15 | Not revalidated | No revalidation in this slice. |
| BLG-041 | Critical | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-042 | Critical | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-044 | Medium | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-065 | High | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-066 | High | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-088 | Medium | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-089 | High | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-090 | Medium | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-094 | High | WP-16 | Previously fixed, one gap closed here | `config/archive.toml:6` now carries `chain_id = 45261` under `profile = "testnet"`, and every service in `ops/docker-compose.yml` passes `--consensus=pos` (lines 106, 160, 193, 226, 259) while its header claims PoS. The part of the finding that says the lock test skips the archive profile is closed by this slice: `the_shipped_node_profiles_agree_with_the_code` now lists `config/archive.toml` as `Network::Testnet`, so the profile is compared with the code registry and not only with the genesis file it names. |
| BLG-096 | High | WP-12 | Not revalidated | No revalidation in this slice. |
| BLG-100 | Critical | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-101 | Critical | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-102 | Critical | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-103 | Critical | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-104 | Critical | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-107 | Critical | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-108 | Critical | WP-15 | Not revalidated | No revalidation in this slice. |
| BLG-113 | Critical | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-118 | Critical | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-119 | Critical | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-125 | Critical | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-128 | High | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-132 | High | WP-12 | Not revalidated | No revalidation in this slice. |
| BLG-140 | High | WP-16 | Not revalidated | No revalidation in this slice. |
| BLG-147 | High | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-151 | High | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-158 | High | WP-12 | Not revalidated | No revalidation in this slice. |
| BLG-167 | High | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-183 | Critical | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-184 | Critical | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-196 | High | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-197 | Critical | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-202 | Critical | WP-17 | Not revalidated | No revalidation in this slice. |
| BLG-203 | Critical | WP-12 | Not revalidated | No revalidation in this slice. |
| BLG-206 | Critical | WP-12 | Not revalidated | No revalidation in this slice. |
| BLG-207 | Critical | WP-12 | Not revalidated | No revalidation in this slice. |

## Notes

1. The 49 `Not revalidated` rows are the remaining work of this package, and
   the count is the package's progress measure. Nothing else in this file
   claims a closure.
2. Section 14.1.7 asks for a permanent regression test per previously fixed
   record. BLG-005 needs one in `src/tests/audit_lane_a.rs`; the file is not
   added by this slice because no toolchain here can compile or run a test,
   and a test that has never been compiled is not evidence.
3. New findings from this slice are recorded in `docs/audit/FINDINGS.md`:
   BLG-268 (red indexing gate), BLG-269 (documents pointing at removed
   scripts) and BLG-270 (33 gates that no workflow invokes).

