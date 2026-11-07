# Live Status

The index of the live finding status (directive 14.1 item 4). One file per lane
carries that lane's records; this file carries the index, the summary and the
mapping back to the directive's own numbers. It is the M0 artifact of WP-04, and M0
is not complete.

Written on a branch based on `main` at `20140e87`. Everything under "measured" was
measured on that commit; everything under "the directive says" is the directive's
snapshot and is labelled as such, because the directive's own rule 0.4 item 3 says a
state held in a document is not a state.

## Measured

| Artifact | State here | Consequence |
|---|---|---|
| `docs/audit/live/lane-a.md` | absent | WP-01 has no record |
| `docs/audit/live/lane-b.md` | absent | WP-02 has no record |
| `docs/audit/live/lane-c.md` | absent | WP-03 has no record |
| `docs/audit/live/lane-d.md` | absent | WP-04 has no record |
| `docs/audit/FINDINGS.md` | absent | No finding has a live status, a reproduction test name, or an evidence line |
| `docs/work/PACKAGES.md` | present | The package register exists as of this change |
| `docs/audit/TLG_REPORT.md` | present | The launch gate register exists as of this change |
| `docs/audit/AUDIT_FINDINGS.md` | present, different register | Review rounds `AF-01`..`AF-15` from two earlier pull requests. It contains 0 `BLG-` identities, so it is not this register and cannot stand in for it |

The finding register is the one artifact every closure claim depends on: directive
14.5 makes a finding closed only when a test named `blg_NNN_<short name>` was red
before the fix and green after it. Measured on this tree:

```
$ grep -rn "fn blg_" --include=*.rs . | wc -l
0
```

So not one finding can be closed by the protocol today, whatever the code does. That
is a statement about the tree, not about the work of the four lanes: a lane that
verifies a finding and finds it already fixed (14.1 item 7) must still land the test
that proves it, and none is in the tree.

## The directive's numbers, not re-measured

| Source | Identity range | Count |
|---|---|---|
| Finding Register (`main` `c5b06799`) | BLG-001 to BLG-207 | 207: 73 Critical, 80 High, 51 Medium, 3 Low |
| B.U.D. 3.0 directive, code defects H1..H15 | BLG-208 to BLG-222 | 15 |
| BudZero directive, findings E1..E23 | BLG-223 to BLG-245 | 23 |
| The directive's own review | BLG-246 to BLG-267 | 22 |
| Archive families | BULGU-001..027, TEST-GAP-01..08, DOC-GAP-01..09 | 44 |

These are the directive's snapshot counts. They are reproduced here so the next
reader does not have to open the directive to know the order of magnitude, and they
are explicitly not a live count: this tree has no artifact that could produce one.

## Findings verified in this session

Four records were verified against the tree while this file was written. They are
not the register, and none of them closes a finding of the directive's list: a
finding closes by the protocol in 14.5, and no `blg_NNN_` test exists yet. The one
record marked closed is BLG-268, a repository defect this branch found and fixed and
therefore one that has no history to re-derive. The rest are here because the
evidence was in hand and a register that arrives later should not have to re-derive
it.

| Identity | Severity | Area | State on this tree | Evidence | Closing package |
|---|---|---|---|---|---|
| BLG-008 | Medium | RPC | Confirmed open, and the contradiction is wider than the register says: it is a documented decision on one side and two configuration files plus the node's own startup check on the other | `config/testnet.toml:50` sets `auth_required = true` for both listeners. `src/main.rs:1624` builds one `RpcSecurityConfig` and `src/main.rs:1697` hands it to the public server; `src/main.rs:1758` refuses to bind the operator listener anywhere but loopback because it runs without auth. `docs/TESTNET.md:33` and directive decision KR-33 say the public listener accepts keyless reads and signed transactions while the operator listener requires the key, which is the opposite arrangement. `ops/docker-compose.yml:15` states the same as the code ("RPC authentication is ON here") and `:125` sends the CI smoke harness to the unauthenticated operator listener, so the arrangement is deliberate in three places, not one | WP-16, with WP-61 |
| BLG-022 | Medium | Consensus | The fix trace exists, and so does the test, so what is missing is the before-and-after | `src/light_client/mod.rs:680` computes the next checkpoint in closed form with checked arithmetic instead of walking the interval, and `:1253` is `next_checkpoint_height_is_closed_form`. The protocol wants the test red first; nothing in the tree records that it ever was | WP-11 |
| BLG-268 (new) | High | Repository | Closed by the cleanup commit in this branch: the binding directive is no longer in the tree, and `/THE_BUDLUM_DIREKTIF.md` is in `.gitignore` | `git show --stat` on the cleanup commit; `tree-is-english` had every line of the file as a finding because it was absent from `ALLOWED_FILES` and from `.github/turkish-baseline.txt` | this branch |
| BLG-269 (new) | High | Repository | Open. Not one test in the tree follows the naming rule of 16.4, so no finding can be closed by the protocol and TLG-02 cannot be evidenced | measured: `*_is_closed_on_testnet` 0, `bud3_*` 0, `uel_*` 0, `blg_NNN_*` 0, `android_*`/`ios_*` 0 | WP-01..WP-04 |

Why BLG-008 was not fixed here: the fix is a second `RpcSecurityConfig` with
`auth_required = false` for the public listener and a keyed one for the operator
listener, plus the config field that feeds it. That is a change inside the RPC
security boundary, it is the boundary 15.5 item 6 asks a second agent to approve, and
this sandbox has no way to compile or run it. A blind edit there trades a documented
contradiction for an undocumented one.


### Documents checked against the tree, and found to agree

The endpoint and parameter claims in `docs/TESTNET.md` were read one by one against
the code and the configuration. These agree, which is worth recording because the one
that does not (BLG-008) is easier to trust when the rest were checked:

| Claim in `docs/TESTNET.md` | Where the tree says the same |
|---|---|
| Chain ids 45260 mainnet, 45261 testnet, 45262 devnet | `src/core/chain_config.rs:34-36`; `config/testnet.toml:5` |
| Network magic `BDLT` | `src/core/chain_config.rs:266` |
| Public RPC `127.0.0.1:28545`, operator `127.0.0.1:18546` | `ops/testnet-local.yml:156` publishes 28545 to the container's 8545; `config/testnet.toml:46` is the operator listener |
| Faucet 100 BUD per request, 100,000 BUD per day | `src/bin/budlum-faucet.rs:61-66` |
| `budlum-faucet`, `budlum-indexer` exist as binaries | `src/bin/` |
| 12-word phrases refused | `crates/wallet-core/src/wallet_v3.rs:76-78` refuses any count but 24 before the mnemonic is read |
| TLS terminated by Caddy; contract in `docs/explorer-api.openapi.yaml` | `ops/Caddyfile.testnet`, `docs/explorer-api.openapi.yaml` |

## Recount proposal (WP-04 job 7)

The directive's own sample says the register's "206 open" is stale for the analysis
base, because 6 of 9 sampled findings already carry a fix. The same is likely here,
and a live number is what M0 asks for. The proposal, in the order it has to happen:

1. Write the four lane files. Each lane takes the findings whose closing package
   belongs to it (directive 15.2) and records, per finding: identity, live state,
   reproduction test name, evidence (file and line), closing package.
2. Write `docs/audit/FINDINGS.md` from those four files, in English, one row per
   finding, with the state the lane measured.
3. Recount by state and severity, and replace the table above with the recount.
4. Only then update the directive's summary, and only with the recount.

Step 1 is the whole of M0 and it is not written: four records are entered above and
265 are not. This file exists so that the gap is visible in the tree rather than in a
comment on a pull request.

## Blocked: one record per package

Directive 15.3 item 1 opens one GitHub record per package, with the card's English
body, and WP-04 job 5 repeats it. Measured:

```
$ gh issue list --limit 5
the 'lubothebook/budlum' repository has disabled issues
```

The step cannot be done in this repository. `docs/work/PACKAGES.md` is therefore the
only package record that exists, and it says so in its own closing section. This is
recorded here as blocked rather than silently skipped, which is what directive 15.1
item 9 asks an agent to do with a blocked step.

## What this file does not claim

1. It does not claim that any finding of the directive's register is closed, open or
   invalid. The one record marked closed above, BLG-268, is a finding this branch
   created and this branch fixed; that is a repository defect with a one-commit
   history, not a verification of the register.
2. It does not claim that any lane is complete.
3. It does not replace the four lane files, which do not exist.
