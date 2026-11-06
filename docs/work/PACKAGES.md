# Work package status

One row per work package of the directive (section 15.7). A row is written only
from evidence: a merged path in the tree, an open pull request, or a command
output quoted in the row. The record protocol is directive section 15.5 item 7:
package, status, pull requests, last commit, CI run, closed findings.

Status vocabulary: `not started`, `in progress`, `in review`, `merged`, `blocked`.

## Live state this file was written against

| Item | Value | How it was read |
|---|---|---|
| `main` | `cccf1da1f4bcfe97503a3a00cfba24b172b49b31` | `git ls-remote origin refs/heads/main` on 2026-11-06 |
| Base CI | red | run 42050659038 on `main`; the failing jobs are listed by WP-20 in `docs/audit/FINDINGS.md` as BLG-268 to BLG-275 |
| Open package pull requests | #8 (WP-24), #9 (WP-12), #11 (WP-06), #12 (WP-01, WP-02, WP-03), #13 (WP-20), #14 (WP-44), #15 and #16 (WP-03), #18 and #21 (WP-04), #20 (WP-05), #17, #19, #22, #23 (WP-00 reports) | `gh pr list --state open` |
| Issue tracker | disabled | `hasIssuesEnabled=false`; a claim is therefore recorded in the package pull request body, as the earlier WP-04 and WP-05 claims did |
| Local toolchain | none | `cargo` and `rustc` are absent and the toolchain host is unreachable, so CI is the validator for every row below |

No package has a merged dependency, because `main` carries one commit. Under a
strict reading of section 15.1 item 5 no package is ready, which is what the WP-00
reports record. The working choice in this queue, used by every pull request above,
is: take a package whose lock paths are free, deliver it on a branch, and let the
merge order resolve the shared files. This file is the queue record for that choice.

## Queue

| Package | Title | Lane | Status | Pull request | Lock paths | Findings |
|---|---|---|---|---|---|---|
| WP-61 | RPC and crypto hardening | D | in review, delivery 1/2 | #41 | `src/rpc/tests.rs`, `src/rpc/server.rs` (test module), `src/rpc/method_class.rs` (append), `src/crypto/{primitives,signer,pq,pkcs11}.rs` (test modules), `.github/rpc-method-coverage-baseline.txt` (new) | BLG-004, BLG-009, BLG-010, BLG-029, BLG-030, BLG-032, BLG-099, BLG-192, BLG-200, BULGU-011, BULGU-012 locked; TEST-GAP-07 ratcheted; BLG-150 and BLG-200 keep open feet in other lanes |

Last commit of the WP-61 row: `git log -1 --format=%H` on the branch, written by
the push that updates this row. CI run: the run number of the `Tests` job on the
pull request head, read after the push and written into the row before a merge is
proposed.

## Remaining work in WP-61

1. `2/2`: lower the coverage baseline by writing the missing answer and refusal
   tests, beginning with the rows the WP-61 card names: the registry reads, the
   validator reads (`bud_getValidator`, `bud_listRelays`, `bud_listGateways`), the
   BNS reads and the storage reveal session reads.
2. The feet of BLG-150 and BLG-200 that sit outside the lock paths of WP-61 stay
   open and are recorded in `docs/audit/FINDINGS.md` with their owning package:
   `src/privacy/` and `src/relayer/` for the nullifier, `src/chain/finality.rs` for
   the aggregator, `src/cross_domain/evm/rlp.rs` for the depth bound.
3. BLG-008 and BLG-032 keep the listener half in WP-16 and the gateway half in
   WP-21; WP-61 touches neither path.
