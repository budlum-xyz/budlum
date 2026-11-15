# Budlum audit report

## Evidence scope

The open-PR snapshot was collected on 2026-11-15. It is a point-in-time inventory, not a final result. Refresh heads, review threads, check runs and protections before acting. No reviewed comment has been replied to, resolved or deleted in this audit pass. The complete captured Strix bodies and per-comment records are in [strix-ledger.md](strix-ledger.md) and `strix-evidence.json.gz`. The ledger marks independent verification pending; a GitHub-resolved thread alone does not prove a fix.

## Open pull requests

| PR | Source -> base | Head at capture | Checks at capture | Unresolved threads | Merge state |
|---|---|---|---|---:|---|
| [#110](https://github.com/budlum-xyz/budlum/pull/110) | `testnet-quantum` -> `main` | `a52933e131050a2027a0d90d582881a68d4e7405` | 124 success, 1 failure, 1 neutral, 1 skipped. Strix is the failure. | 6 | blocked |
| [#164](https://github.com/budlum-xyz/budlum/pull/164) | `garden` -> `main` | `d4a76a7521de3e06ac2c582670bacca3e206b3db` | 113 success, 1 failure, 1 neutral, 1 skipped. OSV Scanner is the failure. | 19 | blocked |
| [#126](https://github.com/budlum-xyz/budlum/pull/126) | `testnet` -> `testnet-quantum` | `ea1440975ad4b82aef2a92b95d43f275727d9e33` | 13 success, 33 skipped, 1 neutral, 86 queued or in progress. | 61 | blocked |

`main` protection requires the Strix Security Review check and resolved conversations. No Strix approval for the current work is established. Existing successful checks are not evidence for an uncommitted fix. The audit branch has no CI run for these notes yet.

## Findings and work in progress

- [B-0001: Garden writes the Budlum domain view outside blocks](findings/garden-settlement.md) is open. Its dependency and no-preexisting-account constraint need a compatible design. No two-node regression or fix commit exists.
- PR #110 has five active master-summary findings: Graft replay capacity, unverified manifest shard sizes, certificate sync-hint authentication, client-selected signing chain IDs, and the bridge asset namespace. The six unresolved inline threads cover the latter three inline subjects. The first and third master-summary findings also sit outside the PR diff and must not be missed merely because no thread is open.
- The storage manifest registration path validates declared structure but does not require a proof linking every declared shard size and parity root to actual bytes. A signer helper that chooses to inspect bytes cannot alone prove what arbitrary signers inspected. A complete protocol must address confidentiality, proof work, transaction size and historical replay; this is not fixed by geometry alone.
- The testnet directive index is a work-in-progress in [testnet/index.md](testnet/index.md). The attached directive is not tracked in the captured repository trees. It is not committed here.

## Local verification and limitations

- The sandbox reports Debian 13 x86_64. No complete multi-OS testnet scenario has been demonstrated.
- On an intermediate PR #110 working tree, `cargo check --all-targets --locked` completed successfully. It is not a final-tree test or CI result.
- A prior-tree targeted test binary passed selected tests. Its full scan was stopped because the tree changed. It does not validate the current tree.
- The PR #110 README definition blocks match the directive's protected checksums and are unchanged by the local edits. The captured `main` blocks differ from those target checksums; the audit branch does not edit them. No README count is changed without a green measured test run.
- Tests for some in-progress fixes were added after implementation. The directive's requirement that the test be observed failing before the fix is not yet demonstrated. Reproduce a red result against the pre-fix tree and report the chronology; do not claim that earlier observation occurred.
- The full directive, every file, every operating system and every PR diff have not yet been independently reviewed. No green CI run or completed testnet rehearsal is claimed for this audit.

## Open risks and next steps

1. Complete and test the PR #110 findings on their own branch. Preserve replay and migration compatibility rather than assuming a fresh chain.
2. Refresh and independently trace all ledger records, including already-resolved historical threads. Record commit and green CI evidence before any review response or deletion.
3. Obtain the required Strix re-review and approval; do not merge while required checks or discussions remain open.
4. Resolve B-0001 and the separate Garden security findings without assuming unmerged main functionality. Run the real multi-node scenario.
5. Finish the directive inventory and source audit, then run the planned operating systems. Keep unrun systems explicitly pending.
6. `BADGE_PUSH_TOKEN` is a named supply-chain risk in the audit directive. A literal search in the captured main and PR #110 workflows found no occurrence. This is not a complete secret or workflow-permission audit; examine badge publishing, permissions and token exposure before declaring the risk absent.
7. An independent third-party security assessment is not evidenced by this pass. Automated Strix review is not a substitute.

## Rule and permission statement

No new `#[allow]`, `#[ignore]`, disabled check, force-push, protection bypass or old dependency pin is intentionally introduced by this audit. This statement does not certify the whole repository. The prior red-test timing requirement remains unverified as stated above. The user-provided directive and credentials are excluded from commits and comments.
