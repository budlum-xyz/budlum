# Branch cleanup, 2026-11-15

The repository carried 35 remote branches. Five are live and were kept:

| kept | why |
|---|---|
| `main` | default, protected |
| `testnet-quantum` | PR #110 head |
| `testnet` | PR #126 head (base `testnet-quantum`) |
| `garden` | PR #164 head |
| `audit-testnet-2026-11` | these notes |

Thirty were deleted after the live check below. Every branch first had its head SHA read from the remote, and every deleted branch that carried commits not reachable from a kept branch was preserved as a lightweight tag under `archive/2026-11-15/<branch-name>` before deletion, so no commit became unreachable.

## Deleted with an archive tag (19)

| branch | head | commits ahead of `main` |
|---|---|---|
| `bns/b1-bud-suffix` … `bns/b12-cli-publish-site` (12 branches) | `d38eadcb` … `ac0e356c` | 1,034 … 1,072 |
| `audit/master-plan` | `330f9c2b` | 5 |
| `audit/testnet-a8` | `30f5b42f` | 1,098 |
| `bug-fix` | `a7c15c67` | 59 |
| `consensus-of-consensuses` | `d1e44431` | 686 |
| `mains` | `5df7acfe` | 984 |
| `new` | `ba1d1d3e` | 934 |
| `thebudlum` | `6cc4dad4` | 988 |

None of the twelve `bns/*` branches is an ancestor of another: the series is a set of parallel trees, not a stack, so each one needed its own tag. `thebudlum` is an ancestor of `audit/testnet-a8`; both are tagged anyway.

## Deleted without a tag (11)

Eleven `dependabot/*` branches (`dependabot/cargo/…` × 10, `dependabot/github_actions/…` × 1). Each carried exactly one dependency-bump commit and no open pull request; Dependabot recreates a branch when it re-raises the update. Their heads were `3f202556`, `4d2f99d4`, `f3bdb396`, `b5edfa20`, `0c77e441`, `ede92e7c`, `f25475be`, `ac3466e4`, `d47de0f1`, `804af2d5`, `4d7b9ec5`.

## Check performed before deleting

For every candidate: `git rev-list --count origin/main..origin/<branch>` (unique commits), `git merge-base --is-ancestor origin/<branch> origin/<kept>` for each kept branch, and `git log -1 --format=%cs`. Every candidate had unique commits — none was fully merged — which is why the archive tags exist. No branch with an open pull request was touched, and `main` is protected.

## What is not here

`audit-testnet-2026-11` is kept although its pull request (#165) was closed and archived by the repository owner at 2026-11-15T14:11Z. The notes are the deliverable; deleting the branch would delete them from the reviewable record. If the owner wants it gone, that is a separate decision.

The archive tags are a preservation mechanism, not a plan. If the twelve `bns/*` trees are meant to become a stack, they should be re-created deliberately from the tagged commits rather than left as branches that PR-less drift keeps open.
