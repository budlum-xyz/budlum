# Why this skill sits in the repository

`SKILL.md` in this directory is [andrej-karpathy-skills](https://github.com/multica-ai/andrej-karpathy-skills),
vendored unchanged under MIT.

It is here rather than in a contributor's own environment because three of its
four principles are already rules this tree enforces, and the fourth is the one
this tree keeps relearning:

| Skill principle | What already enforces it here |
|---|---|
| Think Before Coding | `.specify/memory/constitution.md`, which says a claim must name the mechanism that checks it |
| Simplicity First | convention only, no gate |
| Surgical Changes | `scripts/check-gates-are-wired.sh` and the review rule that every changed line trace to the request |
| Goal-Driven Execution | every `scripts/check-*.sh` carries `--self-test`: a gate must be shown to fail before it is trusted |

The fourth row is the reason for vendoring. "Define success criteria, loop
until verified" is the same rule as the no-vacuous-gate policy, and the
failures recorded in this repository are almost all failures of that rule
rather than of the code:

- a gate that printed a stub message and pointed at a file not in the tree
- a badge push that was rejected on every run while the job stayed green
- a test asserting `result.is_err() || result.unwrap().gas_used > 0`, which
  every outcome satisfies
- a source scan that split at the first `#[cfg(test)]` and so read 1% of the
  file it was auditing

Each of those passed. None of them checked anything.
