# Mobile duty engine continuation

## Scope and live baseline

WP-11 continuation of PR #82, based on
`5685e03d87c257e7e1ecc6fd3355eee5cebdbf94`. The session branch is
`arena/dc0a724c-budlum`. The continuation targets the existing mobile-core
branch rather than copying an unrelated package onto `main`.

The initial live survey found 64 open pull requests and a clean worktree.
Of those pull requests, only #82 changes `mobile/core/`. Other open work
already covers worker transport, committee finality, legacy storage removal,
and Ethereum/Solana RPC namespaces. Those packages are not reimplemented here.
GitHub issues are disabled, so the continuation claim is recorded on #82.

The environment permits neither switching to nor pushing another branch.
No existing PR is closed, merged, or retargeted. The supplied directive is
inherited unchanged; this delivery does not duplicate the open directive-removal
PRs. Toolchains, downloaded upstream sources and test executables live outside
the repository and are not deliverables.

## Regressions under investigation

- Saturating quota addition admits overflow when the quota is `u64::MAX`.
- Admission looks up the ESI anywhere in the placement, not at its claimed
  position, and does not require strict ESI ordering.
- A replayed assignment consumes another local id and another copy of its bytes.
- Admission checks free space before, but not after, storing the incoming bytes.
- A refused admission can first release unrelated existing shares.
- Floor recovery can set the user quota below its required 1 GiB minimum.
- An audit identifies a segment and position without identifying its object;
  two objects can silently select the first object's proof.

The tests are committed before their corrections. Findings are not claimed
closed without the directive's executed evidence and CI run identifiers.

## Initial executed evidence

Local compiler: Rust 1.99.0 (`b940084d7`, x86_64 Linux). This is not the
repository's pinned Rust 1.97.1 and does not replace CI verification.

`rustc --edition=2021 -C linker-features=-lld --test
mobile/core/src/quota.rs` followed by the test executable reproduces:

```text
mobile_quota_overflow_is_a_refusal ... FAILED
assertion failed: !fits(u64::MAX, 1, u64::MAX)
0 passed; 1 failed
```

The remaining new regressions have not yet been executed at this checkpoint.
No performance measurement, green CI result, completed package, or testnet
readiness is claimed.
