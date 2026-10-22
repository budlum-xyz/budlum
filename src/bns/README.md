# BNS: the Budlum Name Service (`.bud`) - a module README

**This is BNS's own README, as the module-separation rule requires.**

## Status

- **Maturity:** the skeleton exists in `src/bns/` (`registry.rs`: `BnsRegistry`;
  `types.rs`: `NameRecord`, `BnsError`, `BnsResolved`).
- **Correction (verified against the code on 2026-07-18):** the phrase "no
  architecture yet, starting from zero" is out of date. Registration, resolve,
  transfer, renewal, subdomains and cost scaling are all implemented and
  tested.
- **Out of scope for this round:** the squatting and speaking-rights economy,
  and the integration contract with the B.U.D. and AI layers - those are a
  separate instruction round.

## Current behaviour (locked by tests)

Registration and resolve, expiration, renewal, owner-only subdomains, refusal
of invalid names, transfer, full resolve through storage, and cost scaling.

## Test suite

- 9 tests in total: `src/tests/bns.rs` (2) and `src/tests/bns_expanded.rs` (7).
  Eight of them carry the `test_bns_` prefix.
- They run inside the core lib suite (`cargo test --lib`). The CI gates are
  **`bns-gate`** and **`bns-names`** in `xtask/gates`, both protected against a
  vacuous pass.

  Note: an earlier version of this file promised
  `scripts/check-bns-gate.sh`. No such script exists and none will: the repo
  rule is that gates are written in Rust. The two gates above are what
  actually runs.
