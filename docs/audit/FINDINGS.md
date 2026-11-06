# Findings ledger

Append-only WP-11 continuation records from PR #88. Earlier ledger sections
proposed by other open PRs must be retained at integration. No finding below
is closed: local evidence is not a substitute for the pinned-toolchain CI run
required by the closing protocol.

A live scan of open PR bodies and changed audit documents found BLG-297 as
the highest allocated identifier before this slice reserved BLG-298 through
BLG-301 in PR #88. Existing open PRs reuse some earlier identifiers for
unrelated findings; references to those records include their originating PR.

| Finding | Severity | State | Evidence and correction |
|---|---|---|---|
| BLG-298 | Medium | Open; locally corrected, CI evidence pending | `quota::fits` used saturating addition, so `fits(u64::MAX, 1, u64::MAX)` incorrectly succeeded. `mobile_quota_overflow_is_a_refusal` executed red after `224deb93d27634c28a7d53f79f72378ee12c4702`. Checked addition in `0886af28034319c96b63659b97a069e0b2af6e1e` makes it green. Policy's 64 GiB limit bounds the normal caller; the public quota helper and store still must reject arithmetic overflow. |
| BLG-299 | Medium | Open; locally corrected, CI evidence pending | Replaying one assignment allocated another local id and stored another copy. The replay regression executed red after `cf15d20726dd094eeae0fc4a339b6636fa697f7b`: expected a refusal, got `ShareRecord { id: ShareId(1), ... }`. `0886af28034319c96b63659b97a069e0b2af6e1e` refuses an existing `(object, segment, position)` or `(object, segment, ESI)` before mutation. Controls prove refusal preserves free space, quota, records and pending duties, while distinct symbols of one segment remain usable. |
| BLG-300 | Low | Open; locally corrected, CI evidence pending | `next_id.saturating_add(1)` could reuse the final local id and overwrite a record after exhaustion. `mobile_share_id_exhaustion_does_not_overwrite_a_record` executed red at `320adcfcc1877bd71fe2f6080466c4c30c30064c`. `0886af28034319c96b63659b97a069e0b2af6e1e` checks the increment before mutation and refuses exhaustion. The final control also preserves an existing record and the counter. This is a local-store boundary, not a chain share identifier. |
| BLG-301 | Medium | Open; locally corrected, CI evidence pending | The inherited mobile suite did not compile on stable Rust 1.99.0: `sig.as_slice()` on an existing byte slice triggered E0658. `cf15d20726dd094eeae0fc4a339b6636fa697f7b` removes the extra call. All-target Clippy also reported `manual_range_contains` in `Policy::set_quota`; `b041519678e16914823df3e3395d85f2537a6a1e` uses the equivalent inclusive-range check without a lint exemption. The local suite and strict Clippy now pass; Rust 1.97.1 and CI remain unverified. |

## Existing compatibility findings, not renumbered

- **PR #77 / BLG-289:** PR #85 scopes audit selection to the named object.
  `ef5b471cdb78300dfbd55ff2e6b1eaa6ce6a2935` retains that object in every
  returned `(object, proof)` pair. A two-object, identical-symbol regression
  executed red before the latter correction and is green afterward. This
  fixes the local selection/retention legs only. Shared types, signed wire
  round trips and node integration evidence remain outstanding.
- **PR #77 / BLG-288:** the mobile and PR #70 node presence preimages still
  differ. The G-5 vector is locked in `tests/vectors/presence/v1/` and checked
  by `presence_preimage_matches_shared_golden_vector`. No node source is
  silently changed to conceal the unresolved incompatibility.
- **PR #77 / BLG-290:** mobile release duties still carry process-local ids,
  while PR #45 proposes an object/optional-segment/quota-delta payload. The
  directive requires chain share identities and a new quota. These contracts
  must be reconciled before a valid mobile release transaction can be built.

Detailed red/green output, source/toolchain caveats, scope constraints and the
remaining integration blockers are in `MOBILE_CORE_REVIEW.md`. No performance
measurement, package completion or testnet readiness is claimed.
