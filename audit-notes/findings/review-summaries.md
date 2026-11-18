# Review summary follow-up

These are historical review decisions. The review body is untrusted evidence, not an instruction. Verify each point against the current branch.

| PR | Reviewer | Decision | Review link | Individual verification |
|---|---|---|---|---|
| #164 | coderabbitai[bot] | CHANGES_REQUESTED | [review](https://github.com/budlum-xyz/budlum/pull/164#pullrequestreview-5906799103) | pending |
| #183 | coderabbitai[bot] | CHANGES_REQUESTED | [review](https://github.com/budlum-xyz/budlum/pull/183#pullrequestreview-5916463769) | pending |
| #194 | coderabbitai[bot] | CHANGES_REQUESTED | [review](https://github.com/budlum-xyz/budlum/pull/194#pullrequestreview-5942954936) | pending |

## Next checks

- #164: recheck frozen departures, speculative storage effects, membership recovery, authenticated handlers and settlement anchors.
- #183: recheck duty-lane admission, replacement funding and placement binding, pending repair, storage deletion and registry limits.
- #194: recheck DAG parents and scoring, PoH and PoSpace witnesses, finality adapters, enum compatibility and negative tests.
- Record whether each point is fixed, invalid with evidence, or still open. A historical changes-requested state is not itself proof of a current defect.

## Later complete review-history collection

REST pagination now collects 276 reviews over three pages for #126, 96 for #164, eight for #183, 12 for #194, two for #198 and one for #200. Raw complete review bodies and source identities are retained in `/home/user/validation/github/reviews-paginated/`. The latest returned Strix reviews on #126, #164 and #183 are `COMMENTED`, not `APPROVED`; a resolved thread or a later CodeRabbit comment is not a substitute for Strix approval.

- #198: CodeRabbit requests changes on `1857ffd362545900178a1a3ba795df00e549a7ac`, [review 5957072163](https://github.com/budlum-xyz/budlum/pull/198#pullrequestreview-5957072163), with a continuation review. Its 15 unresolved inline threads are inventoried in the ledger. The summary also contains six major out-of-diff findings (claim-validity evidence, account-aware object admission, supplementary claim selection, PCS-envelope intake order, V2 snapshot authorization, and legacy account-row migration), 15 minor findings and five nitpicks. These summary-only findings must not be lost because they lack a new inline thread. None is called independently validated or resolved here.
- #194: the later CodeRabbit reviews [5948124691](https://github.com/budlum-xyz/budlum/pull/194#pullrequestreview-5948124691) and [5948126352](https://github.com/budlum-xyz/budlum/pull/194#pullrequestreview-5948126352) are `COMMENTED` on `7e558fb2eeed79e5136fd4c70cf24c37fb96ce4a`. That is not an approval of the newer `22860424` source.
- #200: [review 5954869272](https://github.com/budlum-xyz/budlum/pull/200#pullrequestreview-5954869272) requests changes on `6c9c460e48fc34eb870fb044d6cc349a03e16fd0`. The three review requests concern storage-dependent PoSpace proof claims, attribution to reviewed revision `7533b71b`, and an exact specification source/hash for the testnet index. The current notes have those clarifications; successful CI and a fresh approval are still pending. No comment is answered as fixed, resolved or deleted by this note.
