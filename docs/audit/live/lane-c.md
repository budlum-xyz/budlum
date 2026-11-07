# Lane C live status: execution, BudZero, domains, privacy, AI

WP-03, slice 1/N. The live status of the findings whose closing package is
WP-26 to WP-35, WP-44, or WP-49 to WP-60 (directive section 14.1.4).

| Field | Value |
|---|---|
| Base commit | `20140e87061efc9d8d4076e04305c1318705e348` (`main`) |
| Work branch | `arena/31c78aa9-budlum` |
| Records in scope | 48 |
| Revalidated in this slice | 1 |
| CI run numbers | none: this environment has no `cargo`, `rustc` or `rustfmt` |

## Method

The same method as `docs/audit/live/lane-a.md`: read the live tree, cite the
file and the identifier rather than a line number, and never claim a closure
that no run proves. A record marked `Not revalidated` has a row here so the
remaining set can be counted; it is not a status claim.

## Rows

| Finding | Severity | Closing package | Live status | Evidence |
|---|---|---|---|---|
| BLG-024 | Low | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-036 | Critical | WP-33 | Not revalidated | No revalidation in this slice. |
| BLG-037 | Critical | WP-33 | Not revalidated | No revalidation in this slice. |
| BLG-038 | Critical | WP-33 | Not revalidated | No revalidation in this slice. |
| BLG-039 | Critical | WP-33 | Not revalidated | No revalidation in this slice. |
| BLG-040 | High | WP-33 | Not revalidated | No revalidation in this slice. |
| BLG-043 | Critical | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-050 | Critical | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-051 | High | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-052 | Medium | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-053 | High | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-054 | Critical | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-055 | Critical | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-056 | High | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-057 | High | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-058 | High | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-067 | High | WP-33 | Not revalidated | No revalidation in this slice. |
| BLG-069 | Medium | WP-33 | Not revalidated | No revalidation in this slice. |
| BLG-091 | Critical | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-105 | Critical | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-114 | Critical | WP-33 | Not revalidated | No revalidation in this slice. |
| BLG-115 | Critical | WP-33 | Not revalidated | No revalidation in this slice. |
| BLG-116 | Critical | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-120 | High | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-127 | Critical | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-130 | Critical | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-131 | High | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-134 | Critical | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-136 | High | WP-33 | Not revalidated | No revalidation in this slice. |
| BLG-138 | Critical | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-139 | Critical | WP-33 | Not revalidated | No revalidation in this slice. |
| BLG-142 | Critical | WP-33 | Not revalidated | No revalidation in this slice. |
| BLG-146 | Critical | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-148 | High | WP-33, WP-07 | Not revalidated | No revalidation in this slice. |
| BLG-154 | Critical | WP-33 | Not revalidated | No revalidation in this slice. |
| BLG-155 | High | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-159 | High | WP-33 | Not revalidated | No revalidation in this slice. |
| BLG-162 | High | WP-33 | Not revalidated | No revalidation in this slice. |
| BLG-182 | Critical | WP-33 | Not revalidated | No revalidation in this slice. |
| BLG-186 | Critical | WP-33 | Not revalidated | No revalidation in this slice. |
| BLG-190 | Critical | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-191 | Critical | WP-33 | Not revalidated | No revalidation in this slice. |
| BLG-194 | Critical | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-195 | Critical | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-198 | Critical | WP-33 | Not revalidated | No revalidation in this slice. |
| BLG-199 | High | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-204 | High | WP-44 | Not revalidated | No revalidation in this slice. |
| BLG-205 | Critical | WP-44, WP-15 | Not revalidated | No revalidation in this slice. |

## Notes

1. The 47 `Not revalidated` rows are the remaining work of this package.
2. `docs/audit/live/engine-inventory.md` is the second document the package's
   done criterion names. It is written, but it measures an empty catalog: no
   engine the directive's section 8.2 lists is a dependency of this tree.
   The licences and the `cargo-deny` pre-check cannot be measured here, and
   the file says so instead of guessing.
3. The ledger's second table (section 14.4) uses a different column shape for
   the records it carries: the second column is a family label such as
   `Gonca E1` rather than a severity, and the last column names a file or a
   package list rather than one package. Three of those records fall in this
   lane by their text (BLG-223, BLG-224, BLG-235) and are not counted in the
   48 above. They are recorded here so the omission is deliberate and visible,
   and the lane that owns them adds them with a severity instead of an
   inferred one.

