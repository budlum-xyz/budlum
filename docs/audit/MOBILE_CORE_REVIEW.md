# Mobile duty engine continuation

> **Integration note for #140:** this is PR #88's historical source review and
> Rust 1.99.0 evidence, not a fresh run on the integration branch. The current
> node presence implementation is `src/registry/presence.rs`; it still hashes
> the unlength-prefixed domain/chain/window/class concatenation, so the recorded
> node/mobile presence incompatibility remains open. The current Android/iOS
> applications and release payload were not changed by this integration.

## Scope and live baseline

WP-11 continuation, PR #88, on the session-fixed branch
`arena/dc0a724c-budlum`. The worktree was clean at the initial survey; the
observed `main` head was `cccf1da1f4bcfe97503a3a00cfba24b172b49b31`.

The initial survey found 64 open PRs. Only #82 then changed `mobile/core/`.
It already supplied the mobile duty engine at
`5685e03d87c257e7e1ecc6fd3355eee5cebdbf94`. While this review was underway,
#85 supplied several of the same planned corrections. This continuation
therefore carries #85 intact and targets its branch at
`0a3cf5fc3ac0a242a36f129a27b9fc39698e0055`. The stack is **#82 -> #85 -> #88**.
The final live survey found 68 open PRs, not 68 completed packages.

This does not reimplement the other open worker-ABI, committee-finality,
legacy-storage-removal or Ethereum/Solana gateway packages. GitHub issues
are disabled, so continuation claims and coordination are posted on the PRs.

The environment permits neither switching to nor pushing another branch.
No existing PR is closed, merged or retargeted. Only this continuation PR's
base changes. The supplied directive is inherited unchanged; its removal is
already proposed by other open PRs. Toolchains, downloaded upstream sources,
external manifests and executables are outside the repository and are not
source deliverables.

## Attribution and implemented changes

| Commit | Delivery |
|---|---|
| `224deb93d27634c28a7d53f79f72378ee12c4702` | First boundary regressions; quota overflow executes red before correction |
| `cf15d20726dd094eeae0fc4a339b6636fa697f7b` | Carry #85 intact, adapt the regression controls, repair the inherited unstable slice call |
| `320adcfcc1877bd71fe2f6080466c4c30c30064c` | Test-first reproductions for objectless proof duties and local share-id exhaustion |
| `0886af28034319c96b63659b97a069e0b2af6e1e` | Checked quota/id arithmetic; replay and conflicting-coordinate refusal before mutation |
| `ef5b471cdb78300dfbd55ff2e6b1eaa6ce6a2935` | Retain object keys in returned custody proof batches |
| `b041519678e16914823df3e3395d85f2537a6a1e` | Fix the inherited strict-Clippy range warning without exemptions |
| `d6b7457acc19f6b64499adf931d31b55326bac14` | Stronger refusal/positive controls and the shared G-5 presence vector |

PR #85, not this continuation, implements exact placement-position/ESI/leaf
binding, strict ESI ordering, object-scoped audit selection, the post-admission
free-space check, immediate floor recovery, and quota-reduction selection.
Its commits are preserved rather than independently recreated.

The new code in #88 changes the production `MobileCore`/`ShareStore` path:

- Quota addition fails on overflow rather than saturating into an acceptance.
- An existing object/segment/position or object/segment/ESI cannot be stored
  again. The stable refusal is `mobile_share_already_stored`. The core does
  not charge another copy, consume free space or queue unrelated duties.
- Local share-id exhaustion is `mobile_share_id_exhausted`, checked before
  insertion. The previous record and counter survive the refusal.
- `CustodyProofBatch.proofs` carries `(object, proof)` pairs, matching the
  node transaction's field shape. Two objects with identical symbol bytes
  no longer collapse into the same returned duty.
- The presence vector fixes all four length-prefixed inputs, including the
  domain tag. Class, window and chain-id separation have negative controls.

No new dependency, unsafe code, lint allowance, ignored test, inflated
baseline, genesis parameter, domain tag, RPC name or protobuf field is added.
The proof-batch change is a local Rust API change, not a completed network
serialization or activation change. The concept-name counter is unchanged.

## Executed red evidence

These are actual local results, not a claim that merely committing a test
constitutes a red run.

The first mobile test build found an inherited test-only compiler error:

```text
error[E0658]: use of unstable library feature `str_as_str`
mobile/core/src/lib.rs:53:43
public == OWNER.as_slice() && sig.as_slice() == mock_sign(preimage).as_slice()
```

`sig` is already a byte slice. Removing its unnecessary `as_slice()` fixes
compilation without changing the mock signature verification behavior.
After that repair and after carrying #85, the new tests reproduced:

```text
mobile_quota_overflow_is_a_refusal ... FAILED
assertion failed: !fits(u64::MAX, 1, u64::MAX)

mobile_assignment_replay_does_not_consume_quota ... FAILED
expected a refusal, got ShareRecord { id: ShareId(1), ... }

mobile_share_id_exhaustion_does_not_overwrite_a_record ... FAILED
assertion failed: store.accept(assigned, 1_000).is_err()

mobile_proof_duty_keeps_the_object_identity ... FAILED
assertion `left != right` failed: the host must know which object to submit
```

Strict local Clippy also reproduced the inherited policy warning:

```text
error: manual `!RangeInclusive::contains` implementation
mobile/core/src/policy.rs:71:12
-D clippy::manual-range-contains implied by -D warnings
```

## Local verification boundary

Compiler: **Rust 1.99.0**, `b940084d7eb6a299eb4bfeb8e34901bc051e7ac4`,
x86_64 Linux; cargo 1.99.0, rustfmt 1.10.0, Clippy 0.1.99. These tools
are installed outside Git from the npm toolchain-component mirror. The
repository's pinned **Rust 1.97.1 is not available locally**. It is not
silently replaced in the repository.

Outbound access cannot reach the normal Rust/crates.io distribution hosts.
Local compilation therefore uses exact-version upstream GitHub archives in
an external Cargo directory source. Workspace-inherited lint tables are
removed only from those isolated external dependency manifests so they can
load without their parent workspaces. An external check manifest retains
the mobile package's dependency/features/lint settings and points directly
to the repository's unchanged library and integration-test paths. It does
not substitute copied mobile source or mock cryptographic dependencies.
This is source-level local verification, **not a crates.io lockfile or
pinned-toolchain CI verification**.

Executed commands, with the paths abbreviated to their roles:

```text
cargo test --manifest-path <external-check>/Cargo.toml --offline \
  --config <external-source-config> --no-fail-fast
cargo clippy --manifest-path <external-check>/Cargo.toml --offline \
  --config <external-source-config> --all-targets -- -D warnings
cargo fmt --manifest-path mobile/core/Cargo.toml --all -- --check
git diff --check
```

Final source-check results at implementation commit `d6b7457`:

```text
library tests:     11 passed; 0 failed; 0 ignored
integration tests: 12 passed; 0 failed; 0 ignored
doc tests:          0 passed; 0 failed
strict Clippy:     passed
mobile formatting: passed
diff whitespace:   passed
```

Positive controls retain two distinct symbols of one object/segment and
verify their audit answers. Negative controls cover malformed positions,
ESI order, duplicate/conflicting assignments, unknown objects, low free
space and unchanged records/available bytes/pending duties on refusal.

**No CI run was polled or awaited.** No CI result, run identifier, root
workspace build, signed node/mobile transaction round trip, BLS
interoperability result, device run or performance measurement is claimed.
All new findings remain open pending the required evidence.

## Integration blockers and stop report for the affected subwork

### Presence: PR #77 / BLG-288 remains open

- Requirements: directive G-5 length-prefixes every hash input; section 7.8
  gives one presence signature message shared by node and phone.
- Evidence: PR #70 `src/validators/presence.rs::presence_message` writes the
  domain tag without its length. Mobile `presence_preimage` prefixes it.
  For chain 45261, window 11, Mobile, the node digest is
  `f14a3db552fa9b83037c7b5f0a4749ff05ea1390b436b40c8b071ef45d6ab7fd`,
  while the G-5/mobile digest is
  `26a5bec8b11098debd4eeffbe797638d295a08aa570cb3c176d9c5e41bfbb2a3`.
- Proposed resolution: the node owner uses the same G-5 encoding and the
  fixture in `tests/vectors/presence/v1/`. Move the primitive and types into
  the shared types delivery, then execute real BLS interoperability tests.
  This continuation does not edit another open package's locked node path.

### Release payload: PR #77 / BLG-290 remains open

- Conflicting contracts: directive 6.22.1 specifies a share list and new
  quota; PR #45 `src/storage/bud3/tx.rs::ReleaseShares` instead has one
  object, optional segment and `lower_quota_bytes`. The mobile duty still
  carries only process-local `ShareId` values.
- Evidence: local ids have no object/segment/ESI or declared-quota binding.
  After local deletion, the existing duty cannot reconstruct either chain
  contract. PR #45's payload cannot be copied as the canonical shared type
  without first reconciling it with the directive.
- Proposed resolution: the storage owner establishes the directive's chain
  share-list/new-quota contract; the shared-types delivery carries it; the
  mobile adapter emits that exact type and retains durable release intent
  until acknowledgement. Add a signed `StorageTxV3` round trip. No
  unauthenticated conversion of local ids into chain ids is introduced here.

### Proof batch: PR #77 / BLG-289 is only locally corrected

Object selection is carried from #85 and object retention is fixed here.
Shared proof types, serialization, authenticated finalized assignment roots
and a signed node acceptance test are still required. The in-memory store,
operator-key storage, UniFFI, libp2p mobile profile, light client and device
matrix are also not delivered by this slice. WP-11's formal dependencies
are not all merged. **WP-11 is not complete; the testnet is not certified.**
