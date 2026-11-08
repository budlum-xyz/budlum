# PR #91 mobile shared-types and FFI review

## Decision and boundary

Review source: `affa8b44ea2223291aec40114f2b0577f9fb660a` (PR #91, 28 commits
reported by GitHub, last commit 2026-11-06). The merge base with the integrated
branch was `dec2f9d0649360ac6282b449dcf564f278e1d41a`; 19 source commits were
unique from that base. Integration is a genuine merge with the reviewed source
head as second parent, not a squash or a completion claim. The source-date
condition permits closure after the pushed merge is verified ancestral; red or
pending source checks are not represented as repaired.

This is WP-11 2/N plus current-tree interoperability corrections. It does not
complete WP-11, WP-36, WP-37, WP-38 or WP-48. No testnet activation, mobile
application readiness, real device result or generated-binding build is claimed.

## What changed

- `ValidatorClass`, its timing/quota parameters, the presence preimage/message
  and `PresenceSignal` now have one Rust definition in `budlum-types`. The node
  validator module and presence registry re-export that class; the registry
  also uses the shared signal and digest instead of its former raw-concatenation
  layout. Existing `PresenceClass::Full` and `Mobile` node paths remain aliases.
- The Rust mobile core re-exports the shared definitions, enforces the 8-GiB
  opportunistic quota before mutation, mounts the node's PQ implementation for
  ML-DSA-65 operator keys and seals seeds through a context-bound `KeyVault`.
- The UniFFI crate exposes policy/status/relay/resume/leave and operator-key
  create/open operations. Pending/release counts use `u64`, the Kotlin package
  matches the current `network.budlum.validator` application, and poisoned
  mutexes fail stop instead of being recovered as supposedly consistent.
- The node registry, Rust mobile core and Android WorkManager all pin the same
  65-byte, four-field length-prefixed SHA3-256 vector (`26a5bec8...`). The old
  Android SHA-256/decimal-string layout was removed without a wrong-algorithm
  fallback. Negative windows are refused before duty/storage mutation.
- Shared timing conversion rejects zero slot/epoch parameters and overflow.
  Mobile domain scanning, PQ-context roots, Android Turkish-localization
  boundaries, CI target/binding jobs and locked standalone-crate commands were
  added or adapted. The device matrix now states 24/72/168-hour suspension
  thresholds rather than two missed epochs.

## Explicitly unfinished

- The FFI has no network submission or outbox-consumption API and does not
  expose operator-duty signing. Its outbox remains in memory and unbounded;
  `pending_duties` is a count, not backpressure. Presence BLS key management,
  libp2p and the mobile checkpoint verifier are not implemented here.
- Android/iOS still run separate application engines. Android's custody audit,
  reward and store path is not the canonical Rust core, and `KeystoreKeyVault`
  does not yet authenticate the operator public-key context as `PlatformVault`.
  The presence vector is an interoperability fix, not proof that the whole
  Kotlin engine is canonical. BLG-357 and BLG-360 remain open.
- `docs/LIGHT_CLIENT.md` documents the node reference trust model and explicitly
  says the mobile core has no checkpoint verifier. It is not mobile verifier
  evidence. Certificate-size figures are computed, not measured.
- Mounted PQ source, NIST-vector test source and UniFFI test source are present,
  but no Rust/Kotlin/Swift compiler or device was available. No passing test,
  formatting, Clippy, binding-generation, target-build or hardware result is
  claimed from file presence.

## Complete PR-path disposition

All 33 paths reported by GitHub are listed exactly once. "Current retained"
means the source delta was already represented or was not reapplied over newer
integrated work.

| Path | Disposition |
|---|---|
| `.github/workflows/ci.yml` | Adapted: five mobile-core targets, FFI generation/target checks, three deny/license matrix entries and locked standalone commands; current jobs retained. |
| `Cargo.lock` | Adapted minimally: `budlum-types` records its SHA3 dependency; existing lock retained. |
| `Cargo.toml` | Current retained: required shared-type/root dependencies were already present; no merge diff. |
| `crates/budlum-types/Cargo.lock` | Adapted with the new SHA3 dependency. |
| `crates/budlum-types/Cargo.toml` | Adapted: SHA3 added to the standalone shared-type crate. |
| `crates/budlum-types/src/class.rs` | Integrated, then changed to checked `Result` timing conversion and zero/overflow regressions. |
| `crates/budlum-types/src/lib.rs` | Adapted: class/presence modules and the new timing error are exported. |
| `crates/budlum-types/src/presence.rs` | Integrated: shared vector, signal, hint and window definitions. |
| `docs/LIGHT_CLIENT.md` | Integrated as trust-model documentation with its explicit no-mobile-verifier boundary. |
| `docs/audit/FINDINGS.md` | Rebased onto the canonical current ledger; BLG-350..362 have current dispositions, not stale source statuses. |
| `mobile/core/Cargo.lock` | Integrated for the newly standalone-locked mobile core and mounted PQ dependencies. |
| `mobile/core/Cargo.toml` | Adapted: shared types, node PQ mounts and exact dependencies; current package/lints retained. |
| `mobile/core/src/crypto.rs` | Integrated: path mounts of the node's `ctx`, `scheme` and `pq` sources. |
| `mobile/core/src/duty.rs` | Integrated: shared address conversion and pre-mutation class quota cap. |
| `mobile/core/src/keys.rs` | Integrated: zeroized ML-DSA-65 seed lifecycle and public-key-bound vault contract. |
| `mobile/core/src/lib.rs` | Adapted: new exports; broad crate-level test-lint suppression removed. |
| `mobile/core/src/presence.rs` | Integrated as shared-type re-exports plus the mobile-only resume duty. |
| `mobile/core/tests/duty_boundaries.rs` | Adapted: shared digest assertions and opportunistic-quota boundary. |
| `mobile/core/tests/operator_key.rs` | Integrated: sign/verify, wrong-context, wrong-seed, sealed-length and refusal regressions. |
| `mobile/ffi/Cargo.lock` | Integrated for pinned UniFFI and the standalone dependency graph. |
| `mobile/ffi/Cargo.toml` | Integrated: pinned UniFFI, generator feature and library crate types. |
| `mobile/ffi/src/lib.rs` | Adapted: current package API, u64 counts, poisoned-lock fail-stop and child-process canary. |
| `mobile/ffi/uniffi-bindgen.rs` | Integrated: generator entry point behind the CLI feature. |
| `mobile/ffi/uniffi.toml` | Adapted to `network.budlum.validator.core`; Swift module retained. |
| `src/ai/registry.rs` | Current retained; inherited source history caused no merge delta. |
| `src/ai/types.rs` | Current retained; inherited source history caused no merge delta. |
| `src/core/address.rs` | Current retained: the shared `Address` re-export was already integrated. |
| `src/crypto/domain_tags.rs` | Current inventory retained and presence-hint/mobile-audit registrations added; conflict markers removed. |
| `src/execution/executor.rs` | Current retained; the inherited source comment conflict was not applied. |
| `src/validators/mod.rs` | Adapted: class and opportunistic-cap re-exports replace the duplicate enum/constant. |
| `tests/vectors/presence/v1/README.md` | Updated to the actual node/Rust/Android vector usage and remaining Kotlin-adapter boundary. |
| `xtask/gates/src/gates/domain_tags.rs` | Integrated: mobile scan root and unlisted-mobile-tag canary. |
| `xtask/gates/src/gates/pq_ctx_is_bound.rs` | Integrated: mobile core/FFI production scan roots. |

Current-tree follow-ups outside those source paths are `src/registry/mod.rs`,
`src/registry/presence.rs`, `docs/MOBILE_DEVICE_MATRIX.md`, the Android bridge
and unit test, `xtask/gates/src/gates/tree_is_english.rs`, this review and the
canonical finding rows.

## Verification actually performed

- Pinned tree-sitter parsed 17 affected/new Rust files cleanly.
  `src/registry/presence.rs` has exactly the same two `&raw` parser errors as
  its `HEAD` baseline and no additional parser error; these are recorded, not
  hidden as a clean parse. The whole-tree scan covered 1,115 Rust files and
  retained 61 baseline error files with zero new error files.
- Python independently rebuilt the 65-byte presence preimage and matched both
  binary fixtures and `26a5bec8b11098debd4eeffbe797638d295a08aa570cb3c176d9c5e41bfbb2a3`.
  The Kotlin test containing the same vector was added but not executed.
- The CI YAML parsed with 40 jobs; both new jobs and all five mobile targets are
  present. A source-wide literal comparison found no new unregistered Rust
  domain tag. Known baseline inventory differences remain outside this claim.
- Integration audit passed 14/14 and all 14 injected-violation canaries failed
  as required. Staged diff checks passed and all eight changed TOML/lock files
  parsed. Static parsing, YAML and source scans are not a Rust/Kotlin/Swift
  build, test suite, formatter, Clippy run, UniFFI generation, physical-device
  rehearsal or production interoperability proof.
