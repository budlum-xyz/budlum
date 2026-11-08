# Embedded store choice (WP-11)

The mobile core keeps custody shares under `noBackupFilesDir/bud3/`. The
directory is an embedded store. This file records the choice criteria.
It does not record a winner: no measurement has been run yet, and an
unmeasured number is not written (directive section 0.5).

## Criteria

1. Crash safety: a kill in the middle of an accept or a release must not
   lose the directory invariant (every file is a whole share, every
   recorded id has a file).
2. Pure Rust: the crate must build for `aarch64-linux-android`,
   `x86_64-linux-android`, `armv7-linux-androideabi`, `aarch64-apple-ios`
   and `aarch64-apple-ios-sim` without a C toolchain inside the crate.
3. Licence: compatible with `LicenseRef-PolyForm-Shield-1.0.0` at the
   repository root. The store crate's own licence must be OSI-approved
   or public domain.
4. Binary size: the store must not dominate the mobile core binary. The
   comparison is measured on the same target, same profile, and written
   here when the measurement exists.

## Candidates

- `redb`
- a flat file per share plus an append-only log of ids

`sled` is not a candidate (section 7.9.5: maintenance status).

## Current code

This slice (WP-11, 2/N) keeps shares in memory (`ShareStore`). The host
will mount a crash-safe backend once the measurement in this file names
one. Until then no production phone build ships.
