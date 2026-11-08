# App Store review boundary

## Current package status

This package is **not submission-ready**. It contains local custody storage,
quota enforcement, localization, and unit tests. Registration is disabled
until the production mobile-core adapter exists. No chain registration,
unbonding, reward claim, presence publication, or completed network audit is
represented as a current capability.

## Mining and background execution

The code contains no Proof-of-Work mining, continuous background connection,
background audio, location, advertising, or analytics path. The intended
opportunistic duty is storage custody only. `BackgroundProcessingConfig`
requires external power and network connectivity, but there is currently no
`BGTaskScheduler` registration and therefore no claim that iOS executes an
audit or refresh task.

The audit task identifier is declared for the future scheduler adapter. The
unused refresh task and Face ID usage declaration have been removed rather
than requesting capabilities the current code does not implement.

## Data and keys

Canonical share files are excluded from backup and stored below the app's
`bud3` directory. Segment IDs are validated before constructing paths.
Unknown files are not deleted by Leave. Audit signing fails closed when no
production signer is connected; raw share bytes are not audit proofs.

The Secure Enclave wrapper requires hardware support and has no software
fallback. It currently provides runtime ECDH/AES-GCM wrapping only. Persistent
Keychain references, owner-wallet biometric access control, ML-DSA/BLS
signing, QUIC transport, and presence heartbeat publication must not be listed
as implemented in a review submission until their production code and device
evidence exist.

## Evidence required before submission

- macOS/Swift build and complete test log;
- physical-device Secure Enclave and Keychain persistence tests;
- background-task scheduling/expiration and locked-device audit tests;
- canonical node interop for registration, audit, presence, and unbonding;
- privacy manifest and final capability/permission review.
