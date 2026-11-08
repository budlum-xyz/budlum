# Budlum iOS opportunistic custody package

Swift package targeting iOS 16 and macOS 13 for the `MobileOpportunistic`
validator class. The package contains local custody/policy primitives and
unit tests; it is not yet a production validator application.

## Current behavior

- Registration class is fixed to `MobileOpportunistic` (tag 2).
- Custody quota is limited to 1...8 GiB, with a 4 GiB default.
- Share filenames must be canonical 32-byte segment IDs (64 hexadecimal
  characters); path separators and traversal are rejected.
- Shares persist under `Application Support/bud3`, are excluded from backup,
  and are read back from disk after process restart.
- Replacing a share excludes its previous size from quota accounting. Quota
  cannot be lowered below bytes already stored.
- Leave removes only canonical share files and preserves unknown files.
- Audit signing requires an injected `CustodyAuditSigning` implementation.
  Without it, background duty returns `auditSigningUnavailable`; raw shares
  are never used as audit proofs and no presence success is fabricated.
- `BackgroundProcessingConfig` requires both external power and network
  connectivity. This is configuration only, not evidence that iOS scheduled
  or executed a task.
- Secure Enclave wrapping has no software fallback and supports an in-memory
  wrap/unwrap round trip on hardware where the Enclave is available.

## Deliberately unavailable

The package currently has no production UniFFI/node adapter, chain
registration, presence publication, canonical audit transport,
`BGTaskScheduler` registration, or persistent Keychain reference management.
The registration control is disabled rather than toggling a local success
flag. No TestFlight, device, background-network, staking, reward, unbonding,
or App Store readiness is claimed.

## Verification

```bash
python3 mobile/ios/Scripts/check_class_parity.py --repo .
python3 -m unittest discover -s mobile/ios/Scripts -p 'test_*.py'
cd mobile/ios && swift test
```

The parity scripts use Python's standard library. Swift compilation and test
execution require a macOS/Swift runner. Secure Enclave tests skip explicitly
when hardware support is unavailable; a skip is not a hardware pass.
