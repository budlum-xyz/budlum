# The iOS opportunistic validator (WP-38)

Directive section 7.10. This is the iPhone application. It stores content
shares, answers custody audits, publishes a presence signal and earns a share
of the storage reward. It is one of the two phone classes; the Android
application is `mobile/android` (WP-36).

## What iOS allows, and what this app does about it

iOS does not allow a persistent background network connection. That is a
platform limit, not something the app works around, and nothing in this tree
claims otherwise. The app therefore splits its duty in two:

| State | What runs |
|---|---|
| App open | shares are taken, symbols are served, audits are answered, presence is published |
| App closed | a `BGProcessingTaskRequest` answers audits and publishes presence |

The background task sets both `requiresExternalPower` and
`requiresNetworkConnectivity`. Both are requirements, not preferences: an audit
answered over a metered path on a discharging phone is a worse outcome than an
audit answered late, and the seven-day suspension threshold of the class is
what absorbs the lateness.

The class is `MobileOpportunistic`: a 48-hour audit window, a custody quota
ceiling of 8 GiB and a seven-day suspension threshold (section 7.10 item 5).
It is not a user choice. The platform decides it.

## Layout

```
mobile/ios/
  Package.swift                     Swift package: the kit, the UI, the tests
  Scripts/check_class_parity.py     Rust/Swift class-parameter parity check
  Sources/BudlumValidatorKit/       everything the tests can reach
    ValidatorClass.swift            class and per-class parameters
    MobileCoreBinding.swift         the UniFFI surface, as a protocol
    PolicyEngine.swift              network, power, quota, symbol, thermal
    BackgroundDuty.swift            BGProcessingTask glue and the duty itself
    KeyVault.swift                  AES-256-GCM wrapping via the Keychain
    ShareStore.swift                one file per segment, under a quota
    DutyLog.swift                   the log mobile/tools/log-analyzer parses
  Sources/BudlumValidatorUI/        SwiftUI shell
  Tests/BudlumValidatorKitTests/    unit tests
```

## Where each value comes from

The Rust crate `crates/budlum-types` (WP-11, live on PR #44 and PR #91) is the
single definition of the validator class and its per-class numbers. The node,
the Android app and this app all read it.

`ValidatorClass.swift` carries a reference copy so this app builds and its
tests run before that crate is in the same branch. A copy left unchecked is how
a phone and a node come to disagree about a suspension threshold, so
`Scripts/check_class_parity.py` parses both sides and fails when they differ.
The `Mobile iOS` workflow runs it on every change. While the Rust crate is
absent the script reports green *with a written reason*; that is a skip, not a
pass, and the PR body records it.

## Building and testing

```sh
cd mobile/ios
swift test                                   # unit tests, no Xcode project needed
python3 Scripts/check_class_parity.py --repo ../..
```

The test target links only `BudlumValidatorKit`, so the tests never need
SwiftUI and run from a plain toolchain invocation.

## What is not here yet

| Missing | Lands with |
|---|---|
| The UniFFI binding over `budlum-mobile-core` | WP-36 2/N (`mobile/core`) |
| The Xcode project, TestFlight export | WP-38 2/N |
| On-device and simulator acceptance runs | WP-38 2/N, see `devicetests/` |
| Reproducible-build and F-Droid equivalents | WP-58 (Android only by design) |

Until the UniFFI module exists, `ProductionCore` in
`Sources/BudlumValidatorUI/BudlumValidatorApp.swift` holds a `FakeMobileCore`.
The fake is visible in the previews and in any build made before the binding
lands. Replacing it changes that one file and no other: the protocol is the
contract, and the adapter adds no call of its own.

## App Store

See `APP_STORE.md`. The short version: the app does not mine, and it says so
on the registration screen rather than in a footnote.
