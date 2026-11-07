# Android validator continuation review

## Scope and canonical-tree decision

PR #97 continued the older `dev.budlum.validator` Android scaffold from #92.
The integration branch already has a different `network.budlum.validator`
application and newer Kotlin 2.0.21/Compose configuration. The old package tree,
version catalog and superseded Gradle files were therefore not restored.
Source behavior was reviewed and adapted into the current classes instead.

This is still an unconnected scaffold. The Rust mobile-core UniFFI binding,
network duty transport, durable release intent/acknowledgement and light client
are not delivered. Local policy or storage tests do not demonstrate a connected
validator, an on-chain release, a device field result or testnet readiness.

## Source-to-current mapping

| PR #97 behavior | Integration result |
|---|---|
| Repair policy/test compilation and add the Kotlin 2 Compose plugin | The canonical tree already used Kotlin/Compose 2.0.21; those newer manifests were preserved. The actual current JVM suite was compiled again during integration. |
| Stop quota release as soon as usage fits | Retained and pinned: oldest recognized files are released in timestamp/name order only while usage exceeds quota. A requested policy is refused if local usage remains above its quota. |
| Protect admission and quota operations | Current `ShareCustodyDirectory` uses a process-wide lock, checked accounting, duplicate/no-follow refusal, a temporary synced file and atomic no-replace hard-link publication. Unknown files and symlinks fail snapshots closed instead of being read or deleted. |
| Preserve the free-space floor | Both the engine's host-measured budget and the store's filesystem provider reject a share that would cross 2 GiB. Exact-floor admission is allowed. |
| Fail closed on missing/conflicting wrapping keys | `unwrapKey` now requires an existing provider key and never creates replacement material. The Android provider rejects an alias occupied by a non-secret-key entry. |
| Fall back only when StrongBox is explicitly unavailable | `AndroidKeystoreWrappingKeyProvider` tries StrongBox first and retries an ordinary Keystore key only for `StrongBoxUnavailableException`; other failures propagate. |
| Use real device Keystore checks | Production UI/worker construction now uses the Android Keystore provider rather than the JVM in-memory test provider. Instrumentation checks non-exportability, round trips, tamper refusal and concurrent lookup. |
| Respect foreground start rules | The canonical receiver already avoided background service starts. It now also checks notification permission/enabled state, catches revocation races and opens the UI on notification tap. Instrumentation pins zero service starts. |
| Fail closed when mobile usage is unknown | Metered duty ticks require a non-negative usage below the configured cap when not on unmetered Wi-Fi. Unknown usage no longer means zero. Unmetered Wi-Fi remains independent of the mobile meter. |
| Use the emulator action's `script` input | The manual instrumentation job uses `script` and commit-pinned actions. Wiring is not an emulator pass. |

The source's historical compiler errors and quota failure are evidence about its
old package, not a fresh failure of the current package. The old source tests
were not copied wholesale because their APIs do not exist in the canonical app.

## Executed integration evidence

The pure-JVM sources used by `.github/workflows/mobile.yml` were compiled with
**Kotlin 2.0.21**, `-jvm-target 17`, and executed on **Temurin 21.0.13**. Tools
came from npm registry tarballs and were unpacked outside Git without running
package install scripts. The first run exposed test fixtures that mixed a fake
host-space budget with the sandbox's real filesystem budget; those fixtures now
inject free space explicitly, while the dedicated store test retains physical
floor behavior. Final result:

```text
13/13 JVM test entry points passed
ALL ANDROID VALIDATOR TESTS PASSED
```

The tests cover policy defaults, thermal lock, wrapping round trips, missing-key
refusal, StrongBox fallback controls, atomic/fail-close share admission,
concurrent quota admission, metered-data fail-close, leave/low-space behavior,
onboarding and worker state, and reproducible packaging checks.

Tree-sitter accepted every current Kotlin file, including the Android-only
provider and both instrumentation suites. XML/YAML/static repository checks are
run separately. No local Android SDK, Android Runtime, Gradle dependency
resolution, APK build, emulator, hardware Keystore, StrongBox or real-device
result is claimed. JDK 17 execution and the pinned manual emulator job remain
external validation requirements.
