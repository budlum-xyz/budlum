# Mobile Store Distribution & Reproducible Builds (WP-58)

This document specifies store compliance artifacts and deterministic binary
verification for `network.budlum.validator` across Google Play, Apple App Store,
F-Droid, and direct signed APK releases.

---

## 1. Google Play Store (`FOREGROUND_SERVICE_SPECIAL_USE`)

1. **Foreground Service Subtype Declaration:**
   - Declared in `mobile/android/app/src/main/AndroidManifest.xml` using
     `android:foregroundServiceType="specialUse"` with subtype property
     `android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE` (full reviewer text in
     `mobile/android/PLAY_DECLARATION.md`).
   - Service start is user-initiated from the foreground UI, displays a persistent
     notification with an instant **Pause** action, and transitions cleanly to a
     15-minute unmetered `WorkManager` job whenever paused or stopped by the OS.
2. **Forbidden Permissions & SDKs:**
   - `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` is never requested; OEM battery
     guidance (`OemBatteryGuide.kt`) links only to standard system settings.
   - Zero third-party analytics, crash-reporting, or advertising SDKs are linked;
     Play Data Safety declares no off-device telemetry collection.

---

## 2. Apple App Store (Background Execution Policy)

1. **Opportunistic Duty Model (`WP-38`):**
   - iOS forbids continuous third-party background daemons under App Store Review
     Guidelines 2.5.4 (except VoIP/audio/location, none of which Budlum claims).
   - `mobile/ios/` schedules `BGProcessingTaskRequest`
     (`requiresExternalPower = true`, `requiresNetworkConnectivity = true`) and
     answers audits opportunistically when woken on charger + Wi-Fi.
   - App Review notes state explicitly that Budlum iOS is an opportunistic
     custodian/presence participant whose consensus weight requires zero
     continuous background execution.

---

## 3. F-Droid & Reproducible Direct APK Distribution

1. **Build Recipe (`mobile/android/fdroid/network.budlum.validator.yml`):**
   - Pins Rust `1.97.1`, Android NDK `27.2.12479018`, `SOURCE_DATE_EPOCH=1700000000`,
     `CARGO_INCREMENTAL=0`, and `--remap-path-prefix` so build-host paths never
     leak into `.so` sections.
2. **Gradle Archive Determinism (`mobile/android/app/build.gradle.kts`):**
   - `dependenciesInfo { includeInApk = false; includeInBundle = false }` removes
     Google Play's encrypted signing block so F-Droid's independent build matches
     the upstream unsigned APK byte-for-byte.
   - `AbstractArchiveTask` enforces `isPreserveFileTimestamps = false` and
     `isReproducibleFileOrder = true`.
   - `packaging.jniLibs.useLegacyPackaging = false` ensures deterministic 16 KiB
     page-aligned uncompressed `.so` storage.
3. **Verification (`android_reproducible_build_matches`):**
   - Exercised by `MobileValidatorUnitTest.android_reproducible_build_matches` in
     CI (in keeping with the `no-new-shell-gates` policy against shell scripts).
   - Direct APK releases publish `<apk>.sha256` alongside a detached composite
     (`ML-DSA-87 + Ed25519`) release signature verified prior to sideload updates.
