# Budlum Android validator (WP-36)

Kotlin + Jetpack Compose app for the Android mobile validator. Directive
section 7.9 of THE_BUDLUM_DIREKTIF. `minSdk` 29, `targetSdk` 36 (current Google
Play target API requirement since 2026-08-31).

Layout:

- `policy/` — working policy engine (network/power/thermal/quota/symbol).
  Wi-Fi-only by default; the thermal pause is not user-changeable.
- `keys/` — Android Keystore AES-256-GCM wrapping of the on-device operator
  and BLS keys (StrongBox when available).
- `storage/` — share store under `noBackupFilesDir/bud3/`, one file per
  segment (hex name), quota enforcement, 2 GiB low-space release rule.
- `service/` — `specialUse` foreground service with the persistent
  notification (stored bytes, last audit result, connection state).
- `work/` — 15-minute unmetered WorkManager job (audits/presence/shares while
  the service is stopped) and the policy-driven duty log.
- `boot/` — BOOT_COMPLETED receiver; falls back to a notification when the
  system refuses a background foreground-service start.
- `PLAY_DECLARATION.md` — the `specialUse` declaration text for Play Console.

The Rust mobile core (`mobile/core`, crate `budlum-mobile-core`, WP-11) is
bound through UniFFI in a later WP-36 PR. Build: `gradle assembleDebug
testDebugUnitTest` from this directory (CI: `.github/workflows/mobile.yml`).
