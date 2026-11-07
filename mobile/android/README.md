# Budlum Android validator (WP-36)

This is an **unconnected scaffold**, not a working validator. Do not use this
build to provide custody, answer audits, claim rewards, or join a testnet.
The WP-11 Rust mobile core, UniFFI bindings, onboarding, network transport,
foreground start flow, and durable on-chain release/repair protocol are not
connected. A successful WorkManager policy evaluation is not a passed audit.

The current scaffold contains:

- A policy engine for network, power, thermal state, and quota.
- Android Keystore AES-256-GCM wrapping, with StrongBox preferred when it is
  available. Device/emulator Keystore instrumentation has not yet been run.
- An interim local share store under `noBackupFilesDir/bud3/`. Its local delete
  results are not signed or acknowledged by the chain. It is not the durable
  WP-11 store and must not be used as evidence of successful release or repair.
- A `specialUse` service shell and a periodic policy worker. Neither is wired
  to validator duties. The boot receiver schedules work and requests a status
  notification, but never starts the foreground service from the background.
- A draft Play declaration. It must not be submitted until the implementation
  actually performs the declared duties and has been reviewed on devices.

The project targets Android API 36 and requires API 29 or later. Build with
`gradle assembleDebug testDebugUnitTest` from this directory. Instrumentation
requires an Android device or emulator: `gradle connectedDebugAndroidTest`.
The `mobile` GitHub workflow runs instrumentation only on manual dispatch.
