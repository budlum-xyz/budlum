# Budlum Android testnet app - disconnected validator

**This build is a testnet faucet and account-view companion, not a validator or wallet.**
The UI solves a bounded faucet anti-abuse challenge and requests a transfer to
an externally owned address. It also queries a user-supplied HTTPS RPC for a
node-reported balance. A faucet submission is not a confirmed transfer, and
an RPC response is not a verified account proof, finality or proof of ownership.
Do not enter a mnemonic; this app does not configure a public endpoint.

Validator enrollment, owner signing, Keystore-bound biometric/PIN authorization,
on-chain registration proofs, durable release acknowledgments, network duty
transport, and device-tested custody are not connected. The old public
biometric-token string is rejected for every owner operation. `ValidatorService`,
`DutyPeriodicWorker`, the Kotlin domain model, and the native UniFFI node refuse
to claim working validator duties. Local share storage and operator-key
wrapping are scaffolding only, not successful audits or rewards. The release
build is blocked until generated native bindings, a production gateway, and
verified onboarding exist.

The boot receiver may post an informational notification but cannot start a
foreground validator service or enqueue a working periodic duty job. The
[`specialUse` declaration](PLAY_DECLARATION.md) is a prospective specification,
not the behavior of this APK.

Target: Android API 36; minimum API 29. Build with
`gradle assembleDebug testDebugUnitTest lintDebug` from this directory on a
configured JDK 17 / Android SDK host. `gradle checkNativeValidatorRelease`
**must fail** until native bindings, the real gateway, owner authorization and
on-chain duty transport are integrated. The debug APK is disconnected; it
contains no `libbudlum_mobile_ffi.so` and must not be marketed as a validator.
Cloud backup and Android 12+ device transfer are disabled for private app data.
Instrumentation uses `gradle connectedDebugAndroidTest` on an emulator or
Android device. CI jobs and the field-device harness are defined in
[the mobile workflow](../../.github/workflows/mobile.yml) and
[`devicetests/DeviceFieldHarness.kt`](devicetests/DeviceFieldHarness.kt).
