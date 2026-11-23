# Google Play `specialUse` Declaration & Platform Policy Verification

> **Draft only - do not submit with the current scaffold.** The mobile-core
> network binding, signed duty transport and durable release/acknowledgement
> protocol are not connected. Text below describes intended behavior, not a
> completed device/testnet capability.

## 1. Official Android & Google Play Policy Verification (Section 7.9.2 & 7.9.3)

### 1.1 Target API Level Requirement
- Verified against Google Play's target API level policy: newly submitted apps and
 updates must target **Android 15 (API level 35)** or higher, with **Android 16
 (API level 36)** active as the current SDK target (`compileSdk = 36`,
 `targetSdk = 36`, `minSdk = 29` Android 10).
- Under API 35+, `dataSync` and `mediaProcessing` foreground services are strictly
 capped at **6 hours within any rolling 24-hour window**, after which the platform
 invokes `Service.onTimeout(int, int)` and revokes foreground status. A mobile
 storage validator serving B.U.D. 3.0 erasure-coded shares and answering custody
 audits across 24-hour windows cannot use `dataSync`; it uses `specialUse` with
 the subtype property declared in `AndroidManifest.xml`.

### 1.2 `BOOT_COMPLETED` Broadcast Receiver & `specialUse` Restriction
- Verified against Android 15+ Behavior Changes ("Restrictions on `BOOT_COMPLETED`
 broadcast receivers launching foreground services"): apps targeting API 35+ are
 **prohibited** from calling `startForegroundService` for a `specialUse`
 foreground service from a `BOOT_COMPLETED` (or `LOCKED_BOOT_COMPLETED` /
 `MY_PACKAGE_REPLACED`) receiver; doing so throws
 `ForegroundServiceStartNotAllowedException`.
- Implementation rule enforced in `BootCompletedReceiver.kt` (matching Directive
 Section 7.9.3 item 5 & 6):
 1. The current build does not start a working `ValidatorService`. Any future
 start flow must require the app to be open in the foreground.
 2. On `ACTION_BOOT_COMPLETED`, `BootCompletedReceiver` **never** calls
 `startForegroundService`. It may post an informational notification. While
 onboarding remains disconnected, `DutyPeriodicWorker.enqueuePeriodic` refuses
 to schedule work, and an older installation's existing worker returns failure
 without deleting local shares or claiming a successful audit. The intended
 unmetered 15-minute duty schedule is **not operating** in this build.

## 2. Google Play Console `specialUse` Foreground Service Declaration

**Future release declaration, not current APK behavior.** The present UI
requests a faucet transfer and reads an RPC-reported balance. A Play declaration
for a validator must describe the behavior of its *shipped* build, including a
working wallet, signed registration, transport and custody duties.

- **Foreground service type:** `specialUse`
- **Manifest property (`android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE`):**
 `budlum_storage_validator: keeps peer-to-peer connections open to serve stored data shares and to answer storage audits of the Budlum network`
- **Play Console justification statement:**
 > Budlum Validator turns the user's phone into an opt-in peer-to-peer encrypted
 > storage custodian on the Budlum network. While the user explicitly starts
 > validator duty from the app's main screen, the `ValidatorService` maintains an
 > outbound QUIC/TCP libp2p connection (via Circuit Relay v2 / DCUtR) to serve
 > erasure-coded data symbols stored inside `noBackupFilesDir/bud3/` and to answer
 > periodic cryptographic storage audits. Neither `dataSync` (capped at 6 hours per
 > 24 hours on Android 15+) nor `connectedDevice` / `remoteMessaging` applies to a
 > user-controlled decentralized storage custodian. A persistent notification
 > continuously displays stored bytes, the latest audit outcome, and connection
 > status, and includes a one-tap Stop action. The faucet request performs a
 > bounded anti-abuse work challenge; it does not mine blocks.
- **Future reviewer walkthrough:** The review build must support wallet creation,
 signed registration, foreground duty start/stop, service notification, audited
 custody and a boot flow that does not auto-start a `specialUse` service. The
 current debug build has none of those actions; it only exposes the faucet
 request and RPC account view.

## 3. Key Custody & Privacy Status (not production guarantees)

- **Owner key (`ML-DSA-87`, 24 words):** real wallet creation, biometric/PIN
 authorization and signing are **not implemented**. All owner-key use, staking,
 unbonding and rotation requests are refused, including any caller-supplied token.
- **Operator (`ML-DSA-65`) & presence (`BLS12-381`) keys:** local AES-256-GCM
 wrapping code prefers StrongBox when available; this code alone is neither
 an operational duty signer nor a network audit. The unauthenticated local
 operator wrapper must never be used as owner authorization.
- **Telemetry:** no third-party analytics, ad, or crash-reporting SDK is
 included. `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` is not requested. Privacy
 assertions require device and dependency review before Play submission.
