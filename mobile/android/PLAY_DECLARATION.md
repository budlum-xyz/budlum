# Google Play `specialUse` Declaration & Platform Policy Verification (WP-36)

> **Draft only — do not submit with the current scaffold.** The mobile-core
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
  **prohibited** from calling `startForegroundService()` for a `specialUse`
  foreground service from a `BOOT_COMPLETED` (or `LOCKED_BOOT_COMPLETED` /
  `MY_PACKAGE_REPLACED`) receiver; doing so throws
  `ForegroundServiceStartNotAllowedException`.
- Implementation rule enforced in `BootCompletedReceiver.kt` (matching Directive
  Section 7.9.3 item 5 & 6):
  1. `ValidatorService` is started **exclusively** while the user has the app open
     in the foreground.
  2. On `ACTION_BOOT_COMPLETED`, `BootCompletedReceiver` **never** calls
     `startForegroundService()`. Instead, it posts a tap-to-resume status
     notification so the user can reopen the app to restore persistent foreground
     serving, and immediately schedules `DutyPeriodicWorker` via `WorkManager`
     (15-minute interval, `NetworkType.UNMETERED` constraint). The worker is a
     local policy/storage shell only; no background audit or presence success is
     implied until the network duty binding exists.

## 2. Google Play Console `specialUse` Foreground Service Declaration

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
  > status, and includes a one-tap Stop action. No cryptocurrency PoW mining is
  > performed on the device.
- **Reviewer walkthrough note:**
  1. Launch **Budlum Validator** -> Create a 24-word wallet -> Tap **Request Testnet
     Faucet (100 BUD)** -> Tap **Register Mobile Validator (10 BUD)**.
  2. Tap **Start Validator Duty** while the app is in the foreground. Observe the
     persistent notification showing stored bytes, last audit result, and relay
     connection state.
  3. Tap **Pause** or reboot the emulator: observe that `BOOT_COMPLETED` does not
     auto-launch the foreground service, posts a resume notification instead, and
     continues 15-minute unmetered `WorkManager` audit/presence maintenance.

## 3. Key Custody & Privacy Guarantees

- **Owner key (`ML-DSA-87`, 24 words):** unlocks only with explicit user biometric
  or device PIN authentication for staking, unbonding, or `RotateOperatorKey`
  recovery (`R-16`).
- **Operator (`ML-DSA-65`) & presence (`BLS12-381`) keys:** wrapped at rest under
  an Android Keystore `AES-256-GCM` hardware key (StrongBox preferred when present)
  with `setUserAuthenticationRequired(false)` and `setUnlockedDeviceRequired(false)`
  so background `WorkManager` audits succeed; an attacker with physical access could
  sign duty messages only, never move staked or liquid BUD.
- **Zero telemetry:** no third-party analytics, ad, or crash-reporting SDK is
  included. Crash logs are exported strictly as local files upon explicit user
  confirmation. `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` is never requested.
