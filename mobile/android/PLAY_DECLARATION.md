# Google Play Console Declaration & Platform Verification (`WP-36`)

## 1. Official Android Target SDK & `BOOT_COMPLETED` Verification (Section 7.9.2 item 2, Section 7.9.3 item 5)

* **Target API requirement (`targetSdk = 36`, `minSdk = 29`):** Google Play requires new apps and updates to target Android 15/16 (`API 35`/`36`). `mobile/android/app/build.gradle.kts` sets `minSdk = 29` (Android 10) and `targetSdk = 36` (`compileSdk = 36`).
* **`BOOT_COMPLETED` and `specialUse` Foreground Services:** Under Android 15 (`API 35`) and Android 16 (`API 36`) foreground-service launch restrictions, `BOOT_COMPLETED` broadcast receivers are prohibited from launching `dataSync`, `camera`, `mediaPlayback`, `phoneCall`, `mediaProjection`, and `microphone` foreground services, while `specialUse` remains an allowed exemption category when declared with `FOREGROUND_SERVICE_SPECIAL_USE` and `PROPERTY_SPECIAL_USE_FGS_SUBTYPE`.
* **Defense-in-depth fallback:** Because OEM firmware or future OS revisions can still throw `ForegroundServiceStartNotAllowedException`, `BootCompletedReceiver` always schedules the 15-minute `WorkManager` periodic job (`NetworkType.UNMETERED`) first and wraps `startForegroundService` in a `try / catch (ForegroundServiceStartNotAllowedException)` that posts a user-visible tap-to-resume notification while `WorkManager` continues answering custody audits and emitting presence signals.

## 2. `specialUse` Foreground Service Justification (`PROPERTY_SPECIAL_USE_FGS_SUBTYPE`)

* **Declared subtype:**
  `budlum_storage_validator: keeps peer-to-peer connections open to serve stored data shares and to answer storage audits of the Budlum network`
* **Why `dataSync` and `mediaProcessing` do not fit:** Android 15+ caps `dataSync` and `mediaProcessing` foreground services to 6 hours in any rolling 24-hour window, after which `Service.onTimeout` terminates foreground execution. A user-opted Mobile validator maintaining QUIC/relay peer-to-peer connectivity to serve B.U.D. 3.0 erasure-coded symbol shares and respond to custody audits operates continuously while Wi-Fi, battery, and thermal policies allow.
* **User control & visibility:**
  1. `ValidatorService` is started only when the user explicitly activates validation from the foreground UI (or resumes after reboot).
  2. A persistent notification continuously displays stored custody bytes, last custody audit result, and P2P relay/QUIC connection status, with a one-tap **Pause / Stop** action.
  3. No cryptocurrency proof-of-work mining is ever executed on the device, and no `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` permission is requested.
  4. Zero third-party analytics, ad, or crash-telemetry SDKs are bundled; diagnostic logs are exported strictly as a local file upon explicit user action.
