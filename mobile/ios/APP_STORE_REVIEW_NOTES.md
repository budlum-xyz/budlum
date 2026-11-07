# App Store Review Disclosure Notes (`WP-38` / `R-22`)

## 1. Compliance with App Store Review Guideline 3.1.5(iii) - Zero On-Device Mining

* **Budlum Validator performs ZERO cryptocurrency mining or continuous proof-of-work hashing on the device.**
* Consensus participation in this iOS application is strictly limited to the **`MobileOpportunistic`** storage custody class:
  1. The app stores erasure-coded B.U.D. 3.0 data shares (`<= 8 GiB`, user-selected, excluded from iCloud backup via `URLResourceValues.isExcludedFromBackup = true`) inside `Application Support/bud3/`.
  2. During iOS-scheduled `BGProcessingTask` windows (`requiresExternalPower = true`, `requiresNetworkConnectivity = true`), the app opens a short-lived QUIC/TLS 1.3 session to verify custody of already-stored local file segments (`48h` audit window) and emit a single signed presence heartbeat.
  3. No background audio, location spoofing, silent push loops, or continuous CPU/GPU tasks are ever used. If iOS delays or skips background execution for up to 7 days (`168h`), the network automatically pauses (`Suspended`) the validator without slashing user funds.

## 2. Background Modes Justification (`processing`, `fetch`)

* **`xyz.budlum.validator.audit` (`BGProcessingTaskRequest`):** Runs only when the iPhone is connected to external power and Wi-Fi (`requiresExternalPower = true`, `requiresNetworkConnectivity = true`) to answer pending B.U.D. 3.0 custody challenges and sync newly assigned erasure-coded shares within the user's storage quota.
* **`xyz.budlum.validator.refresh` (`BGAppRefreshTaskRequest`):** Refreshes the user's light-client header summary and validator status badge.

## 3. Cryptography & User Privacy

* Post-quantum signing keys (`ML-DSA-87` owner wallet, `ML-DSA-65` operator duty key) and `BLS12-381` presence keys are wrapped using an Apple Secure Enclave P-256 key and stored in the iOS Keychain (`ThisDeviceOnly`).
* Zero third-party analytics, advertising, or tracking frameworks are linked (`PrivacyInfo` collects zero user identifiers).
