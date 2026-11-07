# Budlum iOS Opportunistic Mobile Validator (WP-38)

SwiftUI and `BGProcessingTask` opportunistic storage validator client targeting
`aarch64-apple-ios` and `aarch64-apple-ios-sim` (`iOS 16+`).

## Protocol Parameters (Directive Section 7.11)

- **Validator class:** `ValidatorClass::MobileOpportunistic` (`tag = 2`).
- **Background execution:** `BGProcessingTaskRequest` with
  `requiresExternalPower = true` and `requiresNetworkConnectivity = true`.
- **Custody quota:** `1 GiB` to `8 GiB` (`4 GiB` default); values above `8 GiB`
  are rejected.
- **Duty cadence:** `48-hour` storage audit response window, `24-hour` presence
  window, `0%` slashing, `7-day` suspension after missed window, reward weight
  capped at `<= 0.5x` of Android `ValidatorClass::Mobile`.
- **App Store Guideline 3.1.5(iii) (`R-22`):** explicit user-facing non-mining
  disclosure; zero Proof-of-Work computation runs on the device.

## Running Tests

```bash
cd mobile/ios
swift test
```
