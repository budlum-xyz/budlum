# Mobile device matrix and field test (WP-37)

Directive 7.9.11 and 7.12. This document defines the device matrix, the field
test instructions (a human step: the Budlum team and volunteers run the
devices and attach logs to the PR), and how the logs are analyzed.

## Device matrix

At least 8 real devices:

| Slot | Manufacturer group | Example | Android version | RAM |
|---|---|---|---|---|
| 1 | Google | Pixel 6/7/8 | current (Android 16) | 8 GB |
| 2 | Google | Pixel 5a | Android 13 | 6 GB |
| 3 | Samsung | Galaxy A54 | Android 14 | 6 GB |
| 4 | Xiaomi | Redmi Note 12 | Android 13 | 4 GB (the required 4 GB device) |
| 5 | BBK group | Oppo Reno / Vivo V27 / Realme GT | Android 14 | 8 GB |
| 6 | Motorola | Moto G Power | Android 12 | 4 GB |
| 7 | Samsung | Galaxy S21 | Android 11 | 8 GB |
| 8 | Google | Pixel 4a | Android 10 (minimum, minSdk 29) | 6 GB |

Rules: at least 5 manufacturers, Android 10 through the current release, at
least one 4 GB RAM device.

## Tests

Device tests (run on each matrix device, logs attached to the PR):

- `android_specialuse_service_runs_24h` — the `specialUse` foreground service
  stays in the foreground for 24 h; `onTimeout` is never called.
- `android_battery_budget` — battery drain on an unplugged day under the
  default policy; target at most 5% per day, or a documented deviation.
- `mobile_nat_matrix` — home NAT, carrier NAT (CGNAT) and IPv6: connection is
  established in every network type; direct / hole-punched / relay ratios are
  written to the report.

Short tests (up to 60 minutes) run in a cloud device farm in CI. The 24-hour,
battery and NAT tests need real devices and are executed by the Budlum team;
while waiting, the package is marked blocked and the agent moves to the next
ready package (directive 15.1 item 9).

## Running the field test (human step)

1. Install the signed APK from GitHub Releases on each matrix device.
2. Complete onboarding and registration (10 BUD stake via the in-app faucet).
3. Leave the app running for 24 h on each device; keep the default policy.
4. Pull the duty log from the device: `adb pull
   /sdcard/Android/data/dev.budlum.validator/files/duty.log` (or the
   noBackupFilesDir equivalent via the debug build).
5. Analyze: `budlum-mobile-log-analyzer duty.log > report.txt`.
6. Attach `report.txt` and the raw log to the PR.

## Analyzer

`mobile/tools/log-analyzer/` (Rust, std-only, standalone workspace) turns a
duty log into a deterministic golden report. Its golden test is
`device_log_analyzer_golden_reports`.

## TESTNET-DEFAULT tuning

After the field results, the mobile audit window, presence window and
suspension threshold defaults are adjusted with measurement evidence attached
in the PR (card item 5).
