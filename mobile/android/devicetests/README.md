# Device tests (WP-37)

Field-test harness for the Android validator app (WP-36).

- The long-running device tests (`android_specialuse_service_runs_24h`,
  `android_battery_budget`, `mobile_nat_matrix`) are defined in
  `docs/MOBILE_DEVICE_MATRIX.md` and executed on the physical device matrix.
- Duty logs are collected from `noBackupFilesDir/duty.log` and analyzed with
  `mobile/tools/log-analyzer` (golden test:
  `device_log_analyzer_golden_reports`).
- Short (<= 60 min) runs go to a cloud device farm in CI; the emulator
  instrumentation job in `.github/workflows/mobile.yml` covers the
  non-physical acceptance tests once the UniFFI core binding lands (WP-36 2/N).
