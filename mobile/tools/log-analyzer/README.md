# Budlum Mobile Validator Log Analyzer (WP-37)

`budlum-mobile-log-analyzer` parses tab-separated `key=value` telemetry emitted by
`mobile/android/devicetests/DeviceFieldHarness.kt` and generates deterministic,
integer-basis-point Markdown reports without floating-point arithmetic.

## Device Matrix Requirements

1. At least **8 physical Android devices** across at least **5 OEM families**:
   Google, Samsung, Xiaomi, one BBK family OEM (OnePlus / Oppo / Vivo / Realme),
   and Motorola.
2. OS coverage from **Android 10 (API 29)** through **Android 16 (API 36)**,
   including at least one device with **<= 4096 MiB RAM**.
3. Three field checks per run:
   - `android_specialuse_service_runs_24h`: >= 86,400 seconds continuous foreground
     execution under `foregroundServiceType="specialUse"` with `onTimeout == false`
     and zero missed storage audits.
   - `android_battery_budget`: <= 5.00% (`500` bps) 24-hour uncharged drain under
     the default Wi-Fi-only policy, or an explicit variance note.
   - `mobile_nat_matrix`: 100% connectivity across `home_nat`, `carrier_cgnat`, and
     `ipv6_only`, reporting Direct, DCUtR Hole-Punch, and CircuitRelayV2 percentages.

## Usage

```bash
cargo test --locked --manifest-path mobile/tools/log-analyzer/Cargo.toml
cargo run --release --locked --manifest-path mobile/tools/log-analyzer/Cargo.toml -- \
  --input field-run.tsv --output matrix-report.md --strict
```
