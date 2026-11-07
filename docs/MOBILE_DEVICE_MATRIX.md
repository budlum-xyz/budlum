# Mobile Validator Device Matrix and Field Telemetry Specification (WP-37)

This document defines the Android hardware tiers, resource budgets, network-serving
rules, and JSONL telemetry format validated by `budlum::registry::rehearsal::analyze_mobile_field_logs`.

## 1. Supported Android Hardware Tiers

| Tier (`MobileDeviceTier`) | Reference Hardware Class | System RAM | Default Custody Quota | Peak Node RSS Ceiling | 24h Background Battery Ceiling |
|---|---|---:|---:|---:|---:|
| `entry4_gb` | ARMv8.2-A 8-core entry SoC, Android 12+ | 4 GB | 1 GiB | 256 MiB | 5.00% (`500 bps`) |
| `midrange8_gb` | ARMv8.2-A / ARMv9 midrange SoC, Android 13+ | 8 GB | 4 GiB | 256 MiB | 5.00% (`500 bps`) |
| `flagship12_gb` | ARMv9 flagship SoC, Android 14+ | 12 GB+ | 16 GiB | 256 MiB | 5.00% (`500 bps`) |

## 2. Mandatory Operating Invariants

1. **Non-slashing offline policy (`V-4`):** Going offline, losing Wi-Fi, or pausing on low
   battery transitions the Mobile validator to `Suspended` after `2` missed presence epochs
   with **zero** stake slash.
2. **Wi-Fi-only custody serving by default:** When `allow_cellular_opt_in == false`,
   `metered_bytes_served` MUST equal `0` (`SymbolProtocolError::CellularServingDisabled`).
3. **Key protection:** Signing keys reside in Android Keystore / StrongBox; the custody store
   uses bounded segment buffers (`<= 2` segments in RAM).

## 3. Field-Test JSONL Schema

Each participating device emits one JSON object per line (`MobileFieldSample`):

```json
{"device_id":"android-01","tier":"midrange8_gb","peak_rss_mib":124,"daily_battery_bps":215,"metered_bytes_served":0,"allow_cellular_opt_in":false,"audits_answered":96,"audits_missed":0,"rewards_credited_atoms":25000}
```

## 4. Required physical-device campaign (blocked on device access)

The following are candidate slots, not evidence of a completed campaign. Record
actual model, build, RAM and Android version before running; substitute devices
as needed to cover Android 10 through the current release. At least eight real
devices and five manufacturers are required, including a 4 GB device.

| Slot | Manufacturer | Candidate model | Required information | Result |
|---|---|---|---|---|
| 1 | Google | Pixel 4a | OS build, RAM | Pending |
| 2 | Google | Pixel 7a | OS build, RAM | Pending |
| 3 | Samsung | Galaxy A12 | OS build, RAM, 4 GB coverage | Pending |
| 4 | Samsung | Galaxy S23 | OS build, RAM | Pending |
| 5 | Xiaomi | Redmi Note 10 | OS build, RAM | Pending |
| 6 | Xiaomi | Redmi Note 12 | OS build, RAM | Pending |
| 7 | OnePlus | Nord | OS build, RAM | Pending |
| 8 | Motorola | Moto G Power | OS build, RAM | Pending |

For each device, record device and app versions, build identifiers, start and
end timestamps, charging state and battery readings. Run the validator for at
least 24 hours with the default Wi-Fi policy while capturing service lifecycle
and timeout events. Report any interruption or `onTimeout` invocation. Measure
battery consumption over the same uncharged interval and report the method,
percentage and any deviation from the 5% daily target. Exercise Wi-Fi and
cellular connectivity, including NAT and relay behavior; record network type,
connection attempts and outcomes. Include failures and missing measurements,
not just successful runs. Protect personal information before attaching logs.

Feed compatible telemetry to the Rust analyzer documented in
`mobile/tools/log-analyzer/README.md`. Its aggregate report is supplementary:
it does not independently prove uptime, absence of timeout events, battery
methodology, or connectivity. Attach raw evidence and reviewed results for each
slot. Do not adjust testnet defaults on the basis of synthetic fixtures.
