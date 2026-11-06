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
