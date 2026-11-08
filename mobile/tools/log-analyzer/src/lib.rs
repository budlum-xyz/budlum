//! Deterministic field-log analyzer for the Budlum mobile validator matrix.
//!
//! All rates and battery budgets are computed in integer basis points (1 bp = 0.01%)
//! so reports stay bit-for-bit reproducible across architectures without floating point.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

/// Minimum foreground duration for the 24-hour service soak test (seconds).
pub const TARGET_FOREGROUND_SECONDS: u64 = 86_400;

/// Uncharged 24-hour battery budget in basis points (500 bps = 5.00%).
pub const BATTERY_BUDGET_BPS: u32 = 500;

/// Minimum real devices required in the  matrix.
pub const MIN_MATRIX_DEVICES: usize = 8;

/// Minimum distinct OEM groups required in the  matrix.
pub const MIN_MATRIX_OEMS: usize = 5;

/// Minimum Android SDK level supported by the mobile validator (Android 10).
pub const MIN_ANDROID_API: u32 = 29;

/// Maximum RAM in MiB for the low-memory device requirement (4 GiB).
pub const LOW_RAM_CEILING_MIB: u32 = 4_096;

/// Canonical OEM family normalized from manufacturer strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OemGroup {
    Google,
    Samsung,
    Xiaomi,
    Bbk,
    Motorola,
    Other,
}

impl OemGroup {
    /// Classify a device manufacturer string into its OEM policy family.
    #[must_use]
    pub fn from_manufacturer(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "google" => Self::Google,
            "samsung" => Self::Samsung,
            "xiaomi" | "redmi" | "poco" => Self::Xiaomi,
            "oneplus" | "oppo" | "vivo" | "realme" | "iqoo" | "bbk" => Self::Bbk,
            "motorola" | "lenovo" => Self::Motorola,
            _ => Self::Other,
        }
    }

    /// Stable label rendered into Markdown reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Google => "Google",
            Self::Samsung => "Samsung",
            Self::Xiaomi => "Xiaomi",
            Self::Bbk => "BBK",
            Self::Motorola => "Motorola",
            Self::Other => "Other",
        }
    }
}

/// Network environment under test in `mobile_nat_matrix`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NatEnvironment {
    HomeNat,
    CarrierCgnat,
    Ipv6Only,
}

impl NatEnvironment {
    /// Parse the wire token emitted by the device harness.
    ///
    /// # Errors
    ///
    /// Returns an error if the token is unknown.
    pub fn parse(token: &str) -> Result<Self, String> {
        match token.trim() {
            "home_nat" => Ok(Self::HomeNat),
            "carrier_cgnat" => Ok(Self::CarrierCgnat),
            "ipv6_only" => Ok(Self::Ipv6Only),
            other => Err(format!("unknown NAT environment `{other}`")),
        }
    }

    /// Stable label rendered into Markdown reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HomeNat => "home_nat",
            Self::CarrierCgnat => "carrier_cgnat",
            Self::Ipv6Only => "ipv6_only",
        }
    }
}

/// Transport path established for a NAT probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NatPath {
    Direct,
    HolePunch,
    Relay,
    Failed,
}

impl NatPath {
    /// Parse the wire token emitted by the device harness.
    ///
    /// # Errors
    ///
    /// Returns an error if the token is unknown.
    pub fn parse(token: &str) -> Result<Self, String> {
        match token.trim() {
            "direct" => Ok(Self::Direct),
            "hole_punch" => Ok(Self::HolePunch),
            "relay" => Ok(Self::Relay),
            "failed" => Ok(Self::Failed),
            other => Err(format!("unknown NAT path `{other}`")),
        }
    }
}

/// Hardware and OS metadata for one matrix device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceProfile {
    pub device_id: String,
    pub manufacturer: String,
    pub model: String,
    pub android_api: u32,
    pub ram_mib: u32,
}

/// Result of a 24-hour foreground service run (`android_specialuse_service_runs_24h`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSoakRecord {
    pub device_id: String,
    pub duration_secs: u64,
    pub on_timeout_called: bool,
    pub audits_answered: u32,
    pub audits_missed: u32,
}

impl ServiceSoakRecord {
    /// True when the `specialUse` service ran at least 24 hours without `onTimeout`.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.duration_secs >= TARGET_FOREGROUND_SECONDS
            && !self.on_timeout_called
            && self.audits_missed == 0
    }
}

/// Result of a 24-hour uncharged battery measurement (`android_battery_budget`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatteryRecord {
    pub device_id: String,
    /// Drain in basis points (e.g. 420 = 4.20%).
    pub drain_bps: u32,
    /// Required explanation when `drain_bps > BATTERY_BUDGET_BPS`.
    pub variance_note: Option<String>,
}

impl BatteryRecord {
    /// True when within the 5.00% budget or carrying a non-empty variance note.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.drain_bps <= BATTERY_BUDGET_BPS
            || self
                .variance_note
                .as_ref()
                .is_some_and(|note| !note.trim().is_empty())
    }
}

/// One connectivity probe from `mobile_nat_matrix`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatProbeRecord {
    pub device_id: String,
    pub environment: NatEnvironment,
    pub path: NatPath,
}

/// Parsed collection of field-test records across the device matrix.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FieldLogBundle {
    pub devices: BTreeMap<String, DeviceProfile>,
    pub soak_runs: Vec<ServiceSoakRecord>,
    pub battery_runs: Vec<BatteryRecord>,
    pub nat_probes: Vec<NatProbeRecord>,
}

/// Aggregated NAT statistics for one network environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatEnvSummary {
    pub total: u32,
    pub connected: u32,
    pub direct_bps: u32,
    pub hole_punch_bps: u32,
    pub relay_bps: u32,
}

/// Summary verdict computed from a [`FieldLogBundle`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixSummary {
    pub device_count: usize,
    pub oem_groups: BTreeSet<OemGroup>,
    pub has_low_ram_device: bool,
    pub min_api_observed: Option<u32>,
    pub matrix_criteria_met: bool,
    pub soak_all_passed: bool,
    pub battery_all_passed: bool,
    pub nat_by_env: BTreeMap<NatEnvironment, NatEnvSummary>,
    pub nat_all_connected: bool,
}

impl MatrixSummary {
    /// Overall  pass verdict.
    #[must_use]
    pub const fn overall_passed(&self) -> bool {
        self.matrix_criteria_met
            && self.soak_all_passed
            && self.battery_all_passed
            && self.nat_all_connected
    }
}

fn parse_kv_line(line: &str) -> Result<BTreeMap<String, String>, String> {
    let mut map = BTreeMap::new();
    for part in line.split('\t') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (k, v) = trimmed
            .split_once('=')
            .ok_or_else(|| format!("malformed field `{trimmed}` (expected key=value)"))?;
        if map.insert(k.trim().to_string(), v.trim().to_string()).is_some() {
            return Err(format!("duplicate key `{k}` in log record"));
        }
    }
    Ok(map)
}

fn req<'a>(
    map: &'a BTreeMap<String, String>,
    key: &str,
    line_no: usize,
) -> Result<&'a str, String> {
    map.get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("line {line_no}: missing required key `{key}`"))
}

fn parse_device_record(
    fields: &BTreeMap<String, String>,
    line_no: usize,
) -> Result<DeviceProfile, String> {
    let device_id = req(fields, "id", line_no)?.to_string();
    let manufacturer = req(fields, "oem", line_no)?.to_string();
    let model = req(fields, "model", line_no)?.to_string();
    let android_api: u32 = req(fields, "api", line_no)?
        .parse()
        .map_err(|_| format!("line {line_no}: invalid api integer"))?;
    let ram_mib: u32 = req(fields, "ram_mib", line_no)?
        .parse()
        .map_err(|_| format!("line {line_no}: invalid ram_mib integer"))?;
    if android_api < MIN_ANDROID_API {
        return Err(format!(
            "line {line_no}: Android API {android_api} below minSdk {MIN_ANDROID_API}"
        ));
    }
    Ok(DeviceProfile {
        device_id,
        manufacturer,
        model,
        android_api,
        ram_mib,
    })
}

fn parse_soak_record(
    fields: &BTreeMap<String, String>,
    line_no: usize,
) -> Result<ServiceSoakRecord, String> {
    let device_id = req(fields, "id", line_no)?.to_string();
    let duration_secs: u64 = req(fields, "duration_secs", line_no)?
        .parse()
        .map_err(|_| format!("line {line_no}: invalid duration_secs"))?;
    let on_timeout_called = match req(fields, "on_timeout", line_no)? {
        "true" => true,
        "false" => false,
        other => {
            return Err(format!("line {line_no}: invalid boolean `{other}`"));
        }
    };
    let audits_answered: u32 = req(fields, "audits_ok", line_no)?
        .parse()
        .map_err(|_| format!("line {line_no}: invalid audits_ok"))?;
    let audits_missed: u32 = req(fields, "audits_missed", line_no)?
        .parse()
        .map_err(|_| format!("line {line_no}: invalid audits_missed"))?;
    Ok(ServiceSoakRecord {
        device_id,
        duration_secs,
        on_timeout_called,
        audits_answered,
        audits_missed,
    })
}

fn parse_battery_record(
    fields: &BTreeMap<String, String>,
    line_no: usize,
) -> Result<BatteryRecord, String> {
    let device_id = req(fields, "id", line_no)?.to_string();
    let drain_bps: u32 = req(fields, "drain_bps", line_no)?
        .parse()
        .map_err(|_| format!("line {line_no}: invalid drain_bps"))?;
    let variance_note = fields
        .get("note")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    Ok(BatteryRecord {
        device_id,
        drain_bps,
        variance_note,
    })
}

fn parse_nat_record(
    fields: &BTreeMap<String, String>,
    line_no: usize,
) -> Result<NatProbeRecord, String> {
    let device_id = req(fields, "id", line_no)?.to_string();
    let environment = NatEnvironment::parse(req(fields, "env", line_no)?)
        .map_err(|e| format!("line {line_no}: {e}"))?;
    let path = NatPath::parse(req(fields, "path", line_no)?)
        .map_err(|e| format!("line {line_no}: {e}"))?;
    Ok(NatProbeRecord {
        device_id,
        environment,
        path,
    })
}

/// Parse tab-separated `key=value` log lines produced by `DeviceFieldHarness`.
///
/// # Errors
///
/// Returns a descriptive error naming the 1-based line number on malformed input.
pub fn parse_field_log(input: &str) -> Result<FieldLogBundle, String> {
    let mut bundle = FieldLogBundle::default();
    for (idx, raw) in input.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let fields = parse_kv_line(trimmed).map_err(|e| format!("line {line_no}: {e}"))?;
        match req(&fields, "kind", line_no)? {
            "device" => {
                let dev = parse_device_record(&fields, line_no)?;
                bundle.devices.insert(dev.device_id.clone(), dev);
            }
            "soak24h" => bundle.soak_runs.push(parse_soak_record(&fields, line_no)?),
            "battery" => {
                bundle
                    .battery_runs
                    .push(parse_battery_record(&fields, line_no)?);
            }
            "nat" => bundle.nat_probes.push(parse_nat_record(&fields, line_no)?),
            other => {
                return Err(format!("line {line_no}: unknown record kind `{other}`"));
            }
        }
    }
    Ok(bundle)
}

fn ratio_bps(part: u32, whole: u32) -> u32 {
    if whole == 0 {
        return 0;
    }
    let scaled = u64::from(part).saturating_mul(10_000) / u64::from(whole);
    u32::try_from(scaled).unwrap_or(10_000)
}

fn count_path(probes: &[&NatProbeRecord], target: NatPath) -> u32 {
    let n = probes.iter().filter(|p| p.path == target).count();
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn summarize_nat_env(probes: &[NatProbeRecord], env: NatEnvironment) -> NatEnvSummary {
    let matching: Vec<&NatProbeRecord> = probes.iter().filter(|p| p.environment == env).collect();
    let total = u32::try_from(matching.len()).unwrap_or(u32::MAX);
    let direct = count_path(&matching, NatPath::Direct);
    let hole = count_path(&matching, NatPath::HolePunch);
    let relay = count_path(&matching, NatPath::Relay);
    let connected = direct.saturating_add(hole).saturating_add(relay);
    NatEnvSummary {
        total,
        connected,
        direct_bps: ratio_bps(direct, total),
        hole_punch_bps: ratio_bps(hole, total),
        relay_bps: ratio_bps(relay, total),
    }
}

/// Evaluate matrix coverage, 24h soak stability, battery budget, and NAT rates.
#[must_use]
pub fn evaluate_bundle(bundle: &FieldLogBundle) -> MatrixSummary {
    let device_count = bundle.devices.len();
    let mut oem_groups = BTreeSet::new();
    let mut has_low_ram_device = false;
    let mut min_api_observed: Option<u32> = None;

    for dev in bundle.devices.values() {
        let group = OemGroup::from_manufacturer(&dev.manufacturer);
        if group != OemGroup::Other {
            oem_groups.insert(group);
        }
        if dev.ram_mib <= LOW_RAM_CEILING_MIB {
            has_low_ram_device = true;
        }
        let next_min = min_api_observed.map_or(dev.android_api, |m| m.min(dev.android_api));
        min_api_observed = Some(next_min);
    }

    let required_oems = [
        OemGroup::Google,
        OemGroup::Samsung,
        OemGroup::Xiaomi,
        OemGroup::Bbk,
        OemGroup::Motorola,
    ];
    let has_required_oems = required_oems.iter().all(|g| oem_groups.contains(g));
    let matrix_criteria_met = device_count >= MIN_MATRIX_DEVICES
        && oem_groups.len() >= MIN_MATRIX_OEMS
        && has_required_oems
        && has_low_ram_device
        && min_api_observed.is_some_and(|api| api >= MIN_ANDROID_API);

    let soak_ids: BTreeSet<&str> = bundle.soak_runs.iter().map(|r| r.device_id.as_str()).collect();
    let soak_all_passed = !bundle.devices.is_empty()
        && bundle.devices.keys().all(|id| soak_ids.contains(id.as_str()))
        && bundle.soak_runs.iter().all(ServiceSoakRecord::passed);

    let bat_ids: BTreeSet<&str> = bundle
        .battery_runs
        .iter()
        .map(|r| r.device_id.as_str())
        .collect();
    let battery_all_passed = !bundle.devices.is_empty()
        && bundle.devices.keys().all(|id| bat_ids.contains(id.as_str()))
        && bundle.battery_runs.iter().all(BatteryRecord::passed);

    let mut nat_by_env = BTreeMap::new();
    for env in [
        NatEnvironment::HomeNat,
        NatEnvironment::CarrierCgnat,
        NatEnvironment::Ipv6Only,
    ] {
        nat_by_env.insert(env, summarize_nat_env(&bundle.nat_probes, env));
    }

    let nat_all_connected = nat_by_env
        .values()
        .all(|summary| summary.total > 0 && summary.connected == summary.total);

    MatrixSummary {
        device_count,
        oem_groups,
        has_low_ram_device,
        min_api_observed,
        matrix_criteria_met,
        soak_all_passed,
        battery_all_passed,
        nat_by_env,
        nat_all_connected,
    }
}

const fn pass_label(ok: bool) -> &'static str {
    if ok {
        "PASS"
    } else {
        "FAIL"
    }
}

fn format_bps_percent(bps: u32) -> String {
    format!("{}.{:02}%", bps / 100, bps % 100)
}

/// Render a deterministic Markdown report from a parsed bundle and its summary.
#[must_use]
pub fn render_markdown_report(bundle: &FieldLogBundle, summary: &MatrixSummary) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Mobile Validator Field Matrix Report\n");
    let _ = writeln!(
        out,
        "- Overall verdict: **{}**",
        pass_label(summary.overall_passed())
    );
    let _ = writeln!(out, "- Devices tested: {}", summary.device_count);
    let oems: Vec<&str> = summary
        .oem_groups
        .iter()
        .copied()
        .map(OemGroup::as_str)
        .collect();
    let _ = writeln!(out, "- OEM families covered: {}", oems.join(", "));
    let _ = writeln!(
        out,
        "- Low-RAM (<= 4096 MiB) device covered: {}\n",
        summary.has_low_ram_device
    );

    let _ = writeln!(out, "## 1. Device Matrix\n");
    let _ = writeln!(out, "| ID | OEM | Model | Android API | RAM (MiB) |");
    let _ = writeln!(out, "|---|---|---|---|---|");
    for dev in bundle.devices.values() {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} |",
            dev.device_id, dev.manufacturer, dev.model, dev.android_api, dev.ram_mib
        );
    }

    let _ = writeln!(out, "\n## 2. 24h Foreground Service Soak\n");
    let _ = writeln!(
        out,
        "| Device | Duration (s) | onTimeout | Audits OK | Audits Missed | Verdict |"
    );
    let _ = writeln!(out, "|---|---|---|---|---|---|");
    for soak in &bundle.soak_runs {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} |",
            soak.device_id,
            soak.duration_secs,
            soak.on_timeout_called,
            soak.audits_answered,
            soak.audits_missed,
            pass_label(soak.passed())
        );
    }

    let _ = writeln!(out, "\n## 3. Uncharged Daily Battery Budget\n");
    let _ = writeln!(out, "| Device | 24h Drain | Budget | Note | Verdict |");
    let _ = writeln!(out, "|---|---|---|---|---|");
    for bat in &bundle.battery_runs {
        let note = bat.variance_note.as_deref().unwrap_or("-");
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} |",
            bat.device_id,
            format_bps_percent(bat.drain_bps),
            format_bps_percent(BATTERY_BUDGET_BPS),
            note,
            pass_label(bat.passed())
        );
    }

    let _ = writeln!(out, "\n## 4. NAT Traversal Matrix\n");
    let _ = writeln!(
        out,
        "| Environment | Connected / Total | Direct | Hole Punch | Relay |"
    );
    let _ = writeln!(out, "|---|---|---|---|---|");
    for (env, stats) in &summary.nat_by_env {
        let _ = writeln!(
            out,
            "| {} | {}/{} | {} | {} | {} |",
            env.as_str(),
            stats.connected,
            stats.total,
            format_bps_percent(stats.direct_bps),
            format_bps_percent(stats.hole_punch_bps),
            format_bps_percent(stats.relay_bps)
        );
    }
    out
}
