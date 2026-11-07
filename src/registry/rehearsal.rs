//! Ceremony rehearsal topology verifier, T-1..T-7 drill pass-criteria evaluator,
//! and Mobile field-test telemetry analyzer ( & ; Sections 12.5, 17, 18).
//! exposed for rehearsal harness runners, mobile device field-test analyzers, and CI gates.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Minimum Full validators required in a ceremony rehearsal network.
pub const MIN_REHEARSAL_FULL_VALIDATORS: usize = 8;

/// Minimum distinct cloud regions across Full validators.
pub const MIN_REHEARSAL_REGIONS: usize = 3;

/// Minimum distinct cloud providers across Full validators.
pub const MIN_REHEARSAL_PROVIDERS: usize = 2;

/// Minimum libp2p circuit-relay v2 nodes.
pub const MIN_REHEARSAL_RELAYS: usize = 4;

/// Minimum B.U.D. 3.0 upload gateways.
pub const MIN_REHEARSAL_GATEWAYS: usize = 2;

/// Minimum physical Android phones participating in the rehearsal.
pub const MIN_REHEARSAL_ANDROID_PHONES: usize = 20;

/// Minimum simulated headless Mobile validators.
pub const MIN_REHEARSAL_SIMULATED_MOBILES: usize = 1_000;

/// Minimum continuous rehearsal duration before chaos drills (`72 hours = 259_200 s`).
pub const MIN_REHEARSAL_STEADY_SECS: u64 = 72 * 3_600;

/// Maximum finality checkpoint lag permitted during T-2 (`10%` Full crash).
pub const MAX_T2_FINALITY_LAG_CHECKPOINTS: u64 = 2;

/// Maximum standby-seat handover delay in checkpoints during T-2.
pub const MAX_T2_SEAT_HANDOVER_CHECKPOINTS: u64 = 3;

/// Minimum aggregate upload volume in T-5 (`100 GiB`).
pub const MIN_T5_TOTAL_UPLOAD_BYTES: u64 = 100_u64 << 30;

/// Minimum small sub-symbol objects packed in T-5 (`10_000`).
pub const MIN_T5_SMALL_OBJECT_COUNT: u64 = 10_000;

/// Maximum daily battery drain in basis points (`5.00% = 500 bps`) allowed on a
/// Mobile validator in Wi-Fi background duty.
pub const MAX_MOBILE_DAILY_BATTERY_BPS: u32 = 500;

/// Maximum cellular custody-serving bytes permitted when Wi-Fi-only policy is active (`0`).
pub const MAX_METERED_SERVING_BYTES_DEFAULT: u64 = 0;

/// One Full validator placement record in the rehearsal topology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RehearsalValidatorNode {
    pub validator_id: [u8; 32],
    pub region: String,
    pub provider: String,
}

/// Complete rehearsal network topology descriptor ( items 1-3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RehearsalTopology {
    pub chain_id: u64,
    pub genesis_digest: [u8; 32],
    pub full_validators: Vec<RehearsalValidatorNode>,
    pub relay_count: usize,
    pub upload_gateway_count: usize,
    pub android_phone_count: usize,
    pub simulated_mobile_count: usize,
    pub steady_state_secs: u64,
}

/// Errors returned by rehearsal topology, drill, or mobile telemetry checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RehearsalError {
    /// Topology failed a mandatory minimum count or diversity floor.
    TopologyViolation(&'static str),
    /// One of the seven drills (`T-1`..`T-7`) failed its pass criterion.
    DrillFailed { drill: &'static str, reason: &'static str },
    /// Mobile field-test log entry violated battery, RAM, or metered-network policy.
    MobileFieldViolation(&'static str),
}

impl std::fmt::Display for RehearsalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TopologyViolation(msg) => write!(f, "rehearsal topology violation: {msg}"),
            Self::DrillFailed { drill, reason } => {
                write!(f, "rehearsal drill {drill} failed: {reason}")
            }
            Self::MobileFieldViolation(msg) => write!(f, "mobile field-test violation: {msg}"),
        }
    }
}

impl std::error::Error for RehearsalError {}

/// Verify all  rehearsal network topology floors.
/// exposed for rehearsal preflight tools and integration suites.
///
/// # Errors
///
/// Returns [`RehearsalError::TopologyViolation`] if any floor is unmet.
pub fn verify_rehearsal_topology(topo: &RehearsalTopology) -> Result<(), RehearsalError> {
    if topo.chain_id == 0 || topo.genesis_digest == [0u8; 32] {
        return Err(RehearsalError::TopologyViolation(
            "chain_id and genesis_digest must be non-zero",
        ));
    }
    if topo.full_validators.len() < MIN_REHEARSAL_FULL_VALIDATORS {
        return Err(RehearsalError::TopologyViolation(
            "fewer than 8 Full validators",
        ));
    }
    let ids: BTreeSet<[u8; 32]> = topo.full_validators.iter().map(|v| v.validator_id).collect();
    if ids.len() != topo.full_validators.len() {
        return Err(RehearsalError::TopologyViolation(
            "duplicate Full validator_id in topology",
        ));
    }
    let regions: BTreeSet<&str> = topo
        .full_validators
        .iter()
        .map(|v| v.region.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if regions.len() < MIN_REHEARSAL_REGIONS {
        return Err(RehearsalError::TopologyViolation(
            "Full validators span fewer than 3 cloud regions",
        ));
    }
    let providers: BTreeSet<&str> = topo
        .full_validators
        .iter()
        .map(|v| v.provider.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if providers.len() < MIN_REHEARSAL_PROVIDERS {
        return Err(RehearsalError::TopologyViolation(
            "Full validators span fewer than 2 cloud providers",
        ));
    }
    if topo.relay_count < MIN_REHEARSAL_RELAYS {
        return Err(RehearsalError::TopologyViolation("fewer than 4 relay nodes"));
    }
    if topo.upload_gateway_count < MIN_REHEARSAL_GATEWAYS {
        return Err(RehearsalError::TopologyViolation(
            "fewer than 2 upload gateways",
        ));
    }
    if topo.android_phone_count < MIN_REHEARSAL_ANDROID_PHONES {
        return Err(RehearsalError::TopologyViolation(
            "fewer than 20 physical Android phones",
        ));
    }
    if topo.simulated_mobile_count < MIN_REHEARSAL_SIMULATED_MOBILES {
        return Err(RehearsalError::TopologyViolation(
            "fewer than 1,000 simulated Mobile validators",
        ));
    }
    if topo.steady_state_secs < MIN_REHEARSAL_STEADY_SECS {
        return Err(RehearsalError::TopologyViolation(
            "steady-state window shorter than 72 hours",
        ));
    }
    Ok(())
}

/// Measured telemetry across all seven  chaos and load drills (`T-1`..`T-7`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RehearsalDrillReport {
    /// T-1: Simultaneous shutdown of 100% of Mobile validators.
    pub t1_finality_latency_delta_ms: u64,
    pub t1_lost_objects: u64,
    pub t1_full_class_reads_succeeded: bool,
    /// T-2: Sudden crash of >= 10% of Full validators.
    pub t2_finality_lag_checkpoints: u64,
    pub t2_seat_handover_checkpoints: u64,
    /// T-3: > 1/3 active seats halted for 50 blocks, then resumed.
    pub t3_finality_stalled_alert_fired: bool,
    pub t3_finality_resumed_after_recovery: bool,
    /// T-4: Mobile validators return, `ResumeValidator` activates next epoch, repair completes.
    pub t4_resume_activated_in_one_epoch: bool,
    pub t4_repair_backlog_after_sweep: u64,
    /// T-5: Storage load (>= 100 GiB total upload, >= 10,000 small objects, concurrent views).
    pub t5_total_uploaded_bytes: u64,
    pub t5_small_objects_uploaded: u64,
    pub t5_concurrent_view_failures: u64,
    /// T-6: Multi-EE toolchains and atomic cross-EE EVM -> CW20 call.
    pub t6_toolchains_green: bool,
    pub t6_atomic_evm_to_cw20_succeeded: bool,
    /// T-7: Public RPC load test with rate limiting active and zero node crashes.
    pub t7_http_429_observed: u64,
    pub t7_unhandled_5xx_or_panics: u64,
}

/// Evaluate all seven  rehearsal drills (`T-1`..`T-7`) against their binding pass criteria.
/// exposed for rehearsal result verification and CI drill suites.
///
/// # Errors
///
/// Returns [`RehearsalError::DrillFailed`] on the first failing drill.
pub fn evaluate_rehearsal_drills(r: &RehearsalDrillReport) -> Result<(), RehearsalError> {
    if r.t1_lost_objects != 0 || !r.t1_full_class_reads_succeeded {
        return Err(RehearsalError::DrillFailed {
            drill: "T-1",
            reason: "Mobile shutdown caused object loss or broke Full-class reads",
        });
    }
    if r.t1_finality_latency_delta_ms > 500 {
        return Err(RehearsalError::DrillFailed {
            drill: "T-1",
            reason: "Mobile shutdown shifted finality latency beyond 500 ms tolerance",
        });
    }
    if r.t2_finality_lag_checkpoints > MAX_T2_FINALITY_LAG_CHECKPOINTS {
        return Err(RehearsalError::DrillFailed {
            drill: "T-2",
            reason: "finality lag exceeded 2 checkpoints under 10% Full crash",
        });
    }
    if r.t2_seat_handover_checkpoints > MAX_T2_SEAT_HANDOVER_CHECKPOINTS {
        return Err(RehearsalError::DrillFailed {
            drill: "T-2",
            reason: "standby seat handover exceeded 3 checkpoints",
        });
    }
    if !r.t3_finality_stalled_alert_fired || !r.t3_finality_resumed_after_recovery {
        return Err(RehearsalError::DrillFailed {
            drill: "T-3",
            reason: "budlum_finality_stalled alert did not fire or finality failed to resume",
        });
    }
    if !r.t4_resume_activated_in_one_epoch || r.t4_repair_backlog_after_sweep != 0 {
        return Err(RehearsalError::DrillFailed {
            drill: "T-4",
            reason: "ResumeValidator did not activate next epoch or repair backlog remained non-zero",
        });
    }
    if r.t5_total_uploaded_bytes < MIN_T5_TOTAL_UPLOAD_BYTES
        || r.t5_small_objects_uploaded < MIN_T5_SMALL_OBJECT_COUNT
        || r.t5_concurrent_view_failures != 0
    {
        return Err(RehearsalError::DrillFailed {
            drill: "T-5",
            reason: "upload volume < 100 GiB, small objects < 10,000, or concurrent view failed",
        });
    }
    if !r.t6_toolchains_green || !r.t6_atomic_evm_to_cw20_succeeded {
        return Err(RehearsalError::DrillFailed {
            drill: "T-6",
            reason: "multi-environment toolchain scenario or EVM-to-CW20 call failed",
        });
    }
    if r.t7_http_429_observed == 0 || r.t7_unhandled_5xx_or_panics != 0 {
        return Err(RehearsalError::DrillFailed {
            drill: "T-7",
            reason: "rate limiter did not emit HTTP 429 or RPC emitted 5xx/panic under load",
        });
    }
    Ok(())
}

/// Hardware tier in the Mobile Device Matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MobileDeviceTier {
    Entry4Gb,
    Midrange8Gb,
    Flagship12Gb,
}

/// One structured field-test telemetry sample emitted by an Android Mobile validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobileFieldSample {
    pub device_id: String,
    pub tier: MobileDeviceTier,
    pub peak_rss_mib: u32,
    pub daily_battery_bps: u32,
    pub metered_bytes_served: u64,
    pub allow_cellular_opt_in: bool,
    pub audits_answered: u64,
    pub audits_missed: u64,
    pub rewards_credited_atoms: u64,
}

/// Summary aggregated over a JSONL stream of [`MobileFieldSample`] records.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MobileFieldSummary {
    pub device_count: usize,
    pub max_rss_mib: u32,
    pub max_daily_battery_bps: u32,
    pub total_audits_answered: u64,
    pub total_rewards_atoms: u64,
}

/// Parse and verify a newline-delimited JSON (`JSONL`) stream of Android field-test logs.
/// exposed for `mobile/tools/log-analyzer` workflows and rehearsal validation.
///
/// # Errors
///
/// Returns [`RehearsalError::MobileFieldViolation`] on malformed JSON, empty input,
/// metered-network serving without opt-in, excessive RAM (`> 256 MiB`), or excessive
/// battery drain (`> 5% / day`).
pub fn analyze_mobile_field_logs(jsonl: &str) -> Result<MobileFieldSummary, RehearsalError> {
    let mut summary = MobileFieldSummary::default();
    let mut devices = BTreeSet::new();
    for raw in jsonl.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let sample: MobileFieldSample = serde_json::from_str(trimmed)
            .map_err(|_| RehearsalError::MobileFieldViolation("malformed JSONL telemetry row"))?;
        if sample.device_id.trim().is_empty() {
            return Err(RehearsalError::MobileFieldViolation(
                "empty device_id in telemetry row",
            ));
        }
        if !sample.allow_cellular_opt_in
            && sample.metered_bytes_served > MAX_METERED_SERVING_BYTES_DEFAULT
        {
            return Err(RehearsalError::MobileFieldViolation(
                "Mobile validator served custody bytes over cellular without opt-in",
            ));
        }
        if sample.peak_rss_mib > 256 {
            return Err(RehearsalError::MobileFieldViolation(
                "Mobile validator exceeded 256 MiB RSS ceiling",
            ));
        }
        if sample.daily_battery_bps > MAX_MOBILE_DAILY_BATTERY_BPS {
            return Err(RehearsalError::MobileFieldViolation(
                "Mobile validator exceeded 5.00%/day background battery ceiling",
            ));
        }
        devices.insert(sample.device_id);
        summary.device_count = devices.len();
        summary.max_rss_mib = summary.max_rss_mib.max(sample.peak_rss_mib);
        summary.max_daily_battery_bps = summary
            .max_daily_battery_bps
            .max(sample.daily_battery_bps);
        summary.total_audits_answered = summary
            .total_audits_answered
            .saturating_add(sample.audits_answered);
        summary.total_rewards_atoms = summary
            .total_rewards_atoms
            .saturating_add(sample.rewards_credited_atoms);
    }
    if summary.device_count == 0 {
        return Err(RehearsalError::MobileFieldViolation(
            "no mobile field-test samples present",
        ));
    }
    Ok(summary)
}

/// Run the full rehearsal verification gate over topology, `T-1..T-7` drill
/// results, and Android field-test JSONL logs ( + ).
/// exposed for ceremony rehearsal runner and release readiness checks.
///
/// # Errors
///
/// Returns [`RehearsalError`] if topology, drill pass criteria, or mobile field
/// bounds fail.
pub fn run_rehearsal_suite(
    topo: &RehearsalTopology,
    report: &RehearsalDrillReport,
    jsonl: &str,
) -> Result<MobileFieldSummary, RehearsalError> {
    verify_rehearsal_topology(topo)?;
    evaluate_rehearsal_drills(report)?;
    analyze_mobile_field_logs(jsonl)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_topology() -> RehearsalTopology {
        let providers = ["hetzner", "ovh"];
        let regions = ["eu-central", "us-east", "ap-southeast"];
        let mut full = Vec::new();
        for i in 0..8u8 {
            full.push(RehearsalValidatorNode {
                validator_id: [i + 1; 32],
                region: regions[usize::from(i) % regions.len()].to_string(),
                provider: providers[usize::from(i) % providers.len()].to_string(),
            });
        }
        RehearsalTopology {
            chain_id: 45262,
            genesis_digest: [0xAB; 32],
            full_validators: full,
            relay_count: 4,
            upload_gateway_count: 2,
            android_phone_count: 20,
            simulated_mobile_count: 1_000,
            steady_state_secs: MIN_REHEARSAL_STEADY_SECS,
        }
    }

    #[test]
    fn topology_enforces_eight_full_three_regions_two_providers() {
        let mut topo = valid_topology();
        assert!(verify_rehearsal_topology(&topo).is_ok());

        topo.full_validators.pop();
        assert!(verify_rehearsal_topology(&topo).is_err());
    }

    #[test]
    fn device_log_analyzer_golden_reports() {
        let input = include_str!("../../mobile/tools/log-analyzer/fixtures/samples.jsonl");
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../mobile/tools/log-analyzer/fixtures/report.json"
        ))
        .unwrap();
        let actual = serde_json::to_value(analyze_mobile_field_logs(input).unwrap()).unwrap();
        assert_eq!(actual, expected);

        assert!(analyze_mobile_field_logs("").is_err());
        assert!(analyze_mobile_field_logs("not json").is_err());
        let excessive_battery =
            input.replace("\"daily_battery_bps\":500", "\"daily_battery_bps\":501");
        assert!(analyze_mobile_field_logs(&excessive_battery).is_err());
        let unapproved_cellular = input.replace(
            "\"allow_cellular_opt_in\":true",
            "\"allow_cellular_opt_in\":false",
        );
        assert!(analyze_mobile_field_logs(&unapproved_cellular).is_err());
    }

    #[test]
    fn mobile_log_analyzer_rejects_unapproved_cellular_serving() {
        let ok_line = r#"{"device_id":"pixel7a-01","tier":"midrange8_gb","peak_rss_mib":118,"daily_battery_bps":240,"metered_bytes_served":0,"allow_cellular_opt_in":false,"audits_answered":48,"audits_missed":0,"rewards_credited_atoms":12500}"#;
        let summary = analyze_mobile_field_logs(ok_line).unwrap();
        assert_eq!(summary.device_count, 1);
        assert_eq!(summary.total_audits_answered, 48);

        let bad_line = r#"{"device_id":"pixel7a-02","tier":"midrange8_gb","peak_rss_mib":118,"daily_battery_bps":240,"metered_bytes_served":4096,"allow_cellular_opt_in":false,"audits_answered":10,"audits_missed":0,"rewards_credited_atoms":100}"#;
        assert!(analyze_mobile_field_logs(bad_line).is_err());
    }
}
