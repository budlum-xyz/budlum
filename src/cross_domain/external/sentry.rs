//! Deterministic Consensus Sentry, admin-keyless cross-domain circuit breaker,
//! and pre-launch testnet readiness self-interrogation engine.
//!
//! Each registered external or internal consensus domain reports canonical
//! observations (height, state root, finality timestamp, remaining light-client
//! trusting window, cryptographic quantum posture, and shared-security restake
//! concentration). `ConsensusSentry` evaluates every observation without floats,
//! wall-clock reads, or privileged admin overrides, escalates per-domain circuit
//! state monotonically on faults, commits a length-prefixed SHA-256 audit root,
//! and emits canonical human- and machine-readable status lines.
//!
//! Convenience: exposed for external finality intake, RPC health surfaces,
//! governance slashing hooks, and testnet launch-gate verification.
//! WIRING: wired - refreshed at block end via `AccountState::refresh_consensus_sentry` (`Blockchain::apply_block_end_roots`), committed into `BridgeState::root` -> `AccountState` state root, enforced by `finality_gate::enforce_sentry_circuit_clear`, exported via `Metrics`, and served through `bud_getDomainHealth`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Domain-separation tag for an individual `SentryAlert` digest.
pub const DOMAIN_SENTRY_EVENT: &[u8] = b"BDLM_SENTRY_EVENT_V1";

/// Domain-separation tag for `ConsensusSentry::state_root`.
pub const DOMAIN_SENTRY_AUDIT_ROOT: &[u8] = b"BDLM_SENTRY_AUDIT_ROOT_V1";

/// Domain-separation tag for `TestnetLaunchVerdict::commitment`.
pub const DOMAIN_SENTRY_LAUNCH_VERDICT: &[u8] = b"BDLM_SENTRY_LAUNCH_VERDICT_V1";

/// Maximum watched consensus domains before fail-closed refusal.
pub const MAX_SENTRY_DOMAINS: usize = 512;

/// Maximum retained alerts in the bounded on-chain ring log.
pub const MAX_SENTRY_EVENTS: usize = 4_096;

/// Maximum identifier byte length accepted for a domain key.
pub const MAX_DOMAIN_ID_LEN: usize = 128;

/// Default maximum shared-security restaking share per domain (30.0000% = `300_000` ppm),
/// preserving a strict safety margin below the 1/3 BFT corruption threshold.
pub const DEFAULT_MAX_RESTAKE_SHARE_PPM: u32 = 300_000;

/// Hard classical BFT adversarial corruption ceiling (33.3333% = `333_333` ppm).
pub const BFT_CORRUPTION_CEILING_PPM: u32 = 333_333;

/// One hundred percent in parts per million.
pub const FULL_SCALE_PPM: u32 = 1_000_000;

/// Canonical Budlum Testnet EVM chain identifier.
pub const CANONICAL_TESTNET_EVM_CHAIN_ID: u64 = 45_261;

/// Canonical Budlum Testnet Aptos chain identifier.
pub const CANONICAL_TESTNET_APTOS_CHAIN_ID: u8 = 205;

/// Canonical Budlum Testnet Cosmos chain identifier.
pub const CANONICAL_TESTNET_COSMOS_CHAIN_ID: &str = "budlum-testnet-1";

fn update_lp(hasher: &mut Sha256, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    hasher.update(len.to_le_bytes());
    hasher.update(bytes);
}

/// Cryptographic post-quantum posture declared for a watched consensus domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DomainQuantumPosture {
    /// Classical discrete-log or pairing cryptography only (ECDSA, Ed25519,
    /// Schnorr, BLS12-381, Groth16, KZG); must be isolated under a CRQC alarm.
    ClassicalOnly,
    /// Dual enforcement requiring both a classical signature/proof and a
    /// post-quantum lattice or hash signature/proof (for example Ed25519 + ML-DSA-65).
    HybridPostQuantum,
    /// Pure post-quantum hash or lattice security (SHA-256 `PoW`, Plonky3 FRI STARK,
    /// ML-DSA-65/87, SLH-DSA, ML-KEM-768/1024).
    PurePostQuantum,
}

impl DomainQuantumPosture {
    /// Returns `true` when the domain remains sound against a cryptographically
    /// relevant quantum adversary.
    ///
    /// exposed for: CRQC posture filtering and Sentry status reports.
    #[must_use]
    pub const fn survives_crqc(self) -> bool {
        matches!(self, Self::HybridPostQuantum | Self::PurePostQuantum)
    }

    const fn code(self) -> u8 {
        match self {
            Self::ClassicalOnly => 0,
            Self::HybridPostQuantum => 1,
            Self::PurePostQuantum => 2,
        }
    }
}

/// Per-domain admin-keyless circuit breaker state, ordered by strict severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SentryCircuitState {
    /// Normal operation: inbound attestations and bridge settlements accepted.
    Open,
    /// Elevated caution: rate-limited intake and mandatory bisection refresh.
    Throttled,
    /// Inbound bridge/settlement halted pending fresh finality or dispute expiry.
    Halted,
    /// Hard protocol freeze triggered by equivocation, deep reorg, BFT ceiling
    /// breach, or CRQC classical exposure; requires governance recovery cooldown.
    Frozen,
}

impl SentryCircuitState {
    /// Returns `true` only when inbound cross-domain settlement is permitted.
    ///
    /// exposed for: bridge and external-intake settlement guards.
    #[must_use]
    pub const fn accepts_settlement(self) -> bool {
        matches!(self, Self::Open)
    }

    /// Canonical uppercase label for RPC and metrics reporting.
    #[must_use]
    pub const fn label(self) -> &'static str {
        self.as_str()
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "OPEN",
            Self::Throttled => "THROTTLED",
            Self::Halted => "HALTED",
            Self::Frozen => "FROZEN",
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Throttled => 1,
            Self::Halted => 2,
            Self::Frozen => 3,
        }
    }
}

/// Alert severity tier aligned with `SENTRY_MIMARISI.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SentrySeverity {
    /// Informational telemetry.
    Info,
    /// Early degradation requiring throttling or light-client refresh.
    Medium,
    /// Liveness stall or repeated proof rejections halting inbound settlement.
    High,
    /// Safety violation, BFT contagion breach, or CRQC classical exposure.
    Critical,
}

impl SentrySeverity {
    const fn code(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Medium => 1,
            Self::High => 2,
            Self::Critical => 3,
        }
    }
}

/// Deterministic remediation prescribed by `ConsensusSentry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SentryAction {
    /// Record telemetry only.
    ObserveOnly,
    /// Throttle intake and request an immediate light-client header refresh.
    DemandHeaderRefresh,
    /// Cap additional shared-security restaking delegation to this domain.
    CapRestakeIntake,
    /// Halt inbound cross-domain transfers until liveness and proofs recover.
    HaltInboundBridge,
    /// Freeze the domain, quarantine provers, and submit slashing evidence.
    FreezeDomainAndSlash,
    /// Freeze a classical-only domain under an active CRQC quantum alarm.
    IsolateClassicalDomain,
}

impl SentryAction {
    const fn code(self) -> u8 {
        match self {
            Self::ObserveOnly => 0,
            Self::DemandHeaderRefresh => 1,
            Self::CapRestakeIntake => 2,
            Self::HaltInboundBridge => 3,
            Self::FreezeDomainAndSlash => 4,
            Self::IsolateClassicalDomain => 5,
        }
    }
}

/// Canonical fault classes detected by `ConsensusSentry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SentryFindingKind {
    /// Two distinct state roots attested for the same finalized height.
    ConflictingFinality {
        height: u64,
        prior_root: [u8; 32],
        conflicting_root: [u8; 32],
    },
    /// Observed height regressed below a previously finalized height.
    FinalityReorg {
        finalized_height: u64,
        regressed_height: u64,
        rollback_blocks: u64,
    },
    /// No fresh finality observed within `max_finality_stall_secs`.
    FinalityStall {
        silent_secs: u64,
        max_allowed_secs: u64,
    },
    /// Remaining IBC/light-client trusting window dropped below safety margin.
    TrustingWindowLow {
        remaining_secs: u64,
        min_required_secs: u64,
    },
    /// Consecutive invalid proof submissions reached the quarantine threshold.
    RepeatedProofFailure {
        consecutive_failures: u32,
        threshold: u32,
    },
    /// Domain's shared-security restake share crossed the configured safety ceiling.
    RestakingContagion { share_ppm: u32, ceiling_ppm: u32 },
    /// CRQC posture activated while domain relies strictly on classical crypto.
    ClassicalExposureUnderCrqc,
}

impl SentryFindingKind {
    fn hash_into(&self, h: &mut Sha256) {
        match self {
            Self::ConflictingFinality {
                height,
                prior_root,
                conflicting_root,
            } => {
                h.update([1u8]);
                h.update(height.to_le_bytes());
                h.update(prior_root);
                h.update(conflicting_root);
            }
            Self::FinalityReorg {
                finalized_height,
                regressed_height,
                rollback_blocks,
            } => {
                h.update([2u8]);
                h.update(finalized_height.to_le_bytes());
                h.update(regressed_height.to_le_bytes());
                h.update(rollback_blocks.to_le_bytes());
            }
            Self::FinalityStall {
                silent_secs,
                max_allowed_secs,
            } => {
                h.update([3u8]);
                h.update(silent_secs.to_le_bytes());
                h.update(max_allowed_secs.to_le_bytes());
            }
            Self::TrustingWindowLow {
                remaining_secs,
                min_required_secs,
            } => {
                h.update([4u8]);
                h.update(remaining_secs.to_le_bytes());
                h.update(min_required_secs.to_le_bytes());
            }
            Self::RepeatedProofFailure {
                consecutive_failures,
                threshold,
            } => {
                h.update([5u8]);
                h.update(consecutive_failures.to_le_bytes());
                h.update(threshold.to_le_bytes());
            }
            Self::RestakingContagion {
                share_ppm,
                ceiling_ppm,
            } => {
                h.update([6u8]);
                h.update(share_ppm.to_le_bytes());
                h.update(ceiling_ppm.to_le_bytes());
            }
            Self::ClassicalExposureUnderCrqc => {
                h.update([7u8]);
            }
        }
    }
}

/// Deterministic policy thresholds enforced for a single watched domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentryDomainPolicy {
    /// Human-readable consensus family tag (e.g. `"bitcoin-spv-v1"`).
    pub consensus_family: String,
    /// Cryptographic quantum posture of this domain's finality proof.
    pub quantum_posture: DomainQuantumPosture,
    /// Maximum silent seconds between finalized headers before `Halted`.
    pub max_finality_stall_secs: u64,
    /// Minimum remaining trusting-window seconds before `Throttled` (`0` for PoW/ZK).
    pub min_trusting_window_secs: u64,
    /// Rollback block depth that escalates directly to `Frozen` (`0` = any regression freezes).
    pub max_reorg_blocks: u64,
    /// Consecutive proof verification failures before `Halted`.
    pub max_consecutive_proof_failures: u32,
    /// Maximum shared-security restaking share in parts per million (`<= 300_000`).
    pub max_restake_share_ppm: u32,
    /// Minimum governance recovery delay in seconds before unfreezing.
    pub recovery_cooldown_secs: u64,
}

impl SentryDomainPolicy {
    /// Validate deterministic bounds on all policy thresholds.
    ///
    /// exposed for: domain registration validation.
    pub fn validate(&self) -> Result<(), SentryError> {
        if self.consensus_family.is_empty() || self.consensus_family.len() > MAX_DOMAIN_ID_LEN {
            return Err(SentryError::InvalidIdentifier("consensus_family"));
        }
        if self.max_finality_stall_secs == 0 {
            return Err(SentryError::InvalidPolicy(
                "max_finality_stall_secs must be positive",
            ));
        }
        if self.max_consecutive_proof_failures == 0 {
            return Err(SentryError::InvalidPolicy(
                "max_consecutive_proof_failures must be positive",
            ));
        }
        if self.max_restake_share_ppm > DEFAULT_MAX_RESTAKE_SHARE_PPM {
            return Err(SentryError::InvalidPolicy(
                "max_restake_share_ppm exceeds 300_000 ppm safety ceiling",
            ));
        }
        if self.recovery_cooldown_secs == 0 {
            return Err(SentryError::InvalidPolicy(
                "recovery_cooldown_secs must be positive",
            ));
        }
        Ok(())
    }
}

/// Canonical finality/telemetry sample fed into `ConsensusSentry::observe`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentryObservation {
    /// Watched domain key (e.g. `"cosmos-hub:tendermint-bft-v1"`).
    pub domain_id: String,
    /// Attested finalized block height or slot.
    pub height: u64,
    /// Attested 32-byte state/app/bank root.
    pub state_root: [u8; 32],
    /// Deterministic block timestamp (seconds) at which this sample is evaluated.
    pub observed_at_secs: u64,
    /// Remaining light-client trusting window in seconds (`None` if non-expiring).
    pub remaining_trust_window_secs: Option<u64>,
    /// Current shared-security restaked collateral share backing this domain (ppm).
    pub restake_share_ppm: u32,
}

/// Signed-free, deterministic alert committed to the Sentry audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentryAlert {
    /// Domain that triggered the alert.
    pub domain_id: String,
    /// Evaluation timestamp in seconds.
    pub observed_at_secs: u64,
    /// Severity tier.
    pub severity: SentrySeverity,
    /// Specific protocol invariant that tripped.
    pub kind: SentryFindingKind,
    /// Automated action executed by `ConsensusSentry`.
    pub action: SentryAction,
    /// Resulting per-domain circuit-breaker state.
    pub resulting_state: SentryCircuitState,
    /// Canonical 32-byte event digest (`DOMAIN_SENTRY_EVENT`).
    pub event_id: [u8; 32],
}

impl SentryAlert {
    fn new(
        domain_id: String,
        observed_at_secs: u64,
        severity: SentrySeverity,
        kind: SentryFindingKind,
        action: SentryAction,
        resulting_state: SentryCircuitState,
    ) -> Self {
        let mut h = Sha256::new();
        update_lp(&mut h, DOMAIN_SENTRY_EVENT);
        update_lp(&mut h, domain_id.as_bytes());
        h.update(observed_at_secs.to_le_bytes());
        h.update([severity.code(), action.code(), resulting_state.code()]);
        kind.hash_into(&mut h);
        let event_id: [u8; 32] = h.finalize().into();
        Self {
            domain_id,
            observed_at_secs,
            severity,
            kind,
            action,
            resulting_state,
            event_id,
        }
    }
}

/// Tracked canonical state for one watched consensus domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchedDomainState {
    /// Immutable policy thresholds bound at registration.
    pub policy: SentryDomainPolicy,
    /// Current circuit-breaker state.
    pub circuit: SentryCircuitState,
    /// Highest accepted finalized height (`None` before first valid observation).
    pub last_height: Option<u64>,
    /// State root committed at `last_height`.
    pub last_state_root: Option<[u8; 32]>,
    /// Timestamp (seconds) of the latest accepted height advance.
    pub last_progress_secs: Option<u64>,
    /// Timestamp (seconds) at which `circuit` last escalated.
    pub last_escalation_secs: Option<u64>,
    /// Consecutive proof verification rejections since the last valid advance.
    pub consecutive_proof_failures: u32,
    /// Latest observed shared-security restake share in ppm.
    pub latest_restake_share_ppm: u32,
}

/// Errors returned by `ConsensusSentry` registration, observation, and recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SentryError {
    /// Empty, oversized, or non-ASCII-printable identifier.
    InvalidIdentifier(&'static str),
    /// Policy threshold violates deterministic safety bounds.
    InvalidPolicy(&'static str),
    /// Domain already registered.
    DuplicateDomain(String),
    /// Domain limit `MAX_SENTRY_DOMAINS` reached.
    DomainCapacityExceeded { max: usize },
    /// Referenced domain has not been registered.
    UnknownDomain(String),
    /// All-zero state root cannot anchor finality.
    ZeroStateRoot,
    /// `restake_share_ppm` exceeds `FULL_SCALE_PPM` (`1_000_000`).
    InvalidRestakeSharePpm(u32),
    /// Observation timestamp regressed below domain history.
    TimestampRegression { got: u64, min: u64 },
    /// Governance recovery attempted before `recovery_cooldown_secs` elapsed.
    RecoveryCooldownActive { ready_at_secs: u64, now_secs: u64 },
    /// Cannot recover a classical-only domain while global CRQC alarm is active.
    CrqcAlarmBlocksClassicalRecovery,
}

/// Deterministic multi-domain Consensus Sentry state machine.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusSentry {
    domains: BTreeMap<String, WatchedDomainState>,
    alerts: Vec<SentryAlert>,
    seen_event_ids: BTreeSet<[u8; 32]>,
    crqc_alarm_active: bool,
    evicted_alert_count: u64,
}

impl ConsensusSentry {
    /// Construct an empty `ConsensusSentry`.
    ///
    /// Convenience: exposed for node, intake, and rehearsal initialization.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Canonical Sentry domain key for a numeric settlement `DomainId`.
    #[must_use]
    pub fn domain_key_for_id(domain_id: u32) -> String {
        format!("domain:{domain_id}")
    }

    /// Returns `true` when no domains, alerts, or CRQC alarms are active.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty() && self.alerts.is_empty() && !self.crqc_alarm_active
    }

    /// Borrow all deterministically tracked watched domains.
    #[must_use]
    pub const fn watched_domains(&self) -> &BTreeMap<String, WatchedDomainState> {
        &self.domains
    }

    /// Number of registered watched domains.
    ///
    /// Convenience: exposed for Sentry telemetry callers.
    #[must_use]
    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }

    /// Slice of retained deterministic `SentryAlert` records.
    ///
    /// Convenience: exposed for RPC audit endpoints and alerting pipelines.
    #[must_use]
    pub fn alerts(&self) -> &[SentryAlert] {
        &self.alerts
    }

    /// Whether the global CRQC quantum emergency posture is active.
    ///
    /// Convenience: exposed for PQ migration readiness callers.
    #[must_use]
    pub const fn crqc_alarm_active(&self) -> bool {
        self.crqc_alarm_active
    }

    /// Inspect tracked state for `domain_id`.
    ///
    /// Convenience: exposed for per-domain bridge settlement checks.
    #[must_use]
    pub fn domain(&self, domain_id: &str) -> Option<&WatchedDomainState> {
        self.domains.get(domain_id)
    }

    /// Count of domains currently in `SentryCircuitState::Frozen`.
    ///
    /// Convenience: exposed for launch-gate and health evaluators.
    #[must_use]
    pub fn frozen_domain_count(&self) -> usize {
        self.domains
            .values()
            .filter(|d| d.circuit == SentryCircuitState::Frozen)
            .count()
    }

    /// Register a new domain under deterministic `policy`.
    ///
    /// Convenience: exposed for external domain onboarding.
    pub fn register_domain(
        &mut self,
        domain_id: impl Into<String>,
        policy: SentryDomainPolicy,
    ) -> Result<(), SentryError> {
        let id = domain_id.into();
        if !is_valid_identifier(&id) {
            return Err(SentryError::InvalidIdentifier("domain_id"));
        }
        policy.validate()?;
        if self.domains.contains_key(&id) {
            return Err(SentryError::DuplicateDomain(id));
        }
        if self.domains.len() >= MAX_SENTRY_DOMAINS {
            return Err(SentryError::DomainCapacityExceeded {
                max: MAX_SENTRY_DOMAINS,
            });
        }
        let initial_circuit = if self.crqc_alarm_active && !policy.quantum_posture.survives_crqc() {
            SentryCircuitState::Frozen
        } else {
            SentryCircuitState::Open
        };
        self.domains.insert(
            id,
            WatchedDomainState {
                policy,
                circuit: initial_circuit,
                last_height: None,
                last_state_root: None,
                last_progress_secs: None,
                last_escalation_secs: None,
                consecutive_proof_failures: 0,
                latest_restake_share_ppm: 0,
            },
        );
        Ok(())
    }

    /// Activate the global CRQC quantum threat posture: immediately isolates every
    /// `ClassicalOnly` domain into `Frozen` while leaving `HybridPostQuantum` and
    /// `PurePostQuantum` domains untouched.
    ///
    /// Convenience: exposed for governance/protocol quantum emergency hooks.
    pub fn activate_crqc_alarm(&mut self, observed_at_secs: u64) -> Vec<SentryAlert> {
        self.crqc_alarm_active = true;
        let classical_ids: Vec<String> = self
            .domains
            .iter()
            .filter(|(_, d)| !d.policy.quantum_posture.survives_crqc())
            .map(|(id, _)| id.clone())
            .collect();
        let mut emitted = Vec::new();
        for id in classical_ids {
            if let Some(alert) = self.escalate_and_record(
                &id,
                observed_at_secs,
                SentrySeverity::Critical,
                SentryFindingKind::ClassicalExposureUnderCrqc,
                SentryAction::IsolateClassicalDomain,
                SentryCircuitState::Frozen,
            ) {
                emitted.push(alert);
            }
        }
        emitted
    }

    /// Record a rejected proof submission against `domain_id` and halt inbound
    /// settlement once `max_consecutive_proof_failures` is reached.
    ///
    /// Convenience: exposed for external adapter intake error paths.
    pub fn record_proof_failure(
        &mut self,
        domain_id: &str,
        observed_at_secs: u64,
    ) -> Result<Option<SentryAlert>, SentryError> {
        let (count, threshold) = {
            let state = self
                .domains
                .get_mut(domain_id)
                .ok_or_else(|| SentryError::UnknownDomain(domain_id.to_string()))?;
            state.consecutive_proof_failures = state.consecutive_proof_failures.saturating_add(1);
            (
                state.consecutive_proof_failures,
                state.policy.max_consecutive_proof_failures,
            )
        };
        if count >= threshold {
            return Ok(self.escalate_and_record(
                domain_id,
                observed_at_secs,
                SentrySeverity::High,
                SentryFindingKind::RepeatedProofFailure {
                    consecutive_failures: count,
                    threshold,
                },
                SentryAction::HaltInboundBridge,
                SentryCircuitState::Halted,
            ));
        }
        Ok(None)
    }

    /// Poll liveness across all watched domains at `now_secs`, halting any domain
    /// whose silence exceeds `max_finality_stall_secs`.
    ///
    /// Convenience: exposed for per-block/per-epoch Sentry tick evaluation.
    pub fn check_liveness(&mut self, now_secs: u64) -> Vec<SentryAlert> {
        let stalled: Vec<(String, u64, u64)> = self
            .domains
            .iter()
            .filter_map(|(id, state)| {
                let last = state.last_progress_secs?;
                let silent = now_secs.checked_sub(last)?;
                if silent > state.policy.max_finality_stall_secs {
                    Some((id.clone(), silent, state.policy.max_finality_stall_secs))
                } else {
                    None
                }
            })
            .collect();
        let mut emitted = Vec::new();
        for (id, silent_secs, max_allowed_secs) in stalled {
            if let Some(alert) = self.escalate_and_record(
                &id,
                now_secs,
                SentrySeverity::High,
                SentryFindingKind::FinalityStall {
                    silent_secs,
                    max_allowed_secs,
                },
                SentryAction::HaltInboundBridge,
                SentryCircuitState::Halted,
            ) {
                emitted.push(alert);
            }
        }
        emitted
    }

    /// Evaluate a new canonical finality observation for a registered domain,
    /// escalating circuit state monotonically on safety, liveness, restaking, or
    /// quantum-posture violations.
    ///
    /// Convenience: exposed for external finality intake pipelines.
    pub fn observe(&mut self, obs: &SentryObservation) -> Result<Vec<SentryAlert>, SentryError> {
        if obs.state_root == [0u8; 32] {
            return Err(SentryError::ZeroStateRoot);
        }
        if obs.restake_share_ppm > FULL_SCALE_PPM {
            return Err(SentryError::InvalidRestakeSharePpm(obs.restake_share_ppm));
        }

        let snapshot = self
            .domains
            .get(&obs.domain_id)
            .cloned()
            .ok_or_else(|| SentryError::UnknownDomain(obs.domain_id.clone()))?;

        if let Some(prev_ts) = snapshot.last_progress_secs {
            if obs.observed_at_secs < prev_ts {
                return Err(SentryError::TimestampRegression {
                    got: obs.observed_at_secs,
                    min: prev_ts,
                });
            }
        }

        let mut emitted = Vec::new();
        let mut safety_fault = false;

        // 1. CRQC posture enforcement.
        if self.crqc_alarm_active && !snapshot.policy.quantum_posture.survives_crqc() {
            safety_fault = true;
            if let Some(a) = self.escalate_and_record(
                &obs.domain_id,
                obs.observed_at_secs,
                SentrySeverity::Critical,
                SentryFindingKind::ClassicalExposureUnderCrqc,
                SentryAction::IsolateClassicalDomain,
                SentryCircuitState::Frozen,
            ) {
                emitted.push(a);
            }
        }

        // 2. Finality safety checks: same-height equivocation and height regression.
        if let (Some(prev_h), Some(prev_root)) = (snapshot.last_height, snapshot.last_state_root) {
            if obs.height == prev_h && !bool::from(obs.state_root.ct_eq(&prev_root)) {
                safety_fault = true;
                if let Some(a) = self.escalate_and_record(
                    &obs.domain_id,
                    obs.observed_at_secs,
                    SentrySeverity::Critical,
                    SentryFindingKind::ConflictingFinality {
                        height: obs.height,
                        prior_root: prev_root,
                        conflicting_root: obs.state_root,
                    },
                    SentryAction::FreezeDomainAndSlash,
                    SentryCircuitState::Frozen,
                ) {
                    emitted.push(a);
                }
            } else if obs.height < prev_h {
                safety_fault = true;
                let rollback = prev_h - obs.height;
                let (sev, next_state, action) = if rollback > snapshot.policy.max_reorg_blocks {
                    (
                        SentrySeverity::Critical,
                        SentryCircuitState::Frozen,
                        SentryAction::FreezeDomainAndSlash,
                    )
                } else {
                    (
                        SentrySeverity::High,
                        SentryCircuitState::Halted,
                        SentryAction::HaltInboundBridge,
                    )
                };
                if let Some(a) = self.escalate_and_record(
                    &obs.domain_id,
                    obs.observed_at_secs,
                    sev,
                    SentryFindingKind::FinalityReorg {
                        finalized_height: prev_h,
                        regressed_height: obs.height,
                        rollback_blocks: rollback,
                    },
                    action,
                    next_state,
                ) {
                    emitted.push(a);
                }
            }
        }

        // 3. Liveness gap check before advancing progress timestamp.
        if let Some(prev_ts) = snapshot.last_progress_secs {
            let silent = obs.observed_at_secs.saturating_sub(prev_ts);
            if silent > snapshot.policy.max_finality_stall_secs {
                if let Some(a) = self.escalate_and_record(
                    &obs.domain_id,
                    obs.observed_at_secs,
                    SentrySeverity::High,
                    SentryFindingKind::FinalityStall {
                        silent_secs: silent,
                        max_allowed_secs: snapshot.policy.max_finality_stall_secs,
                    },
                    SentryAction::HaltInboundBridge,
                    SentryCircuitState::Halted,
                ) {
                    emitted.push(a);
                }
            }
        }

        // 4. Light-client trusting-period decay warning.
        if snapshot.policy.min_trusting_window_secs > 0 {
            if let Some(remaining) = obs.remaining_trust_window_secs {
                if remaining < snapshot.policy.min_trusting_window_secs {
                    let (sev, action, target) = if remaining == 0 {
                        (
                            SentrySeverity::High,
                            SentryAction::HaltInboundBridge,
                            SentryCircuitState::Halted,
                        )
                    } else {
                        (
                            SentrySeverity::Medium,
                            SentryAction::DemandHeaderRefresh,
                            SentryCircuitState::Throttled,
                        )
                    };
                    if let Some(a) = self.escalate_and_record(
                        &obs.domain_id,
                        obs.observed_at_secs,
                        sev,
                        SentryFindingKind::TrustingWindowLow {
                            remaining_secs: remaining,
                            min_required_secs: snapshot.policy.min_trusting_window_secs,
                        },
                        action,
                        target,
                    ) {
                        emitted.push(a);
                    }
                }
            }
        }

        // 5. shared-security restaking contagion guard (30% cap / 33.33% BFT cliff).
        if obs.restake_share_ppm > snapshot.policy.max_restake_share_ppm {
            let (sev, action, target) = if obs.restake_share_ppm >= BFT_CORRUPTION_CEILING_PPM {
                (
                    SentrySeverity::Critical,
                    SentryAction::FreezeDomainAndSlash,
                    SentryCircuitState::Frozen,
                )
            } else {
                (
                    SentrySeverity::High,
                    SentryAction::CapRestakeIntake,
                    SentryCircuitState::Throttled,
                )
            };
            if let Some(a) = self.escalate_and_record(
                &obs.domain_id,
                obs.observed_at_secs,
                sev,
                SentryFindingKind::RestakingContagion {
                    share_ppm: obs.restake_share_ppm,
                    ceiling_ppm: snapshot.policy.max_restake_share_ppm,
                },
                action,
                target,
            ) {
                emitted.push(a);
            }
        }

        // Advance canonical head ONLY when no safety violation occurred and the
        // domain is not frozen.
        if let Some(state) = self.domains.get_mut(&obs.domain_id) {
            state.latest_restake_share_ppm = obs.restake_share_ppm;
            if !safety_fault && state.circuit != SentryCircuitState::Frozen {
                let advances = state.last_height.is_none_or(|prev| obs.height > prev);
                if advances {
                    state.last_height = Some(obs.height);
                    state.last_state_root = Some(obs.state_root);
                    state.last_progress_secs = Some(obs.observed_at_secs);
                    state.consecutive_proof_failures = 0;
                }
            }
        }

        Ok(emitted)
    }

    /// Recover a domain back to `SentryCircuitState::Open` strictly after
    /// `recovery_cooldown_secs` have elapsed since its last escalation (intended
    /// exclusively for finalized on-chain governance execution, never an admin key).
    ///
    /// Convenience: exposed for governance circuit-breaker recovery execution.
    pub fn recover_after_governance_cooldown(
        &mut self,
        domain_id: &str,
        now_secs: u64,
        new_anchor: Option<(u64, [u8; 32])>,
    ) -> Result<(), SentryError> {
        if let Some((_, root)) = new_anchor {
            if root == [0u8; 32] {
                return Err(SentryError::ZeroStateRoot);
            }
        }
        let state = self
            .domains
            .get_mut(domain_id)
            .ok_or_else(|| SentryError::UnknownDomain(domain_id.to_string()))?;
        if self.crqc_alarm_active && !state.policy.quantum_posture.survives_crqc() {
            return Err(SentryError::CrqcAlarmBlocksClassicalRecovery);
        }
        if let Some(esc) = state.last_escalation_secs {
            let ready_at = esc.saturating_add(state.policy.recovery_cooldown_secs);
            if now_secs < ready_at {
                return Err(SentryError::RecoveryCooldownActive {
                    ready_at_secs: ready_at,
                    now_secs,
                });
            }
        }
        state.circuit = SentryCircuitState::Open;
        state.consecutive_proof_failures = 0;
        if let Some((height, root)) = new_anchor {
            state.last_height = Some(height);
            state.last_state_root = Some(root);
            state.last_progress_secs = Some(now_secs);
        }
        Ok(())
    }

    /// Compute the deterministic, length-prefixed SHA-256 commitment over all
    /// watched domains, global CRQC posture, and retained alert identifiers.
    ///
    /// Convenience: exposed for block state-root inclusion and cross-arch replay tests.
    #[must_use]
    pub fn state_root(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        update_lp(&mut h, DOMAIN_SENTRY_AUDIT_ROOT);
        h.update([u8::from(self.crqc_alarm_active)]);
        h.update(self.evicted_alert_count.to_le_bytes());
        h.update((self.domains.len() as u64).to_le_bytes());
        for (id, d) in &self.domains {
            update_lp(&mut h, id.as_bytes());
            update_lp(&mut h, d.policy.consensus_family.as_bytes());
            h.update([d.policy.quantum_posture.code(), d.circuit.code()]);
            h.update(d.last_height.unwrap_or(0).to_le_bytes());
            h.update([u8::from(d.last_height.is_some())]);
            h.update(d.last_state_root.unwrap_or([0u8; 32]));
            h.update(d.last_progress_secs.unwrap_or(0).to_le_bytes());
            h.update(d.consecutive_proof_failures.to_le_bytes());
            h.update(d.latest_restake_share_ppm.to_le_bytes());
        }
        h.update((self.alerts.len() as u64).to_le_bytes());
        for alert in &self.alerts {
            h.update(alert.event_id);
        }
        h.finalize().into()
    }

    /// Render a deterministic line-oriented ASCII summary (`BAT-3`-style canonical
    /// key/value wire text) suitable for CLI, RPC, and cross-node diffs.
    ///
    /// Convenience: exposed for operator inspection and automated readiness gates.
    #[must_use]
    pub fn render_canonical_report(&self) -> String {
        let mut out = String::new();
        let root_hex = hex::encode(self.state_root());
        let _ = writeln!(out, "BDLM_SENTRY_V1");
        let _ = writeln!(out, "state_root={root_hex}");
        let _ = writeln!(out, "crqc_alarm={}", self.crqc_alarm_active);
        let _ = writeln!(out, "domains={}", self.domains.len());
        let _ = writeln!(out, "alerts={}", self.alerts.len());
        let _ = writeln!(out, "evicted_alerts={}", self.evicted_alert_count);
        for (id, d) in &self.domains {
            let h_str = d
                .last_height
                .map_or_else(|| "none".to_string(), |v| v.to_string());
            let _ = writeln!(
                out,
                "domain.{id}=circuit:{} family:{} height:{h_str} restake_ppm:{} pq_safe:{}",
                d.circuit.as_str(),
                d.policy.consensus_family,
                d.latest_restake_share_ppm,
                d.policy.quantum_posture.survives_crqc(),
            );
        }
        out
    }

    fn escalate_and_record(
        &mut self,
        domain_id: &str,
        observed_at_secs: u64,
        severity: SentrySeverity,
        kind: SentryFindingKind,
        action: SentryAction,
        target_state: SentryCircuitState,
    ) -> Option<SentryAlert> {
        let resulting_state = {
            let state = self.domains.get_mut(domain_id)?;
            if target_state > state.circuit {
                state.circuit = target_state;
                state.last_escalation_secs = Some(observed_at_secs);
            }
            state.circuit
        };
        let alert = SentryAlert::new(
            domain_id.to_string(),
            observed_at_secs,
            severity,
            kind,
            action,
            resulting_state,
        );
        if !self.seen_event_ids.insert(alert.event_id) {
            return None;
        }
        if self.alerts.len() >= MAX_SENTRY_EVENTS {
            let removed = self.alerts.remove(0);
            self.seen_event_ids.remove(&removed.event_id);
            self.evicted_alert_count = self.evicted_alert_count.saturating_add(1);
        }
        self.alerts.push(alert.clone());
        Some(alert)
    }
}

/// Canonical snapshot of all hard protocol, audit, CI, and operational criteria
/// required to declare Budlum Testnet launch-ready.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestnetReadinessSnapshot {
    /// Configured EVM chain ID (must equal `45261`).
    pub evm_chain_id: u64,
    /// Configured Aptos chain ID (must equal `205`).
    pub aptos_chain_id: u8,
    /// Configured Cosmos chain ID (must equal `"budlum-testnet-1"`).
    pub cosmos_chain_id: String,
    /// ML-DSA-65/87 + ML-KEM-768/1024 + SLH-DSA active on consensus core.
    pub pq_core_active: bool,
    /// Remaining entries in `.github/no-legacy-storage-baseline.txt` (must be `0`).
    pub legacy_storage_baseline_entries: u32,
    /// Admin backdoor or super-user bypass keys present (must be `0`).
    pub admin_key_count: u32,
    /// Slash amount applied for pure offline downtime (must be `0`).
    pub offline_slash_atoms: u64,
    /// Peak shared-security restaking concentration across all domains (`<= 300_000 ppm`).
    pub max_observed_restake_share_ppm: u32,
    /// All closed-at-testnet modules gated fail-closed.
    pub closed_testnet_features_gated: bool,
    /// All 140+ `budlum-gates` passing.
    pub static_gates_all_green: bool,
    /// All GitHub Actions CI workflows green on target branch.
    pub ci_all_green: bool,
    /// Open `CRITICAL` or `HIGH` security review defects (must be `0`).
    pub open_critical_or_high_findings: u32,
    /// Linux `x86_64` vs `aarch64` replay state root bit-identical.
    pub cross_arch_state_digest_equal: bool,
    /// At least 4 geographically independent validator Genesis rehearsal.
    pub genesis_rehearsal_passed: bool,
    /// Monitoring, alert routing, and incident runbook verified.
    pub monitoring_and_runbook_ready: bool,
    /// Independent external third-party security audit closed.
    pub external_audit_complete: bool,
    /// Number of watched domains currently frozen by `ConsensusSentry` (must be `0`).
    pub sentry_frozen_domains: u32,
}

/// Fail-closed result of `evaluate_testnet_readiness`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestnetLaunchVerdict {
    /// `true` if and only if `blockers` is completely empty.
    pub ready: bool,
    /// Ordered list of exact blocking gate identifiers and reasons.
    pub blockers: Vec<String>,
    /// Canonical 32-byte commitment over the evaluated snapshot and blockers.
    pub commitment: [u8; 32],
}

/// Deterministically interrogate `snapshot` against Budlum's non-negotiable
/// testnet readiness invariants. Any single unmet gate forces
/// `ready = false` and lists the exact blocker.
///
/// Convenience: exposed for release gates, Sentry pre-flight, and rehearsal tools.
#[must_use]
pub fn evaluate_testnet_readiness(snapshot: &TestnetReadinessSnapshot) -> TestnetLaunchVerdict {
    let mut blockers = Vec::new();

    if snapshot.evm_chain_id != CANONICAL_TESTNET_EVM_CHAIN_ID {
        blockers.push(format!(
            "CHAIN_ID: evm_chain_id={} != {CANONICAL_TESTNET_EVM_CHAIN_ID}",
            snapshot.evm_chain_id
        ));
    }
    if snapshot.aptos_chain_id != CANONICAL_TESTNET_APTOS_CHAIN_ID {
        blockers.push(format!(
            "CHAIN_ID: aptos_chain_id={} != {CANONICAL_TESTNET_APTOS_CHAIN_ID}",
            snapshot.aptos_chain_id
        ));
    }
    if snapshot.cosmos_chain_id != CANONICAL_TESTNET_COSMOS_CHAIN_ID {
        blockers.push(format!(
            "CHAIN_ID: cosmos_chain_id='{}' != '{CANONICAL_TESTNET_COSMOS_CHAIN_ID}'",
            snapshot.cosmos_chain_id
        ));
    }
    if !snapshot.pq_core_active {
        blockers.push("PQ_CORE: post-quantum core (ML-DSA/ML-KEM/SLH-DSA) is not active".into());
    }
    if snapshot.legacy_storage_baseline_entries > 0 {
        blockers.push(format!(
            "LEGACY_STORAGE: legacy storage baseline has {} remaining entries (expected 0)",
            snapshot.legacy_storage_baseline_entries
        ));
    }
    if snapshot.admin_key_count > 0 {
        blockers.push(format!(
            "ADMIN_KEYS: {} privileged admin key(s) present (expected 0)",
            snapshot.admin_key_count
        ));
    }
    if snapshot.offline_slash_atoms > 0 {
        blockers.push(format!(
            "OFFLINE_SLASH: offline downtime slashes {} atoms (expected 0)",
            snapshot.offline_slash_atoms
        ));
    }
    if snapshot.max_observed_restake_share_ppm > DEFAULT_MAX_RESTAKE_SHARE_PPM {
        blockers.push(format!(
            "RESTAKE_CAP: restake concentration {} ppm exceeds {DEFAULT_MAX_RESTAKE_SHARE_PPM} ppm cap",
            snapshot.max_observed_restake_share_ppm
        ));
    }
    if !snapshot.closed_testnet_features_gated {
        blockers.push("FEATURE_GATES: closed-at-testnet modules are not all gated".into());
    }
    if !snapshot.static_gates_all_green {
        blockers.push("STATIC_GATES: one or more static budlum-gates failed".into());
    }
    if !snapshot.ci_all_green {
        blockers.push("CI_STATUS: GitHub Actions CI is not completely green".into());
    }
    if snapshot.open_critical_or_high_findings > 0 {
        blockers.push(format!(
            "SECURITY_REVIEW: {} CRITICAL/HIGH security finding(s) remain open",
            snapshot.open_critical_or_high_findings
        ));
    }
    if !snapshot.cross_arch_state_digest_equal {
        blockers.push("CROSS_ARCH: x86_64 and aarch64 state digests are not verified equal".into());
    }
    if !snapshot.genesis_rehearsal_passed {
        blockers.push("GENESIS_REHEARSAL: multi-operator Genesis rehearsal not yet passed".into());
    }
    if !snapshot.monitoring_and_runbook_ready {
        blockers.push("MONITORING: monitoring alerts and incident runbook not verified".into());
    }
    if !snapshot.external_audit_complete {
        blockers
            .push("EXTERNAL_AUDIT: independent external security audit not yet completed".into());
    }
    if snapshot.sentry_frozen_domains > 0 {
        blockers.push(format!(
            "SENTRY: {} watched consensus domain(s) currently FROZEN",
            snapshot.sentry_frozen_domains
        ));
    }

    let ready = blockers.is_empty();
    let mut h = Sha256::new();
    update_lp(&mut h, DOMAIN_SENTRY_LAUNCH_VERDICT);
    h.update([u8::from(ready)]);
    h.update(snapshot.evm_chain_id.to_le_bytes());
    h.update([snapshot.aptos_chain_id]);
    update_lp(&mut h, snapshot.cosmos_chain_id.as_bytes());
    h.update((blockers.len() as u64).to_le_bytes());
    for b in &blockers {
        update_lp(&mut h, b.as_bytes());
    }
    let commitment: [u8; 32] = h.finalize().into();

    TestnetLaunchVerdict {
        ready,
        blockers,
        commitment,
    }
}

fn is_valid_identifier(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_DOMAIN_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_policy(posture: DomainQuantumPosture) -> SentryDomainPolicy {
        SentryDomainPolicy {
            consensus_family: "tendermint-bft-v1".into(),
            quantum_posture: posture,
            max_finality_stall_secs: 600,
            min_trusting_window_secs: 3_600,
            max_reorg_blocks: 0,
            max_consecutive_proof_failures: 3,
            max_restake_share_ppm: DEFAULT_MAX_RESTAKE_SHARE_PPM,
            recovery_cooldown_secs: 7_200,
        }
    }

    fn green_snapshot() -> TestnetReadinessSnapshot {
        TestnetReadinessSnapshot {
            evm_chain_id: CANONICAL_TESTNET_EVM_CHAIN_ID,
            aptos_chain_id: CANONICAL_TESTNET_APTOS_CHAIN_ID,
            cosmos_chain_id: CANONICAL_TESTNET_COSMOS_CHAIN_ID.into(),
            pq_core_active: true,
            legacy_storage_baseline_entries: 0,
            admin_key_count: 0,
            offline_slash_atoms: 0,
            max_observed_restake_share_ppm: 120_000,
            closed_testnet_features_gated: true,
            static_gates_all_green: true,
            ci_all_green: true,
            open_critical_or_high_findings: 0,
            cross_arch_state_digest_equal: true,
            genesis_rehearsal_passed: true,
            monitoring_and_runbook_ready: true,
            external_audit_complete: true,
            sentry_frozen_domains: 0,
        }
    }

    #[test]
    fn sentry_accepts_healthy_progression_and_commits_deterministic_root() {
        let mut a = ConsensusSentry::new();
        let mut b = ConsensusSentry::new();
        for s in [&mut a, &mut b] {
            s.register_domain(
                "hub:ics07",
                default_policy(DomainQuantumPosture::HybridPostQuantum),
            )
            .unwrap();
            let alerts = s
                .observe(&SentryObservation {
                    domain_id: "hub:ics07".into(),
                    height: 100,
                    state_root: [0x11; 32],
                    observed_at_secs: 1_000,
                    remaining_trust_window_secs: Some(86_400),
                    restake_share_ppm: 100_000,
                })
                .unwrap();
            assert!(alerts.is_empty());
            assert!(s.domain("hub:ics07").unwrap().circuit.accepts_settlement());
        }
        assert_eq!(a.state_root(), b.state_root());
        assert_eq!(a.render_canonical_report(), b.render_canonical_report());
    }

    #[test]
    fn sentry_freezes_domain_on_same_height_conflicting_root_and_preserves_anchor() {
        let mut sentry = ConsensusSentry::new();
        sentry
            .register_domain(
                "hub:ics07",
                default_policy(DomainQuantumPosture::HybridPostQuantum),
            )
            .unwrap();
        sentry
            .observe(&SentryObservation {
                domain_id: "hub:ics07".into(),
                height: 500,
                state_root: [0xAA; 32],
                observed_at_secs: 10_000,
                remaining_trust_window_secs: Some(50_000),
                restake_share_ppm: 50_000,
            })
            .unwrap();

        let alerts = sentry
            .observe(&SentryObservation {
                domain_id: "hub:ics07".into(),
                height: 500,
                state_root: [0xBB; 32],
                observed_at_secs: 10_010,
                remaining_trust_window_secs: Some(49_990),
                restake_share_ppm: 50_000,
            })
            .unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, SentrySeverity::Critical);
        assert_eq!(alerts[0].action, SentryAction::FreezeDomainAndSlash);
        let d = sentry.domain("hub:ics07").unwrap();
        assert_eq!(d.circuit, SentryCircuitState::Frozen);
        assert!(!d.circuit.accepts_settlement());
        assert_eq!(d.last_state_root, Some([0xAA; 32]));
        assert_eq!(sentry.frozen_domain_count(), 1);

        // Duplicate replay of the exact conflicting observation is suppressed.
        let dup = sentry
            .observe(&SentryObservation {
                domain_id: "hub:ics07".into(),
                height: 500,
                state_root: [0xBB; 32],
                observed_at_secs: 10_010,
                remaining_trust_window_secs: Some(49_990),
                restake_share_ppm: 50_000,
            })
            .unwrap();
        assert!(dup.is_empty());
    }

    #[test]
    fn sentry_distinguishes_shallow_pow_reorg_from_deep_reorg_freeze() {
        let mut policy = default_policy(DomainQuantumPosture::PurePostQuantum);
        policy.consensus_family = "bitcoin-spv-v1".into();
        policy.min_trusting_window_secs = 0;
        policy.max_reorg_blocks = 2;

        let mut sentry = ConsensusSentry::new();
        sentry.register_domain("btc:mainnet", policy).unwrap();
        sentry
            .observe(&SentryObservation {
                domain_id: "btc:mainnet".into(),
                height: 850_010,
                state_root: [0x21; 32],
                observed_at_secs: 2_000,
                remaining_trust_window_secs: None,
                restake_share_ppm: 0,
            })
            .unwrap();

        // 2-block rollback -> Halted (within max_reorg_blocks = 2).
        let shallow = sentry
            .observe(&SentryObservation {
                domain_id: "btc:mainnet".into(),
                height: 850_008,
                state_root: [0x22; 32],
                observed_at_secs: 2_100,
                remaining_trust_window_secs: None,
                restake_share_ppm: 0,
            })
            .unwrap();
        assert_eq!(shallow[0].resulting_state, SentryCircuitState::Halted);

        // 6-block rollback -> Frozen (exceeds max_reorg_blocks = 2).
        let deep = sentry
            .observe(&SentryObservation {
                domain_id: "btc:mainnet".into(),
                height: 850_004,
                state_root: [0x23; 32],
                observed_at_secs: 2_200,
                remaining_trust_window_secs: None,
                restake_share_ppm: 0,
            })
            .unwrap();
        assert_eq!(deep[0].severity, SentrySeverity::Critical);
        assert_eq!(deep[0].resulting_state, SentryCircuitState::Frozen);
    }

    #[test]
    fn sentry_enforces_trusting_window_liveness_proof_failure_and_restake_caps() {
        let mut sentry = ConsensusSentry::new();
        sentry
            .register_domain(
                "osmosis:ics07",
                default_policy(DomainQuantumPosture::HybridPostQuantum),
            )
            .unwrap();

        // Low trusting window + restake warning -> Throttled.
        let a1 = sentry
            .observe(&SentryObservation {
                domain_id: "osmosis:ics07".into(),
                height: 10,
                state_root: [0x31; 32],
                observed_at_secs: 5_000,
                remaining_trust_window_secs: Some(1_200),
                restake_share_ppm: 310_000,
            })
            .unwrap();
        assert_eq!(a1.len(), 2);
        assert_eq!(
            sentry.domain("osmosis:ics07").unwrap().circuit,
            SentryCircuitState::Throttled
        );

        // 3 consecutive proof failures -> Halted.
        assert!(sentry
            .record_proof_failure("osmosis:ics07", 5_010)
            .unwrap()
            .is_none());
        assert!(sentry
            .record_proof_failure("osmosis:ics07", 5_020)
            .unwrap()
            .is_none());
        let halt = sentry
            .record_proof_failure("osmosis:ics07", 5_030)
            .unwrap()
            .expect("3rd proof rejection must halt");
        assert_eq!(halt.resulting_state, SentryCircuitState::Halted);

        // Liveness poll after > 600s silence emits FinalityStall.
        let stall = sentry.check_liveness(6_000);
        assert_eq!(stall.len(), 1);
        assert!(matches!(
            stall[0].kind,
            SentryFindingKind::FinalityStall { .. }
        ));

        // Restake share crossing 1/3 BFT cliff -> Frozen.
        let freeze = sentry
            .observe(&SentryObservation {
                domain_id: "osmosis:ics07".into(),
                height: 11,
                state_root: [0x32; 32],
                observed_at_secs: 6_010,
                remaining_trust_window_secs: Some(10_000),
                restake_share_ppm: BFT_CORRUPTION_CEILING_PPM,
            })
            .unwrap();
        assert!(freeze
            .iter()
            .any(|a| a.resulting_state == SentryCircuitState::Frozen));
    }

    #[test]
    fn sentry_crqc_alarm_isolates_classical_domains_while_pq_domains_stay_open() {
        let mut sentry = ConsensusSentry::new();
        sentry
            .register_domain(
                "eth:bls",
                default_policy(DomainQuantumPosture::ClassicalOnly),
            )
            .unwrap();
        sentry
            .register_domain(
                "hub:hybrid",
                default_policy(DomainQuantumPosture::HybridPostQuantum),
            )
            .unwrap();
        sentry
            .register_domain(
                "zk:plonky3",
                default_policy(DomainQuantumPosture::PurePostQuantum),
            )
            .unwrap();

        let alerts = sentry.activate_crqc_alarm(20_000);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].domain_id, "eth:bls");
        assert_eq!(
            sentry.domain("eth:bls").unwrap().circuit,
            SentryCircuitState::Frozen
        );
        assert_eq!(
            sentry.domain("hub:hybrid").unwrap().circuit,
            SentryCircuitState::Open
        );
        assert_eq!(
            sentry.domain("zk:plonky3").unwrap().circuit,
            SentryCircuitState::Open
        );

        // Classical domain cannot be recovered while CRQC alarm remains active.
        assert_eq!(
            sentry.recover_after_governance_cooldown("eth:bls", 99_999, None),
            Err(SentryError::CrqcAlarmBlocksClassicalRecovery)
        );
    }

    #[test]
    fn sentry_governance_recovery_enforces_cooldown_window() {
        let mut sentry = ConsensusSentry::new();
        sentry
            .register_domain(
                "aptos:bft",
                default_policy(DomainQuantumPosture::HybridPostQuantum),
            )
            .unwrap();
        sentry
            .observe(&SentryObservation {
                domain_id: "aptos:bft".into(),
                height: 1,
                state_root: [0x41; 32],
                observed_at_secs: 1_000,
                remaining_trust_window_secs: Some(10_000),
                restake_share_ppm: 0,
            })
            .unwrap();
        sentry
            .observe(&SentryObservation {
                domain_id: "aptos:bft".into(),
                height: 1,
                state_root: [0x42; 32],
                observed_at_secs: 1_100,
                remaining_trust_window_secs: Some(10_000),
                restake_share_ppm: 0,
            })
            .unwrap();

        assert_eq!(
            sentry.recover_after_governance_cooldown("aptos:bft", 8_299, None),
            Err(SentryError::RecoveryCooldownActive {
                ready_at_secs: 8_300,
                now_secs: 8_299,
            })
        );
        sentry
            .recover_after_governance_cooldown("aptos:bft", 8_300, Some((2, [0x43; 32])))
            .unwrap();
        assert_eq!(
            sentry.domain("aptos:bft").unwrap().circuit,
            SentryCircuitState::Open
        );
    }

    #[test]
    fn sentry_refuses_policy_above_restake_ceiling_and_invalid_inputs() {
        let mut bad = default_policy(DomainQuantumPosture::PurePostQuantum);
        bad.max_restake_share_ppm = DEFAULT_MAX_RESTAKE_SHARE_PPM + 1;
        let mut sentry = ConsensusSentry::new();
        assert!(matches!(
            sentry.register_domain("bad", bad),
            Err(SentryError::InvalidPolicy(_))
        ));
        assert!(matches!(
            sentry.register_domain(
                "bad space",
                default_policy(DomainQuantumPosture::PurePostQuantum)
            ),
            Err(SentryError::InvalidIdentifier("domain_id"))
        ));
    }

    #[test]
    fn testnet_readiness_evaluator_fails_closed_on_every_unmet_launch_gate() {
        let ok = evaluate_testnet_readiness(&green_snapshot());
        assert!(ok.ready);
        assert!(ok.blockers.is_empty());

        let mut blocked = green_snapshot();
        blocked.legacy_storage_baseline_entries = 93;
        blocked.ci_all_green = false;
        blocked.open_critical_or_high_findings = 1;
        blocked.genesis_rehearsal_passed = false;
        blocked.external_audit_complete = false;
        blocked.sentry_frozen_domains = 1;

        let verdict = evaluate_testnet_readiness(&blocked);
        assert!(!verdict.ready);
        assert_eq!(verdict.blockers.len(), 6);
        assert_ne!(verdict.commitment, ok.commitment);
        assert!(verdict
            .blockers
            .iter()
            .any(|b| b.starts_with("LEGACY_STORAGE:")));
        assert!(verdict.blockers.iter().any(|b| b.starts_with("CI_STATUS:")));
        assert!(verdict
            .blockers
            .iter()
            .any(|b| b.starts_with("SECURITY_REVIEW:")));
        assert!(verdict
            .blockers
            .iter()
            .any(|b| b.starts_with("GENESIS_REHEARSAL:")));
        assert!(verdict
            .blockers
            .iter()
            .any(|b| b.starts_with("EXTERNAL_AUDIT:")));
        assert!(verdict.blockers.iter().any(|b| b.starts_with("SENTRY:")));
    }
}
