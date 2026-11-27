//! Single finality decision point shared by every cross-domain value gate.
//!
//! Instead of each value-moving subsystem re-implementing its own finality
//! heuristic, every gate routes through this module:
//! - bridge mint and unlock (`crate::cross_domain::bridge_tx`),
//! - relayer intent settlement (`crate::settlement::domains`),
//! - app-binding claims (`crate::settlement::app_binding`),
//! - object-layer arrivals (`crate::settlement::domains`),
//! - universal payment routing (`crate::unification`), and
//! - wallet route preflight queries (`crate::rpc::server`).

use std::fmt;

use crate::cross_domain::external::phase_a_dual::{classify_root_proof_status, RootProofStatus};
use crate::settlement::registries::SettlementRegistries;
use crate::settlement::universal_finality::{
    compose_cross_domain_route, EconomicSecurityBound, FinalityBinds, FinalityBucket,
    FinalityGuarantee, FinalityPendingReason, FinalityVerdict, GlobalFinalityCertificate,
    RouteFinalityBound,
};

/// Minimum batch-proof liveness level required by a value gate.
///
/// Liveness does not depend on the prover: when the prover lags behind
/// finalized voted blocks, `VotedOnly` gates continue to settle while
/// `ProvenRequired` gates wait until `proven_height` catches up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofRequirement {
    /// Voted finality suffices; proceeds while batch proving is `PendingProof`
    /// or `DelayExceeded`.
    VotedOnly,
    /// Requires `RootProofStatus::Proven` (`block_height <= proven_height`);
    /// refuses while `PendingProof` or `DelayExceeded`.
    ProvenRequired,
}

/// Parameters for enforcing batch-proof liveness on a value gate decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofLivenessCheck {
    /// Finalized block height inspected by the gate.
    pub block_height: u64,
    /// Latest height covered by an anchored aggregate proof.
    pub proven_height: u64,
    /// Whether voted finality suffices or a proven root is required.
    pub requirement: ProofRequirement,
}

/// Value-carrying settlement gate requesting a finality decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueGate {
    /// Bridge supply mint on Budlum from a verified external lock event.
    BridgeMint,
    /// Bridge supply unlock on Budlum from a verified external burn event.
    BridgeUnlock,
    /// Relayer intent fee payout against a verified external execution result.
    RelayerIntentSettle,
    /// App-binding payout claim anchored to an origin domain event.
    AppBindingClaim,
    /// Universal object-layer asset arrival from a home domain.
    ObjectLayerArrive,
    /// Multi-domain universal payment routing across the settlement hub.
    UniversalPayment,
}

impl ValueGate {
    /// Binding floor owned by the value-moving operation, not by its caller.
    /// Additional caller demands may strengthen this floor, never lower it.
    const fn required_binds(self) -> FinalityBinds {
        match self {
            Self::BridgeMint
            | Self::BridgeUnlock
            | Self::RelayerIntentSettle
            | Self::AppBindingClaim
            | Self::ObjectLayerArrive
            | Self::UniversalPayment => FinalityBinds::EVENT_ROOT,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::BridgeMint => "bridge-mint",
            Self::BridgeUnlock => "bridge-unlock",
            Self::RelayerIntentSettle => "relayer-intent-settle",
            Self::AppBindingClaim => "app-binding-claim",
            Self::ObjectLayerArrive => "object-layer-arrive",
            Self::UniversalPayment => "universal-payment",
        }
    }
}

/// Fail-closed refusal produced by the single finality decision gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueGateRefusal {
    /// No consensus domains are registered, so no finality certificate exists.
    CertificateUnavailable,
    /// The value move requires commitments its rows do not carry.
    ///
    /// `compose` fixes a floor: an `Established` row binds `FINALITY_BINDS_ALL`.
    /// That floor is about *entering* a certificate. A value move has its own
    /// requirement - a bridge mint needs the event root, a bare balance
    /// statement does not - and stating it is how the requirement is checked
    /// against the row instead of assumed from the flag.
    RequiredBindMissing {
        /// Domain whose row lacks a required commitment.
        domain_id: u32,
        /// Required commitments, as a bit set.
        required_binds: FinalityBinds,
        /// Commitments the row carries, as a bit set.
        present_binds: FinalityBinds,
    },
    /// The certificate does not re-derive from its own rows: it was built by
    /// hand instead of by [`crate::settlement::universal_finality::compose`].
    ///
    /// `compose` is the only place an `Established` row's commitment bindings
    /// are checked (`FINALITY_BINDS_ALL` and positive fault tolerance). The rows
    /// and the certificate carry public fields, so a caller can assemble one
    /// that never went through `compose` and hand it to this gate; the bindings
    /// would then be unchecked while every downstream check still passes.
    CertificateNotDerived,
    /// The domain's declared quantum posture does not survive an active CRQC
    /// alarm, and the value gate was asked to move value across it.
    ///
    /// `ConsensusSentry` tracks `DomainQuantumPosture` and freezes a
    /// classical-only domain once the alarm is raised. That was a separate call:
    /// a caller that skipped `enforce_sentry_circuit_clear` moved value under a
    /// posture nobody checked. The posture is now a parameter of the gate.
    QuantumPostureUnfit {
        /// Domain whose posture does not survive the alarm.
        domain_id: u32,
        /// Canonical posture label.
        posture: String,
    },
    /// Required domain is not present in the checkpoint certificate.
    DomainMissing {
        /// Missing domain identifier.
        domain_id: u32,
    },
    /// Domain is in the `Refuted` bucket and cannot move value.
    DomainRefuted {
        /// Refuted domain identifier.
        domain_id: u32,
        /// Rejection code carried by the certificate row.
        code: u16,
    },
    /// Domain is still in the `Pending` bucket and cannot move value.
    DomainPending {
        /// Pending domain identifier.
        domain_id: u32,
        /// Pending reason carried by the certificate row.
        reason: FinalityPendingReason,
    },
    /// Consensus Sentry circuit breaker escalated this domain out of `Open`.
    SentryCircuitEscalated {
        /// Value gate that refused settlement.
        gate: ValueGate,
        /// Domain whose Sentry circuit is escalated.
        domain_id: u32,
        /// Canonical uppercase circuit label (`THROTTLED`, `HALTED`, `FROZEN`).
        circuit: &'static str,
    },
    /// Composed route guarantee fails `admits_cross_domain_value` or has zero fault tolerance.
    RouteFinalityInsufficient {
        /// Source domain identifier.
        source_domain: u32,
        /// Optional target domain identifier.
        target_domain: Option<u32>,
        /// Deterministic human-readable guarantee label of the insufficient route.
        label: String,
    },
    /// Value gate requires a proven block root (`block_height <= proven_height`),
    /// but the prover has not yet covered `block_height`.
    ProofPending {
        /// Finalized block height inspected by the gate.
        block_height: u64,
        /// Latest height covered by an anchored aggregate proof.
        proven_height: u64,
        /// Exact `RootProofStatus` lag classification (`PendingProof` or `DelayExceeded`).
        status: RootProofStatus,
    },
}

impl fmt::Display for ValueGateRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CertificateUnavailable => {
                write!(f, "universal finality certificate is unavailable")
            }
            Self::DomainMissing { domain_id } => {
                write!(f, "domain {domain_id} is absent from the finality certificate")
            }
            Self::RequiredBindMissing {
                domain_id,
                required_binds,
                present_binds,
            } => write!(
                f,
                "domain {domain_id} binds {present_binds} but this move requires {required_binds}"
            ),
            Self::CertificateNotDerived => write!(
                f,
                "the certificate does not re-derive from its rows (compose was bypassed): \
                 an Established row would skip the commitment-binding check"
            ),
            Self::QuantumPostureUnfit { domain_id, posture } => write!(
                f,
                "domain {domain_id} declares quantum posture {posture}, which does not \
                 survive an active CRQC alarm"
            ),
            Self::DomainRefuted { domain_id, code } => write!(
                f,
                "domain {domain_id} is refuted in the finality certificate (code {code})"
            ),
            Self::DomainPending { domain_id, reason } => write!(
                f,
                "domain {domain_id} is pending in the finality certificate ({reason:?})"
            ),
            Self::SentryCircuitEscalated {
                gate,
                domain_id,
                circuit,
            } => write!(
                f,
                "{} refused: consensus sentry circuit for domain {domain_id} is {circuit}",
                gate.as_str()
            ),
            Self::RouteFinalityInsufficient {
                source_domain,
                target_domain,
                label,
            } => write!(
                f,
                "route finality insufficient for source {source_domain} -> {target_domain:?} ({label})"
            ),
            Self::ProofPending {
                block_height,
                proven_height,
                status,
            } => write!(
                f,
                "value gate waiting for aggregate proof at height {block_height} (proven_height={proven_height}, status={status:?})"
            ),
        }
    }
}

/// Certified value-transfer verdict returned when a route passes the single
/// finality gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueGateVerdict {
    /// Gate that requested the check.
    pub gate: ValueGate,
    /// Source domain identifier.
    pub source_domain: u32,
    /// Target domain identifier (`None` when terminating at the settlement hub).
    pub target_domain: Option<u32>,
    /// Weakest-link route bound computed by [`compose_cross_domain_route`].
    pub route: RouteFinalityBound,
    /// Weakest-link composed guarantee across the route.
    pub guarantee: FinalityGuarantee,
    /// Deterministic human-readable label of [`Self::guarantee`].
    pub guarantee_label: String,
    /// Certificate bucket of the source domain (`FinalityBucket::Established`).
    pub source_bucket: FinalityBucket,
    /// Safe per-epoch cross-domain value outflow ceiling in atoms.
    pub safe_value_outflow_ceiling_atoms: u128,
}

/// Compose and admit a cross-domain value route through [`compose_cross_domain_route`]
/// and [`FinalityGuarantee::admits_cross_domain_value`].
///
/// Returns `Some(route)` only when both the source and target domain
/// guarantees admit cross-domain value transfer, the composed weakest-link
/// route admits transfer, and the bottleneck fault tolerance is strictly
/// positive.
#[must_use]
pub fn evaluate_route_guarantee(
    source: &FinalityGuarantee,
    hub: &FinalityGuarantee,
    target: &FinalityGuarantee,
) -> Option<RouteFinalityBound> {
    let route = compose_cross_domain_route(source, hub, target);
    if !source.admits_cross_domain_value()
        || !target.admits_cross_domain_value()
        || !route.source_admits_value_transfer
        || route.bottleneck_fault_tolerance_bps == 0
    {
        return None;
    }
    Some(route)
}

/// Evaluate whether `gate` may move value out of `source_domain` (optionally
/// into `target_domain`) using strictly the derived [`GlobalFinalityCertificate`].
///
/// Fails closed if either domain is missing, `Pending`, or `Refuted`, or if
/// [`evaluate_route_guarantee`] rejects the weakest-link composed guarantee.
///
/// The caller may request additional bindings, but cannot lower the minimum
/// required by the value-moving operation.
///
/// # Errors
///
/// Returns [`ValueGateRefusal`] describing the exact certificate or route
/// invariant that blocked value transfer.
pub fn check_certificate_value_gate(
    cert: &GlobalFinalityCertificate,
    sentry: &crate::cross_domain::external::sentry::ConsensusSentry,
    gate: ValueGate,
    source_domain: u32,
    target_domain: Option<u32>,
    required_binds: FinalityBinds,
) -> Result<ValueGateVerdict, ValueGateRefusal> {
    // The bindings check lives in `compose`, not here. A certificate whose rows
    // were assembled by hand never passes through it, so the gate re-derives the
    // certificate from its own rows before reading a single verdict.
    cert.verify_integrity()
        .map_err(|_| ValueGateRefusal::CertificateNotDerived)?;
    // The quantum posture is a parameter of the decision, not a separate call.
    enforce_quantum_posture(sentry, source_domain)?;
    if let Some(dst) = target_domain {
        enforce_quantum_posture(sentry, dst)?;
    }
    let src = cert
        .prove_domain(source_domain)
        .ok_or(ValueGateRefusal::DomainMissing {
            domain_id: source_domain,
        })?;
    match src.entry.verdict {
        FinalityVerdict::Established => {}
        FinalityVerdict::Refuted { code } => {
            return Err(ValueGateRefusal::DomainRefuted {
                domain_id: source_domain,
                code,
            });
        }
        FinalityVerdict::Pending { reason } => {
            return Err(ValueGateRefusal::DomainPending {
                domain_id: source_domain,
                reason,
            });
        }
    }

    // What this move requires, checked against what the row carries. Placed
    // after the verdict reads so a pending or refuted domain is refused with
    // the more precise reason rather than with a binding complaint.
    let required_binds = gate.required_binds().union(required_binds);
    enforce_required_binds(cert, source_domain, required_binds)?;
    if let Some(dst) = target_domain {
        enforce_required_binds(cert, dst, required_binds)?;
    }

    let hub = FinalityGuarantee::settlement_hub();
    let (target_guarantee, target_econ_ceiling) = match target_domain {
        Some(dst_id) => {
            let dst = cert
                .prove_domain(dst_id)
                .ok_or(ValueGateRefusal::DomainMissing { domain_id: dst_id })?;
            match dst.entry.verdict {
                FinalityVerdict::Established => {}
                FinalityVerdict::Refuted { code } => {
                    return Err(ValueGateRefusal::DomainRefuted {
                        domain_id: dst_id,
                        code,
                    });
                }
                FinalityVerdict::Pending { reason } => {
                    return Err(ValueGateRefusal::DomainPending {
                        domain_id: dst_id,
                        reason,
                    });
                }
            }
            let dst_econ = EconomicSecurityBound::derive(
                &dst.entry.guarantee,
                dst.entry.bond_atoms,
                dst.entry.bond_atoms,
            );
            (
                dst.entry.guarantee,
                dst_econ.safe_value_outflow_ceiling_atoms,
            )
        }
        None => (hub, u128::MAX),
    };

    let composed = src.entry.guarantee.meet(&hub).meet(&target_guarantee);
    let Some(route) = evaluate_route_guarantee(&src.entry.guarantee, &hub, &target_guarantee)
    else {
        return Err(ValueGateRefusal::RouteFinalityInsufficient {
            source_domain,
            target_domain,
            label: composed.label(),
        });
    };
    let src_econ = EconomicSecurityBound::derive(
        &src.entry.guarantee,
        src.entry.bond_atoms,
        src.entry.bond_atoms,
    );
    let safe_ceiling = src_econ
        .safe_value_outflow_ceiling_atoms
        .min(target_econ_ceiling);
    Ok(ValueGateVerdict {
        gate,
        source_domain,
        target_domain,
        route,
        guarantee: composed,
        guarantee_label: composed.label(),
        source_bucket: src.bucket,
        safe_value_outflow_ceiling_atoms: safe_ceiling,
    })
}

/// Check the commitments a value move requires against the ones its rows carry.
///
/// The requirement is a bit set, not a boolean: requiring every commitment
/// everywhere would be simple and would refuse sound routes, and requiring none
/// would make the check decorative. `0` means "this move makes no binding
/// demand", and then nothing is refused.
///
/// A domain absent from the certificate is not refused here - `prove_domain`
/// already refuses it with a more precise reason, and two checks racing to
/// report the same domain would make the refusal depend on call order.
///
/// # Errors
///
/// Returns [`ValueGateRefusal::RequiredBindMissing`] naming both bit sets when
/// the row is present and under-bound.
/// WIRING: production path is `check_certificate_value_gate` (CLI `bud` and the
/// RPC value gate call it; this helper is the binds half of that door).
pub fn enforce_required_binds(
    cert: &GlobalFinalityCertificate,
    domain_id: u32,
    required_binds: FinalityBinds,
) -> Result<(), ValueGateRefusal> {
    if required_binds.is_empty() {
        return Ok(());
    }
    // `prove_domain` returns an inclusion proof, not the row: the fields live
    // behind `entry`.
    let Some(proof) = cert.prove_domain(domain_id) else {
        return Ok(());
    };
    if !proof.entry.binds.covers(required_binds) {
        return Err(ValueGateRefusal::RequiredBindMissing {
            domain_id,
            required_binds,
            present_binds: proof.entry.binds,
        });
    }
    Ok(())
}

/// Refuse value transfer across a domain whose declared quantum posture does
/// not survive the sentry's active CRQC alarm.
///
/// The sentry freezes such a domain on its own circuit, and
/// [`enforce_sentry_circuit_clear`] refuses it when the caller remembers to ask.
/// This asks the same question as part of the value decision, so the route
/// arithmetic is unreachable without it.
///
/// A domain the sentry does not watch has no declared posture and is admitted
/// here: the sentry is not the registry of record, and the certificate's own
/// `guarantee.quantum_posture` still folds into the route meet.
///
/// # Errors
///
/// Returns [`ValueGateRefusal::QuantumPostureUnfit`] when the alarm is active and
/// the watched domain's posture does not `survive_crqc`.
/// WIRING: production path is `check_certificate_value_gate` (CLI `bud` and the
/// RPC value gate call it; this helper is the posture half of that door).
pub fn enforce_quantum_posture(
    sentry: &crate::cross_domain::external::sentry::ConsensusSentry,
    domain_id: u32,
) -> Result<(), ValueGateRefusal> {
    if !sentry.crqc_alarm_active() {
        return Ok(());
    }
    let key = crate::cross_domain::external::sentry::ConsensusSentry::domain_key_for_id(domain_id);
    if let Some(watched) = sentry.domain(&key) {
        if !watched.policy.quantum_posture.survives_crqc() {
            return Err(ValueGateRefusal::QuantumPostureUnfit {
                domain_id,
                posture: format!("{:?}", watched.policy.quantum_posture),
            });
        }
    }
    Ok(())
}

/// Evaluate a value gate with explicit batch-proof liveness enforcement.
///
/// Under `ProofRequirement::VotedOnly`, the gate succeeds whenever the
/// finality certificate, sentry quantum posture, and required binds pass,
/// even if the prover is behind (`PendingProof` or `DelayExceeded`),
/// preserving chain liveness.
/// Under `ProofRequirement::ProvenRequired`, the gate refuses with
/// `ValueGateRefusal::ProofPending` until `proven_height >= block_height`.
///
/// # Errors
///
/// Returns `ValueGateRefusal` if the finality certificate rejects the route
/// or if `requirement == ProofRequirement::ProvenRequired` while
/// `block_height > proven_height`.
pub fn check_certificate_value_gate_with_proof_level(
    cert: &GlobalFinalityCertificate,
    sentry: &crate::cross_domain::external::sentry::ConsensusSentry,
    gate: ValueGate,
    source_domain: u32,
    target_domain: Option<u32>,
    required_binds: FinalityBinds,
    liveness: ProofLivenessCheck,
) -> Result<ValueGateVerdict, ValueGateRefusal> {
    let verdict = check_certificate_value_gate(
        cert,
        sentry,
        gate,
        source_domain,
        target_domain,
        required_binds,
    )?;
    if liveness.requirement == ProofRequirement::ProvenRequired {
        let status = classify_root_proof_status(liveness.block_height, liveness.proven_height);
        if status != RootProofStatus::Proven {
            return Err(ValueGateRefusal::ProofPending {
                block_height: liveness.block_height,
                proven_height: liveness.proven_height,
                status,
            });
        }
    }
    Ok(verdict)
}

/// Refuse any value-moving gate whose `domain_id` is in the certificate's
/// `Refuted` bucket at `checkpoint_height`.
///
/// # Errors
///
/// Returns [`ValueGateRefusal::DomainRefuted`] when `domain_id` is refuted in
/// the derived [`GlobalFinalityCertificate`].
pub fn enforce_domain_not_refuted(
    registries: &SettlementRegistries,
    checkpoint_height: u64,
    gate: ValueGate,
    domain_id: u32,
) -> Result<(), ValueGateRefusal> {
    let Some(cert) = registries.universal_finality_certificate(checkpoint_height) else {
        return Ok(());
    };
    if let Some(proof) = cert.prove_domain(domain_id) {
        match proof.entry.verdict {
            FinalityVerdict::Refuted { code } => {
                let _ = gate.as_str();
                return Err(ValueGateRefusal::DomainRefuted { domain_id, code });
            }
            FinalityVerdict::Pending {
                reason:
                    reason @ (FinalityPendingReason::AttestationUnbound
                    | FinalityPendingReason::RuleNotSatisfied
                    | FinalityPendingReason::BondUnverified),
            } => {
                let _ = gate.as_str();
                return Err(ValueGateRefusal::DomainPending { domain_id, reason });
            }
            FinalityVerdict::Pending {
                reason: FinalityPendingReason::EvidenceMissing,
            } => {
                // If the domain already claims a non-zero committed height but
                // lacks a bound commitment/state root, refuse fail-closed.
                if proof.entry.height > 0 {
                    let _ = gate.as_str();
                    return Err(ValueGateRefusal::DomainPending {
                        domain_id,
                        reason: FinalityPendingReason::EvidenceMissing,
                    });
                }
            }
            FinalityVerdict::Established => {}
        }
    }
    Ok(())
}

/// Fail-closed check against the deterministic [`crate::cross_domain::external::sentry::ConsensusSentry`]
/// circuit breaker for `domain_id`.
///
/// Whenever Sentry has registered `domain_id` and escalated its circuit out of
/// `Open` (`Throttled`, `Halted`, or `Frozen`), value settlement is refused
/// immediately in that block without any admin override.
///
/// # Errors
///
/// Returns [`ValueGateRefusal::SentryCircuitEscalated`] when Sentry blocks
/// settlement for `domain_id`.
pub fn enforce_sentry_circuit_clear(
    sentry: &crate::cross_domain::external::sentry::ConsensusSentry,
    gate: ValueGate,
    domain_id: u32,
) -> Result<(), ValueGateRefusal> {
    let key = crate::cross_domain::external::sentry::ConsensusSentry::domain_key_for_id(domain_id);
    if let Some(watched) = sentry.domain(&key) {
        if !watched.circuit.accepts_settlement() {
            return Err(ValueGateRefusal::SentryCircuitEscalated {
                gate,
                domain_id,
                circuit: watched.circuit.label(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::facts::QuantumClass;
    use crate::settlement::universal_finality::{
        compose, DomainFinalityEntry, FinalityBinds, FinalityComposeError, FinalityReversibility,
        FINALITY_BINDS_ALL,
    };

    /// A certificate above the threshold needs no sentry: with no alarm the
    /// posture question is not asked. This helper represents an *out of scope* sentry.
    fn empty_sentry() -> crate::cross_domain::external::sentry::ConsensusSentry {
        crate::cross_domain::external::sentry::ConsensusSentry::new()
    }

    /// Single-domain certificate above the threshold.
    fn single_domain_cert(id: u32) -> GlobalFinalityCertificate {
        compose(&[entry(
            id,
            FinalityReversibility::CryptographicValidity,
            true,
            5_000,
            FinalityVerdict::Established,
        )])
        .expect("compose established certificate")
    }

    fn entry(
        id: u32,
        reversibility: FinalityReversibility,
        slashable: bool,
        bps: u16,
        verdict: FinalityVerdict,
    ) -> DomainFinalityEntry {
        DomainFinalityEntry {
            domain_id: id,
            height: 50 + u64::from(id),
            checkpoint_height: 100,
            state_root: [u8::try_from(id).unwrap_or(1); 32],
            adapter_id: "pow-header-v1".to_owned(),
            adapter_version: 1,
            finality_proof_hash: [0x11; 32],
            guarantee_backing_hash: [0x22; 32],
            bond_atoms: 10_000_000,
            binds: FinalityBinds::ALL,
            guarantee: FinalityGuarantee {
                reversibility,
                quantum_posture: QuantumClass::Hash,
                attestation: FINALITY_BINDS_ALL,
                slashable_backing: slashable,
                fault_tolerance_bps: bps,
            },
            verdict,
        }
    }

    #[test]
    fn single_gate_admits_established_value_routes_and_refuses_pending_refuted_or_weak() {
        let cert = compose(&[
            entry(
                1,
                FinalityReversibility::ProbabilisticWork { confirmations: 6 },
                false,
                4_999,
                FinalityVerdict::Established,
            ),
            entry(
                2,
                FinalityReversibility::CryptographicValidity,
                false,
                9_999,
                FinalityVerdict::Established,
            ),
            entry(
                3,
                FinalityReversibility::DeterministicQuorum,
                true,
                3_333,
                FinalityVerdict::Pending {
                    reason: FinalityPendingReason::EvidenceMissing,
                },
            ),
            entry(
                4,
                FinalityReversibility::DeterministicQuorum,
                true,
                3_333,
                FinalityVerdict::Refuted { code: 1 },
            ),
            entry(
                5,
                FinalityReversibility::DeterministicQuorum,
                false,
                3_333,
                FinalityVerdict::Established,
            ),
        ])
        .expect("compose cert");

        // All 6 gate labels admit an Established value-admitting route (1 -> 2).
        for gate in [
            ValueGate::BridgeMint,
            ValueGate::BridgeUnlock,
            ValueGate::RelayerIntentSettle,
            ValueGate::AppBindingClaim,
            ValueGate::ObjectLayerArrive,
            ValueGate::UniversalPayment,
        ] {
            let verdict = check_certificate_value_gate(
                &cert,
                &empty_sentry(),
                gate,
                1,
                Some(2),
                FinalityBinds::NONE,
            )
            .expect("established value route must pass");
            assert_eq!(verdict.gate, gate);
            assert_eq!(verdict.source_bucket, FinalityBucket::Established);
            assert!(verdict.safe_value_outflow_ceiling_atoms > 0);
        }

        // Pending domain is refused.
        assert!(matches!(
            check_certificate_value_gate(
                &cert,
                &empty_sentry(),
                ValueGate::BridgeMint,
                3,
                Some(2),
                FinalityBinds::NONE
            ),
            Err(ValueGateRefusal::DomainPending { domain_id: 3, .. })
        ));
        assert!(matches!(
            check_certificate_value_gate(
                &cert,
                &empty_sentry(),
                ValueGate::UniversalPayment,
                1,
                Some(3),
                FinalityBinds::NONE
            ),
            Err(ValueGateRefusal::DomainPending { domain_id: 3, .. })
        ));

        // Refuted domain is refused.
        assert!(matches!(
            check_certificate_value_gate(
                &cert,
                &empty_sentry(),
                ValueGate::AppBindingClaim,
                4,
                None,
                FinalityBinds::NONE
            ),
            Err(ValueGateRefusal::DomainRefuted {
                domain_id: 4,
                code: 1
            })
        ));

        // Non-slashable DeterministicQuorum fails admits_cross_domain_value.
        assert!(matches!(
            check_certificate_value_gate(
                &cert,
                &empty_sentry(),
                ValueGate::ObjectLayerArrive,
                5,
                Some(2),
                FinalityBinds::NONE
            ),
            Err(ValueGateRefusal::RouteFinalityInsufficient {
                source_domain: 5,
                ..
            })
        ));

        // Absent domain is refused.
        assert_eq!(
            check_certificate_value_gate(
                &cert,
                &empty_sentry(),
                ValueGate::RelayerIntentSettle,
                99,
                None,
                FinalityBinds::NONE
            ),
            Err(ValueGateRefusal::DomainMissing { domain_id: 99 })
        );
    }

    #[test]
    fn sentry_circuit_escalation_halts_all_value_gates() {
        use crate::cross_domain::external::sentry::{
            ConsensusSentry, DomainQuantumPosture, SentryCircuitState, SentryDomainPolicy,
            SentryObservation, DEFAULT_MAX_RESTAKE_SHARE_PPM,
        };

        let mut sentry = ConsensusSentry::new();
        let domain_id = 77u32;
        let key = ConsensusSentry::domain_key_for_id(domain_id);
        sentry
            .register_domain(
                key.clone(),
                SentryDomainPolicy {
                    consensus_family: "cometbft-v1".into(),
                    quantum_posture: DomainQuantumPosture::ClassicalOnly,
                    max_finality_stall_secs: 60,
                    min_trusting_window_secs: 30,
                    max_reorg_blocks: 0,
                    max_consecutive_proof_failures: 2,
                    max_restake_share_ppm: DEFAULT_MAX_RESTAKE_SHARE_PPM,
                    recovery_cooldown_secs: 300,
                },
            )
            .expect("register sentry domain");

        for gate in [
            ValueGate::BridgeMint,
            ValueGate::BridgeUnlock,
            ValueGate::RelayerIntentSettle,
            ValueGate::AppBindingClaim,
            ValueGate::ObjectLayerArrive,
            ValueGate::UniversalPayment,
        ] {
            enforce_sentry_circuit_clear(&sentry, gate, domain_id)
                .expect("open sentry circuit admits value");
        }

        sentry
            .observe(&SentryObservation {
                domain_id: key.clone(),
                height: 100,
                state_root: [0x22; 32],
                observed_at_secs: 1_000,
                remaining_trust_window_secs: Some(600),
                restake_share_ppm: 100_000,
            })
            .expect("initial observation");
        let alerts = sentry.check_liveness(1_100);
        assert!(
            !alerts.is_empty(),
            "liveness stall must produce sentry alert"
        );
        assert_eq!(
            sentry.domain(&key).expect("watched").circuit,
            SentryCircuitState::Halted
        );

        for gate in [
            ValueGate::BridgeMint,
            ValueGate::BridgeUnlock,
            ValueGate::RelayerIntentSettle,
            ValueGate::AppBindingClaim,
            ValueGate::ObjectLayerArrive,
            ValueGate::UniversalPayment,
        ] {
            let err = enforce_sentry_circuit_clear(&sentry, gate, domain_id).unwrap_err();
            assert_eq!(
                err,
                ValueGateRefusal::SentryCircuitEscalated {
                    gate,
                    domain_id,
                    circuit: "HALTED",
                }
            );
        }
    }
    #[test]
    fn refresh_consensus_sentry_indexes_domain_id_key_and_blocks_stalled_domain() {
        use crate::core::account::AccountState;
        use crate::domain::plugin::default_domain;
        use crate::domain::types::ConsensusKind;

        let mut state = AccountState::new();
        let mut dom = default_domain(42, ConsensusKind::PoS, 42, "pos", 0);
        dom.last_committed_height = 5;
        dom.last_committed_hash = [0x42; 32];
        state
            .settlement
            .domains
            .register(dom)
            .expect("register domain 42");

        state.refresh_consensus_sentry(1_000);
        let key = crate::cross_domain::external::sentry::ConsensusSentry::domain_key_for_id(42);
        assert!(
            state.bridge_state.consensus_sentry.domain(&key).is_some(),
            "refresh_consensus_sentry must populate canonical domain:<id> key"
        );
        assert!(enforce_sentry_circuit_clear(
            &state.bridge_state.consensus_sentry,
            ValueGate::BridgeMint,
            42,
        )
        .is_ok());

        // Advance well past max_finality_stall_secs (3600s) with no progress.
        state.refresh_consensus_sentry(10_000);
        let err = enforce_sentry_circuit_clear(
            &state.bridge_state.consensus_sentry,
            ValueGate::BridgeMint,
            42,
        )
        .expect_err("stalled domain must trigger Sentry circuit breaker on domain:<id>");
        assert!(matches!(
            err,
            ValueGateRefusal::SentryCircuitEscalated {
                gate: ValueGate::BridgeMint,
                domain_id: 42,
                ..
            }
        ));
    }

    #[test]
    fn enforce_domain_not_refuted_rejects_pending_retired_and_unbound_domains() {
        use crate::domain::plugin::default_domain;
        use crate::domain::types::{ConsensusKind, DomainStatus};
        use crate::settlement::registries::SettlementRegistries;

        let mut regs = SettlementRegistries::new();
        let mut dom = default_domain(77, ConsensusKind::PoS, 77, "pos", 0);
        dom.last_committed_height = 3;
        dom.last_committed_hash = [0x77; 32];
        regs.domains.register(dom).expect("register");

        // Domain claims height 3 without a matching commitment -> Pending(EvidenceMissing) refused.
        let err = enforce_domain_not_refuted(&regs, 10, ValueGate::BridgeMint, 77)
            .expect_err("non-zero height without commitment must be refused fail-closed");
        assert_eq!(
            err,
            ValueGateRefusal::DomainPending {
                domain_id: 77,
                reason: FinalityPendingReason::EvidenceMissing,
            }
        );

        // Retired domain -> Pending(RuleNotSatisfied) refused.
        regs.domains.get_mut(77).unwrap().status = DomainStatus::Retired;
        let err_retired = enforce_domain_not_refuted(&regs, 10, ValueGate::BridgeUnlock, 77)
            .expect_err("retired domain must be refused");
        assert_eq!(
            err_retired,
            ValueGateRefusal::DomainPending {
                domain_id: 77,
                reason: FinalityPendingReason::RuleNotSatisfied,
            }
        );
    }

    #[test]
    fn evaluate_route_guarantee_refuses_weak_or_unslashable_target_domain() {
        let strong_source = FinalityGuarantee {
            reversibility: FinalityReversibility::DeterministicQuorum,
            quantum_posture: QuantumClass::Hash,
            attestation: FINALITY_BINDS_ALL,
            slashable_backing: true,
            fault_tolerance_bps: 3_333,
        };
        let hub = FinalityGuarantee::settlement_hub();
        let unslashable_target = FinalityGuarantee {
            reversibility: FinalityReversibility::DeterministicQuorum,
            quantum_posture: QuantumClass::Hash,
            attestation: FINALITY_BINDS_ALL,
            slashable_backing: false,
            fault_tolerance_bps: 3_333,
        };
        assert!(
            evaluate_route_guarantee(&strong_source, &hub, &unslashable_target).is_none(),
            "route must fail closed when target domain lacks slashable cross-domain value admission"
        );

        let attested_target = FinalityGuarantee {
            reversibility: FinalityReversibility::DeterministicQuorum,
            quantum_posture: QuantumClass::Hash,
            attestation: FINALITY_BINDS_ALL,
            slashable_backing: true,
            fault_tolerance_bps: 3_333,
        };
        assert!(
            evaluate_route_guarantee(&strong_source, &hub, &attested_target).is_some(),
            "established slashable source and target must pass evaluate_route_guarantee"
        );
    }

    // -- Gate 1: certificate origin ----------------------------------------
    #[test]
    fn hand_built_certificate_cannot_pass_value_gate() {
        // `compose` enforces binds; but the fields are `pub`. A hand-built
        // certificate never sees that gate. The gate now re-derives the certificate
        // from its rows: a certificate that cannot be derived carries no value.
        let mut elle = single_domain_cert(11);
        elle.checkpoint_height = elle.checkpoint_height.saturating_add(1);

        assert_eq!(
            check_certificate_value_gate(
                &elle,
                &empty_sentry(),
                ValueGate::BridgeMint,
                11,
                None,
                FinalityBinds::NONE,
            ),
            Err(ValueGateRefusal::CertificateNotDerived)
        );
    }

    #[test]
    fn composed_certificate_passes_value_gate() {
        // The gate does not refuse a correct certificate: the new check is
        // fail-closed but does not break the function. Without this test the one
        // above would also green-light a gate that refuses everything.
        let cert = single_domain_cert(12);
        check_certificate_value_gate(
            &cert,
            &empty_sentry(),
            ValueGate::BridgeMint,
            12,
            None,
            FinalityBinds::NONE,
        )
        .expect("composed certificate must pass the derivation gate");
    }

    // -- Gate 2: quantum posture ------------------------------------------
    #[test]
    fn crqc_alarm_stops_value_on_classical_domain() {
        use crate::cross_domain::external::sentry::{
            ConsensusSentry, DomainQuantumPosture, SentryDomainPolicy,
            DEFAULT_MAX_RESTAKE_SHARE_PPM,
        };

        let domain_id = 13u32;
        let mut sentry = ConsensusSentry::new();
        sentry
            .register_domain(
                ConsensusSentry::domain_key_for_id(domain_id),
                SentryDomainPolicy {
                    consensus_family: "cometbft-v1".into(),
                    quantum_posture: DomainQuantumPosture::ClassicalOnly,
                    max_finality_stall_secs: 60,
                    min_trusting_window_secs: 30,
                    max_reorg_blocks: 0,
                    max_consecutive_proof_failures: 2,
                    max_restake_share_ppm: DEFAULT_MAX_RESTAKE_SHARE_PPM,
                    recovery_cooldown_secs: 300,
                },
            )
            .expect("register sentry domain");
        sentry.activate_crqc_alarm(1_700_000_000);

        let cert = single_domain_cert(domain_id);
        // Posture does not fit: refuse.
        assert!(matches!(
            check_certificate_value_gate(
                &cert,
                &sentry,
                ValueGate::BridgeMint,
                domain_id,
                None,
                FinalityBinds::NONE,
            ),
            Err(ValueGateRefusal::QuantumPostureUnfit { domain_id: 13, .. })
        ));
        // The same call passes without an alarm: the quantum gate is tied to CRQC,
        // not permanent.
        let without_alarm = ConsensusSentry::new();
        check_certificate_value_gate(
            &cert,
            &without_alarm,
            ValueGate::BridgeMint,
            domain_id,
            None,
            FinalityBinds::NONE,
        )
        .expect("no alarm, no posture refusal");
    }

    #[test]
    fn crqc_alarm_checks_target_domain_too() {
        use crate::cross_domain::external::sentry::{
            ConsensusSentry, DomainQuantumPosture, SentryDomainPolicy,
            DEFAULT_MAX_RESTAKE_SHARE_PPM,
        };

        let source_id = 14u32;
        let target_id = 15u32;
        let mut sentry = ConsensusSentry::new();
        for d in [source_id, target_id] {
            sentry
                .register_domain(
                    ConsensusSentry::domain_key_for_id(d),
                    SentryDomainPolicy {
                        consensus_family: "cometbft-v1".into(),
                        // Source is PQ-hardened, target classical: only the target may refuse.
                        quantum_posture: if d == source_id {
                            DomainQuantumPosture::PurePostQuantum
                        } else {
                            DomainQuantumPosture::ClassicalOnly
                        },
                        max_finality_stall_secs: 60,
                        min_trusting_window_secs: 30,
                        max_reorg_blocks: 0,
                        max_consecutive_proof_failures: 2,
                        max_restake_share_ppm: DEFAULT_MAX_RESTAKE_SHARE_PPM,
                        recovery_cooldown_secs: 300,
                    },
                )
                .expect("register sentry domain");
        }
        sentry.activate_crqc_alarm(1_700_000_000);

        let cert = compose(&[
            entry(
                source_id,
                FinalityReversibility::CryptographicValidity,
                true,
                5_000,
                FinalityVerdict::Established,
            ),
            entry(
                target_id,
                FinalityReversibility::CryptographicValidity,
                true,
                5_000,
                FinalityVerdict::Established,
            ),
        ])
        .expect("compose two established rows");

        assert!(matches!(
            check_certificate_value_gate(
                &cert,
                &sentry,
                ValueGate::BridgeMint,
                source_id,
                Some(target_id),
                FinalityBinds::NONE
            ),
            Err(ValueGateRefusal::QuantumPostureUnfit { domain_id: 15, .. })
        ));
    }

    // -- Gate 3: binds the caller required --------------------------------
    #[test]
    fn required_binds_are_enforced() {
        use crate::settlement::universal_finality::FinalityBinds;
        // `compose` says "fully bound". But if the caller only requires the event
        // root, the set the row carries must be asked: if it is not, the `binds`
        // field is decoration and a later narrowed row passes silently.
        let cert = single_domain_cert(21);
        // A fully bound row satisfies any requirement.
        enforce_required_binds(&cert, 21, FinalityBinds::EVENT_ROOT)
            .expect("fully bound row satisfies any requirement");
    }

    #[test]
    fn no_bind_requirement_is_silent() {
        // 0 = "this move imposes no bind requirement". No refusal.
        let cert = single_domain_cert(22);
        enforce_required_binds(&cert, 22, FinalityBinds::NONE).expect("no requirement, no refusal");
    }

    #[test]
    fn bind_gate_defers_missing_domain_to_prove_domain() {
        // Order and single-reason principle: the missing domain is `prove_domain`'s
        // to report. If two checks raced on the same domain the refusal would depend
        // on call order.
        let cert = single_domain_cert(23);
        enforce_required_binds(&cert, 99, FinalityBinds::ALL)
            .expect("missing domain is prove_domain's call");
    }

    #[test]
    fn compose_rejects_unclaimed_binds() {
        use crate::settlement::universal_finality::FinalityBinds;
        // The row says "fully bound" but only carries the state root. If `compose`
        // accepts that, the `binds` field has no force left.
        let eksik = DomainFinalityEntry {
            binds: FinalityBinds::STATE_ROOT,
            ..entry(
                24,
                FinalityReversibility::CryptographicValidity,
                true,
                5_000,
                FinalityVerdict::Established,
            )
        };
        assert_eq!(
            compose(&[eksik]),
            Err(FinalityComposeError::AttestationUnbound { domain_id: 24 })
        );
    }

    #[test]
    fn a_row_that_lacks_a_demanded_binding_is_refused_with_both_sets() {
        use crate::settlement::universal_finality::FinalityBinds;
        // A pending row may carry a narrow binding set (`compose` polices the
        // binding claim only for established rows), so this is the one shape
        // that reaches the refusal without hand-building a certificate.
        let cert = compose(&[DomainFinalityEntry {
            binds: FinalityBinds::EVENT_ROOT,
            ..entry(
                25,
                FinalityReversibility::CryptographicValidity,
                true,
                5_000,
                FinalityVerdict::Pending {
                    reason: FinalityPendingReason::EvidenceMissing,
                },
            )
        }])
        .expect("compose a pending row with a narrow binding set");
        let demand = FinalityBinds::STATE_ROOT.union(FinalityBinds::EVENT_ROOT);
        assert_eq!(
            enforce_required_binds(&cert, 25, demand),
            Err(ValueGateRefusal::RequiredBindMissing {
                domain_id: 25,
                required_binds: demand,
                present_binds: FinalityBinds::EVENT_ROOT,
            })
        );
        // A demand the narrow row does meet is not refused: the check is a
        // set comparison, not "all or nothing".
        enforce_required_binds(&cert, 25, FinalityBinds::EVENT_ROOT)
            .expect("the demanded binding is present");
    }
}

#[cfg(test)]
mod binding_policy_tests {
    use super::{FinalityBinds, ValueGate};

    #[test]
    fn the_binding_floor_is_preserved_for_every_requested_set() {
        assert_eq!(FinalityBinds::ALL.bits(), 0b1111);
        for gate in [
            ValueGate::BridgeMint,
            ValueGate::BridgeUnlock,
            ValueGate::RelayerIntentSettle,
            ValueGate::AppBindingClaim,
            ValueGate::ObjectLayerArrive,
            ValueGate::UniversalPayment,
        ] {
            let minimum = gate.required_binds();
            assert!(!minimum.is_empty(), "{gate:?} has no binding floor");
            assert_eq!(minimum, FinalityBinds::EVENT_ROOT);
            for bits in 0_u8..16 {
                let requested = FinalityBinds::from_bits(bits);
                let effective = minimum.union(requested);
                assert!(effective.covers(minimum));
                assert!(effective.covers(requested));
                assert_eq!(
                    effective.bits(),
                    FinalityBinds::EVENT_ROOT.bits() | requested.bits(),
                    "{gate:?} changed request {bits} beyond its event-root floor"
                );
            }
        }
    }
}
