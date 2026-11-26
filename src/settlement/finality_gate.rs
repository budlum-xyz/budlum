//! Single finality decision point shared by every cross-domain value gate.
//!
//! Every value gate asks one question, through one function:
//! [`check_certificate_value_gate`]. Inside it the checks run in a fixed
//! order, and each one can only refuse:
//!
//! 1. `enforce_root` - the row commits a non-zero state root;
//! 2. the row's verdict (`Refuted`/`Pending` refuse, `Established` passes);
//! 3. `enforce_binds` - the proof binds every root the route reads;
//! 4. `enforce_quantum_posture` - the posture satisfies the gate's policy;
//! 5. `enforce_sentry_circuit_clear` - Sentry has not escalated the circuit;
//! 6. `evaluate_route_guarantee` - the composed route admits value.
//!
//! The four `enforce_*` helpers are private to this module: a caller cannot
//! pick them up and run half a gate. A new value path either calls
//! [`check_certificate_value_gate`] or it does not move value.
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

use crate::settlement::finality_policy::{
    enforce_binds, enforce_quantum_posture, enforce_root, QuantumPosturePolicy, BINDS_PARENT,
    BINDS_VALUE_ROUTE,
};
use crate::settlement::registries::SettlementRegistries;
use crate::settlement::universal_finality::{
    compose_cross_domain_route, EconomicSecurityBound, FinalityBucket, FinalityGuarantee,
    FinalityPendingReason, FinalityVerdict, GlobalFinalityCertificate, RouteFinalityBound,
};

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

    /// The quantum posture this gate settles under.
    ///
    /// Every gate that moves value across a domain boundary demands at least a
    /// lattice-or-hash posture: a classical (Shor-breakable) signature over a
    /// settlement certificate would let a future adversary forge the proof
    /// and then move the value. `Classical` is admitted only where value stays
    /// inside the hub, which no gate in this enum does.
    ///
    /// Private: the policy is a property of the single gate, not a knob a
    /// caller can turn per call site. Callers pick the *gate*; this map says
    /// what that gate settles under.
    #[must_use]
    const fn quantum_posture_policy(self) -> QuantumPosturePolicy {
        QuantumPosturePolicy::AtLeast(crate::crypto::facts::QuantumClass::Lattice)
    }
}

/// Fail-closed refusal produced by the single finality decision gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueGateRefusal {
    /// No consensus domains are registered, so no finality certificate exists.
    CertificateUnavailable,
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
    /// The proof behind the row binds less than the roots this gate reads.
    ///
    /// The rule itself lives in
    /// [`crate::settlement::finality_policy::enforce_binds`]; this variant
    /// names what the gate was about to read.
    BindsUnproven {
        /// Value gate that refused settlement.
        gate: ValueGate,
        /// Domain whose proof binds too little.
        domain_id: u32,
        /// Human-readable list of the roots the gate required.
        required: &'static str,
    },
    /// The row's quantum posture is weaker than this gate's policy.
    QuantumPostureInsufficient {
        /// Value gate that refused settlement.
        gate: ValueGate,
        /// Domain whose posture is too weak.
        domain_id: u32,
        /// Canonical posture label observed on the row.
        observed: &'static str,
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
            Self::DomainRefuted { domain_id, code } => write!(
                f,
                "domain {domain_id} is refuted in the finality certificate (code {code})"
            ),
            Self::DomainPending { domain_id, reason } => write!(
                f,
                "domain {domain_id} is pending in the finality certificate ({reason:?})"
            ),
            Self::BindsUnproven {
                gate,
                domain_id,
                required,
            } => write!(
                f,
                "{} refused: domain {domain_id} proof binds less than required ({required})",
                gate.as_str()
            ),
            Self::QuantumPostureInsufficient {
                gate,
                domain_id,
                observed,
            } => write!(
                f,
                "{} refused: domain {domain_id} quantum posture {observed} is below policy",
                gate.as_str()
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
/// Returns `Some(route)` only when the source guarantee admits cross-domain
/// value transfer, the composed route admits transfer, and the bottleneck fault
/// tolerance is strictly positive.
///
/// This helper answers the *route* question for a caller that already holds
/// state-derived guarantees and no certificate row (universal payment
/// staging). It is deliberately named `evaluate_*`, not `enforce_*`: the
/// authoritative gate over certificate rows is
/// [`check_certificate_value_gate`], and this function cannot admit anything
/// that gate would refuse - it sees strictly less.
#[must_use]
pub fn evaluate_route_guarantee(
    source: &FinalityGuarantee,
    hub: &FinalityGuarantee,
    target: &FinalityGuarantee,
) -> Option<RouteFinalityBound> {
    let route = compose_cross_domain_route(source, hub, target);
    if !source.admits_cross_domain_value()
        || !route.source_admits_value_transfer
        || route.bottleneck_fault_tolerance_bps == 0
    {
        return None;
    }
    Some(route)
}

/// Canonical posture label for a refusal message.
fn posture_label(class: crate::crypto::facts::QuantumClass) -> &'static str {
    match class {
        crate::crypto::facts::QuantumClass::Classical => "CLASSICAL",
        crate::crypto::facts::QuantumClass::Lattice => "LATTICE",
        crate::crypto::facts::QuantumClass::Hash => "HASH",
    }
}

/// The roots a value read requires, spelled for a refusal message.
const REQUIRED_VALUE_ROUTE: &str = "state_root+tx_root+event_root+parent";

/// The parent link alone, spelled for a refusal message.
const REQUIRED_PARENT: &str = "parent";

/// Evaluate whether `gate` may move value out of `source_domain` (optionally
/// into `target_domain`) using strictly the derived [`GlobalFinalityCertificate`].
///
/// The six checks run in this order and each one only refuses:
///
/// 1. `enforce_root` - the source row commits a non-zero state root;
/// 2. verdict - `Refuted`/`Pending` refuse, `Established` proceeds;
/// 3. `enforce_binds` - the source proof binds every root the route reads;
/// 4. `enforce_quantum_posture` - the source posture meets the gate policy;
/// 5. `enforce_sentry_circuit_clear` - Sentry has not escalated the domain.
///
/// Then the same root/binds/posture checks run for the target row, and
/// finally [`enforce_route_guarantee`] admits the composed route. A refusal
/// names the earliest failing condition, so callers can act on it.
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
) -> Result<ValueGateVerdict, ValueGateRefusal> {
    let src = cert
        .prove_domain(source_domain)
        .ok_or(ValueGateRefusal::DomainMissing {
            domain_id: source_domain,
        })?;

    // Checks 1-5 for the source row, in the documented order.
    enforce_row_admissible(gate, &src, sentry)?;

    let hub = FinalityGuarantee::settlement_hub();
    let (target_guarantee, target_econ_ceiling) = match target_domain {
        Some(dst_id) => {
            let dst = cert
                .prove_domain(dst_id)
                .ok_or(ValueGateRefusal::DomainMissing { domain_id: dst_id })?;
            // The same five checks for the target row: value must be admissible
            // at both ends of the route, not only where it leaves.
            enforce_row_admissible(gate, &dst, sentry)?;
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

    // Check 6: the weakest link of the composed route must admit value.
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

/// Run checks 1-5 of the single gate against one certificate row.
///
/// This is the whole per-row contract in one place: root, verdict, binds,
/// posture, sentry. It answers "may this row carry value at all", with no
/// knowledge of routes, ceilings or the other end - so the source and target
/// rows are measured by exactly the same code, and a future third leg would be
/// too.
///
/// # Errors
///
/// Returns the [`ValueGateRefusal`] of the earliest failing check.
fn enforce_row_admissible(
    gate: ValueGate,
    proof: &crate::settlement::universal_finality::DomainFinalityInclusionProof,
    sentry: &crate::cross_domain::external::sentry::ConsensusSentry,
) -> Result<(), ValueGateRefusal> {
    let entry = &proof.entry;
    let domain_id = entry.domain_id;

    // 1. Root: a row that commits no state root proves nothing about state.
    if enforce_root(entry.state_root).is_err() {
        return Err(ValueGateRefusal::DomainPending {
            domain_id,
            reason: FinalityPendingReason::EvidenceMissing,
        });
    }

    // 2. Verdict: the row's own rule decides before any downstream symptom.
    match entry.verdict {
        FinalityVerdict::Established => {}
        FinalityVerdict::Refuted { code } => {
            return Err(ValueGateRefusal::DomainRefuted { domain_id, code });
        }
        FinalityVerdict::Pending { reason } => {
            return Err(ValueGateRefusal::DomainPending { domain_id, reason });
        }
    }

    // 3. Binds: the route reads the parent link and all three roots, so the
    //    parent is named on its own first and then the full route set.
    if enforce_binds(&entry.guarantee.attestation, BINDS_PARENT).is_err() {
        return Err(ValueGateRefusal::BindsUnproven {
            gate,
            domain_id,
            required: REQUIRED_PARENT,
        });
    }
    if enforce_binds(&entry.guarantee.attestation, BINDS_VALUE_ROUTE).is_err() {
        return Err(ValueGateRefusal::BindsUnproven {
            gate,
            domain_id,
            required: REQUIRED_VALUE_ROUTE,
        });
    }

    // 4. Posture: the proof must survive an adversary with a quantum computer.
    if enforce_quantum_posture(
        entry.guarantee.quantum_posture,
        gate.quantum_posture_policy(),
    )
    .is_err()
    {
        return Err(ValueGateRefusal::QuantumPostureInsufficient {
            gate,
            domain_id,
            observed: posture_label(entry.guarantee.quantum_posture),
        });
    }

    // 5. Sentry circuit: a domain the sentry has escalated moves no value.
    enforce_sentry_circuit_clear(sentry, gate, domain_id)
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
///
/// Shared helper, not a second decision point: it answers Sentry's part of
/// the gate and nothing else. The value paths that run it directly
/// (`bridge_tx`, `app_binding`, `domains`) also run
/// [`check_certificate_value_gate`]; the helper is public so they can refuse
/// before touching storage, without duplicating the circuit semantics.
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
    use crate::cross_domain::external::sentry::ConsensusSentry;
    use crate::crypto::facts::QuantumClass;
    use crate::settlement::universal_finality::{
        compose, trace_record_binds, trace_record_quantum_posture, DomainFinalityEntry,
        FinalityReversibility, FINALITY_BINDS_ALL,
    };

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
            guarantee: FinalityGuarantee {
                reversibility,
                quantum_posture: QuantumClass::Hash,
                attestation: FINALITY_BINDS_ALL,
                slashable_backing: slashable,
                fault_tolerance_bps: bps,
            },
            binds: trace_record_binds(&FINALITY_BINDS_ALL),
            posture_trace: trace_record_quantum_posture(QuantumClass::Hash),
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
            let verdict =
                check_certificate_value_gate(&cert, &ConsensusSentry::new(), gate, 1, Some(2))
                    .expect("established value route must pass");
            assert_eq!(verdict.gate, gate);
            assert_eq!(verdict.source_bucket, FinalityBucket::Established);
            assert!(verdict.safe_value_outflow_ceiling_atoms > 0);
        }

        // Pending domain is refused.
        assert!(matches!(
            check_certificate_value_gate(
                &cert,
                &ConsensusSentry::new(),
                ValueGate::BridgeMint,
                3,
                Some(2)
            ),
            Err(ValueGateRefusal::DomainPending { domain_id: 3, .. })
        ));
        assert!(matches!(
            check_certificate_value_gate(
                &cert,
                &ConsensusSentry::new(),
                ValueGate::UniversalPayment,
                1,
                Some(3)
            ),
            Err(ValueGateRefusal::DomainPending { domain_id: 3, .. })
        ));

        // Refuted domain is refused.
        assert!(matches!(
            check_certificate_value_gate(
                &cert,
                &ConsensusSentry::new(),
                ValueGate::AppBindingClaim,
                4,
                None
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
                &ConsensusSentry::new(),
                ValueGate::ObjectLayerArrive,
                5,
                Some(2)
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
                &ConsensusSentry::new(),
                ValueGate::RelayerIntentSettle,
                99,
                None
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
}
