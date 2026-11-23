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

/// Evaluate whether `gate` may move value out of `source_domain` (optionally
/// into `target_domain`) using strictly the derived [`GlobalFinalityCertificate`].
///
/// Fails closed if either domain is missing, `Pending`, or `Refuted`, or if
/// [`evaluate_route_guarantee`] rejects the weakest-link composed guarantee.
///
/// # Errors
///
/// Returns [`ValueGateRefusal`] describing the exact certificate or route
/// invariant that blocked value transfer.
pub fn check_certificate_value_gate(
    cert: &GlobalFinalityCertificate,
    gate: ValueGate,
    source_domain: u32,
    target_domain: Option<u32>,
) -> Result<ValueGateVerdict, ValueGateRefusal> {
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
        compose, DomainFinalityEntry, FinalityReversibility, FINALITY_BINDS_ALL,
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
            let verdict = check_certificate_value_gate(&cert, gate, 1, Some(2))
                .expect("established value route must pass");
            assert_eq!(verdict.gate, gate);
            assert_eq!(verdict.source_bucket, FinalityBucket::Established);
            assert!(verdict.safe_value_outflow_ceiling_atoms > 0);
        }

        // Pending domain is refused.
        assert!(matches!(
            check_certificate_value_gate(&cert, ValueGate::BridgeMint, 3, Some(2)),
            Err(ValueGateRefusal::DomainPending { domain_id: 3, .. })
        ));
        assert!(matches!(
            check_certificate_value_gate(&cert, ValueGate::UniversalPayment, 1, Some(3)),
            Err(ValueGateRefusal::DomainPending { domain_id: 3, .. })
        ));

        // Refuted domain is refused.
        assert!(matches!(
            check_certificate_value_gate(&cert, ValueGate::AppBindingClaim, 4, None),
            Err(ValueGateRefusal::DomainRefuted {
                domain_id: 4,
                code: 1
            })
        ));

        // Non-slashable DeterministicQuorum fails admits_cross_domain_value.
        assert!(matches!(
            check_certificate_value_gate(&cert, ValueGate::ObjectLayerArrive, 5, Some(2)),
            Err(ValueGateRefusal::RouteFinalityInsufficient {
                source_domain: 5,
                ..
            })
        ));

        // Absent domain is refused.
        assert_eq!(
            check_certificate_value_gate(&cert, ValueGate::RelayerIntentSettle, 99, None),
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
