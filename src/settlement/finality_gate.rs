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
        if let FinalityVerdict::Refuted { code } = proof.entry.verdict {
            let _ = gate.as_str();
            return Err(ValueGateRefusal::DomainRefuted { domain_id, code });
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
}
