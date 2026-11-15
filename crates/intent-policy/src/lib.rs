//! Offline route policy, not a finality verifier or a payment executor.
//!
//! Inputs must come from one authenticated snapshot before this can be used
//! for settlement. No token symbol, fiat peg or solver assertion implies
//! asset equivalence. Fee amounts use the input asset of their own leg.
#![forbid(unsafe_code)]

pub const MAX_ROUTE_LEGS: usize = 8;
pub const MAX_DOMAIN_VIEWS: usize = 16;

/// Full domain identities, not truncated external-domain keys.
pub type DomainKey = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetLocation {
    pub domain: DomainKey,
    /// Exact local asset/representation identity. Never a ticker symbol.
    pub asset: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainView {
    pub domain: DomainKey,
    pub snapshot_height: u64,
    pub active: bool,
    pub can_swap: bool,
    pub can_transfer: bool,
    /// Local *domain* transaction atomicity, not a shared VM label.
    pub local_atomic: bool,
    /// A verified conditional escrow capability is needed at both ends.
    pub conditional_escrow: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegKind {
    Swap,
    Transfer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteLeg {
    pub source: AssetLocation,
    pub destination: AssetLocation,
    pub amount_in: u128,
    /// Amount delivered after all destination-side deductions.
    pub amount_out: u128,
    /// Additional debit, denominated only in `source` units.
    pub fee_in: u128,
    pub kind: LegKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlementRequirement {
    /// Every leg must execute in the same sovereign domain atomically.
    LocalAtomic,
    /// Escrow capability admission only. This does not execute a protocol.
    Conditional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentIntent {
    pub source: AssetLocation,
    pub destination: AssetLocation,
    pub max_debit: u128,
    pub min_credit: u128,
    /// Budlum snapshot height, never an external chain's height or clock.
    pub valid_until: u64,
    pub settlement: SettlementRequirement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    EmptyRoute,
    RouteTooLong,
    InvalidAmount,
    Expired,
    InvalidDomainViews,
    UnknownDomain,
    StaleSnapshot,
    InactiveDomain,
    EndpointMismatch,
    DisconnectedRoute,
    InvalidLeg,
    UnsupportedCapability,
    AtomicityUnavailable,
    Overflow,
    DebitExceeded,
    CreditBelowMinimum,
    RepeatedLocation,
}

/// A calculation result only. It is deliberately not a settlement receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteAssessment {
    pub debit: u128,
    pub credit: u128,
    pub snapshot_height: u64,
    pub legs: usize,
}

fn domain_at(views: &[DomainView], key: DomainKey, height: u64) -> Result<&DomainView, Refusal> {
    let view = views
        .iter()
        .find(|view| view.domain == key)
        .ok_or(Refusal::UnknownDomain)?;
    if view.snapshot_height != height {
        return Err(Refusal::StaleSnapshot);
    }
    if !view.active {
        return Err(Refusal::InactiveDomain);
    }
    Ok(view)
}

/// Check a route in bounded time without mutation or network access.
///
/// # Errors
/// Refuses unsupported capabilities, inconsistent units, expired snapshots,
/// arithmetic overflow and routes outside the user's debit/credit bounds.
/// This does not authenticate views, quotes, users or adapter code. Callers
/// must not interpret success as permission to debit an account.
pub fn assess_route(
    intent: &PaymentIntent,
    legs: &[RouteLeg],
    views: &[DomainView],
    height: u64,
) -> Result<RouteAssessment, Refusal> {
    if legs.is_empty() {
        return Err(Refusal::EmptyRoute);
    }
    if legs.len() > MAX_ROUTE_LEGS {
        return Err(Refusal::RouteTooLong);
    }
    if views.is_empty() || views.len() > MAX_DOMAIN_VIEWS {
        return Err(Refusal::InvalidDomainViews);
    }
    for (index, view) in views.iter().enumerate() {
        if views[..index]
            .iter()
            .any(|other| other.domain == view.domain)
        {
            return Err(Refusal::InvalidDomainViews);
        }
    }
    if intent.max_debit == 0 || intent.min_credit == 0 {
        return Err(Refusal::InvalidAmount);
    }
    if height >= intent.valid_until {
        return Err(Refusal::Expired);
    }
    let first = &legs[0];
    let last = &legs[legs.len() - 1];
    if first.source != intent.source || last.destination != intent.destination {
        return Err(Refusal::EndpointMismatch);
    }
    let debit = first
        .amount_in
        .checked_add(first.fee_in)
        .ok_or(Refusal::Overflow)?;
    if debit > intent.max_debit {
        return Err(Refusal::DebitExceeded);
    }
    for (index, leg) in legs.iter().enumerate() {
        if leg.amount_in == 0 || leg.amount_out == 0 {
            return Err(Refusal::InvalidAmount);
        }
        if leg.source == leg.destination {
            return Err(Refusal::InvalidLeg);
        }
        // No cycles, even across distinct domains that reuse asset bytes.
        if leg.destination == first.source
            || legs[..index]
                .iter()
                .any(|previous| previous.destination == leg.destination)
        {
            return Err(Refusal::RepeatedLocation);
        }
        if index > 0 {
            let previous = &legs[index - 1];
            let needed = leg
                .amount_in
                .checked_add(leg.fee_in)
                .ok_or(Refusal::Overflow)?;
            if previous.destination != leg.source || previous.amount_out != needed {
                return Err(Refusal::DisconnectedRoute);
            }
        }
        let source = domain_at(views, leg.source.domain, height)?;
        let destination = domain_at(views, leg.destination.domain, height)?;
        match leg.kind {
            LegKind::Swap => {
                if source.domain != destination.domain {
                    return Err(Refusal::InvalidLeg);
                }
                if !source.can_swap {
                    return Err(Refusal::UnsupportedCapability);
                }
            }
            LegKind::Transfer => {
                // An external transfer may change the representation id. Its
                // equivalence still needs an authenticated execution proof.
                if source.domain == destination.domain {
                    return Err(Refusal::InvalidLeg);
                }
                if !source.can_transfer || !destination.can_transfer {
                    return Err(Refusal::UnsupportedCapability);
                }
            }
        }
        match intent.settlement {
            SettlementRequirement::LocalAtomic => {
                if source.domain != intent.source.domain
                    || destination.domain != intent.source.domain
                    || !source.local_atomic
                {
                    return Err(Refusal::AtomicityUnavailable);
                }
            }
            SettlementRequirement::Conditional => {
                if !source.conditional_escrow || !destination.conditional_escrow {
                    return Err(Refusal::UnsupportedCapability);
                }
            }
        }
    }
    if last.amount_out < intent.min_credit {
        return Err(Refusal::CreditBelowMinimum);
    }
    Ok(RouteAssessment {
        debit,
        credit: last.amount_out,
        snapshot_height: height,
        legs: legs.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn location(domain: u8, asset: u8) -> AssetLocation {
        AssetLocation {
            domain: [domain; 32],
            asset: [asset; 32],
        }
    }

    fn fixture() -> (PaymentIntent, Vec<RouteLeg>, Vec<DomainView>) {
        let a = location(1, 1);
        let b = location(1, 2);
        let c = location(2, 3);
        let legs = vec![
            RouteLeg {
                source: a,
                destination: b,
                amount_in: 100,
                amount_out: 90,
                fee_in: 2,
                kind: LegKind::Swap,
            },
            RouteLeg {
                source: b,
                destination: c,
                amount_in: 87,
                amount_out: 86,
                fee_in: 3,
                kind: LegKind::Transfer,
            },
        ];
        let views = [1, 2]
            .map(|d| DomainView {
                domain: [d; 32],
                snapshot_height: 10,
                active: true,
                can_swap: true,
                can_transfer: true,
                local_atomic: true,
                conditional_escrow: true,
            })
            .to_vec();
        (
            PaymentIntent {
                source: a,
                destination: c,
                max_debit: 102,
                min_credit: 86,
                valid_until: 11,
                settlement: SettlementRequirement::Conditional,
            },
            legs,
            views,
        )
    }

    #[test]
    fn assesses_mixed_asset_fees_without_summing_unlike_units() {
        let (i, l, v) = fixture();
        let assessment = assess_route(&i, &l, &v, 10).unwrap();
        assert_eq!((assessment.debit, assessment.credit), (102, 86));
    }

    #[test]
    fn same_vm_does_not_make_cross_chain_execution_atomic() {
        let (mut i, l, v) = fixture();
        i.settlement = SettlementRequirement::LocalAtomic;
        assert_eq!(
            assess_route(&i, &l, &v, 10),
            Err(Refusal::AtomicityUnavailable)
        );
    }

    #[test]
    fn local_atomic_swap_is_admitted_only_as_policy() {
        let (mut i, mut l, v) = fixture();
        l.truncate(1);
        i.destination = l[0].destination;
        i.settlement = SettlementRequirement::LocalAtomic;
        assert!(assess_route(&i, &l, &v, 10).is_ok());
    }

    #[test]
    fn checks_exclusive_deadline() {
        let (i, l, v) = fixture();
        assert_eq!(assess_route(&i, &l, &v, 11), Err(Refusal::Expired));
    }

    #[test]
    fn refuses_mismatched_domain_identity_even_if_asset_bytes_match() {
        let (i, mut l, v) = fixture();
        l[1].source.domain = [2; 32];
        assert_eq!(
            assess_route(&i, &l, &v, 10),
            Err(Refusal::DisconnectedRoute)
        );
    }

    #[test]
    fn fees_cannot_be_hidden_between_legs() {
        let (i, mut l, v) = fixture();
        l[1].fee_in += 1;
        assert_eq!(
            assess_route(&i, &l, &v, 10),
            Err(Refusal::DisconnectedRoute)
        );
    }

    #[test]
    fn checks_input_and_output_limits() {
        let (mut i, l, v) = fixture();
        i.max_debit -= 1;
        assert_eq!(assess_route(&i, &l, &v, 10), Err(Refusal::DebitExceeded));
        i.max_debit += 1;
        i.min_credit += 1;
        assert_eq!(
            assess_route(&i, &l, &v, 10),
            Err(Refusal::CreditBelowMinimum)
        );
    }

    #[test]
    fn addition_overflow_is_a_refusal() {
        let (mut i, mut l, v) = fixture();
        i.max_debit = u128::MAX;
        l[0].amount_in = u128::MAX;
        assert_eq!(assess_route(&i, &l, &v, 10), Err(Refusal::Overflow));
        l[0].amount_in = 100;
        l[1].amount_in = u128::MAX;
        assert_eq!(assess_route(&i, &l, &v, 10), Err(Refusal::Overflow));
    }

    #[test]
    fn refuses_missing_frozen_stale_and_ambiguous_views() {
        let (i, l, mut v) = fixture();
        assert_eq!(
            assess_route(&i, &l, &v[..1], 10),
            Err(Refusal::UnknownDomain)
        );
        v[1].active = false;
        assert_eq!(assess_route(&i, &l, &v, 10), Err(Refusal::InactiveDomain));
        v[1].active = true;
        v[1].snapshot_height = 9;
        assert_eq!(assess_route(&i, &l, &v, 10), Err(Refusal::StaleSnapshot));
        v[1] = v[0];
        assert_eq!(
            assess_route(&i, &l, &v, 10),
            Err(Refusal::InvalidDomainViews)
        );
    }

    #[test]
    fn refuses_capability_downgrade() {
        let (i, l, mut v) = fixture();
        v[1].conditional_escrow = false;
        assert_eq!(
            assess_route(&i, &l, &v, 10),
            Err(Refusal::UnsupportedCapability)
        );
        v[1].conditional_escrow = true;
        v[0].can_swap = false;
        assert_eq!(
            assess_route(&i, &l, &v, 10),
            Err(Refusal::UnsupportedCapability)
        );
    }

    #[test]
    fn refuses_unbounded_and_empty_routes() {
        let (i, l, v) = fixture();
        assert_eq!(assess_route(&i, &[], &v, 10), Err(Refusal::EmptyRoute));
        assert_eq!(
            assess_route(&i, &vec![l[0]; MAX_ROUTE_LEGS + 1], &v, 10),
            Err(Refusal::RouteTooLong)
        );
    }

    #[test]
    fn a_cycle_is_not_a_payment_route() {
        let (mut i, mut l, v) = fixture();
        l[1].destination = i.source;
        i.destination = i.source;
        assert_eq!(assess_route(&i, &l, &v, 10), Err(Refusal::RepeatedLocation));
    }
}
