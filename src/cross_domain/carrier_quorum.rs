//! Multi-source external-RPC carrier quorum and deterministic integer carrier
//! reward economics.
//!
//! Two fail-closed guarantees live here:
//! 1. **Multi-source carrier agreement:** a carrier never trusts a single RPC
//!    provider. At least two distinct endpoints must agree on `(block_height,
//!    state_root, evidence_digest)` with a strict majority over all polled
//!    endpoints and within `max_height_skew`, so one lying RPC endpoint never
//!    causes an invalid evidence submission.
//! 2. **Incentive-aligned carrier economics:** accepted attestations earn a
//!    checked integer payout split between the domain bond and the route fee
//!    pool; rejected or false attestations strictly pay zero; and idle domains
//!    monotonically escalate the carrier bounty up to a deterministic ceiling.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::domain::types::Hash32;

/// Minimum independent RPC endpoints required by any admissible quorum policy.
pub const MIN_CARRIER_QUORUM_ENDPOINTS: usize = 2;

/// Basis-point denominator (`10_000` bps = `1.0x`).
const BPS_SCALE: u128 = 10_000;

/// Single RPC endpoint observation collected by an evidence carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarrierEndpointObservation {
    /// Stable operator-assigned endpoint identifier (must be non-empty and unique per poll).
    pub endpoint_id: String,
    /// Target external domain identifier.
    pub domain_id: u32,
    /// Observed finalized block height or slot.
    pub block_height: u64,
    /// Observed external state root (`app_hash`, `bank_hash`, `merkle_root`, etc.).
    pub state_root: Hash32,
    /// Digest of the canonical evidence payload returned by this endpoint.
    pub evidence_digest: Hash32,
}

/// Quorum admission policy for multi-source carrier polling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultiSourceQuorumPolicy {
    /// Minimum distinct endpoints that must agree (`>= 2`).
    pub min_independent_endpoints: usize,
    /// Maximum allowed difference between highest and lowest observed block heights.
    pub max_height_skew: u64,
}

/// Accepted multi-source carrier decision ready for `SubmitEvidence` dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumCarrierDecision {
    /// Target external domain identifier.
    pub domain_id: u32,
    /// Agreed finalized block height.
    pub block_height: u64,
    /// Agreed external state root.
    pub state_root: Hash32,
    /// Agreed canonical evidence digest.
    pub evidence_digest: Hash32,
    /// Distinct endpoints that agreed on the winning tuple.
    pub agreeing_endpoints: Vec<String>,
    /// Distinct endpoints whose observation disagreed with the strict majority.
    pub dissenting_endpoints: Vec<String>,
}

/// Fail-closed refusal reasons from [`evaluate_carrier_quorum`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CarrierQuorumError {
    /// Quorum policy violates minimum independent endpoint safety (`< 2`).
    InvalidPolicy(String),
    /// An observation carried empty endpoint id, zero roots/digests, or mismatched domain.
    MalformedObservation(String),
    /// The same `endpoint_id` appeared more than once in one poll batch.
    DuplicateEndpoint(String),
    /// Too few distinct endpoints responded to meet `min_independent_endpoints`.
    InsufficientEndpoints { observed: usize, required: usize },
    /// Endpoint heights diverged beyond `max_height_skew`.
    HeightSkewExceeded {
        min_height: u64,
        max_height: u64,
        max_allowed: u64,
    },
    /// No candidate tuple reached both `min_independent_endpoints` and strict majority.
    ConflictingSources {
        total_endpoints: usize,
        best_agreement: usize,
    },
}

impl fmt::Display for CarrierQuorumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy(m) => write!(f, "invalid carrier quorum policy: {m}"),
            Self::MalformedObservation(m) => write!(f, "malformed carrier observation: {m}"),
            Self::DuplicateEndpoint(id) => write!(f, "duplicate carrier endpoint '{id}'"),
            Self::InsufficientEndpoints { observed, required } => write!(
                f,
                "insufficient carrier endpoints: observed {observed}, required {required}"
            ),
            Self::HeightSkewExceeded {
                min_height,
                max_height,
                max_allowed,
            } => write!(
                f,
                "carrier height skew {} exceeds max {max_allowed} (min={min_height}, max={max_height})",
                max_height.saturating_sub(*min_height)
            ),
            Self::ConflictingSources {
                total_endpoints,
                best_agreement,
            } => write!(
                f,
                "conflicting carrier sources: best agreement {best_agreement}/{total_endpoints} lacks strict majority"
            ),
        }
    }
}

impl std::error::Error for CarrierQuorumError {}

/// Evaluate a batch of multi-source RPC observations fail-closed.
///
/// # Errors
///
/// Refuses single-source policies (`min_independent_endpoints < 2`), duplicate
/// endpoint identifiers, zero roots/digests, cross-domain batches, excessive
/// height skew, and any tie or split lacking strict majority agreement.
pub fn evaluate_carrier_quorum(
    policy: &MultiSourceQuorumPolicy,
    observations: &[CarrierEndpointObservation],
) -> Result<QuorumCarrierDecision, CarrierQuorumError> {
    if policy.min_independent_endpoints < MIN_CARRIER_QUORUM_ENDPOINTS {
        return Err(CarrierQuorumError::InvalidPolicy(format!(
            "min_independent_endpoints must be >= {MIN_CARRIER_QUORUM_ENDPOINTS}"
        )));
    }
    if observations.len() < policy.min_independent_endpoints {
        return Err(CarrierQuorumError::InsufficientEndpoints {
            observed: observations.len(),
            required: policy.min_independent_endpoints,
        });
    }

    let mut seen_endpoints: BTreeSet<&str> = BTreeSet::new();
    let mut expected_domain: Option<u32> = None;
    let mut min_height = u64::MAX;
    let mut max_height = 0u64;
    let mut buckets: BTreeMap<(u64, Hash32, Hash32), Vec<String>> = BTreeMap::new();

    for obs in observations {
        let id = obs.endpoint_id.trim();
        if id.is_empty() {
            return Err(CarrierQuorumError::MalformedObservation(
                "endpoint_id cannot be empty".into(),
            ));
        }
        if !seen_endpoints.insert(id) {
            return Err(CarrierQuorumError::DuplicateEndpoint(id.to_string()));
        }
        if obs.state_root == [0u8; 32] || obs.evidence_digest == [0u8; 32] {
            return Err(CarrierQuorumError::MalformedObservation(format!(
                "endpoint '{id}' supplied zero state_root or evidence_digest"
            )));
        }
        match expected_domain {
            None => expected_domain = Some(obs.domain_id),
            Some(dom) if dom != obs.domain_id => {
                return Err(CarrierQuorumError::MalformedObservation(format!(
                    "endpoint '{id}' reported domain {} expected {dom}",
                    obs.domain_id
                )));
            }
            Some(_) => {}
        }
        if obs.block_height < min_height {
            min_height = obs.block_height;
        }
        if obs.block_height > max_height {
            max_height = obs.block_height;
        }
        buckets
            .entry((obs.block_height, obs.state_root, obs.evidence_digest))
            .or_default()
            .push(id.to_string());
    }

    if max_height.saturating_sub(min_height) > policy.max_height_skew {
        return Err(CarrierQuorumError::HeightSkewExceeded {
            min_height,
            max_height,
            max_allowed: policy.max_height_skew,
        });
    }

    let total_endpoints = observations.len();
    let mut best_key: Option<(u64, Hash32, Hash32)> = None;
    let mut best_count = 0usize;
    for (key, endpoints) in &buckets {
        if endpoints.len() > best_count {
            best_count = endpoints.len();
            best_key = Some(*key);
        }
    }

    // Strict majority (best_count * 2 > total_endpoints) AND >= min_independent_endpoints.
    let meets_quorum = best_count >= policy.min_independent_endpoints
        && best_count
            .checked_mul(2)
            .is_some_and(|doubled| doubled > total_endpoints);

    let Some(winning_key) = best_key.filter(|_| meets_quorum) else {
        return Err(CarrierQuorumError::ConflictingSources {
            total_endpoints,
            best_agreement: best_count,
        });
    };

    let mut agreeing_endpoints = Vec::new();
    let mut dissenting_endpoints = Vec::new();
    for (key, mut endpoints) in buckets {
        endpoints.sort();
        if key == winning_key {
            agreeing_endpoints = endpoints;
        } else {
            dissenting_endpoints.extend(endpoints);
        }
    }
    dissenting_endpoints.sort();

    let domain_id = expected_domain.ok_or_else(|| {
        CarrierQuorumError::MalformedObservation("empty carrier observation batch".into())
    })?;

    Ok(QuorumCarrierDecision {
        domain_id,
        block_height: winning_key.0,
        state_root: winning_key.1,
        evidence_digest: winning_key.2,
        agreeing_endpoints,
        dissenting_endpoints,
    })
}

// ============================================================================
// Deterministic Integer Carrier Reward Schedule
// ============================================================================

/// Policy governing carrier attestation rewards and idle-domain escalation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CarrierRewardPolicy {
    /// Base reward in smallest token atoms for a timely accepted attestation.
    pub base_reward_atoms: u128,
    /// Target freshness window in blocks (`<= target` receives `1.0x`).
    pub target_freshness_blocks: u64,
    /// Block interval per idle escalation step (`> 0`).
    pub escalation_step_blocks: u64,
    /// Basis-point bonus added per overdue step (for example `2_500` = `+25%`).
    pub escalation_bps_per_step: u64,
    /// Hard upper cap on total multiplier in basis points (`>= 10_000`).
    pub max_multiplier_bps: u64,
    /// Portion of gross reward drawn from the domain registrant bond (`0..=10_000` bps);
    /// remainder is drawn from route fees.
    pub domain_bond_share_bps: u16,
}

impl CarrierRewardPolicy {
    /// Validate policy parameters fail-closed.
    ///
    /// # Errors
    ///
    /// Refuses zero base reward, zero block intervals, sub-1.0x max multiplier,
    /// or `domain_bond_share_bps > 10_000`.
    pub fn validate(&self) -> Result<(), CarrierRewardError> {
        if self.base_reward_atoms == 0 {
            return Err(CarrierRewardError::InvalidPolicy(
                "base_reward_atoms must be > 0".into(),
            ));
        }
        if self.target_freshness_blocks == 0 || self.escalation_step_blocks == 0 {
            return Err(CarrierRewardError::InvalidPolicy(
                "freshness and escalation block intervals must be > 0".into(),
            ));
        }
        if u128::from(self.max_multiplier_bps) < BPS_SCALE {
            return Err(CarrierRewardError::InvalidPolicy(
                "max_multiplier_bps must be >= 10_000 (1.0x)".into(),
            ));
        }
        if u128::from(self.domain_bond_share_bps) > BPS_SCALE {
            return Err(CarrierRewardError::InvalidPolicy(
                "domain_bond_share_bps must be <= 10_000".into(),
            ));
        }
        Ok(())
    }
}

/// Outcome of submitting a carrier attestation on-chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierAttestationOutcome {
    /// Attestation passed verification and advanced the domain anchor.
    Accepted {
        /// Blocks elapsed since the domain's previous accepted attestation.
        blocks_since_last_attestation: u64,
        /// Funded balance currently available in the domain registrant's carrier bond.
        available_domain_bond: u128,
        /// Funded balance currently available in the route fee pool.
        available_route_fee_pool: u128,
    },
    /// Attestation failed verification or was falsified; strictly earns zero reward.
    RejectedOrFalse,
}

/// Computed deterministic integer payout for a carrier attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CarrierPayout {
    /// Effective multiplier applied in basis points (`0` when rejected, `>= 10_000` when accepted).
    pub multiplier_bps: u64,
    /// Amount drawn from the domain registrant's carrier bond.
    pub domain_bond_draw: u128,
    /// Amount drawn from the route fee pool.
    pub route_fee_draw: u128,
    /// Total carrier payout (`domain_bond_draw + route_fee_draw`).
    pub total_payout: u128,
}

/// Fail-closed errors returned by [`compute_carrier_reward`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CarrierRewardError {
    /// Policy parameter is out of range.
    InvalidPolicy(String),
    /// Checked integer arithmetic overflowed.
    Overflow(&'static str),
}

impl fmt::Display for CarrierRewardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy(m) => write!(f, "invalid carrier reward policy: {m}"),
            Self::Overflow(op) => write!(f, "carrier reward overflow in {op}"),
        }
    }
}

impl std::error::Error for CarrierRewardError {}

/// Compute deterministic integer carrier payout from funded pools.
///
/// - `RejectedOrFalse` always returns a zero payout (lying never earns reward).
/// - `Accepted` scales monotonically from `10_000` bps (`1.0x`) up to
///   `policy.max_multiplier_bps` as `blocks_since_last_attestation` exceeds
///   `policy.target_freshness_blocks`, and strictly caps draws to the funded
///   domain bond and route fee pools.
///
/// # Errors
///
/// Fails closed if `policy` is invalid or checked `u128` arithmetic overflows.
pub fn compute_carrier_reward(
    policy: &CarrierRewardPolicy,
    outcome: CarrierAttestationOutcome,
) -> Result<CarrierPayout, CarrierRewardError> {
    policy.validate()?;

    let CarrierAttestationOutcome::Accepted {
        blocks_since_last_attestation,
        available_domain_bond,
        available_route_fee_pool,
    } = outcome
    else {
        return Ok(CarrierPayout {
            multiplier_bps: 0,
            domain_bond_draw: 0,
            route_fee_draw: 0,
            total_payout: 0,
        });
    };

    let multiplier_bps: u64 = if blocks_since_last_attestation <= policy.target_freshness_blocks {
        10_000
    } else {
        let overdue = blocks_since_last_attestation - policy.target_freshness_blocks;
        // Ceiling division so the first overdue block enters step 1 immediately.
        let steps = overdue.div_ceil(policy.escalation_step_blocks);
        let bonus = steps.saturating_mul(policy.escalation_bps_per_step);
        10_000u64
            .saturating_add(bonus)
            .min(policy.max_multiplier_bps)
    };

    let gross_reward = policy
        .base_reward_atoms
        .checked_mul(u128::from(multiplier_bps))
        .ok_or(CarrierRewardError::Overflow("gross_reward"))?
        / BPS_SCALE;

    let target_bond_share = gross_reward
        .checked_mul(u128::from(policy.domain_bond_share_bps))
        .ok_or(CarrierRewardError::Overflow("target_bond_share"))?
        / BPS_SCALE;
    let target_fee_share = gross_reward.saturating_sub(target_bond_share);

    let domain_bond_draw = target_bond_share.min(available_domain_bond);
    let route_fee_draw = target_fee_share.min(available_route_fee_pool);
    let total_payout = domain_bond_draw
        .checked_add(route_fee_draw)
        .ok_or(CarrierRewardError::Overflow("total_payout"))?;

    Ok(CarrierPayout {
        multiplier_bps,
        domain_bond_draw,
        route_fee_draw,
        total_payout,
    })
}
