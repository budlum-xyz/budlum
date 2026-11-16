//! Claim fees: what a claim costs and who is paid.
//!
//! Block execution reaches [`settle`] through
//! [`super::chain::settlement_of`]: the executor takes the claim fees out of
//! the fee of each paying transaction and credits the [`FeePayout`].

use super::claim::Claim;
use super::frame::ClaimFrame;
use super::params::AggParams;
use crate::core::address::Address;

/// Basis points of a whole.
const BPS: u128 = 10_000;

/// `claim_fee(claim) = claim_fee_per_byte * encoded bytes of the claim`.
#[must_use]
pub fn claim_fee(params: &AggParams, claim: &Claim) -> u64 {
    let bytes = u64::try_from(claim.encoded_len()).unwrap_or(u64::MAX);
    params.claim_fee_per_byte.saturating_mul(bytes)
}

/// Split the claim fees a segment collected: the aggregator share and the
/// rest, which goes to the block producer. The two parts add up to `total`.
///
/// The split is exposed for a wallet or an explorer that shows what a
/// claim pays to whom; [`settle`] is the caller on the chain.
#[must_use]
pub fn split_segment_fees(params: &AggParams, total: u64) -> (u64, u64) {
    let bps = u128::from(params.agg_share_bps).min(BPS);
    let share = u128::from(total).saturating_mul(bps) / BPS;
    let share = u64::try_from(share).unwrap_or(total).min(total);
    (share, total.saturating_sub(share))
}

/// Who is paid what for the claims of a block.
///
/// The type is exposed for the executor, which reads it through
/// [`ClaimSettlement::payout`] when it credits the claim fees of a block.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FeePayout {
    /// The amount each aggregator earns, one entry per segment, in segment
    /// order.
    pub aggregators: Vec<(Address, u64)>,
    /// The amount the block producer earns.
    pub producer: u64,
}

/// The payout of a block frame.
///
/// `paid` holds, per claim in frame order, the claim fee that was collected:
/// the fee of the claim when its first referring transaction paid it, zero
/// when that transaction failed because its fee did not cover it. The claim
/// stays in the frame either way.
#[must_use]
fn payout(params: &AggParams, frame: &ClaimFrame, paid: &[u64]) -> FeePayout {
    let mut out = FeePayout::default();
    let mut rest = paid;
    for segment in &frame.segments {
        let count = usize::try_from(segment.count).unwrap_or(usize::MAX);
        let (own, tail) = rest.split_at(count.min(rest.len()));
        rest = tail;
        let total = own.iter().fold(0u64, |acc, fee| acc.saturating_add(*fee));
        let (aggregator, producer) = split_segment_fees(params, total);
        out.aggregators.push((segment.aggregator, aggregator));
        out.producer = out.producer.saturating_add(producer);
    }
    out
}

/// What the claim fees of a block come to.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClaimSettlement {
    /// Per transaction of the block: the claim fees taken out of its fee.
    pub charged: Vec<u64>,
    /// Per transaction of the block: whether it fails because its fee does
    /// not cover the claims it is first to refer to.
    pub failed: Vec<bool>,
    /// Who is paid.
    pub payout: FeePayout,
}

/// Settle the claim fees of a block.
///
/// `payers` holds, per claim in frame order, the index of the first
/// transaction that refers to it, and `tx_fees` the fee of every transaction
/// of the block. The fee of a claim is taken out of the fee of its payer. A
/// transaction whose fee does not cover every claim it pays for fails and
/// pays for none of them; its claims stay in the frame and earn nothing.
#[must_use]
pub fn settle(
    params: &AggParams,
    frame: &ClaimFrame,
    payers: &[usize],
    tx_fees: &[u64],
) -> ClaimSettlement {
    let mut owed = vec![0u64; tx_fees.len()];
    for (claim, payer) in frame.claims.iter().zip(payers) {
        if let Some(slot) = owed.get_mut(*payer) {
            *slot = slot.saturating_add(claim_fee(params, claim));
        }
    }
    let failed: Vec<bool> = owed
        .iter()
        .zip(tx_fees)
        .map(|(owed, fee)| owed > fee)
        .collect();
    let paid: Vec<u64> = frame
        .claims
        .iter()
        .zip(payers)
        .map(|(claim, payer)| match failed.get(*payer) {
            Some(false) => claim_fee(params, claim),
            _ => 0,
        })
        .collect();
    let charged = owed
        .iter()
        .zip(&failed)
        .map(|(owed, failed)| if *failed { 0 } else { *owed })
        .collect();
    ClaimSettlement {
        charged,
        failed,
        payout: payout(params, frame, &paid),
    }
}
