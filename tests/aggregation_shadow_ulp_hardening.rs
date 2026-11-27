//! Regression tests for aggregation claim-fee supply conservation across
//! unsegmented tail claims and zero-address segment aggregators.

use budlum_core::aggregation::claim::Claim;
use budlum_core::aggregation::fees::settle;
use budlum_core::aggregation::frame::{ClaimFrame, Segment, SegmentAttestation};
use budlum_core::aggregation::params::AggParams;
use budlum_core::core::address::Address;
use budlum_core::crypto::primitives::{ML_DSA_87_PUBLIC_KEY_LEN, ML_DSA_87_SIGNATURE_LEN};
use budlum_core::crypto::scheme::SchemeId;

fn sample_claim(tag: u8) -> Claim {
    Claim::Sig {
        scheme: SchemeId::ML_DSA_87,
        signer: Address::from([tag; 32]),
        msg_hash: [tag.wrapping_add(1); 32],
    }
}

fn dummy_att() -> SegmentAttestation {
    SegmentAttestation {
        public_key: Box::new([0x11; ML_DSA_87_PUBLIC_KEY_LEN]),
        signature: Box::new([0x22; ML_DSA_87_SIGNATURE_LEN]),
    }
}

#[test]
fn aggregation_settle_conserves_total_charged_fees_and_never_pays_zero_aggregator() {
    let mut params = AggParams::default();
    params.claim_fee_per_byte = 10;
    params.agg_share_bps = 5_000; // 50%

    let c1 = sample_claim(1);
    let c2 = sample_claim(2);

    // Frame has 2 claims, but Segment 0 has aggregator == Address::zero() and count == 1
    // (leaving c2 unsegmented in tail). Both claims are paid by tx 0!
    let frame = ClaimFrame {
        segments: vec![Segment {
            claims_root: [0xAA; 32],
            count: 1,
            aggregator: Address::zero(),
            attestation: dummy_att(),
        }],
        shape: Vec::new(),
        claims: vec![c1, c2],
        proof: Vec::new(),
    };

    let settlement = settle(&params, &frame, &[0, 0], &[1_000_000]);
    let total_charged: u64 = settlement.charged.iter().sum();
    let total_agg_paid: u64 = settlement
        .payout
        .aggregators
        .iter()
        .map(|(_, amt)| *amt)
        .sum();
    let total_credited = total_agg_paid.saturating_add(settlement.payout.producer);

    assert!(total_charged > 0);
    assert_eq!(
        total_credited, total_charged,
        "charged claim fees ({total_charged}) must equal total credited payouts ({total_credited}); supply must never vanish"
    );
    assert!(
        settlement
            .payout
            .aggregators
            .iter()
            .all(|(addr, amt)| *addr != Address::zero() || *amt == 0),
        "Address::zero() aggregator must never receive positive fee payout"
    );
}
