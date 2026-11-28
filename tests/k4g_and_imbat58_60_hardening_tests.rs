use budlum_core::bns::registry::BnsRegistry;
use budlum_core::core::address::Address;
use budlum_core::pollen::offers::MarketplaceRegistry;
use budlum_core::relayer::policy::{
    IntentSettlement, IntentSettlementStatus, RelayerPolicyRegistry,
    DEFAULT_SOLVER_CONCENTRATION_WARN_BPS,
};
use budlum_core::settlement::liquidation_proof::{
    evaluate_quote_against_proven_twap, AmmReserveSnapshot, LiquidationError,
    DEFAULT_QUOTE_DEVIATION_WARN_BPS,
};
use budlum_core::socialfi::nft_folders::{NftFolderRegistry, SocialFiBud3Error};
use budlum_core::storage::ContentId;

fn must<T, E: std::fmt::Debug>(res: Result<T, E>, msg: &str) -> T {
    match res {
        Ok(v) => v,
        Err(e) => panic!("{msg}: {e:?}"),
    }
}

fn addr(byte: u8) -> Address {
    Address::from([byte; 32])
}

#[test]
fn k4g_og2_proven_twap_reference_warns_only_when_solver_quote_deviates_above_threshold() {
    // 3 epochs of proven AMM reserves at exact 2.000 price (reserve_y / reserve_x = 2.0 -> 2e18).
    let observations = vec![
        AmmReserveSnapshot {
            state_root: [0x11; 32],
            epoch: 10,
            reserve_x: 1_000_000,
            reserve_y: 2_000_000,
            proof: vec![[0xA1; 32]],
        },
        AmmReserveSnapshot {
            state_root: [0x22; 32],
            epoch: 11,
            reserve_x: 1_000_000,
            reserve_y: 2_000_000,
            proof: vec![[0xA2; 32]],
        },
        AmmReserveSnapshot {
            state_root: [0x33; 32],
            epoch: 12,
            reserve_x: 1_000_000,
            reserve_y: 2_000_000,
            proof: vec![[0xA3; 32]],
        },
    ];

    let two_e18: u128 = 2_000_000_000_000_000_000;

    // Quote deviating by 2% (200 bps) is within the 500 bps threshold -> no warning.
    let fair_quote = two_e18 + two_e18 / 50;
    let fair = must(
        evaluate_quote_against_proven_twap(
            &observations,
            fair_quote,
            DEFAULT_QUOTE_DEVIATION_WARN_BPS,
        ),
        "fair quote advisory",
    );
    assert_eq!(fair.reference_twap_scaled, two_e18);
    assert_eq!(fair.deviation_bps, 200);
    assert!(!fair.exceeds_threshold);

    // Quote deviating by 12% (1200 bps) triggers the non-binding wallet advisory warning.
    let bad_quote = two_e18 - (two_e18 * 12) / 100;
    let bad = must(
        evaluate_quote_against_proven_twap(
            &observations,
            bad_quote,
            DEFAULT_QUOTE_DEVIATION_WARN_BPS,
        ),
        "bad quote advisory",
    );
    assert_eq!(bad.deviation_bps, 1_200);
    assert!(bad.exceeds_threshold);

    // Insufficient reserve history fails closed rather than synthesizing an oracle price.
    let short_obs = observations.get(..1).map_or_else(Vec::new, |s| s.to_vec());
    assert!(matches!(
        evaluate_quote_against_proven_twap(&short_obs, two_e18, DEFAULT_QUOTE_DEVIATION_WARN_BPS),
        Err(LiquidationError::InsufficientObservations { .. })
    ));
}

#[test]
fn k4g_og6_solver_concentration_report_alerts_when_single_solver_exceeds_share_threshold() {
    let mut reg = RelayerPolicyRegistry::default();
    let empty = reg.get_solver_concentration_report(DEFAULT_SOLVER_CONCENTRATION_WARN_BPS);
    assert_eq!(empty.total_executed_settlements, 0);
    assert!(!empty.concentration_alert);

    // Balanced market: 3 solvers with 2 executed settlements each (3333 bps <= 5000 bps -> no alert).
    for (idx, solver_byte) in [1u8, 1, 2, 2, 3, 3].iter().enumerate() {
        let mut id = [0u8; 32];
        id[0] = u8::try_from(idx + 1).unwrap_or(1);
        reg.settlements.insert(
            id,
            IntentSettlement {
                intent_id: id,
                relayer: addr(*solver_byte),
                paid_fee: 100,
                settled_at_block: 10 + u64::try_from(idx).unwrap_or(0),
                status: IntentSettlementStatus::Executed,
            },
        );
    }
    // Non-executed rows (Expired/Slashed) must NOT distort executed solver market share.
    reg.settlements.insert(
        [0xFE; 32],
        IntentSettlement {
            intent_id: [0xFE; 32],
            relayer: addr(1),
            paid_fee: 0,
            settled_at_block: 20,
            status: IntentSettlementStatus::Expired,
        },
    );
    let balanced = reg.get_solver_concentration_report(DEFAULT_SOLVER_CONCENTRATION_WARN_BPS);
    assert_eq!(balanced.total_executed_settlements, 6);
    assert_eq!(balanced.distinct_solvers, 3);
    assert_eq!(balanced.top_solver_share_bps, 3_333);
    assert!(!balanced.concentration_alert);

    // Dominant solver captures 5 more settlements -> 7/11 = 6363 bps > 5000 bps -> alert fires!
    for extra in 0u8..5u8 {
        let id = [0x80 + extra; 32];
        reg.settlements.insert(
            id,
            IntentSettlement {
                intent_id: id,
                relayer: addr(1),
                paid_fee: 100,
                settled_at_block: 30 + u64::from(extra),
                status: IntentSettlementStatus::Executed,
            },
        );
    }
    let concentrated = reg.get_solver_concentration_report(DEFAULT_SOLVER_CONCENTRATION_WARN_BPS);
    assert_eq!(concentrated.total_executed_settlements, 11);
    assert_eq!(concentrated.top_solver, Some(addr(1)));
    assert_eq!(concentrated.top_solver_settlements, 7);
    assert_eq!(concentrated.top_solver_share_bps, 6_363);
    assert!(concentrated.concentration_alert);
}

#[test]
fn imbat58_59_checked_counters_refuse_u64_max_overwrite_and_grace_overflow() {
    // 1. SocialFi NftFolderRegistry refuses u64::MAX next_folder_id instead of saturating/overwriting.
    let saturated_json = serde_json::json!({
        "commitments": {},
        "folders": {},
        "owner_folders": {},
        "next_folder_id": u64::MAX
    });
    let mut folders: NftFolderRegistry = must(
        serde_json::from_value(saturated_json),
        "deserialize saturated NftFolderRegistry",
    );
    assert_eq!(
        folders.create_folder(addr(0x11), "vault"),
        Err(SocialFiBud3Error::FolderLimitExceeded)
    );

    // 2. Pollen MarketplaceRegistry refuses u64::MAX next_offer_id instead of saturating.
    let mut market = MarketplaceRegistry::new();
    market.next_offer_id = u64::MAX;
    let cid = ContentId([0x44; 32]);
    let offer_err = market.create_offer(addr(0x22), cid, 1_000, 10);
    assert!(
        offer_err.is_err(),
        "u64::MAX next_offer_id must fail closed"
    );

    // 3. BNS renew refuses expires_at + GRACE_PERIOD overflow near u64::MAX.
    let near_max = u64::MAX - BnsRegistry::GRACE_PERIOD + 1;
    let bns_json = serde_json::json!({
        "names": {
            "alpha.bud": {
                "name": "alpha.bud",
                "owner": addr(0x33),
                "registered_at": near_max - 10,
                "expires_at": near_max - 5,
                "content_hash": null,
                "endpoint": null,
                "subdomains": {}
            }
        }
    });
    if let Ok(mut bns) = serde_json::from_value::<BnsRegistry>(bns_json) {
        let renew_res = bns.renew(
            "alpha.bud",
            &addr(0x33),
            near_max - 6,
            budlum_core::bns::MIN_DURATION,
        );
        assert!(
            renew_res.is_err(),
            "renewal whose expires_at + GRACE_PERIOD overflows u64 must be refused"
        );
    }
}

#[test]
fn imbat58_59_offer_id_exhaustion_prevents_post_prune_id_reuse() {
    let mut market = MarketplaceRegistry::new();
    let first_seller = addr(0x51);
    let second_seller = addr(0x52);
    let cid = ContentId([0x45; 32]);
    market.next_offer_id = u64::MAX - 1;

    assert_eq!(
        market.create_offer(first_seller, cid, 1_000, 10),
        Ok(u64::MAX - 1)
    );
    assert_eq!(market.next_offer_id, u64::MAX);

    // Close and evict the terminal offer (simulating MAX_OFFERS retain or TTL sweep):
    // an exhausted counter at u64::MAX must still fail closed rather than issuing a
    // saturating u64::MAX id that could later be evicted and handed to a second seller.
    must(
        market.close_offer(u64::MAX - 1, &first_seller),
        "close terminal offer",
    );
    market.offers.remove(&(u64::MAX - 1));

    assert_eq!(
        market
            .create_offer(second_seller, cid, 2_000, 11)
            .err()
            .as_deref(),
        Some("offer id counter exhausted")
    );
    assert!(market.offers.is_empty());
    assert_eq!(market.next_offer_id, u64::MAX);
}
