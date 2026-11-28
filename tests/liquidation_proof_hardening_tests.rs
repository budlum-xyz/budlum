//! RED -> GREEN -> MUTATION security & overflow suite for CEO K4-H
//! (`src/settlement/liquidation_proof.rs`, `USTURPA-01-K4H-LIQUIDATION-PROOF-HARDENING`).
//!
//! Covers:
//! 1. 18-decimal (`1e18`) `u128` saturation bug in `execute_liquidation`,
//!    `prove_position_health`, `compute_seized_collateral`, and
//!    `execute_proven_cross_domain_liquidation` (both healthy-position false
//!    liquidation and seizure under-calculation).
//! 2. Exact boundary invariant (`health_bps == maintenance_threshold_bps` is
//!    healthy and NOT liquidatable; only `health_bps < maintenance_threshold_bps`
//!    is liquidatable).
//! 3. Minimum geometric liquidity floor `sqrt(reserve_x * reserve_y) >= MIN_POOL_LIQUIDITY`
//!    blocking dust-pool TWAP manipulation.
//! 4. Consecutive observation price-jump bound (`MAX_CONSECUTIVE_PRICE_JUMP_BPS`)
//!    and minimum epoch span (`MIN_TWAP_EPOCH_SPAN`).
//! 5. Cross-domain AMM observation domain mixing rejection in `prove_position_health`
//!    and duplicate `(domain_id, asset_id)` leg rejection in
//!    `execute_proven_cross_domain_liquidation`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use budlum_core::domain::types::Hash32;
use budlum_core::settlement::liquidation_proof::{
    build_reserve_inclusion_proof, build_reserve_state_root, execute_liquidation,
    execute_proven_cross_domain_liquidation, prove_position_health, reserve_observation_leaf,
    AmmReserveSnapshot, CollateralLegSpec, CrossDomainLiquidationParams, LiquidationError,
    LiquidationPosition, ProvenReserveObservation,
};

const E18: u128 = 1_000_000_000_000_000_000;

fn build_proven_obs(
    domain_epochs: &[(u32, u64, u128, u128)],
) -> (BTreeMap<(u32, u64), Hash32>, Vec<ProvenReserveObservation>) {
    let mut roots = BTreeMap::new();
    let mut obs = Vec::new();
    for &(domain_id, epoch, rx, ry) in domain_epochs {
        let leaf = reserve_observation_leaf(domain_id, epoch, rx, ry);
        let leaves = [leaf, [0xAB; 32]];
        let root = build_reserve_state_root(&leaves);
        let proof = build_reserve_inclusion_proof(&leaves, 0).expect("proof");
        roots.insert((domain_id, epoch), root);
        obs.push(ProvenReserveObservation {
            domain_id,
            snapshot: AmmReserveSnapshot {
                state_root: root,
                epoch,
                reserve_x: rx,
                reserve_y: ry,
                proof,
            },
            leaf_index: 0,
            leaf_count: leaves.len(),
        });
    }
    (roots, obs)
}

#[test]
fn eighteen_decimal_healthy_position_is_not_falsely_liquidated_and_unhealthy_seizes_exact_amount() {
    // Realistic 18-decimal pool: 100_000 X and 200_000 Y (price Y/X = 2.0 * 1e18).
    let rx = 100_000 * E18;
    let ry = 200_000 * E18;
    let (roots, proven_obs) =
        build_proven_obs(&[(10, 100, rx, ry), (10, 101, rx, ry), (10, 102, rx, ry)]);
    let raw_obs: Vec<AmmReserveSnapshot> = proven_obs.iter().map(|o| o.snapshot.clone()).collect();

    // 1b. Even with small integer pool reserves (`rx = 1_000, ry = 2_000`) where
    // `instant_price_scaled` does NOT return `PriceOverflow`, a healthy 18-decimal
    // position (`debt = 5_000 * 1e18, collateral = 20_000 * 1e18` -> 200% health)
    // previously saturated `collateral_y.saturating_mul(1e18)` at `u128::MAX` (~3.4e38)
    // and reported `health_bps = 340` (< 15_000), falsely liquidating a 200%-solvent user!
    let (small_roots, small_obs) = build_proven_obs(&[
        (10, 100, 1_000, 2_000),
        (10, 101, 1_000, 2_000),
        (10, 102, 1_000, 2_000),
    ]);
    let small_health = prove_position_health(
        &LiquidationPosition {
            position_id: 100,
            debt_x: 5_000 * E18,
            collateral_y: 20_000 * E18,
            maintenance_threshold_bps: 15_000,
        },
        1,
        &small_roots,
        &small_obs,
    )
    .expect("small-pool 18-decimal position health");
    assert_eq!(small_health.health_bps, 20_000);
    assert!(
        !small_health.liquidatable,
        "200%-healthy 18-decimal position on small-unit pool must not saturate to 340 bps"
    );

    // 1. Realistic 18-decimal pool + 18-decimal healthy position:
    let healthy_18d = LiquidationPosition {
        position_id: 101,
        debt_x: 5_000 * E18,
        collateral_y: 20_000 * E18,
        maintenance_threshold_bps: 15_000,
    };
    let health = prove_position_health(&healthy_18d, 1, &roots, &proven_obs)
        .expect("18-decimal health proof must succeed");
    assert_eq!(health.health_bps, 20_000);
    assert!(
        !health.liquidatable,
        "200%-collateralized 18-decimal position must NEVER be marked liquidatable"
    );
    let batch_out = execute_liquidation(&raw_obs, std::slice::from_ref(&healthy_18d))
        .expect("batch liquidation");
    assert!(
        batch_out.is_empty(),
        "execute_liquidation must not liquidate a 200%-healthy 18-decimal position"
    );

    // 2. Unhealthy 18-decimal position:
    // debt_x = 10_000 * 1e18 (worth 20_000 Y at price 2.0),
    // collateral_y = 25_000 * 1e18 (health = 12_500 bps < 15_000 bps).
    // Repaying 5_000 * 1e18 (50% close factor) with 500 bps (5%) bonus at price 2.0
    // MUST seize `5_000 * 2.0 * 1.05 * 1e18 = 10_500 * 1e18` Y, NOT saturate to ~0.034 Y!
    let unhealthy_18d = LiquidationPosition {
        position_id: 102,
        debt_x: 10_000 * E18,
        collateral_y: 25_000 * E18,
        maintenance_threshold_bps: 15_000,
    };
    let legs = vec![CollateralLegSpec {
        domain_id: 20,
        asset_id: [0x20; 32],
        custody_or_remote_root: [0xBB; 32],
        available_y: 25_000 * E18,
    }];
    let res = execute_proven_cross_domain_liquidation(
        &unhealthy_18d,
        &roots,
        &proven_obs,
        &legs,
        &CrossDomainLiquidationParams {
            debt_domain_id: 1,
            repay_debt_x: 5_000 * E18,
            bonus_bps: 500,
            delivery_proof_root: [0xDD; 32],
        },
    )
    .expect("18-decimal cross-domain liquidation must succeed");
    assert_eq!(res.seized_legs.len(), 1);
    assert_eq!(res.seized_legs[0].seized_y, 10_500 * E18);
    assert_eq!(res.seized_legs[0].remainder_y, 14_500 * E18);

    // Full batch liquidation on `unhealthy_18d` seizes `10_000 * 2.0 * 1.05 = 21_000 * 1e18`.
    let full_out = execute_liquidation(&raw_obs, std::slice::from_ref(&unhealthy_18d))
        .expect("18-decimal batch liquidation");
    assert_eq!(full_out.len(), 1);
    assert_eq!(full_out[0].seized_collateral_y, 21_000 * E18);
    assert_eq!(full_out[0].remainder_y, 4_000 * E18);
}

#[test]
fn exact_maintenance_threshold_boundary_is_healthy_and_not_liquidatable() {
    // Price = 2.0, debt = 1_000, collateral = 3_000 -> health = 15_000 bps == threshold (15_000 bps).
    // At exact maintenance threshold, the position meets its maintenance requirement and must NOT be liquidated!
    let (roots, proven_obs) = build_proven_obs(&[
        (10, 10, 1_000, 2_000),
        (10, 11, 1_000, 2_000),
        (10, 12, 1_000, 2_000),
    ]);
    let raw_obs: Vec<AmmReserveSnapshot> = proven_obs.iter().map(|o| o.snapshot.clone()).collect();
    let boundary_pos = LiquidationPosition {
        position_id: 201,
        debt_x: 1_000,
        collateral_y: 3_000,
        maintenance_threshold_bps: 15_000,
    };
    let health = prove_position_health(&boundary_pos, 1, &roots, &proven_obs).expect("health");
    assert_eq!(health.health_bps, 15_000);
    assert!(
        !health.liquidatable,
        "health_bps == maintenance_threshold_bps must be healthy (not liquidatable)"
    );
    let batch_out = execute_liquidation(&raw_obs, &[boundary_pos]).expect("batch");
    assert!(
        batch_out.is_empty(),
        "execute_liquidation must skip positions right at maintenance_threshold_bps"
    );
}

#[test]
fn liquidation_rejects_dust_pool_liquidity_and_extreme_consecutive_price_jump() {
    let pos = LiquidationPosition {
        position_id: 301,
        debt_x: 1_000,
        collateral_y: 1_000,
        maintenance_threshold_bps: 15_000,
    };

    // 1. Dust 1-wei pool (`reserve_x = 1, reserve_y = 2`) has geometric liquidity < MIN_POOL_LIQUIDITY.
    let (_, dust_obs) = build_proven_obs(&[(10, 1, 1, 2), (10, 2, 1, 2), (10, 3, 1, 2)]);
    let dust_raw: Vec<AmmReserveSnapshot> = dust_obs.iter().map(|o| o.snapshot.clone()).collect();
    let dust_err = execute_liquidation(&dust_raw, std::slice::from_ref(&pos))
        .expect_err("dust 1-atom AMM pool must be rejected");
    assert!(
        matches!(dust_err, LiquidationError::MissingProofAnchor(_))
            || format!("{dust_err}").contains("liquidity")
    );

    // 2. Flash/sandwich 100x jump between consecutive epochs (`(1_000, 1_000) -> (1_000, 100_000) -> (1_000, 1_000)`).
    let (jump_roots, jump_obs) = build_proven_obs(&[
        (10, 1, 1_000, 1_000),
        (10, 2, 1_000, 100_000),
        (10, 3, 1_000, 1_000),
    ]);
    let jump_err = prove_position_health(&pos, 1, &jump_roots, &jump_obs)
        .expect_err("100x single-step AMM price spike must be rejected");
    assert!(
        matches!(jump_err, LiquidationError::MissingProofAnchor(_))
            || format!("{jump_err}").contains("deviation")
    );

    // 3. Stale epoch window span > MAX_TWAP_EPOCHS (100) must also be rejected!
    let (stale_roots, stale_obs) = build_proven_obs(&[
        (10, 1, 1_000, 1_000),
        (10, 50, 1_000, 1_000),
        (10, 102, 1_000, 1_000), // span = 101 > MAX_TWAP_EPOCHS (100)
    ]);
    let stale_err = prove_position_health(&pos, 1, &stale_roots, &stale_obs)
        .expect_err("TWAP epoch span > MAX_TWAP_EPOCHS must be rejected");
    assert!(matches!(stale_err, LiquidationError::MissingProofAnchor(_)));
}

#[test]
fn cross_domain_liquidation_rejects_mixed_observation_domains_and_duplicate_collateral_legs() {
    // 1. Mixing observations from domain 10 and domain 11 into a single TWAP series must fail closed!
    let (mixed_roots, mixed_obs) = build_proven_obs(&[
        (10, 10, 1_000, 2_000),
        (11, 11, 1_000, 2_000), // different domain!
        (10, 12, 1_000, 2_000),
    ]);
    let pos = LiquidationPosition {
        position_id: 401,
        debt_x: 1_000,
        collateral_y: 2_000,
        maintenance_threshold_bps: 15_000,
    };
    let mix_err = prove_position_health(&pos, 1, &mixed_roots, &mixed_obs)
        .expect_err("observations mixing distinct AMM source domains must be rejected");
    assert!(
        matches!(mix_err, LiquidationError::MissingProofAnchor(_))
            || format!("{mix_err}").contains("domain")
    );

    // 2. Duplicate `(domain_id, asset_id)` collateral legs must fail closed so a caller cannot split/alias the same asset custody proof!
    let (roots, honest_obs) = build_proven_obs(&[
        (10, 10, 1_000, 2_000),
        (10, 11, 1_000, 2_000),
        (10, 12, 1_000, 2_000),
    ]);
    let dup_legs = vec![
        CollateralLegSpec {
            domain_id: 20,
            asset_id: [0x20; 32],
            custody_or_remote_root: [0xAA; 32],
            available_y: 1_000,
        },
        CollateralLegSpec {
            domain_id: 20,
            asset_id: [0x20; 32], // duplicate (domain_id, asset_id)!
            custody_or_remote_root: [0xAA; 32],
            available_y: 1_000,
        },
    ];
    let dup_err = execute_proven_cross_domain_liquidation(
        &pos,
        &roots,
        &honest_obs,
        &dup_legs,
        &CrossDomainLiquidationParams {
            debt_domain_id: 1,
            repay_debt_x: 500,
            bonus_bps: 500,
            delivery_proof_root: [0xDD; 32],
        },
    )
    .expect_err("duplicate (domain_id, asset_id) collateral legs must be rejected");
    assert!(
        matches!(dup_err, LiquidationError::MissingProofAnchor(_))
            || format!("{dup_err}").contains("duplicate")
    );
}

#[test]
fn baseline_batch_liquidation_unit_regressions_hold() {
    let make_raw = |prices: &[(u64, u128, u128)]| -> Vec<AmmReserveSnapshot> {
        prices
            .iter()
            .map(|(epoch, rx, ry)| AmmReserveSnapshot {
                state_root: [0xAA; 32],
                epoch: *epoch,
                reserve_x: *rx,
                reserve_y: *ry,
                proof: vec![[0x01; 32]],
            })
            .collect()
    };

    // 1. Valid liquidation seizes 2100 Y on debt_x=1000, price=2.0, 5% penalty.
    let obs = make_raw(&[(1, 100, 200), (2, 100, 200), (3, 100, 200)]);
    let outcomes = execute_liquidation(
        &obs,
        &[LiquidationPosition {
            position_id: 1,
            debt_x: 1000,
            collateral_y: 2500,
            maintenance_threshold_bps: 15_000,
        }],
    )
    .expect("valid liquidation");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].seized_collateral_y, 2100);
    assert_eq!(outcomes[0].remainder_y, 400);

    // 2. TWAP varies with reserves (`2.0, 4.0, 3.0 -> 3.0e18`).
    let varied = make_raw(&[(1, 100, 200), (2, 100, 400), (3, 100, 300)]);
    let varied_out = execute_liquidation(
        &varied,
        &[LiquidationPosition {
            position_id: 1,
            debt_x: 100,
            collateral_y: 100,
            maintenance_threshold_bps: 15_000,
        }],
    )
    .expect("twap varied");
    assert_eq!(varied_out[0].twap_price_scaled, 3_000_000_000_000_000_000);

    // 3. Oracle-free cross-domain seizure order independence & close-factor / bonus bounds.
    let (roots, proven_obs) = build_proven_obs(&[
        (10, 10, 1_000, 2_000),
        (10, 11, 1_000, 2_000),
        (10, 12, 1_000, 2_000),
    ]);
    let unhealthy = LiquidationPosition {
        position_id: 42,
        debt_x: 1_000,
        collateral_y: 2_500,
        maintenance_threshold_bps: 15_000,
    };
    let legs_bc = vec![
        CollateralLegSpec {
            domain_id: 20,
            asset_id: [0x20; 32],
            custody_or_remote_root: [0xBB; 32],
            available_y: 800,
        },
        CollateralLegSpec {
            domain_id: 30,
            asset_id: [0x30; 32],
            custody_or_remote_root: [0xCC; 32],
            available_y: 1_700,
        },
    ];
    let mut legs_cb = legs_bc.clone();
    legs_cb.reverse();
    let params = CrossDomainLiquidationParams {
        debt_domain_id: 1,
        repay_debt_x: 500,
        bonus_bps: 500,
        delivery_proof_root: [0xDD; 32],
    };
    let r_bc =
        execute_proven_cross_domain_liquidation(&unhealthy, &roots, &proven_obs, &legs_bc, &params)
            .expect("bc");
    let r_cb =
        execute_proven_cross_domain_liquidation(&unhealthy, &roots, &proven_obs, &legs_cb, &params)
            .expect("cb");
    assert_eq!(r_bc, r_cb);
    assert_eq!(r_bc.seized_legs[0].seized_y, 800);
    assert_eq!(r_bc.seized_legs[1].seized_y, 250);
}
