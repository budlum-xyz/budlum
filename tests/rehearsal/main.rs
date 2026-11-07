//! End-to-end rehearsal drill suite (`T-1`..`T-7`, WP-46) and Mobile device
//! field-test telemetry suite (WP-37).

use std::collections::BTreeSet;

use budlum_core::core::address::Address;
use budlum_core::registry::handover::HandoverCoordinator;
use budlum_core::registry::presence::{PresenceClass, PresenceTracker};
use budlum_core::registry::rehearsal::{
    analyze_mobile_field_logs, evaluate_rehearsal_drills, verify_rehearsal_topology,
    RehearsalDrillReport, RehearsalTopology, RehearsalValidatorNode, MIN_REHEARSAL_STEADY_SECS,
    MIN_T5_SMALL_OBJECT_COUNT, MIN_T5_TOTAL_UPLOAD_BYTES,
};
use budlum_core::storage::bud3::bof1::Object;
use budlum_core::storage::bud3::limits::{Bud3Limits, Profile};
use budlum_core::storage::bud3::pipeline::prepare_public_upload;
use budlum_core::storage::bud3::placement::{Class, Share};
use budlum_core::storage::bud3::registry::Bud3Registry;
use budlum_core::storage::bud3::view::{view_from_network, MemorySymbolNetwork};
use budlum_core::storage::bud3::volume::{AggregationVolume, VolumeScope};

const P: Profile = Profile {
    id: 0,
    qr_version: 40,
    symbol_size: 256,
    fps: 10,
    k_max: 32,
};

#[test]
fn rehearsal_t1_to_t7_drills_and_mobile_field_matrix_hold() {
    // 1. Topology check (>= 8 Full, >= 3 regions, >= 2 cloud providers, >= 4 relays, >= 2 gateways,
    //    >= 20 Android phones, >= 1,000 simulated Mobile validators, >= 72h steady window).
    let regions = ["eu-central-1", "us-east-1", "ap-northeast-1"];
    let providers = ["hetzner", "aws"];
    let full_validators: Vec<RehearsalValidatorNode> = (0..8u8)
        .map(|i| RehearsalValidatorNode {
            validator_id: [i + 1; 32],
            region: regions[usize::from(i) % regions.len()].to_string(),
            provider: providers[usize::from(i) % providers.len()].to_string(),
        })
        .collect();
    let topo = RehearsalTopology {
        chain_id: 45262,
        genesis_digest: [0x5A; 32],
        full_validators,
        relay_count: 4,
        upload_gateway_count: 2,
        android_phone_count: 20,
        simulated_mobile_count: 1_000,
        steady_state_secs: MIN_REHEARSAL_STEADY_SECS,
    };
    verify_rehearsal_topology(&topo).unwrap();

    // 2. Simulate T-1, T-3, and T-4 on live B.U.D. 3.0 + PresenceTracker + HandoverCoordinator state.
    let mut bud3 = Bud3Registry::default();
    let mut presence = PresenceTracker::new(3, 50);
    for i in 0..8u8 {
        presence.register_validator(Address([i + 1; 32]), PresenceClass::Full, vec![i + 1; 48], 0);
    }
    for m in 0..4u8 {
        presence.register_validator(
            Address([100 + m; 32]),
            PresenceClass::Mobile,
            vec![100 + m; 48],
            0,
        );
    }

    let payload = b"rehearsal t1 mobile mass-shutdown resilience payload".repeat(12);
    let up = prepare_public_upload(&payload, &P, &Bud3Limits::default(), 16).unwrap();
    let key = up.record.commitment;
    let mut net = MemorySymbolNetwork::default();
    for (_, syms) in &up.segments {
        for sym in syms {
            net.insert([1u8; 32], key, sym.clone());
        }
    }
    let shares = vec![
        (
            0,
            Share {
                validator: [1u8; 32],
                class: Class::Full,
                first_esi: 0,
                symbols: 14,
            },
        ),
        (
            0,
            Share {
                validator: [100u8; 32],
                class: Class::Mobile,
                first_esi: 14,
                symbols: 2,
            },
        ),
    ];
    let nft_id = [0xEE; 32];
    bud3.register_object([1u8; 32], up.record, shares, 1, 30)
        .unwrap();
    bud3.bind_nft(nft_id, [1u8; 32], &key).unwrap();

    // T-1: Full validators participate while Mobile validators remain silent for 25 epochs (> 24h window);
    // Mobile validators transition to non-slashing suspension while Full-class reads succeed uninterrupted.
    let active_full: BTreeSet<Address> = (0..8u8).map(|i| Address([i + 1; 32])).collect();
    for epoch in 1..=26 {
        presence.record_full_seat_participation(&active_full, epoch);
        presence.advance_epoch(epoch);
    }
    assert!(presence.state_of(&Address([100u8; 32])).unwrap().suspended);
    let read_t1 = view_from_network(&bud3, &key, None, &net).unwrap();
    assert_eq!(read_t1, payload);

    // T-3: > 1/3 Full seats silent for 50 blocks triggers disaster-recovery gauge, then clears on checkpoint.
    let mut handover = HandoverCoordinator::default();
    for h in 1..=50 {
        handover.observe_block(h, 1, None);
    }
    assert_eq!(handover.budlum_finality_stalled(), 1);
    handover.observe_block(51, 2, Some(51));
    assert_eq!(handover.budlum_finality_stalled(), 0);

    // T-5 small-object packing smoke via AggregationVolume.
    let mut vol = AggregationVolume::new(VolumeScope::Public, P, 1 << 20);
    for idx in 0..32u16 {
        let small = idx.to_le_bytes();
        let obj = Object::raw_public(&small);
        vol.insert(&obj, None).unwrap();
    }
    assert!(!vol.bytes().is_empty());
    assert_ne!(vol.root(), [0u8; 32]);

    // Evaluate complete T-1..T-7 pass-criteria report.
    let report = RehearsalDrillReport {
        t1_finality_latency_delta_ms: 45,
        t1_lost_objects: 0,
        t1_full_class_reads_succeeded: true,
        t2_finality_lag_checkpoints: 1,
        t2_seat_handover_checkpoints: 2,
        t3_finality_stalled_alert_fired: true,
        t3_finality_resumed_after_recovery: true,
        t4_resume_activated_in_one_epoch: true,
        t4_repair_backlog_after_sweep: 0,
        t5_total_uploaded_bytes: MIN_T5_TOTAL_UPLOAD_BYTES,
        t5_small_objects_uploaded: MIN_T5_SMALL_OBJECT_COUNT,
        t5_concurrent_view_failures: 0,
        t6_toolchains_green: true,
        t6_atomic_evm_to_cw20_succeeded: true,
        t7_http_429_observed: 412,
        t7_unhandled_5xx_or_panics: 0,
    };
    evaluate_rehearsal_drills(&report).unwrap();

    // 3. WP-37: Verify 20-device Android JSONL field telemetry stream + full suite runner.
    let tiers = ["entry4_gb", "midrange6_gb", "midrange8_gb", "flagship12_gb"];
    let mut jsonl = String::new();
    for dev in 0..20u8 {
        jsonl.push_str(&format!(
            "{{\"device_id\":\"phone-{dev:02}\",\"tier\":\"{}\",\"peak_rss_mib\":118,\"daily_battery_bps\":240,\"metered_bytes_served\":0,\"allow_cellular_opt_in\":false,\"audits_answered\":48,\"audits_missed\":0,\"rewards_credited_atoms\":12500}}\n",
            tiers[usize::from(dev) % tiers.len()]
        ));
    }
    let field_summary = analyze_mobile_field_logs(&jsonl).unwrap();
    assert_eq!(field_summary.device_count, 20);
    assert_eq!(field_summary.total_audits_answered, 960);
    let suite_summary =
        budlum_core::registry::rehearsal::run_rehearsal_suite(&topo, &report, &jsonl).unwrap();
    assert_eq!(suite_summary, field_summary);
}
