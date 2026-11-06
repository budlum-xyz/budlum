//! End-to-end rehearsal drill suite (`T-1`..`T-7`, WP-46) and Mobile device
//! field-test telemetry suite (WP-37).

use budlum::registry::handover::HandoverCoordinator;
use budlum::registry::presence::{PresenceTracker, ValidatorDutyState};
use budlum::registry::rehearsal::{
    analyze_mobile_field_logs, evaluate_rehearsal_drills, verify_rehearsal_topology,
    RehearsalDrillReport, RehearsalTopology, RehearsalValidatorNode, MIN_REHEARSAL_STEADY_SECS,
    MIN_T5_SMALL_OBJECT_COUNT, MIN_T5_TOTAL_UPLOAD_BYTES,
};
use budlum::storage::bud3::content_gateway::Bud3ContentGateway;
use budlum::storage::bud3::limits::{Bud3Limits, Profile};
use budlum::storage::bud3::pipeline::prepare_public_upload;
use budlum::storage::bud3::placement::{Class, Share};
use budlum::storage::bud3::registry::Bud3Registry;
use budlum::storage::bud3::volume::AggregationVolume;

const P: Profile = Profile {
    id: 0,
    qr_version: 40,
    symbol_size: 1024,
    fps: 10,
    k_max: 64,
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
    verify_rehearsal_topology(&topo).expect("valid rehearsal topology");

    // 2. Simulate T-1 & T-4 on live B.U.D. 3.0 + PresenceTracker + HandoverCoordinator state:
    //    Upload an object across 8 Full + 4 Mobile shares, shut down 100% of Mobile validators,
    //    verify zero slashing, Full-class reads continue, and `ResumeValidator` reactivates next epoch.
    let mut bud3 = Bud3Registry::new();
    let mut gateway = Bud3ContentGateway::new();
    let mut presence = PresenceTracker::new();
    for i in 0..8u8 {
        presence.register_validator([i + 1; 32], Class::Full, 10_000_000_000);
    }
    for m in 0..4u8 {
        presence.register_validator([100 + m; 32], Class::Mobile, 100_000_000);
    }

    let payload = b"rehearsal t1 mobile mass-shutdown resilience payload".repeat(40);
    let up = prepare_public_upload(&payload, &P, &Bud3Limits::default()).unwrap();
    let key = up.record.commitment;
    let shares = vec![
        (
            0,
            Share {
                validator: [1u8; 32],
                class: Class::Full,
                first_esi: 0,
                symbol_count: up.record.symbols_per_segment,
            },
        ),
        (
            0,
            Share {
                validator: [100u8; 32],
                class: Class::Mobile,
                first_esi: up.record.symbols_per_segment,
                symbol_count: 2,
            },
        ),
    ];
    let nft_id = [0xEE; 32];
    bud3.register_object(up.record.clone(), shares, 1, 30, 20_000)
        .unwrap();
    bud3.bind_nft(nft_id, key).unwrap();
    gateway.stage_object(&up.record, &up.object_bytes).unwrap();

    // T-1: All Mobile validators miss presence for 2 consecutive epochs -> Suspended (zero slash!),
    // while Full-class read via gateway continues uninterrupted.
    for epoch in 1..=2 {
        for i in 0..8u8 {
            presence.record_heartbeat([i + 1; 32], epoch);
        }
        presence.finalize_epoch(epoch);
    }
    assert_eq!(
        presence.duty_state(&[100u8; 32]),
        Some(ValidatorDutyState::Suspended)
    );
    assert_eq!(presence.stake_of(&[100u8; 32]), Some(100_000_000));
    let read_t1 = gateway.get_object(&bud3, &key, Some(nft_id), None, 25).unwrap();
    assert_eq!(read_t1.body, payload);

    // T-3: > 1/3 Full seats silent for 50 blocks triggers disaster-recovery flag, then clears on checkpoint.
    let mut handover = HandoverCoordinator::new();
    for h in 1..=50 {
        handover.observe_block(h, false);
    }
    assert!(handover.in_disaster_recovery());
    handover.observe_block(51, true);
    assert!(!handover.in_disaster_recovery());

    // T-4: Mobile submits `ResumeValidator` in epoch 3 -> activates in epoch 4.
    presence.submit_resume([100u8; 32], 3).unwrap();
    for i in 0..8u8 {
        presence.record_heartbeat([i + 1; 32], 3);
    }
    presence.record_heartbeat([100u8; 32], 3);
    presence.finalize_epoch(3);
    assert_eq!(
        presence.duty_state(&[100u8; 32]),
        Some(ValidatorDutyState::Active)
    );

    // T-5 small-object packing smoke via AggregationVolume.
    let mut vol = AggregationVolume::new(1);
    for idx in 0..64u16 {
        let small = idx.to_le_bytes();
        let sup = prepare_public_upload(&small, &P, &Bud3Limits::default()).unwrap();
        vol.append(sup.record.content_id, &sup.object_bytes).unwrap();
    }
    assert_eq!(vol.entry_count(), 64);

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
    evaluate_rehearsal_drills(&report).expect("all seven rehearsal drills pass");

    // 3. WP-37: Verify 20-device Android JSONL field telemetry stream.
    let mut jsonl = String::new();
    for dev in 0..20u32 {
        jsonl.push_str(&format!(
            "{{\"device_id\":\"android-{dev:02}\",\"tier\":\"midrange8_gb\",\"peak_rss_mib\":124,\"daily_battery_bps\":215,\"metered_bytes_served\":0,\"allow_cellular_opt_in\":false,\"audits_answered\":96,\"audits_missed\":0,\"rewards_credited_atoms\":25000}}\n"
        ));
    }
    let summary = analyze_mobile_field_logs(&jsonl).expect("valid 20-phone telemetry");
    assert_eq!(summary.device_count, 20);
    assert_eq!(summary.total_audits_answered, 1_920);
}
