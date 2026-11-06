//! Golden report and acceptance tests for `budlum-mobile-log-analyzer` (WP-37).

use budlum_mobile_log_analyzer::NatEnvironment;
use budlum_mobile_log_analyzer::{evaluate_bundle, parse_field_log, render_markdown_report};

const EIGHT_DEVICE_FIXTURE: &str = "\
# WP-37 8-device, 5-OEM golden field log
kind=device\tid=dev-pixel8a\toem=Google\tmodel=Pixel_8a\tapi=36\tram_mib=8192
kind=device\tid=dev-pixel4a\toem=Google\tmodel=Pixel_4a\tapi=29\tram_mib=6144
kind=device\tid=dev-s24\toem=Samsung\tmodel=Galaxy_S24\tapi=35\tram_mib=8192
kind=device\tid=dev-a15-4gb\toem=Samsung\tmodel=Galaxy_A15\tapi=34\tram_mib=4096
kind=device\tid=dev-rn13\toem=Xiaomi\tmodel=Redmi_Note_13\tapi=34\tram_mib=6144
kind=device\tid=dev-nordce4\toem=OnePlus\tmodel=Nord_CE_4\tapi=35\tram_mib=8192
kind=device\tid=dev-motog54\toem=Motorola\tmodel=Moto_G54\tapi=34\tram_mib=8192
kind=device\tid=dev-findx\toem=Oppo\tmodel=Reno_11\tapi=34\tram_mib=8192

kind=soak24h\tid=dev-pixel8a\tduration_secs=86400\ton_timeout=false\taudits_ok=96\taudits_missed=0
kind=soak24h\tid=dev-pixel4a\tduration_secs=86450\ton_timeout=false\taudits_ok=96\taudits_missed=0
kind=soak24h\tid=dev-s24\tduration_secs=86400\ton_timeout=false\taudits_ok=96\taudits_missed=0
kind=soak24h\tid=dev-a15-4gb\tduration_secs=86410\ton_timeout=false\taudits_ok=95\taudits_missed=0
kind=soak24h\tid=dev-rn13\tduration_secs=86400\ton_timeout=false\taudits_ok=96\taudits_missed=0
kind=soak24h\tid=dev-nordce4\tduration_secs=86400\ton_timeout=false\taudits_ok=96\taudits_missed=0
kind=soak24h\tid=dev-motog54\tduration_secs=86420\ton_timeout=false\taudits_ok=96\taudits_missed=0
kind=soak24h\tid=dev-findx\tduration_secs=86400\ton_timeout=false\taudits_ok=96\taudits_missed=0

kind=battery\tid=dev-pixel8a\tdrain_bps=380
kind=battery\tid=dev-pixel4a\tdrain_bps=490
kind=battery\tid=dev-s24\tdrain_bps=360
kind=battery\tid=dev-a15-4gb\tdrain_bps=450
kind=battery\tid=dev-rn13\tdrain_bps=470
kind=battery\tid=dev-nordce4\tdrain_secs=0\tdrain_bps=410
kind=battery\tid=dev-motog54\tdrain_bps=440
kind=battery\tid=dev-findx\tdrain_bps=540\tnote=ColorOS_cellular_handover_spike_under_weak_signal

kind=nat\tid=dev-pixel8a\tenv=home_nat\tpath=direct
kind=nat\tid=dev-s24\tenv=home_nat\tpath=hole_punch
kind=nat\tid=dev-rn13\tenv=carrier_cgnat\tpath=hole_punch
kind=nat\tid=dev-a15-4gb\tenv=carrier_cgnat\tpath=relay
kind=nat\tid=dev-nordce4\tenv=ipv6_only\tpath=direct
kind=nat\tid=dev-motog54\tenv=ipv6_only\tpath=relay
";

#[test]
fn device_log_analyzer_golden_reports() {
    let bundle = parse_field_log(EIGHT_DEVICE_FIXTURE).expect("golden fixture parses");
    let summary = evaluate_bundle(&bundle);
    assert!(summary.matrix_criteria_met);
    assert!(summary.overall_passed());

    let report_a = render_markdown_report(&bundle, &summary);
    let report_b = render_markdown_report(&bundle, &summary);
    assert_eq!(report_a, report_b, "report rendering must be deterministic");
    assert!(report_a.contains("Overall verdict: **PASS**"));
    assert!(report_a.contains("OEM families covered: Google, Samsung, Xiaomi, BBK, Motorola"));
    assert!(report_a.contains("ColorOS_cellular_handover_spike_under_weak_signal"));
}

#[test]
fn android_specialuse_service_runs_24h() {
    let mut broken = EIGHT_DEVICE_FIXTURE.replace("on_timeout=false", "on_timeout=true");
    let bundle = parse_field_log(&broken).expect("timeout fixture parses");
    let summary = evaluate_bundle(&bundle);
    assert!(
        !summary.soak_all_passed,
        "any Service.onTimeout invocation during 24h must fail the soak gate"
    );

    broken = EIGHT_DEVICE_FIXTURE.replace("duration_secs=86400", "duration_secs=21600");
    let short_bundle = parse_field_log(&broken).expect("short fixture parses");
    let short_summary = evaluate_bundle(&short_bundle);
    assert!(
        !short_summary.soak_all_passed,
        "6h dataSync-style cutoff (< 86400s) must fail the 24h soak gate"
    );
}

#[test]
fn android_battery_budget() {
    let unexplained = EIGHT_DEVICE_FIXTURE.replace(
        "kind=battery\tid=dev-s24\tdrain_bps=360",
        "kind=battery\tid=dev-s24\tdrain_bps=620",
    );
    let bundle = parse_field_log(&unexplained).expect("battery fixture parses");
    let summary = evaluate_bundle(&bundle);
    assert!(
        !summary.battery_all_passed,
        "uncharged drain above 5.00% without a documented variance note must fail"
    );
}

#[test]
fn mobile_nat_matrix() {
    let bundle = parse_field_log(EIGHT_DEVICE_FIXTURE).expect("golden fixture parses");
    let summary = evaluate_bundle(&bundle);
    let cgnat = summary
        .nat_by_env
        .get(&NatEnvironment::CarrierCgnat)
        .expect("carrier_cgnat summary present");
    assert_eq!(cgnat.total, 2);
    assert_eq!(cgnat.connected, 2);
    assert_eq!(cgnat.hole_punch_bps, 5_000);
    assert_eq!(cgnat.relay_bps, 5_000);

    let failed_nat = format!(
        "{EIGHT_DEVICE_FIXTURE}\nkind=nat\tid=dev-pixel4a\tenv=carrier_cgnat\tpath=failed\n"
    );
    let failed_bundle = parse_field_log(&failed_nat).expect("failed nat fixture parses");
    let failed_summary = evaluate_bundle(&failed_bundle);
    assert!(
        !failed_summary.nat_all_connected,
        "an unconnected NAT probe must fail the matrix connectivity check"
    );
}
