//! Every Budlum metric named by a Prometheus rule or dashboard must be exported.
//!
//! The node inventory is `src/core/metrics.rs`; the faucet owns its separate
//! grant counter. Histogram constructors also export `_bucket`, `_sum` and
//! `_count`, so those suffixes are derived from real declarations rather than
//! added as a blanket exception for unknown metric names.

use std::collections::BTreeSet;

const ALERT_RULES: &str = include_str!("../../ops/monitoring/alerts.yml");
const METRIC_DEFINITIONS: &str = include_str!("../core/metrics.rs");
const FAUCET_METRIC_DEFINITIONS: &str = include_str!("../bin/budlum-faucet.rs");
const DASHBOARD: &str = include_str!("../../ops/monitoring/grafana/budlum-testnet.json");

/// All `budlum_*` tokens in `text`, split on anything that cannot be part of
/// an identifier. Metrics from other exporters (`node_*`, `up`) are out of scope.
fn budlum_metric_names(text: &str) -> BTreeSet<String> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|token| token.starts_with("budlum_") && token.len() > "budlum_".len())
        .map(str::to_string)
        .collect()
}

/// The source inventory plus the actual derived series of each histogram.
fn exported_metrics() -> BTreeSet<String> {
    let mut exported = budlum_metric_names(METRIC_DEFINITIONS)
        .into_iter()
        .chain(budlum_metric_names(FAUCET_METRIC_DEFINITIONS))
        .collect::<BTreeSet<_>>();
    let lines: Vec<&str> = METRIC_DEFINITIONS.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        if !line.contains("Histogram::") && !line.contains("HistogramOpts::new(") {
            continue;
        }
        let constructor = lines[index..(index + 4).min(lines.len())].join("\n");
        for base in budlum_metric_names(&constructor) {
            for suffix in ["_bucket", "_sum", "_count"] {
                exported.insert(format!("{base}{suffix}"));
            }
        }
    }
    exported
}

/// Only expressions are claims about a metric; comments are not queries.
fn queried_metrics(text: &str) -> BTreeSet<String> {
    let expressions: String = text
        .lines()
        .filter(|line| line.trim_start().starts_with("expr:") || line.trim_start().contains("\"expr\":"))
        .collect::<Vec<_>>()
        .join("\n");
    budlum_metric_names(&expressions)
}

#[test]
fn alert_rules_reference_existing_metrics() {
    let exported = exported_metrics();
    let referenced = queried_metrics(ALERT_RULES);
    assert!(exported.len() > 50, "the metric inventory scan is vacuous");
    assert!(!referenced.is_empty(), "the alert scan is vacuous");
    let missing: Vec<&str> = referenced
        .iter()
        .filter(|name| !exported.contains(*name))
        .map(String::as_str)
        .collect();
    assert!(missing.is_empty(), "alert rules refer to missing metrics: {missing:?}");
    assert!(referenced.contains("budlum_rpc_rate_limited_total"));
    assert!(referenced.contains("budlum_faucet_grants_total"));
}

#[test]
fn the_mandatory_alert_rules_exist_and_have_metrics() {
    let exported = exported_metrics();
    let referenced = queried_metrics(ALERT_RULES);
    for mandatory in [
        "budlum_finality_stalled",
        "budlum_finality_lag_checkpoints",
        "budlum_bud3_segments_at_risk",
        "budlum_bud3_repair_backlog",
        "budlum_relay_reservations",
        "budlum_state_root_mismatch_total",
        "budlum_rpc_rate_limited_total",
    ] {
        assert!(exported.contains(mandatory), "{mandatory} is not exported");
        assert!(referenced.contains(mandatory), "{mandatory} has no alert");
    }
}

#[test]
fn every_budlum_rule_queries_a_budlum_series() {
    let mut in_our_group = false;
    let mut rules = 0usize;
    for line in ALERT_RULES.lines() {
        let trimmed = line.trim_start();
        if let Some(name) = trimmed.strip_prefix("- name: ") {
            let name = name.trim();
            // The disk group intentionally reads node_exporter's foreign series.
            in_our_group = name.starts_with("budlum-") && name != "budlum-disk";
            continue;
        }
        if in_our_group {
            if let Some(expression) = trimmed.strip_prefix("expr: ") {
                rules += 1;
                assert!(
                    !budlum_metric_names(expression).is_empty(),
                    "a Budlum alert queries no Budlum series: {expression}"
                );
            }
        }
    }
    assert!(rules >= 8, "the rule scan found {rules} rules; that is vacuous");
}

#[test]
fn the_dashboard_queries_series_the_node_exports() {
    let exported = exported_metrics();
    let queried = queried_metrics(DASHBOARD);
    assert!(queried.len() >= 10, "the dashboard scan is vacuous");
    let missing: Vec<&str> = queried
        .iter()
        .filter(|name| !exported.contains(*name))
        .map(String::as_str)
        .collect();
    assert!(missing.is_empty(), "dashboard queries missing metrics: {missing:?}");
    for mandatory in [
        "budlum_finality_stalled",
        "budlum_finality_lag_checkpoints",
        "budlum_bud3_segments_at_risk",
        "budlum_bud3_repair_backlog",
        "budlum_relay_reservations",
        "budlum_state_root_mismatch_total",
        "budlum_rpc_rate_limited_total",
    ] {
        assert!(queried.contains(mandatory), "{mandatory} has no dashboard panel");
    }
}
