//! WP-41 item 6: every Budlum metric named by a Prometheus alert rule is
//! exported, and every mandatory alert rule exists.
//!
//! An alert that refers to a metric the node never writes is a silent lie:
//! the rule never fires, and an operator cannot tell a quiet network from a
//! broken exporter. The metric inventory is `src/core/metrics.rs`; the alert
//! rules are `ops/monitoring/alerts.yml`. The rule file is read here with
//! `include_str!`, so editing a rule recompiles this test rather than leaving
//! a green build over a rule that cannot fire.

use std::collections::BTreeSet;

const ALERT_RULES: &str = include_str!("../../ops/monitoring/alerts.yml");
const METRIC_DEFINITIONS: &str = include_str!("../core/metrics.rs");

/// All `budlum_*` tokens in `text`, split on anything that cannot be part of
/// an identifier. Metrics from other exporters (`node_*`, `up`) are out of
/// scope: those are not ours to declare in `src/core/metrics.rs`.
fn budlum_metric_names(text: &str) -> BTreeSet<String> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|token| token.starts_with("budlum_") && token.len() > "budlum_".len())
        .map(str::to_string)
        .collect()
}

/// Only the `expr:` lines are a claim about a metric. The rule file also
/// documents metric names in prose, and a comment is not a query.
fn queried_metrics() -> BTreeSet<String> {
    let expressions: String = ALERT_RULES
        .lines()
        .filter(|line| line.trim_start().starts_with("expr:"))
        .collect::<Vec<_>>()
        .join("\n");
    budlum_metric_names(&expressions)
}

/// The named lock for the alert-rule surface.
#[test]
fn alert_rules_reference_existing_metrics() {
    let exported = budlum_metric_names(METRIC_DEFINITIONS);
    let referenced = queried_metrics();
    assert!(
        exported.len() > 50,
        "the metric inventory scan found too few metrics; the scan is vacuous"
    );
    assert!(
        !referenced.is_empty(),
        "the alert file names no Budlum metric; the scan is vacuous"
    );
    let missing: Vec<&str> = referenced
        .iter()
        .filter(|name| !exported.contains(*name))
        .map(String::as_str)
        .collect();
    assert!(
        missing.is_empty(),
        "alert rules refer to metrics the node does not export: {missing:?}"
    );
}

/// WP-41 item 6 names eight mandatory alerts. Each one has to exist as a
/// metric the node writes and as a rule that queries it: a metric with no rule
/// alarms nobody, and a rule with no metric never fires.
#[test]
fn the_mandatory_alert_rules_exist_and_have_metrics() {
    let exported = budlum_metric_names(METRIC_DEFINITIONS);
    let referenced = queried_metrics();
    for mandatory in [
        "budlum_finality_stalled",
        "budlum_finality_lag_checkpoints",
        "budlum_bud3_segments_at_risk",
        "budlum_bud3_repair_backlog",
        "budlum_relay_reservations",
        "budlum_ee_fault_total",
        "budlum_state_root_mismatch_total",
        "budlum_rpc_rate_limited_total",
    ] {
        assert!(
            exported.contains(mandatory),
            "mandatory alert metric {mandatory} is not declared in src/core/metrics.rs"
        );
        assert!(
            referenced.contains(mandatory),
            "mandatory alert metric {mandatory} is exported but no alert rule queries it"
        );
    }
}

/// A rule whose `expr` names no `budlum_*` series at all is usually a typo in
/// the rule file rather than a deliberate foreign metric, so every rule in a
/// `budlum-` group has to name at least one of ours.
#[test]
fn every_budlum_rule_queries_a_budlum_series() {
    let mut in_our_group = false;
    let mut rules = 0usize;
    for line in ALERT_RULES.lines() {
        let trimmed = line.trim_start();
        if let Some(name) = trimmed.strip_prefix("- name: ") {
            in_our_group = name.trim_start().starts_with("budlum-");
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
