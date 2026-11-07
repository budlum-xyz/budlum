//! Every Budlum metric named by a Prometheus alert rule must be exported.
//!
//! An alert that refers to a metric the node never writes is a silent lie:
//! the rule never fires, and an operator cannot tell a quiet network from a
//! broken exporter. The metric inventory is `src/core/metrics.rs`; the alert
//! rules are `ops/monitoring/alerts.yml`; the faucet owns its separate grant
//! counter in `src/bin/budlum-faucet.rs`. All are compiled into this test,
//! so a rule added against a metric that does not exist fails the build here
//! rather than on the first incident.

use std::collections::BTreeSet;

const ALERT_RULES: &str = include_str!("../../ops/monitoring/alerts.yml");
const METRIC_DEFINITIONS: &str = include_str!("../core/metrics.rs");
const FAUCET_METRIC_DEFINITIONS: &str = include_str!("../bin/budlum-faucet.rs");

/// All `budlum_*` tokens in `text`, split on anything that cannot be part of
/// an identifier. Metrics from other exporters (`node_*`, `up`) are out of
/// scope: those are not ours to declare in `src/core/metrics.rs`.
fn budlum_metric_names(text: &str) -> BTreeSet<String> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|token| token.starts_with("budlum_") && token.len() > "budlum_".len())
        .map(str::to_string)
        .collect()
}

/// The named lock for the alert-rule surface.
#[test]
fn alert_rules_reference_existing_metrics() {
    let exported = budlum_metric_names(METRIC_DEFINITIONS)
        .into_iter()
        .chain(budlum_metric_names(FAUCET_METRIC_DEFINITIONS))
        .collect::<BTreeSet<_>>();
    // Only the `expr:` lines are a claim about a metric. The rule file also
    // documents metric names that are deliberately not wired yet; a comment
    // is not a query and must not be read as one.
    let expressions: String = ALERT_RULES
        .lines()
        .filter(|line| line.trim_start().starts_with("expr:"))
        .collect::<Vec<_>>()
        .join("\n");
    let referenced = budlum_metric_names(&expressions);
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
    // The two metrics the faucet and RPC rate limiter write must be covered,
    // so the rule file cannot quietly lose its public-service alerts.
    assert!(referenced.contains("budlum_rpc_rate_limited_total"));
    assert!(referenced.contains("budlum_faucet_grants_total"));
}
