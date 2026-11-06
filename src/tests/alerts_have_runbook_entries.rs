//! WP-41 item 7: every alert the node raises has a line in the runbook.
//!
//! An alert an operator has never seen is a page at 3 a.m. spent reading the
//! rule file. The incident table in `docs/OPERATIONS.md` is the answer to
//! "what do I check first"; a rule added without a row is a rule nobody can
//! act on, and a row left behind after the rule is renamed sends the operator
//! looking for an alert that no longer exists.
//!
//! Both directions are checked, so the table cannot rot into a museum.

const ALERT_RULES: &str = include_str!("../../ops/monitoring/alerts.yml");
const RUNBOOK: &str = include_str!("../../docs/OPERATIONS.md");

/// Every `- alert: Name` in the rule file.
fn declared_alerts() -> Vec<&'static str> {
    ALERT_RULES
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("- alert: "))
        .map(str::trim)
        .collect()
}

/// Every alert name the runbook's incident table documents.
///
/// The cell is everything up to the next pipe. The closing backtick is not a
/// reliable stop: one row quotes a pair of alert names in a single cell
/// (`BudlumForkSuspected` / `BudlumNodesDisagreeOnHeight`), because the two
/// rules share a first check, so the cell is split on the slash as well.
fn documented_alerts() -> Vec<String> {
    RUNBOOK
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("| "))
        .filter_map(|rest| rest.split('|').next())
        .flat_map(|cell| {
            cell.replace('`', "")
                .split('/')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Each rule names its first check and its action in the runbook.
#[test]
fn every_alert_has_a_runbook_row() {
    let rules = declared_alerts();
    assert!(
        rules.len() >= 8,
        "the rule scan found {} alerts; that is vacuous",
        rules.len()
    );
    let documented = documented_alerts();
    let missing: Vec<&&str> = rules
        .iter()
        .filter(|name| !documented.iter().any(|row| row == **name))
        .collect();
    assert!(
        missing.is_empty(),
        "these alerts have no row in the docs/OPERATIONS.md incident table, so \
         nobody knows what to check first: {missing:?}"
    );
}

/// A row for an alert that no longer exists is worse than no row: it teaches a
/// procedure for a page that will never arrive, and it hides the real gap when
/// the alert is renamed.
#[test]
fn every_runbook_row_names_a_live_alert() {
    let rules = declared_alerts();
    for row in documented_alerts() {
        if !row.starts_with("Budlum") {
            continue;
        }
        assert!(
            rules.iter().any(|name| *name == row),
            "docs/OPERATIONS.md documents {row}, which no rule in \
             ops/monitoring/alerts.yml declares"
        );
    }
}

/// The severities an operator sorts a page by are the ones a pager knows, and
/// the two readiness rules the directive makes mandatory are critical rather
/// than informational.
#[test]
fn every_rule_carries_a_severity() {
    let mut pending = "<unknown>";
    for line in ALERT_RULES.lines() {
        let trimmed = line.trim_start();
        if let Some(name) = trimmed.strip_prefix("- alert: ") {
            pending = name.trim();
            continue;
        }
        if let Some(level) = trimmed.strip_prefix("severity: ") {
            let level = level.trim();
            assert!(
                matches!(level, "critical" | "warning" | "info"),
                "alert {pending} has severity {level}, which no pager understands"
            );
        }
    }
    for critical in [
        "BudlumFinalityRecoveryMode",
        "BudlumStateRootMismatch",
        "BudlumRelayReservationNeedsOperator",
    ] {
        let at = ALERT_RULES
            .find(critical)
            .unwrap_or_else(|| panic!("{critical} must exist"));
        let block = &ALERT_RULES[at..(at + 700).min(ALERT_RULES.len())];
        assert!(
            block.contains("severity: critical"),
            "{critical} must page: it is a condition only a person can resolve"
        );
    }
}

/// A gauge is not a counter. `increase()` on a gauge that falls reports a
/// negative number and fires on the reset, so the reservation rule - whose
/// series is the depth of the pending table - must compare the value instead.
#[test]
fn no_rule_calls_increase_on_a_gauge() {
    let gauges = [
        "budlum_relay_reservations",
        "budlum_relay_inflight_reservations",
        "budlum_finality_stalled",
        "budlum_finality_lag_checkpoints",
        "budlum_bud3_segments_at_risk",
        "budlum_bud3_repair_backlog",
        "budlum_bud3_objects",
    ];
    for line in ALERT_RULES.lines() {
        let trimmed = line.trim_start();
        let Some(expression) = trimmed.strip_prefix("expr: ") else {
            continue;
        };
        for gauge in gauges {
            assert!(
                !(expression.contains(gauge) && expression.contains("increase(")),
                "{gauge} is a gauge and cannot be read with increase(): {expression}"
            );
        }
    }
}
