//! WP-41 item 6: the scrape topology reaches every exporter the rules read.
//!
//! An alert rule is only as good as the series behind it. Two of the rules in
//! `ops/monitoring/alerts.yml` read the node_exporter filesystem gauges, and
//! nothing in either scrape config enumerated a node_exporter job, so those two
//! alerts could not fire on any node - a red rule that reports green forever.
//!
//! The same shape of mistake hides in the rule chain: a rule file nothing
//! mounts is a file nobody evaluates, and an evaluation interval longer than
//! the scrape interval samples every change twice or not at all.

use std::path::Path;

fn read(rel: &str) -> String {
    let mut path = Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    path.push(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The two Prometheus configs and the compose files that mount them.
const SCRAPE_FILES: &[&str] = &[
    "ops/prometheus.yml",
    "ops/monitoring/testnet-local-prometheus.yml",
];

/// Every series a rule expression reads that is not ours.
///
/// Only `expr:` lines count: a rule file also documents names in prose, and a
/// comment is not a query.
fn foreign_series_in_rules() -> Vec<String> {
    let rules = read("ops/monitoring/alerts.yml");
    let mut out = Vec::new();
    for line in rules.lines() {
        let Some(expression) = line.trim_start().strip_prefix("expr: ") else {
            continue;
        };
        for token in expression.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
            // A series name carries an underscore and is longer than a PromQL
            // keyword; the keywords and label names are filtered out by that.
            if token.contains('_')
                && token.len() > 6
                && !token.starts_with("budlum_")
                && !out.iter().any(|seen| seen == token)
            {
                out.push(token.to_string());
            }
        }
    }
    out
}

/// Each foreign series the rules read has a scrape job that produces it.
#[test]
fn every_series_the_rules_read_has_a_scrape_job() {
    let foreign = foreign_series_in_rules();
    assert!(
        !foreign.is_empty(),
        "the rule scan found no foreign series; the scan is vacuous"
    );
    let mut configs = String::new();
    for path in SCRAPE_FILES {
        configs.push_str(&read(path));
    }
    assert!(
        configs.contains("job_name"),
        "no scrape config enumerates a job; the scan is vacuous"
    );
    // node_exporter series come from the `node` job, and Prometheus only keeps
    // `up{job="node"}` if that job exists.
    for series in &foreign {
        if series.starts_with("node_") {
            assert!(
                configs.contains("job_name: node"),
                "the rules read {series}, exported by node_exporter, but no scrape \
                 config enumerates a node_exporter job"
            );
        }
    }
}

/// Both compose stacks that ship a Prometheus mount the rule file, and the
/// rule file's path in the config is the path it is mounted at.
#[test]
fn the_rules_are_mounted_where_the_config_expects_them() {
    let config = read("ops/prometheus.yml");
    let rule_file = config
        .lines()
        .find_map(|line| line.trim().strip_prefix("- /etc/prometheus/"))
        .expect("the config names its rule file");
    for (compose, expected) in [
        ("ops/docker-compose.yml", format!("monitoring/{rule_file}")),
        (
            "ops/testnet-local.yml",
            format!("monitoring/{rule_file}"),
        ),
    ] {
        let body = read(compose);
        assert!(
            body.contains(&expected),
            "{compose} must mount the rule file the config loads ({expected})"
        );
        assert!(
            body.contains("/etc/prometheus/alerts.yml"),
            "{compose} must mount it at the path the config reads"
        );
    }
    let local = read("ops/monitoring/testnet-local-prometheus.yml");
    assert!(
        local.contains(&format!("/etc/prometheus/{rule_file}")),
        "the local rehearsal config must load the same rule file"
    );
}

/// The evaluation interval covers the scrape interval.
///
/// An evaluation interval shorter than a scrape re-reads the same sample and
/// doubles the work; one that is much longer turns a one-minute alert into a
/// sampling lottery. Equal is wrong in the other direction: a single missed
/// scrape is then an evaluation with no data.
#[test]
fn evaluation_covers_the_scrape_interval() {
    for path in SCRAPE_FILES {
        let body = read(path);
        let mut scrape = None;
        let mut evaluation = None;
        for line in body.lines() {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("scrape_interval:") {
                scrape = Some(v.trim().to_string());
            }
            if let Some(v) = line.strip_prefix("evaluation_interval:") {
                evaluation = Some(v.trim().to_string());
            }
        }
        let scrape = scrape.unwrap_or_else(|| panic!("{path} sets no scrape_interval"));
        let evaluation = evaluation.unwrap_or_else(|| panic!("{path} sets no evaluation_interval"));
        assert_eq!(scrape, "15s", "{path}: the documented scrape is 15s");
        assert_eq!(
            evaluation, "30s",
            "{path}: evaluation must be a whole multiple of the scrape"
        );
    }
}
