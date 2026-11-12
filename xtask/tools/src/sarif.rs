//! Convert JSON and text scanner reports into SARIF 2.1.0 documents.
//!
//! GitHub Code Scanning ingests SARIF 2.1.0 (`$schema` + `version: "2.1.0"`).
//! Several repository scanners (`Clippy`, `actionlint`, `cargo-audit`,
//! `cargo-deny`, `cargo-geiger`) emit structured JSON or text rather than
//! native SARIF. Converting those reports in pure `std` Rust keeps shell/jq
//! pipelines out of the trust boundary and adds zero crate dependencies.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use crate::json::{self, Value};

const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";

/// One normalized finding ready to serialize into SARIF `results[]`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Finding {
    rule_id: String,
    rule_desc: String,
    level: &'static str,
    message: String,
    uri: String,
    line: usize,
    column: usize,
}

/// Escape a Rust string for inclusion inside JSON double quotes.
fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out
}

/// Normalize a file path to a relative repository URI suitable for SARIF.
fn normalize_uri(raw: &str, fallback: &str) -> String {
    let trimmed = raw.trim().replace('\\', "/");
    let stripped = trimmed.strip_prefix("./").unwrap_or(&trimmed);
    let stripped = stripped.trim_start_matches('/');
    if stripped.is_empty() {
        fallback.to_string()
    } else {
        stripped.to_string()
    }
}

fn parse_usize_num(val: Option<&Value>, default: usize) -> usize {
    val.and_then(|v| match v {
        Value::Number(n) => n.parse::<usize>().ok(),
        _ => None,
    })
    .filter(|&n| n >= 1)
    .unwrap_or(default)
}

/// Render a valid SARIF 2.1.0 document for `tool_name`.
fn render_sarif(tool_name: &str, info_uri: &str, findings: &[Finding]) -> String {
    let mut rules: BTreeMap<&str, &str> = BTreeMap::new();
    for f in findings {
        rules
            .entry(f.rule_id.as_str())
            .or_insert(f.rule_desc.as_str());
    }

    let mut out = String::with_capacity(512 + findings.len() * 256);
    out.push_str("{\n");
    let _ = writeln!(out, "  \"$schema\": \"{}\",", json_escape(SARIF_SCHEMA));
    out.push_str("  \"version\": \"2.1.0\",\n");
    out.push_str("  \"runs\": [\n    {\n      \"tool\": {\n        \"driver\": {\n");
    let _ = writeln!(out, "          \"name\": \"{}\",", json_escape(tool_name));
    let _ = writeln!(
        out,
        "          \"informationUri\": \"{}\",",
        json_escape(info_uri)
    );
    out.push_str("          \"rules\": [");
    for (idx, (id, desc)) in rules.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "\n            {{\"id\": \"{}\", \"shortDescription\": {{\"text\": \"{}\"}}}}",
            json_escape(id),
            json_escape(desc)
        );
    }
    if !rules.is_empty() {
        out.push_str("\n          ");
    }
    out.push_str("]\n        }\n      },\n      \"results\": [");

    for (idx, f) in findings.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "\n        {{\n          \"ruleId\": \"{}\",\n          \"level\": \"{}\",\n          \"message\": {{\"text\": \"{}\"}},\n          \"locations\": [\n            {{\n              \"physicalLocation\": {{\n                \"artifactLocation\": {{\"uri\": \"{}\"}},\n                \"region\": {{\"startLine\": {}, \"startColumn\": {}}}\n              }}\n            }}\n          ]\n        }}",
            json_escape(&f.rule_id),
            f.level,
            json_escape(&f.message),
            json_escape(&f.uri),
            f.line.max(1),
            f.column.max(1),
        );
    }
    if !findings.is_empty() {
        out.push_str("\n      ");
    }
    out.push_str("]\n    }\n  ]\n}\n");
    out
}

fn convert_clippy(text: &str) -> String {
    let mut findings = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(record) = json::parse(trimmed) else {
            continue;
        };
        if record.get("reason").and_then(Value::as_str) != Some("compiler-message") {
            continue;
        }
        let Some(msg) = record.get("message") else {
            continue;
        };
        let level = match msg.get("level").and_then(Value::as_str) {
            Some("error") => "error",
            Some("warning") => "warning",
            _ => continue,
        };
        let Some(spans) = msg.get("spans").and_then(Value::as_array) else {
            continue;
        };
        let primary = spans
            .iter()
            .find(|s| matches!(s.get("is_primary"), Some(Value::Bool(true))))
            .or_else(|| spans.first());
        let Some(span) = primary else {
            continue;
        };
        let raw_file = span.get("file_name").and_then(Value::as_str).unwrap_or("");
        if raw_file.starts_with('/') || raw_file.contains("/cargo/registry/") {
            continue;
        }
        let uri = normalize_uri(raw_file, "Cargo.toml");
        let rule_id = msg
            .get("code")
            .and_then(|c| c.get("code"))
            .and_then(Value::as_str)
            .unwrap_or("rustc-diagnostic")
            .to_string();
        let body = msg
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("compiler diagnostic")
            .to_string();
        findings.push(Finding {
            rule_desc: format!("Rust Clippy diagnostic {rule_id}"),
            rule_id,
            level,
            message: body,
            uri,
            line: parse_usize_num(span.get("line_start"), 1),
            column: parse_usize_num(span.get("column_start"), 1),
        });
    }
    render_sarif(
        "Clippy",
        "https://rust-lang.github.io/rust-clippy/",
        &findings,
    )
}

fn convert_actionlint(text: &str) -> Result<String, String> {
    let trimmed = text.trim();
    let mut findings = Vec::new();
    if !trimmed.is_empty() {
        let parsed =
            json::parse(trimmed).map_err(|e| format!("invalid actionlint JSON input: {e}"))?;
        let items = parsed
            .as_array()
            .ok_or_else(|| "actionlint JSON root must be an array".to_string())?;
        for item in items {
            let kind = item
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("workflow-lint")
                .to_string();
            let message = item
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("actionlint finding")
                .to_string();
            let filepath = item
                .get("filepath")
                .and_then(Value::as_str)
                .unwrap_or(".github/workflows/ci.yml");
            findings.push(Finding {
                rule_desc: format!("GitHub Actions workflow check ({kind})"),
                rule_id: format!("actionlint/{kind}"),
                level: "error",
                message,
                uri: normalize_uri(filepath, ".github/workflows/ci.yml"),
                line: parse_usize_num(item.get("line"), 1),
                column: parse_usize_num(item.get("column"), 1),
            });
        }
    }
    Ok(render_sarif(
        "actionlint",
        "https://github.com/rhysd/actionlint",
        &findings,
    ))
}

fn convert_cargo_audit(text: &str, default_uri: &str) -> Result<String, String> {
    let trimmed = text.trim();
    let mut findings = Vec::new();
    if !trimmed.is_empty() {
        let root = json::parse(trimmed).map_err(|e| format!("invalid cargo-audit JSON: {e}"))?;
        if let Some(list) = root
            .get("vulnerabilities")
            .and_then(|v| v.get("list"))
            .and_then(Value::as_array)
        {
            for entry in list {
                let advisory = entry.get("advisory");
                let pkg = entry.get("package");
                let id = advisory
                    .and_then(|a| a.get("id"))
                    .and_then(Value::as_str)
                    .unwrap_or("RUSTSEC-UNKNOWN")
                    .to_string();
                let title = advisory
                    .and_then(|a| a.get("title"))
                    .and_then(Value::as_str)
                    .unwrap_or("RustSec vulnerability");
                let crate_name = pkg
                    .and_then(|p| p.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let crate_ver = pkg
                    .and_then(|p| p.get("version"))
                    .and_then(Value::as_str)
                    .unwrap_or("0.0.0");
                findings.push(Finding {
                    rule_desc: title.to_string(),
                    rule_id: id,
                    level: "error",
                    message: format!("{crate_name} {crate_ver}: {title}"),
                    uri: normalize_uri(default_uri, "Cargo.lock"),
                    line: 1,
                    column: 1,
                });
            }
        }
    }
    Ok(render_sarif(
        "cargo-audit",
        "https://rustsec.org/",
        &findings,
    ))
}

fn convert_cargo_deny(text: &str) -> String {
    let mut findings = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(obj) = json::parse(trimmed) else {
            continue;
        };
        if obj.get("type").and_then(Value::as_str) != Some("diagnostic") {
            continue;
        }
        let Some(fields) = obj.get("fields") else {
            continue;
        };
        let level = match fields.get("severity").and_then(Value::as_str) {
            Some("error" | "bug") => "error",
            Some("warning") => "warning",
            _ => continue,
        };
        let code = fields
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("deny-diagnostic")
            .to_string();
        let message = fields
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("cargo-deny policy violation")
            .to_string();
        let first_label = fields
            .get("labels")
            .and_then(Value::as_array)
            .and_then(|a| a.first());
        let raw_uri = first_label
            .and_then(|l| l.get("span"))
            .and_then(|s| s.get("file"))
            .and_then(Value::as_str)
            .unwrap_or("Cargo.lock");
        let line_no = first_label
            .and_then(|l| l.get("span"))
            .map_or(1, |s| parse_usize_num(s.get("line"), 1));
        findings.push(Finding {
            rule_desc: format!("cargo-deny check ({code})"),
            rule_id: format!("cargo-deny/{code}"),
            level,
            message,
            uri: normalize_uri(raw_uri, "Cargo.lock"),
            line: line_no,
            column: 1,
        });
    }
    render_sarif(
        "cargo-deny",
        "https://embarkstudios.github.io/cargo-deny/",
        &findings,
    )
}

fn convert_cargo_geiger(text: &str) -> String {
    let mut findings = Vec::new();
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        for window in tokens.windows(2) {
            let [name, counts] = window else {
                continue;
            };
            if !(name.starts_with("budlum-") || name.starts_with("bud-")) {
                continue;
            }
            let Some((used_str, _)) = counts.split_once('/') else {
                continue;
            };
            let Ok(used) = used_str.parse::<usize>() else {
                continue;
            };
            if used > 0 {
                findings.push(Finding {
                    rule_id: "geiger/first-party-unsafe".to_string(),
                    rule_desc: "First-party crate contains unsafe Rust expressions".to_string(),
                    level: "error",
                    message: format!("first-party crate `{name}` reports {used} unsafe item(s)"),
                    uri: "Cargo.toml".to_string(),
                    line: 1,
                    column: 1,
                });
            }
        }
    }
    render_sarif(
        "cargo-geiger",
        "https://github.com/geiger-rs/cargo-geiger",
        &findings,
    )
}

/// Run the SARIF converter CLI:
/// `budlum-tools sarif <clippy|actionlint|cargo-audit|cargo-deny|cargo-geiger> <in> <out> [lockfile]`
///
/// # Errors
///
/// If arguments are missing, the input file cannot be read, JSON parsing fails,
/// or the output SARIF file cannot be written.
pub fn run(root: &Path, args: &[&str]) -> Result<String, String> {
    if args == ["--self-test"] {
        return self_test();
    }
    let [kind, input, output, rest @ ..] = args else {
        return Err(
            "usage: budlum-tools sarif <clippy|actionlint|cargo-audit|cargo-deny|cargo-geiger> <input> <output.sarif> [uri]"
                .to_string(),
        );
    };
    let in_path = if Path::new(input).is_absolute() {
        Path::new(input).to_path_buf()
    } else {
        root.join(input)
    };
    let out_path = if Path::new(output).is_absolute() {
        Path::new(output).to_path_buf()
    } else {
        root.join(output)
    };
    let raw = std::fs::read_to_string(&in_path)
        .map_err(|e| format!("cannot read {}: {e}", in_path.display()))?;
    let default_uri = rest.first().copied().unwrap_or("Cargo.lock");
    let sarif_doc = match *kind {
        "clippy" => convert_clippy(&raw),
        "actionlint" => convert_actionlint(&raw)?,
        "cargo-audit" => convert_cargo_audit(&raw, default_uri)?,
        "cargo-deny" => convert_cargo_deny(&raw),
        "cargo-geiger" => convert_cargo_geiger(&raw),
        other => return Err(format!("unknown sarif source `{other}`")),
    };
    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
    }
    std::fs::write(&out_path, &sarif_doc)
        .map_err(|e| format!("cannot write {}: {e}", out_path.display()))?;
    Ok(format!("sarif ({kind}): wrote {}", out_path.display()))
}

/// Canary for the SARIF converters: verifies both positive findings and valid
/// JSON round-trip across all five input formats.
///
/// # Errors
///
/// If any converter produces invalid JSON or misses a synthetic finding.
pub fn self_test() -> Result<String, String> {
    let clippy_sample = r#"{"reason":"compiler-message","message":{"code":{"code":"clippy::unwrap_used"},"level":"warning","message":"used unwrap","spans":[{"file_name":"src/lib.rs","is_primary":true,"line_start":12,"column_start":5}]}}"#;
    let clippy_sarif = convert_clippy(clippy_sample);
    let parsed = json::parse(&clippy_sarif).map_err(|e| format!("clippy sarif invalid: {e}"))?;
    if parsed.get("version").and_then(Value::as_str) != Some("2.1.0")
        || !clippy_sarif.contains("clippy::unwrap_used")
    {
        return Err("clippy sarif canary missed synthetic finding".to_string());
    }

    let al_sample = r#"[{"message":"bad expr","filepath":".github/workflows/ci.yml","line":9,"column":3,"kind":"expression"}]"#;
    let al_sarif = convert_actionlint(al_sample)?;
    json::parse(&al_sarif).map_err(|e| format!("actionlint sarif invalid: {e}"))?;
    if !al_sarif.contains("actionlint/expression") {
        return Err("actionlint sarif canary missed synthetic finding".to_string());
    }

    let audit_sample = r#"{"vulnerabilities":{"list":[{"advisory":{"id":"RUSTSEC-2099-0001","title":"demo flaw"},"package":{"name":"demo","version":"0.1.0"}}]}}"#;
    let audit_sarif = convert_cargo_audit(audit_sample, "Cargo.lock")?;
    json::parse(&audit_sarif).map_err(|e| format!("cargo-audit sarif invalid: {e}"))?;
    if !audit_sarif.contains("RUSTSEC-2099-0001") {
        return Err("cargo-audit sarif canary missed synthetic finding".to_string());
    }

    let deny_sample = r#"{"type":"diagnostic","fields":{"severity":"error","code":"A001","message":"denied","labels":[{"span":{"file":"Cargo.lock","line":4}}]}}"#;
    let deny_sarif = convert_cargo_deny(deny_sample);
    json::parse(&deny_sarif).map_err(|e| format!("cargo-deny sarif invalid: {e}"))?;
    if !deny_sarif.contains("cargo-deny/A001") {
        return Err("cargo-deny sarif canary missed synthetic finding".to_string());
    }

    let geiger_sample = "0/0 3/3 0/0 0/0 0/0 ! budlum-core 3/3";
    let geiger_sarif = convert_cargo_geiger(geiger_sample);
    json::parse(&geiger_sarif).map_err(|e| format!("cargo-geiger sarif invalid: {e}"))?;
    if !geiger_sarif.contains("geiger/first-party-unsafe") {
        return Err("cargo-geiger sarif canary missed synthetic finding".to_string());
    }

    Ok("ok: sarif self-test (5 converters verified)".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sarif_canary_passes_and_empty_inputs_are_valid_json() {
        self_test().unwrap();
        for doc in [
            convert_clippy(""),
            convert_actionlint("[]").unwrap(),
            convert_cargo_audit("{}", "Cargo.lock").unwrap(),
            convert_cargo_deny(""),
            convert_cargo_geiger("budlum-core 0/0"),
        ] {
            let v = json::parse(&doc).unwrap();
            assert_eq!(v.get("version").and_then(Value::as_str), Some("2.1.0"));
        }
    }
}
