//! Every registered Prometheus metric must be written in production code.
//!
//! A metric that is constructed, registered and never updated is a dashboard
//! lie: scrapes report a permanent zero next to real counters, and an operator
//! cannot tell a quiet network from a broken exporter. The tree has paid for
//! this before - `budlum_peer_count` sat beside `budlum_p2p_peers_connected`
//! and only the second was ever set.
//!
//! # What counts as a write
//!
//! After production sources are flattened (whitespace collapsed so a call that
//! spans lines still matches) and `#[cfg(test)]` blocks are stripped, a write
//! is a call of the form `.<field>.<method>(...)` where `<method>` is one of
//! the prometheus mutators this tree uses:
//!
//!   `set`, `inc`, `dec`, `add`, `sub`, `observe`, `inc_by`, `add_by`,
//!   `start_timer`, `observe_closure_duration`
//!
//! The left side of the field is already bounded by the leading `.`. The right
//! side must not continue as an identifier (`peer_count` must not match
//! `peer_count_something`), and the method parenthesis must follow immediately
//! after the second dot once whitespace is gone.
//!
//! # Why a ratchet and not a ban
//!
//! Some metrics describe surfaces that are not yet on a production path. Those
//! are recorded in [`BASELINE_PATH`] so the gate fails on **new** unwritten
//! metrics without forcing a half-honest bind. The baseline only shrinks: a
//! line that is now written is itself a failure so the file cannot rot into a
//! permanent excuse.
//!
//! # What is out of scope
//!
//! * `tests/`, `benches/`, `fuzz/`, `examples/` - not production.
//! * The definition file itself is scanned; a write that lives only inside its
//!   own `#[cfg(test)]` module does not count, because those blocks are
//!   stripped before the search.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// Where metric fields are declared.
const METRICS_PATH: &str = "src/core/metrics.rs";

/// Roots that hold production code.
const PROD_ROOTS: &[&str] = &["src", "bud", "crates", "budzero"];

/// Directories that are never production, wherever they appear.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    "tests",
    "benches",
    "fuzz",
    "examples",
    "corpus",
];

/// Recorded metrics that are still unwritten. May only shrink.
const BASELINE_PATH: &str = ".github/unwritten-metrics-baseline.txt";

/// Mutators that change a prometheus metric's value.
const WRITE_METHODS: &[&str] = &[
    "set",
    "inc",
    "dec",
    "add",
    "sub",
    "observe",
    "inc_by",
    "add_by",
    "start_timer",
    "observe_closure_duration",
];

/// A scan that finds too few fields is vacuous and must fail rather than pass.
const VACUITY_FLOOR: usize = 10;

/// How many findings are printed before the list is summarised.
const MAX_REPORTED: usize = 40;

fn report_limit() -> usize {
    if std::env::var_os("BUDLUM_GATE_REPORT_ALL").is_some() {
        usize::MAX
    } else {
        MAX_REPORTED
    }
}

/// One registered metric field.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Metric {
    kind: String,
    field: String,
}

impl Metric {
    /// Baseline key: `<kind>\t<field>`.
    fn key(&self) -> String {
        format!("{}\t{}", self.kind, self.field)
    }
}

/// Remove every `#[cfg(test)]` item, bodyful or bodyless.
///
/// A bodyless item (`#[cfg(test)] use foo;`) has no `{`. Matching braces from
/// the next `{` in the file would swallow the rest of the crate. The scan
/// therefore asks whether the decorated item has a body before walking.
fn strip_cfg_test(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let bytes = src.as_bytes();
    let mut i = 0usize;
    while i < src.len() {
        let Some(rel) = src[i..].find("#[cfg(test)]") else {
            out.push_str(&src[i..]);
            break;
        };
        let at = i + rel;
        out.push_str(&src[i..at]);
        let mut j = at + "#[cfg(test)]".len();
        // Skip whitespace and further attributes on the same item.
        loop {
            while j < src.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j + 1 < src.len() && bytes[j] == b'#' && bytes[j + 1] == b'[' {
                if let Some(close) = src[j..].find(']') {
                    j += close + 1;
                    continue;
                }
                j = src.len();
                break;
            }
            break;
        }
        // Does the item have a `{` body, or is it bodyless (`...;`)?
        let mut k = j;
        let mut has_body = false;
        while k < src.len() {
            match bytes[k] {
                b'{' => {
                    has_body = true;
                    break;
                }
                b';' => break,
                _ => k += 1,
            }
        }
        if !has_body {
            i = (k + 1).min(src.len());
            continue;
        }
        let open = k;
        let mut depth = 0usize;
        let mut p = open;
        while p < bytes.len() {
            match bytes[p] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        p += 1;
                        break;
                    }
                }
                _ => {}
            }
            p += 1;
        }
        i = p.min(src.len());
    }
    out
}

/// Replace line comments, block comments and string literals with spaces so a
/// name that appears only in prose cannot count as a write.
fn strip_comments_and_strings(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0usize;
    while i < b.len() {
        // Raw string: r"..." or r#"..."#
        if b[i] == b'r' && i + 1 < b.len() && (b[i + 1] == b'"' || b[i + 1] == b'#') {
            let mut hashes = 0usize;
            let mut j = i + 1;
            while j < b.len() && b[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            if j < b.len() && b[j] == b'"' {
                let close = format!("\"{}", "#".repeat(hashes));
                let rest = &src[j + 1..];
                let end = rest
                    .find(&close)
                    .map_or(b.len(), |p| j + 1 + p + close.len());
                out.push(' ');
                i = end;
                continue;
            }
        }
        match b[i] {
            b'/' if i + 1 < b.len() && b[i + 1] == b'/' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < b.len() && b[i + 1] == b'*' => {
                let mut depth = 1usize;
                i += 2;
                while i < b.len() && depth > 0 {
                    if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
                        depth += 1;
                        i += 2;
                        continue;
                    }
                    if b[i] == b'*' && i + 1 < b.len() && b[i + 1] == b'/' {
                        depth -= 1;
                        i += 2;
                        continue;
                    }
                    i += 1;
                }
            }
            b'"' => {
                i += 1;
                while i < b.len() {
                    if b[i] == b'\\' {
                        i = (i + 2).min(b.len());
                        continue;
                    }
                    if b[i] == b'"' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                out.push(' ');
            }
            b'\'' => {
                // Keep char literals short; skip simply.
                out.push(b[i] as char);
                i += 1;
                if i < b.len() && b[i] == b'\\' {
                    out.push(' ');
                    i = (i + 2).min(b.len());
                    if i < b.len() && b[i] == b'\'' {
                        i += 1;
                    }
                } else if i < b.len() {
                    out.push(b[i] as char);
                    i += 1;
                    if i < b.len() && b[i] == b'\'' {
                        out.push('\'');
                        i += 1;
                    }
                }
            }
            c => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    out
}

/// Collapse runs of whitespace so multi-line calls still match.
fn flatten(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut was_ws = false;
    for ch in src.chars() {
        if ch.is_whitespace() {
            if !was_ws {
                // Drop whitespace entirely rather than replacing with a single
                // space: the matcher looks for `.{field}.{method}(` with no
                // gaps once production sources are joined.
                was_ws = true;
            }
        } else {
            was_ws = false;
            out.push(ch);
        }
    }
    out
}

fn is_ident_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// Is `field` written somewhere in the flattened production blob?
fn is_written(field: &str, blob: &str) -> bool {
    let anchor = format!(".{field}");
    let bytes = blob.as_bytes();
    let ab = anchor.as_bytes();
    let mut start = 0usize;
    while let Some(rel) = blob[start..].find(&anchor) {
        let idx = start + rel;
        let after = idx + ab.len();
        if after < bytes.len() && is_ident_char(bytes[after]) {
            start = idx + 1;
            continue;
        }
        // Expect `.{method}(` immediately.
        if after >= bytes.len() || bytes[after] != b'.' {
            start = idx + 1;
            continue;
        }
        let rest = &blob[after + 1..];
        for method in WRITE_METHODS {
            let needle = format!("{method}(");
            if rest.starts_with(&needle) {
                return true;
            }
        }
        start = idx + 1;
    }
    false
}

/// Parse `pub field: Kind` declarations from the metrics struct.
fn parse_metrics(src: &str) -> Vec<Metric> {
    let cleaned = strip_cfg_test(src);
    let mut out = Vec::new();
    // Only the struct body matters; a simple line scan is enough because
    // fields are written one per line in this tree.
    for line in cleaned.lines() {
        let t = line.trim();
        let Some(rest) = t.strip_prefix("pub ") else {
            continue;
        };
        let Some((name, ty)) = rest.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let ty = ty.trim().trim_end_matches(',').trim();
        if !matches!(ty, "IntCounter" | "IntGauge" | "Histogram") {
            continue;
        }
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        out.push(Metric {
            kind: ty.to_string(),
            field: name.to_string(),
        });
    }
    out
}

fn should_skip(path: &Path) -> bool {
    path.components().any(|c| {
        let s = c.as_os_str().to_string_lossy();
        SKIP_DIRS.iter().any(|d| *d == s)
    })
}

fn collect_prod_sources(root: &Path) -> Result<String, String> {
    let mut chunks = Vec::new();
    for rel in PROD_ROOTS {
        let dir = root.join(rel);
        if !dir.exists() {
            continue;
        }
        let mut stack = vec![dir];
        while let Some(cur) = stack.pop() {
            let rd = fs::read_dir(&cur).map_err(|e| format!("read_dir {}: {e}", cur.display()))?;
            for ent in rd.filter_map(Result::ok) {
                let path = ent.path();
                if path.is_dir() {
                    if should_skip(&path) {
                        continue;
                    }
                    stack.push(path);
                    continue;
                }
                if path.extension().is_some_and(|x| x == "rs") {
                    if should_skip(&path) {
                        continue;
                    }
                    let text = fs::read_to_string(&path)
                        .map_err(|e| format!("read {}: {e}", path.display()))?;
                    chunks.push(strip_comments_and_strings(&strip_cfg_test(&text)));
                }
            }
        }
    }
    Ok(flatten(&chunks.join("\n")))
}

fn load_baseline(root: &Path) -> Result<BTreeSet<String>, String> {
    let path = root.join(BASELINE_PATH);
    if !path.exists() {
        return Ok(BTreeSet::new());
    }
    let text = fs::read_to_string(&path).map_err(|e| format!("read {BASELINE_PATH}: {e}"))?;
    let mut set = BTreeSet::new();
    for (n, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = t.split('\t').collect();
        if parts.len() != 2 {
            return Err(format!(
                "{BASELINE_PATH}:{}: expected `<kind>\\t<field>`, got {t:?}",
                n + 1
            ));
        }
        set.insert(format!("{}\t{}", parts[0], parts[1]));
    }
    Ok(set)
}

/// # Errors
///
/// Returns a human-readable failure when a metric is unwritten and not
/// baselined, when a baseline entry is now written, or when the scan is
/// vacuous.
pub fn run(root: &Path) -> Result<String, String> {
    let metrics_src = fs::read_to_string(root.join(METRICS_PATH))
        .map_err(|e| format!("read {METRICS_PATH}: {e}"))?;
    let metrics = parse_metrics(&metrics_src);
    if metrics.len() < VACUITY_FLOOR {
        return Err(format!(
            "vacuous: parsed only {} metric fields from {METRICS_PATH} (floor {VACUITY_FLOOR})",
            metrics.len()
        ));
    }
    let blob = collect_prod_sources(root)?;
    let baseline = load_baseline(root)?;

    let mut unwritten = Vec::new();
    let mut written_keys = BTreeSet::new();
    for m in &metrics {
        let key = m.key();
        if is_written(&m.field, &blob) {
            written_keys.insert(key);
        } else {
            unwritten.push(m.clone());
        }
    }

    let mut new_unwritten = Vec::new();
    for m in &unwritten {
        let key = m.key();
        if !baseline.contains(&key) {
            new_unwritten.push(m.clone());
        }
    }

    let mut stale = Vec::new();
    for b in &baseline {
        if written_keys.contains(b) {
            stale.push(b.clone());
        } else {
            // Baseline entry for a metric that no longer exists also stales.
            let field = b.split('\t').nth(1).unwrap_or("");
            if !metrics.iter().any(|m| m.field == field) {
                stale.push(b.clone());
            }
        }
    }

    if new_unwritten.is_empty() && stale.is_empty() {
        return Ok(format!(
            "metrics-are-written OK ({} fields, {} still baselined unwritten).",
            metrics.len(),
            unwritten.len()
        ));
    }

    let mut msg = String::new();
    if !new_unwritten.is_empty() {
        let _ = writeln!(
            msg,
            "FAIL: {} metric(s) registered but never written in production:",
            new_unwritten.len()
        );
        for (i, m) in new_unwritten.iter().enumerate() {
            if i >= report_limit() {
                let _ = writeln!(
                    msg,
                    "  ... and {} more (set BUDLUM_GATE_REPORT_ALL=1 for full list)",
                    new_unwritten.len() - i
                );
                break;
            }
            let _ = writeln!(msg, "  {}\t{}", m.kind, m.field);
        }
    }
    if !stale.is_empty() {
        let _ = writeln!(
            msg,
            "FAIL: {} baseline entr(y/ies) are now written or gone (remove them):",
            stale.len()
        );
        for (i, k) in stale.iter().enumerate() {
            if i >= report_limit() {
                let _ = writeln!(msg, "  ... and {} more", stale.len() - i);
                break;
            }
            let _ = writeln!(msg, "  {k}");
        }
    }
    Err(msg)
}

// ─── self-test ───────────────────────────────────────────────────────────────

fn scratch_dir() -> Result<PathBuf, String> {
    let base =
        std::env::temp_dir().join(format!("budlum-metrics-are-written-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).map_err(|e| format!("scratch: {e}"))?;
    Ok(base)
}

fn write_tree(root: &Path, files: &[(&str, &str)]) -> Result<(), String> {
    for (rel, body) in files {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        fs::write(&path, body).map_err(|e| format!("write {rel}: {e}"))?;
    }
    Ok(())
}

fn accepts(root: &Path) -> Result<bool, String> {
    match run(root) {
        Ok(_) => Ok(true),
        Err(msg) if msg.starts_with("FAIL:") || msg.starts_with("vacuous:") => Ok(false),
        Err(e) => Err(e),
    }
}

/// Minimal metrics.rs + one writer, enough fields to clear the vacuity floor.
fn clean_tree_files() -> Vec<(&'static str, &'static str)> {
    let mut fields = String::new();
    let mut inits = String::new();
    let mut registers = String::new();
    let mut struct_init = String::new();
    // 12 gauges so vacuity floor is cleared.
    for i in 0..12 {
        let name = format!("m{i}");
        let _ = writeln!(fields, "    pub {name}: IntGauge");
        let _ = writeln!(
            inits,
            "        let {name} = IntGauge::new(\"budlum_{name}\", \"h\")?"
        );
        let _ = writeln!(
            registers,
            "        registry.register(Box::new({name}.clone()))?"
        );
        let _ = writeln!(struct_init, "            {name},");
    }
    let metrics = format!(
        "use prometheus::{{IntGauge, Registry}};\n\
         pub struct Metrics {{\n\
         {fields}\
         }}\n\
         impl Metrics {{\n\
         pub fn new() -> Result<Self, prometheus::Error> {{\n\
         let registry = Registry::new();\n\
         {inits}\
         {registers}\
         Ok(Metrics {{\n\
         {struct_init}\
         }})\n\
         }}\n\
         }}\n"
    );
    // Write every field in production.
    let mut writer = String::from("fn emit(m: &crate::core::metrics::Metrics) {\n");
    for i in 0..12 {
        let _ = writeln!(writer, "    m.m{i}.set(1);");
    }
    writer.push_str("}\n");
    vec![
        ("docs/ARCHITECTURE.md", "# a\n"),
        ("Cargo.toml", "[package]\nname = \"x\"\nversion = \"0\"\n"),
        ("src/core/metrics.rs", Box::leak(metrics.into_boxed_str())),
        ("src/writer.rs", Box::leak(writer.into_boxed_str())),
    ]
}

/// # Errors
///
/// Returns the first canary that misbehaves.
pub fn self_test() -> Result<String, String> {
    let tmp = scratch_dir()?;
    clean_case(&tmp)?;
    baseline_case(&tmp)?;
    // Stale baseline (metric now written) must fail.
    let stale = tmp.join("stale");
    write_tree(&stale, &clean_tree_files())?;
    fs::create_dir_all(stale.join(".github")).map_err(|e| e.to_string())?;
    fs::write(stale.join(BASELINE_PATH), "IntGauge\tm0\n").map_err(|e| e.to_string())?;
    if accepts(&stale)? {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: a stale baseline entry for a now-written metric passed",
        ));
    }

    // Multi-line write must count.
    let multiline = tmp.join("multiline");
    write_tree(&multiline, &clean_tree_files())?;
    let ml_writer = "fn emit(m: &crate::core::metrics::Metrics) {\n\
                     m.m0.set(1); m.m1.set(1); m.m2.set(1); m.m3.set(1);\n\
                     m.m4.set(1); m.m5.set(1); m.m6.set(1); m.m7.set(1);\n\
                     m.m8.set(1); m.m9.set(1); m.m10.set(1);\n\
                     m.m11\n    .set(1);\n\
                     }\n";
    fs::write(multiline.join("src/writer.rs"), ml_writer).map_err(|e| e.to_string())?;
    if !accepts(&multiline)? {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: a multi-line `.field.set(` write was not detected",
        ));
    }

    timer_case(&tmp)?;

    // cfg(test) write must NOT count.
    let test_only = tmp.join("test_only");
    write_tree(&test_only, &clean_tree_files())?;
    let test_writer = "fn emit(m: &crate::core::metrics::Metrics) {\n\
                       m.m0.set(1); m.m1.set(1); m.m2.set(1); m.m3.set(1);\n\
                       m.m4.set(1); m.m5.set(1); m.m6.set(1); m.m7.set(1);\n\
                       m.m8.set(1); m.m9.set(1); m.m10.set(1);\n\
                       }\n\
                       #[cfg(test)]\n\
                       mod tests {\n\
                       fn t(m: &crate::core::metrics::Metrics) { m.m11.set(1); }\n\
                       }\n";
    fs::write(test_only.join("src/writer.rs"), test_writer).map_err(|e| e.to_string())?;
    if accepts(&test_only)? {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: a write inside #[cfg(test)] counted as production",
        ));
    }

    // Bodyless cfg(test) must not swallow the file.
    let bodyless = tmp.join("bodyless");
    write_tree(&bodyless, &clean_tree_files())?;
    let bodyless_writer = "#[cfg(test)]\nuse super::foo;\n\
                           fn emit(m: &crate::core::metrics::Metrics) {\n\
                           m.m0.set(1); m.m1.set(1); m.m2.set(1); m.m3.set(1);\n\
                           m.m4.set(1); m.m5.set(1); m.m6.set(1); m.m7.set(1);\n\
                           m.m8.set(1); m.m9.set(1); m.m10.set(1); m.m11.set(1);\n\
                           }\n";
    fs::write(bodyless.join("src/writer.rs"), bodyless_writer).map_err(|e| e.to_string())?;
    if !accepts(&bodyless)? {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: bodyless #[cfg(test)] swallowed production writes",
        ));
    }

    // Identity boundary: peer_count must not match peer_count_extra.
    let boundary = tmp.join("boundary");
    write_tree(&boundary, &clean_tree_files())?;
    // Rename nothing; instead add an unwritten m11 and a false-friend write.
    let boundary_writer = "fn emit(m: &crate::core::metrics::Metrics) {\n\
                           m.m0.set(1); m.m1.set(1); m.m2.set(1); m.m3.set(1);\n\
                           m.m4.set(1); m.m5.set(1); m.m6.set(1); m.m7.set(1);\n\
                           m.m8.set(1); m.m9.set(1); m.m10.set(1);\n\
                           m.m11_extra.set(1);\n\
                           }\n";
    fs::write(boundary.join("src/writer.rs"), boundary_writer).map_err(|e| e.to_string())?;
    if accepts(&boundary)? {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: field prefix matched a longer identifier as a write",
        ));
    }

    // A name that appears only inside a comment is not a write.
    let prose = tmp.join("prose");
    write_tree(&prose, &clean_tree_files())?;
    let prose_writer = "fn emit(m: &crate::core::metrics::Metrics) {\n\
                       m.m0.set(1); m.m1.set(1); m.m2.set(1); m.m3.set(1);\n\
                       m.m4.set(1); m.m5.set(1); m.m6.set(1); m.m7.set(1);\n\
                       m.m8.set(1); m.m9.set(1); m.m10.set(1);\n\
                       // m.m11.set(1);\n\
                       }\n";
    fs::write(prose.join("src/writer.rs"), prose_writer).map_err(|e| e.to_string())?;
    if accepts(&prose)? {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: a write that lives only inside a comment counted as production",
        ));
    }

    empty_case(&tmp)?;


    let _ = fs::remove_dir_all(&tmp);
    Ok(String::from(
        "metrics-are-written canary OK (written PASSes, unwritten FAILs, baseline exempts, \
         stale baseline FAILs, multi-line and start_timer count, cfg(test) does not, \
         bodyless cfg(test) does not swallow, identity boundary holds, comment-only write FAILs, empty tree FAILs).",
    ))
}
fn timer_case(tmp: &Path) -> Result<(), String> {
    // start_timer counts as a write for histograms - use a dedicated tree.
    let timer = tmp.join("timer");
    let metrics_hist = r"use prometheus::{Histogram, HistogramOpts, Registry};
pub struct Metrics {
    pub h0: Histogram,
    pub h1: Histogram,
    pub h2: Histogram,
    pub h3: Histogram,
    pub h4: Histogram,
    pub h5: Histogram,
    pub h6: Histogram,
    pub h7: Histogram,
    pub h8: Histogram,
    pub h9: Histogram,
    pub h10: Histogram,
    pub h11: Histogram,
}
";
    write_tree(
        &timer,
        &[
            ("docs/ARCHITECTURE.md", "# a\n"),
            ("Cargo.toml", "[package]\nname=\"x\"\nversion=\"0\"\n"),
            ("src/core/metrics.rs", metrics_hist),
            (
                "src/writer.rs",
                "fn e(m: &crate::core::metrics::Metrics) {\n\
                 let _ = m.h0.start_timer();\n\
                 let _ = m.h1.start_timer();\n\
                 let _ = m.h2.start_timer();\n\
                 let _ = m.h3.start_timer();\n\
                 let _ = m.h4.start_timer();\n\
                 let _ = m.h5.start_timer();\n\
                 let _ = m.h6.start_timer();\n\
                 let _ = m.h7.start_timer();\n\
                 let _ = m.h8.start_timer();\n\
                 let _ = m.h9.start_timer();\n\
                 let _ = m.h10.start_timer();\n\
                 let _ = m.h11.start_timer();\n\
                 }\n",
            ),
        ],
    )?;
    if !accepts(&timer)? {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "canary: start_timer was not accepted as a write",
        ));
    }
    Ok(())

}

fn empty_case(tmp: &Path) -> Result<(), String> {
    // Vacuity floor.
    let empty = tmp.join("empty");
    write_tree(
        &empty,
        &[
            ("docs/ARCHITECTURE.md", "# a\n"),
            ("Cargo.toml", "[package]\nname=\"x\"\nversion=\"0\"\n"),
            (
                "src/core/metrics.rs",
                "pub struct Metrics { pub only: IntGauge, }\n",
            ),
            ("src/w.rs", "fn e(m: &Metrics) { m.only.set(1); }\n"),
        ],
    )?;
    if accepts(&empty)? {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "canary: a near-empty metrics struct passed, so the gate can be vacuous",
        ));
    }
    Ok(())

}
/// The shape that must pass before any refusal means something: a tree whose every
/// metric is written in production.
fn clean_case(tmp: &Path) -> Result<(), String> {
    let clean = tmp.join("clean");
    write_tree(&clean, &clean_tree_files())?;

    if let Err(msg) = run(&clean) {
        let _ = fs::remove_dir_all(tmp);
        return Err(format!("canary: fully written tree rejected: {msg}"));
    }
    Ok(())
}

/// The baseline can exempt an unwritten field, and must stop exempting it once the
/// write exists; both directions are one fixture because the second tree is the
/// first with a line added.
fn baseline_case(tmp: &Path) -> Result<(), String> {
    // Unwritten field must fail.
    let bad = tmp.join("unwritten");
    let mut files = clean_tree_files();
    // Drop writes for m11 only.
    let writer = "fn emit(m: &crate::core::metrics::Metrics) {\n\
                  m.m0.set(1); m.m1.set(1); m.m2.set(1); m.m3.set(1);\n\
                  m.m4.set(1); m.m5.set(1); m.m6.set(1); m.m7.set(1);\n\
                  m.m8.set(1); m.m9.set(1); m.m10.set(1);\n\
                  }\n";
    files.push(("src/writer.rs", writer));
    // clean_tree_files already has writer; replace by writing after.
    write_tree(&bad, &files)?;
    fs::write(bad.join("src/writer.rs"), writer).map_err(|e| e.to_string())?;
    if accepts(&bad)? {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from("canary: an unwritten metric was accepted"));
    }

    // Baseline exempts the unwritten field.
    let baselined = tmp.join("baselined");
    write_tree(&baselined, &files)?;
    fs::write(baselined.join("src/writer.rs"), writer).map_err(|e| e.to_string())?;
    fs::create_dir_all(baselined.join(".github")).map_err(|e| e.to_string())?;
    fs::write(baselined.join(BASELINE_PATH), "IntGauge\tm11\n").map_err(|e| e.to_string())?;
    if !accepts(&baselined)? {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "canary: a baselined unwritten metric still failed",
        ));
    }
    Ok(())
}

