//! Every quantum statement in the repository carries a claim id, and the claim
//! is backed.
//!
//! # The failure this closes
//!
//! A README that says "quantum-resistant" without saying of what is a claim
//! nobody can test. `docs/pq/CLAIMS.md` is the register: each claim has an id, a
//! layer, the rung of the claim ladder (I-0 to I-4) its sentence needs, the rung
//! its evidence reaches today (`Status`), and the tests that carry it. This gate
//! ties the prose to the register.
//!
//! # What is checked
//!
//! 1. The register parses, ids are unique, every claim names at least one
//!    evidence item (`test:NAME`, `gate:NAME` or `tool:NAME`; `planned:TASK` only
//!    while the claim has no status).
//! 2. A claim with a status has evidence that exists: a `test:` name is a `fn`
//!    in the tree, a `gate:` name is a registered gate, a `tool:` name is a
//!    registered tool. A claim whose status is below its rung cannot be cited.
//! 3. Every line of the scanned documents that talks about quantum computers
//!    carries a `claim:ID` marker (an HTML comment), the id exists, and the
//!    claim's status is at or above its rung. Fenced code and inline code are
//!    not prose and are skipped.
//! 4. Words forbids are refused everywhere in the scanned
//!    documents, marker or not, and an unscoped "quantum-resistant" (no layer
//!    named on the same line) is refused too.
//!
//! The scanned set is the root READMEs, `docs/` (without `docs/audit/` and
//! `docs/pq/`, which are the ledgers and the design record themselves),
//! `bud/README.md`, `budzero/README.md` and `crates/*/README*.md`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

const CLAIMS_REL: &str = "docs/pq/CLAIMS.md";
const GATES_MAIN_REL: &str = "xtask/gates/src/main.rs";
const TOOLS_MAIN_REL: &str = "xtask/tools/src/bin/budlum-tools.rs";

/// Substrings that make a line a quantum statement.
const TRIGGERS: &[&str] = &["quantum", "kuantum"];

/// Whole words that make a line a quantum statement (`shor` must not match `short`).
const TRIGGER_WORDS: &[&str] = &["shor", "grover"];

/// Words that are refused wherever they appear in the scanned documents.
const FORBIDDEN: &[&str] = &[
    "unbreakable",
    "uncrackable",
    "quantum-proof",
    "quantum proof",
    "100% quantum",
    "fully quantum",
    "kırılamaz",
    "yüzde yüz kuantum güvenli",
    "kuantum geçirmez",
];

/// Phrases that need a named scope on the same line.
const SCOPED_PHRASES: &[&str] = &[
    "quantum-resistant",
    "quantum resistant",
    "quantum-safe",
    "quantum safe",
    "quantum-secure",
    "kuantuma dayanıklı",
    "kuantum dayanıklı",
];

/// Scope words: the layer a scoped phrase is about.
const SCOPES: &[&str] = &[
    "signature",
    "signatures",
    "key",
    "keys",
    "wallet",
    "finality",
    "hash",
    "hashes",
    "proof",
    "proofs",
    "stark",
    "layer",
    "kem",
    "transport",
    "tls",
    "imza",
    "anahtar",
    "kesinlik",
    "kanıt",
    "katman",
];

const SKIP_DIRS: &[&str] = &[".git", "target", "node_modules", ".cargo"];

/// A scan that reads fewer documents than this looked at nothing.
const VACUITY_FLOOR: usize = 3;

#[derive(Debug, Clone)]
struct Claim {
    rung: usize,
    status: Option<usize>,
    evidence: Vec<String>,
}

fn rung_rank(text: &str) -> Option<usize> {
    let digit = text.strip_prefix("I-")?;
    let rank: usize = digit.parse().ok()?;
    (rank <= 4).then_some(rank)
}

fn is_claim_id(text: &str) -> bool {
    let mut parts = text.split('-');
    let Some(first) = parts.next() else {
        return false;
    };
    let rest: Vec<&str> = parts.collect();
    !first.is_empty()
        && first.chars().all(|c| c.is_ascii_uppercase())
        && !rest.is_empty()
        && rest
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric()))
}

fn evidence_items(cell: &str) -> Vec<String> {
    cell.split(',')
        .map(|item| item.trim().trim_matches('`').trim().to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

/// Parse the register. Returns the claims and the problems found.
fn parse_register(text: &str) -> (BTreeMap<String, Claim>, Vec<String>) {
    let mut claims = BTreeMap::new();
    let mut problems = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('|') {
            continue;
        }
        let cells: Vec<&str> = trimmed
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        let Some(id) = cells.first().map(|c| c.trim_matches('`')) else {
            continue;
        };
        if !is_claim_id(id) {
            continue;
        }
        if cells.len() != 6 {
            problems.push(format!(
                "{CLAIMS_REL}: row `{id}` has {} cells, expected 6 (ID, Layer, Rung, Status, Evidence, Statement)",
                cells.len()
            ));
            continue;
        }
        let Some(rung) = rung_rank(cells[2]) else {
            problems.push(format!(
                "{CLAIMS_REL}: row `{id}` has the rung `{}`, expected I-0 to I-4",
                cells[2]
            ));
            continue;
        };
        let status = if cells[3] == "none" {
            None
        } else if let Some(rank) = rung_rank(cells[3]) {
            Some(rank)
        } else {
            problems.push(format!(
                "{CLAIMS_REL}: row `{id}` has the status `{}`, expected `none` or I-0 to I-4",
                cells[3]
            ));
            continue;
        };
        let claim = Claim {
            rung,
            status,
            evidence: evidence_items(cells[4]),
        };
        if claims.insert(id.to_string(), claim).is_some() {
            problems.push(format!("{CLAIMS_REL}: claim id `{id}` appears twice"));
        }
    }
    (claims, problems)
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(read) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = read.filter_map(Result::ok).collect();
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if kind.is_dir() {
            if !SKIP_DIRS.contains(&name.as_str()) {
                walk(&path, out);
            }
        } else if kind.is_file() {
            out.push(path);
        }
    }
}

/// `fn NAME` as a whole word in some Rust source of the tree.
fn tree_has_fn(files: &[(String, String)], name: &str) -> bool {
    let needle = format!("fn {name}");
    files.iter().any(|(_, text)| {
        text.match_indices(&needle).any(|(pos, _)| {
            let after = text[pos + needle.len()..].chars().next();
            !after.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        })
    })
}

fn registered(text: &str, name: &str) -> bool {
    text.contains(&format!("\"{name}\""))
}

fn check_register(
    claims: &BTreeMap<String, Claim>,
    rust_files: &[(String, String)],
    gates_main: &str,
    tools_main: &str,
) -> Vec<String> {
    let mut problems = Vec::new();
    for (id, claim) in claims {
        if claim.evidence.is_empty() {
            problems.push(format!("{CLAIMS_REL}: claim `{id}` has no evidence"));
        }
        for item in &claim.evidence {
            let Some((kind, name)) = item.split_once(':') else {
                problems.push(format!(
                    "{CLAIMS_REL}: claim `{id}` evidence `{item}` is not `test:`, `gate:`, `tool:` or `planned:`"
                ));
                continue;
            };
            match kind {
                "planned" => {
                    if claim.status.is_some() {
                        problems.push(format!(
                            "{CLAIMS_REL}: claim `{id}` has a status but its evidence `{item}` is only planned"
                        ));
                    }
                }
                "test" | "gate" | "tool" => {
                    if claim.status.is_none() {
                        continue;
                    }
                    let found = match kind {
                        "test" => tree_has_fn(rust_files, name),
                        "gate" => registered(gates_main, name),
                        _ => registered(tools_main, name),
                    };
                    if !found {
                        problems.push(format!(
                            "{CLAIMS_REL}: claim `{id}` cites {kind} `{name}`, which does not exist in the tree"
                        ));
                    }
                }
                _ => problems.push(format!(
                    "{CLAIMS_REL}: claim `{id}` evidence `{item}` has the unknown kind `{kind}`"
                )),
            }
        }
    }
    problems
}

/// The marker ids on a line: `claim:ID` inside the text.
fn markers(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (pos, _) in line.match_indices("claim:") {
        let id: String = line[pos + "claim:".len()..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();
        if !id.is_empty() {
            out.push(id);
        }
    }
    out
}

/// The line without HTML comments and inline code.
fn prose_of(line: &str) -> String {
    let mut out = String::new();
    let mut rest = line;
    while let Some(start) = rest.find("<!--") {
        out.push_str(&rest[..start]);
        if let Some(end) = rest[start..].find("-->") {
            rest = &rest[start + end + 3..];
        } else {
            rest = "";
            break;
        }
    }
    out.push_str(rest);
    let mut plain = String::new();
    let mut in_code = false;
    for c in out.chars() {
        if c == '`' {
            in_code = !in_code;
        } else if !in_code {
            plain.push(c);
        }
    }
    plain
}

fn check_document(rel: &str, text: &str, claims: &BTreeMap<String, Claim>) -> Vec<String> {
    let mut problems = Vec::new();
    let mut fenced = false;
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        let prose = prose_of(line).to_lowercase();
        for word in FORBIDDEN {
            if prose.contains(word) {
                problems.push(format!(
                    "{rel}:{number}: the phrase `{word}` is not allowed"
                ));
            }
        }
        let talks_about_quantum = TRIGGERS.iter().any(|t| prose.contains(t))
            || prose
                .split(|c: char| !c.is_alphanumeric())
                .any(|word| TRIGGER_WORDS.contains(&word));
        if !talks_about_quantum {
            continue;
        }
        for phrase in SCOPED_PHRASES {
            if prose.contains(phrase) && !SCOPES.iter().any(|s| prose.contains(s)) {
                problems.push(format!(
                    "{rel}:{number}: `{phrase}` names no layer; say what is resistant (signatures, keys, finality, hashes, proofs)"
                ));
            }
        }
        let ids = markers(line);
        if ids.is_empty() {
            problems.push(format!(
                "{rel}:{number}: a quantum statement without a claim id; add `<!-- claim:ID -->` from {CLAIMS_REL}"
            ));
            continue;
        }
        for id in ids {
            match claims.get(&id) {
                None => problems.push(format!("{rel}:{number}: claim id `{id}` is not in {CLAIMS_REL}")),
                Some(claim) => match claim.status {
                    Some(status) if status >= claim.rung => {}
                    _ => problems.push(format!(
                        "{rel}:{number}: claim `{id}` is not yet held (its evidence has not reached its rung), so no document may cite it"
                    )),
                },
            }
        }
    }
    problems
}

fn is_scanned_document(rel: &str) -> bool {
    if !std::path::Path::new(rel)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("md"))
    {
        return false;
    }
    let file = rel.rsplit('/').next().unwrap_or(rel);
    if !rel.contains('/') {
        return file.starts_with("README");
    }
    if rel.starts_with("docs/audit/") || rel.starts_with("docs/pq/") {
        return false;
    }
    if rel.starts_with("docs/") {
        return true;
    }
    rel == "bud/README.md"
        || rel == "budzero/README.md"
        || (rel.starts_with("crates/")
            && rel.matches('/').count() == 2
            && file.starts_with("README"))
}

/// # Errors
///
/// A malformed register, a claim without backing evidence, a quantum statement
/// without a claim id, a claim cited above what its evidence reaches, or a
/// forbidden phrase.
pub fn run(root: &Path) -> Result<String, String> {
    let register = fs::read_to_string(root.join(CLAIMS_REL))
        .map_err(|e| format!("FAIL: {CLAIMS_REL} could not be read: {e}"))?;
    let (claims, mut problems) = parse_register(&register);
    if claims.is_empty() {
        return Err(format!("FAIL: {CLAIMS_REL} holds no claim rows"));
    }
    let mut paths = Vec::new();
    walk(root, &mut paths);
    let mut rust_files = Vec::new();
    let mut documents = Vec::new();
    for path in paths {
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if path.extension().is_some_and(|e| e == "rs") {
            if let Ok(text) = fs::read_to_string(&path) {
                rust_files.push((rel, text));
            }
        } else if is_scanned_document(&rel) {
            if let Ok(text) = fs::read_to_string(&path) {
                documents.push((rel, text));
            }
        }
    }
    let gates_main = fs::read_to_string(root.join(GATES_MAIN_REL)).unwrap_or_default();
    let tools_main = fs::read_to_string(root.join(TOOLS_MAIN_REL)).unwrap_or_default();
    problems.extend(check_register(
        &claims,
        &rust_files,
        &gates_main,
        &tools_main,
    ));
    if documents.len() < VACUITY_FLOOR {
        problems.push(format!(
            "only {} documents were scanned; the gate would look at nothing",
            documents.len()
        ));
    }
    for (rel, text) in &documents {
        problems.extend(check_document(rel, text, &claims));
    }
    if problems.is_empty() {
        return Ok(format!(
            "Every quantum statement is backed: {} claims, {} documents scanned.",
            claims.len(),
            documents.len()
        ));
    }
    let mut msg = String::new();
    for problem in &problems {
        let _ = writeln!(msg, "FAIL: {problem}");
    }
    Err(msg)
}

const CANARY_REGISTER: &str = "\
| ID | Layer | Rung | Status | Evidence | Statement |
|---|---|---|---|---|---|
| S-I0 | plan | I-0 | I-0 | `test:real_test`, `gate:real-gate` | held |
| S-I1 | all | I-1 | none | `planned:` | not held |
";

fn fixture(root: &Path, docs: &[(&str, &str)], register: &str) -> Result<(), String> {
    let write = |rel: &str, text: &str| -> Result<(), String> {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::write(path, text).map_err(|e| e.to_string())
    };
    write(CLAIMS_REL, register)?;
    write(GATES_MAIN_REL, "name: \"real-gate\",\n")?;
    write(TOOLS_MAIN_REL, "\"real-tool\"\n")?;
    write("src/lib.rs", "fn real_test() {}\n")?;
    write("README.md", "# Title\n\nPlain prose.\n")?;
    write("docs/a.md", "Plain prose.\n")?;
    write("docs/b.md", "Plain prose.\n")?;
    for (rel, text) in docs {
        write(rel, text)?;
    }
    Ok(())
}

/// A canary: a label, the extra documents, the register and whether the gate must pass.
type Case = (
    &'static str,
    &'static [(&'static str, &'static str)],
    &'static str,
    bool,
);

const MARKED: &str = "Signatures use ML-DSA, a quantum safe layer. <!-- claim:S-I0 -->\n";

const CASES: &[Case] = &[
    ("backed statement", &[("README.md", MARKED)], CANARY_REGISTER, true),
    (
        "no quantum statement at all",
        &[],
        CANARY_REGISTER,
        true,
    ),
    (
        "a code fence is not prose",
        &[("docs/c.md", "```\nquantum anything\n```\n")],
        CANARY_REGISTER,
        true,
    ),
    (
        "the design record is exempt",
        &[("docs/pq/x.md", "quantum without a marker\n")],
        CANARY_REGISTER,
        true,
    ),
    (
        "an unmarked Shor statement, and short is not Shor",
        &[("README.md", "Short prose.\nShor's algorithm applies here.\n")],
        CANARY_REGISTER,
        false,
    ),
    (
        "an unmarked statement",
        &[("README.md", "Budlum is a quantum project.\n")],
        CANARY_REGISTER,
        false,
    ),
    (
        "an unknown claim id",
        &[("README.md", "A quantum note. <!-- claim:X-NOPE -->\n")],
        CANARY_REGISTER,
        false,
    ),
    (
        "a claim that is not yet held",
        &[("README.md", "A quantum note. <!-- claim:S-I1 -->\n")],
        CANARY_REGISTER,
        false,
    ),
    (
        "a forbidden phrase even with a marker",
        &[("README.md", "Unbreakable quantum layer. <!-- claim:S-I0 -->\n")],
        CANARY_REGISTER,
        false,
    ),
    (
        "an unscoped phrase",
        &[("README.md", "It is quantum-resistant. <!-- claim:S-I0 -->\n")],
        CANARY_REGISTER,
        false,
    ),
    (
        "evidence that does not exist",
        &[],
        "| S-I0 | plan | I-0 | I-0 | `test:no_such_test` | x |\n",
        false,
    ),
    (
        "a held claim with planned evidence",
        &[],
        "| S-I0 | plan | I-0 | I-0 | `planned:` | x |\n",
        false,
    ),
    (
        "a claim without evidence",
        &[],
        "| S-I0 | plan | I-0 | none |  | x |\n",
        false,
    ),
    (
        "a duplicate id",
        &[],
        "| S-I0 | plan | I-0 | none | `planned:` | x |\n| S-I0 | plan | I-0 | none | `planned:` | y |\n",
        false,
    ),
];

/// # Errors
///
/// The first canary that misbehaves: a backed tree passes, and each way a
/// statement or the register can lose its backing is caught.
pub fn self_test() -> Result<String, String> {
    let tmp = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-claims")?;
    for (index, (label, docs, register, should_pass)) in CASES.iter().enumerate() {
        let dir = tmp.join(format!("case{index}"));
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        fixture(&dir, docs, register)?;
        let passed = run(&dir).is_ok();
        if passed != *should_pass {
            let _ = fs::remove_dir_all(&tmp);
            return Err(format!(
                "canary `{label}`: expected the gate to {}, it did the opposite",
                if *should_pass { "pass" } else { "fail" }
            ));
        }
    }
    let _ = fs::remove_dir_all(&tmp);
    Ok(format!(
        "pq-claims-are-backed self-test ok: {} cases",
        CASES.len()
    ))
}
