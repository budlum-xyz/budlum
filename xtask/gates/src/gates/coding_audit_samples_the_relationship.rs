//! The coding audit must check the Reed-Solomon relationship, on a column the
//! operator did not choose, and must refuse the objects it cannot audit.
//!
//! Ported from `scripts/check-coding-audit-samples-the-relationship.sh`, 505
//! lines of shell wrapping Python. The shell was a here-doc launcher and the
//! Python did the work, so the port replaces two languages with one, and the
//! Python's regexes become plain string and brace matching.
//!
//! # Why this gate exists
//!
//! A retrieval challenge asks whether the operator still has the bytes. It
//! cannot ask whether those bytes are correct parity, because the chain never
//! sees shard contents. So an operator could pass every retrieval challenge
//! it was ever given while storing garbage under the parity shard's
//! `ContentId`, and nobody would find out until the repair that needed that
//! parity, which is the one moment the object cannot afford it.
//!
//! The audit closes that by sampling the relationship itself. Reed-Solomon
//! works symbol-wise, so one byte column is a complete instance of it: parity
//! byte `c` of shard `i` is `XOR_j coeff(i, j) * data_j[c]`. That makes the
//! audit cost `k` data bytes plus one parity byte no matter how large the
//! object is.
//!
//! The four ways this can be built so it looks right and proves nothing:
//!
//! 1. The verifier compares hashes, or compares the parity byte against
//!    something other than the generator product. Then it is a checksum over
//!    bytes the operator supplied, and the operator supplies both sides.
//! 2. The column is chosen by the caller rather than derived from entropy.
//!    An opener who picks the column picks one the operator has, and an
//!    operator who knows the column in advance stores only that column.
//! 3. A replicated object reports a passing audit. There is no parity, so
//!    there is no relationship, and "pass" there is a report about an audit
//!    that did not happen, on exactly the objects with no redundancy to
//!    spare.
//! 4. An out-of-range parity index or a short data column is treated as
//!    zero-padded rather than refused. Zero is a valid byte, so the
//!    relationship stays checkable and an operator answers an audit it
//!    cannot answer.
//!
//! What this gate does not check: that the operator stores anything. That is
//! the retrieval challenge's question.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Where the coder lives.
const ERASURE: &str = "src/storage/erasure.rs";
/// Where the selection and verifier live.
const DEAL: &str = "src/domain/storage_deal.rs";
/// Where the regression tests live.
const LOCKS: &str = "src/tests/manifest_commitment_locks.rs";

/// The six tests this gate requires to exist as real `#[test]`s.
const REQUIRED_TESTS: &[&str] = &[
    "an_honest_operator_passes_the_audit",
    "an_operator_serving_garbage_parity_fails",
    "a_single_flipped_bit_is_caught",
    "a_replicated_object_has_nothing_to_audit",
    "the_selection_is_not_the_openers_to_make",
    "the_selection_lands_inside_the_object",
];

/// Remove line comments, exactly as the shell version did.
fn strip_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.split_inclusive('\n') {
        if let Some(rel) = line.find("//") {
            let (head, _) = line.split_at(rel);
            out.push_str(head);
            if line.ends_with('\n') {
                out.push('\n');
            }
        } else {
            out.push_str(line);
        }
    }
    out
}

/// The brace-matched body of the item whose text starts at `marker`.
fn body_of(src: &str, marker: &str) -> Option<String> {
    let start = src.find(marker)?;
    let open = src[start + marker.len()..].find('{')? + start + marker.len();
    let mut depth = 0usize;
    for (idx, c) in src[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(src[open..=open + idx].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

/// The text inside the first parentheses after `marker`, when the function
/// also returns something (`->` follows the closing paren).
fn parens_of(src: &str, marker: &str) -> Option<String> {
    let start = src.find(marker)?;
    let after = start + marker.len();
    let open = src[after..].find('(')? + after;
    let close = src[open + 1..].find(')')? + open + 1;
    let mut j = close + 1;
    while j < src.len() && src[j..].chars().next().is_some_and(char::is_whitespace) {
        let len = src[j..].chars().next().map_or(1, char::len_utf8);
        j += len;
    }
    if !src[j..].starts_with("->") {
        return None;
    }
    Some(src[open + 1..close].to_string())
}

/// Is the test present as a real `#[test] fn`, allowing attributes between
/// the marker and the name?
fn test_is_present(locks: &str, name: &str) -> bool {
    let needle = "[test]";
    let mut i = 0usize;
    while let Some(rel) = locks[i..].find(needle) {
        let mut j = i + rel + needle.len();
        loop {
            while j < locks.len() && locks.as_bytes()[j].is_ascii_whitespace() {
                j += 1;
            }
            if locks[j..].starts_with('[') {
                if let Some(end) = locks[j..].find(']') {
                    j += end + 1;
                    continue;
                }
            }
            break;
        }
        if locks[j..].starts_with("fn") {
            let mut k = j + 2;
            while k < locks.len() && locks.as_bytes()[k].is_ascii_whitespace() {
                k += 1;
            }
            if locks[k..].starts_with(name) {
                let mut m = k + name.len();
                while m < locks.len() && locks.as_bytes()[m].is_ascii_whitespace() {
                    m += 1;
                }
                if locks[m..].starts_with('(') {
                    return true;
                }
            }
        }
        i = j;
    }
    false
}

/// Does the text contain `needle` as a whole identifier?
fn has_ident(text: &str, needle: &str) -> bool {
    let nb = needle.as_bytes();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i + nb.len() <= bytes.len() {
        if &bytes[i..i + nb.len()] == nb {
            let prev_ok = i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
            let after = i + nb.len();
            let next_ok = after >= bytes.len()
                || !(bytes[after].is_ascii_alphanumeric() || bytes[after] == b'_');
            if prev_ok && next_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

struct Outcome {
    checked: usize,
    problems: Vec<String>,
}

/// Read the three files and measure every property the audit depends on.
fn measure(root: &Path) -> Result<Outcome, String> {
    let erasure = root.join(ERASURE);
    let deal = root.join(DEAL);
    let locks = root.join(LOCKS);
    for path in [&erasure, &deal, &locks] {
        if !path.is_file() {
            return Err(format!("expected source file missing: {}", path.display()));
        }
    }

    let erasure_src = std::fs::read_to_string(&erasure)
        .map_err(|e| format!("cannot read {}: {e}", erasure.display()))?;
    let erasure_code = strip_comments(&erasure_src);
    let deal_src = std::fs::read_to_string(&deal)
        .map_err(|e| format!("cannot read {}: {e}", deal.display()))?;
    let deal_code = strip_comments(&deal_src);
    let locks_src = std::fs::read_to_string(&locks)
        .map_err(|e| format!("cannot read {}: {e}", locks.display()))?;

    let col = check_column(&erasure_code);
    let sel = check_selection(&deal_code);
    let ver = check_verifier(&deal_code);
    let tests = check_tests(&locks_src);

    let checked = col.checked + sel.checked + ver.checked + tests.checked;
    let mut problems = col.problems;
    problems.extend(sel.problems);
    problems.extend(ver.problems);
    problems.extend(tests.problems);

    Ok(Outcome { checked, problems })
}

struct Checks {
    checked: usize,
    problems: Vec<String>,
}

impl Checks {
    fn new(checked: usize, problems: Vec<String>) -> Self {
        Self { checked, problems }
    }
}

fn check_column(erasure_code: &str) -> Checks {
    let mut checked = 0;
    let mut problems: Vec<String> = Vec::new();
    // 1. The column check must exist and must actually multiply through the
    //    generator. A version comparing hashes would pass every name-based
    //    check.
    checked += 1;
    let col = body_of(erasure_code, "pub fn column_is_correctly_encoded");
    if col.is_none() {
        problems.push(String::from(
            "`ReedSolomon::column_is_correctly_encoded` is gone. It is the only \
         thing that checks parity against the generator rather than against \
         bytes the operator supplied.",
        ));
    } else {
        let col = col.as_deref().unwrap_or("");
        checked += 1;
        if !has_ident(col, "gf_mul") {
            problems.push(String::from(
                "`column_is_correctly_encoded` no longer multiplies through the \
             field. Without `gf_mul` it is not checking the Reed-Solomon \
             relationship, whatever else it compares.",
            ));
        }
        checked += 1;
        if !col.contains("^=") && !col.contains('^') {
            problems.push(String::from(
                "`column_is_correctly_encoded` no longer accumulates with XOR. \
             GF(2^8) addition is XOR; any other combiner computes a different \
             code.",
            ));
        }
        checked += 1;
        if !col.contains("generator") {
            problems.push(String::from(
                "`column_is_correctly_encoded` does not read the generator \
             matrix, so it is not comparing against the coefficients the \
             encoder used.",
            ));
        }
        // 4. Width and range must be refused, not padded.
        checked += 1;
        if !col.contains("self.k") || !col.contains("self.m") {
            problems.push(String::from(
                "`column_is_correctly_encoded` does not bound the column width \
             against `k` and the parity index against `m`. A short column \
             treated as zero-padded still satisfies the relationship, because \
             zero is a valid byte, so an operator answers an audit it cannot \
             answer.",
            ));
        }
    }

    // 2. Selection must be derived
    Checks::new(checked, problems)
}
fn check_selection(deal_code: &str) -> Checks {
    let mut checked = 0;
    let mut problems: Vec<String> = Vec::new();
    // 2. Selection must be derived from entropy, inside the chain, not taken
    //    as a caller-chosen argument.
    checked += 1;
    let sel = body_of(deal_code, "pub fn derive_coding_audit");
    let sig = parens_of(deal_code, "pub fn derive_coding_audit");
    if sel.is_none() || sig.is_none() {
        problems.push(String::from(
            "`derive_coding_audit` is gone; nothing derives which column to \
         sample, so the choice falls to whoever opens the challenge.",
        ));
    } else {
        let sel = sel.as_deref().unwrap_or("");
        let sig = sig.as_deref().unwrap_or("");
        checked += 1;
        if !sig.contains("entropy") {
            problems.push(String::from(
                "`derive_coding_audit` does not take entropy. An opener who picks \
             the column picks one the operator has, and an operator who knows \
             the column in advance stores only that column.",
            ));
        }
        checked += 1;
        if !sel.contains("hash_fields_bytes") {
            problems.push(String::from(
                "`derive_coding_audit` no longer hashes its inputs, so the \
             selection is not a function of unpredictable entropy.",
            ));
        }
        checked += 1;
        if !sel.contains('%') {
            problems.push(String::from(
                "`derive_coding_audit` never reduces the digest into range, so \
             the selection can land outside the object and no honest operator \
             can answer it.",
            ));
        }
        // 3. Replication must be refused.
        checked += 1;
        if !sel.contains("NoParityToAudit") {
            problems.push(String::from(
                "`derive_coding_audit` does not refuse an object with no parity. \
             Reporting a pass there reports an audit that never happened, on \
             the objects that have no redundancy to lose.",
            ));
        }
    }

    // 5. The verifier must go
    Checks::new(checked, problems)
}
fn check_verifier(deal_code: &str) -> Checks {
    let mut checked = 0;
    let mut problems: Vec<String> = Vec::new();
    // 5. The verifier must go through the coder rather than reimplementing it.
    checked += 1;
    let ver = body_of(deal_code, "pub fn verify_coding_audit");
    if ver.is_none() {
        problems.push(String::from(
            "`verify_coding_audit` is gone; nothing checks an answer.",
        ));
    } else {
        let ver = ver.as_deref().unwrap_or("");
        checked += 1;
        if !ver.contains("column_is_correctly_encoded") {
            problems.push(String::from(
                "`verify_coding_audit` does not call \
             `column_is_correctly_encoded`. A second implementation of the \
             relationship can disagree with the encoder, and the encoder is \
             what a repair will use.",
            ));
        }
        checked += 1;
        if !ver.contains("ParityColumnMismatch") {
            problems.push(String::from(
                "`verify_coding_audit` has no distinct failure for a wrong \
             column, so a mismatch is indistinguishable from a lookup error.",
            ));
        }
    }

    // 6. The regressions must exist
    Checks::new(checked, problems)
}
fn check_tests(locks_src: &str) -> Checks {
    let checked = 1;
    let mut problems = Vec::new();
    for test in REQUIRED_TESTS {
        if !test_is_present(locks_src, test) {
            problems.push(format!(
                "required regression test `{test}` is missing or is not a `#[test]`."
            ));
        }
    }
    Checks::new(checked, problems)
}

/// # Errors
///
/// Returns a finding when the tree does not sample the relationship at an
/// entropy-chosen column, or refuses the objects it cannot audit.
pub fn run(root: &Path) -> Result<String, String> {
    let outcome = measure(root)?;
    if outcome.checked == 0 {
        return Err(String::from("gate checked nothing"));
    }
    if !outcome.problems.is_empty() {
        return Err(outcome.problems.join("\n"));
    }
    Ok(format!(
        "coding audit gate OK: {} checks, the relationship is sampled at an \
         entropy-chosen column and replication is refused",
        outcome.checked
    ))
}

/// A fixture and what the gate must do with it.
struct Canary {
    name: &'static str,
    col_mode: &'static str,
    sel_mode: &'static str,
    ver_mode: &'static str,
    tests_mode: &'static str,
    expect: Expect,
}

/// The classification a canary expects from the gate.
enum Expect {
    Finding,
    Pass,
}

fn fixture_col(mode: &str) -> String {
    match mode {
        "gone" => String::new(),
        "hash" => String::from(
            r"    pub fn column_is_correctly_encoded(&self, i: usize, c: &[u8], p: u8) -> bool {
        hash(c) == hash(&[p])
    }
",
        ),
        "nobound" => String::from(
            r"    pub fn column_is_correctly_encoded(&self, i: usize, c: &[u8], p: u8) -> bool {
        let mut acc = 0u8;
        for (j, b) in c.iter().enumerate() {
            acc ^= gf_mul(self.generator.get(j), *b);
        }
        acc == p
    }
",
        ),
        "nogf" => String::from(
            r"    pub fn column_is_correctly_encoded(&self, i: usize, c: &[u8], p: u8) -> bool {
        if c.len() != self.k || i >= self.m { return false; }
        let mut acc = 0u8;
        for b in c.iter() { acc = acc.wrapping_add(*b); }
        acc == p
    }
",
        ),
        _ => String::from(
            r"    pub fn column_is_correctly_encoded(&self, i: usize, c: &[u8], p: u8) -> bool {
        if c.len() != self.k || i >= self.m { return false; }
        let mut acc = 0u8;
        for (j, b) in c.iter().enumerate() {
            acc ^= gf_mul(self.generator.get(self.k + i, j), *b);
        }
        acc == p
    }
",
        ),
    }
}

fn fixture_sel(mode: &str) -> String {
    match mode {
        "gone" => String::new(),
        "caller" => String::from(
            r"    pub fn derive_coding_audit(
        column: u64,
        manifest: &ContentManifest,
        challenge_id: u64,
    ) -> Result<CodingAudit, StorageError> {
        if manifest.erasure.parity_count() == 0 {
            return Err(StorageError::NoParityToAudit { manifest_id: manifest.manifest_id });
        }
        Ok(CodingAudit { manifest_id: manifest.manifest_id, parity_index: 0, column })
    }
",
        ),
        "norange" => String::from(
            r#"    pub fn derive_coding_audit(
        entropy: &Hash32,
        manifest: &ContentManifest,
        challenge_id: u64,
    ) -> Result<CodingAudit, StorageError> {
        if manifest.erasure.parity_count() == 0 {
            return Err(StorageError::NoParityToAudit { manifest_id: manifest.manifest_id });
        }
        let d = hash_fields_bytes(&[b"X", entropy]);
        Ok(CodingAudit {
            manifest_id: manifest.manifest_id,
            parity_index: 0,
            column: u64::from_le_bytes(d[..8].try_into().unwrap()),
        })
    }
"#,
        ),
        "noparity" => String::from(
            r#"    pub fn derive_coding_audit(
        entropy: &Hash32,
        manifest: &ContentManifest,
        challenge_id: u64,
    ) -> Result<CodingAudit, StorageError> {
        let d = hash_fields_bytes(&[b"X", entropy]);
        Ok(CodingAudit {
            manifest_id: manifest.manifest_id,
            parity_index: 0,
            column: u64::from_le_bytes(d[..8].try_into().unwrap()) % 16,
        })
    }
"#,
        ),
        _ => String::from(
            r#"    pub fn derive_coding_audit(
        entropy: &Hash32,
        manifest: &ContentManifest,
        challenge_id: u64,
    ) -> Result<CodingAudit, StorageError> {
        if manifest.erasure.parity_count() == 0 {
            return Err(StorageError::NoParityToAudit { manifest_id: manifest.manifest_id });
        }
        let d = hash_fields_bytes(&[b"X", entropy, &challenge_id.to_le_bytes()]);
        Ok(CodingAudit {
            manifest_id: manifest.manifest_id,
            parity_index: 0,
            column: u64::from_le_bytes(d[..8].try_into().unwrap()) % 16,
        })
    }
"#,
        ),
    }
}

fn fixture_ver(mode: &str) -> String {
    match mode {
        "gone" => String::new(),
        "reimpl" => String::from(
            r"    pub fn verify_coding_audit(&self, a: &CodingAudit, c: &[u8], p: u8) -> Result<(), StorageError> {
        let mut acc = 0u8;
        for b in c.iter() { acc ^= *b; }
        if acc == p { Ok(()) } else {
            Err(StorageError::ParityColumnMismatch {
                manifest_id: a.manifest_id, parity_index: a.parity_index, column: a.column,
            })
        }
    }
",
        ),
        "noerror" => String::from(
            r"    pub fn verify_coding_audit(&self, a: &CodingAudit, c: &[u8], p: u8) -> Result<(), StorageError> {
        let coder = ReedSolomon::for_scheme(&self.scheme).unwrap();
        if coder.column_is_correctly_encoded(a.parity_index as usize, c, p) {
            Ok(())
        } else {
            Err(StorageError::UnknownManifest(a.manifest_id))
        }
    }
",
        ),
        _ => String::from(
            r"    pub fn verify_coding_audit(&self, a: &CodingAudit, c: &[u8], p: u8) -> Result<(), StorageError> {
        let coder = ReedSolomon::for_scheme(&self.scheme).unwrap();
        if coder.column_is_correctly_encoded(a.parity_index as usize, c, p) {
            Ok(())
        } else {
            Err(StorageError::ParityColumnMismatch {
                manifest_id: a.manifest_id, parity_index: a.parity_index, column: a.column,
            })
        }
    }
",
        ),
    }
}

const CANARIES: &[Canary] = &[
    Canary {
        name: "good",
        col_mode: "ok",
        sel_mode: "ok",
        ver_mode: "ok",
        tests_mode: "present",
        expect: Expect::Pass,
    },
    Canary {
        name: "nocol",
        col_mode: "gone",
        sel_mode: "ok",
        ver_mode: "ok",
        tests_mode: "present",
        expect: Expect::Finding,
    },
    Canary {
        name: "hash",
        col_mode: "hash",
        sel_mode: "ok",
        ver_mode: "ok",
        tests_mode: "present",
        expect: Expect::Finding,
    },
    Canary {
        name: "nobound",
        col_mode: "nobound",
        sel_mode: "ok",
        ver_mode: "ok",
        tests_mode: "present",
        expect: Expect::Finding,
    },
    Canary {
        name: "nogf",
        col_mode: "nogf",
        sel_mode: "ok",
        ver_mode: "ok",
        tests_mode: "present",
        expect: Expect::Finding,
    },
    Canary {
        name: "nosel",
        col_mode: "ok",
        sel_mode: "gone",
        ver_mode: "ok",
        tests_mode: "present",
        expect: Expect::Finding,
    },
    Canary {
        name: "caller",
        col_mode: "ok",
        sel_mode: "caller",
        ver_mode: "ok",
        tests_mode: "present",
        expect: Expect::Finding,
    },
    Canary {
        name: "norange",
        col_mode: "ok",
        sel_mode: "norange",
        ver_mode: "ok",
        tests_mode: "present",
        expect: Expect::Finding,
    },
    Canary {
        name: "noparity",
        col_mode: "ok",
        sel_mode: "noparity",
        ver_mode: "ok",
        tests_mode: "present",
        expect: Expect::Finding,
    },
    Canary {
        name: "nover",
        col_mode: "ok",
        sel_mode: "ok",
        ver_mode: "gone",
        tests_mode: "present",
        expect: Expect::Finding,
    },
    Canary {
        name: "reimpl",
        col_mode: "ok",
        sel_mode: "ok",
        ver_mode: "reimpl",
        tests_mode: "present",
        expect: Expect::Finding,
    },
    Canary {
        name: "noerror",
        col_mode: "ok",
        sel_mode: "ok",
        ver_mode: "noerror",
        tests_mode: "present",
        expect: Expect::Finding,
    },
    Canary {
        name: "notest",
        col_mode: "ok",
        sel_mode: "ok",
        ver_mode: "ok",
        tests_mode: "absent",
        expect: Expect::Finding,
    },
];

/// Build a fixture tree with the requested shapes.
fn write_fixture(tmp: &Path, case: &str, c: &Canary) -> Result<(), String> {
    let root = tmp.join(case);
    for sub in ["src/storage", "src/domain", "src/tests"] {
        std::fs::create_dir_all(root.join(sub))
            .map_err(|e| format!("cannot create fixture dirs: {e}"))?;
    }

    let col = fixture_col(c.col_mode);
    std::fs::write(
        root.join(ERASURE),
        format!("impl ReedSolomon {{\n{col}}}\n"),
    )
    .map_err(|e| format!("cannot write fixture erasure: {e}"))?;

    let sel = fixture_sel(c.sel_mode);
    let ver = fixture_ver(c.ver_mode);
    std::fs::write(
        root.join(DEAL),
        format!("impl StorageRegistry {{\n{sel}\n{ver}}}\n"),
    )
    .map_err(|e| format!("cannot write fixture deal: {e}"))?;

    let mut names = REQUIRED_TESTS.to_vec();
    if c.tests_mode == "absent" {
        names.pop();
    }
    let mut locks = String::new();
    for n in names {
        let _ = writeln!(locks, "#[test]\nfn {n}() {{}}\n");
    }
    std::fs::write(root.join(LOCKS), locks)
        .map_err(|e| format!("cannot write fixture locks: {e}"))?;
    Ok(())
}

/// Run the gate against a fixture and classify the result.
fn verdict(tmp: &Path, case: &str, want: &Expect) -> Result<(), String> {
    let dir = tmp.join(case);
    match (run(&dir), want) {
        (Ok(_), Expect::Pass) => Ok(()),
        (Ok(msg), _) => Err(format!("VACUOUS: {case} passed: {msg}")),
        (Err(msg), Expect::Finding) => {
            if msg.contains("expected source file missing") {
                Err(format!(
                    "BROKEN: {case} measured nothing instead of finding: {msg}"
                ))
            } else {
                Ok(())
            }
        }
        (Err(msg), Expect::Pass) => Err(format!("WRONG: {case} was rejected: {msg}")),
    }
}

/// A fresh, exclusively-created scratch directory under the crate's own
/// `target/gate-fixtures`, which the tree owns and the Semgrep scan skips.
fn scratch_dir() -> Result<PathBuf, String> {
    let root = std::env::var("BUDLUM_ROOT")
        .map(PathBuf::from)
        .or_else(|_| std::env::current_dir().map_err(|e| e.to_string()))
        .map_err(|e| format!("cannot determine repo root for fixtures: {e}"))?;
    let base = root.join("target").join("gate-fixtures");
    std::fs::create_dir_all(&base).map_err(|e| format!("cannot create {}: {e}", base.display()))?;
    for attempt in 0..100u32 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = base.join(format!(
            "coding-audit-{}-{nanos}-{attempt}",
            std::process::id()
        ));
        match std::fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(format!("cannot create scratch dir: {e}")),
        }
    }
    Err(String::from(
        "cannot find a free scratch directory name under target/gate-fixtures",
    ))
}

/// # Errors
///
/// Returns every canary that did not behave, joined so the runner prints them
/// as one finding.
pub fn self_test() -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();
    let tmp = scratch_dir()?;
    for c in CANARIES {
        if let Err(e) = write_fixture(&tmp, c.name, c) {
            problems.push(e);
            continue;
        }
        if let Err(e) = verdict(&tmp, c.name, &c.expect) {
            problems.push(e);
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);
    if !problems.is_empty() {
        return Err(problems.join("\n"));
    }
    Ok(String::from(
        "coding audit gate self-test OK: the corrected tree passes and all 12 \
         defect shapes are refused (missing column check, checksum stand-in, \
         unbounded width, non-field accumulator, missing selection, caller-chosen \
         column, unreduced selection, replicated-object audit, missing verifier, \
         reimplemented relationship, indistinct failure, missing regression test).",
    ))
}
