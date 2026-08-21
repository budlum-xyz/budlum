//! No secret material may be compared with plain `==` / `!=`.
//!
//! Ported from `scripts/check-timing-safe.sh`. Scanning `src/rpc` and
//! `src/crypto`, a line that pairs a secret-ish identifier with a plain
//! equality is a timing side-channel candidate and is reported. Lines that
//! are explicitly constant-time, comments, assertions, `#[cfg(test)]` and
//! length checks are filtered, mirroring the shell gate's filter list.
//!
//! # Why this gate exists
//!
//! `src/rpc` and `src/crypto` handle API keys, bearer tokens and private
//! keys. A plain `==` on those leaks timing; the correct comparison is
//! `subtle` / `constant_time_eq_str` (B3 fix). This static scan is the
//! complement of the dudect-style statistical test in
//! `benches/micro/timing_safe.rs`; together they form the CI `timing-safe`
//! job.

use std::fs;
use std::path::Path;

/// Case-insensitive secret-ish identifier stems (the shell regex
/// `secret|api_?key|bearer|token|password|credential|passwd|priv_?key`).
const SECRET_STEMS: &[&str] = &[
    "secret",
    "api_key",
    "apikey",
    "api-key",
    "bearer",
    "token",
    "password",
    "credential",
    "passwd",
    "priv_key",
    "privkey",
    "priv-key",
];

/// Directories scanned by the gate.
const SCAN_DIRS: &[&str] = &["src/rpc", "src/crypto"];

/// Lower-cases the line for case-insensitive stem matching.
fn has_secret(line: &str) -> bool {
    let low = line.to_ascii_lowercase();
    SECRET_STEMS.iter().any(|s| low.contains(s))
}

/// `(==|!=)` present on the line.
fn has_plain_eq(line: &str) -> bool {
    line.contains("==") || line.contains("!=")
}

/// The shell gate's `filter_allowed` list.
fn is_filtered(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        return true;
    }
    if line.contains("ct_eq") || line.contains("constant_time") {
        return true;
    }
    if line.contains(".len()") {
        return true;
    }
    if line.contains("assert") {
        return true;
    }
    if line.contains("#[cfg(test)]") {
        return true;
    }
    if line.contains("REPLACE_TOKEN") {
        return true;
    }
    if line.contains("expect(") {
        return true;
    }
    // A comment on the same line that itself compares a secret is filtered
    // too (`//.*(==|!=).*secret`).
    if let Some(pos) = line.find("//") {
        let tail = &line[pos..];
        if (tail.contains("==") || tail.contains("!=")) && has_secret(tail) {
            return true;
        }
    }
    false
}

/// Collect candidate lines: `*.rs` files under [`SCAN_DIRS`] where a secret-ish name
/// and a plain equality share the line, then drop the filtered ones.
fn collect(root: &Path) -> Vec<String> {
    let mut hits = Vec::new();
    for dir in SCAN_DIRS {
        let base = root.join(dir);
        collect_dir(&base, &mut hits);
    }
    hits.retain(|l| !is_filtered(l));
    hits
}

fn collect_dir(dir: &Path, out: &mut Vec<String>) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.filter_map(Result::ok).collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for e in entries {
        let Ok(path_kind) = e.file_type() else {
            continue;
        };
        let path = e.path();
        if path_kind.is_dir() {
            collect_dir(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            for line in text.lines() {
                if has_secret(line) && has_plain_eq(line) {
                    out.push(format!("{}: {}", path.display(), line.trim()));
                }
            }
        }
    }
}

/// # Errors
///
/// Returns every candidate line (the shell gate's "İHLAL ADAYLARI" report).
pub fn run(root: &Path) -> Result<String, String> {
    let hits = collect(root);
    if hits.is_empty() {
        return Ok(String::from(
            "[check-timing-safe] TEMİZ: gizli materyal üzerinde ham == / != yok.",
        ));
    }
    let mut msg = String::from("[check-timing-safe] İHLAL ADAYLARI BULUNDU:\n");
    for h in &hits {
        msg.push_str(h);
        msg.push('\n');
    }
    msg.push_str(
        "\n[check-timing-safe] Gizli materyal ham == / != ile karşılaştırılamaz.\n\
         [check-timing-safe] Çözüm: subtle::ConstantTimeEq / constant_time_eq_str kullan\n\
         [check-timing-safe] (referans: src/rpc/server.rs, B3).",
    );
    Err(msg)
}

/// The shell gate's alarm canary: two deliberate violations must be caught;
/// if the scan misses them the gate is vacuous and fails with exit 3.
pub fn self_test() -> Result<String, String> {
    let canary = "fn is_authorized_canary(provided: &str, expected_secret: &str) -> bool {\n    // KASITLI İHLAL: gizli materyalin ham == ile karşılaştırılması.\n    provided == expected_secret\n}\nfn pin_check(pin: &str, api_key: &str) -> bool {\n    pin != api_key\n}\n";
    let mut hits: Vec<&str> = Vec::new();
    for line in canary.lines() {
        if has_secret(line)
            && has_plain_eq(line)
            && !line.contains("ct_eq")
            && !line.contains("constant_time")
        {
            hits.push(line);
        }
    }
    if hits.is_empty() {
        return Err(String::from(
            "[check-timing-safe] HATA: kanarya ihlalleri yakalanamadı → statik kapı BOŞ (vacuous)!",
        ));
    }
    Ok(format!(
        "[check-timing-safe] Kanarya YAKALANDI ({} ihlal satırı) → statik kapı ÇALIŞIYOR.",
        hits.len()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canary_lines_are_detected() {
        let lines = [
            "provided == expected_secret",
            "pin != api_key",
            "if token == supplied {",
        ];
        for l in lines {
            assert!(has_secret(l) && has_plain_eq(l), "line missed: {l}");
        }
    }

    #[test]
    fn filtered_lines_are_exempt() {
        let lines = [
            "// comparing secret is fine in prose",
            "a.ct_eq(b)",
            "constant_time_eq_str(a, b)",
            "assert_eq!(a, b)",
            "if key.len() == expected.len() {",
        ];
        for l in lines {
            assert!(is_filtered(l), "line not filtered: {l}");
        }
    }

    #[test]
    fn clean_lines_are_not_candidates() {
        assert!(!has_secret("let x = 1 + 2;"));
        assert!(!has_plain_eq("let a = 5;"));
    }
}
