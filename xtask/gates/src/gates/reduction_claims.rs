//! A reduction claim states both units (files and bytes) or neither.
//!
//! Ported from `scripts/check-reduction-claims-state-both-units.sh`. The
//! roadmap must quantify shares in both object and byte units, carry the
//! DOI citation for the corpus measurement, and record the 447 factor whose
//! table row actually divides to it.

use std::path::Path;

const DOC: &str = "docs/BUD_STORAGE_ROADMAP.md";

fn mentions_object_unit(text: &str) -> bool {
    let lower = text.to_lowercase();
    lower.contains("share of files")
        || lower.contains("share of objects")
        || lower.contains("% of files")
        || lower.contains("% of objects")
        || lower.contains("files") && lower.contains('%')
        || lower.contains("objects") && lower.contains('%')
}

fn mentions_byte_unit(text: &str) -> bool {
    let lower = text.to_lowercase();
    lower.contains("share of bytes")
        || lower.contains("share of volume")
        || lower.contains("% of bytes")
        || lower.contains("% of volume")
        || lower.contains("bytes") && lower.contains('%')
        || lower.contains("volume") && lower.contains('%')
        || lower.contains("billed in bytes")
}

/// True when `needle` appears in `text` as a whole number, not inside a longer
/// one such as `1447` or `447.5`.
fn has_number(text: &str, needle: &str) -> bool {
    let b = text.as_bytes();
    let numeric = |c: u8| c.is_ascii_digit() || c == b'.' || c == b',';
    text.match_indices(needle).any(|(at, _)| {
        let before = at.checked_sub(1).and_then(|i| b.get(i)).copied();
        let after = b.get(at + needle.len()).copied();
        let after_ok = match after {
            None => true,
            Some(c) => {
                !numeric(c)
                    || (c == b'.' || c == b',')
                        && !b.get(at + needle.len() + 1).is_some_and(u8::is_ascii_digit)
            }
        };
        !before.is_some_and(numeric) && after_ok
    })
}

/// The first paragraph that states a share in one unit with an explicit
/// phrase and never names the other unit.
fn one_unit_paragraph(text: &str) -> Option<String> {
    text.split("\n\n").find_map(|para| {
        let lower = para.to_lowercase();
        let obj = lower.contains("% of files") || lower.contains("% of objects");
        let by_bytes = lower.contains("% of bytes") || lower.contains("% of volume");
        let has_obj = obj || lower.contains("share of files") || lower.contains("share of objects");
        let has_bytes = by_bytes || lower.contains("share of bytes") || lower.contains("share of volume");
        ((obj && !has_bytes) || (by_bytes && !has_obj))
            .then(|| para.lines().next().unwrap_or("").to_string())
    })
}

/// Parse the JSON row of the corpus table: `| JSON ... | <files_pct> | <bytes_pct> | ...`.
fn json_row_ratio(text: &str) -> Option<(f64, f64)> {
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with('|') && l.contains("JSON"))?;
    let cells: Vec<&str> = line.split('|').collect();
    // cells[0] empty, cells[1]="JSON", cells[2]=files%, cells[3]=bytes%
    if cells.len() < 5 {
        return None;
    }
    let files: String = cells[2]
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let bytes: String = cells[3]
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if files.is_empty() || bytes.is_empty() {
        return None;
    }
    let f: f64 = files.parse().ok()?;
    let b: f64 = bytes.parse().ok()?;
    if b == 0.0 {
        return None;
    }
    Some((f, b))
}

/// # Errors
///
/// Returns the first violated claim.
pub fn run(root: &Path) -> Result<String, String> {
    let path = root.join(DOC);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("claim document missing: {}: {e}", path.display()))?;

    let obj = mentions_object_unit(&text);
    let has_byte = mentions_byte_unit(&text);
    if obj && !has_byte {
        return Err(format!(
            "{DOC} quantifies a share of objects and never a share of bytes.\n  \
             Measured: the same corpus is 40.2% of files and 0.09% of bytes for one\n  \
             class. Storage is billed in bytes, so the object figure alone overstates\n  \
             the saving by up to a factor of 447."
        ));
    }
    if has_byte && !obj {
        return Err(format!(
            "{DOC} quantifies a share of bytes and never a share of objects.\n  \
             The byte figure alone understates how much of what a user uploads is\n  \
             covered. Both units or neither."
        ));
    }

    if let Some(first) = one_unit_paragraph(&text) {
        return Err(format!(
            "{DOC} has a paragraph that states a share in one unit only, starting: {first}\n  \
             Every claim names both files and bytes."
        ));
    }

    if !text.contains("10.1145/3656015") {
        return Err(String::from(
            "the corpus composition measurement has no citation in the roadmap.\n  \
             The rule this gate enforces rests on a specific published crawl. Without\n  \
             the reference the rule is an assertion, and the next person to reweight\n  \
             the numbers has nothing to check them against.",
        ));
    }
    if !has_number(&text, "447") {
        return Err(String::from(
            "the roadmap no longer records the size of the discrepancy.\n  \
             447 is the factor between the two units for one class, and it is the whole\n  \
             reason this rule exists.",
        ));
    }
    match json_row_ratio(&text) {
        None => {
            return Err(String::from(
                "the corpus table has no JSON row.\n  \
             The 447 the rule rests on is the ratio of that row's two percentages, and\n  \
             without the row the number is an assertion.",
            ))
        }
        Some((f, b)) => {
            let factor = (f / b).round();
            let rounded = factor.round();
            if (rounded - 447.0).abs() > 0.5 {
                return Err(format!(
                    "the roadmap states a factor of 447 but its own table divides to {rounded:.0}."
                ));
            }
        }
    }

    Ok(String::from(
        "Reduction-claims gate OK: both units stated, citation present, 447 factor matches the table.",
    ))
}

/// # Errors
///
/// Returns a finding when a defect fixture passes.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-reduce")?;
    let _ = std::fs::create_dir_all(dir.join("docs"));

    let good = "The corpus: 40.2% of files, 0.09% of bytes (share of files vs share of bytes).\nReference: 10.1145/3656015. Factor: 447.\n| JSON | 40.2% | 0.09% |\n";
    std::fs::write(dir.join(DOC), good).map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a correct document was refused"));
    }
    // Object-only claim.
    let bad = "40.2% of files only, no byte share.\n";
    std::fs::write(dir.join(DOC), bad).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a single object-unit claim passed"));
    }
    // A single-unit claim in its own paragraph, and a number that only contains 447.
    let para = format!("{good}\n40.2% of files are small.\n");
    std::fs::write(dir.join(DOC), para).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a single-unit paragraph passed"));
    }
    if has_number("factor 1447 here", "447") || !has_number("factor 447.", "447") {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: number matching is not exact"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "reduction-claims canary OK (both units PASS, a single unit FAILs).",
    ))
}
