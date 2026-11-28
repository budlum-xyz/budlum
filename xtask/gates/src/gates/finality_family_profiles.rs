//! The two finality decision paths agree with the one family-profile table,
//! and with each other.
//!
//! # The failure this closes
//!
//! `ExternalVerifierFamily` has 32 variants. Two functions decide what each of
//! them may finalize on, on two different paths:
//! `ExternalVerifierFamily::verify_descriptor` (does this adapter still declare
//! the profile its family owns?) and
//! `FinalityProofShape::from_external_attestation` (may this attestation's
//! security backing carry this family?). Each used to carry its own 32-arm
//! `match`. A family added to one and forgotten in the other would finalize
//! something the other path refuses, and nothing in the tree read both.
//!
//! `decision::FAMILY_PROFILES` now states the profile once and both paths read
//! it. This gate is what makes that hold when the file is edited again:
//!
//! 1. every family has exactly one row, and the rows cover the enum exactly;
//! 2. each row's `consensus_kind` is what `consensus_kind()` returns;
//! 3. each row asks for its own family's backing set, and `backings_of`
//!    answers every family exactly once;
//! 4. both decision paths consult the table instead of restating the profile.
//!
//! What this gate does not claim: that a family's *chosen* profile is the
//! right one. That is a behavioural question, answered by the crate's own
//! named tests (`the_pairings_are_the_ones_the_code_asserted` among them),
//! which the named-test half of the gate family requires by name.
//!
//! Reading Rust by text is a weak instrument and says so: the family
//! extraction is anchored on the row constructor `p(` and on the arm heads
//! `ExternalVerifierFamily::`, so a rewrite that changes either shape fails
//! here with "cannot read" instead of passing silently.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

/// The file that carries the table and both decision paths.
const SOURCE_REL: &str = "src/domain/finality_proof_model.rs";

/// The number of built-in families, from the enum's `BudZkVmExecution = 31`.
const FAMILY_COUNT: usize = 32;

/// What one family's profile row says that text can be held to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Row {
    pub(crate) family: String,
    pub(crate) consensus_kind: String,
    pub(crate) backings_of: String,
}

/// The source under test, read from the repository this gate belongs to.
///
/// # Errors
///
/// A source this gate cannot read is a failure, never a panic: a canary that
/// panics reports nothing.
pub(crate) fn fixture() -> Result<String, String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .ok_or_else(|| String::from("finality-family-profiles: no repository root above the gate"))?;
    std::fs::read_to_string(root.join(SOURCE_REL))
        .map_err(|e| format!("finality-family-profiles: cannot read the source under test: {e}"))
}

/// Read the six fields of one row, joining formatter-wrapped lines.
fn row_fields(chunk: &str) -> Vec<String> {
    let mut fields = Vec::new();
    for line in chunk.lines().map(str::trim) {
        if line.starts_with("//") || line.is_empty() {
            continue;
        }
        fields.push(line.to_string());
        if line.starts_with("backings_of(") || line == ")," {
            break;
        }
    }
    fields
}

/// Read the `FAMILY_PROFILES` rows.
///
/// # Errors
///
/// A row that cannot be read is an error, not a skip: a table this gate could
/// not read is a table it cannot hold the code to.
pub(crate) fn rows(text: &str) -> Result<Vec<Row>, String> {
    let start = text
        .find("pub const FAMILY_PROFILES: &[Profile] = &[")
        .ok_or_else(|| format!("{SOURCE_REL}: no `FAMILY_PROFILES` table"))?;
    let table = &text[start..];
    let end = table
        .find("\n    ];")
        .ok_or_else(|| format!("{SOURCE_REL}: the `FAMILY_PROFILES` table has no end"))?;

    let mut out = Vec::new();
    for chunk in table[..end].split("p(\n").skip(1) {
        let fields = row_fields(chunk);
        let read = |i: usize| -> Result<&str, String> {
            fields.get(i).map(String::as_str).ok_or_else(|| {
                format!(
                    "{SOURCE_REL}: a row stopped after field {i}; read: {}",
                    fields.join(" | ")
                )
            })
        };
        let family = read(0)?
            .strip_prefix("ExternalVerifierFamily::")
            .and_then(|l| l.strip_suffix(','))
            .ok_or_else(|| format!("{SOURCE_REL}: a row does not start with a family name"))?
            .to_string();
        let consensus_kind = read(1)?
            .strip_prefix('"')
            .and_then(|l| l.rsplit_once('"'))
            .map(|(k, _)| k.to_string())
            .ok_or_else(|| format!("{SOURCE_REL}: row {family} has no consensus kind"))?;
        let backings_of = read(5)?
            .strip_prefix("backings_of(ExternalVerifierFamily::")
            .and_then(|l| l.strip_suffix("),"))
            .ok_or_else(|| {
                format!("{SOURCE_REL}: row {family} does not name its backing set through `backings_of`")
            })?
            .to_string();
        out.push(Row {
            family,
            consensus_kind,
            backings_of,
        });
    }
    Ok(out)
}

/// The variants the enum declares, as `(name, discriminant)`.
///
/// # Errors
///
/// An enum this reader cannot parse is a finding, not a skip.
pub(crate) fn enum_variants(text: &str) -> Result<Vec<(String, u8)>, String> {
    let start = text
        .find("pub(crate) enum ExternalVerifierFamily {")
        .ok_or_else(|| format!("{SOURCE_REL}: no `ExternalVerifierFamily` enum"))?;
    let rest = &text[start..];
    let end = rest
        .find("\n}")
        .ok_or_else(|| format!("{SOURCE_REL}: the family enum has no end"))?;
    let mut out = Vec::new();
    for line in rest[..end].lines().skip(1) {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        let Some((name, disc)) = line.trim_end_matches(',').split_once(" = ") else {
            continue;
        };
        let disc: u8 = disc.trim().parse().map_err(|_| {
            format!("{SOURCE_REL}: family {name} has a discriminant this reader cannot parse")
        })?;
        out.push((name.to_string(), disc));
    }
    Ok(out)
}

/// The arms of `backings_of`, as `family -> backing set`.
///
/// The arms are read as one squashed line: whitespace carries no meaning in a
/// `match` arm and the formatter may wrap anywhere.
///
/// # Errors
///
/// A tree without the decision is a finding: the backing half of the profile
/// has to have one home.
pub(crate) fn backings_arms(text: &str) -> Result<Vec<(String, String)>, String> {
    let start = text
        .find("pub const fn backings_of(family: ExternalVerifierFamily) -> Backings {")
        .ok_or_else(|| {
            format!("{SOURCE_REL}: `backings_of` is gone; the backing half of the profile has no home")
        })?;
    let rest = &text[start..];
    let end = rest
        .find("\n    }\n")
        .ok_or_else(|| format!("{SOURCE_REL}: `backings_of` has no end"))?;
    let squashed: String = rest[..end]
        .split_whitespace()
        .collect::<String>()
        .replace("=>{", "=>")
        .replace('}', ",");
    // Everything before the `match family {` is the signature; the arms start
    // after it, so a signature that this reader cannot parse never becomes an
    // arm.
    let marker = "matchfamily{";
    let Some(at) = squashed.find(marker) else {
        return Err(format!(
            "{SOURCE_REL}: `backings_of` does not match on the family"
        ));
    };
    let body = &squashed[at + marker.len()..];

    let mut out = Vec::new();
    for arm in body.split(',') {
        let Some((lhs, rhs)) = arm.split_once("=>") else {
            continue;
        };
        let Some(backing) = rhs.trim_matches(|c| c == '{' || c == '}').strip_prefix("Backings::")
        else {
            continue;
        };
        for name in lhs.split('|') {
            let name = name
                .strip_prefix("ExternalVerifierFamily::")
                .ok_or_else(|| format!("{SOURCE_REL}: unreadable arm `{arm}`"))?;
            out.push((name.to_string(), backing.to_string()));
        }
    }
    if out.is_empty() {
        return Err(format!(
            "{SOURCE_REL}: `backings_of` states no arm this reader can read"
        ));
    }
    Ok(out)
}

/// `consensus_kind()` arms, as `family -> string`.
fn consensus_kinds(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(start) = text.find("pub(crate) const fn consensus_kind(self) -> &'static str {") else {
        return out;
    };
    let rest = &text[start..];
    let Some(end) = rest.find("\n    }\n") else {
        return out;
    };
    for line in rest[..end].lines() {
        let Some(arm) = line.trim().strip_prefix("Self::") else {
            continue;
        };
        let Some((name, value)) = arm.split_once(" => ") else {
            continue;
        };
        out.insert(
            name.trim().to_string(),
            value.trim().trim_end_matches(',').trim_matches('"').to_string(),
        );
    }
    out
}

/// Does `verify_descriptor` consult the table instead of restating the profile?
pub(crate) fn verify_descriptor_consults_the_table(text: &str) -> bool {
    let Some(start) = text.find("pub(crate) fn verify_descriptor(") else {
        return false;
    };
    let rest = &text[start..];
    let end = rest.find("\n    }\n").unwrap_or(rest.len());
    rest[..end].contains("decision::family(self)") && rest[..end].contains("profile.accepts(")
}

/// Does the attestation path consult the table instead of restating the rule?
pub(crate) fn attestation_consults_the_table(text: &str) -> bool {
    let Some(start) = text.find("pub(crate) fn from_external_attestation(") else {
        return false;
    };
    let rest = &text[start..];
    let end = rest.find("\n    }\n").unwrap_or(rest.len());
    rest[..end].contains("decision::family(family)") && rest[..end].contains("accepts_backing(")
}

/// Every finding for one source text.
pub(crate) fn check_text(text: &str, label: &str) -> Vec<String> {
    let mut findings: Vec<String> = Vec::new();
    let variants = match enum_variants(text) {
        Ok(v) => v,
        Err(e) => return vec![e],
    };
    let rows = match rows(text) {
        Ok(r) => r,
        Err(e) => return vec![e],
    };

    if variants.len() != FAMILY_COUNT {
        findings.push(format!(
            "{label}: the family enum declares {} variants, the profile table is written for {FAMILY_COUNT}",
            variants.len()
        ));
    }
    let discs: Vec<u8> = variants.iter().map(|(_, d)| *d).collect();
    let expected: Vec<u8> = (0..FAMILY_COUNT as u8).collect();
    if discs != expected {
        findings.push(format!(
            "{label}: family discriminants are not 0..={}: {discs:?}",
            FAMILY_COUNT - 1
        ));
    }

    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for r in &rows {
        if !seen.insert(&r.family) {
            findings.push(format!(
                "{label}: family `{}` has more than one profile row",
                r.family
            ));
        }
    }
    for (name, _) in &variants {
        if !seen.contains(name.as_str()) {
            findings.push(format!(
                "{label}: family `{name}` has no profile row; nobody decided its backing rule"
            ));
        }
    }
    for r in &rows {
        if !variants.iter().any(|(n, _)| n == &r.family) {
            findings.push(format!(
                "{label}: profile row `{}` names no family in the enum",
                r.family
            ));
        }
        if r.backings_of != r.family {
            findings.push(format!(
                "{label}: row `{}` states `{}`'s backing; a row may only carry its own family's",
                r.family, r.backings_of
            ));
        }
    }

    let canonical = consensus_kinds(text);
    for r in &rows {
        match canonical.get(&r.family) {
            Some(kind) if kind == &r.consensus_kind => {}
            Some(kind) => findings.push(format!(
                "{label}: row `{}` says `{}`, `consensus_kind()` says `{kind}`",
                r.family, r.consensus_kind
            )),
            None => findings.push(format!(
                "{label}: family `{}` has a profile row but no canonical consensus kind",
                r.family
            )),
        }
    }

    if !verify_descriptor_consults_the_table(text) {
        findings.push(format!(
            "{label}: `verify_descriptor` does not read `decision::family(..)`; the profile is restated locally again"
        ));
    }
    if !attestation_consults_the_table(text) {
        findings.push(format!(
            "{label}: `from_external_attestation` does not read `decision::family(..)`; the backing rule is restated locally again"
        ));
    }

    match backings_arms(text) {
        Err(e) => findings.push(e),
        Ok(arms) => {
            let answered: Vec<&str> = arms.iter().map(|(f, _)| f.as_str()).collect();
            for (name, _) in &variants {
                if !answered.contains(&name.as_str()) {
                    findings.push(format!(
                        "{label}: family `{name}` has no arm in the backing decision"
                    ));
                }
            }
            for name in &answered {
                if answered.iter().filter(|a| a == &name).count() > 1 {
                    findings.push(format!(
                        "{label}: family `{name}` is answered more than once by the backing decision"
                    ));
                }
            }
        }
    }

    if findings.is_empty() {
        let mut note = String::new();
        let _ = write!(
            note,
            "finality-family-profiles: {} families, {} rows, one table; both decision paths read it and the backing decision answers every family once",
            variants.len(),
            rows.len()
        );
        return vec![note];
    }
    findings.sort();
    findings.dedup();
    findings
}

/// Run the gate against a repository root.
///
/// # Errors
///
/// Returns every finding.
pub fn run(root: &Path) -> Result<String, String> {
    let path = root.join(SOURCE_REL);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("finality-family-profiles: cannot read {}: {e}", path.display()))?;
    let mut findings = check_text(&text, SOURCE_REL);
    if findings.len() == 1 && findings[0].starts_with("finality-family-profiles:") {
        return Ok(findings.remove(0));
    }
    Err(format!(
        "finality-family-profiles: {} finding(s):\n  {}",
        findings.len(),
        findings.join("\n  ")
    ))
}

/// Self-test: the gate reads a real tree, and refuses each tamper it exists for.
///
/// # Errors
///
/// Returns the tamper that passed or the good tree that failed.
pub fn self_test() -> Result<String, String> {
    let good = fixture()?;
    let findings = check_text(&good, "fixture");
    if !(findings.len() == 1 && findings[0].starts_with("finality-family-profiles:")) {
        return Err(format!(
            "finality-family-profiles self-test: the tree was refused: {}",
            findings.join("; ")
        ));
    }

    // A canary must actually change the text, and must be refused.
    let expect = |text: &str, needle: &str, what: &str| -> Result<(), String> {
        if check_text(text, "fixture").iter().all(|f| !f.contains(needle)) {
            return Err(format!("finality-family-profiles self-test: {what} passed"));
        }
        Ok(())
    };

    // 1. A family missing from the table.
    let missing = good.replace(
        "            ExternalVerifierFamily::TendermintBft,\n            \"tendermint-bft\",",
        "            ExternalVerifierFamily::TendermintBff,\n            \"tendermint-bft\",",
    );
    if missing == good {
        return Err(String::from(
            "finality-family-profiles self-test: no Tendermint row to remove",
        ));
    }
    expect(&missing, "has no profile row", "a missing row")?;
    expect(&missing, "profile row `TendermintBff` names no family", "a row naming no family")?;

    // 2. A row whose consensus kind drifts from the canonical string.
    let drifted = good.replace(
        "            ExternalVerifierFamily::TendermintBft,\n            \"tendermint-bft\",",
        "            ExternalVerifierFamily::TendermintBft,\n            \"tendermint-bft-draft\",",
    );
    expect(&drifted, "`consensus_kind()` says", "a drifted consensus kind")?;

    // 3. A row that carries another family's backing.
    let stolen = good.replace(
        "            backings_of(ExternalVerifierFamily::TendermintBft),",
        "            backings_of(ExternalVerifierFamily::TendermintBff),",
    );
    if stolen == good {
        return Err(String::from(
            "finality-family-profiles self-test: no Tendermint backing reference to move",
        ));
    }
    expect(&stolen, "a row may only carry its own family", "a row carrying a neighbour's backing")?;

    // 4. A family losing its arm in the backing decision.
    let no_arm = good.replace(
        "            | ExternalVerifierFamily::TendermintBft\n",
        "",
    );
    if no_arm == good {
        return Err(String::from(
            "finality-family-profiles self-test: no Tendermint arm to remove",
        ));
    }
    expect(&no_arm, "has no arm in the backing decision", "a family without an arm")?;

    // 5. A family answered twice.
    let twice = good.replace(
        "            | ExternalVerifierFamily::TendermintBft\n",
        "            | ExternalVerifierFamily::TendermintBft\n            \
         | ExternalVerifierFamily::TendermintBft\n",
    );
    expect(&twice, "answered more than once", "a doubly answered family")?;

    // 6. `verify_descriptor` stops reading the table.
    let local_again = good.replace(
        "let Some(profile) = super::decision::family(self) else {",
        "let Some(profile) = super::local_profile_row(self) else {",
    );
    if local_again == good {
        return Err(String::from(
            "finality-family-profiles self-test: the tree does not read the table where the canary expects it",
        ));
    }
    expect(&local_again, "`verify_descriptor` does not read", "a path restating the profile")?;

    // 7. The attestation path stops reading the table.
    let att_local = good.replace(
        "let Some(profile) = decision::family(family) else {",
        "let Some(profile) = local_backing_row(family) else {",
    );
    if att_local == good {
        return Err(String::from(
            "finality-family-profiles self-test: the attestation path does not read the table where the canary expects it",
        ));
    }
    expect(
        &att_local,
        "`from_external_attestation` does not read",
        "an attestation path restating the backing rule",
    )?;

    // 8. An enum variant the table cannot see.
    let extra = good.replace(
        "    BudZkVmExecution = 31,\n}",
        "    BudZkVmExecution = 31,\n    Unlisted = 32,\n}",
    );
    if extra == good {
        return Err(String::from(
            "finality-family-profiles self-test: no enum tail to extend",
        ));
    }
    expect(&extra, "declares 33 variants", "an unlisted family")?;

    // 9. The backing decision removed.
    let no_decision = good.replace(
        "pub const fn backings_of(family: ExternalVerifierFamily) -> Backings {",
        "pub const fn backings_of_renamed(family: ExternalVerifierFamily) -> Backings {",
    );
    expect(&no_decision, "backing half of the profile has no home", "a removed backing decision")?;

    Ok(String::from(
        "finality-family-profiles self-test: a missing row, a row naming no family, a drifted \
         consensus kind, a row carrying a neighbour's backing, a family without an arm, a doubly \
         answered family, both paths restating their rule, an unlisted family and a removed \
         backing decision are each refused; the tree as committed passes",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_test_passes() -> Result<(), String> {
        super::self_test().map(|_| ())
    }

    #[test]
    fn the_table_covers_every_variant() -> Result<(), String> {
        let text = super::fixture()?;
        let variants = super::enum_variants(&text)?;
        let rows = super::rows(&text)?;
        if variants.len() != 32 || rows.len() != 32 {
            return Err(format!(
                "the enum declares {} families and the table carries {} rows",
                variants.len(),
                rows.len()
            ));
        }
        Ok(())
    }

    #[test]
    fn the_backing_arms_are_read() -> Result<(), String> {
        let text = super::fixture()?;
        let arms = super::backings_arms(&text)?;
        for (family, backing) in [
            ("HeterogeneousMultiProver", "ZkOrSignatureSet"),
            ("BitcoinNakamotoPow", "Work"),
            ("BitVmCovenant", "Work"),
            ("TendermintBft", "SignatureSet"),
            ("AuxPowPop", "WorkOrSignatureSet"),
        ] {
            if !arms.iter().any(|(f, b)| f == family && b == backing) {
                return Err(format!("`backings_of` does not answer {family} with {backing}"));
            }
        }
        Ok(())
    }
}
