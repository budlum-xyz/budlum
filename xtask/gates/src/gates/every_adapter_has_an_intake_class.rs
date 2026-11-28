//! Every external adapter is in exactly one of three classes, and says which.
//!
//! # The failure this gate closes
//!
//! Measured 2026-11-27 on `src/cross_domain/external`, production code only
//! (`#[cfg(test)]` stripped, and a `pub use` in `mod.rs` not counted - the
//! sibling gate [`super::no_idle_code`] already states why: a re-export is an
//! import, not a use). Thirty-two `pub struct *Adapter*`, and three different
//! fates:
//!
//! | class | count | what it means |
//! |---|---|---|
//! | named by `intake.rs` | 21 | a verified finality proof can reach a global header |
//! | named only by `economic_guard.rs` | **8** | the family is verified and tested, and its finality cannot be recorded |
//! | named by neither | 3 | not wired at all |
//!
//! The three in the last row each carry `WIRING: unwired - ... awaits
//! AdapterSpec` in their own module header. They are declared debt, and the
//! `unwired declarations` ratchet shrinks them.
//!
//! The eight in the middle row carry nothing. They are not dead code - they
//! have tests and they pass the `selftest::admit` probes - but eight consensus
//! families (Algorand state proofs, merged-mining `AuxPoW`, based
//! preconfirmation, restaking AVS, Simplex BFT, Stellar SCP, Mina recursion,
//! TON Catchain) can be *verified* and cannot be *recorded*. For a layer whose
//! whole claim is "we fold every family's finality into one header", that is
//! the claim being half true in a way nothing in the tree reports.
//!
//! # What this gate decides
//!
//! Every `pub struct *Adapter*` under `src/cross_domain/external` is in exactly
//! one class, and the class is readable from the tree:
//!
//! 1. `intake.rs` names it - no declaration needed, the wiring is the evidence;
//! 2. its module header declares `WIRING: unwired` - declared debt, already
//!    counted by the ratchet that shrinks it;
//! 3. its module header declares `INTAKE: economic-guard-only - <reason>` - the
//!    family is verified for economic purposes and deliberately not recorded.
//!
//! An adapter in none of them fails by name. The point is not to force any
//! particular wiring: it is that the answer to "can this family's finality
//! reach a global header" is written down for all thirty-two, so the count of
//! families Budlum settles is a number anyone can read off the tree instead of
//! a claim.
//!
//! Fail-closed, and in both directions: a class-three declaration on an adapter
//! that `intake.rs` does name is a stale note, and stale notes are how a list
//! stops describing the tree.

use std::path::Path;

/// Where the external domain adapters live.
pub const ADAPTER_DIR: &str = "src/cross_domain/external";

/// The file that is the production intake door.
pub const INTAKE_FILE: &str = "intake.rs";

/// The declaration that puts an adapter in the third class.
pub const ECONOMIC_ONLY: &str = "INTAKE: economic-guard-only";

/// The declaration the already-recorded unwired adapters carry.
pub const UNWIRED: &str = "WIRING: unwired";

/// Files that define adapters but are infrastructure, not a domain family.
const NOT_A_FAMILY: &[&str] = &["spec.rs", "registry.rs", "intake.rs", "mod.rs"];

/// Which class an adapter is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    /// The intake door names it.
    Intake,
    /// Declared unwired.
    Unwired,
    /// Declared verified-but-not-recorded.
    EconomicGuardOnly,
    /// Nothing says which.
    Unclassified,
}

/// One adapter and its class.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Adapter {
    pub name: String,
    pub file: String,
    pub class: Class,
}

/// Production code: every `#[cfg(test)]` item removed, braces balanced.
///
/// Truncating at the first `#[cfg(test)]` is wrong here and was measured to be
/// wrong: four of these files carry a test-only item partway down - in
/// `based_preconf.rs` the first one is at byte 17528 of 56906 - and a reader
/// that stops there never sees the `pub struct ... Adapter` below it. The
/// shared stripper in [`super::capability_modules_are_wired`] removes the item
/// the attribute attaches to and keeps the rest.
fn production(src: &str) -> String {
    super::capability_modules_are_wired::strip_test_mods(src)
}

/// The `pub struct <Name>Adapter<..>` names one source declares.
#[must_use]
pub fn adapter_structs(src: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let prod = production(src);
    for line in prod.lines() {
        let t = line.trim_start();
        let Some(rest) = t.strip_prefix("pub struct ") else {
            continue;
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        // `AdapterId` and `AdapterDescriptor` are the shared vocabulary, not a
        // family; an adapter's name ends with the word.
        if name.ends_with("Adapter") && name != "Adapter" {
            out.push(name);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Does this text name the identifier as a whole word?
fn names(text: &str, ident: &str) -> bool {
    let b = text.as_bytes();
    let mut from = 0usize;
    while let Some(rel) = text[from..].find(ident) {
        let at = from + rel;
        let end = at + ident.len();
        let left_ok = at == 0 || !(b[at - 1].is_ascii_alphanumeric() || b[at - 1] == b'_');
        let right_ok = end >= b.len() || !(b[end].is_ascii_alphanumeric() || b[end] == b'_');
        if left_ok && right_ok {
            return true;
        }
        from = at + ident.len();
    }
    false
}

/// Classify every adapter across the adapter sources.
#[must_use]
pub fn classify(sources: &[(String, String)]) -> Vec<Adapter> {
    let intake = sources
        .iter()
        .find(|(f, _)| f == INTAKE_FILE)
        .map(|(_, s)| production(s))
        .unwrap_or_default();
    let mut out: Vec<Adapter> = Vec::new();
    for (file, src) in sources {
        if NOT_A_FAMILY.contains(&file.as_str()) {
            continue;
        }
        let header = production(src);
        for name in adapter_structs(src) {
            let class = if names(&intake, &name) {
                Class::Intake
            } else if header.contains(UNWIRED) {
                Class::Unwired
            } else if header.contains(ECONOMIC_ONLY) {
                Class::EconomicGuardOnly
            } else {
                Class::Unclassified
            };
            out.push(Adapter {
                name,
                file: file.clone(),
                class,
            });
        }
    }
    out.sort();
    out.dedup();
    out
}

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    pub at: String,
    pub why: String,
}

/// The checkable core.
#[must_use]
pub fn findings(sources: &[(String, String)]) -> Vec<Finding> {
    let adapters = classify(sources);
    let mut out: Vec<Finding> = Vec::new();
    for a in &adapters {
        if a.class == Class::Unclassified {
            out.push(Finding {
                at: format!("{} `{}`", a.file, a.name),
                why: format!(
                    "`{INTAKE_FILE}` does not name it and its module header declares neither \
                     `{UNWIRED}` nor `{ECONOMIC_ONLY} - <reason>`. Say which: a family whose \
                     finality cannot reach a global header is a fact about the settlement \
                     layer, not a detail of one file."
                ),
            });
        }
    }
    // A declaration on an adapter the intake door does name is stale.
    for (file, src) in sources {
        if NOT_A_FAMILY.contains(&file.as_str()) {
            continue;
        }
        if !production(src).contains(ECONOMIC_ONLY) {
            continue;
        }
        let wired_here = adapters
            .iter()
            .any(|a| &a.file == file && a.class == Class::Intake);
        if wired_here {
            out.push(Finding {
                at: file.clone(),
                why: format!(
                    "declares `{ECONOMIC_ONLY}` while `{INTAKE_FILE}` names its adapter. A note \
                     that contradicts the wiring is a list that stopped describing the tree; \
                     delete it."
                ),
            });
        }
    }
    out.sort();
    out.dedup();
    out
}

fn read_adapters(root: &Path) -> Result<Vec<(String, String)>, String> {
    let dir = root.join(ADAPTER_DIR);
    let entries = std::fs::read_dir(&dir).map_err(|e| {
        format!(
            "every-adapter-has-an-intake-class: {} is unreadable: {e}",
            dir.display()
        )
    })?;
    let mut out: Vec<(String, String)> = Vec::new();
    for entry in entries {
        let entry = entry
            .map_err(|e| format!("every-adapter-has-an-intake-class: read_dir failed: {e}"))?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "rs") {
            let name = path
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
            let src = std::fs::read_to_string(&path).map_err(|e| {
                format!(
                    "every-adapter-has-an-intake-class: {} is unreadable: {e}",
                    path.display()
                )
            })?;
            out.push((name, src));
        }
    }
    out.sort();
    Ok(out)
}

pub fn run(root: &Path) -> Result<String, String> {
    let sources = read_adapters(root)?;
    if sources.is_empty() {
        return Err(String::from(
            "every-adapter-has-an-intake-class: no adapter source was read. A check that examines \
             nothing reports OK, which is the failure this gate exists for.",
        ));
    }
    if !sources.iter().any(|(f, _)| f == INTAKE_FILE) {
        return Err(format!(
            "every-adapter-has-an-intake-class: {ADAPTER_DIR}/{INTAKE_FILE} is missing, so every \
             adapter would read as unwired. The intake door is the input to this gate."
        ));
    }
    let adapters = classify(&sources);
    if adapters.is_empty() {
        return Err(String::from(
            "every-adapter-has-an-intake-class: no `pub struct *Adapter*` was found. \
             Thirty-two were present when this gate was written; finding none means the reader \
             is broken or the adapters moved.",
        ));
    }
    let found = findings(&sources);
    if !found.is_empty() {
        let mut msg = format!(
            "every-adapter-has-an-intake-class: {} adapter(s) do not say whether their family's \
             finality can reach a global header:\n",
            found.len()
        );
        for f in &found {
            msg.push_str("  - ");
            msg.push_str(&f.at);
            msg.push_str(": ");
            msg.push_str(&f.why);
            msg.push('\n');
        }
        return Err(msg);
    }
    let count = |c: Class| adapters.iter().filter(|a| a.class == c).count();
    Ok(format!(
        "every-adapter-has-an-intake-class OK: {} adapter(s) - {} named by {INTAKE_FILE}, {} \
         declaring `{UNWIRED}`, {} declaring `{ECONOMIC_ONLY}`, 0 silent",
        adapters.len(),
        count(Class::Intake),
        count(Class::Unwired),
        count(Class::EconomicGuardOnly)
    ))
}

pub fn self_test() -> Result<String, String> {
    let intake = (
        "intake.rs".to_string(),
        String::from("fn door() {\n    let a = BitcoinSpvAdapter::new();\n}\n"),
    );
    let wired = (
        "bitcoin_spv.rs".to_string(),
        String::from("//! SPV.\npub struct BitcoinSpvAdapter {\n    n: u8,\n}\n"),
    );
    let silent = (
        "stellar_fba.rs".to_string(),
        String::from("//! SCP.\npub struct StellarScpAdapter {\n    n: u8,\n}\n"),
    );
    let sources = vec![intake.clone(), wired.clone(), silent.clone()];
    let found = findings(&sources);
    if found.len() != 1 || !found[0].at.contains("StellarScpAdapter") {
        return Err(format!(
            "canary: an adapter the intake door does not name and that declares nothing must be \
             reported once, got {found:?}"
        ));
    }

    // The same adapter, declaring the class: no finding.
    let declared = (
        "stellar_fba.rs".to_string(),
        String::from(
            "//! SCP.\n//! INTAKE: economic-guard-only - the quorum slices price risk, the \
             finality is not recorded yet.\npub struct StellarScpAdapter {\n    n: u8,\n}\n",
        ),
    );
    if !findings(&[intake.clone(), wired.clone(), declared]).is_empty() {
        return Err(String::from(
            "canary: a declared economic-guard-only adapter must produce no finding",
        ));
    }

    // Declared unwired is the other accepted class.
    let unwired = (
        "arweave_spora.rs".to_string(),
        String::from(
            "//! WIRING: unwired - awaits AdapterSpec.\npub struct ArweaveSpOraAdapter {\n    n: \
             u8,\n}\n",
        ),
    );
    if !findings(&[intake.clone(), wired.clone(), unwired]).is_empty() {
        return Err(String::from(
            "canary: a declared unwired adapter must produce no finding",
        ));
    }

    // A note that contradicts the wiring is stale.
    let contradicting = (
        "bitcoin_spv.rs".to_string(),
        String::from(
            "//! INTAKE: economic-guard-only - left behind.\npub struct BitcoinSpvAdapter {\n    \
             n: u8,\n}\n",
        ),
    );
    let stale = findings(&[intake.clone(), contradicting]);
    if stale.len() != 1 || !stale[0].why.contains("stopped describing the tree") {
        return Err(format!(
            "canary: a note contradicting the wiring must be reported, got {stale:?}"
        ));
    }

    // A struct defined inside the test module is not an adapter of the tree.
    let only_in_tests = (
        "x.rs".to_string(),
        String::from("#[cfg(test)]\nmod t {\n    pub struct FixtureAdapter {}\n}\n"),
    );
    if !findings(&[intake, wired, only_in_tests]).is_empty() {
        return Err(String::from(
            "canary: a fixture adapter inside the test module must be skipped",
        ));
    }

    Ok(String::from(
        "every-adapter-has-an-intake-class canary OK (a silent adapter is reported, an \
         economic-guard-only declaration clears it, an unwired declaration clears it, a note \
         that contradicts the wiring is reported, and a fixture inside the test module is \
         skipped).",
    ))
}
