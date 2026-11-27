//! One refusal class, one error variant: `require_slashable` is refused with
//! `AdapterError::UnslashableBacking` and nothing else.
//!
//! # The failure this gate closes
//!
//! `AdapterError` carries a dedicated variant for exactly one question:
//!
//! ```text
//! /// The backing is not slashable and the caller required slashable backing.
//! #[error("the caller requires slashable backing; this evidence's backing is not")]
//! UnslashableBacking,
//! ```
//!
//! and the type's own doc says why: "Every variant names the rule, so a refusal
//! can be logged, metered and tested without reading the adapter's source."
//!
//! Measured on 2026-11-27 across `src/cross_domain/external`: nineteen
//! production `if policy.require_slashable { ... }` guards. Thirteen returned
//! `UnslashableBacking`. Six, in five files, returned the catch-all
//! `ConsensusRule { rule: String }` instead - `algorand_stateproof.rs`,
//! `bitvm_covenant.rs`, `casper_ffg.rs`, `ethereum.rs` (twice),
//! `mysticeti_dag.rs`, `simplex_bft.rs`.
//!
//! Three consequences, all measurable:
//!
//! * A consumer pricing risk across heterogeneous domains - the whole point of
//!   a settlement layer that verifies other people's consensus - cannot tell
//!   "your backing is not slashable" apart from any other consensus-rule
//!   refusal without matching on an English sentence.
//! * The tests that pinned those six refusals asserted
//!   `Err(AdapterError::ConsensusRule { .. })`, or in two files only
//!   `is_err()`. Both are satisfied by a refusal for a completely different
//!   reason, so the test did not prove the slashable rule fired at all.
//! * A refusal class that cannot be matched cannot be metered.
//!
//! # What this gate decides
//!
//! For every file in `src/cross_domain/external`, outside `#[cfg(test)]`:
//! every `if policy.require_slashable { ... }` block that returns an error
//! returns `AdapterError::UnslashableBacking`. That is the whole rule, and it
//! has no false positive: the guard names the policy field, and the block
//! either names the variant or does not.
//!
//! A second rule was written and then taken out, with the measurement that
//! removed it: "a test that sets the flag and asserts a refusal must name the
//! variant" flagged thirteen tests in seven files on the tree it was written
//! against, and most were long acceptance tests that happen to set the flag in
//! one place and assert thirty unrelated things elsewhere. A gate that reports
//! a finding the reader has to triage is a gate the reader learns to skip, so
//! the rule was dropped rather than loosened; the six tests that really did
//! pin this refusal with `ConsensusRule { .. }` or a bare `is_err()` were
//! tightened by hand in the same change.
//!
//! Fail-closed: a tree where the gate finds no guard at all is a failure, not
//! a pass, because the shape it measures was present when it was written.
//!
//! The reader is textual and brace-balanced rather than a full parse, for the
//! same reason [`super::ci_trigger_coverage`] is: the shape is local, and a
//! shape it cannot read is reported rather than guessed.

use std::path::Path;

/// Where the external domain adapters live.
pub const ADAPTER_DIR: &str = "src/cross_domain/external";

/// The variant every `require_slashable` refusal must use.
pub const REQUIRED_VARIANT: &str = "UnslashableBacking";

/// The guard whose refusal this gate types.
const GUARD: &str = "if policy.require_slashable {";

/// One production guard and what it returns.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Guard {
    pub file: String,
    pub line: usize,
    /// `true` when the block returns `AdapterError::UnslashableBacking`.
    pub typed: bool,
    /// `true` when the block returns an error at all.
    pub refuses: bool,
}

/// Where `#[cfg(test)]` starts in this source, if it does.
fn test_module_start(src: &str) -> usize {
    src.find("#[cfg(test)]").unwrap_or(src.len())
}

/// The balanced `{ ... }` block that starts at the `{` in `src[open..]`.
fn balanced_block(src: &str, open: usize) -> &str {
    let bytes = src.as_bytes();
    let mut depth = 0usize;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &src[open..=i];
                }
            }
            _ => {}
        }
        i += 1;
    }
    &src[open..]
}

/// Read the production guards of one adapter source.
#[must_use]
pub fn guards(file: &str, src: &str) -> Vec<Guard> {
    let prod = &src[..test_module_start(src)];
    let mut out: Vec<Guard> = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = prod[from..].find(GUARD) {
        let at = from + rel;
        let open = at + GUARD.len() - 1;
        let block = balanced_block(prod, open);
        out.push(Guard {
            file: file.to_string(),
            line: prod[..at].matches('\n').count() + 1,
            typed: block.contains(REQUIRED_VARIANT),
            refuses: block.contains("Err("),
        });
        from = at + GUARD.len();
    }
    out
}

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    pub where_: String,
    pub what: String,
}

/// The checkable core: sources in, findings out.
#[must_use]
pub fn findings(sources: &[(String, String)]) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    for (file, src) in sources {
        for g in guards(file, src) {
            if g.refuses && !g.typed {
                out.push(Finding {
                    where_: format!("{file}:{}", g.line),
                    what: format!(
                        "the `require_slashable` guard refuses with an untyped error; the \
                         refusal class has a variant of its own, `AdapterError::{REQUIRED_VARIANT}`"
                    ),
                });
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Read every `.rs` file under the adapter directory.
fn read_adapters(root: &Path) -> Result<Vec<(String, String)>, String> {
    let dir = root.join(ADAPTER_DIR);
    let entries = std::fs::read_dir(&dir).map_err(|e| {
        format!(
            "unslashable-refusal-is-typed: {} is unreadable: {e}",
            dir.display()
        )
    })?;
    let mut out: Vec<(String, String)> = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|e| format!("unslashable-refusal-is-typed: read_dir failed: {e}"))?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "rs") {
            let name = path
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
            let src = std::fs::read_to_string(&path).map_err(|e| {
                format!(
                    "unslashable-refusal-is-typed: {} is unreadable: {e}",
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
            "unslashable-refusal-is-typed: no adapter source was read. A check that examines \
             nothing reports OK, which is the failure this gate exists for.",
        ));
    }
    let total_guards: usize = sources.iter().map(|(f, s)| guards(f, s).len()).sum();
    if total_guards == 0 {
        return Err(format!(
            "unslashable-refusal-is-typed: no `{GUARD}` guard was found in {} adapter source(s). \
             Nineteen were present when this gate was written; finding none means the reader is \
             broken or the guard moved, and either way the gate is no longer measuring what it \
             claims.",
            sources.len()
        ));
    }
    let found = findings(&sources);
    if !found.is_empty() {
        let mut msg = format!(
            "unslashable-refusal-is-typed: {} site(s) do not use the refusal class the spec \
             created for them:\n",
            found.len()
        );
        for f in &found {
            msg.push_str("  - ");
            msg.push_str(&f.where_);
            msg.push_str(": ");
            msg.push_str(&f.what);
            msg.push('\n');
        }
        msg.push_str(
            "A consumer that prices risk across domains must be able to match the class, not an \
             English sentence. Return `AdapterError::",
        );
        msg.push_str(REQUIRED_VARIANT);
        msg.push_str("` and assert that variant in the test.");
        return Err(msg);
    }
    Ok(format!(
        "unslashable-refusal-is-typed OK: {} adapter source(s), {total_guards} production \
         `require_slashable` guard(s), every one refusing with AdapterError::{REQUIRED_VARIANT}",
        sources.len()
    ))
}

pub fn self_test() -> Result<String, String> {
    // The measured shape: a guard that refuses with the catch-all.
    let untyped = (
        "casper_ffg.rs".to_string(),
        String::from(
            "fn verify(&self) -> R {\n    if policy.require_slashable {\n        return \
             Err(AdapterError::ConsensusRule { rule: \"not escrowed\".to_string() });\n    }\n    \
             Ok(())\n}\n",
        ),
    );
    let found = findings(std::slice::from_ref(&untyped));
    if found.len() != 1 || !found[0].where_.starts_with("casper_ffg.rs:2") {
        return Err(format!(
            "canary: an untyped `require_slashable` refusal must be reported once, got {found:?}"
        ));
    }

    // The same guard, typed: no finding.
    let typed = (
        "ghostdag.rs".to_string(),
        String::from(
            "fn verify(&self) -> R {\n    if policy.require_slashable {\n        return \
             Err(AdapterError::UnslashableBacking);\n    }\n    Ok(())\n}\n",
        ),
    );
    if !findings(std::slice::from_ref(&typed)).is_empty() {
        return Err(String::from(
            "canary: a guard that returns the typed variant must produce no finding",
        ));
    }

    // A guard inside `#[cfg(test)]` is a fixture, not a production refusal.
    let in_tests = (
        "x.rs".to_string(),
        String::from(
            "#[cfg(test)]\nmod t {\n    fn helper() {\n        if policy.require_slashable {\n   \
             return Err(AdapterError::ConsensusRule { rule: \"x\".into() });\n        }\n    }\n}\n",
        ),
    );
    if !findings(std::slice::from_ref(&in_tests)).is_empty() {
        return Err(String::from(
            "canary: a guard inside the test module is not a production refusal",
        ));
    }

    Ok(String::from(
        "unslashable-refusal-is-typed canary OK (an untyped refusal is reported, a typed one is \
         not, and a guard inside the test module is skipped).",
    ))
}
