//! An economic property is not read off a cryptographic one without saying so.
//!
//! # The failure this gate closes
//!
//! `SecurityBacking::SignatureSet` carries one field whose whole job is to be
//! comparable across domains:
//!
//! ```text
//! /// `slashable` is carried because it is the difference between "the
//! /// signers lose money if they lie" and "the signers lose nothing"
//! ```
//!
//! A settlement layer that verifies other people's consensus lives or dies on
//! that field meaning the same thing in every domain. A consumer prices a
//! Bitcoin route against a Cosmos route by reading it; if one adapter sets it
//! from economics and another from cryptography, the comparison is wrong and
//! nothing in the tree says so.
//!
//! Measured 2026-11-27 across `src/` and `crates/`, production code only: one
//! site in the whole tree chooses the field with a condition named after a
//! cryptographic property -
//! `src/cross_domain/external/babylon_eots.rs:972`, `if pq_pinned_and_verified
//! { slashable: true } else { slashable: false }`. Every other adapter decides
//! it from the remote protocol's own slashing rule.
//!
//! That one site may well be right: if the key that the slashing evidence
//! extracts can be broken, the slashing guarantee is void, so tying the claim
//! to the observed scheme is a defensible reading. What is not defensible is
//! that the reading is invisible. A consumer comparing two domains cannot know
//! that `slashable` answers a different question in one of them.
//!
//! # What this gate decides
//!
//! A production `if <condition naming a cryptographic property> { ...
//! slashable: <literal> ... } else { ... slashable: <literal> ... }` must carry
//! a declaration in the twelve lines above it:
//!
//! ```text
//! // SLASHABLE-DEPENDS-ON-SCHEME: <why the economic claim depends on the
//! // cryptography here>
//! ```
//!
//! The gate does not forbid the pattern and does not change any behaviour. It
//! makes the set of domains where `slashable` means something extra
//! **enumerable**: `grep SLASHABLE-DEPENDS-ON-SCHEME` is the list, and a new
//! adapter cannot join it silently.
//!
//! Fail-closed in the usual direction, and in one more: a declaration whose
//! site no longer exists is also a failure, because a stale declaration is a
//! list that has stopped describing the tree.

use std::path::{Path, PathBuf};

/// The declaration a site must carry.
pub const DECLARATION: &str = "SLASHABLE-DEPENDS-ON-SCHEME:";

/// Roots that hold production code.
const PROD_ROOTS: &[&str] = &["src", "crates", "budzero"];

/// Directories that are never production.
const SKIP_DIRS: &[&str] = &[".git", "target", "node_modules", "tests", "benches", "fuzz"];

/// Identifier fragments that name a cryptographic property rather than an
/// economic one.
const CRYPTO_WORDS: &[&str] = &[
    "pq",
    "post_quantum",
    "quantum",
    "ml_dsa",
    "mldsa",
    "dilithium",
    "lattice",
    "hybrid",
    "classical",
    "scheme",
];

/// Does this identifier name a cryptographic property?
///
/// Matched on `_`-separated words so `pq_pinned_and_verified` hits and
/// `epoch_quorum` does not: a substring match on `pq` would also fire on
/// `opqueue`, and a gate that reports a word inside another word is a gate the
/// reader learns to ignore.
#[must_use]
pub fn names_a_scheme(condition: &str) -> bool {
    let cleaned: String = condition
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' {
                c
            } else {
                ' '
            }
        })
        .collect();
    cleaned
        .split_whitespace()
        .flat_map(|t| t.split('_'))
        .any(|w| CRYPTO_WORDS.contains(&w.to_ascii_lowercase().as_str()))
}

/// One site where the economic field is chosen by a cryptographic condition.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Site {
    pub file: String,
    pub line: usize,
    pub condition: String,
    pub declared: bool,
}

/// Production code: every `#[cfg(test)]` item removed, braces balanced.
///
/// Truncating at the first `#[cfg(test)]` was measured to be wrong on this
/// tree: several sources carry a test-only item partway down, and a reader
/// that stops there never sees the code below it.
fn production(src: &str) -> String {
    super::capability_modules_are_wired::strip_test_mods(src)
}

/// Does this text carry the declaration as a real line comment?
///
/// A `///` doc comment that *describes* the rule - the one on
/// `SecurityBacking::SignatureSet`, which is where the contract is written
/// down - is prose about the token, not a declaration at a site. Counting it
/// would make the field's own documentation look like a stale entry, which is
/// what the first version of this reader did.
#[must_use]
pub fn declaration_lines(text: &str) -> usize {
    text.lines()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with("//")
                && !t.starts_with("///")
                && !t.starts_with("//!")
                && t.trim_start_matches('/')
                    .trim_start()
                    .starts_with(DECLARATION)
        })
        .count()
}

/// The balanced block that starts at the `{` at `open`.
fn balanced(src: &str, open: usize) -> &str {
    let b = src.as_bytes();
    let mut depth = 0usize;
    let mut i = open;
    while i < b.len() {
        match b[i] {
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

/// The literal `slashable: true|false` an arm sets, if it sets one.
fn arm_literal(arm: &str) -> Option<bool> {
    let at = arm.find("slashable:")?;
    let rest = arm[at + "slashable:".len()..].trim_start();
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

/// The sites one source carries.
///
/// A site is an `if <cond> { .. } else { .. }` whose two arms set the field to
/// **different** literals. That is the shape that matters and the only one:
///
/// * `if all_pq { scheme = A } else { scheme = B }` followed by a constant
///   `slashable: true` chooses the *scheme*, not the claim - measured in
///   `auxpow_pop.rs`, and reported by a looser reader that took the nearest
///   `if`;
/// * `if pq_verified { SignatureSet { slashable: false } } else { Work { .. } }`
///   is non-slashable either way - measured in `pospace_vdf.rs`.
///
/// Neither reads an economic claim off a cryptographic one, so neither is a
/// finding. Both were reported by the first version of this reader, and both
/// are why it compares the two arms instead of trusting proximity.
#[must_use]
pub fn sites(file: &str, src: &str) -> Vec<Site> {
    let prod = &production(src);
    let mut out: Vec<Site> = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = prod[from..].find("if ") {
        let at = from + rel;
        from = at + 3;
        let prev_ok = at == 0 || {
            let p = prod.as_bytes()[at - 1];
            !p.is_ascii_alphanumeric() && p != b'_'
        };
        if !prev_ok {
            continue;
        }
        let Some(brace_rel) = prod[at..].find('{') else {
            break;
        };
        let open = at + brace_rel;
        let cond = prod[at + 3..open].trim();
        if cond.is_empty() || cond.contains('\n') || !names_a_scheme(cond) {
            continue;
        }
        let then_arm = balanced(prod, open);
        let after = open + then_arm.len();
        let tail = prod[after..].trim_start();
        if !tail.starts_with("else") {
            continue;
        }
        let else_off = after + (prod[after..].len() - tail.len()) + "else".len();
        let Some(else_rel) = prod[else_off..].find('{') else {
            continue;
        };
        let else_arm = balanced(prod, else_off + else_rel);
        let (Some(a), Some(b)) = (arm_literal(then_arm), arm_literal(else_arm)) else {
            continue;
        };
        if a == b {
            continue;
        }
        let line = prod[..at].matches('\n').count() + 1;
        let window_start = prod[..at]
            .rmatch_indices('\n')
            .nth(12)
            .map_or(0, |(i, _)| i);
        out.push(Site {
            file: file.to_string(),
            line,
            condition: cond.to_string(),
            declared: declaration_lines(&prod[window_start..at]) > 0,
        });
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
    let mut out: Vec<Finding> = Vec::new();
    let mut declared_anywhere = 0usize;
    let mut sites_total = 0usize;
    for (file, src) in sources {
        for s in sites(file, src) {
            sites_total += 1;
            if s.declared {
                declared_anywhere += 1;
                continue;
            }
            out.push(Finding {
                at: format!("{}:{}", s.file, s.line),
                why: format!(
                    "`slashable` is chosen by `if {}`, which names a cryptographic property, not \
                     an economic one. Declare it with `{DECLARATION} <reason>` within twelve \
                     lines above, so the domains where this field answers an extra question can \
                     be listed.",
                    s.condition
                ),
            });
        }
        // A declaration with no site is a list that stopped describing the tree.
        let prod = production(src);
        let notes = declaration_lines(&prod);
        let here = sites(file, src).iter().filter(|s| s.declared).count();
        if notes > here {
            out.push(Finding {
                at: file.clone(),
                why: format!(
                    "{notes} `{DECLARATION}` declaration(s) but {here} site(s) that need one. A \
                     declaration whose site is gone is a stale entry; delete it."
                ),
            });
        }
    }
    let _ = (declared_anywhere, sites_total);
    out.sort();
    out.dedup();
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.filter_map(Result::ok) {
        let p = e.path();
        let name = p
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        if p.is_dir() {
            if !SKIP_DIRS.contains(&name.as_str()) {
                walk(&p, out);
            }
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

pub fn run(root: &Path) -> Result<String, String> {
    let mut files: Vec<PathBuf> = Vec::new();
    for r in PROD_ROOTS {
        let p = root.join(r);
        if p.is_dir() {
            walk(&p, &mut files);
        }
    }
    if files.is_empty() {
        return Err(String::from(
            "slashable-is-not-quietly-a-scheme-claim: no production source was read. A check that \
             examines nothing reports OK, which is the failure this gate exists for.",
        ));
    }
    files.sort();
    let mut sources: Vec<(String, String)> = Vec::new();
    let mut carriers = 0usize;
    for path in &files {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        if text.contains("slashable:") {
            carriers += 1;
        }
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        sources.push((rel, text));
    }
    if carriers == 0 {
        return Err(String::from(
            "slashable-is-not-quietly-a-scheme-claim: no source sets a `slashable:` field. The \
             field this gate is about was present when it was written; finding none means the \
             reader is broken or the field moved.",
        ));
    }
    let found = findings(&sources);
    if !found.is_empty() {
        let mut msg = format!(
            "slashable-is-not-quietly-a-scheme-claim: {} site(s) read an economic claim off a \
             cryptographic one without saying so:\n",
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
    let declared: usize = sources
        .iter()
        .map(|(f, s)| sites(f, s).iter().filter(|x| x.declared).count())
        .sum();
    Ok(format!(
        "slashable-is-not-quietly-a-scheme-claim OK: {} production source(s), {carriers} setting \
         a `slashable:` field, {declared} site(s) where the economic claim depends on the \
         observed scheme and every one of them says so",
        sources.len()
    ))
}

pub fn self_test() -> Result<String, String> {
    // The measured shape, undeclared.
    let bare = (
        "babylon_eots.rs".to_string(),
        String::from(
            "fn att(&self) -> A {\n    let security = if pq_pinned_and_verified {\n        \
             SecurityBacking::SignatureSet { signers: 1, slashable: true }\n    } else {\n        \
             SecurityBacking::SignatureSet { signers: 1, slashable: false }\n    };\n}\n",
        ),
    );
    let found = findings(std::slice::from_ref(&bare));
    if found.len() != 1 {
        return Err(format!(
            "canary: an undeclared scheme-chosen `slashable` must be reported once, got {found:?}"
        ));
    }

    // Two arms that agree are not a scheme-chosen claim.
    let same = (
        "pospace_vdf.rs".to_string(),
        String::from(
            "fn att() -> A {\n    let s = if pq_verified {\n        \
             SecurityBacking::SignatureSet { slashable: false }\n    } else {\n        \
             SecurityBacking::SignatureSet { slashable: false }\n    };\n}\n",
        ),
    );
    if !findings(std::slice::from_ref(&same)).is_empty() {
        return Err(String::from(
            "canary: two arms that set the same literal are not a finding",
        ));
    }

    // A crypto condition that chooses something else, with a constant field
    // after it, is not a finding either.
    let other = (
        "auxpow_pop.rs".to_string(),
        String::from(
            "fn att() -> A {\n    let scheme = if all_pq { A } else { B };\n    \
             SecurityBacking::SignatureSet { scheme, slashable: true }\n}\n",
        ),
    );
    if !findings(std::slice::from_ref(&other)).is_empty() {
        return Err(String::from(
            "canary: a crypto condition that chooses the scheme is not a finding",
        ));
    }

    // The same shape with the declaration above it: no finding.
    let declared = (
        "babylon_eots.rs".to_string(),
        String::from(
            "fn att(&self) -> A {\n    // SLASHABLE-DEPENDS-ON-SCHEME: the slashing evidence \
             extracts the signing key, so a breakable scheme voids the guarantee.\n    let \
             security = if pq_pinned_and_verified {\n        SecurityBacking::SignatureSet { \
             signers: 1, slashable: true }\n    } else {\n        \
             SecurityBacking::SignatureSet { signers: 1, slashable: false }\n    };\n}\n",
        ),
    );
    if !findings(std::slice::from_ref(&declared)).is_empty() {
        return Err(String::from(
            "canary: a declared site must produce no finding",
        ));
    }

    // An economic condition is not this gate's business.
    let economic = (
        "tendermint.rs".to_string(),
        String::from(
            "fn att(&self) -> A {\n    let s = if bonded_stake_is_escrowed {\n        \
             SecurityBacking::SignatureSet { slashable: true }\n    } else {\n        \
             SecurityBacking::SignatureSet { slashable: false }\n    };\n}\n",
        ),
    );
    if !findings(std::slice::from_ref(&economic)).is_empty() {
        return Err(String::from(
            "canary: a condition named after economics must not be reported",
        ));
    }

    // A stale declaration, with no site under it, is a finding of its own.
    let stale = (
        "x.rs".to_string(),
        String::from("// SLASHABLE-DEPENDS-ON-SCHEME: left behind\nfn f() { let x = 1; }\n"),
    );
    let s = findings(std::slice::from_ref(&stale));
    if s.len() != 1 || !s[0].why.contains("stale entry") {
        return Err(format!(
            "canary: a declaration with no site must be reported, got {s:?}"
        ));
    }

    // `pq` inside a longer word is not the word `pq`.
    if names_a_scheme("opqueue_is_full") {
        return Err(String::from(
            "canary: a crypto word inside another word must not match",
        ));
    }
    if !names_a_scheme("pq_pinned_and_verified") {
        return Err(String::from(
            "canary: an underscore-separated crypto word must match",
        ));
    }

    Ok(String::from(
        "slashable-is-not-quietly-a-scheme-claim canary OK (an undeclared scheme-chosen slashable \
         is reported, a declared one is not, two agreeing arms are not, a crypto condition that \
         chooses the scheme is not, an economic condition is ignored, a stale declaration is \
         reported, and a crypto word inside another word does not match).",
    ))
}
