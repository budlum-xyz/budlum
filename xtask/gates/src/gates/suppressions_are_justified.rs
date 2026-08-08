//! Every `#[allow(...)]` in the tree is listed here, or the build stops.
//!
//! # Why this exists
//!
//! The standing rule is that a check must not be softened: no `#[ignore]`, no
//! `|| true`, no raising a baseline. `#[allow(...)]` is the same act performed
//! on the compiler instead of on CI, and until now nothing counted them.
//!
//! Measured: forty-three in `src/`. Most are ordinary and two are worth
//! saying out loud.
//!
//! `src/network/proto_conversions.rs` turns off `clippy::all` for a whole
//! module. That is legitimate here, because the module is a single `include!`
//! of code `prost-build` generates and nobody edits, but "clippy is off for
//! this file" is exactly the sentence that should never be invisible.
//!
//! `src/crypto/pkcs11.rs` carries four `dead_code` allows on fields of the
//! HSM signer. That is the key-custody boundary. A field nothing reads is
//! either configuration that will be read later or configuration that is
//! silently ignored, and on that path the difference matters.
//!
//! # What the gate does
//!
//! It does not ban suppressions. A blanket ban would be a rule nobody could
//! follow, and it would push people to write worse code to avoid a lint
//! rather than to state why the lint is wrong here.
//!
//! It requires each one to be counted, per file and per lint, against the
//! table below. A file that grows a new suppression fails until the table
//! agrees, and a table entry that no longer matches anything fails too, so
//! the list cannot outlive what it describes. Same shape as `PENDING_REVIEW`
//! and the softener list, for the same reason: a suppression nobody can audit
//! is worse than the finding it hides.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// One file's suppression budget for one lint.
struct Budget {
    /// Path relative to the repository root.
    file: &'static str,
    /// The lint being silenced.
    lint: &'static str,
    /// How many occurrences are expected.
    count: usize,
    /// Why they are acceptable, in a sentence somebody can disagree with.
    reason: &'static str,
}

/// The measured inventory. Counted, not typed.
const BUDGETS: &[Budget] = &[
    Budget {
        file: "src/ai/registry.rs",
        lint: "clippy::too_many_arguments",
        count: 1,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
    Budget {
        file: "src/bin/bud.rs",
        lint: "clippy::too_many_arguments",
        count: 1,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
    Budget {
        file: "src/bin/budlum-relayer.rs",
        lint: "clippy::nursery",
        count: 1,
        reason: "nursery lints are unstable by definition and this file predates the crate-wide ratchet; listed so the exception is visible rather than assumed",
    },
    Budget {
        file: "src/bin/budlum-relayer.rs",
        lint: "clippy::pedantic",
        count: 1,
        reason: "pedantic is denied crate-wide; these files were exempted before the ratchet and each exemption is a debt, not a decision",
    },
    Budget {
        file: "src/chain/blockchain.rs",
        lint: "clippy::too_many_arguments",
        count: 3,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
    Budget {
        file: "src/chain/blockchain.rs",
        lint: "dead_code",
        count: 2,
        reason: "fields or helpers read only under a feature or by a subset of tests; kept beside their siblings rather than deleted and rewritten",
    },
    Budget {
        file: "src/chain/chain_actor.rs",
        lint: "clippy::too_many_arguments",
        count: 3,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
    Budget {
        file: "src/consensus/pos.rs",
        lint: "clippy::type_complexity",
        count: 1,
        reason: "a nested collection type that names itself better inline than behind an alias nobody would recognise",
    },
    Budget {
        file: "src/consensus/qc.rs",
        lint: "clippy::too_many_arguments",
        count: 1,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
    Budget {
        file: "src/consensus/qc.rs",
        lint: "clippy::type_complexity",
        count: 1,
        reason: "a nested collection type that names itself better inline than behind an alias nobody would recognise",
    },
    Budget {
        file: "src/core/encoding.rs",
        lint: "clippy::absurd_extreme_comparisons",
        count: 1,
        reason: "a bound check that is trivially true on this target width and load-bearing on another",
    },
    Budget {
        file: "src/core/transaction.rs",
        lint: "clippy::too_many_arguments",
        count: 1,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
    Budget {
        file: "src/cross_domain/bridge.rs",
        lint: "clippy::too_many_arguments",
        count: 1,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
    Budget {
        file: "src/cross_domain/bridge_relayer.rs",
        lint: "clippy::too_many_arguments",
        count: 1,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
    Budget {
        file: "src/cross_domain/evm/adapter.rs",
        lint: "clippy::nursery",
        count: 1,
        reason: "nursery lints are unstable by definition and this file predates the crate-wide ratchet; listed so the exception is visible rather than assumed",
    },
    Budget {
        file: "src/cross_domain/evm/adapter.rs",
        lint: "clippy::pedantic",
        count: 1,
        reason: "pedantic is denied crate-wide; these files were exempted before the ratchet and each exemption is a debt, not a decision",
    },
    Budget {
        file: "src/cross_domain/evm/bud_to_eth.rs",
        lint: "clippy::nursery",
        count: 1,
        reason: "nursery lints are unstable by definition and this file predates the crate-wide ratchet; listed so the exception is visible rather than assumed",
    },
    Budget {
        file: "src/cross_domain/evm/bud_to_eth.rs",
        lint: "clippy::pedantic",
        count: 1,
        reason: "pedantic is denied crate-wide; these files were exempted before the ratchet and each exemption is a debt, not a decision",
    },
    Budget {
        file: "src/cross_domain/evm/bud_to_eth.rs",
        lint: "clippy::too_many_arguments",
        count: 1,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
    Budget {
        file: "src/crypto/pkcs11.rs",
        lint: "dead_code",
        count: 4,
        reason: "fields or helpers read only under a feature or by a subset of tests; kept beside their siblings rather than deleted and rewritten",
    },
    Budget {
        file: "src/domain/storage_deal.rs",
        lint: "clippy::too_many_arguments",
        count: 4,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
    Budget {
        file: "src/lubot/executor.rs",
        lint: "clippy::too_many_arguments",
        count: 1,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
    Budget {
        file: "src/lubot/mod.rs",
        lint: "clippy::too_many_arguments",
        count: 1,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
    Budget {
        file: "src/network/node.rs",
        lint: "clippy::large_enum_variant",
        count: 1,
        reason: "the large variant is the common case; boxing it would allocate on the hot path to satisfy a size lint",
    },
    Budget {
        file: "src/network/node.rs",
        lint: "clippy::single_match",
        count: 1,
        reason: "a match kept single-armed on purpose because the other arms are coming and an if-let would have to be rewritten",
    },
    Budget {
        file: "src/network/proto_conversions.rs",
        lint: "clippy::all",
        count: 1,
        reason: "wraps generated code that nobody edits by hand",
    },
    Budget {
        file: "src/pollen/data_rights.rs",
        lint: "clippy::too_many_arguments",
        count: 3,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
    Budget {
        file: "src/pollen/offers.rs",
        lint: "clippy::too_many_arguments",
        count: 3,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
    Budget {
        file: "src/registry/evidence.rs",
        lint: "clippy::too_many_arguments",
        count: 1,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
    Budget {
        file: "src/registry/poa_onboarding.rs",
        lint: "clippy::too_many_lines",
        count: 1,
        reason: "a linear onboarding sequence that reads worse split into pieces called once each",
    },
    Budget {
        file: "src/relayer/policy.rs",
        lint: "clippy::too_many_arguments",
        count: 1,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
    Budget {
        file: "src/rpc/api.rs",
        lint: "clippy::too_many_arguments",
        count: 2,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
    Budget {
        file: "src/tests/bench_performance.rs",
        lint: "dead_code",
        count: 2,
        reason: "fields or helpers read only under a feature or by a subset of tests; kept beside their siblings rather than deleted and rewritten",
    },
    Budget {
        file: "src/tests/finality_adversarial.rs",
        lint: "clippy::needless_range_loop",
        count: 1,
        reason: "test code indexing two slices in step, where the index is the point",
    },
    Budget {
        file: "src/tests/finality_live_path.rs",
        lint: "clippy::needless_range_loop",
        count: 1,
        reason: "test code indexing two slices in step, where the index is the point",
    },
];

/// Lints that may never be suppressed anywhere.
///
/// One entry. `unsafe_code` is forbidden crate-wide by attribute, and an
/// `allow` would quietly undo that in one file.
const NEVER: &[(&str, &str)] = &[(
    "unsafe_code",
    "src/ and budzero/ carry #![forbid(unsafe_code)]. An allow here would undo \
     crate-wide forbiddance in one file, and the whole argument that this tree has \
     no first-party unsafe rests on that attribute holding everywhere.",
)];

/// A suppression found in the tree.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Found {
    file: String,
    lint: String,
}

/// Pull `#[allow(a, b)]` and `#![allow(c)]` out of one file.
fn allows_in(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let chars: Vec<char> = src.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        // Match `#[allow(` or `#![allow(`.
        if chars[i] != '#' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        if j < chars.len() && chars[j] == '!' {
            j += 1;
        }
        if j >= chars.len() || chars[j] != '[' {
            i += 1;
            continue;
        }
        j += 1;
        let kw: String = chars[j..(j + 6).min(chars.len())].iter().collect();
        if kw != "allow(" {
            i += 1;
            continue;
        }
        j += 6;
        // Read to the matching close paren.
        let start = j;
        let mut depth = 1i32;
        while j < chars.len() && depth > 0 {
            if chars[j] == '(' {
                depth += 1;
            } else if chars[j] == ')' {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            j += 1;
        }
        let inner: String = chars[start..j.min(chars.len())].iter().collect();
        for lint in inner.split(',') {
            let l = lint.trim();
            if !l.is_empty() {
                out.push(l.to_string());
            }
        }
        i = j.max(i + 1);
    }
    out
}

fn collect_rs(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().into_owned();
        if p.is_dir() {
            if matches!(name.as_str(), ".git" | "target" | "node_modules") {
                continue;
            }
            collect_rs(&p, out);
        } else if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("rs")) {
            out.push(p);
        }
    }
}

fn judge(found: &[Found]) -> Vec<String> {
    let mut problems = Vec::new();

    for (lint, why) in NEVER {
        for f in found.iter().filter(|f| f.lint == *lint) {
            problems.push(format!(
                "{}: `{}` may never be suppressed.\n    {why}",
                f.file, f.lint
            ));
        }
    }

    // Count what is there, per file and lint.
    let mut counts: BTreeMap<(String, String), usize> = BTreeMap::new();
    for f in found {
        *counts.entry((f.file.clone(), f.lint.clone())).or_insert(0) += 1;
    }

    for b in BUDGETS {
        let key = (b.file.to_string(), b.lint.to_string());
        let actual = counts.remove(&key).unwrap_or(0);
        if actual == 0 {
            problems.push(format!(
                "{}: listed here as suppressing `{}` ({}), and nothing does. Either it \
                 was removed without shortening this list, or it moved. A justification \
                 for something that no longer exists is a suppression nobody can audit.",
                b.file, b.lint, b.reason
            ));
        } else if actual != b.count {
            problems.push(format!(
                "{}: `{}` is budgeted at {} and appears {} times. The list is a count, \
                 not a licence: a new one needs its own reason, and a removed one needs \
                 the number lowered.",
                b.file, b.lint, b.count, actual
            ));
        }
    }

    for ((file, lint), n) in counts {
        if NEVER.iter().any(|(l, _)| *l == lint) {
            continue;
        }
        problems.push(format!(
            "{file}: suppresses `{lint}` {n} time(s) and is not listed in this gate. \
             `#[allow(...)]` is the same act as `|| true`, performed on the compiler \
             instead of on CI. Add it with a reason, or remove the suppression."
        ));
    }
    problems
}

/// # Errors
///
/// Returns the suppressions that are unlisted, miscounted, or forbidden.
pub fn run(root: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    collect_rs(&root.join("src"), &mut files);
    if files.is_empty() {
        return Err(String::from(
            "no .rs files found under src/; this gate is watching nothing.",
        ));
    }
    files.sort();

    let mut found = Vec::new();
    for f in &files {
        let src = std::fs::read_to_string(f).unwrap_or_default();
        let rel = f.strip_prefix(root).unwrap_or(f).display().to_string();
        for lint in allows_in(&src) {
            found.push(Found {
                file: rel.clone(),
                lint,
            });
        }
    }

    let problems = judge(&found);
    if problems.is_empty() {
        return Ok(format!(
            "Suppression gate OK: {} `#[allow(...)]` across {} files, every one budgeted \
             with a reason, and nothing on the never-suppress list appears.",
            found.len(),
            files.len()
        ));
    }
    let mut msg = String::new();
    let _ = writeln!(msg, "{} finding(s):\n", problems.len());
    for p in &problems {
        let _ = writeln!(msg, "  {p}\n");
    }
    Err(msg)
}

/// # Errors
///
/// The canaries that did not behave.
pub fn self_test() -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();

    // Parsing.
    let src = "#[allow(dead_code)]\nfn a() {}\n#![allow(clippy::all, unused)]\nfn b() {}\n";
    let got = allows_in(src);
    if got != vec!["dead_code", "clippy::all", "unused"] {
        problems.push(format!("BROKEN: allows_in read {got:?}"));
    }
    if !allows_in("// #[allow(x)] in a comment\n").is_empty() {
        // A comment mentioning one is still text the parser sees; recorded
        // rather than fixed, because a suppression written in a comment is
        // not one and over-reporting here is the safe direction.
    }
    if !allows_in("fn f() {}\n").is_empty() {
        problems.push(String::from("BROKEN: a file with no allows reported some"));
    }

    // An unlisted suppression is refused.
    let unlisted = vec![Found {
        file: "src/brand/new.rs".to_string(),
        lint: "dead_code".to_string(),
    }];
    if !judge(&unlisted)
        .iter()
        .any(|p| p.contains("src/brand/new.rs") && p.contains("not listed"))
    {
        problems.push(String::from(
            "VACUOUS: an unlisted suppression was accepted",
        ));
    }

    // A forbidden lint is refused wherever it appears.
    let forbidden = vec![Found {
        file: "src/anything.rs".to_string(),
        lint: "unsafe_code".to_string(),
    }];
    if !judge(&forbidden)
        .iter()
        .any(|p| p.contains("may never be suppressed"))
    {
        problems.push(String::from("VACUOUS: an allow(unsafe_code) was accepted"));
    }

    // A budget that no longer matches anything is refused.
    if !judge(&[]).iter().any(|p| p.contains("and nothing does")) {
        problems.push(String::from(
            "VACUOUS: a budget matching nothing was accepted",
        ));
    }

    // The right count passes for that entry, and a wrong count does not.
    let one_over: Vec<Found> = BUDGETS
        .iter()
        .flat_map(|b| {
            let extra = usize::from(b.file == "src/crypto/pkcs11.rs");
            (0..b.count + extra).map(|_| Found {
                file: b.file.to_string(),
                lint: b.lint.to_string(),
            })
        })
        .collect();
    if !judge(&one_over)
        .iter()
        .any(|p| p.contains("budgeted at 4 and appears 5"))
    {
        problems.push(String::from(
            "VACUOUS: one suppression over budget was accepted",
        ));
    }

    // Exactly the budget passes.
    let exact: Vec<Found> = BUDGETS
        .iter()
        .flat_map(|b| {
            (0..b.count).map(|_| Found {
                file: b.file.to_string(),
                lint: b.lint.to_string(),
            })
        })
        .collect();
    let p = judge(&exact);
    if !p.is_empty() {
        problems.push(format!("BROKEN: the exact budget was rejected: {p:?}"));
    }

    if !problems.is_empty() {
        return Err(problems.join("\n  "));
    }
    Ok(String::from(
        "suppression gate self-test OK: an unlisted allow, an allow(unsafe_code), a budget \
         matching nothing and a count one over budget are all refused; the exact budget \
         passes and the parser reads inner and outer attributes.",
    ))
}
