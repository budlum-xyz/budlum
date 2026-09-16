//! One house rule: siblings that do the same job must run the same checks.
//!
//! The audit report's dominant finding class (7 of 12 findings) was not a
//! wrong check but a **missing sibling**: the mint path validated the fee
//! ceiling while the unlock path narrowed it with a cast (F-8), two of the
//! three Merkle implementations promoted an odd tail while the third
//! duplicated it (F-6), one fork-choice family resolved equal-weight ties
//! while its siblings refused the reorg in both directions (F-2). Every
//! one of those is a set of functions that do the same job, where one of
//! them stopped carrying a guard its siblings still carry.
//!
//! This gate makes that class a config entry instead of an audit finding.
//! A *family* is a set of code slices that do the same job (a function
//! body, a match arm - any brace-balanced slice rooted at a needle). A
//! *guard* is a mark every member of the family must carry. The gate
//! extracts each member's body, checks every guard against every member,
//! and refuses when a guard is present in some siblings and absent from
//! others - the exact shape the findings came in. A guard that is absent
//! everywhere is not a finding (it may simply have been replaced by a
//! better check); the asymmetry is.

use std::path::Path;

/// One member of a family: a name for the report and a needle that roots
/// a brace-balanced slice in `file`.
struct Sibling {
    name: &'static str,
    file: &'static str,
    start: &'static str,
}

/// A mark every member of a family must carry once it is carried by any.
///
/// Alternative needles count as carrying the same duty: a sibling can
/// reach the one primitive through a delegation instead of naming it.
struct Guard {
    name: &'static str,
    needles: &'static [&'static str],
}

/// A set of siblings that do the same job, and the guards they must share.
struct Family {
    name: &'static str,
    why: &'static str,
    siblings: &'static [Sibling],
    guards: &'static [Guard],
}

const FAMILIES: &[Family] = &[
    Family {
        name: "bridge-mint",
        why: "every path that mints a bridge transfer must take the same fee split, \
              the same supply ceiling and the same mint",
        siblings: &[
            Sibling {
                name: "executor-bridge-mint",
                file: "src/execution/executor.rs",
                start: "MessageKind::BridgeLock => {",
            },
            Sibling {
                name: "blockchain-verified-mint",
                file: "src/chain/blockchain.rs",
                start: "pub fn mint_bridge_transfer_from_verified_event(",
            },
            Sibling {
                name: "blockchain-relay-mint",
                file: "src/chain/blockchain.rs",
                start: "MessageKind::BridgeLock => {",
            },
        ],
        guards: &[
            Guard {
                name: "fee split",
                needles: &["split_bridge_fee("],
            },
            Guard {
                name: "supply ceiling",
                needles: &["ensure_mint_headroom"],
            },
            Guard {
                name: "bridge-state mint",
                needles: &[".mint("],
            },
            Guard {
                name: "ceiling-bound credit",
                needles: &["try_mint_balance"],
            },
        ],
    },
    Family {
        name: "bridge-unlock",
        why: "every path that unlocks a burned bridge transfer must run the same \
              domain check, the same fee split and the same refund",
        siblings: &[
            Sibling {
                name: "executor-bridge-unlock",
                file: "src/execution/executor.rs",
                start: "MessageKind::BridgeBurn => {",
            },
            Sibling {
                name: "blockchain-relay-unlock",
                file: "src/chain/blockchain.rs",
                start: "MessageKind::BridgeBurn => {",
            },
        ],
        guards: &[
            Guard {
                name: "burn-domain rule",
                needles: &["check_burn_matches_lock_domain"],
            },
            Guard {
                name: "bridge-state unlock",
                needles: &[".unlock("],
            },
            Guard {
                name: "fee split",
                needles: &["split_bridge_fee("],
            },
            Guard {
                name: "overflow-checked refund",
                needles: &["try_add_balance"],
            },
        ],
    },
    Family {
        name: "merkle-delegation",
        why: "every committed Merkle root and proof must come from the one tree \
              primitive, not from a private re-implementation of the shape",
        siblings: &[
            Sibling {
                name: "settlement-root",
                file: "src/settlement/commitment_tree.rs",
                start: "pub fn merkle_root(",
            },
            Sibling {
                name: "event-root",
                file: "src/cross_domain/event_tree.rs",
                start: "pub fn root(&self) -> Hash32 {",
            },
            Sibling {
                name: "event-proof",
                file: "src/cross_domain/event_tree.rs",
                start: "pub fn proof(&self, index: usize) -> Option<MerkleProof> {",
            },
            Sibling {
                name: "event-verify",
                file: "src/cross_domain/event_tree.rs",
                start: "pub fn verify(&self, expected_root: Hash32) -> bool {",
            },
            Sibling {
                name: "qc-root",
                file: "src/consensus/qc.rs",
                start: "pub fn compute_merkle_root(",
            },
        ],
        guards: &[Guard {
            name: "shared primitive",
            needles: &["merkle_tree::", "commitment_tree::merkle_root"],
        }],
    },
    Family {
        name: "merkle-promote",
        why: "every binding into the tree primitive must name a promotion function: \
              an unpaired tail is promoted under its own domain, never paired \
              with itself",
        siblings: &[
            Sibling {
                name: "settlement-binding",
                file: "src/settlement/commitment_tree.rs",
                start: "pub fn merkle_root(",
            },
            Sibling {
                name: "event-proof-binding",
                file: "src/cross_domain/event_tree.rs",
                start: "pub fn proof(&self, index: usize) -> Option<MerkleProof> {",
            },
            Sibling {
                name: "event-verify-binding",
                file: "src/cross_domain/event_tree.rs",
                start: "pub fn verify(&self, expected_root: Hash32) -> bool {",
            },
            Sibling {
                name: "qc-binding",
                file: "src/consensus/qc.rs",
                start: "pub fn compute_merkle_root(",
            },
        ],
        guards: &[Guard {
            name: "promotion binding",
            needles: &["promote"],
        }],
    },
    Family {
        name: "fork-choice-tie",
        why: "every consensus family must resolve an equal-weight tie through the \
              deterministic resolver; a strict comparison in one of them is a \
              permanent fork out of honest behaviour",
        siblings: &[
            Sibling {
                name: "pow",
                file: "src/consensus/pow.rs",
                start:
                    "fn is_better_chain(&self, current: &[Block], candidate: &[Block]) -> bool {",
            },
            Sibling {
                name: "poa",
                file: "src/consensus/poa.rs",
                start:
                    "fn is_better_chain(&self, current: &[Block], candidate: &[Block]) -> bool {",
            },
            Sibling {
                name: "pos",
                file: "src/consensus/pos.rs",
                start:
                    "fn is_better_chain(&self, current: &[Block], candidate: &[Block]) -> bool {",
            },
        ],
        guards: &[
            Guard {
                name: "tie resolver",
                needles: &["resolve_split_tie"],
            },
            Guard {
                name: "candidate ordering",
                needles: &["SplitCandidate"],
            },
            Guard {
                name: "decision",
                needles: &["SplitDecision"],
            },
        ],
    },
];

/// The brace-balanced slice rooted at the first `{` at or after `start`.
///
/// Balancing is a plain depth count over the bytes. Braces inside string
/// literals are not treated specially; every brace this codebase puts in
/// a message is balanced (`{e}`-style), and the slice a mismatch would
/// produce fails the family check loudly rather than silently.
fn body_of(src: &str, start: &str, sibling: &str) -> Result<String, String> {
    let i = src
        .find(start)
        .ok_or_else(|| format!("one-house-guards: sibling {sibling}: needle not found: {start}"))?;
    let rest = &src[i..];
    let open = rest
        .find('{')
        .ok_or_else(|| format!("one-house-guards: sibling {sibling}: no brace after needle"))?;
    let mut depth = 0usize;
    for (off, b) in rest[open..].bytes().enumerate() {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1).ok_or_else(|| {
                    format!("one-house-guards: sibling {sibling}: unbalanced body")
                })?;
                if depth == 0 {
                    return Ok(rest[open..=open + off].to_string());
                }
            }
            _ => {}
        }
    }
    Err(format!(
        "one-house-guards: sibling {sibling}: body never closes"
    ))
}

/// The siblings that carry `guard` and the ones that do not.
fn guard_split<'a>(bodies: &[(&'a str, String)], needles: &[&str]) -> (Vec<&'a str>, Vec<&'a str>) {
    let mut with = Vec::new();
    let mut without = Vec::new();
    for (name, body) in bodies {
        if needles.iter().any(|needle| body.contains(needle)) {
            with.push(*name);
        } else {
            without.push(*name);
        }
    }
    (with, without)
}

/// Check one family: every guard must be carried by either all siblings or
/// none of them.
fn check_family(root: &Path, family: &Family) -> Result<(), String> {
    let mut bodies = Vec::new();
    for sibling in family.siblings {
        let path = root.join(sibling.file);
        let src = std::fs::read_to_string(&path)
            .map_err(|e| format!("one-house-guards: {}: {e}", sibling.file))?;
        bodies.push((sibling.name, body_of(&src, sibling.start, sibling.name)?));
    }
    for guard in family.guards {
        let (with, without) = guard_split(&bodies, guard.needles);
        if with.is_empty() {
            // Absent everywhere: not an asymmetry. Either the check was
            // replaced everywhere or the family needs new guards; both are
            // review decisions, not this gate's refusal.
            continue;
        }
        if !without.is_empty() {
            return Err(format!(
                "one-house-guards [{}] guard '{}' ({}) is carried by [{}] but missing from [{}]: {}",
                family.name,
                guard.name,
                guard.needles.join(" or "),
                with.join(", "),
                without.join(", "),
                family.why
            ));
        }
    }
    Ok(())
}

/// # Errors
///
/// Returns a finding when a guard is asymmetric across a family's
/// siblings, or when a sibling's slice cannot be extracted.
pub fn run(root: &Path) -> Result<String, String> {
    for family in FAMILIES {
        check_family(root, family)?;
    }
    Ok(String::from(
        "One house rule OK: 5 families checked (bridge-mint, bridge-unlock, \
         merkle-delegation, merkle-promote, fork-choice-tie); every guard \
         each sibling once carried is carried by all of them.",
    ))
}

/// # Errors
///
/// Returns a finding when the gate accepts a broken copy of the real tree.
pub fn self_test() -> Result<String, String> {
    let root = std::env::var_os("BUDLUM_ROOT").map_or_else(
        || std::env::current_dir().unwrap_or_default(),
        std::path::PathBuf::from,
    );
    if !root.join("src/execution/executor.rs").is_file() {
        return Err(String::from(
            "canary: real tree not found (run from the repo root)",
        ));
    }
    let tmp = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-ohg")?;
    let files = [
        "src/execution/executor.rs",
        "src/chain/blockchain.rs",
        "src/consensus/pow.rs",
        "src/consensus/poa.rs",
        "src/consensus/pos.rs",
        "src/settlement/commitment_tree.rs",
        "src/cross_domain/event_tree.rs",
        "src/consensus/qc.rs",
    ];
    for rel in files {
        if let Some(dir) = std::path::Path::new(rel).parent() {
            std::fs::create_dir_all(tmp.join(dir)).map_err(|e| e.to_string())?;
        }
        std::fs::copy(root.join(rel), tmp.join(rel)).map_err(|e| e.to_string())?;
    }
    if run(&tmp).is_err() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from("canary: an unmodified copy was refused"));
    }

    // Break 1: the mint family loses its supply ceiling in one sibling.
    let rel = "src/chain/blockchain.rs";
    let text = std::fs::read_to_string(tmp.join(rel)).map_err(|e| e.to_string())?;
    std::fs::write(
        tmp.join(rel),
        // The replacement must not contain the original needle: the gate scans
        // text, so a `_gone` suffix would still "carry" the guard.
        text.replace("ensure_mint_headroom", "no_headroom_check"),
    )
    .map_err(|e| e.to_string())?;
    let refused = run(&tmp).is_err();
    std::fs::copy(root.join(rel), tmp.join(rel)).map_err(|e| e.to_string())?;
    if !refused {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: a mint sibling that dropped the supply ceiling passed",
        ));
    }

    // Break 2: one fork-choice family stops resolving equal-weight ties.
    let rel = "src/consensus/poa.rs";
    let text = std::fs::read_to_string(tmp.join(rel)).map_err(|e| e.to_string())?;
    std::fs::write(
        tmp.join(rel),
        text.replace("resolve_split_tie", "tie_check_gone"),
    )
    .map_err(|e| e.to_string())?;
    let refused = run(&tmp).is_err();
    std::fs::copy(root.join(rel), tmp.join(rel)).map_err(|e| e.to_string())?;
    if !refused {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: a fork-choice sibling without the tie resolver passed",
        ));
    }

    let _ = std::fs::remove_dir_all(&tmp);
    Ok(String::from(
        "one-house-guards canary OK (clean PASSes, broken FAILs).",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_of_extracts_a_function_body() {
        let src = "prelude\nfn f(a: u64) -> u64 {\n    let x = a + 1;\n    x\n}\ntail\n";
        let body = body_of(src, "fn f(", "t").expect("extracts");
        assert!(body.starts_with('{'));
        assert!(body.contains("let x = a + 1;"));
        assert!(body.trim_end().ends_with('}'));
    }

    #[test]
    fn body_of_extracts_a_match_arm_with_nested_blocks() {
        let src = "match k {\n    Kind::A => {\n        if a { b(); }\n    }\n    _ => {}\n}\n";
        let body = body_of(src, "Kind::A => {", "t").expect("extracts");
        assert!(body.contains("if a { b(); }"));
        assert!(!body.contains("_ =>"));
    }

    #[test]
    fn body_of_survives_balanced_braces_in_strings() {
        let src = "fn g() {\n    let m = format!(\"{e} and {{x}}\");\n}\n";
        let body = body_of(src, "fn g()", "t").expect("extracts");
        assert!(body.contains("{e}"));
    }

    #[test]
    fn body_of_refuses_a_missing_needle() {
        assert!(body_of("fn h() {}", "fn missing(", "t").is_err());
    }

    #[test]
    fn guard_split_names_both_sides() {
        let bodies = vec![
            ("a", String::from("has the mark")),
            ("b", String::from("has the mark too")),
            ("c", String::from("does not")),
        ];
        let (with, without) = guard_split(&bodies, &["mark"]);
        assert_eq!(with, vec!["a", "b"]);
        assert_eq!(without, vec!["c"]);
    }
}
