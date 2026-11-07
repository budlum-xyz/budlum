//! Method coverage: every served JSON-RPC method is exercised by a named test
//! (directive WP-61 item 5, TEST-GAP-07).
//!
//! The finding is that the RPC surface was largely untested: a method could be
//! registered, classified and served with no test ever calling it, so a handler
//! that panicked, answered the wrong shape or silently accepted a bad argument
//! passed every gate. `method_class` already proves *that* a method exists and
//! which listener serves it; this module proves that each row is *exercised*.
//!
//! # The rule
//!
//! For every method name `M` in `api.rs` the test tree carries at least one test
//! named `<stem>_ok` (a success) and one named `<stem>_refused` (a refusal).
//! `<stem>` is `M` without the `bud_` prefix, lowercased and snake-cased:
//! `bud_getBlockByHash` -> `get_block_by_hash`, so `get_block_by_hash_ok` and
//! `get_block_by_hash_refused` cover it. A suffix is a whole word: `_okay` is
//! not `_ok`, and a longer method name is not covered by a shorter one.
//!
//! Naming is the coupling. Renaming a test away from its method breaks the
//! rule, which is the point: the link between a method and its coverage is
//! readable in one line of test output rather than asserted in a comment.
//!
//! # The baseline
//!
//! The tree does not yet carry the pair for every method. The exceptions are in
//! `.github/rpc-method-coverage-baseline.txt`, and there are two forms:
//!
//! ```text
//! bud_someMethod
//! bud_someRead | no-refusal: <why this method has no refusal arm>
//! ```
//!
//! * A bare line is placeholder debt: both tests may be missing. It is the
//!   form to burn down.
//! * A `no-refusal` line says the method has a success test and *cannot*
//!   refuse, so the refusal half is waived on purpose. The reason is required:
//!   a method that has a success test but no refusal test and no reason fails
//!   the gate, so a refusal that goes missing cannot be waived by silence.
//!
//! Either way the list only shrinks: a listed method that is covered now fails
//! the gate until its line is deleted, and a listed name that is not a method
//! in `api.rs` fails too. A one-directional ratchet is a to-do list nobody
//! reads (`dead-pub-api`, `idle-code` both learned this and both enforce the
//! same two directions).
//!
//! # Why the behavioural half is not generic
//!
//! A harness that invoked all 183 methods would have to fabricate an argument
//! for each, and a fabricated argument proves a handler does not panic, not
//! that it refuses the wrong input. The behaviour lives in the per-method tests
//! in `src/rpc/tests.rs`; this module holds the completeness half, so a new
//! method cannot be added without them.

#[cfg(test)]
mod rpc_method_coverage {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;

    /// The test-name suffixes that count as a refusal.
    const REFUSAL_SUFFIXES: &[&str] = &["_refused", "_rejected", "_invalid", "_error"];
    /// The test-name suffix that counts as a success.
    const SUCCESS_SUFFIX: &str = "_ok";
    /// The baseline reason prefix that waives the refusal half.
    const NO_REFUSAL: &str = "no-refusal:";

    /// The baseline file, relative to the repository root.
    const BASELINE: &str = ".github/rpc-method-coverage-baseline.txt";

    /// The `#[method(name = ...)]` and `#[subscription(name = ...)]` names of
    /// `api.rs`, in declaration order.
    fn declared_methods(api_source: &str) -> Vec<String> {
        let mut found: Vec<(usize, String)> = Vec::new();
        for needle in [
            "#[method(name = \"",
            "#[subscription(name = \"",
            "unsubscribe = \"",
        ] {
            for (at, _) in api_source.match_indices(needle) {
                let rest = &api_source[at + needle.len()..];
                let end = rest.find('"').expect("a method name is closed");
                found.push((at, rest[..end].to_string()));
            }
        }
        found.sort();
        found.into_iter().map(|(_, name)| name).collect()
    }

    /// The handler stem of a method name: `bud_getBlockByHash` ->
    /// `get_block_by_hash`. A name without the `bud_` prefix keeps its own
    /// lowercased spelling, so the rule is total.
    fn method_stem(method: &str) -> String {
        let bare = method.strip_prefix("bud_").unwrap_or(method);
        let mut out = String::with_capacity(bare.len() + 4);
        for (i, ch) in bare.char_indices() {
            if ch.is_ascii_uppercase() {
                if i != 0 {
                    out.push('_');
                }
                out.push(ch.to_ascii_lowercase());
            } else {
                out.push(ch);
            }
        }
        out
    }

    /// Whether `rest` (the part of a test name after the method stem) carries
    /// the suffix `suffix` as a whole word: exactly `suffix`, or `suffix`
    /// followed by `_` and a description.
    fn carries_suffix(rest: &str, suffix: &str) -> bool {
        rest == suffix
            || rest
                .strip_prefix(suffix)
                .is_some_and(|tail| tail.starts_with('_'))
    }

    /// Whether `test_name` is a success test for `stem`.
    fn is_success_for(test_name: &str, stem: &str) -> bool {
        test_name
            .strip_prefix(stem)
            .is_some_and(|rest| carries_suffix(rest, SUCCESS_SUFFIX))
    }

    /// Whether `test_name` is a refusal test for `stem`.
    fn is_refusal_for(test_name: &str, stem: &str) -> bool {
        test_name.strip_prefix(stem).is_some_and(|rest| {
            REFUSAL_SUFFIXES
                .iter()
                .any(|suffix| carries_suffix(rest, suffix))
        })
    }

    /// The test function names of every test region under `roots`.
    fn test_names(roots: &[&Path]) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        for root in roots {
            collect(root, &mut names);
        }
        names
    }

    fn collect(path: &Path, names: &mut BTreeSet<String>) {
        if path.is_dir() {
            let Ok(entries) = std::fs::read_dir(path) else {
                return;
            };
            let mut entries: Vec<_> = entries.flatten().collect();
            entries.sort_by_key(std::fs::DirEntry::file_name);
            for entry in entries {
                collect(&entry.path(), names);
            }
            return;
        }
        if path.extension().is_none_or(|e| e != "rs") {
            return;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            return;
        };
        // Every `fn name(` after the first `#[cfg(test)]` counts: a test may be
        // nested inside a module and `#[tokio::test]` has the same shape.
        let Some(cut) = text.find("#[cfg(test)]") else {
            return;
        };
        for line in text[cut..].lines() {
            let trimmed = line.trim_start();
            let rest = trimmed
                .strip_prefix("async fn ")
                .or_else(|| trimmed.strip_prefix("fn "));
            let Some(rest) = rest else {
                continue;
            };
            let Some(open) = rest.find('(') else {
                continue;
            };
            let name = rest[..open].trim();
            if !name.is_empty() {
                names.insert(name.to_string());
            }
        }
    }

    /// What a method is missing.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Gaps {
        success: bool,
        refusal: bool,
    }

    /// The gaps of every method that has at least one.
    fn gaps(methods: &[String], tests: &BTreeSet<String>) -> BTreeMap<String, Gaps> {
        let mut out = BTreeMap::new();
        for method in methods {
            let stem = method_stem(method);
            let success = tests.iter().any(|t| is_success_for(t, &stem));
            let refusal = tests.iter().any(|t| is_refusal_for(t, &stem));
            if !(success && refusal) {
                out.insert(method.clone(), Gaps { success, refusal });
            }
        }
        out
    }

    /// Parse the baseline: `name` -> `None`, or `name` -> `Some(reason)`.
    fn parse_baseline(text: &str) -> BTreeMap<String, Option<String>> {
        let mut out = BTreeMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match line.split_once('|') {
                Some((name, reason)) => {
                    out.insert(name.trim().to_string(), Some(reason.trim().to_string()));
                }
                None => {
                    out.insert(line.to_string(), None);
                }
            }
        }
        out
    }

    /// Compare coverage against the baseline.
    ///
    /// # Errors
    ///
    /// Every deviation, one line each: a gap outside the baseline, a refusal
    /// that went missing behind a bare baseline line, a stale entry, or an
    /// entry that names no method.
    fn compare(
        methods: &[String],
        tests: &BTreeSet<String>,
        baseline: &BTreeMap<String, Option<String>>,
    ) -> Result<(), String> {
        let missing = gaps(methods, tests);
        let mut problems = Vec::new();
        for (method, gap) in &missing {
            let stem = method_stem(method);
            match baseline.get(method) {
                None => problems.push(format!(
                    "{method} has no {} test (expected `{stem}_ok` and `{stem}_refused`)",
                    match (gap.success, gap.refusal) {
                        (false, false) => "success and refusal",
                        (false, true) => "success",
                        (true, false) => "refusal",
                        (true, true) => unreachable!("a full gap is not in the map"),
                    }
                )),
                Some(None) => {
                    // A bare entry is placeholder debt and waives both halves.
                }
                Some(Some(reason)) => {
                    // A reasoned entry waives the refusal only, and only when
                    // it says so. A success test is still mandatory.
                    if !reason.starts_with(NO_REFUSAL) {
                        problems.push(format!(
                            "{method} is listed with the reason `{reason}`, which is not a `{NO_REFUSAL}` waiver"
                        ));
                    }
                    if !gap.success {
                        problems.push(format!(
                            "{method} is listed as having no refusal arm but has no success test either; add `{stem}_ok`"
                        ));
                    }
                }
            }
        }
        for (method, reason) in baseline {
            if !methods.contains(method) {
                problems.push(format!(
                    "{method} is listed in {BASELINE} but is not a method in api.rs"
                ));
                continue;
            }
            if !missing.contains_key(method) {
                problems.push(format!(
                    "{method} is listed in {BASELINE} but is covered now; delete its line"
                ));
                continue;
            }
            if reason.is_none() && missing.get(method).is_some_and(|gap| gap.success) {
                problems.push(format!(
                    "{method} has a success test and no refusal test; give it `{}` or a `{NO_REFUSAL}` reason",
                    format!("{}_refused", method_stem(method))
                ));
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            problems.sort();
            problems.dedup();
            Err(problems.join("\n"))
        }
    }

    #[test]
    fn the_stem_is_the_snake_cased_method_name() {
        assert_eq!(method_stem("bud_getBlockByHash"), "get_block_by_hash");
        assert_eq!(method_stem("bud_chainId"), "chain_id");
        assert_eq!(method_stem("bud_aiGetModel"), "ai_get_model");
        assert_eq!(method_stem("bud_subscribe"), "subscribe");
        assert_eq!(method_stem("noPrefix"), "no_prefix");
    }

    #[test]
    fn the_suffix_rule_accepts_only_whole_word_endings() {
        assert!(is_success_for("get_nonce_ok", "get_nonce"));
        assert!(is_success_for("get_nonce_ok_reports_the_value", "get_nonce"));
        assert!(!is_success_for("get_nonce_okay", "get_nonce"));
        assert!(is_refusal_for("get_nonce_refused", "get_nonce"));
        assert!(is_refusal_for("get_nonce_refused_on_a_bad_address", "get_nonce"));
        assert!(is_refusal_for("get_nonce_invalid", "get_nonce"));
        // A test named after the method but asserting neither half covers
        // nothing: this is the shape that would otherwise pass silently.
        assert!(!is_success_for("get_nonce_reports_the_value", "get_nonce"));
        assert!(!is_refusal_for("get_nonce_reports_the_value", "get_nonce"));
        // A longer method name is not covered by a shorter one's test.
        assert!(!is_success_for("get_nonce_ok", "get_nonce_by_hash"));
    }

    #[test]
    fn the_completeness_rule_catches_a_missing_half() {
        let methods = vec![
            "bud_alpha".to_string(),
            "bud_beta".to_string(),
            "bud_gamma".to_string(),
        ];
        let tests: BTreeSet<String> = ["alpha_ok", "alpha_refused", "beta_ok"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let missing = gaps(&methods, &tests);
        assert_eq!(
            missing.get("bud_beta"),
            Some(&Gaps {
                success: true,
                refusal: false
            })
        );
        assert_eq!(
            missing.get("bud_gamma"),
            Some(&Gaps {
                success: false,
                refusal: false
            })
        );
        assert!(!missing.contains_key("bud_alpha"));
    }

    #[test]
    fn a_bare_entry_cannot_waive_a_refusal_that_has_a_success_test() {
        let methods = vec!["bud_alpha".to_string()];
        let tests: BTreeSet<String> = ["alpha_ok"].into_iter().map(str::to_string).collect();

        let bare: BTreeMap<String, Option<String>> =
            [("bud_alpha".to_string(), None)].into_iter().collect();
        let err = compare(&methods, &tests, &bare).expect_err("a bare entry is too weak here");
        assert!(err.contains("has a success test and no refusal test"), "{err}");

        let reasoned: BTreeMap<String, Option<String>> = [(
            "bud_alpha".to_string(),
            Some(format!("{NO_REFUSAL} the read cannot fail")),
        )]
        .into_iter()
        .collect();
        assert!(compare(&methods, &tests, &reasoned).is_ok());

        let wrong_reason: BTreeMap<String, Option<String>> =
            [("bud_alpha".to_string(), Some("covered later".to_string()))]
                .into_iter()
                .collect();
        assert!(compare(&methods, &tests, &wrong_reason).is_err());
    }

    #[test]
    fn a_stale_entry_and_an_unknown_name_are_refused() {
        let methods = vec!["bud_alpha".to_string(), "bud_beta".to_string()];
        let tests: BTreeSet<String> = ["alpha_ok", "alpha_refused"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let baseline: BTreeMap<String, Option<String>> = [
            ("bud_alpha".to_string(), None),
            ("bud_gone".to_string(), None),
        ]
        .into_iter()
        .collect();
        let err = compare(&methods, &tests, &baseline).expect_err("both entries are wrong");
        assert!(err.contains("bud_alpha is listed in"), "{err}");
        assert!(err.contains("bud_gone is listed in"), "{err}");
        assert!(err.contains("bud_beta"), "{err}");

        let good: BTreeMap<String, Option<String>> =
            [("bud_beta".to_string(), None)].into_iter().collect();
        assert!(compare(&methods, &tests, &good).is_ok());
    }

    /// The real rule over the real tree. This is the gate.
    #[test]
    fn rpc_every_method_has_success_and_refusal_test() {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
        let methods = declared_methods(include_str!("api.rs"));
        assert!(
            methods.len() > 100,
            "the scan found {} methods in api.rs; it is reading the wrong text",
            methods.len()
        );
        let tests = test_names(&[&repository.join("src/rpc"), &repository.join("src/tests")]);
        assert!(
            tests.len() > 100,
            "the scan found {} test names; it is reading the wrong text",
            tests.len()
        );
        let baseline_path = repository.join(BASELINE);
        let text = std::fs::read_to_string(&baseline_path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", baseline_path.display()));
        let baseline = parse_baseline(&text);
        if let Err(problems) = compare(&methods, &tests, &baseline) {
            panic!(
                "RPC method coverage gap (TEST-GAP-07):\n{problems}\n\
                 Add the named pair in src/rpc/tests.rs and delete the method's line from {BASELINE}."
            );
        }
    }

    /// The baseline the gate reads is the one in the tree, and it is an
    /// exception list rather than a copy of the surface.
    #[test]
    fn the_coverage_baseline_is_present_and_shrinking() {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
        let text = std::fs::read_to_string(repository.join(BASELINE)).expect("baseline file");
        assert!(
            text.contains("rpc-method-coverage"),
            "the baseline file must name its rule"
        );
        let baseline = parse_baseline(&text);
        let methods = declared_methods(include_str!("api.rs"));
        assert!(
            baseline.len() < methods.len(),
            "the baseline lists {} of {} methods; it is a shrinking exception list, not a copy",
            baseline.len(),
            methods.len()
        );
        for (method, reason) in &baseline {
            let stem = method_stem(method);
            assert!(
                !stem.is_empty() && stem.chars().all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
                "{method} does not reduce to a valid test-name stem"
            );
            if let Some(reason) = reason {
                assert!(
                    reason.starts_with(NO_REFUSAL),
                    "{method}: a reason must start with `{NO_REFUSAL}`"
                );
            }
        }
    }
}
