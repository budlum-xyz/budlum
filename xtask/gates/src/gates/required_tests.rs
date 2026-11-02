//! Every name a Rust gate requires must really be a `#[test]`.
//!
//! The required-test lists used to live in `required_tests=(...)` arrays of
//! shell gates; this gate read `ops/scripts/check-*.sh` for them. Those
//! scripts are gone, so the gate had nothing to read and returned OK without
//! checking one name. The lists now live in the `TESTS` constants of the Rust
//! gates that read a cargo test log (`named_tests`, `exact_named_tests`), and
//! this gate checks those lists directly: a name in a list that no
//! `#[test]` function carries is a gate describing a test the tree does not
//! have, and the log check can then never be satisfied or, worse, be
//! satisfied by a lookalike.
//!
//! A name counts when exactly one function of that name exists in the tree,
//! it carries `#[test]` or `#[tokio::test(..)]`, and no `#[ignore]`
//! attribute sits in the same attribute block. A name written as a module
//! path (`tests::bns::tests::name`) must also live in a file whose path
//! carries those modules.

use std::fmt::Write as _;
use std::path::Path;

/// The gate modules that carry a required-test list, with the list.
fn registry() -> Vec<(&'static str, &'static [&'static str])> {
    vec![
        ("bns", super::bns_gate::TESTS),
        ("bud-e2e", super::bud_e2e::TESTS),
        ("economy-invariants", super::economy_invariants::TESTS),
        ("fork-choice", super::fork_choice_gate::TESTS),
        ("governance-invariants", super::governance_invariants::TESTS),
        ("network-hardening", super::network_hardening_gate::TESTS),
        (
            "node-classification",
            super::node_classification_gate::TESTS,
        ),
        ("poa-compliance", super::poa_compliance_gate::TESTS),
        ("pq-core", super::pq_core_gate::TESTS),
        ("storage-provider", super::storage_provider_gate::TESTS),
        ("wallet-core", super::wallet_core_gate::TESTS),
    ]
}

/// One `fn` definition found in the tree.
struct FnDef {
    /// Repository-relative path of the file.
    file: String,
    name: String,
    /// `#[test]` or `#[tokio::test]` present in the attribute block.
    is_test: bool,
    /// `#[ignore]` present in the attribute block.
    ignored: bool,
}

/// The name after `fn ` on a line, if the line defines a function.
fn fn_name(line: &str) -> Option<String> {
    let pos = line.find("fn ")?;
    // `fn` must start a word: `pub fn`, `async fn`, line start, or `{ fn`.
    let before = line[..pos].chars().next_back();
    if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let name: String = line[pos + 3..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

fn is_test_attr(t: &str) -> bool {
    t.starts_with("#[test]") || t.starts_with("#[tokio::test")
}

/// Every function definition under `root` with its attribute facts.
///
/// Attributes are the contiguous lines above the `fn` that start with `#[`,
/// plus any on the same line; doc comments and blank comment lines between
/// them are skipped.
fn collect_fns(root: &Path) -> Result<Vec<FnDef>, String> {
    let mut out = Vec::new();
    let mut stack: Vec<std::path::PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd = std::fs::read_dir(&dir)
            .map_err(|e| format!("required-tests: cannot read {}: {e}", dir.display()))?;
        for e in rd.filter_map(Result::ok) {
            let path = e.path();
            let kind = e
                .file_type()
                .map_err(|err| format!("required-tests: cannot stat {}: {err}", path.display()))?;
            let name = e.file_name().to_string_lossy().into_owned();
            if kind.is_dir() {
                if name != "target" && name != ".git" && name != "node_modules" {
                    stack.push(path);
                }
                continue;
            }
            if path.extension().is_none_or(|x| x != "rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path)
                .map_err(|err| format!("required-tests: cannot read {}: {err}", path.display()))?;
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let lines: Vec<&str> = text.lines().collect();
            for (i, l) in lines.iter().enumerate() {
                let Some(fname) = fn_name(l) else {
                    continue;
                };
                let mut is_test = false;
                let mut ignored = false;
                // Attributes on the same line, before the `fn`.
                let head = &l[..l.find("fn ").unwrap_or(0)];
                for part in head.split("#[").skip(1) {
                    let attr = format!("#[{part}");
                    is_test |= is_test_attr(&attr);
                    ignored |= attr.starts_with("#[ignore");
                }
                // The attribute block above.
                let mut j = i;
                while j > 0 {
                    j -= 1;
                    let t = lines[j].trim();
                    if t.starts_with("#[") {
                        is_test |= is_test_attr(t);
                        ignored |= t.starts_with("#[ignore");
                    } else if !t.starts_with("//") {
                        break;
                    }
                }
                out.push(FnDef {
                    file: rel.clone(),
                    name: fname,
                    is_test,
                    ignored,
                });
            }
        }
    }
    Ok(out)
}

/// Does the file path carry the module path (minus inline test modules and
/// the function name)?
fn file_carries_modules(file: &str, modules: &[&str]) -> bool {
    let comps: Vec<String> = file
        .trim_end_matches(".rs")
        .split('/')
        .map(str::to_string)
        .collect();
    modules
        .iter()
        .filter(|m| **m != "tests" || modules.len() == 1)
        .all(|m| comps.iter().any(|c| c == m))
        // A bare leading `tests` is a real directory in this tree.
        && (modules.first() != Some(&"tests") || comps.iter().any(|c| c == "tests"))
}

/// Check one gate's list; returns the problems.
fn check_list(gate: &str, names: &[&str], defs: &[FnDef]) -> Vec<String> {
    let mut problems = Vec::new();
    if names.is_empty() {
        problems.push(format!("{gate}: the required-test list is empty"));
    }
    for full in names {
        let mut segs: Vec<&str> = full.split("::").collect();
        let Some(name) = segs.pop() else {
            continue;
        };
        let found: Vec<&FnDef> = defs.iter().filter(|d| d.name == name).collect();
        let tests: Vec<&&FnDef> = found.iter().filter(|d| d.is_test && !d.ignored).collect();
        let in_scope: Vec<&&&FnDef> = tests
            .iter()
            .filter(|d| segs.is_empty() || file_carries_modules(&d.file, &segs))
            .collect();
        if found.is_empty() {
            problems.push(format!("{gate}: `{full}` has no function in the tree"));
        } else if found.iter().any(|d| d.ignored) {
            problems.push(format!("{gate}: `{full}` carries #[ignore]"));
        } else if tests.is_empty() {
            problems.push(format!(
                "{gate}: `{full}` exists but carries no #[test] attribute"
            ));
        } else if in_scope.is_empty() {
            problems.push(format!(
                "{gate}: `{full}` is a test, but not in a file under the module path it names"
            ));
        } else if found.len() != 1 {
            problems.push(format!(
                "{gate}: `{full}` is defined {} times; a log line cannot say which one ran",
                found.len()
            ));
        }
    }
    problems
}

/// # Errors
///
/// Returns a finding per required name that is not a real test.
pub fn run(root: &Path) -> Result<String, String> {
    let defs = collect_fns(root)?;
    if !defs.iter().any(|d| d.is_test) {
        return Err(format!(
            "no #[test] functions found under {} - wrong root?",
            root.display()
        ));
    }
    let mut total = 0usize;
    let mut all: Vec<String> = Vec::new();
    let reg = registry();
    for (gate, names) in &reg {
        total += names.len();
        all.extend(check_list(gate, names, &defs));
    }
    if !all.is_empty() {
        let mut msg = String::from("FAIL: required tests that are not tests:\n");
        for p in &all {
            writeln!(msg, "  - {p}").expect("writing to a String cannot fail");
        }
        msg.push_str(
            "\nA name in a gate's TESTS list that carries no #[test] attribute is a\n\
             gate describing a test the tree does not have. Restore the attribute,\n\
             or remove the name and say why in the same commit.",
        );
        return Err(msg);
    }
    Ok(format!(
        "Required-test gate OK: {total} required names across {} gates all carry #[test].",
        reg.len()
    ))
}

/// # Errors
///
/// Returns a finding when a required name that is not a test passes.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-rtt")?;
    let write = |rel: &str, body: &str| -> Result<(), String> {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(p, body).map_err(|e| e.to_string())
    };
    let check = |names: &[&str]| -> Result<Vec<String>, String> {
        let defs = collect_fns(&dir)?;
        Ok(check_list("fixture", names, &defs))
    };
    let fail = |msg: &str| -> Result<String, String> {
        let _ = std::fs::remove_dir_all(&dir);
        Err(format!("required-tests canary: {msg}"))
    };

    write("src/lib.rs", "#[test]\nfn a_real_test() {}\n")?;
    if !check(&["a_real_test"])?.is_empty() {
        return fail("a correct tree was refused");
    }
    write("src/lib.rs", "fn a_real_test() {}\n")?;
    if check(&["a_real_test"])?.is_empty() {
        return fail("a name carrying no #[test] passed");
    }
    write("src/lib.rs", "#[test]\n#[ignore]\nfn a_real_test() {}\n")?;
    if check(&["a_real_test"])?.is_empty() {
        return fail("an #[ignore]d test passed");
    }
    write("src/lib.rs", "#[ignore]\n#[test]\nfn a_real_test() {}\n")?;
    if check(&["a_real_test"])?.is_empty() {
        return fail("an #[ignore] above #[test] passed");
    }
    write(
        "src/lib.rs",
        "#[tokio::test(flavor = \"multi_thread\")]\nasync fn a_real_test() {}\n",
    )?;
    if !check(&["a_real_test"])?.is_empty() {
        return fail("a #[tokio::test(..)] test was refused");
    }
    write("src/lib.rs", "#[test] fn a_real_test() {}\n")?;
    if !check(&["a_real_test"])?.is_empty() {
        return fail("a one-line #[test] fn was refused");
    }
    write("src/lib.rs", "// #[test]\nfn a_real_test() {}\n")?;
    if check(&["a_real_test"])?.is_empty() {
        return fail("a commented-out #[test] passed");
    }
    write(
        "src/lib.rs",
        "#[test]\nfn a_real_test() {}\nfn other() {}\nmod m { fn a_real_test() {} }\n",
    )?;
    if check(&["a_real_test"])?.is_empty() {
        return fail("a name defined twice passed");
    }
    // A module path must be carried by the file path.
    let _ = std::fs::remove_file(dir.join("src/lib.rs"));
    write("src/tests/bns.rs", "#[test]\nfn t_one() {}\n")?;
    if !check(&["tests::bns::tests::t_one"])?.is_empty() {
        return fail("a test under its module path was refused");
    }
    if check(&["tests::other::tests::t_one"])?.is_empty() {
        return fail("a test outside the module path it names passed");
    }
    if check(&["missing_everywhere"])?.is_empty() {
        return fail("a name with no function passed");
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "required-tests canary OK: a #[test] passes; a missing attribute, #[ignore], a \
         commented-out attribute, a duplicate name and a wrong module path each FAIL.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_test_passes() {
        super::self_test().expect("required-tests self-test");
    }
}
