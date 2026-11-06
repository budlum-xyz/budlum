//! Two packages may not write one file, and `src/storage/bud3/mod.rs` is
//! where that rule is checkable.
//!
//! # The failure this closes, measured on the live pull request queue
//!
//! Directive section 15.3 item 3 gives an open package's lock paths to that
//! package alone, and section 15.5 requires one package per pull request. Both
//! are process rules, and both were violated in the open queue while this gate
//! was written:
//!
//! * `src/storage/bud3/volume.rs` is claimed by three open pull requests
//!   (WP-19 #55, WP-21 #57, and #45), each of which adds
//!   `pub mod volume;` to `mod.rs`.
//! * `src/storage/bud3/content_ref.rs` is claimed by two (WP-07 #69, #45).
//!
//! Neither collision fails a build. Each of the three patches applies
//! cleanly to `main`; the second one to merge either wins silently or
//! conflicts in a single line of `mod.rs` that any resolution will "fix" by
//! keeping both. The resulting tree then has two files claiming one module
//! name, or one file written by two packages that disagreed about what it
//! means - and the disagreement is discovered by a reader, months later, not
//! by CI.
//!
//! # What is checked here, and why it is checkable at all
//!
//! This gate reads the tree, not the pull requests: a gate that asked GitHub
//! what is open would need a token and a network, and would answer differently
//! on every push. What it *can* see is the durable half of the rule - **one
//! module declaration per name in one `mod.rs`**, and **no module file that
//! nothing declares**. Those are the shapes the collisions produce once they
//! land:
//!
//! 1. A `mod.rs` that names the same module twice. A bad merge that keeps both
//!    sides produces exactly this, and `rustc` only reports it as an
//!    unreachable-pattern warning in some configurations; here it is a
//!    failure with the file named.
//! 2. A `.rs` file in `src/storage/bud3/` that no `mod.rs` declares. That is
//!    an orphan module: it is compiled by nothing, tested by nothing, and it
//!    is what a resolved-in-the-wrong-direction conflict leaves behind.
//! 3. A module declared as both `pub mod x;` and `mod x;`, which is two
//!    packages disagreeing about the module's visibility.
//!
//! # What it does not do
//!
//! It does not fail on a *directory* module (`volume/mod.rs` beside
//! `volume.rs`): Rust permits it during a transition, and refusing it here
//! would fail on the honest half of a split. The orphan rule above still
//! catches the file nobody declares.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// The directory whose modules are checked: the one tree the open queue
/// collided in, and the one where every package's lock paths land.
const DIR: &str = "src/storage/bud3";

/// One `mod` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Decl {
    /// The declared name.
    name: String,
    /// `pub mod` rather than `mod`.
    public: bool,
    /// The line number, for the failure message.
    line: usize,
}

/// Strip `//` comments and string literals, so a declaration in prose or in a
/// string is not a declaration. Kept deliberately small: the input is Rust
/// source this repository writes, not arbitrary text.
fn code_only(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        // A line comment runs to the end of its line.
        if let Some(i) = rest.find("//") {
            let (before, after) = rest.split_at(i);
            // Keep everything before, drop the comment, keep the newline.
            out.push_str(before);
            match after.find('\n') {
                Some(nl) => {
                    out.push('\n');
                    rest = &after[nl + 1..];
                }
                None => rest = "",
            }
            continue;
        }
        out.push_str(rest);
        rest = "";
    }
    // String literals: replace their contents with spaces so a `"pub mod x;"`
    // in a test fixture cannot declare anything. The scanner is the simple
    // one: it handles escapes and raw strings, which is what the tree uses.
    let mut cleaned = String::with_capacity(out.len());
    let bytes: Vec<char> = out.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == '"' {
            cleaned.push('"');
            i += 1;
            while i < bytes.len() {
                if bytes[i] == '\\' {
                    i += 2;
                    continue;
                }
                if bytes[i] == '"' {
                    cleaned.push('"');
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        cleaned.push(c);
        i += 1;
    }
    cleaned
}

/// Every `mod` declaration in one file, with duplicates preserved so the
/// caller can count them.
fn declarations(text: &str) -> Vec<Decl> {
    let code = code_only(text);
    let mut out = Vec::new();
    for (i, line) in code.lines().enumerate() {
        let t = line.trim_start();
        let public = t.starts_with("pub mod ");
        let name = if public {
            t.strip_prefix("pub mod ")
        } else {
            t.strip_prefix("mod ")
        };
        let Some(name) = name else { continue };
        let name = name
            .trim_end()
            .strip_suffix(';')
            .or_else(|| name.trim_end().strip_suffix(';'))
            .map(str::trim);
        // A braced `mod x { ... }` is a declaration too, but it declares
        // something inline; it cannot collide with a file, so it is skipped.
        if let Some(name) = name {
            if !name.is_empty() && !name.contains('{') && !name.contains(' ') {
                out.push(Decl {
                    name: name.to_owned(),
                    public,
                    line: i + 1,
                });
            }
        }
    }
    out
}

/// The `.rs` files directly in `dir`, by module name: `foo.rs` and
/// `foo/mod.rs` both name `foo`.
fn module_files(dir: &Path) -> Result<BTreeMap<String, Vec<String>>, String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("read {}: {e}", dir.display()))?;
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name == "mod.rs" {
            continue;
        }
        if let Some(stem) = name.strip_suffix(".rs") {
            out.entry(stem.to_owned()).or_default().push(name.to_owned());
        } else if path.is_dir() {
            let inner = path.join("mod.rs");
            if inner.is_file() {
                out.entry(name.to_owned())
                    .or_default()
                    .push(format!("{name}/mod.rs"));
            }
        }
    }
    Ok(out)
}

/// Check the tree.
///
/// # Errors
///
/// A sentence naming every collision found: a module declared twice, a module
/// declared both `pub` and private, or a file that no `mod` declaration
/// reaches.
pub fn run(root: &Path) -> Result<String, String> {
    let dir = root.join(DIR);
    let mod_rs = dir.join("mod.rs");
    if !mod_rs.is_file() {
        return Err(format!("{} is missing", mod_rs.display()));
    }
    let text = std::fs::read_to_string(&mod_rs).map_err(|e| e.to_string())?;
    let decls = declarations(&text);
    if decls.is_empty() {
        return Err(format!(
            "{DIR}/mod.rs declares no module: the gate would pass on an empty file, which is \
             the failure it exists to catch."
        ));
    }

    // 1. A name declared twice, and 2. the same name at two visibilities.
    let mut by_name: BTreeMap<&str, Vec<&Decl>> = BTreeMap::new();
    for d in &decls {
        by_name.entry(d.name.as_str()).or_default().push(d);
    }
    let mut problems = String::new();
    for (name, group) in &by_name {
        if group.len() > 1 {
            let lines: Vec<String> = group
                .iter()
                .map(|d| {
                    let vis = if d.public { "pub mod" } else { "mod" };
                    format!("line {} ({vis} {name};)", d.line)
                })
                .collect();
            problems.push_str(&format!(
                "  `{name}` is declared {} times: {}\n    One file cannot be two packages' \
                 module. Section 15.3 item 3 gives a lock path to one package; a merged \
                 conflict that kept both sides reads exactly like this.\n",
                group.len(),
                lines.join(", ")
            ));
        }
    }

    // 3. A file nothing declares: an orphan module, compiled by nothing.
    let files = module_files(&dir)?;
    let declared: BTreeSet<&str> = decls.iter().map(|d| d.name.as_str()).collect();
    for (name, names) in &files {
        if !declared.contains(name.as_str()) {
            problems.push_str(&format!(
                "  `{}` names module `{name}`, which {} does not declare: the file is \
                 compiled by nothing and tested by nothing.\n",
                names.join(" and "),
                format!("{DIR}/mod.rs")
            ));
        }
    }

    if !problems.is_empty() {
        return Err(format!(
            "FAIL: the B.U.D. 3.0 module tree has a collision or an orphan:\n{problems}"
        ));
    }

    Ok(format!(
        "bud3 module claims do not collide OK: {} module(s) declared once each in {DIR}/mod.rs, \
         and every module file is reached",
        decls.len()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch tree holding one `mod.rs` and whatever files a canary needs.
    fn tree(mod_rs: &str, files: &[&str]) -> std::path::PathBuf {
        let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-claims")
            .expect("scratch dir");
        let inner = dir.join(DIR);
        std::fs::create_dir_all(&inner).expect("mkdir");
        std::fs::write(inner.join("mod.rs"), mod_rs).expect("write mod.rs");
        for f in files {
            std::fs::write(inner.join(f), "// module\n").expect("write module file");
        }
        dir
    }

    /// Run and clean up, so a failing canary leaves no directory behind.
    fn check(root: &std::path::Path) -> Result<String, String> {
        let out = run(root);
        let _ = std::fs::remove_dir_all(root);
        out
    }

    #[test]
    fn a_tree_that_declares_each_module_once_passes() {
        let root = tree("pub mod a;\npub mod b;\n", &["a.rs", "b.rs"]);
        let out = check(&root).expect("a clean tree");
        assert!(out.contains("2 module(s)"), "{out}");
    }

    /// The shape a bad merge leaves: both sides' declaration kept.
    #[test]
    fn a_module_declared_twice_fails_and_names_both_lines() {
        let root = tree("pub mod volume;\npub mod a;\npub mod volume;\n", &["volume.rs", "a.rs"]);
        let err = check(&root).expect_err("a duplicate declaration must fail");
        assert!(err.contains("`volume` is declared 2 times"), "{err}");
        assert!(err.contains("line 1"), "{err}");
        assert!(err.contains("line 3"), "{err}");
    }

    #[test]
    fn the_same_module_at_two_visibilities_fails() {
        let root = tree("pub mod x;\nmod x;\n", &["x.rs"]);
        let err = check(&root).expect_err("two visibilities must fail");
        assert!(err.contains("`x` is declared 2 times"), "{err}");
    }

    /// The other half of a bad resolution: the declaration went one way and the
    /// file stayed.
    #[test]
    fn a_file_no_mod_declaration_reaches_fails() {
        let root = tree("pub mod a;\n", &["a.rs", "orphan.rs"]);
        let err = check(&root).expect_err("an orphan module must fail");
        assert!(err.contains("orphan.rs"), "{err}");
        assert!(err.contains("compiled by nothing"), "{err}");
    }

    #[test]
    fn a_declaration_in_a_comment_or_a_string_is_not_a_declaration() {
        // The comment names `ghost`, and so does a string. Neither declares.
        let root = tree(
            "// pub mod ghost;\npub mod a;\nconst S: &str = \"pub mod phantom;\";\n",
            &["a.rs"],
        );
        check(&root).expect("a comment and a string declare nothing");
    }

    /// A directory module is a real module: `volume/mod.rs` is declared as
    /// `pub mod volume;` and must not read as an orphan.
    #[test]
    fn a_directory_module_is_reached_by_its_declaration() {
        let root = tree("pub mod volume;\n", &[]);
        let inner = root.join(DIR).join("volume");
        std::fs::create_dir_all(&inner).expect("mkdir volume");
        std::fs::write(inner.join("mod.rs"), "// the volume\n").expect("write");
        check(&root).expect("a directory module is a module");
    }

    #[test]
    fn an_empty_mod_rs_fails_rather_than_passing_vacuously() {
        let root = tree("// nothing here\n", &[]);
        let err = check(&root).expect_err("an empty file must fail");
        assert!(err.contains("declares no module"), "{err}");
    }
}

/// The canaries, as the gate runner expects them.
///
/// # Errors
///
/// When a canary does not behave.
pub fn self_test() -> Result<String, String> {
    // The unit tests above are the canaries; this runs them from the binary so
    // `--self-test` reports something even when the harness is not in play.
    let root = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-claims-self")
        .map_err(|e| e)?;
    let inner = root.join(DIR);
    std::fs::create_dir_all(&inner).map_err(|e| e.to_string())?;
    let result = (|| {
        std::fs::write(inner.join("mod.rs"), "pub mod a;\npub mod a;\n")
            .map_err(|e| e.to_string())?;
        std::fs::write(inner.join("a.rs"), "// a\n").map_err(|e| e.to_string())?;
        match run(&root) {
            Err(e) if e.contains("declared 2 times") => {}
            other => return Err(format!("canary: a duplicate module did not fail: {other:?}")),
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&root);
    result?;
    Ok(String::from(
        "bud3-module-claims-do-not-collide canary OK: a module declared twice, the same module \
         at two visibilities, a file nothing declares and an empty mod.rs all failed.",
    ))
}
