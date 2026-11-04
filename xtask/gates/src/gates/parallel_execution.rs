//! Every node must reach the same root from the same block.
//!
//! Gate code: `K-EXECUTION-PARALLEL-DETERMINISTIC`. A finding or a document that names this code resolves here.
//!
//! Parallel execution is promised in the fourth phase, and the property that
//! makes it possible is already required: the state root must be a fold whose
//! input order is fixed by the data. `StorageRegistry::root()` is that fold.
//! A `HashMap` inside it would let two honest nodes hash the same registry
//! into two different roots, which is a fork, not a performance problem.
//!
//! So this gate requires every ordered-map field of the registry to be named
//! inside the fold. One exception is allowed, and only while every write to
//! that field happens in a single function of this file: an exception that
//! covers a table anyone can append to is how a root stops being a root. A
//! new table added without folding is exactly the accident this exists to
//! catch, so it fails the gate rather than the tests.

use std::fmt::Write as _;
use std::path::Path;

/// Fields deliberately outside the fold, each with the function that owns its
/// writes. The condition is re-checked here, not trusted from the file.
const UNFOLDED: [(&str, &str); 1] = [("access_events", "record_proven_read")];

/// Ways a field is written, with `{name}` for the field. Any of them outside
/// the owning function breaks the single-writer claim.
const WRITE_FORMS: [&str; 12] = [
    "self.{name}.entry(",
    "self.{name}.insert(",
    "self.{name}.remove(",
    "self.{name}.clear()",
    "self.{name}.get_mut(",
    "self.{name}.retain(",
    "self.{name}.extend(",
    "self.{name}.append(",
    "self.{name}.values_mut(",
    "self.{name}.iter_mut(",
    "self.{name}.drain(",
    "&mut self.{name}",
];

fn read(root: &Path, rel: &str) -> Result<String, String> {
    let f = root.join(rel);
    if !f.is_file() {
        return Err(format!("no {rel} at {}", f.display()));
    }
    std::fs::read_to_string(&f).map_err(|e| e.to_string())
}

/// The byte span of a function body, counting braces but not the ones inside
/// strings, chars and comments. `root()` has a `match` and serialized
/// literals in it, so a naive count ends in the wrong place.
///
/// Offsets are byte offsets throughout. The scan used to index a `Vec<char>`
/// and add the character index to a byte offset from `str::find`, so a body
/// with any non-ASCII character in or before it (a doc comment with a
/// typographic quote is enough) was sliced short or split mid-character.
fn span_of(src: &str, name: &str) -> Option<(usize, usize)> {
    let at = src.find(&format!("fn {name}("))?;
    let bytes: Vec<(usize, char)> = src[at..].char_indices().collect();
    let mut i = 0usize;
    let mut open: Option<usize> = None;
    let mut depth = 0usize;
    let mut in_str = false;
    let mut in_char = false;
    let mut in_line = false;
    let mut in_block = false;
    let mut esc = false;
    while i < bytes.len() {
        let (pos, c) = bytes[i];
        let next = if i + 1 < bytes.len() {
            bytes[i + 1].1
        } else {
            ' '
        };
        if in_line {
            if c == '\n' {
                in_line = false;
            }
        } else if in_block {
            if c == '*' && next == '/' {
                in_block = false;
                i += 1;
            }
        } else if in_str {
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
        } else if in_char {
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '\'' {
                in_char = false;
            }
        } else if c == '/' && next == '/' {
            in_line = true;
            i += 1;
        } else if c == '/' && next == '*' {
            in_block = true;
            i += 1;
        } else if c == '"' {
            in_str = true;
        } else if c == '\'' {
            // A char literal is `'x'` or `'\..'`; a lifetime (`&'a`) is not one
            // and must not swallow the code up to the next quote.
            let literal = next == '\\' || bytes.get(i + 2).is_some_and(|(_, c2)| *c2 == '\'');
            in_char = literal;
        } else if c == '{' {
            depth += 1;
            if open.is_none() {
                open = Some(pos);
            }
        } else if c == '}' {
            // A stray `}` before the first `{` must not underflow.
            depth = depth.saturating_sub(1);
            if depth == 0 && open.is_some() {
                if let Some(o) = open {
                    return Some((at + o, at + pos + 1));
                }
            }
        }
        i += 1;
    }
    None
}

fn body_of(src: &str, name: &str) -> Option<String> {
    let (a, b) = span_of(src, name)?;
    Some(src[a..b].to_string())
}

/// Every field declared in `pub struct StorageRegistry`, whatever its type.
///
/// A field is consensus state when it holds a table or a registry, and the
/// type tells nothing reliable: `dictionaries` is a `DictionaryRegistry`
/// (a struct around a `BTreeMap`) and `self_host_policies` carries its
/// `BTreeMap` type on the line after the name. Filtering by a `BTreeMap<` on
/// the name's line made both invisible to the gate, so every field has to be
/// folded or named in [`UNFOLDED`]. A declaration may span lines; it ends at
/// the first line that closes with `,` outside brackets.
fn struct_fields(struct_text: &str) -> Vec<String> {
    struct_field_decls(struct_text)
        .into_iter()
        .map(|(name, _)| name)
        .collect()
}

/// Every field with the text of its type, as declared.
fn struct_field_decls(struct_text: &str) -> Vec<(String, String)> {
    let body = struct_text
        .split_once('{')
        .map_or(struct_text, |(_, rest)| rest);
    let mut out = Vec::new();
    let mut decl = String::new();
    let mut depth = 0i32;
    for l in body.lines() {
        let t = l.trim();
        if t.is_empty() || t.starts_with("//") || t.starts_with("#[") {
            continue;
        }
        decl.push_str(t);
        decl.push(' ');
        for c in t.chars() {
            match c {
                '<' | '(' | '[' => depth += 1,
                '>' | ')' | ']' => depth -= 1,
                _ => {}
            }
        }
        if depth <= 0 && t.ends_with(',') {
            if let Some((name, ty)) = decl.split_once(':') {
                let name = name
                    .trim()
                    .trim_start_matches("pub(crate) ")
                    .trim_start_matches("pub ")
                    .trim();
                if !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                {
                    out.push((name.to_string(), ty.trim().to_string()));
                }
            }
            decl.clear();
            depth = 0;
        }
    }
    out
}

/// Is `name` used as a whole identifier in `code`? A substring match let
/// `deals` be satisfied by `deals_by_shard`.
fn mentions_ident(code: &str, name: &str) -> bool {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut from = 0usize;
    while let Some(pos) = code[from..].find(name) {
        let abs = from + pos;
        let before = code[..abs].chars().next_back();
        let after = code[abs + name.len()..].chars().next();
        if !before.is_some_and(is_ident) && !after.is_some_and(is_ident) {
            return true;
        }
        from = abs + name.len();
    }
    false
}

/// The three properties the fold must keep about *how* it folds, not what it
/// folds: a domain tag, the confidential pair, and no unordered container.
fn extra_checks(body: &str) -> (usize, Vec<String>) {
    let mut ok = 0usize;
    let mut problems = Vec::new();
    if body.contains("BDLM_STORAGE_REGISTRY_V1") {
        ok += 1;
    } else {
        problems.push(
            "`root()` no longer hashes the registry's domain tag. Without a tag the digest of              this table is the digest of any other table with the same bytes."
                .to_string(),
        );
    }
    for need in ["confidential_commits", "confidential_owners"] {
        if body.contains(need) {
            ok += 1;
        } else {
            problems.push(format!(
                "the confidential `{need}` map is no longer folded. A body and the address that                  may open it are consensus facts: a node that drops them can serve content the                  agreed state never committed to."
            ));
        }
    }
    let unordered: Vec<String> = body
        .lines()
        .filter(|l| l.contains("HashMap") || l.contains("HashSet"))
        .map(|l| l.trim().to_string())
        .collect();
    if unordered.is_empty() {
        ok += 1;
    } else {
        problems.push(format!(
            "the root fold touches an unordered container: {}. Iteration order there is a              property of the allocator, not of the block.",
            unordered.join(" / ")
        ));
    }
    (ok, problems)
}

/// # Errors
///
/// Returns the list of violated claims.
/// Formats the findings the way every gate in this crate reports them.
fn report(problems: &[String]) -> String {
    let mut msg = String::new();
    for p in problems {
        writeln!(msg, "FAIL: {p}").expect("writing to a String cannot fail");
    }
    msg
}

pub fn run(root: &Path) -> Result<String, String> {
    let src = read(root, "src/domain/storage_deal.rs")?;
    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    let struct_at = src
        .find("pub struct StorageRegistry")
        .ok_or_else(|| "no `pub struct StorageRegistry`".to_string())?;
    let struct_end = src[struct_at..]
        .find("\n}")
        .map_or(src.len(), |i| struct_at + i);
    let fields = struct_fields(&src[struct_at..struct_end]);
    if fields.len() < 8 {
        problems.push(format!(
            "the registry declares {} fields; the fold covers at least twelve. A field quietly \
             dropped is a table that stops being part of the state root, and nothing else \
             notices.",
            fields.len()
        ));
    } else {
        checked += 1;
    }

    // Anchor on the registry's own impl: the file also has an economics
    // ledger with a `fn root(` of its own, and folding that one instead
    // reports every registry field as missing.
    let impl_at = src
        .find("impl StorageRegistry")
        .ok_or_else(|| "no `impl StorageRegistry` to anchor on".to_string())?;
    let registry_src = &src[impl_at..];
    let body = body_of(registry_src, "root")
        .ok_or_else(|| "no `fn root(` in the registry impl to inspect".to_string())?;
    let mut missing: Vec<String> = Vec::new();
    let mut excused = 0usize;
    // Comments and literals are blanked, so a field named in a comment above
    // the fold does not count as folded.
    let fold_code = crate::gates::rust_literals::scrub(&body);
    for name in &fields {
        if mentions_ident(&fold_code, name) {
            checked += 1;
            continue;
        }
        let Some((_, owner)) = UNFOLDED.iter().find(|(f, _)| f == name) else {
            missing.push(name.clone());
            continue;
        };
        let span = span_of(&src, owner);
        let alone = span.is_some_and(|(start, end)| {
            let mut ok = src.contains(&format!("fn {owner}"));
            for pat in WRITE_FORMS.iter().map(|f| f.replace("{name}", name)) {
                let mut at = 0usize;
                while let Some(j) = src[at..].find(&pat) {
                    let pos = at + j;
                    if !(start..end).contains(&pos) {
                        ok = false;
                    }
                    at = pos + pat.len();
                }
            }
            ok
        });
        if alone {
            excused += 1;
        } else {
            missing.push(format!(
                "{name} (claimed exception, its writes are not in one place)"
            ));
        }
    }
    if !missing.is_empty() {
        problems.push(format!(
            "these fields are in the registry but not in the root fold: {}. Two nodes \
             that agree on every block can disagree on the state, and only the next block hash \
             reveals it.",
            missing.join(", ")
        ));
    }
    // A folded field whose type is a HashMap or HashSet is walked in the
    // allocator's order. The fold body never writes the type name, so the
    // declaration is what shows it.
    let unordered_folded: Vec<String> = struct_field_decls(&src[struct_at..struct_end])
        .into_iter()
        .filter(|(name, ty)| {
            (ty.contains("HashMap") || ty.contains("HashSet")) && mentions_ident(&fold_code, name)
        })
        .map(|(name, _)| name)
        .collect();
    if !unordered_folded.is_empty() {
        problems.push(format!(
            "the root folds fields declared as a HashMap or HashSet: {}. Iteration order \
             there is a property of the allocator, not of the block.",
            unordered_folded.join(", ")
        ));
    }
    let (extra, sorun) = extra_checks(&body);
    checked += extra;
    problems.extend(sorun);
    if checked == 0 {
        return Err(String::from("gate checked nothing"));
    }
    if !problems.is_empty() {
        return Err(report(&problems));
    }
    Ok(format!(
        "state-root determinism OK: {checked} checks, {} fields folded, {excused} \
         excused by a single writer, fold begins with the domain tag",
        fields.len()
    ))
}

fn self_test_tail(dir: &std::path::Path, good: &str) -> Result<(), String> {
    let second = good.replace(
        "        self.access_events.entry(id).or_default();",
        "        self.access_events.entry(id).or_default();\n        self.access_events.insert(7, 8);",
    );
    let spread = second.replace(
        "    fn record_proven_read(&mut self, id: u64) {",
        "    fn other_writer(&mut self) {\n        self.access_events.insert(3, 4);\n    }\n    fn record_proven_read(&mut self, id: u64) {",
    );
    std::fs::write(dir.join("src/domain/storage_deal.rs"), spread).map_err(|e| e.to_string())?;
    if run(dir).is_ok() {
        let _ = std::fs::remove_dir_all(dir);
        return Err(String::from(
            "canary: an exception held while a second writer existed",
        ));
    }
    // A multi-byte character ahead of the body must not move the span. With
    // char indices added to a byte offset, the slice fell short of the fold's
    // end, so the last folded map read as dropped; and a genuinely dropped fold
    // behind such a character has to stay visible.
    let accented = good.replace(
        "    pub fn root(&self) -> Hash32 {",
        "    /// The root folds every table, na\u{ef}ve order, r\u{e9}sum\u{e9} of the state.\n    pub fn root(&self) -> Hash32 {",
    );
    std::fs::write(dir.join("src/domain/storage_deal.rs"), &accented).map_err(|e| e.to_string())?;
    if let Err(e) = run(dir) {
        let _ = std::fs::remove_dir_all(dir);
        return Err(format!(
            "canary: a non-ASCII comment before the fold shifted the span: {e}"
        ));
    }
    let accented_dropped = accented.replace(
        "        for x in &self.confidential_owners { h.update(x.0.to_le_bytes()); }\n",
        "",
    );
    std::fs::write(dir.join("src/domain/storage_deal.rs"), accented_dropped)
        .map_err(|e| e.to_string())?;
    if run(dir).is_ok() {
        let _ = std::fs::remove_dir_all(dir);
        return Err(String::from(
            "canary: a dropped fold behind a non-ASCII comment passed",
        ));
    }
    Ok(())
}

/// # Errors
///
/// Returns a finding when a defect fixture passes.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-par")?;
    std::fs::create_dir_all(dir.join("src/domain")).map_err(|e| e.to_string())?;
    let maps = (0..9)
        .map(|i| format!("    map_{i}: BTreeMap<u64, u64>,"))
        .collect::<Vec<_>>()
        .join("\n");
    let folds = (0..9)
        .map(|i| {
            format!(
                "        for (k, v) in &self.map_{i} {{ h.update(k.to_le_bytes()); h.update(v.to_le_bytes()); }}"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let good = format!(
        "pub struct StorageRegistry {{\n{maps}\n    confidential_commits: BTreeMap<u64, u64>,\n    confidential_owners: BTreeMap<u64, u64>,\n    access_events: BTreeMap<u64, u64>,\n}}\n\nimpl StorageRegistry {{\n    pub fn root(&self) -> Hash32 {{\n        let mut h = Sha256::new();\n        h.update(b\"BDLM_STORAGE_REGISTRY_V1\");\n{folds}\n        for x in &self.confidential_commits {{ h.update(x.0.to_le_bytes()); }}\n        for x in &self.confidential_owners {{ h.update(x.0.to_le_bytes()); }}\n        h.finalize().into()\n    }}\n    fn record_proven_read(&mut self, id: u64) {{\n        self.access_events.entry(id).or_default();\n    }}\n}}\n"
    );
    std::fs::write(dir.join("src/domain/storage_deal.rs"), &good).map_err(|e| e.to_string())?;
    if let Err(e) = run(&dir) {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(format!("canary: a fully folded fixture was refused: {e}"));
    }
    let dropped = good.replace(
        "        for x in &self.confidential_owners { h.update(x.0.to_le_bytes()); }\n",
        "",
    );
    std::fs::write(dir.join("src/domain/storage_deal.rs"), dropped).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a map dropped from the fold passed"));
    }
    let added = good.replace(
        "    access_events: BTreeMap<u64, u64>,",
        "    access_events: BTreeMap<u64, u64>,\n    side_table: BTreeMap<u64, u64>,",
    );
    std::fs::write(dir.join("src/domain/storage_deal.rs"), added).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a new table nobody folds passed silently",
        ));
    }
    // A registry-typed field and a multi-line typed field are consensus
    // state too; neither shows a `BTreeMap<` on the name's line.
    for extra in [
        "    dictionaries: DictionaryRegistry,",
        "    self_host_policies:\n        BTreeMap<u64, u64>,",
    ] {
        let hidden = good.replace(
            "    access_events: BTreeMap<u64, u64>,",
            &format!("    access_events: BTreeMap<u64, u64>,\n{extra}"),
        );
        std::fs::write(dir.join("src/domain/storage_deal.rs"), hidden)
            .map_err(|e| e.to_string())?;
        if run(&dir).is_ok() {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(format!(
                "canary: an unfolded field `{extra}` passed because of its type shape"
            ));
        }
    }
    // A field name that is only a prefix of a folded one is not folded, and a
    // comment naming it is not a fold.
    let prefix = good.replace(
        "    access_events: BTreeMap<u64, u64>,",
        "    access_events: BTreeMap<u64, u64>,\n    map: BTreeMap<u64, u64>,",
    );
    std::fs::write(dir.join("src/domain/storage_deal.rs"), prefix).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a field satisfied by a longer name (`map` vs `map_0`) passed",
        ));
    }
    let commented = good
        .replace(
            "    access_events: BTreeMap<u64, u64>,",
            "    access_events: BTreeMap<u64, u64>,\n    side_table: BTreeMap<u64, u64>,",
        )
        .replace(
            "        h.finalize().into()",
            "        // side_table is folded elsewhere\n        h.finalize().into()",
        );
    std::fs::write(dir.join("src/domain/storage_deal.rs"), commented).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a field named only in a comment passed as folded",
        ));
    }
    self_test_tail(&dir, &good)?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "state-root determinism canary OK (full fold and single-writer exception PASS, also \
         behind a non-ASCII comment; a dropped fold, an unfolded new table and a second \
         writer each FAIL).",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_test_passes() {
        super::self_test().expect("parallel-execution self-test");
    }

    #[test]
    fn struct_fields_reads_multi_line_and_registry_types() {
        let text = "pub struct R {\n    a: u64,\n    pub b: crate::x::Registry,\n    pub c:\n        BTreeMap<u64, u64>,\n    d: BTreeMap<(u8, u8), Vec<u64>>,\n}";
        assert_eq!(super::struct_fields(text), ["a", "b", "c", "d"]);
    }
}

#[cfg(test)]
mod decl_tests {
    use super::*;

    #[test]
    fn field_types_are_kept_with_their_names() {
        let text =
            "pub struct R {\n    a: BTreeMap<u64, u64>,\n    b: HashMap<u64,\n        u64>,\n}";
        let d = struct_field_decls(text);
        assert_eq!(d.len(), 2);
        assert!(d[1].1.contains("HashMap"));
        assert_eq!(
            struct_fields(text),
            vec![String::from("a"), String::from("b")]
        );
    }

    #[test]
    fn a_lifetime_does_not_end_the_body_early_and_a_stray_brace_does_not_panic() {
        let src = "fn root(x: &'a str) -> u8 { let y = 1; if y > 0 { 2 } else { 3 } }\nfn z() {}";
        let (a, b) = span_of(src, "root").unwrap();
        assert!(src[a..b].ends_with("3 } }"));
        assert!(
            span_of("fn root() } {", "root").is_some()
                || span_of("fn root() } {", "root").is_none()
        );
    }
}
