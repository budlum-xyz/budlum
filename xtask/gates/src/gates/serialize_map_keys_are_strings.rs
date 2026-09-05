//! A map inside a `Serialize` struct must have a key JSON can write.
//!
//! `serde_json` writes a map key only if it is a string, an integer, a
//! bool or a char (or a newtype / unit variant that serialises to one).
//! A `BTreeMap<[u8; 32], _>` or a tuple-keyed map compiles, derives
//! `Serialize`, passes every test that runs with the map empty, and then
//! fails with "key must be a string" at the first real entry. The V2 state
//! snapshot is JSON, and that is exactly how the first bridge transfer on a
//! chain stopped every later snapshot write (`warn!`, nothing else). The
//! `core::map_keys` helper fixes the fields that existed; this gate keeps a
//! new registry from bringing the failure back.
//!
//! # What is a finding
//!
//! A named field of a `struct` that derives `Serialize`, whose type is
//! `BTreeMap<K, V>` or `HashMap<K, V>` (bare, or wrapped in `Option`,
//! `Vec`, `Box`, `Arc`, `Rc`, `RefCell`, `Mutex`, `RwLock`, in any nesting),
//! where `K` is not on the string-safe list below, and the field carries no
//! `#[serde(with = ..)]`, `#[serde(serialize_with = ..)]` or
//! `#[serde(skip / skip_serializing)]`.
//!
//! # What counts as a string-safe key
//!
//! * `String`, `&str`, `str`, `char`, `bool`, every integer type.
//! * `Address`: its hand-written `Serialize` writes a hex string.
//! * `AssetId` and its aliases (`GrantId`, `SaleAuthorizationId`): the inner
//!   bytes carry `#[serde(with = "asset_id_serde")]`, and `serde_json`
//!   unwraps a newtype when it is used as a key.
//! * `DomainId` (`u32`) and `ConstitutionParameterKey` (a unit-variant
//!   enum, written as its variant name).
//!
//! The list is by name. `type` aliases are collected from the whole tree
//! first and followed to a fixed point (`type GrantId = AssetId` is safe,
//! `type MessageId = Hash32` is not); an alias name declared with two
//! different targets in the tree is refused as ambiguous rather than
//! guessed. A name that is not on the list and not an alias is a finding,
//! so a new byte-keyed id type is caught by default rather than missed by
//! default.
//!
//! # Why the derive is required
//!
//! A struct with a hand-written `impl Serialize` decides its own encoding;
//! the derive is what turns a map field into a serde map with the field's
//! key type. `#[cfg(test)]` code is scanned too: a test-only struct that
//! derives `Serialize` with a byte key is exactly the fixture this gate's
//! own tests use, and `core::map_keys` marks its counter-example with
//! `serialize_with`-free intent by naming it in `SELF_EXEMPT`.
//!
//! # Scope
//!
//! `src`, `crates`, `budzero` and `bud`: every tree whose structs can be
//! reached from a JSON writer. `xtask` is not a JSON producer and is left
//! out; `target` and `.git` are skipped.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use syn::{Fields, GenericArgument, Item, PathArguments, Type};

/// Trees whose `Serialize` structs are checked.
const ROOTS: &[&str] = &["src", "crates", "budzero", "bud"];

/// Key type names `serde_json` can write as a map key.
const STRING_SAFE: &[&str] = &[
    "String",
    "str",
    "char",
    "bool",
    "u8",
    "u16",
    "u32",
    "u64",
    "u128",
    "usize",
    "i8",
    "i16",
    "i32",
    "i64",
    "i128",
    "isize",
    "Address",
    "AssetId",
    "DomainId",
    "ConstitutionParameterKey",
];

/// Map types whose key is checked.
const MAP_TYPES: &[&str] = &["BTreeMap", "HashMap"];

/// Wrappers that are looked through to find a map.
const TRANSPARENT: &[&str] = &[
    "Option", "Vec", "Box", "Arc", "Rc", "RefCell", "Mutex", "RwLock", "Cell",
];

/// Fields that exist to prove the failure and are therefore allowed to carry
/// it: `(file suffix, struct name)`. Each one must be a `#[cfg(test)]`
/// counter-example whose test asserts that `serde_json` rejects it.
const SELF_EXEMPT: &[(&str, &str)] = &[("src/core/map_keys.rs", "Derived")];

/// A scan that reads too few structs is vacuous and must fail rather than
/// pass; the tree has hundreds of `Serialize` structs.
const VACUITY_FLOOR: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Finding {
    file: String,
    strukt: String,
    field: String,
    key: String,
}

fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.filter_map(Result::ok).collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            let name = entry.file_name();
            if name == "target" || name == ".git" || name == "node_modules" {
                continue;
            }
            collect_rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn derives_serialize(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("derive") {
            return false;
        }
        let mut found = false;
        let _ = attr.parse_nested_meta(|meta| {
            if meta
                .path
                .segments
                .last()
                .is_some_and(|s| s.ident == "Serialize")
            {
                found = true;
            }
            Ok(())
        });
        found
    })
}

/// Does the field opt out of the derived map encoding?
fn field_is_handled(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("serde") {
            return false;
        }
        let mut handled = false;
        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("with")
                || meta.path.is_ident("serialize_with")
                || meta.path.is_ident("skip")
                || meta.path.is_ident("skip_serializing")
            {
                handled = true;
            }
            // Consume any `= value` so the parser can move on.
            if meta.input.peek(syn::Token![=]) {
                let _eq: syn::Token![=] = meta.input.parse()?;
                let _value: syn::Expr = meta.input.parse()?;
            }
            Ok(())
        });
        handled
    })
}

/// Last path segment of a type path, and its generic arguments.
fn path_head(ty: &Type) -> Option<(String, Vec<&Type>)> {
    let Type::Path(tp) = ty else {
        return None;
    };
    let seg = tp.path.segments.last()?;
    let args = match &seg.arguments {
        PathArguments::AngleBracketed(a) => a
            .args
            .iter()
            .filter_map(|g| match g {
                GenericArgument::Type(t) => Some(t),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    Some((seg.ident.to_string(), args))
}

/// Find every map key type inside `ty`, looking through transparent
/// wrappers and into map values (a map inside a map value is a map too).
fn map_keys_in<'a>(ty: &'a Type, out: &mut Vec<&'a Type>) {
    match ty {
        Type::Reference(r) => map_keys_in(&r.elem, out),
        Type::Paren(p) => map_keys_in(&p.elem, out),
        Type::Path(_) => {
            let Some((head, args)) = path_head(ty) else {
                return;
            };
            if MAP_TYPES.contains(&head.as_str()) {
                if let Some(key) = args.first() {
                    out.push(key);
                }
                if let Some(value) = args.get(1) {
                    map_keys_in(value, out);
                }
            } else if TRANSPARENT.contains(&head.as_str()) {
                for arg in args {
                    map_keys_in(arg, out);
                }
            }
        }
        _ => {}
    }
}

/// Is this key type something `serde_json` writes as a string or number?
///
/// `aliases` are the `type` declarations of the same file, followed to a
/// fixed point so `type GrantId = AssetId` resolves to `AssetId`.
fn key_is_string_safe(key: &Type, aliases: &[(String, Type)]) -> bool {
    let mut current = key.clone();
    for _ in 0..8 {
        match &current {
            Type::Reference(r) => {
                current = (*r.elem).clone();
                continue;
            }
            Type::Path(_) => {}
            // Tuples, arrays, slices: never a JSON key.
            _ => return false,
        }
        let Some((head, args)) = path_head(&current) else {
            return false;
        };
        if !args.is_empty() {
            return false;
        }
        if STRING_SAFE.contains(&head.as_str()) {
            return true;
        }
        match aliases.iter().find(|(name, _)| *name == head) {
            Some((_, target)) => current = target.clone(),
            None => return false,
        }
    }
    false
}

fn type_text(ty: &Type) -> String {
    quote::ToTokens::to_token_stream(ty)
        .to_string()
        .replace(" ,", ",")
        .replace("< ", "<")
        .replace(" >", ">")
        .replace(" ;", ";")
        .replace("[ ", "[")
        .replace(" ]", "]")
}

/// Walk items recursively (inline modules included) and collect the
/// findings for one file. Returns `(structs seen, findings)`.
fn scan_items(
    items: &[Item],
    rel: &str,
    aliases: &[(String, Type)],
    out: &mut Vec<Finding>,
) -> usize {
    let mut seen = 0usize;
    for item in items {
        match item {
            Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    seen += scan_items(inner, rel, aliases, out);
                }
            }
            Item::Struct(s) => {
                if !derives_serialize(&s.attrs) {
                    continue;
                }
                seen += 1;
                let name = s.ident.to_string();
                if SELF_EXEMPT
                    .iter()
                    .any(|(suffix, strukt)| rel.ends_with(suffix) && *strukt == name)
                {
                    continue;
                }
                let Fields::Named(named) = &s.fields else {
                    continue;
                };
                for field in &named.named {
                    if field_is_handled(&field.attrs) {
                        continue;
                    }
                    let mut keys = Vec::new();
                    map_keys_in(&field.ty, &mut keys);
                    for key in keys {
                        if !key_is_string_safe(key, aliases) {
                            out.push(Finding {
                                file: rel.to_string(),
                                strukt: name.clone(),
                                field: field
                                    .ident
                                    .as_ref()
                                    .map(ToString::to_string)
                                    .unwrap_or_default(),
                                key: type_text(key),
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }
    seen
}

fn aliases_in(items: &[Item], out: &mut Vec<(String, Type)>) {
    for item in items {
        match item {
            Item::Type(t) => out.push((t.ident.to_string(), (*t.ty).clone())),
            Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    aliases_in(inner, out);
                }
            }
            _ => {}
        }
    }
}

struct Scan {
    structs: usize,
    files: usize,
    unparsed: Vec<String>,
    ambiguous: Vec<String>,
    findings: Vec<Finding>,
}

fn scan_tree(root: &Path) -> Scan {
    let mut files = Vec::new();
    for dir in ROOTS {
        collect_rust_files(&root.join(dir), &mut files);
    }
    let mut scan = Scan {
        structs: 0,
        files: 0,
        unparsed: Vec::new(),
        ambiguous: Vec::new(),
        findings: Vec::new(),
    };
    // Pass 1: parse everything, collect every `type` alias in the tree.
    let mut parsed: Vec<(String, syn::File)> = Vec::new();
    let mut aliases: Vec<(String, Type)> = Vec::new();
    for path in files {
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        scan.files += 1;
        match syn::parse_file(&text) {
            Ok(ast) => {
                aliases_in(&ast.items, &mut aliases);
                parsed.push((rel, ast));
            }
            Err(_) => scan.unparsed.push(rel),
        }
    }
    // An alias name with two different targets cannot be followed.
    let mut names: Vec<&str> = aliases.iter().map(|(n, _)| n.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    for name in names {
        let mut targets: Vec<String> = aliases
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, t)| type_text(t))
            .collect();
        targets.sort();
        targets.dedup();
        if targets.len() > 1 && alias_matters(name, &parsed) {
            scan.ambiguous
                .push(format!("{name} = {}", targets.join(" | ")));
        }
    }
    // Pass 2: check the structs.
    for (rel, ast) in &parsed {
        scan.structs += scan_items(&ast.items, rel, &aliases, &mut scan.findings);
    }
    scan.findings.sort();
    scan
}

/// Only an alias that some map key resolves through can make a wrong
/// answer; a duplicated alias name nobody keys a map by is not this gate's
/// business (the tree has many `type Error = ..` and generic `type F = ..`).
fn alias_matters(name: &str, parsed: &[(String, syn::File)]) -> bool {
    fn keys_in_items(items: &[Item], out: &mut Vec<String>) {
        for item in items {
            match item {
                Item::Mod(m) => {
                    if let Some((_, inner)) = &m.content {
                        keys_in_items(inner, out);
                    }
                }
                Item::Struct(s) if derives_serialize(&s.attrs) => {
                    if let Fields::Named(named) = &s.fields {
                        for field in &named.named {
                            let mut keys = Vec::new();
                            map_keys_in(&field.ty, &mut keys);
                            for key in keys {
                                if let Some((head, _)) = path_head(key) {
                                    out.push(head);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    let mut heads = Vec::new();
    for (_, ast) in parsed {
        keys_in_items(&ast.items, &mut heads);
    }
    heads.iter().any(|h| h == name)
}

/// # Errors
///
/// Returns the list of map fields whose key `serde_json` cannot write.
pub fn run(root: &Path) -> Result<String, String> {
    let scan = scan_tree(root);
    if scan.structs < VACUITY_FLOOR {
        return Err(format!(
            "FAIL [serialize-map-keys-are-strings]: only {} Serialize structs found in {} files \
             (floor {VACUITY_FLOOR}); the scan is not looking at the tree",
            scan.structs, scan.files
        ));
    }
    if !scan.unparsed.is_empty() {
        let mut msg = String::from(
            "FAIL [serialize-map-keys-are-strings]: files that do not parse cannot be checked:\n",
        );
        for f in &scan.unparsed {
            let _ = writeln!(msg, "  {f}");
        }
        return Err(msg);
    }
    if !scan.ambiguous.is_empty() {
        let mut msg = String::from(
            "FAIL [serialize-map-keys-are-strings]: a map key alias has two different targets in \
             the tree, so it cannot be resolved:\n",
        );
        for a in &scan.ambiguous {
            let _ = writeln!(msg, "  type {a}");
        }
        return Err(msg);
    }
    if scan.findings.is_empty() {
        return Ok(format!(
            "Serialize map keys OK: {} Serialize structs in {} files, every map key is a string, \
             a number, or carries a serde `with`.",
            scan.structs, scan.files
        ));
    }
    let mut msg = String::from(
        "FAIL [serialize-map-keys-are-strings]: a Serialize struct keys a map by a type \
         serde_json cannot write:\n",
    );
    for f in &scan.findings {
        let _ = writeln!(
            msg,
            "  {}  {}.{}: key `{}`",
            f.file, f.strukt, f.field, f.key
        );
    }
    msg.push_str(
        "\nJSON map keys must be strings. Add `#[serde(with = \"crate::core::map_keys\")]` \
         (and a `MapKey` impl for a new key type), or `#[serde(skip)]` if the map is \
         never persisted.",
    );
    Err(msg)
}

/// A fresh scratch tree this process alone created.
///
/// `remove_dir_all` followed by `create_dir_all` on a predictable name
/// leaves a window in which another local user can plant a symlink at that
/// path and receive the fixture writes. `exclusive_scratch_dir` creates the
/// directory with `create_dir`, which fails if anything already sits there.
fn scratch_dir() -> Result<PathBuf, String> {
    let dir = super::rust_literals::exclusive_scratch_dir("budlum-gates-map-keys")?;
    fs::create_dir(dir.join("src")).map_err(|e| format!("cannot create scratch dir: {e}"))?;
    Ok(dir)
}

/// Enough harmless `Serialize` structs to clear the vacuity floor.
fn filler() -> String {
    let mut out = String::from("use serde::Serialize;\nuse std::collections::BTreeMap;\n");
    for i in 0..VACUITY_FLOOR {
        let _ = writeln!(
            out,
            "#[derive(Serialize)]\npub struct Filler{i} {{ pub by_name: BTreeMap<String, u64>, pub n: u{} }}",
            if i % 2 == 0 { "64" } else { "32" }
        );
    }
    out
}

fn fixture_findings(dir: &Path, src: &str) -> Result<Vec<Finding>, String> {
    fs::write(dir.join("src/probe.rs"), src).map_err(|e| e.to_string())?;
    Ok(scan_tree(dir).findings)
}

/// Canaries 4 to 7: alias resolution across files, ambiguous aliases,
/// wrapped and nested maps, structs without a derive, inline modules.
fn alias_and_shape_canaries(dir: &Path, failures: &mut Vec<String>) -> Result<(), String> {
    // 4. Tuple keys, newtype byte ids and aliases to bytes are findings;
    //    an alias to AssetId is not.
    let tuple = "use serde::Serialize;\nuse std::collections::BTreeMap;\n\
        pub type Hash32 = [u8; 32];\npub type MessageId = Hash32;\npub type GrantId = AssetId;\n\
        #[derive(Serialize)]\npub struct Id(pub [u8; 32]);\n\
        #[derive(Serialize)]\npub struct Reg {\n\
          pub a: BTreeMap<(u32, Address), u64>,\n\
          pub b: BTreeMap<MessageId, u64>,\n\
          pub c: BTreeMap<Id, u64>,\n\
          pub d: BTreeMap<GrantId, u64>,\n\
          pub e: BTreeMap<Address, u64>,\n\
          pub f: BTreeMap<u64, u64>,\n\
        }\n";
    let f = fixture_findings(dir, tuple)?;
    let fields: Vec<&str> = f.iter().map(|x| x.field.as_str()).collect();
    if fields != ["a", "b", "c"] {
        failures.push(format!(
            "tuple/alias resolution wrong, findings on {fields:?}"
        ));
    }

    // 4b. An alias declared in another file is followed too: `GrantId` lives
    //     in `pollen/mod.rs`, the map that uses it in `pollen/offers.rs`.
    fs::write(
        dir.join("src/aliases.rs"),
        "pub type RemoteGrantId = AssetId;\npub type RemoteRowId = [u8; 32];\n",
    )
    .map_err(|e| e.to_string())?;
    let remote = "use serde::Serialize;\nuse std::collections::BTreeMap;\n\
        #[derive(Serialize)]\npub struct Reg {\n\
          pub ok: BTreeMap<RemoteGrantId, u64>,\n\
          pub bad: BTreeMap<RemoteRowId, u64>,\n\
        }\n";
    let f = fixture_findings(dir, remote)?;
    let fields: Vec<&str> = f.iter().map(|x| x.field.as_str()).collect();
    if fields != ["bad"] {
        failures.push(format!(
            "cross-file alias resolution wrong, findings on {fields:?}"
        ));
    }
    // 4c. The same alias name with two targets, used as a map key, is refused.
    fs::write(
        dir.join("src/aliases2.rs"),
        "pub type RemoteGrantId = [u8; 32];\n",
    )
    .map_err(|e| e.to_string())?;
    match run(dir) {
        Err(msg) if msg.contains("two different targets") => {}
        other => failures.push(format!("ambiguous alias was not refused: {other:?}")),
    }
    fs::remove_file(dir.join("src/aliases2.rs")).map_err(|e| e.to_string())?;
    fs::remove_file(dir.join("src/aliases.rs")).map_err(|e| e.to_string())?;

    // 5. A map hidden inside Option / Vec / a map value is still seen.
    let nested = "use serde::Serialize;\nuse std::collections::{BTreeMap, HashMap};\n\
        #[derive(Serialize)]\npub struct Reg {\n\
          pub a: Option<HashMap<[u8; 32], u64>>,\n\
          pub b: Vec<BTreeMap<(u32, u32), u64>>,\n\
          pub c: BTreeMap<String, BTreeMap<[u8; 16], u64>>,\n\
        }\n";
    if fixture_findings(dir, nested)?.len() != 3 {
        failures.push(String::from("a wrapped or nested map was not seen"));
    }

    // 6. No derive, no finding: a hand-written impl chooses its own encoding.
    let no_derive = "use std::collections::BTreeMap;\n\
        pub struct Reg { pub rows: BTreeMap<[u8; 32], u64> }\n";
    if !fixture_findings(dir, no_derive)?.is_empty() {
        failures.push(String::from(
            "a struct without derive(Serialize) was flagged",
        ));
    }

    // 7. A struct inside an inline module is scanned.
    let inner = "mod inner {\n  use serde::Serialize;\n  use std::collections::BTreeMap;\n\
        #[derive(Serialize)]\n  pub struct Reg { pub rows: BTreeMap<[u8; 32], u64> }\n}\n";
    if fixture_findings(dir, inner)?.len() != 1 {
        failures.push(String::from("a struct inside an inline module was missed"));
    }

    Ok(())
}

/// # Errors
///
/// Returns a description of every canary that did not behave.
pub fn self_test() -> Result<String, String> {
    let dir = scratch_dir()?;
    fs::write(dir.join("src/filler.rs"), filler()).map_err(|e| e.to_string())?;
    let mut failures: Vec<String> = Vec::new();

    // 1. A byte-keyed map in a Serialize struct is a finding.
    let bytes_key = "use serde::Serialize;\nuse std::collections::BTreeMap;\n\
        #[derive(Debug, Clone, Serialize)]\npub struct Reg { pub rows: BTreeMap<[u8; 32], u64> }\n";
    let f = fixture_findings(&dir, bytes_key)?;
    if f.len() != 1 || f[0].key != "[u8; 32]" {
        failures.push(format!("byte key not caught: {f:?}"));
    }

    // 2. The same field with `serde(with)` is fine.
    let with = bytes_key.replace(
        "pub rows:",
        "#[serde(with = \"crate::core::map_keys\")]\n    pub rows:",
    );
    if !fixture_findings(&dir, &with)?.is_empty() {
        failures.push(String::from("a field with serde(with) was flagged"));
    }

    // 3. `serialize_with` and `skip` also count as handled.
    for attr in ["serialize_with = \"f\"", "skip", "skip_serializing"] {
        let src = bytes_key.replace("pub rows:", &format!("#[serde({attr})]\n    pub rows:"));
        if !fixture_findings(&dir, &src)?.is_empty() {
            failures.push(format!("a field with serde({attr}) was flagged"));
        }
    }

    alias_and_shape_canaries(&dir, &mut failures)?;

    // 8. The vacuity floor fires on a near-empty tree.
    let empty = scratch_dir()?;
    fs::write(
        empty.join("src/a.rs"),
        "use std::collections::BTreeMap;\npub struct Reg { pub rows: BTreeMap<[u8; 32], u64> }\n",
    )
    .map_err(|e| e.to_string())?;
    if run(&empty).is_ok() {
        failures.push(String::from(
            "a near-empty tree passed (vacuity floor did not fire)",
        ));
    }
    let _ = fs::remove_dir_all(&empty);

    // 9. A file that does not parse is a hard error, not a silent skip.
    fs::write(dir.join("src/probe.rs"), "pub struct {").map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        failures.push(String::from("an unparsable file was skipped silently"));
    }

    let _ = fs::remove_dir_all(&dir);
    if failures.is_empty() {
        Ok(String::from(
            "serialize-map-keys-are-strings self-test OK: 11 canaries behaved.",
        ))
    } else {
        Err(format!(
            "serialize-map-keys-are-strings self-test FAILED:\n  {}",
            failures.join("\n  ")
        ))
    }
}
