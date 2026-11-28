//! Every canonical external consensus family must be reachable from the
//! production registration door.
//!
//! # What this measures
//!
//! `ExternalVerifierFamily` in `src/domain/finality_proof_model.rs` is the
//! canonical list of external consensus families this node claims to verify:
//! each variant owns a `consensus_kind` string, a descriptor profile
//! (`verify_descriptor`) and a place in the shared proof model. It is the
//! public statement of what "consensus of consensuses" covers.
//!
//! A family is only *reachable* if a chain can actually admit a domain of
//! that family. There is exactly one production path that admits one:
//!
//! ```text
//! ExternalDomainTx::Register { spec, .. }
//!   -> IntakeState::register_domain(spec, ..)        (intake.rs)
//!   -> AdapterSpec::build(..) -> Box<dyn ExternalFinalityAdapter>
//!   -> adapter.descriptor().consensus_kind
//!   -> ExternalDomainRegistry::register(..)
//! ```
//!
//! So the reachable set is exactly the set of `consensus_kind` strings the
//! adapters built by `AdapterSpec::build` declare. A family whose
//! `consensus_kind` is produced by no `AdapterSpec` arm has a verifier, a
//! profile and a shape, but **no door**: no transaction can ever install it.
//! That is a reachability claim the tree makes in its model and does not keep
//! at its door, and nothing else in the gate set measures it.
//!
//! # Why a gate rather than a note
//!
//! The gap is invisible from either side. Reading `finality_proof_model.rs`
//! shows a family list; reading `intake.rs` shows a spec list; only the join
//! shows that the lists differ. Each new adapter is written in its own module
//! and registers its canonical kind there, so the join drifts silently every
//! time a family is added without a spec variant.
//!
//! # How it reads the tree
//!
//! `syn`, not substrings. Three passes:
//!
//!   1. `ExternalVerifierFamily` variants and the `consensus_kind()` match,
//!      from the proof model.
//!   2. `AdapterSpec` variants and the `AdapterSpec::build` match arms, from
//!      intake; each arm is reduced to the adapter type it constructs.
//!   3. For each adapter type, the `consensus_kind: "..."` literal inside an
//!      `impl` block for that type, across `src/cross_domain/external/*.rs`.
//!
//! The gate is fail-closed in both directions: an arm whose adapter type
//! cannot be resolved, and an adapter type whose `consensus_kind` cannot be
//! found, are both failures. An unresolved join must never read as "covered".

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use quote::ToTokens;
use syn::{Expr, Item, Lit};

const MODEL: &str = "src/domain/finality_proof_model.rs";
const INTAKE: &str = "src/cross_domain/external/intake.rs";
const EXTERNAL_DIR: &str = "src/cross_domain/external";

fn parse(root: &Path, rel: &str) -> Result<syn::File, String> {
    let path = root.join(rel);
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("{rel} could not be read: {e}"))?;
    syn::parse_file(&text).map_err(|e| format!("{rel} does not parse: {e}"))
}

/// Walk every item, including items nested in `mod` blocks.
fn walk_items<'a>(items: &'a [Item], out: &mut Vec<&'a Item>) {
    for item in items {
        out.push(item);
        if let Item::Mod(m) = item {
            if let Some((_, inner)) = &m.content {
                walk_items(inner, out);
            }
        }
    }
}

fn flat_items(file: &syn::File) -> Vec<&Item> {
    let mut out = Vec::new();
    walk_items(&file.items, &mut out);
    out
}

/// The canonical families and the `consensus_kind` each one claims.
fn canonical_families(root: &Path) -> Result<BTreeMap<String, String>, String> {
    let file = parse(root, MODEL)?;
    let items = flat_items(&file);

    let mut names: Vec<String> = Vec::new();
    for item in &items {
        if let Item::Enum(e) = item {
            if e.ident == "ExternalVerifierFamily" {
                names = e.variants.iter().map(|v| v.ident.to_string()).collect();
            }
        }
    }
    if names.is_empty() {
        return Err(format!("{MODEL}: enum ExternalVerifierFamily not found"));
    }

    // `const fn consensus_kind(self) -> &'static str { match self { .. } }`
    let mut kinds: BTreeMap<String, String> = BTreeMap::new();
    for item in &items {
        let Item::Impl(imp) = item else { continue };
        if imp.self_ty.to_token_stream().to_string() != "ExternalVerifierFamily" {
            continue;
        }
        for sub in &imp.items {
            let syn::ImplItem::Fn(f) = sub else { continue };
            if f.sig.ident != "consensus_kind" {
                continue;
            }
            for stmt in &f.block.stmts {
                let syn::Stmt::Expr(expr, _) = stmt else {
                    continue;
                };
                let Expr::Match(m) = expr else { continue };
                for arm in &m.arms {
                    let variant = arm
                        .pat
                        .to_token_stream()
                        .to_string()
                        .replace(' ', "")
                        .trim_start_matches("Self::")
                        .to_string();
                    if let Expr::Lit(l) = &*arm.body {
                        if let Lit::Str(s) = &l.lit {
                            kinds.insert(variant, s.value());
                        }
                    }
                }
            }
        }
    }

    let mut out = BTreeMap::new();
    for name in names {
        let Some(kind) = kinds.get(&name) else {
            return Err(format!(
                "{MODEL}: ExternalVerifierFamily::{name} has no consensus_kind arm"
            ));
        };
        out.insert(name, kind.clone());
    }
    Ok(out)
}

/// Every `AdapterSpec` variant, and the adapter type its `build` arm
/// constructs. An arm that constructs nothing resolves to `None`, which the
/// caller treats as a failure rather than as coverage.
fn spec_arms(root: &Path) -> Result<BTreeMap<String, Option<String>>, String> {
    let file = parse(root, INTAKE)?;
    let items = flat_items(&file);

    let mut variants: Vec<String> = Vec::new();
    for item in &items {
        if let Item::Enum(e) = item {
            if e.ident == "AdapterSpec" {
                variants = e.variants.iter().map(|v| v.ident.to_string()).collect();
            }
        }
    }
    if variants.is_empty() {
        return Err(format!("{INTAKE}: enum AdapterSpec not found"));
    }

    let mut built: BTreeMap<String, Option<String>> = BTreeMap::new();
    for item in &items {
        let Item::Impl(imp) = item else { continue };
        if imp.self_ty.to_token_stream().to_string() != "AdapterSpec" {
            continue;
        }
        for sub in &imp.items {
            let syn::ImplItem::Fn(f) = sub else { continue };
            if f.sig.ident != "build" {
                continue;
            }
            for stmt in &f.block.stmts {
                let syn::Stmt::Expr(expr, _) = stmt else {
                    continue;
                };
                let Expr::Match(m) = expr else { continue };
                for arm in &m.arms {
                    let pat = arm.pat.to_token_stream().to_string().replace(' ', "");
                    let Some(variant) = pat
                        .strip_prefix("Self::")
                        .map(|p| {
                            p.chars()
                                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                                .collect::<String>()
                        })
                        .filter(|v| !v.is_empty())
                    else {
                        continue;
                    };
                    built.insert(variant, adapter_type_in(&arm.body));
                }
            }
        }
    }

    let mut out = BTreeMap::new();
    for v in variants {
        let arm = built.get(&v).cloned().ok_or_else(|| {
            format!("{INTAKE}: AdapterSpec::{v} has no arm in AdapterSpec::build")
        })?;
        out.insert(v, arm);
    }
    Ok(out)
}

/// The adapter type a build arm constructs.
///
/// Constructor names are not uniform across the arms (`new`, `new_pinned`,
/// `new_optional`, a `pinned.build_adapter(..)` helper), so the arm is not
/// matched on a function name. Every `<Type>::<assoc>` path in the arm whose
/// `Type` ends in `Adapter` is collected instead; each arm names its adapter
/// type at least once, through its constructor or through the
/// `<Type>::with_golden` rebuild handle `box_with_golden` takes.
///
/// Fail-closed: zero candidates, or two different adapter types in one arm,
/// resolve to `None`. A reader cannot tell which family such an arm admits,
/// so neither may the gate.
fn adapter_type_in(body: &Expr) -> Option<String> {
    let text = body.to_token_stream().to_string().replace(' ', "");
    let bytes = text.as_bytes();
    let mut found: BTreeSet<String> = BTreeSet::new();
    let mut from = 0usize;
    while let Some(i) = text[from..].find("::") {
        let at = from + i;
        from = at + 2;
        let start = text[..at]
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .map_or(0, |i| i + 1);
        let ty = &text[start..at];
        // The segment may be the tail of a fully qualified path
        // (`crate::..::module::TypeAdapter::new`); the type is the segment
        // immediately before the `::`, wherever the path started.
        if !ty.ends_with("Adapter") || !ty.starts_with(|c: char| c.is_ascii_uppercase()) {
            continue;
        }
        // `Type::assoc` only: a trailing `::<` turbofish is not a call here.
        if bytes
            .get(from)
            .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_')
        {
            found.insert(ty.to_string());
        }
    }
    if found.len() == 1 {
        found.into_iter().next()
    } else {
        None
    }
}

/// `adapter type -> consensus_kind` strings declared inside an `impl` for
/// that type, over the whole external adapter directory.
fn declared_kinds(root: &Path) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let dir = root.join(EXTERNAL_DIR);
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .map_err(|e| format!("{EXTERNAL_DIR} could not be listed: {e}"))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    entries.sort();

    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for path in entries {
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("{} could not be read: {e}", path.display()))?;
        let Ok(file) = syn::parse_file(&text) else {
            // Parseability is another gate's job; an unparsed file simply
            // contributes nothing here, and a family left uncovered by it
            // still fails this gate.
            continue;
        };
        for item in flat_items(&file) {
            let Item::Impl(imp) = item else { continue };
            let ty = imp.self_ty.to_token_stream().to_string().replace(' ', "");
            let ty = ty.split('<').next().unwrap_or(&ty).to_string();
            let body = imp.to_token_stream().to_string();
            for kind in kind_literals(&body) {
                out.entry(ty.clone()).or_default().insert(kind);
            }
        }
    }
    Ok(out)
}

/// `consensus_kind : "literal"` occurrences in a token-stream rendering.
fn kind_literals(tokens: &str) -> Vec<String> {
    let mut out = Vec::new();
    let needle = "consensus_kind :";
    let mut from = 0;
    while let Some(i) = tokens[from..].find(needle) {
        let at = from + i + needle.len();
        from = at;
        let rest = tokens[at..].trim_start();
        if !rest.starts_with('"') {
            continue;
        }
        let body = &rest[1..];
        let Some(end) = body.find('"') else { continue };
        out.push(body[..end].to_string());
    }
    out
}

/// The three tables that must name every `AdapterSpec` variant one by one.
///
/// Each is `(file, function, what a default arm would cost)`. They are not
/// checked for completeness here: `rustc` already refuses a non-exhaustive
/// match, and re-implementing that would be a second mechanism beside the
/// compiler. What the compiler cannot defend is the *condition* that makes
/// its check meaningful - a single `_ =>` arm silently restores
/// exhaustiveness and turns "the tree will not build until you handle the new
/// family" into "the new family quietly gets a default".
///
/// That is exactly how a family can end up admitted by the door with no
/// signed preimage of its pin, or with a finality ceiling it never earned.
const EXHAUSTIVE_TABLES: &[(&str, &str, &str)] = &[
    (
        "src/cross_domain/external/intake.rs",
        "pub fn build(",
        "a new family would build no adapter",
    ),
    (
        "src/core/transaction.rs",
        "fn encode_adapter_spec(",
        "a new family's pin would stay outside the signature preimage",
    ),
    (
        "src/settlement/universal_finality.rs",
        "fn for_external_spec_declared(",
        "a new family would inherit a finality ceiling it never earned",
    ),
];

/// The balanced body of the first item whose header matches `header`.
fn function_body(text: &str, header: &str) -> Option<String> {
    let start = text.find(header)?;
    let open = text[start..].find('{')? + start;
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(text[open..=i].to_string());
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Is `line` a wildcard match arm (`_ =>`), ignoring comments?
fn is_wildcard_arm(line: &str) -> bool {
    let code = line.split("//").next().unwrap_or("");
    let trimmed = code.trim_start();
    let Some(rest) = trimmed.strip_prefix('_') else {
        return false;
    };
    let rest = rest.trim_start();
    // `_ =>` is a wildcard; `_name =>` and `_ if cond =>` are not the same
    // thing, but a guarded wildcard still leaves an unguarded fall-through
    // only when a later bare `_` exists, which this same check would catch.
    rest.starts_with("=>")
}

fn check_exhaustive_tables(root: &Path) -> Result<usize, String> {
    let mut checked = 0usize;
    for (rel, header, cost) in EXHAUSTIVE_TABLES {
        let text = std::fs::read_to_string(root.join(rel))
            .map_err(|e| format!("{rel} could not be read: {e}"))?;
        let body = function_body(&text, header).ok_or_else(|| {
            format!("{rel}: `{header}` not found; the exhaustive-table list is stale")
        })?;
        if let Some(line) = body.lines().find(|l| is_wildcard_arm(l)) {
            return Err(format!(
                "{rel}: `{header}` carries a wildcard arm (`{}`). Remove it and name every                  AdapterSpec variant: with a default arm, {cost}, and the compiler stops                  reporting the omission.",
                line.trim()
            ));
        }
        checked += 1;
    }
    Ok(checked)
}

/// Which `AdapterSpec` arms of `for_external_spec_declared` may bind an event
/// root, and therefore may reach `admits_cross_domain_value`.
///
/// # Why this list exists
///
/// `FinalityGuarantee::admits_cross_domain_value` refuses before it looks at
/// anything else unless `attestation.event_root` is set:
///
/// ```text
/// if !self.attestation.event_root || self.fault_tolerance_bps == 0 { return false; }
/// if self.slashable_backing { return true; }
/// ```
///
/// An event root is the claim "this event happened on that chain". It is the
/// only binding that lets a foreign domain move value here, and most proof
/// families cannot make it: an SCP externalise message, a Mithril certificate
/// or a vault signature set commits to a block or a state root, not to an
/// event. Declaring `event_root: true` for such a family would hand it value
/// authority its proof does not support.
///
/// The list is therefore a value-authority boundary, not a style rule, and it
/// is deliberately short. Adding a name to it is a change to who may move
/// value across domains and must be argued on that basis.
const EVENT_ROOT_BEARING_SPECS: &[&str] = &[
    // A chained-HotStuff QC signs the whole commitment, event root included.
    "HotStuffQc",
    // A Bullshark certificate carries the same full-commitment signature.
    "DagCertificate",
    // Mysticeti commits the full block contents it certifies.
    "MysticetiDag",
    // A BitVM2 covenant disproof binds the executed program's outputs.
    "BitVmCovenant",
    // HoneyBadger's ACS output is the agreed block in full.
    "HoneyBadgerBft",
];

/// Refuse an arm that starts binding an event root without being on the list.
///
/// The check is textual on purpose: it reads the same `for_external_spec_declared`
/// arms a reviewer reads, and the question it answers ("did this arm gain the
/// ability to set `event_root`?") is a question about the written table.
fn check_event_root_authority(root: &Path) -> Result<usize, String> {
    const REL: &str = "src/settlement/universal_finality.rs";
    let text = std::fs::read_to_string(root.join(REL))
        .map_err(|e| format!("{REL} could not be read: {e}"))?;
    let body = function_body(&text, "fn for_external_spec_declared(")
        .ok_or_else(|| format!("{REL}: fn for_external_spec_declared( not found"))?;

    // Split the match into per-variant segments: each starts at an
    // `AdapterSpec::<Name>` mention and runs to the next one.
    let marks: Vec<(usize, String)> = body
        .match_indices("AdapterSpec::")
        .map(|(i, _)| {
            let rest = &body[i + "AdapterSpec::".len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            (i, name)
        })
        .collect();
    if marks.is_empty() {
        return Err(format!(
            "{REL}: for_external_spec_declared names no variants"
        ));
    }

    let mut bearers: Vec<String> = Vec::new();
    for (idx, (pos, name)) in marks.iter().enumerate() {
        let end = marks.get(idx + 1).map_or(body.len(), |(p, _)| *p);
        let seg = &body[*pos..end];
        let Some(at) = seg.find("event_root:") else {
            continue;
        };
        let value: String = seg[at + "event_root:".len()..]
            .chars()
            .take_while(|c| *c != ',' && *c != '\n')
            .collect();
        if value.trim() != "false" {
            bearers.push(name.clone());
        }
    }

    let mut unexpected: Vec<&String> = bearers
        .iter()
        .filter(|n| !EVENT_ROOT_BEARING_SPECS.contains(&n.as_str()))
        .collect();
    unexpected.sort();
    unexpected.dedup();
    if !unexpected.is_empty() {
        return Err(format!(
            "{REL}: {} now bind an event root without being declared event-root bearing.              An event root is what lets a foreign domain move value here              (admits_cross_domain_value refuses without it), so this is a change to who holds              value authority. Argue it, then add the name to EVENT_ROOT_BEARING_SPECS.",
            unexpected
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let mut missing: Vec<&&str> = EVENT_ROOT_BEARING_SPECS
        .iter()
        .filter(|n| !bearers.iter().any(|b| b == *n))
        .collect();
    missing.sort();
    if !missing.is_empty() {
        return Err(format!(
            "{REL}: {} are listed as event-root bearing but their arms pin event_root to false.              Remove them from EVENT_ROOT_BEARING_SPECS rather than leaving a stale entry that              would silently authorise a future change.",
            missing
                .iter()
                .map(|s| **s)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok(bearers.len())
}

/// The declared order of `AdapterSpec` must equal its signature wire tags.
///
/// # Two numbers for one variant
///
/// An `AdapterSpec` is written down twice. It is persisted with bincode,
/// which identifies a variant by its **declaration index**, and it is hashed
/// into the registration's signature preimage by `encode_adapter_spec`, which
/// writes an **explicit tag byte**. Nothing in the language ties the two
/// together.
///
/// While they agree, a stored registration and a signed registration mean the
/// same thing. If they ever diverge - a variant inserted in the middle, or a
/// tag renumbered - a spec read back from the database would be a different
/// variant from the one whose signature was checked, and neither side would
/// report an error. Both numbers are append-only for the same reason.
///
/// The check is deliberately strict: index `i` must carry tag `i`, with no
/// gaps. A gap would mean a variant was deleted rather than retired, which
/// silently shifts every bincode index after it.
fn check_tag_order(root: &Path) -> Result<usize, String> {
    const REL: &str = "src/core/transaction.rs";
    let intake = parse(root, INTAKE)?;
    let mut variants: Vec<String> = Vec::new();
    for item in flat_items(&intake) {
        if let Item::Enum(e) = item {
            if e.ident == "AdapterSpec" {
                variants = e.variants.iter().map(|v| v.ident.to_string()).collect();
            }
        }
    }
    if variants.is_empty() {
        return Err(format!("{INTAKE}: enum AdapterSpec not found"));
    }

    let text = std::fs::read_to_string(root.join(REL))
        .map_err(|e| format!("{REL} could not be read: {e}"))?;
    let body = function_body(&text, "fn encode_adapter_spec(")
        .ok_or_else(|| format!("{REL}: fn encode_adapter_spec( not found"))?;

    // Per-variant segments, in source order; the tag is the first `put_u8`.
    let marks: Vec<(usize, String)> = body
        .match_indices("AdapterSpec::")
        .map(|(i, _)| {
            let rest = &body[i + "AdapterSpec::".len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            (i, name)
        })
        .collect();

    for (index, variant) in variants.iter().enumerate() {
        let Some((pos, _)) = marks.iter().find(|(_, n)| n == variant) else {
            return Err(format!(
                "{REL}: AdapterSpec::{variant} has no arm in encode_adapter_spec, so it is                  persisted at bincode index {index} with no signed tag at all"
            ));
        };
        let end = marks
            .iter()
            .find(|(p, _)| *p > *pos)
            .map_or(body.len(), |(p, _)| *p);
        let seg = &body[*pos..end];
        let Some(at) = seg.find("put_u8(out, ") else {
            return Err(format!("{REL}: AdapterSpec::{variant} writes no wire tag"));
        };
        let digits: String = seg[at + "put_u8(out, ".len()..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        let tag: usize = digits
            .parse()
            .map_err(|_| format!("{REL}: AdapterSpec::{variant} writes a non-literal wire tag"))?;
        if tag != index {
            return Err(format!(
                "{REL}: AdapterSpec::{variant} is bincode index {index} but signs wire tag                  {tag}. The persisted variant and the signed variant must be the same number:                  a spec read back from storage would otherwise verify as a different consensus                  family. Append new variants at the end and never renumber a tag."
            ));
        }
    }
    Ok(variants.len())
}

/// # Errors
///
/// A canonical consensus family that no `AdapterSpec` variant can admit, a
/// build arm whose adapter type cannot be resolved, an adapter type whose
/// `consensus_kind` is not declared in its own module, or one of the three
/// per-variant tables growing a wildcard arm.
pub fn run(root: &Path) -> Result<String, String> {
    let families = canonical_families(root)?;
    let specs = spec_arms(root)?;
    let kinds = declared_kinds(root)?;

    let mut unresolved: Vec<String> = Vec::new();
    let mut reachable: BTreeMap<String, String> = BTreeMap::new();
    for (variant, adapter) in &specs {
        let Some(adapter) = adapter else {
            unresolved.push(format!(
                "AdapterSpec::{variant} build arm constructs no adapter type"
            ));
            continue;
        };
        let Some(declared) = kinds.get(adapter) else {
            unresolved.push(format!(
                "AdapterSpec::{variant} builds {adapter}, which declares no consensus_kind"
            ));
            continue;
        };
        for kind in declared {
            reachable.insert(kind.clone(), variant.clone());
        }
    }

    let mut doorless: Vec<(&String, &String)> = families
        .iter()
        .filter(|(_, kind)| !reachable.contains_key(*kind))
        .collect();
    doorless.sort();

    if !unresolved.is_empty() || !doorless.is_empty() {
        let mut msg = String::new();
        let _ = writeln!(
            msg,
            "{} of {} canonical consensus families are reachable from AdapterSpec.",
            families.len() - doorless.len(),
            families.len()
        );
        for (family, kind) in &doorless {
            let _ = writeln!(
                msg,
                "  no door: ExternalVerifierFamily::{family} (\"{kind}\") has a verifier and a \
                 profile, but no AdapterSpec variant builds an adapter that declares it, so \
                 ExternalDomainTx::Register can never admit a domain of this family"
            );
        }
        for u in &unresolved {
            let _ = writeln!(msg, "  unresolved: {u}");
        }
        let _ = write!(
            msg,
            "Add the AdapterSpec variant (with its build, network and signature-preimage arms), \
             or delete the family from ExternalVerifierFamily. A family the model names and the \
             door refuses is a claim the node cannot keep."
        );
        return Err(msg);
    }

    let tables = check_exhaustive_tables(root)?;
    let bearers = check_event_root_authority(root)?;
    let ordered = check_tag_order(root)?;

    Ok(format!(
        "every consensus family has a door: {} canonical families, {} AdapterSpec variants, {} \
         reachable consensus_kind(s); the model and the registration door agree, {tables} \
         per-variant tables stay exhaustive by construction, {bearers} declared families \
         may bind an event root, and {ordered} variants carry the same number as a bincode \
         index and as a signed wire tag",
        families.len(),
        specs.len(),
        reachable.len()
    ))
}

fn write_canary_tree(
    dir: &Path,
    families: &str,
    kind_arms: &str,
    variants: &str,
    build_arms: &str,
    adapters: &str,
) -> Result<(), String> {
    let model_dir = dir.join("src/domain");
    let ext_dir = dir.join(EXTERNAL_DIR);
    let core_dir = dir.join("src/core");
    let settlement_dir = dir.join("src/settlement");
    std::fs::create_dir_all(&model_dir).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&ext_dir).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&core_dir).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&settlement_dir).map_err(|e| e.to_string())?;

    let model_src = format!(
        "pub enum ExternalVerifierFamily {{\n{families}}}\n\
         impl ExternalVerifierFamily {{\n    \
         pub const fn consensus_kind(self) -> &'static str {{\n        \
         match self {{\n{kind_arms}        }}\n    }}\n}}\n"
    );
    let intake_src = format!(
        "pub enum AdapterSpec {{\n{variants}}}\n\
         impl AdapterSpec {{\n    pub fn build(&self) -> u8 {{\n        \
         match self {{\n{build_arms}        }}\n    }}\n}}\n"
    );
    std::fs::write(model_dir.join("finality_proof_model.rs"), model_src)
        .map_err(|e| e.to_string())?;
    std::fs::write(ext_dir.join("intake.rs"), intake_src).map_err(|e| e.to_string())?;
    std::fs::write(ext_dir.join("adapters.rs"), adapters).map_err(|e| e.to_string())?;
    std::fs::write(
        core_dir.join("transaction.rs"),
        "fn encode_adapter_spec(s: &AdapterSpec) {\n    match s {\n        AdapterSpec::AlphaSpec { .. } => { put_u8(out, 0); }\n    }\n}\n",
    )
    .map_err(|e| e.to_string())?;
    let mut settlement_src =
        String::from("fn for_external_spec_declared(s: &AdapterSpec) {\n    match s {\n");
    for bearer in EVENT_ROOT_BEARING_SPECS {
        let _ = writeln!(
            settlement_src,
            "        AdapterSpec::{bearer} {{ .. }} => Self {{ event_root: valid, }},"
        );
    }
    settlement_src.push_str(
        "        AdapterSpec::AlphaSpec { .. } => Self { event_root: false, },\n    }\n}\n",
    );
    std::fs::write(settlement_dir.join("universal_finality.rs"), settlement_src)
        .map_err(|e| e.to_string())
}

fn self_test_door_canaries(dir: &Path) -> Result<(), String> {
    // Canary 1 - honest tree: one family, one spec, one adapter that declares
    // the family's kind. Must pass.
    write_canary_tree(
        dir,
        "    Alpha,\n",
        "            Self::Alpha => \"alpha-bft\",\n",
        "    AlphaSpec { network: String },\n",
        "            Self::AlphaSpec { .. } => AlphaAdapter::new(1),\n",
        "impl AlphaAdapter {\n    fn d(&self) -> D {\n        D { consensus_kind: \"alpha-bft\".to_string() }\n    }\n}\n",
    )?;
    if let Err(e) = run(dir) {
        return Err(format!("canary 1: an honest tree was rejected: {e}"));
    }

    // Canary 2 - a family with no door. Must fail and name the family.
    write_canary_tree(
        dir,
        "    Alpha,\n    Beta,\n",
        "            Self::Alpha => \"alpha-bft\",\n            Self::Beta => \"beta-pow\",\n",
        "    AlphaSpec { network: String },\n",
        "            Self::AlphaSpec { .. } => AlphaAdapter::new(1),\n",
        "impl AlphaAdapter {\n    fn d(&self) -> D {\n        D { consensus_kind: \"alpha-bft\".to_string() }\n    }\n}\n",
    )?;
    match run(dir) {
        Ok(_) => {
            return Err(String::from(
                "canary 2: a family with no AdapterSpec variant was accepted",
            ));
        }
        Err(e) if !e.contains("Beta") => {
            return Err(format!("canary 2: failed without naming the family: {e}"));
        }
        Err(_) => {}
    }

    // Canary 3 - the spec exists but builds an adapter that declares a
    // different kind. Coverage must not be inferred from the variant name.
    write_canary_tree(
        dir,
        "    Beta,\n",
        "            Self::Beta => \"beta-pow\",\n",
        "    Beta { network: String },\n",
        "            Self::Beta { .. } => AlphaAdapter::new(1),\n",
        "impl AlphaAdapter {\n    fn d(&self) -> D {\n        D { consensus_kind: \"alpha-bft\".to_string() }\n    }\n}\n",
    )?;
    if run(dir).is_ok() {
        return Err(String::from(
            "canary 3: a same-named spec building a foreign adapter was accepted",
        ));
    }

    // Canary 4 - a build arm that constructs nothing must be unresolved.
    write_canary_tree(
        dir,
        "    Alpha,\n",
        "            Self::Alpha => \"alpha-bft\",\n",
        "    Alpha { network: String },\n",
        "            Self::Alpha { .. } => 0u8,\n",
        "impl AlphaAdapter {\n    fn d(&self) -> D {\n        D { consensus_kind: \"alpha-bft\".to_string() }\n    }\n}\n",
    )?;
    match run(dir) {
        Ok(_) => {
            return Err(String::from(
                "canary 4: a build arm constructing no adapter was accepted as a door",
            ));
        }
        Err(e) if !e.contains("unresolved") && !e.contains("no door") => {
            return Err(format!("canary 4: failed for the wrong reason: {e}"));
        }
        Err(_) => {}
    }

    // Canary 5 - an adapter type with no declared consensus_kind is unresolved.
    write_canary_tree(
        dir,
        "    Alpha,\n",
        "            Self::Alpha => \"alpha-bft\",\n",
        "    Alpha { network: String },\n",
        "            Self::Alpha { .. } => GhostAdapter::new(1),\n",
        "impl AlphaAdapter {\n    fn d(&self) -> D {\n        D { consensus_kind: \"alpha-bft\".to_string() }\n    }\n}\n",
    )?;
    if run(dir).is_ok() {
        return Err(String::from(
            "canary 5: an adapter declaring no consensus_kind was accepted as a door",
        ));
    }

    Ok(())
}

fn self_test_wildcard_canaries(dir: &Path) -> Result<(), String> {
    write_canary_tree(
        dir,
        "    Alpha,\n",
        "            Self::Alpha => \"alpha-bft\",\n",
        "    AlphaSpec { network: String },\n",
        "            Self::AlphaSpec { .. } => AlphaAdapter::new(1),\n",
        "impl AlphaAdapter {\n    fn d(&self) -> D {\n        D { consensus_kind: \"alpha-bft\".to_string() }\n    }\n}\n",
    )?;
    std::fs::write(
        dir.join("src/core/transaction.rs"),
        "fn encode_adapter_spec(s: &AdapterSpec) {\n    match s {\n        AdapterSpec::AlphaSpec { .. } => 0,\n        _ => 1,\n    }\n}\n",
    )
    .map_err(|e| e.to_string())?;
    match run(dir) {
        Ok(_) => {
            return Err(String::from(
                "canary 6a: a wildcard arm in the signature-preimage table was accepted",
            ));
        }
        Err(e) if !e.contains("wildcard") => {
            return Err(format!("canary 6a: failed for the wrong reason: {e}"));
        }
        Err(_) => {}
    }

    let probe = dir.join("probe.rs");
    std::fs::write(
        &probe,
        "fn build() {\n    match s {\n        Self::A => 1,\n        _ => 0,\n    }\n}\n",
    )
    .map_err(|e| e.to_string())?;
    let text = std::fs::read_to_string(&probe).map_err(|e| e.to_string())?;
    let body = function_body(&text, "fn build(")
        .ok_or_else(|| String::from("canary 6: the probe body was not found"))?;
    if !body.lines().any(is_wildcard_arm) {
        return Err(String::from("canary 6: a real `_ =>` arm was not detected"));
    }
    for honest in [
        "        _name => 0,",
        "        // _ => 0,",
        "        Self::B => 0,",
        "        _unused => 0,",
    ] {
        if is_wildcard_arm(honest) {
            return Err(format!(
                "canary 6: `{honest}` was misread as a wildcard arm"
            ));
        }
    }
    Ok(())
}

fn self_test_event_root_and_tag_canaries(dir: &Path) -> Result<(), String> {
    let settlement = dir.join("src/settlement/universal_finality.rs");
    let table = |hotstuff: &str, alpha: &str| {
        let mut out =
            String::from("fn for_external_spec_declared(s: &AdapterSpec) {\n    match s {\n");
        for bearer in EVENT_ROOT_BEARING_SPECS {
            let value = if *bearer == "HotStuffQc" {
                hotstuff
            } else {
                "valid"
            };
            let _ = writeln!(
                out,
                "        AdapterSpec::{bearer} {{ .. }} => Self {{ event_root: {value}, }},"
            );
        }
        let _ = writeln!(
            out,
            "        AdapterSpec::AlphaSpec {{ .. }} => Self {{ event_root: {alpha}, }},\n    }}\n}}"
        );
        out
    };
    // 8: an undeclared arm starts binding an event root.
    std::fs::write(&settlement, table("valid", "valid")).map_err(|e| e.to_string())?;
    match check_event_root_authority(dir) {
        Ok(_) => {
            return Err(String::from(
                "canary 8: an undeclared arm binding an event root was accepted",
            ));
        }
        Err(e) if !e.contains("AlphaSpec") => {
            return Err(format!("canary 8: failed without naming the arm: {e}"));
        }
        Err(_) => {}
    }
    // 9: a declared bearer stops binding one, leaving a stale entry.
    std::fs::write(&settlement, table("false", "false")).map_err(|e| e.to_string())?;
    match check_event_root_authority(dir) {
        Ok(_) => {
            return Err(String::from(
                "canary 9: a stale event-root entry was accepted",
            ));
        }
        Err(e) if !e.contains("HotStuffQc") => {
            return Err(format!(
                "canary 9: failed without naming the stale entry: {e}"
            ));
        }
        Err(_) => {}
    }

    // Canary 10 - the bincode index and the signed wire tag must be one number.
    let core_tx = dir.join("src/core/transaction.rs");
    std::fs::write(
        &core_tx,
        "fn encode_adapter_spec(s: &AdapterSpec) {\n    match s {\n                 AdapterSpec::AlphaSpec { .. } => { put_u8(out, 7); }\n    }\n}\n",
    )
    .map_err(|e| e.to_string())?;
    match check_tag_order(dir) {
        Ok(_) => {
            return Err(String::from(
                "canary 10: index 0 signing wire tag 7 was accepted",
            ));
        }
        Err(e) if !e.contains("wire tag") => {
            return Err(format!("canary 10: failed for the wrong reason: {e}"));
        }
        Err(_) => {}
    }
    std::fs::write(
        &core_tx,
        "fn encode_adapter_spec(s: &AdapterSpec) {\n    match s {\n                 AdapterSpec::AlphaSpec { .. } => { put_u8(out, 0); }\n    }\n}\n",
    )
    .map_err(|e| e.to_string())?;
    if let Err(e) = check_tag_order(dir) {
        return Err(format!("canary 10: an honest tag order was rejected: {e}"));
    }
    Ok(())
}

pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-ecfhad")?;
    let outcome = self_test_door_canaries(&dir)
        .and_then(|()| self_test_wildcard_canaries(&dir))
        .and_then(|()| self_test_event_root_and_tag_canaries(&dir));
    let _ = std::fs::remove_dir_all(&dir);
    outcome?;
    Ok(String::from(
        "every-consensus-family-has-a-door self-test OK: 10 canaries (honest tree, doorless \
         family, name-only match, empty build arm, undeclared adapter kind, wildcard arm in a \
         per-variant table, underscore-prefixed binding is not a wildcard, undeclared \
         event-root binding, stale event-root entry, wire tag that disagrees with the \
         bincode index)",
    ))
}
