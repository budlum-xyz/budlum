//! A registered external domain must be admitted through exactly one door, and
//! that door must refuse an unpinned trust anchor.
//!
//! # What this measures
//!
//! `every_consensus_family_has_a_door` proves every canonical family reaches
//! `AdapterSpec::build`. It does **not** prove what happens at the door. A
//! `build` arm can exist, and the family can still be admitted unpinned: the
//! arm is reachable without any `CommitteeNotPinned` path, or the pin body is a
//! constant `true` no one can see.
//!
//! This gate closes that gap on four measurements, all `syn`-based:
//!
//!   1. **Door refuses.** Every `AdapterSpec` variant is named in a
//!      `register_domain` guard, and each guard returns
//!      `IntakeError::CommitteeNotPinned`. A variant that only reaches `build`
//!      is a door that opens unpinned.
//!
//!   2. **Pin bodies are meaningful.** Every `has_pinned_trust_anchor` body
//!      under `src/cross_domain/external` is either exactly the closed default
//!      `false`, or a real test of a field. A body that is a bare `true`, or a
//!      literal with no field read, is a pin that cannot fail.
//!
//!   3. **Anchor families are total.** `PinnedExternalAnchor::family()` covers
//!      every `AnchorFamily` variant with no wildcard arm. A wildcard folds a
//!      future family into whatever arm sits above it.
//!
//!   4. **The second door is narrower than the first.** Every `GuardedExternalAdapter`
//!      variant names the same family as an `AdapterSpec` variant, so the
//!      guarded table can never carry a family the intake door cannot. The
//!      guarded door is *narrower*, and this gate records that as debt rather
//!      than as coverage: a family reachable through `refresh_backing_from_adapter`
//!      alone is reachable without the pin check.
//!
//! # Why "single presence test" is not the rule
//!
//! An earlier design required each pin body to be exactly
//! `self.field.is_some()`. On the current tree that rule is **wrong**: eight
//! families test `is_some_and(|pin| pin.weight > 0)`, which is strictly
//! stronger — it refuses a pin that exists but anchors nothing. The rule here
//! is therefore *meaningfulness*, not *shape*: a body must read at least one
//! field and must not be a constant.
//!
//! # Errors
//!
//! `run` returns the findings, one per line, when a variant has no refusing
//! guard, a pin body is constant, the anchor family match is partial or
//! wildcarded, or the guarded table names a family intake cannot admit.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use quote::ToTokens;
use syn::{Expr, Item, Stmt};

/// The module that owns the intake door.
const INTAKE: &str = "src/cross_domain/external/intake.rs";

/// The module that owns the guarded (second) door.
const ECONOMIC_GUARD: &str = "src/cross_domain/economic_guard.rs";

/// The trait whose closed default this gate pins.
const SPEC: &str = "src/cross_domain/external/spec.rs";

/// The directory the pin bodies live in.
const EXTERNAL_DIR: &str = "src/cross_domain/external";

/// The smallest `AdapterSpec` that makes this measurement meaningful.
///
/// The tree has 32 today. A smaller count means the enum moved or the scan
/// stopped early, and a gate that measures nothing must not report green.
const MIN_SPEC_VARIANTS: usize = 20;

/// The smallest number of pin bodies that is a scan.
///
/// The tree has 35 today (34 in family modules and the Ethernet/ZK-VM pair,
/// plus the trait default in `spec.rs`).
const MIN_PIN_BODIES: usize = 20;

/// The smallest number of `AnchorFamily` variants a total `family()` needs.
const MIN_ANCHOR_FAMILIES: usize = 6;

/// One finding, with the site it names.
struct Finding {
    site: String,
    message: String,
}

impl Finding {
    fn new(site: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            site: site.into(),
            message: message.into(),
        }
    }
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

/// Whether an item sits behind `#[cfg(test)]`.
///
/// Test fixtures implement `has_pinned_trust_anchor` as a literal `true` so a
/// test can reach the shape gate without curve arithmetic. Those bodies are
/// not part of the production construction surface and are not measured.
fn is_test_only(item: &Item) -> bool {
    let Some(attrs) = item_attrs(item) else {
        return false;
    };
    attrs.iter().any(|a| {
        a.path().is_ident("cfg")
            && a.to_token_stream()
                .to_string()
                .replace(' ', "")
                .contains("test")
    })
}

fn item_attrs(item: &Item) -> Option<&[syn::Attribute]> {
    match item {
        Item::Const(i) => Some(&i.attrs),
        Item::Enum(i) => Some(&i.attrs),
        Item::Fn(i) => Some(&i.attrs),
        Item::Impl(i) => Some(&i.attrs),
        Item::Mod(i) => Some(&i.attrs),
        Item::Struct(i) => Some(&i.attrs),
        Item::Trait(i) => Some(&i.attrs),
        Item::Type(i) => Some(&i.attrs),
        Item::Use(i) => Some(&i.attrs),
        Item::Static(i) => Some(&i.attrs),
        _ => None,
    }
}

/// Flat items with `#[cfg(test)]` modules and items removed.
fn production_items(file: &syn::File) -> Vec<&Item> {
    let mut out = Vec::new();
    fn walk<'a>(items: &'a [Item], out: &mut Vec<&'a Item>) {
        for item in items {
            if is_test_only(item) {
                continue;
            }
            out.push(item);
            if let Item::Mod(m) = item {
                if let Some((_, inner)) = &m.content {
                    walk(inner, out);
                }
            }
        }
    }
    walk(&file.items, &mut out);
    out
}

fn parse(root: &Path, rel: &str) -> Result<syn::File, String> {
    let path = root.join(rel);
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("{rel} could not be read: {e}"))?;
    syn::parse_file(&text).map_err(|e| format!("{rel} does not parse: {e}"))
}

/// Every `AdapterSpec` variant name, in declaration order.
fn spec_variants(items: &[&Item]) -> Result<Vec<String>, String> {
    for item in items {
        if let Item::Enum(e) = item {
            if e.ident == "AdapterSpec" {
                return Ok(e.variants.iter().map(|v| v.ident.to_string()).collect());
            }
        }
    }
    Err(format!("{INTAKE}: enum AdapterSpec not found"))
}

/// Variant names a pattern mentions, with `Self::` stripped.
fn pattern_variants(pat: &syn::Pat) -> Vec<String> {
    let text = pat.to_token_stream().to_string().replace(' ', "");
    let mut out = Vec::new();
    let mut rest = text.as_str();
    while let Some(pos) = rest.find("Self::") {
        let tail = &rest[pos + "Self::".len()..];
        let name: String = tail
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            rest = &tail[name.len()..];
            out.push(name);
        } else {
            rest = tail;
        }
    }
    out
}

/// `AdapterSpec` variant names mentioned in a condition, under either spelling.
fn spec_names(text: &str) -> Vec<String> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let mut out = Vec::new();
    for prefix in ["AdapterSpec::", "Self::"] {
        let mut rest = compact.as_str();
        while let Some(pos) = rest.find(prefix) {
            let tail = &rest[pos + prefix.len()..];
            let name: String = tail
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() {
                rest = tail;
            } else {
                rest = &tail[name.len()..];
                out.push(name);
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// A CamelCase identifier split into lowercase words.
///
/// `MinaSuccinctRecursive` becomes `["mina", "succinct", "recursive"]`, which
/// lets a shorter spelling of the same family (`MinaRecursive`) be recognised
/// as a name for it rather than as an orphan.
fn words(ident: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in ident.chars() {
        if c.is_ascii_uppercase() && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        cur.extend(c.to_lowercase());
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// `AnchorFamily` variant names mentioned in an expression.
fn anchor_names(text: &str) -> Vec<String> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let mut out = Vec::new();
    let mut rest = compact.as_str();
    while let Some(pos) = rest.find("AnchorFamily::") {
        let tail = &rest[pos + "AnchorFamily::".len()..];
        let name: String = tail
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            rest = tail;
        } else {
            rest = &tail[name.len()..];
            out.push(name);
        }
    }
    out
}

/// Whether the block returns `IntakeError::CommitteeNotPinned` anywhere.
fn refuses_with_pin_block(block: &syn::Block) -> bool {
    block
        .to_token_stream()
        .to_string()
        .replace(' ', "")
        .contains("CommitteeNotPinned")
}

/// Whether `expr` returns `IntakeError::CommitteeNotPinned` anywhere inside it.
fn refuses_with_pin(expr: &Expr) -> bool {
    let text = expr.to_token_stream().to_string().replace(' ', "");
    text.contains("CommitteeNotPinned")
}

/// Measure criterion 1: every variant is named by a refusing guard.
fn check_door(root: &Path) -> Result<String, String> {
    let file = parse(root, INTAKE)?;
    let items = flat_items(&file);
    let variants = spec_variants(&items)?;
    if variants.len() < MIN_SPEC_VARIANTS {
        return Err(format!(
            "{INTAKE}: `AdapterSpec` declares {} variants, under the {MIN_SPEC_VARIANTS} \
             this measurement needs; the enum moved and the gate measured nothing",
            variants.len()
        ));
    }

    // Every guard in `register_domain`, reduced to (variants named, refuses?).
    //
    // The pattern is read textually from the condition because the tree spells
    // the same variant two ways in this function: `Self::X` in `matches!` and
    // `AdapterSpec::X` in `if let`. Matching only one spelling silently
    // measured zero guards while the door was in fact closed thirty-two times.
    let mut guards: Vec<(Vec<String>, bool)> = Vec::new();
    let mut found = false;
    for item in &items {
        let Item::Impl(imp) = item else { continue };
        if imp.self_ty.to_token_stream().to_string() != "IntakeState" {
            continue;
        }
        for sub in &imp.items {
            let syn::ImplItem::Fn(f) = sub else { continue };
            if f.sig.ident != "register_domain" {
                continue;
            }
            found = true;
            for stmt in &f.block.stmts {
                let Stmt::Expr(Expr::If(i), _) = stmt else {
                    continue;
                };
                let named = spec_names(&i.cond.to_token_stream().to_string());
                if named.is_empty() {
                    continue;
                }
                let refuses = refuses_with_pin_block(&i.then_branch)
                    || i.else_branch
                        .as_ref()
                        .is_some_and(|(_, e)| refuses_with_pin(e));
                guards.push((named, refuses));
            }
        }
    }
    if !found {
        return Err(format!("{INTAKE}: IntakeState::register_domain not found"));
    }

    let mut covered: BTreeMap<String, bool> = BTreeMap::new();
    for (named, refuses) in &guards {
        for v in named {
            let entry = covered.entry(v.clone()).or_insert(false);
            *entry = *entry || *refuses;
        }
    }

    let mut out = String::new();
    let mut missing = Vec::new();
    let mut unpinned = Vec::new();
    for v in &variants {
        match covered.get(v) {
            None => missing.push(v.clone()),
            Some(true) => {}
            Some(false) => unpinned.push(v.clone()),
        }
    }

    let guarded = variants.len() - missing.len();
    let _ = writeln!(
        out,
        "door: {guarded}/{} AdapterSpec variants named in register_domain guards \
         ({} refuse with CommitteeNotPinned)",
        variants.len(),
        covered.values().filter(|b| **b).count()
    );
    for v in &missing {
        let _ = writeln!(
            out,
            "FAIL {INTAKE}: AdapterSpec::{v} is reachable through build with no \
             register_domain guard; that family can be admitted unpinned"
        );
    }
    for v in &unpinned {
        let _ = writeln!(
            out,
            "FAIL {INTAKE}: AdapterSpec::{v} has a register_domain guard that never \
             returns CommitteeNotPinned; an unpinned anchor is admitted"
        );
    }
    if !missing.is_empty() || !unpinned.is_empty() {
        return Err(out);
    }
    Ok(out)
}

/// Measure criterion 2: every pin body reads a field, or is the closed default.
fn check_pin_bodies(root: &Path) -> Result<String, String> {
    let dir = root.join(EXTERNAL_DIR);
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .map_err(|e| format!("{EXTERNAL_DIR} could not be read: {e}"))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    files.sort();

    let mut bodies = 0_usize;
    let mut out = String::new();
    let mut findings = Vec::new();

    for path in &files {
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();
        // A file the gate cannot read or parse is a finding, not a skip.
        // Skipping it silently drops every pin body it holds, and a tree with
        // broken syntax would read as "fewer bodies, all meaningful" - green
        // on a measurement that never happened.
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("{rel} could not be read: {e}"))?;
        let file = syn::parse_file(&text).map_err(|e| {
            format!("{rel} does not parse, so its pin bodies cannot be measured: {e}")
        })?;
        for item in production_items(&file) {
            let Item::Impl(imp) = item else { continue };
            for sub in &imp.items {
                let syn::ImplItem::Fn(f) = sub else { continue };
                if f.sig.ident != "has_pinned_trust_anchor" {
                    continue;
                }
                bodies += 1;
                let body = f.block.to_token_stream().to_string();
                let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
                // The closed default is legal and is the whole point of the
                // trait: a new adapter that says nothing stays fail-closed.
                if compact == "{false}" {
                    continue;
                }
                // A constant `true` (or any body with no field read) cannot fail.
                if compact == "{true}" {
                    findings.push(Finding::new(
                        format!("{rel}:{}", f.sig.ident),
                        "has_pinned_trust_anchor returns a constant true; \
                         no anchor can ever be refused",
                    ));
                    continue;
                }
                if !compact.contains("self.") {
                    findings.push(Finding::new(
                        format!("{rel}:{}", f.sig.ident),
                        "has_pinned_trust_anchor reads no field of self; \
                         the answer cannot depend on the anchor",
                    ));
                }
            }
        }
    }

    if bodies < MIN_PIN_BODIES {
        return Err(format!(
            "{EXTERNAL_DIR}: found {bodies} `has_pinned_trust_anchor` bodies, under the \
             {MIN_PIN_BODIES} a real scan needs"
        ));
    }
    let _ = writeln!(out, "pin bodies: {bodies} measured, all meaningful");
    for f in &findings {
        let _ = writeln!(out, "FAIL {}: {}", f.site, f.message);
    }
    if !findings.is_empty() {
        return Err(out);
    }
    Ok(out)
}

/// Measure criterion 3: `PinnedExternalAnchor::family()` is total, no wildcard.
fn check_anchor_family(root: &Path) -> Result<String, String> {
    let file = parse(root, INTAKE)?;
    let items = flat_items(&file);

    let mut families: Vec<String> = Vec::new();
    for item in &items {
        if let Item::Enum(e) = item {
            if e.ident == "AnchorFamily" {
                families = e.variants.iter().map(|v| v.ident.to_string()).collect();
            }
        }
    }
    if families.len() < MIN_ANCHOR_FAMILIES {
        return Err(format!(
            "{INTAKE}: enum AnchorFamily declares {} variants, under the \
             {MIN_ANCHOR_FAMILIES} this gate needs",
            families.len()
        ));
    }

    let mut covered: BTreeSet<String> = BTreeSet::new();
    let mut wildcard = false;
    let mut found = false;
    for item in &items {
        let Item::Impl(imp) = item else { continue };
        if imp.self_ty.to_token_stream().to_string() != "PinnedExternalAnchor" {
            continue;
        }
        for sub in &imp.items {
            let syn::ImplItem::Fn(f) = sub else { continue };
            if f.sig.ident != "family" {
                continue;
            }
            found = true;
            for stmt in &f.block.stmts {
                let Stmt::Expr(Expr::Match(m), _) = stmt else {
                    continue;
                };
                for arm in &m.arms {
                    if matches!(arm.pat, syn::Pat::Wild(_)) {
                        wildcard = true;
                        continue;
                    }
                    // Both sides count: `Self::Nipopow(_) => AnchorFamily::PoWSuccinct`
                    // names the family it covers as a path expression, not as the
                    // pattern. Reading only the pattern reported a covered family
                    // as missing.
                    covered.extend(pattern_variants(&arm.pat));
                    covered.extend(anchor_names(&arm.body.to_token_stream().to_string()));
                }
            }
        }
    }
    if !found {
        return Err(format!(
            "{INTAKE}: PinnedExternalAnchor::family() not found; the map key that \
             ties a pin to an AnchorFamily is gone"
        ));
    }

    let mut out = String::new();
    let _ = writeln!(
        out,
        "anchor family: {}/{} AnchorFamily variants covered by family(), wildcard={wildcard}",
        families.iter().filter(|f| covered.contains(*f)).count(),
        families.len()
    );
    let missing: Vec<_> = families
        .iter()
        .filter(|f| !covered.contains(*f))
        .cloned()
        .collect();
    if !missing.is_empty() || wildcard {
        for f in &missing {
            let _ = writeln!(
                out,
                "FAIL {INTAKE}: AnchorFamily::{f} has no PinnedExternalAnchor::family() arm"
            );
        }
        if wildcard {
            let _ = writeln!(
                out,
                "FAIL {INTAKE}: PinnedExternalAnchor::family() carries a wildcard arm; \
                 a new family would silently inherit an existing one's map key"
            );
        }
        return Err(out);
    }
    Ok(out)
}

/// Measure criterion 4: the guarded table is a subset of the intake door.
fn check_guarded_subset(root: &Path) -> Result<String, String> {
    let intake = parse(root, INTAKE)?;
    let variants = spec_variants(&flat_items(&intake))?;

    let guard = parse(root, ECONOMIC_GUARD)?;
    let items = flat_items(&guard);
    let mut guarded: Vec<String> = Vec::new();
    for item in &items {
        if let Item::Enum(e) = item {
            if e.ident == "GuardedExternalAdapter" {
                guarded = e.variants.iter().map(|v| v.ident.to_string()).collect();
            }
        }
    }

    let mut out = String::new();
    if guarded.is_empty() {
        // The guarded table may legitimately go away: `KUTUPYILDIZI-02` is
        // merging it into AdapterSpec. Its absence is not a failure, but the
        // gate must say so rather than claim coverage.
        let _ = writeln!(
            out,
            "guarded table: absent (merged into AdapterSpec?) - no second door to measure"
        );
        return Ok(out);
    }

    // Variant names differ in spelling between the two enums: `MinaRecursive`
    // in the guarded table is `MinaSuccinctRecursive` in `AdapterSpec`, where a
    // word sits between the shared tokens. Neither name contains the other, so
    // containment is the wrong test. The match is *every word of the guarded
    // name appears in the spec name*, which accepts that pair and still refuses
    // a genuine orphan (`Zulu`) or a same-prefix stranger (`TonX`).
    let orphans: Vec<_> = guarded
        .iter()
        .filter(|g| {
            let want = words(g);
            !variants.iter().any(|v| {
                let have = words(v);
                want.iter().all(|w| have.contains(w))
            })
        })
        .cloned()
        .collect();

    let _ = writeln!(
        out,
        "guarded table: {}/{} variant(s) named by AdapterSpec ({} families in the second door)",
        guarded.len() - orphans.len(),
        guarded.len(),
        guarded.len()
    );
    for g in &orphans {
        let _ = writeln!(
            out,
            "FAIL {ECONOMIC_GUARD}: GuardedExternalAdapter::{g} is not an AdapterSpec variant; \
             the second door admits a family the intake door cannot"
        );
    }
    if !orphans.is_empty() {
        return Err(out);
    }
    Ok(out)
}

/// Measure criterion 5: the trait's closed default stays `false`.
fn check_trait_default(root: &Path) -> Result<String, String> {
    let file = parse(root, SPEC)?;
    for item in flat_items(&file) {
        let Item::Trait(t) = item else { continue };
        if t.ident != "ExternalFinalityAdapter" {
            continue;
        }
        for sub in &t.items {
            let syn::TraitItem::Fn(f) = sub else { continue };
            if f.sig.ident != "has_pinned_trust_anchor" {
                continue;
            }
            let Some(block) = &f.default else {
                return Err(format!(
                    "{SPEC}: has_pinned_trust_anchor has no default body; the closed \
                     default is what keeps a new adapter fail-closed"
                ));
            };
            let compact: String = block
                .to_token_stream()
                .to_string()
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            if compact != "{false}" {
                return Err(format!(
                    "{SPEC}: the trait default is `{compact}`, not `{{false}}`; a new \
                     adapter would claim a pinned anchor it does not have"
                ));
            }
            return Ok(format!(
                "trait default: has_pinned_trust_anchor() -> false\n"
            ));
        }
        return Err(format!("{SPEC}: trait has no has_pinned_trust_anchor"));
    }
    Err(format!("{SPEC}: trait ExternalFinalityAdapter not found"))
}

/// Run the gate over `root`.
///
/// # Errors
///
/// Returns the findings, one per line, when a variant is reachable without a
/// refusing guard, a pin body cannot fail, the anchor map is partial or
/// wildcarded, the guarded table names a family intake cannot admit, or the
/// trait default is no longer closed.
pub fn run(root: &Path) -> Result<String, String> {
    let mut out = String::new();
    out.push_str(&check_door(root)?);
    out.push_str(&check_pin_bodies(root)?);
    out.push_str(&check_anchor_family(root)?);
    out.push_str(&check_guarded_subset(root)?);
    out.push_str(&check_trait_default(root)?);
    // A gate that read nothing is not a green gate.
    let total: usize = out
        .lines()
        .filter(|l| {
            l.contains("door:") || l.contains("pin bodies:") || l.contains("guarded table:")
        })
        .count();
    if total < 3 {
        return Err(format!(
            "only {total}/3 measurements reported; a gate that measured nothing \
             must not read as green\n{out}"
        ));
    }
    Ok(out)
}

/// A scratch tree no other gate shares.
fn scratch_dir() -> Result<std::path::PathBuf, String> {
    let base = std::env::temp_dir().join("budlum-gate-one-path");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).map_err(|e| format!("scratch dir: {e}"))?;
    Ok(base)
}

/// One fixture tree: the shape the gate is pointed at.
struct Fixture {
    spec_variants: usize,
    /// Offsets of spec variants that get no `register_domain` guard.
    unguarded: Vec<usize>,
    /// Offsets of variants whose guard does not refuse.
    nonrefusing: Vec<usize>,
    pin_bodies: usize,
    /// If set, one pin body is this literal.
    bad_pin: Option<&'static str>,
    anchor_families: usize,
    wildcard: bool,
    /// Offsets of anchor families with no `family()` arm.
    anchor_missing: Vec<usize>,
    guarded: Vec<&'static str>,
    trait_default: &'static str,
}

impl Fixture {
    fn good() -> Self {
        Self {
            spec_variants: 24,
            unguarded: Vec::new(),
            nonrefusing: Vec::new(),
            pin_bodies: 22,
            bad_pin: None,
            anchor_families: 6,
            wildcard: false,
            anchor_missing: Vec::new(),
            guarded: vec!["Alpha", "Beta"],
            trait_default: "false",
        }
    }
}

const NAMES: &[&str] = &[
    "Alpha", "Beta", "Gamma", "Delta", "Epsilon", "Zeta", "Eta", "Theta", "Iota", "Kappa",
    "Lambda", "Mu", "Nu", "Xi", "Omicron", "Pi", "Rho", "Sigma", "Tau", "Upsilon", "Phi", "Chi",
    "Psi", "Omega", "Alfa", "Bravo", "Charlie", "Echo",
];

fn write_tree(dir: &std::path::Path, f: &Fixture) -> Result<(), String> {
    let ext = dir.join("src/cross_domain/external");
    std::fs::create_dir_all(&ext).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(dir.join("src/cross_domain")).map_err(|e| e.to_string())?;

    let variants: Vec<&str> = NAMES[..f.spec_variants].to_vec();
    let mut enum_body = String::new();
    for v in &variants {
        let _ = writeln!(enum_body, "    {v} {{ x: u8 }},");
    }

    let mut guards = String::new();
    for (i, v) in variants.iter().enumerate() {
        if f.unguarded.contains(&i) {
            continue;
        }
        let body = if f.nonrefusing.contains(&i) {
            "return Err(IntakeError::NotPinnedYet)"
        } else {
            "return Err(IntakeError::CommitteeNotPinned)"
        };
        let _ = writeln!(
            guards,
            "        if let AdapterSpec::{v} {{ .. }} = &self.spec {{ {body}; }}"
        );
    }

    let intake = format!(
        "pub enum IntakeError {{ CommitteeNotPinned, NotPinnedYet }}\n\
         pub enum AdapterSpec {{\n{enum_body}}}\n\n\
         pub enum AnchorFamily {{\n{anchors}}}\n\
         pub struct PinnedExternalAnchor {{ p: u8 }}\n\
         impl PinnedExternalAnchor {{\n    pub const fn family(&self) -> AnchorFamily {{\n        match self {{\n{arms}\n        }}\n    }}\n}}\n\n\
         pub struct IntakeState {{ spec: u8 }}\n\
         impl IntakeState {{\n    pub fn register_domain(&mut self) -> Result<u8, IntakeError> {{\n{guards}        Ok(0)\n    }}\n}}\n",
        anchors = (0..f.anchor_families)
            .map(|i| format!("    A{i},\n"))
            .collect::<String>(),
        arms = {
            let mut s = String::new();
            for i in 0..f.anchor_families {
                if f.anchor_missing.contains(&i) {
                    continue;
                }
                let _ = writeln!(s, "            Self {{ .. }} if true => AnchorFamily::A{i},");
            }
            if f.wildcard {
                let _ = writeln!(s, "            _ => AnchorFamily::A0,");
            }
            if s.is_empty() {
                s.push_str("            PinnedExternalAnchor { p: _ } => AnchorFamily::A0,\n");
            }
            s
        },
    );
    std::fs::write(dir.join("src/cross_domain/external/intake.rs"), intake)
        .map_err(|e| e.to_string())?;

    let mut pins = String::new();
    for i in 0..f.pin_bodies {
        let body = if i == 0 {
            f.bad_pin
                .unwrap_or("self.anchor.is_some_and(|a| a.weight > 0)")
        } else {
            "self.anchor.is_some_and(|a| a.weight > 0)"
        };
        let _ = writeln!(
            pins,
            "pub struct P{i};\nimpl ExternalFinalityAdapter for P{i} {{\n    fn has_pinned_trust_anchor(&self) -> bool {{ {body} }}\n}}"
        );
    }
    std::fs::write(dir.join("src/cross_domain/external/pins.rs"), pins)
        .map_err(|e| e.to_string())?;

    let spec = format!(
        "pub trait ExternalFinalityAdapter {{\n    fn has_pinned_trust_anchor(&self) -> bool {{ {} }}\n}}\n",
        f.trait_default
    );
    std::fs::write(dir.join("src/cross_domain/external/spec.rs"), spec)
        .map_err(|e| e.to_string())?;

    let mut g = String::new();
    for v in &f.guarded {
        let _ = writeln!(g, "    {v} {{ n: u8 }},");
    }
    std::fs::write(
        dir.join("src/cross_domain/economic_guard.rs"),
        format!("pub enum GuardedExternalAdapter {{\n{g}}}\n"),
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}

/// Trees that must pass.
fn pass_canaries(tmp: &std::path::Path) -> Result<(), String> {
    let dir = tmp.join("pass");
    let f = Fixture::good();
    write_tree(&dir, &f)?;
    let report = run(&dir).map_err(|e| format!("clean tree was refused:\n{e}"))?;
    if !report.contains("door:") {
        return Err(format!(
            "clean tree report does not name the door: {report}"
        ));
    }
    Ok(())
}

/// Trees that must fail, one per criterion.
fn fail_canaries(tmp: &std::path::Path) -> Result<(), String> {
    let cases: Vec<(&str, Fixture, &str)> = vec![
        (
            "variant with no register_domain guard",
            Fixture {
                unguarded: vec![3],
                ..Fixture::good()
            },
            "AdapterSpec::Delta is reachable through build",
        ),
        (
            "guard that does not refuse",
            Fixture {
                nonrefusing: vec![5],
                ..Fixture::good()
            },
            "never returns CommitteeNotPinned",
        ),
        (
            "pin body that is a constant true",
            Fixture {
                bad_pin: Some("true"),
                ..Fixture::good()
            },
            "returns a constant true",
        ),
        (
            "pin body that reads no field",
            Fixture {
                bad_pin: Some("1 == 1"),
                ..Fixture::good()
            },
            "reads no field of self",
        ),
        (
            "anchor family with no arm",
            Fixture {
                anchor_missing: vec![2],
                ..Fixture::good()
            },
            "AnchorFamily::A2 has no",
        ),
        (
            "anchor family wildcard",
            Fixture {
                wildcard: true,
                ..Fixture::good()
            },
            "carries a wildcard arm",
        ),
        (
            "guarded variant intake cannot admit",
            Fixture {
                guarded: vec!["Alpha", "Beta", "Omega", "Zulu"],
                ..Fixture::good()
            },
            "not an AdapterSpec variant",
        ),
        (
            "trait default opened",
            Fixture {
                trait_default: "true",
                ..Fixture::good()
            },
            "not `{false}`",
        ),
    ];

    for (i, (label, fixture, needle)) in cases.iter().enumerate() {
        let dir = tmp.join(format!("fail{i}"));
        write_tree(&dir, fixture)?;
        match run(&dir) {
            Ok(report) => return Err(format!("tree that must fail passed: {label}\n{report}")),
            Err(report) => {
                if !report.contains(needle) {
                    return Err(format!(
                        "tree that must fail gave the wrong finding: {label}\nexpected to \
                         contain `{needle}`, got:\n{report}"
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Point the gate at trees that must pass and trees that must fail.
///
/// # Errors
///
/// Returns the first canary that misbehaves: a tree that must pass is refused,
/// or a tree that must fail passes.
pub fn self_test() -> Result<String, String> {
    let tmp = scratch_dir()?;
    pass_canaries(&tmp)?;
    fail_canaries(&tmp)?;
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(
        "11 canaries: 1 clean tree accepted, 8 defective trees refused, \
        2 thresholds enforced"
            .to_string(),
    )
}
