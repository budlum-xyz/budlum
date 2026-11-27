//! The finality acceptance surface has exactly one measured entry path.
//!
//! # Why this gate exists
//!
//! `finality-acceptance-surface-is-append-only` pins the *identity* of the
//! external verifier family table: variant order, discriminants, and the two
//! `consensus_kind` string tables. It deliberately says nothing about how an
//! adapter is *constructed*, and construction is where the second path lives.
//!
//! An adapter today has two doors. Door A is `AdapterSpec::build` in
//! `cross_domain/external/intake.rs`: registration runs `register_domain`,
//! which refuses a spec whose pin is `None` with `CommitteeNotPinned`, so the
//! admission path is closed when the anchor is missing. Door B is
//! `BridgeEconomicGuard::refresh_backing_from_adapter` in
//! `cross_domain/economic_guard.rs`: it constructs eight adapters directly and
//! calls `verify` without ever passing through admission. A ninth door - a
//! helper, a `Default`, a config loader - reopens Door B one constructor at a
//! time, and no existing gate notices, because each constructor compiles and
//! each adapter verifies.
//!
//! This gate measures the construction surface as it stands and refuses to let
//! it grow silently. It is a ratchet, not a refactor: it records today's map,
//! and the map may only shrink.
//!
//! # What it measures
//!
//! 1. **Pin presence is one condition.** Every `has_pinned_trust_anchor` body
//!    must be a single presence test - `self.<field>.is_some()` or a single
//!    `!self.<field>.is_empty()`. A conjunction (`&&`, `||`) hides which anchor
//!    is being attested (today `EthereumSyncAdapter` accepts a committee *or*
//!    an SSZ pin, `ZkVmFinalityAdapter` needs both its program hash and its
//!    chain id), and the design's §3.5 names both as must-fix. Until they are
//!    fixed the map records them under `pin-nonpresence`; the count is a
//!    ratchet, so the fix shrinks the map and a new conjunction cannot arrive
//!    unseen. A literal `true` is a third-party adapter claiming an anchor it
//!    does not hold and a literal `false` an adapter that can never be
//!    admitted - neither may be recorded. The trait default in `spec.rs` is
//!    the closed default and must stay `false`.
//!
//! 2. **`AdapterSpec::family()` is total when it exists.** The design's slice
//!    introduces it; if it is present it must be a `match self` with an arm for
//!    every variant and no wildcard arm. A wildcard would map a newly appended
//!    variant onto an existing family's identity, and the append-only gate
//!    would stay green because the identity table did not change.
//!
//! 3. **Production constructor sites are the committed set.** Every
//!    `XAdapter::new(` / `::new_pinned(` / `::new_optional(` / `::with_golden(`
//!    / `::build_adapter(` call outside `cross_domain/external/` is recorded in
//!    `.github/guarded-adapter-family-map.txt` as `<count> <file>`. A call site
//!    that is not in the map fails the gate, and so does a mapped site that
//!    disappeared: removing a door is progress and must move the map in the
//!    same change. Test code (`src/tests/`, `benches/`, `examples/`) constructs
//!    adapters freely; it is not a production door.
//!
//! 4. **The guard's adapter table is closed.** `GuardedExternalAdapter` has
//!    exactly the `guarded-variants:` count the map states, and every variant
//!    has an arm in `refresh_backing_from_adapter`. Widening the guard is the
//!    finding; slicing it down is the migration the design calls slice 3.
//!
//! # What this gate does not do
//!
//! It does not measure whether a `Vec`-backed pin is non-empty at verification
//! time, nor whether `register_domain` refuses every unpinned variant:
//! `src/tests/external_unpinned_refusal.rs` pins that behaviour and the CI
//! "Budlum Core library test" job runs it. This gate is text over committed
//! sources, so it runs without compiling the core crate.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// Where the external adapter module lives.
const EXTERNAL_DIR: &str = "src/cross_domain/external";

/// The module that owns Door A.
const INTAKE: &str = "src/cross_domain/external/intake.rs";

/// The trait whose closed default this gate pins.
const SPEC: &str = "src/cross_domain/external/spec.rs";

/// The module that owns Door B.
const ECONOMIC_GUARD: &str = "src/cross_domain/economic_guard.rs";

/// The recorded construction map.
const MAP: &str = ".github/guarded-adapter-family-map.txt";

/// The guard variant count the tree carries today. The map states it; this
/// constant is what the gate expects the header to say.
const GUARDED_VARIANTS: usize = 8;

/// Directories whose adapters are test fixtures, not production doors.
const TEST_DIRS: &[&str] = &["src/tests/", "benches/", "examples/"];

/// Constructor calls this gate counts.
const CONSTRUCTORS: &[&str] = &[
    "::new(",
    "::new_pinned(",
    "::new_optional(",
    "::with_golden(",
    "::build_adapter(",
];

/// The smallest number of `has_pinned_trust_anchor` bodies that is a scan.
///
/// The tree has twelve today: ten family modules, the Ethereum and ZK-VM
/// adapters, plus the trait default in `spec.rs`. A smaller count means the
/// module or its pattern moved, and a gate that measures nothing must not
/// report green.
const MIN_PIN_BODIES: usize = 10;

/// The smallest number of external `.rs` files that is a scan.
const MIN_FILES: usize = 20;

/// The smallest `AdapterSpec` that makes the family total-ness meaningful.
const MIN_SPEC_VARIANTS: usize = 10;

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

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.site, self.message)
    }
}

/// Blank out comments, preserving byte offsets and newlines.
fn strip_comments(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
        } else if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            out.push(b' ');
            out.push(b' ');
            i += 2;
            let mut depth = 1usize;
            while i < bytes.len() && depth > 0 {
                if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
                    depth += 1;
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                } else if bytes[i] == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                    depth -= 1;
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                } else {
                    out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                    i += 1;
                }
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

/// Cut a file at its first real `#[cfg(test)]` module.
///
/// Test fixtures implement the trait with a literal `true` so a test can reach
/// the shape gate without curve arithmetic; those bodies are not part of the
/// production construction surface and are not measured here.
///
/// Only `#[cfg(test)]` followed by a `mod` counts: the same attribute also
/// appears on test-only `use` imports near the top of a file
/// (`bitcoin_spv.rs:56`), and cutting there would hide the whole adapter.
fn without_tests(src: &str) -> &str {
    let needle = "#[cfg(test)]";
    let mut from = 0usize;
    while let Some(pos) = src[from..].find(needle) {
        let at = from + pos;
        let window = &src[at + needle.len()..];
        let cut = window.find("\nmod ").or_else(|| window.find("\npub mod "));
        match cut {
            Some(off) if off < 400 => return &src[..at],
            _ => from = at + needle.len(),
        }
    }
    src
}

/// Text between the braces of `needle`'s block, or a finding.
fn block_after<'a>(src: &'a str, needle: &str) -> Result<&'a str, String> {
    let start = src.find(needle).ok_or_else(|| {
        format!("`{needle}` was not found; the surface this gate measures has moved")
    })?;
    let open = src[start..]
        .find('{')
        .ok_or_else(|| format!("`{needle}` has no opening brace"))?
        + start;
    let mut depth = 0usize;
    for (off, c) in src[open..].char_indices() {
        if c == '{' {
            depth += 1;
        } else if c == '}' {
            depth -= 1;
            if depth == 0 {
                return Ok(&src[open + 1..open + off]);
            }
        }
    }
    Err(format!("`{needle}` braces never balance"))
}

/// Line number (1-based) of byte offset `off` in `src`.
fn line_of(src: &str, off: usize) -> usize {
    src[..off.min(src.len())]
        .bytes()
        .filter(|b| *b == b'\n')
        .count()
        + 1
}

/// Every regular `.rs` file under `dir`, sorted.
fn rust_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        let entries =
            fs::read_dir(&next).map_err(|e| format!("cannot read {}: {e}", next.display()))?;
        for entry in entries {
            let path = entry.map_err(|e| e.to_string())?.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// One `has_pinned_trust_anchor` body found under the external module.
struct PinBody {
    file: String,
    line: usize,
    text: String,
    /// The body is a single presence test of `self.<field>`.
    presence: bool,
}

/// Whether `body` is exactly one presence test, and which field it reads.
fn single_presence(body: &str) -> Option<&str> {
    let rest = body.trim().strip_prefix("self.")?;
    let (field, rest) = rest.split_once('.')?;
    let field = field.trim();
    if field.is_empty() || !field.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let call = rest.trim().strip_suffix("()")?;
    matches!(call, "is_some" | "is_empty").then_some(field)
}

/// Every pin body under `EXTERNAL_DIR`, comments and tests excluded.
fn pin_bodies(root: &Path) -> Result<Vec<PinBody>, String> {
    let files = rust_files(&root.join(EXTERNAL_DIR))?;
    if files.len() < MIN_FILES {
        return Err(format!(
            "{EXTERNAL_DIR} holds {} readable .rs files, under the {MIN_FILES} a real scan needs",
            files.len()
        ));
    }
    let mut out = Vec::new();
    let needle = "fn has_pinned_trust_anchor(&self) -> bool";
    for path in files {
        let rel = path
            .strip_prefix(root)
            .map_err(|e| e.to_string())?
            .display()
            .to_string();
        let raw = fs::read_to_string(&path).map_err(|e| format!("{rel}: {e}"))?;
        let code = strip_comments(without_tests(&raw));
        let mut from = 0usize;
        while let Some(pos) = code[from..].find(needle) {
            let at = from + pos;
            let body = block_after(&code[at..], needle)?;
            let text = body.split_whitespace().collect::<Vec<_>>().join(" ");
            out.push(PinBody {
                file: rel.clone(),
                line: line_of(&raw, at),
                presence: single_presence(&text).is_some(),
                text,
            });
            from = at + needle.len();
        }
    }
    Ok(out)
}

/// The trait default in `spec.rs` must stay `false`.
fn check_trait_default(bodies: &[PinBody]) -> Vec<Finding> {
    bodies
        .iter()
        .filter(|b| b.file == SPEC)
        .filter(|b| b.text != "false")
        .map(|b| {
            Finding::new(
                format!("{}:{}", b.file, b.line),
                format!(
                    "the trait default is `{}`, not `false`: a third-party adapter would hold an \
                     anchor it never proved",
                    b.text
                ),
            )
        })
        .collect()
}

/// Measure criterion 1 against the map's `pin-nonpresence` records.
fn check_pin_bodies(bodies: &[PinBody], recorded: &[String]) -> Vec<Finding> {
    if bodies.len() < MIN_PIN_BODIES {
        return vec![Finding::new(
            EXTERNAL_DIR,
            format!(
                "found {} `has_pinned_trust_anchor` bodies, under the {MIN_PIN_BODIES} a real \
                 scan needs: the adapter module or its trait method has moved",
                bodies.len()
            ),
        )];
    }
    let mut findings = check_trait_default(bodies);
    let mut measured: Vec<&str> = Vec::new();
    for body in bodies {
        if body.file == SPEC {
            continue;
        }
        if body.presence {
            if recorded.contains(&body.file) {
                findings.push(Finding::new(
                    format!("{}:{}", body.file, body.line),
                    format!(
                        "{MAP} still records this file under `pin-nonpresence`, but its body is \
                         now the single presence test `{}`: fixing a conjunction must shrink the \
                         map in the same change",
                        body.text
                    ),
                ));
            }
            continue;
        }
        if body.text == "true" || body.text == "false" {
            findings.push(Finding::new(
                format!("{}:{}", body.file, body.line),
                format!(
                    "`has_pinned_trust_anchor` is the literal `{}`: admission reads this as \
                     \"holds a trust anchor\", and a constant cannot be derived from the \
                     adapter's own pin",
                    body.text
                ),
            ));
            continue;
        }
        measured.push(body.file.as_str());
        if !recorded.contains(&body.file) {
            findings.push(Finding::new(
                format!("{}:{}", body.file, body.line),
                format!(
                    "`has_pinned_trust_anchor` is `{}`, which is not a single presence test and \
                     is not recorded under `pin-nonpresence` in {MAP}: a conjunction hides which \
                     anchor is attested, so it enters the map as a debt or not at all",
                    body.text
                ),
            ));
        }
    }
    let mut measured_sorted = measured.clone();
    measured_sorted.sort_unstable();
    measured_sorted.dedup();
    let mut recorded_sorted: Vec<&str> = recorded.iter().map(String::as_str).collect();
    recorded_sorted.sort_unstable();
    for ghost in &recorded_sorted {
        if !measured_sorted.contains(ghost) {
            findings.push(Finding::new(
                *ghost,
                format!(
                    "recorded under `pin-nonpresence` in {MAP} but no longer measured: the file \
                     moved or the body changed; a stale record must be removed"
                ),
            ));
        }
    }
    findings
}

/// Ordered variant names of an enum body, uppercase-leading segments only.
fn variant_names(body: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut depth = 0usize;
    let mut current = String::new();
    let push = |segment: &str, names: &mut Vec<String>| {
        let trimmed = segment.trim_start();
        let end = trimmed
            .char_indices()
            .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_'))
            .map_or(trimmed.len(), |(i, _)| i);
        if end > 0 && trimmed.starts_with(|c: char| c.is_ascii_uppercase()) {
            names.push(trimmed[..end].to_string());
        }
    };
    for c in body.chars() {
        match c {
            '{' | '(' => {
                depth += 1;
                current.push(c);
            }
            '}' | ')' => {
                depth = depth.saturating_sub(1);
                current.push(c);
            }
            ',' if depth == 0 => {
                push(&current, &mut names);
                current.clear();
            }
            _ => current.push(c),
        }
    }
    push(&current, &mut names);
    names
}

/// The variant names a `match` covers, and whether it carries a wildcard arm.
fn match_arms(body: &str) -> (Vec<String>, bool) {
    let mut arms: Vec<String> = Vec::new();
    let mut wildcard = false;
    let mut depth = 0usize;
    let mut current = String::new();
    let flush = |segment: &str, arms: &mut Vec<String>, wildcard: &mut bool| {
        let Some((pattern, _)) = segment.split_once("=>") else {
            return;
        };
        let pattern = pattern.trim();
        if pattern == "_" {
            *wildcard = true;
            return;
        }
        let ident = pattern
            .trim_start_matches("Self::")
            .trim_start_matches("AdapterSpec::")
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .next()
            .unwrap_or("");
        if ident.starts_with(|c: char| c.is_ascii_uppercase()) {
            arms.push(ident.to_string());
        }
    };
    for c in body.chars() {
        match c {
            '{' | '(' | '[' => {
                depth += 1;
                current.push(c);
            }
            '}' | ')' | ']' => {
                depth = depth.saturating_sub(1);
                current.push(c);
            }
            ',' if depth == 0 => {
                flush(&current, &mut arms, &mut wildcard);
                current.clear();
            }
            _ => current.push(c),
        }
    }
    flush(&current, &mut arms, &mut wildcard);
    (arms, wildcard)
}

/// Measure criterion 2.
fn check_family(root: &Path) -> Result<Vec<Finding>, String> {
    let raw = fs::read_to_string(root.join(INTAKE)).map_err(|e| format!("{INTAKE}: {e}"))?;
    let code = strip_comments(without_tests(&raw));
    let spec = block_after(&code, "enum AdapterSpec").map_err(|e| format!("{INTAKE}: {e}"))?;
    let variants = variant_names(spec);
    if variants.len() < MIN_SPEC_VARIANTS {
        return Err(format!(
            "{INTAKE}: `AdapterSpec` declares {} variants, under the {MIN_SPEC_VARIANTS} this \
             gate needs before a family map means anything",
            variants.len()
        ));
    }
    // Only a `family()` on `AdapterSpec` counts: `PinnedExternalAnchor::family`
    // is a different map (anchor -> AnchorFamily), and reading its arms here
    // would report a partial `AdapterSpec` map that does not exist.
    // No `impl AdapterSpec` block is not a finding: the design introduces
    // `family()` in a later slice, and this gate must not refuse the tree it
    // is landing on. The block, when present, is measured in full.
    let Ok(spec_impl) = block_after(&code, "impl AdapterSpec") else {
        return Ok(vec![]);
    };
    let Some(pos) = spec_impl.find("fn family(&self)") else {
        return Ok(vec![]);
    };
    let fn_body =
        block_after(&spec_impl[pos..], "fn family(&self)").map_err(|e| format!("{INTAKE}: {e}"))?;
    // Arms are separated one level inside `match self { .. }`: read the match
    // block's interior, or every arm but the last reads as one segment.
    let match_at = fn_body
        .find("match")
        .ok_or_else(|| format!("{INTAKE}: `family()` has no `match`, so it cannot be total"))?;
    let body = block_after(&fn_body[match_at..], "match").map_err(|e| format!("{INTAKE}: {e}"))?;
    let (arms, wildcard) = match_arms(body);
    let site = format!(
        "{INTAKE}:{}",
        line_of(&raw, code.find(spec_impl).unwrap_or(0) + pos)
    );
    let mut findings = Vec::new();
    if wildcard {
        findings.push(Finding::new(
            &site,
            "`AdapterSpec::family()` has a wildcard arm: a newly appended variant would inherit \
             an existing family's identity and the append-only gate would stay green",
        ));
    }
    let mut missing: Vec<&String> = variants.iter().filter(|v| !arms.contains(v)).collect();
    missing.sort();
    if !missing.is_empty() {
        findings.push(Finding::new(
            &site,
            format!(
                "`AdapterSpec::family()` does not cover {} of {} variants: {:?}",
                missing.len(),
                variants.len(),
                missing
            ),
        ));
    }
    Ok(findings)
}

/// One production file and how many constructors it calls.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Site {
    file: String,
    count: usize,
}

/// Adapter type names, read from the module so a rename cannot leave a stale
/// allow-list behind.
fn adapter_types(root: &Path) -> Result<Vec<String>, String> {
    let mut adapters = Vec::new();
    for path in rust_files(&root.join(EXTERNAL_DIR))? {
        let raw = fs::read_to_string(&path).map_err(|e| e.to_string())?;
        for line in strip_comments(without_tests(&raw)).lines() {
            let Some(pos) = line.find("pub struct ") else {
                continue;
            };
            let name: String = line[pos + "pub struct ".len()..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if name.ends_with("Adapter")
                || name.ends_with("FinalityAdapter")
                || name.ends_with("LightClient")
            {
                adapters.push(name);
            }
        }
    }
    adapters.sort();
    adapters.dedup();
    if adapters.len() < MIN_FILES {
        return Err(format!(
            "found {} public types in {EXTERNAL_DIR}, too few to measure the constructor surface",
            adapters.len()
        ));
    }
    Ok(adapters)
}

/// Measure criterion 3's left-hand side.
fn measure_constructor_sites(root: &Path) -> Result<Vec<Site>, String> {
    let adapters = adapter_types(root)?;
    let mut out: Vec<Site> = Vec::new();
    for dir in ["src", "benches", "examples"] {
        let base = root.join(dir);
        if !base.is_dir() {
            continue;
        }
        for path in rust_files(&base)? {
            let rel = path
                .strip_prefix(root)
                .map_err(|e| e.to_string())?
                .display()
                .to_string();
            if rel.starts_with(&format!("{EXTERNAL_DIR}/"))
                || TEST_DIRS.iter().any(|t| rel.starts_with(t))
                || rel.contains("/tests/")
            {
                continue;
            }
            let raw = fs::read_to_string(&path).map_err(|e| format!("{rel}: {e}"))?;
            let code = strip_comments(without_tests(&raw));
            let mut count = 0usize;
            for line in code.lines() {
                for adapter in &adapters {
                    for ctor in CONSTRUCTORS {
                        if line.contains(&format!("{adapter}{ctor}")) {
                            count += 1;
                        }
                    }
                }
            }
            if count > 0 {
                out.push(Site { file: rel, count });
            }
        }
    }
    out.sort();
    Ok(out)
}

/// The committed map: counts, guarded variants, and recorded debt.
struct Map {
    guarded_variants: usize,
    sites: Vec<Site>,
    pin_nonpresence: Vec<String>,
}

/// Parse the committed map.
fn read_map(root: &Path) -> Result<Map, String> {
    let raw = fs::read_to_string(root.join(MAP))
        .map_err(|e| format!("{MAP}: {e} - the map is the record this gate compares against"))?;
    let mut guarded_variants = None;
    let mut sites = Vec::new();
    let mut pin_nonpresence = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let directive = line.strip_prefix('#').map_or(line, str::trim);
        if let Some(value) = directive.strip_prefix("guarded-variants:") {
            guarded_variants = value.trim().parse::<usize>().ok();
        }
        if line.starts_with('#') {
            continue;
        }
        if directive.starts_with("guarded-variants:") {
            continue;
        }
        let (head, rest) = line.split_once(char::is_whitespace).ok_or_else(|| {
            format!(
                "{MAP}:{}: `{line}` is not `<count> <file>` or `nonpresence <file>`",
                idx + 1
            )
        })?;
        let rest = rest.trim();
        if head == "nonpresence" {
            pin_nonpresence.push(rest.to_string());
            continue;
        }
        let count = head
            .parse::<usize>()
            .map_err(|e| format!("{MAP}:{}: {e}", idx + 1))?;
        sites.push(Site {
            file: rest.to_string(),
            count,
        });
    }
    let guarded_variants = guarded_variants
        .ok_or_else(|| format!("{MAP}: the header must state `guarded-variants: <n>`"))?;
    Ok(Map {
        guarded_variants,
        sites,
        pin_nonpresence,
    })
}

/// Measure criterion 3's right-hand side.
fn check_constructor_map(measured: &[Site], mapped: &[Site]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for site in measured {
        match mapped.iter().find(|m| m.file == site.file) {
            None => findings.push(Finding::new(
                &site.file,
                format!(
                    "{} constructor call(s) outside `{EXTERNAL_DIR}` are not in {MAP}: a new \
                     construction path can bypass admission, so it must be recorded - and later \
                     removed - rather than arrive unseen",
                    site.count
                ),
            )),
            Some(entry) if entry.count != site.count => findings.push(Finding::new(
                &site.file,
                format!(
                    "{} constructor call(s) outside `{EXTERNAL_DIR}`, the map records {}",
                    site.count, entry.count
                ),
            )),
            Some(_) => {}
        }
    }
    for entry in mapped {
        if !measured.iter().any(|s| s.file == entry.file) {
            findings.push(Finding::new(
                &entry.file,
                format!(
                    "recorded in {MAP} with {} constructor call(s), but the file has none: \
                     removing a door is progress and must move the map in the same change",
                    entry.count
                ),
            ));
        }
    }
    findings
}

/// Measure criterion 4.
fn check_guarded_table(root: &Path, mapped: usize) -> Result<Vec<Finding>, String> {
    let raw = fs::read_to_string(root.join(ECONOMIC_GUARD))
        .map_err(|e| format!("{ECONOMIC_GUARD}: {e}"))?;
    let code = strip_comments(without_tests(&raw));
    let body = block_after(&code, "enum GuardedExternalAdapter")
        .map_err(|e| format!("{ECONOMIC_GUARD}: {e}"))?;
    let variants = variant_names(body);
    let mut findings = Vec::new();
    if variants.len() != GUARDED_VARIANTS {
        findings.push(Finding::new(
            ECONOMIC_GUARD,
            format!(
                "`GuardedExternalAdapter` declares {} variants; Door B is recorded as holding \
                 {GUARDED_VARIANTS}. Widening the unpinned construction path is the finding; \
                 shrinking it is the migration",
                variants.len()
            ),
        ));
    }
    if mapped != GUARDED_VARIANTS {
        findings.push(Finding::new(
            MAP,
            format!("the header states `guarded-variants: {mapped}`, the gate expects {GUARDED_VARIANTS}"),
        ));
    }
    for variant in &variants {
        if !code.contains(&format!("GuardedExternalAdapter::{variant} {{")) {
            findings.push(Finding::new(
                ECONOMIC_GUARD,
                format!(
                    "`{variant}` has no arm in `refresh_backing_from_adapter`: a guard variant \
                     that constructs no adapter is dead weight, and one that constructs through \
                     a helper this gate cannot see is a finding"
                ),
            ));
        }
    }
    Ok(findings)
}

/// Run the gate over `root`.
///
/// # Errors
///
/// Returns the findings, one per line, when the construction surface has grown
/// past its map, when a pin body is not a single presence test and is not
/// recorded, when `AdapterSpec::family()` is partial or wildcarded, or when the
/// guard table moved.
pub fn run(root: &Path) -> Result<String, String> {
    let bodies = pin_bodies(root)?;
    let map = read_map(root)?;
    let mut findings = check_pin_bodies(&bodies, &map.pin_nonpresence);
    findings.extend(check_family(root)?);
    let sites = measure_constructor_sites(root)?;
    findings.extend(check_constructor_map(&sites, &map.sites));
    findings.extend(check_guarded_table(root, map.guarded_variants)?);

    if !findings.is_empty() {
        let mut text = format!(
            "the finality acceptance surface has more than one path ({} finding(s)):\n",
            findings.len()
        );
        for finding in &findings {
            let _ = writeln!(text, "  - {finding}");
        }
        return Err(text);
    }

    Ok(format!(
        "one measured path: {} pin bodies ({} recorded non-presence), {} constructor call(s) in \
         {} production file(s), {} guarded adapter(s)",
        bodies.len(),
        map.pin_nonpresence.len(),
        sites.iter().map(|s| s.count).sum::<usize>(),
        sites.len(),
        map.guarded_variants
    ))
}

/// A scratch directory no other gate shares.
fn scratch_dir() -> Result<PathBuf, String> {
    crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-one-path")
}

/// What the fixture's `AdapterSpec` carries.
#[derive(Clone)]
enum FamilyFixture {
    /// No `family()` method at all.
    Absent,
    /// A `family()` whose `match self` arms are the given text.
    Arms(String),
}

/// One fixture tree: the shape the gate is pointed at.
#[derive(Clone)]
struct Fixture {
    /// Which criterion the tree violates, or `clean`.
    broken: &'static str,
    /// The body of the one pin function under test.
    pin_body: &'static str,
    /// The `AdapterSpec::family()` shape.
    family: FamilyFixture,
    /// Production files and their constructor counts.
    sites: &'static [(&'static str, usize)],
    /// Guard variants the fixture's enum declares.
    guarded_variants: usize,
    /// Guard variants the map's header states.
    mapped_guarded: usize,
    /// Files recorded under `nonpresence`.
    recorded_nonpresence: &'static [&'static str],
}

impl Fixture {
    /// The same tree with one `AdapterSpec::family()` shape.
    fn with_family(mut self, family: FamilyFixture) -> Self {
        self.family = family;
        self
    }

    /// The same tree with a different pin body.
    const fn with_pin(mut self, pin_body: &'static str) -> Self {
        self.pin_body = pin_body;
        self
    }

    /// The same tree with different constructor sites.
    const fn with_sites(mut self, sites: &'static [(&'static str, usize)]) -> Self {
        self.sites = sites;
        self
    }
}

/// The ten `AdapterSpec` variants the fixture declares.
const SPEC_VARIANTS: &[&str] = &[
    "Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot", "Golf", "Hotel", "India", "Juliet",
    "Kilo",
];

/// A `match self` covering every [`SPEC_VARIANTS`] variant.
fn full_arms() -> String {
    let mut arms = String::new();
    for name in SPEC_VARIANTS {
        let _ = writeln!(arms, "            Self::{name} {{ .. }} => F::{name},");
    }
    arms
}

/// Write the fixture tree and its map.
fn write_tree(dir: &Path, fixture: &Fixture) -> Result<(), String> {
    let create = |path: &Path| -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("cannot create fixture: {e}"))?;
        }
        Ok(())
    };

    let intake = dir.join(INTAKE);
    create(&intake)?;
    let mut spec_src = String::from("pub enum AdapterSpec {\n");
    for name in SPEC_VARIANTS {
        let _ = writeln!(spec_src, "    {name} {{ network: String }},");
    }
    spec_src.push_str("}\n");
    if let FamilyFixture::Arms(ref arms) = fixture.family {
        let _ = write!(
            spec_src,
            "\nimpl AdapterSpec {{\n    pub const fn family(&self) -> ExternalVerifierFamily {{\n        match self {{\n{arms}        }}\n    }}\n}}\n"
        );
    }
    fs::write(&intake, spec_src).map_err(|e| e.to_string())?;

    let spec = dir.join(SPEC);
    create(&spec)?;
    fs::write(
        &spec,
        "pub trait ExternalFinalityAdapter {\n    fn has_pinned_trust_anchor(&self) -> bool {\n        false\n    }\n}\n",
    )
    .map_err(|e| e.to_string())?;

    let mut variants = String::new();
    let mut arms = String::new();
    let names = [
        "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten",
    ];
    for name in names.iter().take(fixture.guarded_variants) {
        let _ = writeln!(variants, "    {name} {{ network: String }},");
        let _ = write!(
            arms,
            "            GuardedExternalAdapter::{name} {{ .. }} => {{\n                build(name)\n            }}\n"
        );
    }
    let guard = dir.join(ECONOMIC_GUARD);
    create(&guard)?;
    fs::write(
        &guard,
        format!(
            "pub enum GuardedExternalAdapter {{\n{variants}}}\n\nimpl Guard {{\n    fn refresh(&mut self, adapter_cfg: &GuardedExternalAdapter) {{\n        let _ = match adapter_cfg {{\n{arms}        }};\n    }}\n}}\n"
        ),
    )
    .map_err(|e| e.to_string())?;

    // Twenty-six adapter modules: the scan needs MIN_FILES, and the first one
    // carries the pin body under test.
    for idx in 0..26u32 {
        let path = dir.join(EXTERNAL_DIR).join(format!("m{idx:02}.rs"));
        create(&path)?;
        let body = if idx == 0 {
            fixture.pin_body.to_string()
        } else {
            format!("        self.pin{idx}.is_some()")
        };
        fs::write(
            &path,
            format!(
                "pub struct A{idx:02}Adapter;\n\nimpl ExternalFinalityAdapter for A{idx:02}Adapter {{\n    fn has_pinned_trust_anchor(&self) -> bool {{\n{body}\n    }}\n}}\n"
            ),
        )
        .map_err(|e| e.to_string())?;
    }

    let mut map = String::from(
        "# Finality acceptance surface construction map.\n# <count> <file>, `nonpresence <file>` for recorded pin debt.\n",
    );
    let _ = writeln!(map, "guarded-variants: {}", fixture.mapped_guarded);
    for (file, count) in fixture.sites {
        let path = dir.join(file);
        create(&path)?;
        let mut body = String::new();
        for n in 0..*count {
            let _ = writeln!(body, "    let a{n} = A00Adapter::new();");
        }
        fs::write(&path, format!("fn prod() {{\n{body}}}\n")).map_err(|e| e.to_string())?;
        // `new-site` writes the call but withholds the map entry: a constructor
        // that arrives without a record is the finding that canary is for.
        if !(fixture.broken == "new-site" && *file == "src/extra.rs") {
            let _ = writeln!(map, "{count} {file}");
        }
    }
    let nonpresence = match fixture.broken {
        "unrecorded-conjunction" => &[][..],
        _ => fixture.recorded_nonpresence,
    };
    for file in nonpresence {
        let _ = writeln!(map, "nonpresence {file}");
    }
    if fixture.broken == "stale-map" {
        map.push_str("1 src/ghost.rs\n");
    }
    let map_path = dir.join(MAP);
    create(&map_path)?;
    fs::write(&map_path, map).map_err(|e| e.to_string())?;

    Ok(())
}

/// The trees that must pass.
fn pass_canaries(tmp: &Path) -> Result<(), String> {
    let base = Fixture {
        broken: "clean",
        pin_body: "        self.committee.is_some()",
        family: FamilyFixture::Absent,
        sites: &[("src/bin/bud.rs", 2), ("src/guard.rs", 1)],
        guarded_variants: 8,
        mapped_guarded: 8,
        recorded_nonpresence: &[],
    };

    let with_full = |fixture: Fixture| fixture.with_family(FamilyFixture::Arms(full_arms()));

    let clean = tmp.join("clean");
    write_tree(&clean, &with_full(base.clone()))?;
    if let Err(msg) = run(&clean) {
        return Err(format!("canary: a clean tree was rejected: {msg}"));
    }

    // The design's transition state: a conjunction is tolerated only while the
    // map records it.
    let recorded = tmp.join("recorded-conjunction");
    write_tree(
        &recorded,
        &with_full(base.clone())
            .with_pin("        self.committee.is_some() || self.ssz_pin.is_some()"),
    )?;
    let recorded_map = recorded.join(MAP);
    let mut map = fs::read_to_string(&recorded_map).map_err(|e| e.to_string())?;
    let _ = writeln!(map, "nonpresence {EXTERNAL_DIR}/m00.rs");
    fs::write(&recorded_map, map).map_err(|e| e.to_string())?;
    if let Err(msg) = run(&recorded) {
        return Err(format!("canary: a recorded conjunction was refused: {msg}"));
    }

    // A tree that has not grown `family()` yet is not a finding: the design
    // introduces it in a later slice.
    let absent = tmp.join("no-family");
    write_tree(&absent, &base)?;
    if let Err(msg) = run(&absent) {
        return Err(format!(
            "canary: an absent `family()` was treated as a finding: {msg}"
        ));
    }
    Ok(())
}

/// The trees that must fail, one per criterion.
fn fail_canaries(tmp: &Path) -> Result<(), String> {
    let base = Fixture {
        broken: "clean",
        pin_body: "        self.committee.is_some()",
        family: FamilyFixture::Absent,
        sites: &[("src/bin/bud.rs", 2), ("src/guard.rs", 1)],
        guarded_variants: 8,
        mapped_guarded: 8,
        recorded_nonpresence: &[],
    };
    let full = FamilyFixture::Arms(full_arms());
    let wildcard = FamilyFixture::Arms(
        "            Self::Alpha { .. } => F::Alpha,\n            _ => F::Bravo,\n".to_string(),
    );
    let partial = FamilyFixture::Arms(
        "            Self::Alpha { .. } => F::Alpha,\n            Self::Bravo { .. } => F::Bravo,\n".to_string(),
    );
    let wider = &[
        ("src/bin/bud.rs", 2),
        ("src/guard.rs", 1),
        ("src/extra.rs", 1),
    ];

    let cases: Vec<(&'static str, Fixture)> = vec![
        (
            "unrecorded-conjunction",
            base.clone()
                .with_family(full.clone())
                .with_pin("        self.committee.is_some() || self.ssz_pin.is_some()"),
        ),
        (
            "literal-true",
            base.clone()
                .with_family(full.clone())
                .with_pin("        true"),
        ),
        (
            "literal-false",
            base.clone()
                .with_family(full.clone())
                .with_pin("        false"),
        ),
        ("wildcard-family", base.clone().with_family(wildcard)),
        ("partial-family", base.clone().with_family(partial)),
        (
            "new-site",
            base.clone().with_family(full.clone()).with_sites(wider),
        ),
        (
            "wider-guard",
            Fixture {
                guarded_variants: 9,
                ..base.clone().with_family(full.clone())
            },
        ),
    ];
    for (name, mut fixture) in cases {
        fixture.broken = name;
        let dir = tmp.join(name);
        write_tree(&dir, &fixture)?;
        if run(&dir).is_ok() {
            return Err(format!("canary: a tree broken by `{name}` passed"));
        }
    }

    // A map that names a file with no constructor must fail: removing a door
    // moves the map, or the map describes a tree that no longer exists.
    let stale = tmp.join("stale-map");
    write_tree(&stale, &base.with_family(FamilyFixture::Arms(full_arms())))?;
    let map_path = stale.join(MAP);
    let mut map = fs::read_to_string(&map_path).map_err(|e| e.to_string())?;
    map.push_str("1 src/ghost.rs\n");
    fs::write(&map_path, map).map_err(|e| e.to_string())?;
    if run(&stale).is_ok() {
        return Err("canary: a map naming a file with no constructor passed".into());
    }
    Ok(())
}

/// # Errors
///
/// Returns the first canary that misbehaves: a tree that must pass is refused,
/// or a tree that must fail passes.
pub fn self_test() -> Result<String, String> {
    let tmp = scratch_dir()?;
    let result = pass_canaries(&tmp).and_then(|()| fail_canaries(&tmp));
    let _ = fs::remove_dir_all(&tmp);
    result?;
    Ok(
        "one-path canaries: clean, recorded-conjunction and absent-family pass; unrecorded \
        conjunction, literal true/false, wildcard, partial family, new site, wider guard and \
        stale map are refused"
            .into(),
    )
}
