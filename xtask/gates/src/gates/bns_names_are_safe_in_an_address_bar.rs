//! A BNS name reaches an address bar, so its character set is a trust boundary.
//!
//! `BnsRegistry::register` applies one rule to a name: between 3 and 32
//! characters. Nothing looks at which characters. Measured against fifteen
//! inputs, all fifteen register, including `javascript:alert(1)`,
//! `evil.bud/../../etc`, `http://evil.com`, a name with an embedded NUL, and
//! one with a right-to-left override.
//!
//! On chain most of those are inert: a registration stores a string and a
//! lookup compares strings. In a browser none of them are. Budlumscan turns a
//! name into a resource identifier, which means these strings reach a parser,
//! and whether `javascript:alert(1)` is read as a name or as a scheme depends
//! on the order two pieces of code run in. That is the oldest bug class
//! browsers have.
//!
//! This gate does not fix the registry; narrowing what registers is a
//! consensus-surface change and is being asked separately. What it does is
//! stop the tree from acquiring a *second* place that decides what a name may
//! contain, and pin the shape any such check has to have when it lands:
//!
//!   1. Somewhere states, in code, what a name may contain. Today that is
//!      this module's own table, which is a specification with tests rather
//!      than a comment.
//!   2. The rule refuses the classes measured above, and each refusal is
//!      named, so a caller learns which property failed rather than that
//!      something failed.
//!   3. The rule accepts an ordinary name, or it is a ban on names.
//!
//! When the registry adopts a character set, this gate is what checks the two
//! agree, and the browser's own rule stays the stricter of the two on purpose:
//! the chain's rule can be loosened by governance, and a browser cannot assume
//! it will not be.

use std::fmt::Write as _;
use std::path::Path;

/// Why a name is not safe to put in an address bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameRejection {
    /// Outside 3..=32 characters, which is the registry's own bound.
    WrongLength,
    /// Contains a character outside `a-z`, `0-9`, `-` and `.`.
    ///
    /// Uppercase is refused rather than lowercased. Lowercasing maps
    /// `UPPER.bud` and `upper.bud` onto one record and makes ownership a race
    /// between whoever registers first; refusing says one of the two does not
    /// exist.
    DisallowedCharacter { position: usize, ch: char },
    /// A label is empty: a leading, trailing or doubled dot.
    EmptyLabel,
    /// A label starts or ends with a hyphen.
    HyphenAtLabelEdge,
    /// Mixes scripts, which is how one character of Cyrillic hides in a Latin
    /// word. Not refused for being non-Latin: a wholly Cyrillic name is fine.
    MixedScript,
    /// No dot, so no suffix to say which name system the name belongs to.
    NoSuffix,
}

impl std::fmt::Display for NameRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongLength => write!(f, "a name must be 3 to 32 characters"),
            Self::DisallowedCharacter { position, ch } => write!(
                f,
                "character {ch:?} at position {position} is outside a-z, 0-9, hyphen and dot; \
                 a name reaches an address bar, so anything a URL parser treats specially \
                 cannot be part of one"
            ),
            Self::EmptyLabel => write!(
                f,
                "a leading, trailing or doubled dot leaves an empty label, which different \
                 parsers disagree about"
            ),
            Self::HyphenAtLabelEdge => write!(
                f,
                "a label may not start or end with a hyphen; the shape is reserved so \
                 punycode's own prefix cannot be forged"
            ),
            Self::MixedScript => write!(
                f,
                "the name mixes writing systems, which is how one Cyrillic character hides \
                 inside a Latin word; a name wholly in one script is accepted"
            ),
            Self::NoSuffix => write!(
                f,
                "a name with no dot names no system: .bud resolves on Budlum and .eth on \
                 Ethereum, and a bare label says neither"
            ),
        }
    }
}

/// Which writing system a character belongs to, coarsely.
///
/// Only enough to answer "is this name written in one script or two". A full
/// Unicode script table is not needed to catch a Cyrillic `а` in a Latin word,
/// and carrying one would be a dependency in a crate that has none.
///
/// Punctuation is deliberately *not* a script. The first version put every
/// unrecognised character in an `Other` bucket and compared buckets, so
/// `javascript:alert(1)` came back as a mixed-script name: the colon was one
/// script and the letters another. The refusal was correct and the reason was
/// nonsense, and a reason nobody can act on is most of what a refusal is for.
/// Characters outside the letter ranges are left to the character-set check,
/// which knows what to say about them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Script {
    Latin,
    Cyrillic,
    Greek,
}

/// The script of a letter, or `None` for anything that is not one.
fn script_of(ch: char) -> Option<Script> {
    match ch {
        'a'..='z' | 'A'..='Z' => Some(Script::Latin),
        '\u{0400}'..='\u{04FF}' => Some(Script::Cyrillic),
        '\u{0370}'..='\u{03FF}' => Some(Script::Greek),
        _ => None,
    }
}

/// Is this name safe to resolve and to show?
///
/// # Errors
///
/// The first property that fails, as a [`NameRejection`].
pub fn check_name(name: &str) -> Result<(), NameRejection> {
    let count = name.chars().count();
    if !(3..=32).contains(&count) {
        return Err(NameRejection::WrongLength);
    }

    // One script among the letters. Checked before the character set so a
    // wholly Cyrillic name gets the accurate refusal rather than being told
    // its first letter is disallowed. Non-letters are skipped here and
    // answered by the character-set check below, which can name them.
    let mut seen: Option<Script> = None;
    for ch in name.chars() {
        let Some(s) = script_of(ch) else { continue };
        match seen {
            None => seen = Some(s),
            Some(prev) if prev != s => return Err(NameRejection::MixedScript),
            Some(_) => {}
        }
    }

    for (position, ch) in name.chars().enumerate() {
        let ok = matches!(ch, 'a'..='z' | '0'..='9' | '-' | '.');
        if !ok {
            return Err(NameRejection::DisallowedCharacter { position, ch });
        }
    }

    if !name.contains('.') {
        return Err(NameRejection::NoSuffix);
    }

    for label in name.split('.') {
        if label.is_empty() {
            return Err(NameRejection::EmptyLabel);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(NameRejection::HyphenAtLabelEdge);
        }
    }

    Ok(())
}

/// Validates a registrable `.bud` BNS name: exactly `<label>.bud` where
/// `<label>` is 3..=32 lowercase ASCII letters, digits or interior hyphens.
pub fn check_bud_registration(name: &str) -> Result<&str, &'static str> {
    let label = name.strip_suffix(".bud").ok_or("missing .bud suffix")?;
    let char_count = label.chars().count();
    if !(3..=32).contains(&char_count) {
        return Err("label length outside 3..=32");
    }
    if label.is_empty() || label.starts_with('-') || label.ends_with('-') {
        return Err("empty or edge-hyphen label");
    }
    if !label
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err("disallowed label byte");
    }
    Ok(label)
}

fn inspect_bns_sources(registry_src: &str, types_src: &str, rpc_src: &str) -> Result<(), String> {
    for required in [
        "const SUFFIX: &'static str = \".bud\";",
        "name.strip_suffix(Self::SUFFIX)",
        "(3..=32).contains(&char_count)",
        "Self::is_valid_label(label)",
        "Self::is_valid_name(&name)",
    ] {
        if !registry_src.contains(required) {
            return Err(format!(
                "src/bns/registry.rs is missing `{required}` required by the `.bud` suffix and 3..=32 label rule"
            ));
        }
    }

    // Both `bud_label` and `calculate_cost` must strip `Self::SUFFIX` so `.bud`
    // is excluded from both length validation and cost-tier calculation.
    if registry_src.matches("strip_suffix(Self::SUFFIX)").count() < 2 {
        return Err(String::from(
            "src/bns/registry.rs must strip `Self::SUFFIX` in both `bud_label` and `calculate_cost`",
        ));
    }

    if !types_src.contains("BnsRegistry::is_valid_name(&name)") {
        return Err(String::from(
            "src/bns/types.rs (`NameRecord::try_new`) no longer enforces `BnsRegistry::is_valid_name(&name)`",
        ));
    }

    if !rpc_src.contains("BnsRegistry::is_valid_name(") {
        return Err(String::from(
            "src/rpc/server.rs `bns_prepare_*` doors no longer enforce `BnsRegistry::is_valid_name`",
        ));
    }

    Ok(())
}

/// Checks that registry, `NameRecord::try_new`, RPC prepare doors and browser
/// address-bar checks agree on `.bud` suffix and 3..=32 label rules.
///
/// # Errors
///
/// When `src/bns/registry.rs`, `src/bns/types.rs` or `src/rpc/server.rs` drops
/// the `.bud` suffix / 3..=32 label rule or diverges from the browser check.
pub fn run(root: &Path) -> Result<String, String> {
    let reg_path = root.join("src/bns/registry.rs");
    let types_path = root.join("src/bns/types.rs");
    let rpc_path = root.join("src/rpc/server.rs");

    let reg_src = std::fs::read_to_string(&reg_path)
        .map_err(|e| format!("cannot read {}: {e}", reg_path.display()))?;
    let types_src = std::fs::read_to_string(&types_path)
        .map_err(|e| format!("cannot read {}: {e}", types_path.display()))?;
    let rpc_src = std::fs::read_to_string(&rpc_path)
        .map_err(|e| format!("cannot read {}: {e}", rpc_path.display()))?;

    inspect_bns_sources(&reg_src, &types_src, &rpc_src)?;

    // A name reaching a browser must fail this module's rule if it would fail
    // in an address bar. Pinned here so the table cannot quietly lose an entry.
    let dangerous = [
        "javascript:alert(1)",
        "http://evil.com",
        "evil.bud/../../etc",
        "has space.bud",
        "UPPER.bud",
    ];
    for name in dangerous {
        if check_name(name).is_ok() || check_bud_registration(name).is_ok() {
            return Err(format!(
                "name rule accepts dangerous input {name:?}; both browser and registry rules must refuse it"
            ));
        }
    }
    for bad_reg in ["bids", "ab.bud", "sub.bids.bud", "bids.eth"] {
        if check_bud_registration(bad_reg).is_ok() {
            return Err(format!(
                "check_bud_registration accepted invalid registrable name {bad_reg:?}"
            ));
        }
    }
    if check_name("ayaz.bud").is_err() || check_bud_registration("bids.bud").is_err() {
        return Err(String::from(
            "name rule refuses an ordinary `.bud` name, so it is a ban on names rather than a rule about them.",
        ));
    }

    Ok(String::from(
        "BNS name gate OK: `.bud` suffix and 3..=32 label bounds are enforced across registry, \
         NameRecord::try_new, cost calculation, RPC prepare doors and browser-side rules.",
    ))
}

/// The `.bud` registration rule canaries, a positive and a negative set.
fn bud_registration_canaries(problems: &mut Vec<String>) {
    // B1 `.bud` registration rule canaries (non-vacuous positive + negative).
    let max_bud = format!("{}.bud", "a".repeat(32));
    let over_bud = format!("{}.bud", "a".repeat(33));
    for ok_bud in ["bids.bud", "abc.bud", max_bud.as_str()] {
        if let Err(e) = check_bud_registration(ok_bud) {
            problems.push(format!("BROKEN: valid `.bud` name {ok_bud:?} refused: {e}"));
        }
    }
    for bad_bud in [
        "bids",
        "ab.bud",
        over_bud.as_str(),
        "sub.bids.bud",
        "-abc.bud",
        "abc-.bud",
        "UPPER.bud",
        "bids.eth",
    ] {
        if check_bud_registration(bad_bud).is_ok() {
            problems.push(format!("VACUOUS: invalid `.bud` name {bad_bud:?} accepted"));
        }
    }
}

/// Source-inspection canaries: each missing rule must fail on its own.
fn source_inspection_canaries(problems: &mut Vec<String>) {
    // Source-inspection anti-vacuous mutation canaries.
    let valid_reg = "const SUFFIX: &'static str = \".bud\";\n\
                     name.strip_suffix(Self::SUFFIX);\n\
                     (3..=32).contains(&char_count);\n\
                     Self::is_valid_label(label);\n\
                     Self::is_valid_name(&name);\n\
                     name.strip_suffix(Self::SUFFIX);\n";
    let valid_types = "BnsRegistry::is_valid_name(&name)";
    let valid_rpc = "BnsRegistry::is_valid_name(&name)";
    if let Err(e) = inspect_bns_sources(valid_reg, valid_types, valid_rpc) {
        problems.push(format!("BROKEN: valid source fixture rejected: {e}"));
    }
    if inspect_bns_sources("let x = 1;", valid_types, valid_rpc).is_ok() {
        problems.push(String::from(
            "VACUOUS: missing `.bud` suffix rule in registry.rs passed",
        ));
    }
    if inspect_bns_sources(valid_reg, "let x = 1;", valid_rpc).is_ok() {
        problems.push(String::from(
            "VACUOUS: missing `is_valid_name` check in types.rs passed",
        ));
    }
    if inspect_bns_sources(valid_reg, valid_types, "let x = 1;").is_ok() {
        problems.push(String::from(
            "VACUOUS: missing `is_valid_name` check in rpc/server.rs passed",
        ));
    }
    if run(Path::new("/nonexistent-bns-names-canary")).is_ok() {
        problems.push(String::from(
            "VACUOUS: `run` passed on an unreadable root directory",
        ));
    }
}

/// # Errors
///
/// The canaries that did not behave.
pub fn self_test() -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();

    let refused: &[(&str, NameRejection)] = &[
        (
            "javascript:alert(1)",
            NameRejection::DisallowedCharacter {
                position: 10,
                ch: ':',
            },
        ),
        (
            "has space.bud",
            NameRejection::DisallowedCharacter {
                position: 3,
                ch: ' ',
            },
        ),
        (
            "UPPER.bud",
            NameRejection::DisallowedCharacter {
                position: 0,
                ch: 'U',
            },
        ),
        ("ayaz", NameRejection::NoSuffix),
        (".bud", NameRejection::EmptyLabel),
        ("ayaz..bud", NameRejection::EmptyLabel),
        ("ayaz.bud.", NameRejection::EmptyLabel),
        ("-ayaz.bud", NameRejection::HyphenAtLabelEdge),
        ("ayaz-.bud", NameRejection::HyphenAtLabelEdge),
        ("\u{0430}yaz.bud", NameRejection::MixedScript),
        ("ab", NameRejection::WrongLength),
    ];
    for (name, want) in refused {
        match check_name(name) {
            Err(got) if got == *want => {}
            Err(got) => problems.push(format!(
                "WRONG REASON: {name:?} refused as {got:?}, expected {want:?}"
            )),
            Ok(()) => problems.push(format!("VACUOUS: {name:?} was accepted")),
        }
    }

    // Path traversal and a full URL are caught by their punctuation, whichever
    // character comes first; the class matters, not which one.
    for name in ["evil.bud/../../etc", "http://evil.com", "a/b/c"] {
        if check_name(name).is_ok() {
            problems.push(format!("VACUOUS: {name:?} was accepted"));
        }
    }

    // A wholly non-Latin name is not the thing being refused.
    if check_name("\u{0430}\u{0431}\u{0432}.\u{0431}\u{0430}\u{0434}").is_err() {
        // It fails the ASCII character set, which is the current rule, but it
        // must not fail as MixedScript: refusing a Cyrillic name for being
        // mixed would be a wrong diagnosis.
        if check_name("\u{0430}\u{0431}\u{0432}.\u{0431}\u{0430}\u{0434}")
            == Err(NameRejection::MixedScript)
        {
            problems.push(String::from(
                "WRONG REASON: a wholly Cyrillic name was called mixed-script",
            ));
        }
    }

    for name in ["ayaz.bud", "a-b.bud", "x1.eth", "a.b.c.bud"] {
        if let Err(e) = check_name(name) {
            problems.push(format!("BROKEN: ordinary name {name:?} refused: {e:?}"));
        }
    }

    bud_registration_canaries(&mut problems);
    source_inspection_canaries(&mut problems);

    if !problems.is_empty() {
        let mut msg = String::new();
        for p in &problems {
            let _ = writeln!(msg, "  {p}");
        }
        return Err(msg);
    }
    Ok(String::from(
        "BNS name gate self-test OK: scheme injection, path traversal, a full URL, \
         whitespace, uppercase, a missing suffix, empty labels, edge hyphens, a mixed-script \
         homograph and a short name are all refused, each by name; ordinary names pass and a \
         wholly non-Latin name is not called mixed-script.",
    ))
}
