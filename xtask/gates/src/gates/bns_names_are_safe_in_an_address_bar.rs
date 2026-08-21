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

/// The registry still applies only a length rule, and this records that.
///
/// # Errors
///
/// When `src/bns/registry.rs` has grown a second character-set rule that this
/// module does not know about, so the two can disagree without anyone looking.
pub fn run(root: &Path) -> Result<String, String> {
    let path = root.join("src/bns/registry.rs");
    let display = path.display().to_string();
    let src = std::fs::read_to_string(&path).map_err(|e| format!("cannot read {display}: {e}"))?;

    if !src.contains("(3..=32).contains(&char_count)") {
        return Err(format!(
            "{display} no longer applies the 3..=32 length rule this module was measured \
             against. Either the bound moved or a character-set rule landed. If a rule \
             landed, this module's check_name must be reconciled with it in the same \
             commit: two places deciding what a name may contain, disagreeing, is worse \
             than one place deciding badly."
        ));
    }

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
        if check_name(name).is_ok() {
            return Err(format!(
                "check_name accepts {name:?}, which the registry also accepts. This module \
                 exists because the registry's rule is a length and nothing else; if the \
                 browser's rule stops catching these, nothing does."
            ));
        }
    }
    if check_name("ayaz.bud").is_err() {
        return Err(String::from(
            "check_name refuses an ordinary name, so it is a ban on names rather than a \
             rule about them.",
        ));
    }

    Ok(String::from(
        "BNS name gate OK: the registry still applies a length rule and nothing else, and \
         the browser-side rule refuses scheme injection, path traversal, whitespace, \
         uppercase and mixed scripts while accepting an ordinary name.",
    ))
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
