//! The address bar is a trust boundary: a name passes this rule first.
//!
//! # The measured problem
//!
//! `src/bns/registry.rs` applies one rule to a name: 3..=32 characters. There
//! is no character-set check. On the chain side that is mostly harmless - a
//! record is a string and resolution is a lookup - but not in a browser:
//! Budscan turns a name into a resource identifier, so the string enters a
//! parser. `javascript:alert(1)` is a registrable BNS name today.
//!
//! # Why two layers
//!
//! The chain's rule can be loosened by governance, and a browser cannot assume
//! otherwise. So the browser's rule is always **narrower** than the chain's,
//! and whatever the chain accepts, this file makes its own decision. A name
//! that comes from the chain but does not pass here **is displayed**, is not
//! opened, and the reason is stated.
//!
//! # A refusal's reason has to be actionable
//!
//! Every refusal class has its own name. A generic "invalid name" error robs
//! the caller of knowing which property failed, and for a user "it did not
//! open" and "a colon is not a name character" are not the same thing.
//!
//! This module is the running version of the rule inside
//! `xtask/gates/src/gates/bns_names_are_safe_in_an_address_bar.rs`. The two
//! copies deliberately apply the same table, and the
//! `budscan-name-rule-parity` gate fails their divergence in CI: two places
//! deciding what a name may contain, drifting apart unaware of each other, is
//! worse than one place deciding badly.

use std::fmt;

/// Why a name cannot be put in the address bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameRejection {
    /// Outside 3..=32 characters. The registry's own bound.
    WrongLength,
    /// A character outside `a-z`, `0-9`, `-` and `.`.
    ///
    /// Upper case is refused, not lowercased. Lowercasing would collapse
    /// `UPPER.bud` and `upper.bud` into one record and turn ownership into a
    /// race won by whoever registers first; refusing says that one of the two
    /// does not exist.
    DisallowedCharacter { position: usize, ch: char },
    /// An empty label: a leading, trailing or doubled dot.
    EmptyLabel,
    /// A label starts or ends with a hyphen. The shape is reserved so that
    /// punycode's own `xn--` prefix cannot be forged.
    HyphenAtLabelEdge,
    /// Writing systems are mixed, which is how a Cyrillic character hides
    /// inside a Latin word. It is not refused for being non-Latin: a name
    /// wholly in Cyrillic is accepted and displayed as punycode.
    MixedScript,
    /// No dot, so no suffix saying which naming system the name belongs to.
    NoSuffix,
    /// The suffix is recognised, but this browser has no resolver for it.
    UnknownSuffix,
}

impl fmt::Display for NameRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength => write!(f, "a name must be 3 to 32 characters"),
            Self::DisallowedCharacter { position, ch } => write!(
                f,
                "character {ch:?} at position {position} is outside a-z, 0-9, hyphen \
                 and dot; a name reaches an address bar, so anything a URL parser \
                 treats specially cannot be part of one"
            ),
            Self::EmptyLabel => write!(
                f,
                "a leading, trailing or doubled dot leaves an empty label, which \
                 different parsers disagree about"
            ),
            Self::HyphenAtLabelEdge => write!(
                f,
                "a label may not start or end with a hyphen; the shape is reserved so \
                 punycode's own prefix cannot be forged"
            ),
            Self::MixedScript => write!(
                f,
                "the name mixes writing systems, which is how one Cyrillic character \
                 hides inside a Latin word; a name wholly in one script is accepted"
            ),
            Self::NoSuffix => write!(
                f,
                "a name with no dot names no system: .bud resolves on Budlum and .eth \
                 on Ethereum, and a bare label says neither"
            ),
            Self::UnknownSuffix => write!(
                f,
                "there is no resolver for this suffix; the browser does not know which \
                 naming system to ask, and does not guess"
            ),
        }
    }
}

/// Which writing system a character belongs to, coarsely.
///
/// Only enough to answer "is this name written in a single script". Catching a
/// Cyrillic `a` inside a Latin word does not need a full Unicode script table,
/// and carrying such a table into a dependency-free crate is not free.
///
/// Punctuation is deliberately **not** a script. A first version that put every
/// unrecognised character into one bucket and compared buckets returned
/// `MixedScript` for `javascript:alert(1)`: the colon was one system and the
/// letters another. The refusal was right and the reason was nonsense. A reason
/// that cannot be acted on wastes most of what a refusal exists for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Script {
    Latin,
    Cyrillic,
    Greek,
    Arabic,
    Hebrew,
    Han,
}

/// A letter's writing system; `None` for anything that is not a letter.
fn script_of(ch: char) -> Option<Script> {
    match ch {
        'a'..='z' | 'A'..='Z' => Some(Script::Latin),
        '\u{0370}'..='\u{03FF}' | '\u{1F00}'..='\u{1FFF}' => Some(Script::Greek),
        '\u{0400}'..='\u{04FF}' | '\u{0500}'..='\u{052F}' => Some(Script::Cyrillic),
        '\u{0590}'..='\u{05FF}' => Some(Script::Hebrew),
        '\u{0600}'..='\u{06FF}' | '\u{0750}'..='\u{077F}' => Some(Script::Arabic),
        '\u{4E00}'..='\u{9FFF}' | '\u{3400}'..='\u{4DBF}' => Some(Script::Han),
        _ => None,
    }
}

/// The suffixes this browser has a resolver for.
///
/// The list is deliberately short. A suffix is added here after a proof path
/// for it has been written: a naming system whose resolution cannot be verified
/// produces an answer that looks verified in the address bar, and that is the
/// one thing this browser avoids.
pub const RESOLVABLE_SUFFIXES: &[&str] = &["bud", "eth"];

/// May this name be resolved and displayed?
///
/// # Errors
///
/// The first property that fails, as a [`NameRejection`].
pub fn check_name(name: &str) -> Result<(), NameRejection> {
    let count = name.chars().count();
    if !(3..=32).contains(&count) {
        return Err(NameRejection::WrongLength);
    }

    // One writing system across the letters. This runs before the character
    // set so that a wholly Cyrillic name gets the right refusal instead of
    // being told its first letter is disallowed. Non-letters are skipped here;
    // the character-set check below is what speaks about them.
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
        if !matches!(ch, 'a'..='z' | '0'..='9' | '-' | '.') {
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

/// Returns the name's suffix: the last label after a dot.
#[must_use]
pub fn suffix_of(name: &str) -> Option<&str> {
    name.rsplit('.').next().filter(|s| !s.is_empty())
}

/// [`check_name`], plus "can we resolve this suffix".
///
/// # Errors
///
/// Whatever [`check_name`] refuses, or [`NameRejection::UnknownSuffix`] for a
/// suffix it does not know.
pub fn check_resolvable(name: &str) -> Result<(), NameRejection> {
    check_name(name)?;
    let suffix = suffix_of(name).ok_or(NameRejection::NoSuffix)?;
    if RESOLVABLE_SUFFIXES.contains(&suffix) {
        Ok(())
    } else {
        Err(NameRejection::UnknownSuffix)
    }
}

/// The form shown in the address bar.
///
/// A name that passes the rule is shown as it is. A name that does not **is not
/// opened**, but may still need to be displayed - in history, over a link, on
/// an error line. In that case every non-ASCII label is converted to punycode,
/// because the gap between what the user is shown and what is resolved is
/// exactly where a homograph attack lives.
#[must_use]
pub fn display_form(name: &str) -> String {
    if check_name(name).is_ok() {
        return name.to_string();
    }
    let mut out = String::with_capacity(name.len() + 8);
    for (i, label) in name.split('.').enumerate() {
        if i > 0 {
            out.push('.');
        }
        if label.is_ascii() {
            out.push_str(label);
        } else if let Some(encoded) = crate::punycode::encode_label(label) {
            out.push_str("xn--");
            out.push_str(&encoded);
        } else {
            // Showing the raw bytes of a label that cannot be encoded opens
            // the very gap between displayed and resolved that we are trying to
            // close.
            out.push_str("[?]");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_are_named_not_generic() {
        let cases: &[(&str, NameRejection)] = &[
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
        for (name, want) in cases {
            assert_eq!(check_name(name), Err(*want), "{name:?}");
        }
    }

    #[test]
    fn path_traversal_and_urls_are_refused() {
        for name in [
            "evil.bud/../../etc",
            "http://evil.com",
            "a/b/c",
            "ayaz.bud\u{0}x",
            "\u{202E}dub.zaya",
        ] {
            assert!(check_name(name).is_err(), "{name:?} was accepted");
        }
    }

    #[test]
    fn an_ordinary_name_passes() {
        for name in ["ayaz.bud", "a-b.bud", "x1.eth", "a.b.c.bud"] {
            assert!(check_name(name).is_ok(), "{name:?} was refused");
        }
    }

    #[test]
    fn a_wholly_cyrillic_name_is_not_called_mixed_script() {
        // Failing on the ASCII set is right; calling it MixedScript would be a
        // wrong diagnosis.
        let name = "\u{0430}\u{0431}\u{0432}.\u{0431}\u{0430}\u{0434}";
        assert_ne!(check_name(name), Err(NameRejection::MixedScript));
        assert!(check_name(name).is_err());
    }

    #[test]
    fn an_unknown_suffix_is_refused_by_the_resolvable_check_only() {
        assert!(check_name("ayaz.sol").is_ok());
        assert_eq!(
            check_resolvable("ayaz.sol"),
            Err(NameRejection::UnknownSuffix)
        );
        assert!(check_resolvable("ayaz.bud").is_ok());
        assert!(check_resolvable("ayaz.eth").is_ok());
    }

    #[test]
    fn display_form_punycodes_what_it_cannot_accept() {
        assert_eq!(display_form("ayaz.bud"), "ayaz.bud");
        // The value was computed, not copied out of the document: see the note
        // in the `punycode` test. The architecture document writes
        // `xn--yaz-hlc.bud` here, and that is wrong.
        assert_eq!(display_form("\u{0430}yaz.bud"), "xn--yaz-5cd.bud");
    }
}
