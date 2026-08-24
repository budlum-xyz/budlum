//! What is the thing typed into the search box?
//!
//! "Wallet addresses, NFTs, web sites are all searched here" means one single
//! box, and one single box means a **parsing order**. The oldest class of bug in
//! browser history lives exactly here: whether a string counts as a name or as a
//! scheme depends on which check runs first.
//!
//! # Rule: classify first, resolve later
//!
//! This module **resolves nothing**. It only says which class the typed thing
//! falls into, and returns [`Query::Ambiguous`] when it cannot decide. Resolving
//! the ambiguity on its own would turn what the user typed into something the
//! user did not mean; an ambiguous input is put back to the user.
//!
//! # A scheme is never guessed
//!
//! `javascript:alert(1)` looks like a scheme and truly is one. This module does
//! not read it as a name; it returns [`Query::RefusedScheme`] and states why it
//! was refused. The name rule refuses the same input separately
//! ([`crate::name_rule`]); both layers refusing is deliberate, because one of
//! them relaxing must not mean the other one goes quiet.

use crate::name_rule::{self, NameRejection};

/// The class of the typed thing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    /// A resolvable name: `ayaz.bud`, `x1.eth`.
    Name { name: String, suffix: String },
    /// A 32-byte Budlum address (0x + 64 hex).
    BudAddress([u8; 32]),
    /// A 20-byte EVM address (0x + 40 hex).
    EvmAddress([u8; 20]),
    /// A B.U.D. content id (0x + 64 hex, explicitly marked with a `bud://` or
    /// `cid:` prefix).
    ContentId([u8; 32]),
    /// IPFS CID.
    Cid(String),
    /// An NFT id: `nft:12` or a bare integer.
    NftId(u64),
    /// A block height: `block:1200`.
    BlockHeight(u64),
    /// A transaction hash: `tx:0x...`.
    TxHash([u8; 32]),
    /// An HTTPS URL. It must be written out; it is never guessed.
    HttpsUrl(String),
    /// Free text: it fits no class. It may be a search term.
    FreeText(String),
    /// The same input fits two classes and is not guessed.
    Ambiguous {
        input: String,
        candidates: Vec<String>,
    },
    /// A scheme was written and that scheme will not be opened.
    RefusedScheme { input: String, scheme: String },
    /// It looks like a name but does not pass the name rule.
    RefusedName {
        input: String,
        rejection: NameRejection,
    },
}

/// Schemes that will under no condition enter the address bar as a name.
///
/// The list is a **refusal** list, not an allow list, and that is deliberate: an
/// allow list silently accepts every new scheme that is not on it. This list
/// names the known harmful ones; every remaining scheme is already refused with
/// [`Query::RefusedScheme`] because `scheme_of` stops at the colon.
pub const NEVER_OPENED_SCHEMES: &[&str] = &[
    "javascript",
    "data",
    "vbscript",
    "file",
    "blob",
    "chrome",
    "resource",
    "about",
];

/// Does a string start with "scheme:"?
///
/// `https://` is a scheme too and is handled separately. The question here is
/// only "is there a scheme label before the colon".
fn scheme_of(input: &str) -> Option<&str> {
    let idx = input.find(':')?;
    let scheme = &input[..idx];
    if scheme.is_empty() {
        return None;
    }
    let ok = scheme
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.');
    if ok && scheme.chars().next()?.is_ascii_alphabetic() {
        Some(scheme)
    } else {
        None
    }
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    hex::decode(s).ok()
}

/// Classify the typed thing. Nothing is resolved, no network call is made.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn classify(raw: &str) -> Query {
    let input = raw.trim();

    if input.is_empty() {
        return Query::FreeText(String::new());
    }

    // 1. Explicit prefixes. If the user said what they wanted, there is no guessing.
    if let Some(rest) = input.strip_prefix("nft:") {
        if let Ok(id) = rest.trim().parse::<u64>() {
            return Query::NftId(id);
        }
        return Query::FreeText(input.to_string());
    }
    if let Some(rest) = input.strip_prefix("block:") {
        if let Ok(h) = rest.trim().parse::<u64>() {
            return Query::BlockHeight(h);
        }
        return Query::FreeText(input.to_string());
    }
    if let Some(rest) = input.strip_prefix("tx:") {
        if let Some(bytes) = hex_bytes(rest.trim()) {
            if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                return Query::TxHash(arr);
            }
        }
        return Query::FreeText(input.to_string());
    }
    if let Some(rest) = input
        .strip_prefix("bud://")
        .or_else(|| input.strip_prefix("cid:"))
    {
        let rest = rest.trim();
        if let Some(bytes) = hex_bytes(rest) {
            if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                return Query::ContentId(arr);
            }
        }
        // `bud://ayaz.bud` is a valid spelling too: the scheme points at a name.
        return classify_name(rest);
    }
    if let Some(rest) = input.strip_prefix("ipfs://") {
        return Query::Cid(rest.trim().to_string());
    }

    // 2. HTTPS must be written out. Someone typing `evil.com` may have wanted
    //    HTTPS, but `evil.com` also looks like a name; we do not guess, we
    //    return `Ambiguous` (below).
    if input.starts_with("https://") {
        return Query::HttpsUrl(input.to_string());
    }
    if input.starts_with("http://") {
        // Plain HTTP: neither the content nor the transport is verified. It is
        // not refused outright, but it is named for what it is; the verdict is
        // not `Target::Https`, because even that assumes TLS.
        return Query::RefusedScheme {
            input: input.to_string(),
            scheme: String::from("http"),
        };
    }

    // 3. Every remaining scheme is refused. This comes first, because
    //    `javascript:alert(1)` can also look "name-like" and the order decides.
    if let Some(scheme) = scheme_of(input) {
        return Query::RefusedScheme {
            input: input.to_string(),
            scheme: scheme.to_string(),
        };
    }

    // 4. Hex addresses.
    if let Some(bytes) = hex_bytes(input) {
        if input.starts_with("0x") {
            if let Ok(arr) = <[u8; 20]>::try_from(bytes.as_slice()) {
                return Query::EvmAddress(arr);
            }
            if bytes.len() == 32 {
                // 32 bytes can be a Budlum address, a ContentId or a
                // transaction hash. The ambiguity is threefold and not guessed.
                return Query::Ambiguous {
                    input: input.to_string(),
                    candidates: vec![
                        String::from("wallet address (Address)"),
                        String::from("content id (ContentId) - write it with bud://"),
                        String::from("transaction hash - write it with tx:"),
                    ],
                };
            }
        }
    }

    // 5. A bare integer: NFT or block? No guessing.
    if input.parse::<u64>().is_ok() {
        return Query::Ambiguous {
            input: input.to_string(),
            candidates: vec![
                String::from("NFT id - write it with nft:"),
                String::from("block height - write it with block:"),
            ],
        };
    }

    // 6. Does it look like an IPFS CID? (`Qm...` or `bafy.../bafk...`)
    if (input.len() == 46 && input.starts_with("Qm"))
        || (input.starts_with("baf")
            && input.len() > 20
            && input.chars().all(|c| c.is_ascii_alphanumeric()))
    {
        return Query::Cid(input.to_string());
    }

    // 7. Something with a dot: a name, or a domain?
    if input.contains('.') {
        return classify_name(input);
    }

    Query::FreeText(input.to_string())
}

/// Run a dotted input through the name rule.
fn classify_name(input: &str) -> Query {
    match name_rule::check_name(input) {
        Ok(()) => {
            let suffix = name_rule::suffix_of(input).unwrap_or_default().to_string();
            if name_rule::RESOLVABLE_SUFFIXES.contains(&suffix.as_str()) {
                Query::Name {
                    name: input.to_string(),
                    suffix,
                }
            } else {
                // `evil.com` is a valid name shape but has no resolver.
                // Falling back to HTTPS would assume a scheme the user did not
                // write; we call it ambiguous.
                Query::Ambiguous {
                    input: input.to_string(),
                    candidates: vec![
                        format!("there is no name resolver for .{suffix}"),
                        String::from("ordinary web site - write it with https://"),
                    ],
                }
            }
        }
        Err(rejection) => Query::RefusedName {
            input: input.to_string(),
            rejection,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bud_name_is_a_name() {
        assert_eq!(
            classify("ayaz.bud"),
            Query::Name {
                name: String::from("ayaz.bud"),
                suffix: String::from("bud")
            }
        );
        assert_eq!(
            classify("  x1.eth  "),
            Query::Name {
                name: String::from("x1.eth"),
                suffix: String::from("eth")
            }
        );
    }

    #[test]
    fn javascript_is_a_refused_scheme_not_a_name() {
        match classify("javascript:alert(1)") {
            Query::RefusedScheme { scheme, .. } => assert_eq!(scheme, "javascript"),
            other => panic!("expected a scheme refusal, got {other:?}"),
        }
        for s in NEVER_OPENED_SCHEMES {
            let input = format!("{s}:whatever");
            assert!(
                matches!(classify(&input), Query::RefusedScheme { .. }),
                "{input} was accepted"
            );
        }
    }

    #[test]
    fn plain_http_is_refused_by_name() {
        match classify("http://evil.com") {
            Query::RefusedScheme { scheme, .. } => assert_eq!(scheme, "http"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn https_must_be_written_out() {
        assert_eq!(
            classify("https://example.com/x"),
            Query::HttpsUrl(String::from("https://example.com/x"))
        );
        // A bare domain is not guessed.
        assert!(matches!(classify("example.com"), Query::Ambiguous { .. }));
    }

    #[test]
    fn an_evm_address_is_twenty_bytes() {
        let q = classify("0x0000000000000000000000000000000000000001");
        assert!(matches!(q, Query::EvmAddress(_)), "{q:?}");
    }

    #[test]
    fn thirty_two_bytes_is_ambiguous_and_says_all_three() {
        let q = classify(&format!("0x{}", "11".repeat(32)));
        match q {
            Query::Ambiguous { candidates, .. } => assert_eq!(candidates.len(), 3),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn explicit_prefixes_remove_the_ambiguity() {
        assert!(matches!(
            classify(&format!("bud://0x{}", "11".repeat(32))),
            Query::ContentId(_)
        ));
        assert!(matches!(
            classify(&format!("tx:0x{}", "22".repeat(32))),
            Query::TxHash(_)
        ));
        assert_eq!(classify("nft:12"), Query::NftId(12));
        assert_eq!(classify("block:1200"), Query::BlockHeight(1200));
    }

    #[test]
    fn a_bare_integer_is_ambiguous_not_guessed() {
        assert!(matches!(classify("12"), Query::Ambiguous { .. }));
    }

    #[test]
    fn a_bad_name_is_refused_with_its_reason() {
        match classify("has space.bud") {
            Query::RefusedName { rejection, .. } => {
                assert!(matches!(
                    rejection,
                    NameRejection::DisallowedCharacter { .. }
                ));
            }
            other => panic!("{other:?}"),
        }
        match classify("UPPER.bud") {
            Query::RefusedName { rejection, .. } => {
                assert_eq!(
                    rejection,
                    NameRejection::DisallowedCharacter {
                        position: 0,
                        ch: 'U'
                    }
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn path_traversal_never_becomes_a_name() {
        assert!(matches!(
            classify("evil.bud/../../etc"),
            Query::RefusedName { .. }
        ));
    }

    #[test]
    fn a_cid_is_recognised_by_shape() {
        assert!(matches!(
            classify("bafkreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yegnrjhc4yeq"),
            Query::Cid(_)
        ));
        assert!(matches!(
            classify("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"),
            Query::Cid(_)
        ));
        assert!(matches!(classify("ipfs://bafkrei..."), Query::Cid(_)));
    }

    #[test]
    fn free_text_stays_free_text() {
        assert_eq!(
            classify("learning material"),
            Query::FreeText(String::from("learning material"))
        );
    }

    #[test]
    fn a_bidi_override_is_refused_not_displayed() {
        assert!(matches!(
            classify("\u{202E}dub.zaya"),
            Query::RefusedName { .. }
        ));
    }
}
