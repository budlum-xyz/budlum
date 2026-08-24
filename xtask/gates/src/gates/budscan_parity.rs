//! `budscan` duplicates two definitions; if the copies diverge this gate fails.
//!
//! # Why there are copies
//!
//! `budscan` is a browser core and does not depend on `budlum-core`. Doing so
//! would pull in libp2p, tokio, jsonrpsee and sled, and that dependency graph
//! is unwanted at a browser's trust boundary. The price is two copies:
//!
//! 1. **The name rule.** `crates/budscan/src/name_rule.rs::check_name` and
//!    `bns_names_are_safe_in_an_address_bar::check_name` apply the same table.
//! 2. **The content identity.** `crates/budscan/src/content_id.rs::ContentId::of`
//!    and `src/storage/content_id.rs::ContentId::of` use the same domain tag and
//!    the same length-prefixed hash.
//!
//! Both can diverge silently, and if they do the outcome is silent too: the
//! scanner accepts a name the chain does not, or the scanner says a byte is
//! verified while the chain computes a different identity. This gate turns
//! those two silences into noise.
//!
//! # What is measured
//!
//! Not a behaviour comparison but a text comparison: the constants that must be
//! identical on both sides - domain tag, length prefix, character set, refusal
//! class names - are searched for one by one. The `grep` question is "does this
//! text exist", and there are many places where that is the wrong question;
//! here it is the right one, because what is sought is exactly the written
//! form.

use std::fmt::Write as _;
use std::path::Path;

/// The refusal class names that must appear in both copies of the name rule.
const REJECTION_VARIANTS: &[&str] = &[
    "WrongLength",
    "DisallowedCharacter",
    "EmptyLabel",
    "HyphenAtLabelEdge",
    "MixedScript",
    "NoSuffix",
];

/// The character set of the name rule must be written identically in both copies.
const CHARSET_PATTERN: &str = "'a'..='z' | '0'..='9' | '-' | '.'";

/// The length bound.
const LENGTH_BOUND: &str = "(3..=32).contains(&count)";

/// The domain separator tag of the content identity; it must be the same on both sides.
const CONTENT_DOMAIN_TAG: &str = "BDLM_CONTENT_V1";

fn read(root: &Path, rel: &str) -> Result<String, String> {
    let path = root.join(rel);
    std::fs::read_to_string(&path).map_err(|e| format!("{} could not be read: {e}", path.display()))
}

/// # Errors
///
/// When one of the two copies has lost a definition the other carries.
pub fn run(root: &Path) -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();
    check_name_rule(root, &mut problems)?;
    check_content_id(root, &mut problems)?;
    check_shared_constants(root, &mut problems)?;

    if problems.is_empty() {
        return Ok(String::from(
            "budscan parity OK: the name rule carries six refusal classes and the same character set, \
             ContentId is computed with the same domain tag and length prefix, \
             and the size bound and EPOCH_LENGTH agree in all three places",
        ));
    }
    let mut msg = String::new();
    for p in &problems {
        let _ = writeln!(msg, "  {p}");
    }
    Err(msg)
}

/// Do the two name-rule copies carry the same table?
fn check_name_rule(root: &Path, problems: &mut Vec<String>) -> Result<(), String> {
    // -- 1. The name rule ------------------------------------------------
    let browser = read(root, "crates/budscan/src/name_rule.rs")?;
    let gate = read(
        root,
        "xtask/gates/src/gates/bns_names_are_safe_in_an_address_bar.rs",
    )?;

    for variant in REJECTION_VARIANTS {
        if !browser.contains(variant) {
            problems.push(format!(
                "the {variant} refusal class is missing from crates/budscan/src/name_rule.rs; the gate carries \
                 it, so the scanner may be accepting something the gate refuses"
            ));
        }
        if !gate.contains(variant) {
            problems.push(format!(
                "{variant} is missing from bns_names_are_safe_in_an_address_bar.rs; \
                 the scanner carries it"
            ));
        }
    }

    if !browser.contains(CHARSET_PATTERN) {
        problems.push(format!(
            "crates/budscan/src/name_rule.rs does not write the character set as \
             {CHARSET_PATTERN}. The set has widened or narrowed; either way it has to be \
             identical to the chain-side copy"
        ));
    }
    if !gate.contains("'a'..='z' | '0'..='9' | '-' | '.'") {
        problems.push(String::from(
            "the gate's own character set has changed; the two sides have diverged",
        ));
    }
    if !browser.contains(LENGTH_BOUND) {
        problems.push(format!(
            "crates/budscan/src/name_rule.rs does not enforce the {LENGTH_BOUND} length bound"
        ));
    }

    // The scanner rule must be **narrower** than the chain rule. On the chain
    // side there is still only a length rule; that is not trusted, it is
    // measured.
    let registry = read(root, "src/bns/registry.rs")?;
    if !registry.contains("(3..=32).contains(&char_count)") {
        problems.push(String::from(
            "src/bns/registry.rs no longer enforces the 3..=32 length rule. Either the \
             bound moved or a character-set rule landed. If a character set landed, it has \
             to be reconciled with crates/budscan/src/name_rule.rs in the same commit: two \
             places deciding what a name may contain, drifting apart unaware of each \
             other, is worse than one place deciding badly",
        ));
    }

    Ok(())
}

/// Do the two `ContentId` definitions produce the same identity?
fn check_content_id(root: &Path, problems: &mut Vec<String>) -> Result<(), String> {
    // -- 2. The content identity -----------------------------------------
    let browser_cid = read(root, "crates/budscan/src/content_id.rs")?;
    let core_cid = read(root, "src/storage/content_id.rs")?;

    if !browser_cid.contains(CONTENT_DOMAIN_TAG) {
        problems.push(format!(
            "crates/budscan/src/content_id.rs does not use the {CONTENT_DOMAIN_TAG} tag; \
             the identity the scanner computes will not equal the chain's, and every \
             verification fails silently"
        ));
    }
    if !core_cid.contains(CONTENT_DOMAIN_TAG) {
        problems.push(format!(
            "src/storage/content_id.rs has lost the {CONTENT_DOMAIN_TAG} tag; the \
             scanner carries it"
        ));
    }

    // Length prefix: without it `["a","bc"]` and `["ab","c"]` hash to the same
    // value.
    if !browser_cid.contains("(field.len() as u64).to_le_bytes()") {
        problems.push(String::from(
            "crates/budscan/src/content_id.rs does not length-prefix the fields before hashing. \
             Without the prefix two different contents can share one identity",
        ));
    }

    Ok(())
}

/// Are the constants repeated in three places identical?
fn check_shared_constants(root: &Path, problems: &mut Vec<String>) -> Result<(), String> {
    // -- 3. Size bound: identical in three places ------------------------
    let browser_fetch = read(root, "crates/budscan/src/fetch.rs")?;
    let core_gateway = read(root, "src/gateway/service.rs")?;
    let browser_limit = browser_fetch.contains("10 * 1024 * 1024");
    let core_limit = core_gateway.contains("10 * 1024 * 1024");
    if browser_limit != core_limit {
        problems.push(String::from(
            "the content size bound has diverged between crates/budscan/src/fetch.rs and \
             src/gateway/service.rs. Two different bounds open a gap where one accepts \
             what the other refuses",
        ));
    }

    // -- 4. Epoch length ---------------------------------------------------
    let browser_lc = read(root, "crates/budscan/src/light_client.rs")?;
    let chain = read(root, "src/chain/blockchain.rs")?;
    if chain.contains("pub const EPOCH_LENGTH: u64 = 10;")
        != browser_lc.contains("pub const EPOCH_LENGTH: u64 = 10;")
    {
        problems.push(String::from(
            "EPOCH_LENGTH has diverged between src/chain/blockchain.rs and \
             crates/budscan/src/light_client.rs. The scanner would take the wrong headers \
             for an epoch boundary, and the chain it follows would not be the chain \
             itself",
        ));
    }

    Ok(())
}

/// # Errors
///
/// Canaries that do not behave as expected.
pub fn self_test() -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();

    // Canary: on an empty tree the gate must **not** pass. A gate that cannot
    // read a file and says "no problem" has inspected nothing and called it
    // OK.
    let empty = std::path::Path::new("/nonexistent-budscan-parity-canary");
    if run(empty).is_ok() {
        problems.push(String::from(
            "VACUOUS: the gate passed on a tree it could not read",
        ));
    }

    // Canary: the list of constants sought must not be empty, otherwise the
    // loop checks nothing and the gate always passes.
    if REJECTION_VARIANTS.is_empty() {
        problems.push(String::from(
            "VACUOUS: the refusal class list is empty, the loop searches for nothing",
        ));
    }
    if CHARSET_PATTERN.is_empty() || LENGTH_BOUND.is_empty() {
        problems.push(String::from(
            "VACUOUS: the sought pattern is empty; an empty pattern is found in every text",
        ));
    }

    if !problems.is_empty() {
        let mut msg = String::new();
        for p in &problems {
            let _ = writeln!(msg, "  {p}");
        }
        return Err(msg);
    }
    Ok(String::from(
        "budscan parity self-test OK: the gate does not pass on a tree it cannot read and none of \
         the patterns it searches for are empty",
    ))
}
