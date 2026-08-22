//! The domain-separation tag inventory must not drift.
//!
//! Every `BDLM_*` and `BUDLUM_*` string literal in the Rust sources is either
//! a separation tag listed in `src/crypto/domain_tags.rs`, or a deliberately
//! non-separating literal on the [`EXEMPT`] list below. A literal that is
//! neither is a finding: a new separation domain slipped in without review.
//!
//! Two prefixes coexist for historical reasons. `BDLM_*` is the original
//! inventory prefix; a large part of the consensus, custody and privacy
//! separation surface was written with the longer `BUDLUM_*` prefix. While this
//! gate matched only `BDLM_*`, those tags were invisible, so the gate reported
//! "OK" while a reviewer would have checked an incomplete surface. The gate now
//! matches both prefixes and the inventory was completed. A listed-but-unused
//! tag is stale (a reviewer would check a surface that does not exist); an
//! exempt-but-unused entry is stale for the same reason.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

const INVENTORY: &str = "src/crypto/domain_tags.rs";

/// Directories whose `*.rs` files are scanned for tag literals.
///
/// `crates/wallet-core` holds the wallet's cryptographic helpers and reaches
/// several `BUDLUM_*` hash domains; it was previously listed as `wallet-core`
/// (a path that does not exist at the repo root), so every tag there was
/// silently unscanned. `crates/budscan` is intentionally out of scope here: it
/// carries its own tags that are reconciled by the `budscan-parity` gate.
const SCAN_DIRS: &[&str] = &["src", "budzero", "crates/wallet-core"];

/// `BUDLUM_*` literals that are intentionally NOT separation tags.
///
/// These name environment variables, CLI knobs, test fixtures or data markers;
/// they never reach a hash or signature, so they do not belong in the
/// cryptographic inventory. Listing them keeps the gate honest: every matched
/// literal is accounted for in exactly one of two reviewable places (the
/// inventory for separators, this list for everything else).
const EXEMPT: &[&str] = &[
    // Runtime configuration read from the environment (src/cli, src/main).
    "BUDLUM_CHAIN_ID",
    "BUDLUM_DB_PATH",
    "BUDLUM_METRICS_API_KEY",
    "BUDLUM_MOBILE_MODE",
    "BUDLUM_NETWORK",
    "BUDLUM_ROLE",
    "BUDLUM_RPC_ALLOWED_IPS",
    "BUDLUM_RPC_API_KEY_ENV",
    "BUDLUM_RPC_AUTH_REQUIRED",
    "BUDLUM_RPC_RATE_LIMIT_PER_MINUTE",
    "BUDLUM_VALIDATOR_KEY",
    "BUDLUM_VERIFY_MERKLE", // removed env var, retained in a legacy list
    // Test-only fixture key.
    "BUDLUM_TUR6_RPC_TEST_KEY",
    // Slot role label (display string), not a hash domain.
    "BUDLUM_MAINNET_VALIDATOR",
    // Genesis transaction magic payload, compared by equality, not hashed as a domain.
    "BUDLUM_GENESIS_TX",
];

/// Scan `*.rs` files under `root` for tag literals, optionally excluding one
/// file name (the inventory itself).
fn tags_under(root: &Path, exclude: Option<&str>) -> BTreeSet<String> {
    let mut tags = BTreeSet::new();
    for dir in SCAN_DIRS {
        scan_dir(&root.join(dir), exclude, &mut tags);
    }
    tags
}

fn scan_dir(dir: &Path, exclude: Option<&str>, out: &mut BTreeSet<String>) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.filter_map(Result::ok).collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for e in entries {
        let Ok(path_kind) = e.file_type() else {
            continue;
        };
        let path = e.path();
        if path_kind.is_dir() {
            scan_dir(&path, exclude, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            if let Some(ex) = exclude {
                if path.file_name().is_some_and(|n| n == ex) {
                    continue;
                }
            }
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            extract(&text, out);
        }
    }
}

/// A literal is a tag candidate if it begins with `BDLM_` or `BUDLUM_` and
/// continues in `A-Z0-9_` past the prefix.
fn is_tag(lit: &str) -> bool {
    let prefix = if lit.starts_with("BDLM_") {
        "BDLM_"
    } else if lit.starts_with("BUDLUM_") {
        "BUDLUM_"
    } else {
        return false;
    };
    lit.len() > prefix.len()
        && lit
            .bytes()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
}

/// `"BDLM_..."` / `"BUDLUM_..."` literals, de-quoted.
fn extract(text: &str, out: &mut BTreeSet<String>) {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            if let Some(end) = text[i + 1..].find('"') {
                let lit = &text[i + 1..i + 1 + end];
                if is_tag(lit) {
                    out.insert(lit.to_string());
                }
                i += 1 + end + 1;
                continue;
            }
        }
        i += 1;
    }
}

/// # Errors
///
/// Returns a finding when a used tag is unlisted and not exempt (incomplete
/// inventory), a listed tag is unused (stale inventory), or an exempt literal
/// is unused (stale exemption).
pub fn run(root: &Path) -> Result<String, String> {
    let inventory_path = root.join(INVENTORY);
    if !inventory_path.is_file() {
        return Err(format!("missing inventory: {INVENTORY}"));
    }
    // `listed` comes from the inventory file alone; `used` comes from every
    // source file except the inventory itself (the shell gate's
    // `tags_in_inventory` / `tags_in_sources` split).
    let inventory_text =
        fs::read_to_string(&inventory_path).map_err(|e| format!("cannot read {INVENTORY}: {e}"))?;
    let mut listed = BTreeSet::new();
    extract(&inventory_text, &mut listed);
    let used = tags_under(root, Some("domain_tags.rs"));
    let exempt: BTreeSet<String> = EXEMPT.iter().copied().map(String::from).collect();

    // Used in code but neither listed nor exempt: an unreviewed domain.
    let missing: Vec<&String> = used
        .iter()
        .filter(|t| !listed.contains(*t) && !exempt.contains(*t))
        .collect();
    if !missing.is_empty() {
        let mut msg = format!("Tags used in code but absent from {INVENTORY} and not exempt:\n");
        for m in &missing {
            writeln!(msg, "  + {m}").expect("writing to a String cannot fail");
        }
        msg.push_str("inventory is incomplete: add separation tags to DOMAIN_TAGS, or non-separators to the EXEMPT list");
        return Err(msg);
    }

    // Listed in the inventory but no longer used: a surface that no longer exists.
    let extra: Vec<&String> = listed.difference(&used).collect();
    if !extra.is_empty() {
        let mut msg = format!("Tags listed in {INVENTORY} but unused in code:\n");
        for e in &extra {
            writeln!(msg, "  - {e}").expect("writing to a String cannot fail");
        }
        msg.push_str("inventory is stale");
        return Err(msg);
    }

    // Exempt but no longer used: the exemption outlived the literal.
    let stale_exempt: Vec<&String> = exempt.difference(&used).collect();
    if !stale_exempt.is_empty() {
        let mut msg = String::from("Exempt literals no longer used in code:\n");
        for e in &stale_exempt {
            writeln!(msg, "  ~ {e}").expect("writing to a String cannot fail");
        }
        msg.push_str("exemption list is stale");
        return Err(msg);
    }

    Ok(format!(
        "Domain tag inventory OK ({} tags, {} exempt)",
        listed.len(),
        exempt.len()
    ))
}

/// # Errors
///
/// Returns a finding when the canary tree does not behave: a matching tree
/// passes, exempt non-separators pass, an unlisted `BDLM_` or `BUDLUM_`
/// separator is caught, a listed-but-unused tag is caught, and a stale
/// exemption is caught.
pub fn self_test() -> Result<String, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let tmp =
        std::env::temp_dir().join(format!("budlum-gates-dtags-{}-{nanos}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    for d in ["src/crypto", "budzero", "crates/wallet-core"] {
        fs::create_dir_all(tmp.join(d)).map_err(|e| format!("cannot create fixture dir: {e}"))?;
    }

    // A fixture that "uses" every real EXEMPT literal, so the base tree
    // exercises exemption without tripping the stale-exemption check on the
    // other entries. Built from EXEMPT so it tracks the real list.
    let exempt_uses = format!(
        "const EXEMPT_USES: &[&str] = &[{}];\n",
        EXEMPT
            .iter()
            .map(|t| format!("\"{t}\""))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let used_with_exempt = format!("const A: &str = \"BDLM_LISTED_V1\";\n{exempt_uses}");

    // Base tree: one listed+used BDLM separator plus every exempt non-tag used.
    fs::write(
        tmp.join("src/crypto/domain_tags.rs"),
        "pub const DOMAIN_TAGS: &[&str] = &[\"BDLM_LISTED_V1\"];\n",
    )
    .map_err(|e| e.to_string())?;
    fs::write(tmp.join("src/used.rs"), used_with_exempt).map_err(|e| e.to_string())?;
    if run(&tmp).is_err() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "self-test: matching tree with exempt non-tags should pass",
        ));
    }

    // Unlisted BDLM separator -> caught.
    fs::write(
        tmp.join("src/sneaky.rs"),
        "const C: &str = \"BDLM_UNLISTED_V1\";\n",
    )
    .map_err(|e| e.to_string())?;
    if run(&tmp).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from("self-test: unlisted BDLM tag was not caught"));
    }

    // Unlisted BUDLUM separator -> caught (proves the prefix was broadened).
    fs::write(
        tmp.join("src/sneaky.rs"),
        "const D: &str = \"BUDLUM_SNEAKY_V1\";\n",
    )
    .map_err(|e| e.to_string())?;
    if run(&tmp).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "self-test: unlisted BUDLUM tag was not caught",
        ));
    }

    fs::remove_file(tmp.join("src/sneaky.rs")).map_err(|e| e.to_string())?;

    // Stale inventory (listed but unused).
    fs::write(
        tmp.join("src/crypto/domain_tags.rs"),
        "pub const DOMAIN_TAGS: &[&str] = &[\"BDLM_LISTED_V1\", \"BDLM_GONE_V1\"];\n",
    )
    .map_err(|e| e.to_string())?;
    if run(&tmp).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from("self-test: stale tag was not caught"));
    }

    // Stale exemption: restore the inventory, then drop every exempt use.
    fs::write(
        tmp.join("src/crypto/domain_tags.rs"),
        "pub const DOMAIN_TAGS: &[&str] = &[\"BDLM_LISTED_V1\"];\n",
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        tmp.join("src/used.rs"),
        "const A: &str = \"BDLM_LISTED_V1\";\n",
    )
    .map_err(|e| e.to_string())?;
    if run(&tmp).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from("self-test: stale exemption was not caught"));
    }

    let _ = fs::remove_dir_all(&tmp);
    Ok(String::from("Domain tag gate self-test OK"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_finds_tags() {
        let mut s = BTreeSet::new();
        extract(
            "const A: &str = \"BDLM_HELLO_V1\";\nlet b = \"BUDLUM_VRF\";\n",
            &mut s,
        );
        assert!(s.contains("BDLM_HELLO_V1"));
        assert!(s.contains("BUDLUM_VRF"));
    }

    #[test]
    fn extract_skips_non_tags() {
        let mut s = BTreeSet::new();
        extract(
            "\"not_a_tag\" \"BDLM_OK\" \"BUDLUM_OK\" \"xBDLM_NO\" \"xBUDLUM_NO\"",
            &mut s,
        );
        assert!(s.contains("BDLM_OK"));
        assert!(s.contains("BUDLUM_OK"));
        assert!(!s.contains("not_a_tag"));
        assert!(!s.contains("xBDLM_NO"));
        assert!(!s.contains("xBUDLUM_NO"));
    }
}
