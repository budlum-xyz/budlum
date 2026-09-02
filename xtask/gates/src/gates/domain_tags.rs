//! The `BDLM_*` / `BUDLUM_*` domain-separation tag inventory must not drift.
//!
//! Ported from `scripts/check-domain-tags.sh`. Every quoted literal carrying
//! one of the two prefixes in the Rust sources must be listed in
//! `src/crypto/domain_tags.rs`, and every listed tag must still be used.
//! A tag used but unlisted means a new separation domain slipped in without
//! review; a listed-but-unused tag means the inventory is stale and a
//! reviewer would check a surface that does not exist.
//!
//! Two scope fixes are load-bearing, and both were measured, not assumed:
//!
//! 1. **Prefix blind spot.** The gate used to match only `BDLM_`. The tree
//!    carries a full legacy `BUDLUM_` generation from before the rename:
//!    23 hash/signature tags (finality, consensus, `PoA`, note registry,
//!    wallet-core key derivation) plus 14 non-domain literals (env vars,
//!    HSM slot label, CLI/test strings). None of them reached the
//!    inventory, so a separation tag could be edited in those files without
//!    any review surface noticing. The gate now matches both prefixes, and
//!    the inventory lists all of them - including the non-domain ones, so
//!    the gate needs no hidden exception list to stay total.
//! 2. **Path blind spot.** The scan used to read `src`, `budzero` and a
//!    literal `wallet-core` directory that does not exist (the crate lives
//!    at `crates/wallet-core`). `scan_dir` returns early on a missing
//!    directory, so the wallet-core surface was never looked at. The scan
//!    became `src` + `budzero` + `crates`.
//! 3. **The `bud/` exemption.** `bud/` was then left out on the grounds
//!    that it is a separate workspace with its own `BDLM_BUD_*` constellation
//!    and its own gates. Measured (2026-09-02): `bud/` has no domain-tag
//!    gate of its own, it carries 55 distinct tags, and one of them,
//!    `BDLM_CONTENT_V1`, is also used by `src/storage/content_id.rs` and
//!    `budzero/bud-node/src/store.rs`. A tag shared across trees is the
//!    collision case the inventory exists to review, and it sat outside the
//!    review surface. The scan is `src` + `budzero` + `crates` + `bud` now.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

const INVENTORY: &str = "src/crypto/domain_tags.rs";

/// Scan `*.rs` files under `root` for literals with either tag prefix,
/// optionally excluding one file name (the inventory itself).
fn tags_under(root: &Path, exclude: Option<&str>) -> BTreeSet<String> {
    let mut tags = BTreeSet::new();
    for dir in ["src", "budzero", "crates", "bud"] {
        let base = root.join(dir);
        scan_dir(&base, exclude, &mut tags);
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

/// `"BDLM_[A-Z0-9_]+"` and `"BUDLUM_[A-Z0-9_]+"` literals, de-quoted.
///
/// The scanner used to pair every `"` with the next `"` and skip the span
/// between them. A character literal `'"'` (a quote-tracking parser has one,
/// `bud/src/bud_format_container.rs:71`) flipped that pairing for the rest
/// of the file, so every tag after it sat inside a span the scanner treated
/// as "between strings" and was never seen: two tags in that file, one of
/// them `BDLM_CONTENT_V1`. The scanner now looks for the tag shape directly
/// at each `"` instead of trusting quote parity: a tag is a `"`, the prefix,
/// the body characters, and a closing `"`. It cannot lose sync because it
/// never skips ahead further than one literal it has fully recognised.
fn extract(text: &str, out: &mut BTreeSet<String>) {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let rest = &text[i + 1..];
            let prefix_len = if rest.starts_with("BUDLUM_") {
                Some("BUDLUM_".len())
            } else if rest.starts_with("BDLM_") {
                Some("BDLM_".len())
            } else {
                None
            };
            if let Some(prefix_len) = prefix_len {
                let body_len = rest[prefix_len..]
                    .bytes()
                    .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
                    .count();
                let end = prefix_len + body_len;
                if body_len > 0 && rest.as_bytes().get(end) == Some(&b'"') {
                    out.insert(rest[..end].to_string());
                    i += 1 + end + 1;
                    continue;
                }
            }
        }
        i += 1;
    }
}

/// # Errors
///
/// Returns a finding when a used tag is unlisted (incomplete inventory) or a
/// listed tag is unused (stale inventory).
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

    let missing: Vec<&String> = used.difference(&listed).collect();
    if !missing.is_empty() {
        let mut msg = format!("Domain tags used in code but absent from {INVENTORY}:\n");
        for m in &missing {
            writeln!(msg, "  + {m}").expect("writing to a String cannot fail");
        }
        msg.push_str("inventory is incomplete");
        return Err(msg);
    }

    let extra: Vec<&String> = listed.difference(&used).collect();
    if !extra.is_empty() {
        let mut msg = format!("Domain tags listed in {INVENTORY} but unused in code:\n");
        for e in &extra {
            writeln!(msg, "  - {e}").expect("writing to a String cannot fail");
        }
        msg.push_str("inventory is stale");
        return Err(msg);
    }

    Ok(format!("Domain tag inventory OK ({} tags)", listed.len()))
}

/// # Errors
///
/// Returns a finding when the canary tree does not behave: matching tree
/// passes, an unlisted used tag is caught, a listed-but-unused tag is caught.
pub fn self_test() -> Result<String, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let tmp =
        std::env::temp_dir().join(format!("budlum-gates-dtags-{}-{nanos}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    for d in ["src/crypto", "budzero", "crates/wallet-core/src", "bud/src"] {
        fs::create_dir_all(tmp.join(d)).map_err(|e| format!("cannot create fixture dir: {e}"))?;
    }
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

    if run(&tmp).is_err() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from("self-test: matching tree should pass"));
    }

    fs::write(
        tmp.join("src/sneaky.rs"),
        "const B: &str = \"BDLM_UNLISTED_V1\";\n",
    )
    .map_err(|e| e.to_string())?;
    if run(&tmp).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from("self-test: unlisted tag was not caught"));
    }

    // The `BUDLUM_` prefix lives in code that predates the rename; an
    // unlisted legacy tag must trip the gate just like a `BDLM_` one.
    fs::write(
        tmp.join("src/sneaky.rs"),
        "const B: &[u8] = b\"BUDLUM_UNLISTED_V1\";\n",
    )
    .map_err(|e| e.to_string())?;
    if run(&tmp).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "self-test: unlisted legacy-prefix tag was not caught",
        ));
    }

    // A tag under `crates/` must be seen: the scan used to name a
    // nonexistent top-level `wallet-core` directory, which made the whole
    // wallet surface invisible without a single error.
    fs::remove_file(tmp.join("src/sneaky.rs")).map_err(|e| e.to_string())?;
    fs::write(
        tmp.join("crates/wallet-core/src/lib.rs"),
        "const C: &[u8] = b\"BUDLUM_UNLISTED_V1\";\n",
    )
    .map_err(|e| e.to_string())?;
    if run(&tmp).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "self-test: tag under crates/ was not seen (path blind spot)",
        ));
    }

    // A tag under `bud/` must be seen too: the B.U.D. workspace was
    // exempted as "having its own gates", and it has none for this.
    fs::remove_file(tmp.join("crates/wallet-core/src/lib.rs")).map_err(|e| e.to_string())?;
    fs::write(
        tmp.join("bud/src/lib.rs"),
        "const D: &[u8] = b\"BDLM_BUD_UNLISTED_V1\";\n",
    )
    .map_err(|e| e.to_string())?;
    if run(&tmp).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "self-test: tag under bud/ was not seen (workspace blind spot)",
        ));
    }

    fs::remove_file(tmp.join("bud/src/lib.rs")).map_err(|e| e.to_string())?;
    fs::write(
        tmp.join("src/crypto/domain_tags.rs"),
        "pub const DOMAIN_TAGS: &[&str] = &[\"BDLM_LISTED_V1\", \"BDLM_GONE_V1\"];\n",
    )
    .map_err(|e| e.to_string())?;
    if run(&tmp).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from("self-test: stale tag was not caught"));
    }

    let _ = fs::remove_dir_all(&tmp);
    Ok(String::from("Domain tag gate self-test OK"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `'"'` character literal must not hide the tags after it.
    #[test]
    fn extract_survives_a_quote_character_literal() {
        let mut s = BTreeSet::new();
        extract(
            "if c == '\"' { flip(); }\nlet tag = b\"BDLM_AFTER_V1\";\n",
            &mut s,
        );
        assert!(
            s.contains("BDLM_AFTER_V1"),
            "a quote character literal desynchronised the scanner: {s:?}"
        );
    }

    /// A tag-shaped word that is not a complete literal is not a tag.
    #[test]
    fn extract_requires_a_closing_quote() {
        let mut s = BTreeSet::new();
        extract("let x = \"BDLM_OPEN_V1 and more\";\n", &mut s);
        assert!(s.is_empty(), "got {s:?}");
    }

    #[test]
    fn extract_finds_tags() {
        let mut s = BTreeSet::new();
        extract(
            "const A: &str = \"BDLM_HELLO_V1\";\nlet b = \"BDLM_OTHER\";\n",
            &mut s,
        );
        assert!(s.contains("BDLM_HELLO_V1"));
        assert!(s.contains("BDLM_OTHER"));
    }

    #[test]
    fn extract_finds_legacy_prefix_tags() {
        let mut s = BTreeSet::new();
        extract(
            "const A: &[u8] = b\"BUDLUM_ADDRESS_V2\";\nlet b = \"BUDLUM_GENESIS_TX\";\n",
            &mut s,
        );
        assert!(s.contains("BUDLUM_ADDRESS_V2"));
        assert!(s.contains("BUDLUM_GENESIS_TX"));
    }

    #[test]
    fn extract_skips_non_tags() {
        let mut s = BTreeSet::new();
        extract("\"not_a_tag\" \"BDLM_OK\" \"xBDLM_NO\"", &mut s);
        assert!(s.contains("BDLM_OK"));
        assert!(!s.contains("not_a_tag"));
        assert!(!s.contains("xBDLM_NO"));
    }

    #[test]
    fn extract_skips_non_matching_legacy_strings() {
        let mut s = BTreeSet::new();
        extract(
            "\"BUDLUM_RPC_AUTH_REQUIRED=0\" \"BUDLUM_\" \"prefixBUDLUM_X\"",
            &mut s,
        );
        assert!(s.is_empty(), "unexpected matches: {s:?}");
    }
}
