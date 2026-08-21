//! The `BDLM_*` domain-separation tag inventory must not drift.
//!
//! Ported from `scripts/check-domain-tags.sh`. Every `BDLM_...` string
//! literal in the Rust sources must be listed in `src/crypto/domain_tags.rs`,
//! and every listed tag must still be used. A tag used but unlisted means a
//! new separation domain slipped in without review; a listed-but-unused tag
//! means the inventory is stale and a reviewer would check a surface that
//! does not exist.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

const INVENTORY: &str = "src/crypto/domain_tags.rs";

/// Scan `*.rs` files under `root` for `"BDLM_..."` literals, optionally
/// excluding one file name (the inventory itself).
fn tags_under(root: &Path, exclude: Option<&str>) -> BTreeSet<String> {
    let mut tags = BTreeSet::new();
    for dir in ["src", "budzero", "wallet-core"] {
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

/// `"BDLM_[A-Z0-9_]+"` literals, de-quoted.
fn extract(text: &str, out: &mut BTreeSet<String>) {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            if let Some(end) = text[i + 1..].find('"') {
                let lit = &text[i + 1..i + 1 + end];
                if lit.starts_with("BDLM_")
                    && lit.len() > "BDLM_".len()
                    && lit
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                {
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
    for d in ["src/crypto", "budzero", "wallet-core"] {
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

    fs::remove_file(tmp.join("src/sneaky.rs")).map_err(|e| e.to_string())?;
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
    fn extract_skips_non_tags() {
        let mut s = BTreeSet::new();
        extract("\"not_a_tag\" \"BDLM_OK\" \"xBDLM_NO\"", &mut s);
        assert!(s.contains("BDLM_OK"));
        assert!(!s.contains("not_a_tag"));
        assert!(!s.contains("xBDLM_NO"));
    }
}
