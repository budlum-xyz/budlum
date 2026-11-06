//! The storage fee input is the physical byte.
//!
//! Physical bytes are object bytes times redundancy. A fee computed from a
//! declared, claimed or logical size is a hole a caller walks through: the
//! old three-regime meter returned zero held bytes and the fee with it. The
//! fee record splits the physical bytes it charges: `user_physical_bytes`
//! and `decentralization_physical_bytes`.
//!
//! No fee surface exists yet; this gate arms the contract. When a fee or
//! cost function lands in the storage path, its input is physical bytes.

use std::path::Path;

/// Roots scanned for fee surfaces.
const ROOTS: &[&str] = &["src"];

const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules"];

/// A size word that must never be the fee input.
const FORBIDDEN_INPUTS: &[&str] = &["declared_len", "claimed_len", "declared_bytes", "claimed_bytes"];

/// Lowered production code of one file.
fn production_code(text: &str) -> String {
    let no_tests = super::capability_modules_are_wired::strip_test_mods(text);
    no_tests
        .lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
        .to_lowercase()
}

fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, std::path::PathBuf)>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for e in entries {
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if p.is_dir() {
            if !SKIP_DIRS.contains(&name.as_str()) {
                walk(&p, root, out);
            }
        } else if name.ends_with(".rs") {
            if let Ok(rel) = p.strip_prefix(root) {
                out.push((rel.to_string_lossy().replace('\\', "/"), p.clone()));
            }
        }
    }
}

/// One `fn` block whose name carries a fee word.
fn fee_fn_bodies(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(at) = code[from..].find("fn ") {
        let start = from + at;
        let after = start + 3;
        let mut j = after;
        while j < code.len() && (code.as_bytes()[j].is_ascii_alphanumeric() || code.as_bytes()[j] == b'_') {
            j += 1;
        }
        let name = &code[after..j];
        let is_fee = (name.contains("fee") || name.contains("cost"))
            && (name.contains("storage") || name.contains("content") || name.contains("custody")
                || name.contains("upload") || name.contains("holding") || name.contains("bud3"));
        if is_fee {
            if let Some(brace) = code[j..].find('{') {
                let o = j + brace;
                let mut d = 0usize;
                let mut k = o;
                while k < code.len() {
                    if code.as_bytes()[k] == b'{' {
                        d += 1;
                    } else if code.as_bytes()[k] == b'}' {
                        d -= 1;
                        if d == 0 {
                            out.push(code[start..=k].to_string());
                            break;
                        }
                    }
                    k += 1;
                }
            }
        }
        from = j.max(start + 3);
    }
    out
}

/// # Errors
///
/// The fee function whose input is not physical bytes.
pub fn run(root: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    for r in ROOTS {
        let p = root.join(r);
        if p.exists() {
            walk(&p, root, &mut files);
        }
    }
    let mut checked = 0usize;
    for (rel, path) in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let code = production_code(&text);
        for body in fee_fn_bodies(&code) {
            checked += 1;
            for bad in FORBIDDEN_INPUTS {
                if body.contains(bad) {
                    return Err(format!(
                        "{rel}: a storage fee function takes `{bad}`. The fee input is the physical \\\n  byte (object bytes x redundancy): a declared or claimed size is a hole the caller \\\n  walks through."
                    ));
                }
            }
            if !body.contains("physical") {
                return Err(format!(
                    "{rel}: a storage fee function never names physical bytes. The fee input is \\\n  `physical_bytes`: object bytes times redundancy."
                ));
            }
        }
    }
    Ok(format!(
        "bud3 fee uses physical bytes OK: {checked} storage fee function(s) checked, contract armed for the fee surface"
    ))
}

/// The canary: a fee function on a declared size must fail.
///
/// # Errors
///
/// When the gate does not behave.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-fee")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };
        put("src/storage/bud3/fees.rs", "pub fn other() {}\n")?;
        run(&dir).map_err(|e| format!("canary: a clean tree failed: {e}"))?;
        put(
            "src/storage/bud3/fees.rs",
            "pub fn storage_fee(declared_len: u64) -> u64 { declared_len }\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a declared-size fee passed"));
        }
        put(
            "src/storage/bud3/fees.rs",
            "pub fn storage_fee(physical_bytes: u64) -> u64 { physical_bytes }\n",
        )?;
        run(&dir).map_err(|e| format!("canary: a physical-byte fee failed: {e}"))?;
        put(
            "src/storage/bud3/fees.rs",
            "pub fn storage_fee(len: u64) -> u64 { len }\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a fee that names no physical byte passed"));
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "bud3-fee-uses-physical-bytes canary OK: a declared-size fee failed and a physical-byte fee passed.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn bud3_fee_uses_physical_bytes_gate() {
        assert!(super::self_test().is_ok(), "{:?}", super::self_test());
    }
}
