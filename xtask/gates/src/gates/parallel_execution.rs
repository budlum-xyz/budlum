//! The registry state root is a fold over every field, in a fixed order.
//!
//! The chain may verify state transitions in parallel only if the state root
//! is a deterministic fold whose input order is fixed by the data, not by
//! iteration accidents. The B.U.D. 3.0 registry is the state that matters:
//! `Bud3Registry::state_root` folds every persisted map under a domain tag.
//! A field the fold skips is a field a parallel writer changes silently.
//!
//! This gate pins the coverage: every field of `Bud3Registry` is named in
//! the `state_root` body, and the fold carries its tag.

use std::path::Path;

const REGISTRY: &str = "src/storage/bud3/registry.rs";

/// Field names of `pub struct Bud3Registry`.
fn struct_fields(text: &str) -> Vec<String> {
    let start = text.find("pub struct Bud3Registry").unwrap_or(text.len());
    let body = &text[start..];
    let end = body.find('}').unwrap_or(body.len());
    let mut out = Vec::new();
    for line in body[..end].lines() {
        let t = line.trim();
        if t.starts_with("//") || t.starts_with('#') {
            continue;
        }
        if let Some((name, _)) = t.split_once(':') {
            let name = name.trim().trim_start_matches("pub ").trim();
            if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                out.push(name.to_string());
            }
        }
    }
    out
}

/// The body of `fn state_root`.
fn state_root_body(text: &str) -> Option<String> {
    let at = text.find("fn state_root")?;
    let brace = text[at..].find('{')?;
    let o = at + brace;
    let mut d = 0usize;
    let mut k = o;
    while k < text.len() {
        if text.as_bytes()[k] == b'{' {
            d += 1;
        } else if text.as_bytes()[k] == b'}' {
            d -= 1;
            if d == 0 {
                return Some(text[o..=k].to_string());
            }
        }
        k += 1;
    }
    None
}

/// # Errors
///
/// The field the fold skips, or the missing fold.
pub fn run(root: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(root.join(REGISTRY))
        .map_err(|e| format!("read {REGISTRY}: {e}"))?;
    let fields = struct_fields(&text);
    if fields.is_empty() {
        return Err(String::from(
            "registry.rs has no `pub struct Bud3Registry` fields the gate can read.",
        ));
    }
    let body = state_root_body(&text).ok_or_else(|| {
        String::from("registry.rs has no `fn state_root` body the gate can read.")
    })?;
    let mut missing = Vec::new();
    for f in &fields {
        if !body.contains(f) {
            missing.push(f.clone());
        }
    }
    if !missing.is_empty() {
        return Err(format!(
            "Bud3Registry::state_root skips field(s) {missing:?}. The state root folds every \n  persisted map in a fixed order; a skipped field changes without moving the root."
        ));
    }
    if !body.contains("REGISTRY_TAG") && !body.contains("tag") {
        return Err(String::from(
            "Bud3Registry::state_root folds without its domain tag. The tag keeps the fold \n  domain-separated from every other transcript.",
        ));
    }
    Ok(format!(
        "parallel execution OK: the state root folds all {} registry fields under the registry tag",
        fields.len()
    ))
}

/// The canary: a fold that skips a field must fail.
///
/// # Errors
///
/// When the gate does not behave.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-par")?;
    let result = (|| {
        let put = |body: &str| -> Result<(), String> {
            let p = dir.join(REGISTRY);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };
        put(
            "pub struct Bud3Registry {\n    objects: u8,\n    tombstones: u8,\n}\n\
             pub fn state_root(&self) -> [u8; 32] {\n    let _ = REGISTRY_TAG;\n    let _ = &self.objects;\n    let _ = &self.tombstones;\n    [0; 32]\n}\n",
        )?;
        run(&dir).map_err(|e| format!("canary: a full fold failed: {e}"))?;
        put(
            "pub struct Bud3Registry {\n    objects: u8,\n    tombstones: u8,\n}\n\
             pub fn state_root(&self) -> [u8; 32] {\n    let _ = REGISTRY_TAG;\n    let _ = &self.objects;\n    [0; 32]\n}\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a fold that skips tombstones passed"));
        }
        put(
            "pub struct Bud3Registry {\n    objects: u8,\n    tombstones: u8,\n}\n\
             pub fn state_root(&self) -> [u8; 32] {\n    let _ = &self.objects;\n    let _ = &self.tombstones;\n    [0; 32]\n}\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a fold with no domain tag passed"));
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "parallel-execution canary OK: a skipped field and a missing tag each failed.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn parallel_execution_gate() {
        assert!(super::self_test().is_ok(), "{:?}", super::self_test());
    }
}
