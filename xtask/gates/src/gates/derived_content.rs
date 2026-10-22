//! Derived content must stay byte-exact.
//!
//! Ported from `scripts/check-derived-content-stays-byte-exact.sh`. The
//! derived-content module must express crop boxes in blocks (not pixels), pin
//! `DERIVED_BLOCK_PIXELS` to 16, refuse derivation chains, and use no
//! floating point. Each claim is a presence/absence check over the module
//! source with comments stripped.

use std::path::Path;

fn target(root: &Path) -> Result<std::path::PathBuf, String> {
    let f = root.join("src/storage/derived.rs");
    if !f.is_file() {
        return Err(format!("derived content module missing: {}", f.display()));
    }
    Ok(f)
}

/// Source with `//` comments stripped, line by line.
fn code_of(root: &Path) -> Result<String, String> {
    let f = target(root)?;
    let text = std::fs::read_to_string(&f).map_err(|e| e.to_string())?;
    Ok(text
        .lines()
        .map(|l| l.split("//").next().unwrap_or("").to_string())
        .collect::<Vec<_>>()
        .join("\n"))
}

fn has(code: &str, pat: &str) -> bool {
    code.contains(pat)
}

/// The u32 fields declared as `pub <name>: u32` in the module.
fn u32_field_names(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in code.lines() {
        let t = line.trim();
        let rest = t.strip_prefix("pub ").unwrap_or("");
        let name_end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        let name = &rest[..name_end];
        let after = rest[name_end..].trim_start();
        if after.starts_with(": u32") || after.starts_with(":u32") {
            out.push(name.to_string());
        }
    }
    out
}

/// Any declared u32 field named exactly one of `names`?
fn has_any_field(code: &str, names: &[&str]) -> bool {
    u32_field_names(code)
        .iter()
        .any(|f| names.contains(&f.as_str()))
}

/// A floating-point literal appears (digit.digit, or a float type).
fn has_float(code: &str) -> bool {
    if code.lines().any(|l| {
        let t = l.trim();
        t.contains("f32") || t.contains("f64") || t.contains(": f32") || t.contains(": f64")
    }) {
        return true;
    }
    code.lines().any(|l| {
        let t = l.trim();
        let bytes = t.as_bytes();
        (0..bytes.len().saturating_sub(1)).any(|i| {
            bytes[i].is_ascii_digit()
                && bytes[i + 1] == b'.'
                && bytes.get(i + 2).is_some_and(u8::is_ascii_digit)
        })
    })
}

/// # Errors
///
/// Returns the first violated claim.
pub fn run(root: &Path) -> Result<String, String> {
    let code = code_of(root)?;

    // 1. The box is expressed in blocks.
    for field in ["block_x", "block_y", "block_w", "block_h"] {
        if !has(&code, &format!("pub {field}: u32")) {
            return Err(format!(
                "DerivedSpec has no `{field}`.\n  The box must be expressed in blocks. In pixels, a misaligned crop is\n  representable, and a misaligned crop cannot be recomputed byte-exactly."
            ));
        }
    }
    if has_any_field(
        &code,
        &[
            "pixel_x", "pixel_y", "pixel_w", "pixel_h", "x", "y", "w", "h",
        ],
    ) {
        return Err(String::from(
            "DerivedSpec carries a pixel-coordinate field.\n  That makes an unrepresentable state representable again.",
        ));
    }

    // 2. The block size is conservative.
    if !has(&code, "DERIVED_BLOCK_PIXELS: u32 = 16;") {
        return Err(String::from(
            "DERIVED_BLOCK_PIXELS is not 16.\n  8 is correct for luma and wrong for 4:2:0 chroma, where the planes are\n  halved. 16 is what jpegtran uses, for this reason.",
        ));
    }

    // 3. Derivations do not chain.
    if !has(&code, "DerivationChain") {
        return Err(String::from(
            "there is no DerivationChain refusal.\n  A derivation naming another derivation has an unbounded dependency depth.",
        ));
    }
    if !has(&code, "fn check_master_is_stored") {
        return Err(String::from(
            "check_master_is_stored is gone, so nothing enforces the refusal.",
        ));
    }

    // 4. No floating point.
    if has_float(&code) {
        return Err(String::from(
            "floating point in the derived content module.\n  Two nodes that produce different answers disagree about whether an object\n  is valid, which is a fork. This module decides validity.",
        ));
    }

    Ok(String::from(
        "Derived-content gate OK: block box, 16-px block, no chaining, no floats.",
    ))
}

/// # Errors
///
/// Returns a finding when a defect fixture passes the gate.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-derived")?;
    let _ = std::fs::create_dir_all(dir.join("src/storage"));

    // Good module.
    let good = "pub struct DerivedSpec {\n    pub block_x: u32,\n    pub block_y: u32,\n    pub block_w: u32,\n    pub block_h: u32,\n}\npub const DERIVED_BLOCK_PIXELS: u32 = 16;\npub struct DerivationChain;\nfn check_master_is_stored() {}\nfn f() -> u32 { 1 + 2 }\n";
    std::fs::write(dir.join("src/storage/derived.rs"), good).map_err(|e| e.to_string())?;
    let good_ok = run(&dir).is_ok();

    // Pixel-coordinate defect.
    let pixel = "pub struct DerivedSpec {\n    pub pixel_x: u32,\n}\n";
    std::fs::write(dir.join("src/storage/derived.rs"), pixel).map_err(|e| e.to_string())?;
    let pixel_fails = run(&dir).is_err();

    // Float defect.
    let floaty = "pub struct DerivedSpec {\n    pub block_x: u32,\n    pub block_y: u32,\n    pub block_w: u32,\n    pub block_h: u32,\n}\npub const DERIVED_BLOCK_PIXELS: u32 = 16;\npub struct DerivationChain;\nfn check_master_is_stored() {}\nfn f() -> f64 { 1.5 }\n";
    std::fs::write(dir.join("src/storage/derived.rs"), floaty).map_err(|e| e.to_string())?;
    let float_fails = run(&dir).is_err();

    let _ = std::fs::remove_dir_all(&dir);

    if !good_ok {
        return Err(String::from("canary: a clean module was refused"));
    }
    if !pixel_fails {
        return Err(String::from("canary: a pixel coordinate space passed"));
    }
    if !float_fails {
        return Err(String::from("canary: a floating point value passed"));
    }
    Ok(String::from(
        "derived-content canary OK (clean PASSes, pixel/float FAILs).",
    ))
}
