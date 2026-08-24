//! Generated content must be verifiable, float-free and metered.
//!
//! Ported from `scripts/check-generated-content-is-verifiable.sh`. Three
//! claims over `src/storage/generated.rs`: no floating point (a fork risk),
//! `generate_and_verify` actually checks `ContentId`/`IdMismatch`, and every
//! `draw_*` generator charges the meter.

use std::fmt::Write as _;
use std::path::Path;

fn code_of(root: &Path) -> Result<String, String> {
    let f = root.join("src/storage/generated.rs");
    if !f.is_file() {
        return Err(format!(
            "generated-content module missing at {}",
            f.display()
        ));
    }
    std::fs::read_to_string(&f).map_err(|e| e.to_string())
}

/// A float is `f32`/`f64` (types, `as` casts) or a `N.Nf` literal, with
/// comments stripped.
fn find_floats(text: &str) -> Vec<String> {
    let mut hits = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let stripped = line.split("//").next().unwrap_or("");
        let t = stripped.trim();
        if t.contains("f32") || t.contains("f64") || t.contains(" as f") {
            hits.push(format!("{}: {}", i + 1, t));
            continue;
        }
        // `N.Nf32` style literals.
        let bytes = t.as_bytes();
        let mut j = 0;
        while j + 2 < bytes.len() {
            if bytes[j].is_ascii_digit() && bytes[j + 1] == b'.' && bytes[j + 2].is_ascii_digit() {
                hits.push(format!("{}: {}", i + 1, t));
                break;
            }
            j += 1;
        }
    }
    hits
}

/// The body of `fn generate_and_verify` must mention `ContentId` or `IdMismatch`.
fn has_id_check(text: &str) -> bool {
    let start = text.find("fn generate_and_verify");
    let Some(start) = start else {
        return false;
    };
    let rest = &text[start..];
    let end = rest.find("}\n").map_or(rest.len(), |e| e + 2);
    let body = &rest[..end.min(rest.len())];
    body.contains("ContentId::of") || body.contains("IdMismatch")
}

/// Every `fn draw_*` must call `meter.charge`.
fn find_unmetered(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut idx = 0;
    while let Some(rel) = text[idx..].find("fn draw_") {
        let start = idx + rel;
        let after = &text[start + "fn draw_".len()..];
        let name_end = after
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(after.len());
        let name = format!("draw_{}", &after[..name_end]);
        // Body: to the closing brace at depth 1.
        let body_start = text[start..].find('{').map(|p| start + p + 1);
        let body = body_start.map(|bs| {
            let mut depth = 1i32;
            let mut i = bs;
            while i < text.len() {
                match text.as_bytes()[i] {
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            &text[bs..i]
        });
        if body.is_none_or(|b| !b.contains("meter.charge")) {
            out.push(name.clone());
        }
        idx = start + name.len() + 1;
    }
    out
}

/// # Errors
///
/// Returns a finding when a claim is violated.
pub fn run(root: &Path) -> Result<String, String> {
    let code = code_of(root)?;

    let floats = find_floats(&code);
    if !floats.is_empty() {
        let mut msg = String::from("floating point in a content generator:\n");
        for f in floats.iter().take(20) {
            writeln!(msg, "  {f}").expect("writing to a String cannot fail");
        }
        return Err(msg);
    }
    if !has_id_check(&code) {
        return Err(String::from(
            "generate_and_verify does not check ContentId / IdMismatch.\n  \
             A generator whose output is not hashed and compared to the manifest\n  \
             id proves nothing; the id claim becomes decoration.",
        ));
    }
    let unmetered = find_unmetered(&code);
    if !unmetered.is_empty() {
        return Err(format!(
            "generators that never charge the meter: {}\n  \
             A generator that cannot run out of budget is a DoS: anyone can\n  \
             upload a recipe whose cost is unbounded and every node pays it.",
            unmetered.join(", ")
        ));
    }
    Ok(String::from(
        "Generated-content gate OK: no floats, generate_and_verify checks the id, every draw_* is metered.",
    ))
}

/// # Errors
///
/// Returns a finding when a defect fixture passes.
pub fn self_test() -> Result<String, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!("budlum-gates-gen-{}-{nanos}", std::process::id()));
    let _ = std::fs::create_dir_all(dir.join("src/storage"));

    let good = "fn generate_and_verify() {\n    let id = ContentId::of(&bytes);\n    if id != expected { return IdMismatch; }\n}\nfn draw_thing(meter: &mut Meter) -> Vec<u8> {\n    meter.charge(1)?;\n    vec![]\n}\n";
    std::fs::write(dir.join("src/storage/generated.rs"), good).map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a clean module was refused"));
    }

    let floaty = "fn draw_thing(meter: &mut Meter) -> Vec<u8> {\n    let x: f64 = 0.5;\n    meter.charge(1)?;\n    vec![]\n}\n";
    std::fs::write(dir.join("src/storage/generated.rs"), floaty).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a generator containing f64 passed"));
    }

    let unmetered = "fn generate_and_verify() {\n    let id = ContentId::of(&bytes);\n}\nfn draw_thing(meter: &mut Meter) -> Vec<u8> {\n    vec![]\n}\n";
    std::fs::write(dir.join("src/storage/generated.rs"), unmetered).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a generator with no metre passed"));
    }

    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "generated-content canary OK (clean PASSes, float/metreless FAILs).",
    ))
}
