//! Every AIR selector column must be bound to its opcode, and every opcode
//! must have a selector.
//!
//! Ported from `scripts/check-air-selectors-are-opcode-bound.sh`. The ISA enum
//! discriminants are the source of truth; the AIR's `COL_IS_*` selectors must
//! appear in the binding sum `is_<op>.clone() * (opcode_here.clone() -
//! op(0xNN))` with the correct value.

use std::fmt::Write as _;
use std::path::Path;

fn strip_block_comments(text: &str) -> String {
    let mut out = String::new();
    let b = text.as_bytes();
    let mut i = 0;
    let mut depth = 0i32;
    while i < b.len() {
        if i + 1 < b.len() && b[i] == b'/' && b[i + 1] == b'*' {
            depth += 1;
            i += 2;
            continue;
        }
        if depth > 0 && i + 1 < b.len() && b[i] == b'*' && b[i + 1] == b'/' {
            depth -= 1;
            i += 2;
            continue;
        }
        if depth > 0 {
            i += 1;
            continue;
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

fn strip_non_code(text: &str) -> String {
    let mut out = String::new();
    for l in text.lines() {
        let idx = l.find("//").unwrap_or(l.len());
        out.push_str(&l[..idx]);
        out.push('\n');
    }
    let out = strip_block_comments(&out);
    // string/char literals -> "" / ''
    let mut out2 = String::new();
    let b = out.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'"' || b[i] == b'\'' {
            let q = b[i];
            out2.push(if q == b'"' { '"' } else { '\'' });
            i += 1;
            while i < b.len() {
                if b[i] == b'\\' && i + 1 < b.len() {
                    i += 2;
                    continue;
                }
                if b[i] == q {
                    i += 1;
                    break;
                }
                i += 1;
            }
        } else {
            out2.push(b[i] as char);
            i += 1;
        }
    }
    out2
}

/// ISA opcode discriminants: `    NAME = 0xNN,` at 4-space indent.
fn isa_opcodes(isa: &str) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    for line in isa.lines() {
        let t = line;
        if !t.starts_with("    ") {
            continue;
        }
        let rest = t.trim_start();
        let Some(eq) = rest.find('=') else {
            continue;
        };
        let name = rest[..eq].trim();
        let val = rest[eq + 1..].trim().trim_end_matches(',');
        let v = val
            .strip_prefix("0x")
            .or_else(|| val.strip_prefix("0X"))
            .and_then(|h| u32::from_str_radix(h, 16).ok());
        if let Some(v) = v {
            if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                out.push((name.to_string(), v));
            }
        }
    }
    out
}

/// Selector columns: `pub const COL_IS_<X>: usize = N;`.
fn parse_selectors(air_src: &str) -> Vec<String> {
    let mut selectors: Vec<String> = Vec::new();
    let mut rest = air_src;
    while let Some(pos) = rest.find("pub const COL_IS_") {
        let after = &rest[pos + "pub const COL_IS_".len()..];
        let name_end = after
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(after.len());
        let name = after[..name_end].to_string();
        if !name.is_empty() {
            selectors.push(name);
        }
        rest = &after[name_end..];
    }
    selectors
}

/// Binding sum: `is_<op>.clone() * (opcode_here.clone() - op(0xNN))`.
fn parse_binding_sum(air_src: &str) -> std::collections::HashMap<String, u32> {
    let mut bound: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    let mut rest = air_src;
    while let Some(pos) = rest.find("opcode_here.clone() - op(0x") {
        let before = &rest[..pos];
        let sel_start = before.rfind("is_").map_or(0, |s| s + 3);
        let sel_end = before[sel_start..]
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .map_or(before.len(), |e| sel_start + e);
        let sel = before[sel_start..sel_end].to_string();
        let after = &rest[pos + "opcode_here.clone() - op(0x".len()..];
        let hex_end = after
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(after.len());
        let v = u32::from_str_radix(&after[..hex_end], 16).ok();
        if let Some(v) = v {
            bound.insert(sel.to_uppercase(), v);
        }
        rest = &after[hex_end..];
    }
    bound
}

/// `COL_IS_<X>` -> ISA name by removing underscores, case-insensitive.
fn isa_name_for(selector: &str, opcodes: &[(String, u32)]) -> Option<String> {
    let flat = selector.replace('_', "").to_lowercase();
    opcodes
        .iter()
        .find(|(n, _)| n.to_lowercase() == flat)
        .map(|(n, _)| n.clone())
}

/// # Errors
///
/// Returns the list of violated claims.
pub fn run(root: &Path) -> Result<String, String> {
    let air_path = root.join("budzero/bud-proof/src/plonky3_air.rs");
    let isa_path = root.join("budzero/bud-isa/src/lib.rs");
    if !air_path.is_file() {
        return Err(format!("no AIR at {}", air_path.display()));
    }
    if !isa_path.is_file() {
        return Err(format!("no ISA at {}", isa_path.display()));
    }
    let air_src = strip_non_code(&std::fs::read_to_string(&air_path).map_err(|e| e.to_string())?);
    let isa_src = strip_non_code(&std::fs::read_to_string(&isa_path).map_err(|e| e.to_string())?);

    let opcodes = isa_opcodes(&isa_src);
    if opcodes.is_empty() {
        return Err(String::from(
            "no opcodes parsed out of the ISA - the gate would be vacuous",
        ));
    }

    let selectors = parse_selectors(&air_src);
    if selectors.is_empty() {
        return Err(String::from(
            "no COL_IS_* selectors found in the AIR - the gate would be vacuous",
        ));
    }

    let bound = parse_binding_sum(&air_src);
    if bound.is_empty() {
        return Err(String::from(
            "the selector to opcode binding sum was not found in the AIR.\n      \
             Either it was removed, or it was rewritten in a shape this gate\n      \
             cannot read. Both need looking at: with no binding, any row can\n      \
             be relabelled as any other opcode.",
        ));
    }

    let mut problems: Vec<String> = Vec::new();
    let mut selectors_sorted = selectors.clone();
    selectors_sorted.sort();
    for sel in &selectors_sorted {
        let Some(isa_name) = isa_name_for(sel, &opcodes) else {
            problems.push(format!(
                "selector COL_IS_{sel} matches no opcode in the ISA - either the \
                 opcode was removed and the column is dead, or it is misspelled"
            ));
            continue;
        };
        let opcode_val = opcodes
            .iter()
            .find(|(n, _)| n == &isa_name)
            .map_or(0, |(_, v)| *v);
        if !bound.contains_key(sel) {
            problems.push(format!(
                "selector COL_IS_{sel} (opcode {isa_name} = 0x{opcode_val:02X}) is not in \
                 the binding sum - a row carrying any other opcode could set it"
            ));
            continue;
        }
        if bound[sel] != opcode_val {
            problems.push(format!(
                "selector COL_IS_{sel} is bound to 0x{:02X} but \
                 {isa_name} encodes to 0x{opcode_val:02X}",
                bound[sel]
            ));
        }
    }

    // Direction 2: every opcode must have a selector.
    let selector_isa_names: Vec<String> = selectors
        .iter()
        .filter_map(|s| isa_name_for(s, &opcodes))
        .collect();
    for (name, value) in &opcodes {
        if !selector_isa_names.contains(name) {
            problems.push(format!(
                "opcode {name} = 0x{value:02X} has no COL_IS_* selector - \
                 a row carrying it is outside the exclusivity sum"
            ));
        }
    }

    if !problems.is_empty() {
        let mut msg = String::from("FAIL: the AIR's selector to opcode binding is incomplete:\n");
        for p in &problems {
            writeln!(msg, "  - {p}").expect("writing to a String cannot fail");
        }
        msg.push_str(
            "\nEvery per opcode rule runs under `builder.when(is_<op>)`. A selector \
             that nothing pins to an opcode lets a prover choose which rules apply \
             to a row.",
        );
        return Err(msg);
    }
    Ok(format!(
        "AIR selector binding OK: all {} selectors are bound to \
         their opcode, and all {} opcodes have a selector.",
        selectors.len(),
        opcodes.len()
    ))
}

/// # Errors
///
/// Returns a finding when a defect fixture passes.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-as")?;
    let _ = std::fs::create_dir_all(dir.join("budzero/bud-proof/src"));
    let _ = std::fs::create_dir_all(dir.join("budzero/bud-isa/src"));

    let isa = "pub enum Opcode {\n    HALT = 0x00,\n    ADD = 0x01,\n}\n";
    let air = "pub const COL_IS_HALT: usize = 1;\npub const COL_IS_ADD: usize = 2;\nlet z = is_HALT.clone() * (opcode_here.clone() - op(0x00));\nlet z2 = is_ADD.clone() * (opcode_here.clone() - op(0x01));\n";
    std::fs::write(dir.join("budzero/bud-isa/src/lib.rs"), isa).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("budzero/bud-proof/src/plonky3_air.rs"), air)
        .map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a correct binding was refused"));
    }
    // Wrong binding value.
    let bad = air.replace("op(0x01)", "op(0x02)");
    std::fs::write(dir.join("budzero/bud-proof/src/plonky3_air.rs"), bad)
        .map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a wrong binding passed"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "air-selectors canary OK (correct PASSes, a wrong binding FAILs).",
    ))
}
