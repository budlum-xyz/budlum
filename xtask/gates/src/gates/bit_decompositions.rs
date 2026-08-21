//! A bit decomposition must be pinned to the canonical representative, not
//! just reconstitute to the right field element.
//!
//! Ported from `scripts/check-bit-decompositions-are-canonical.sh`.
//!
//! # The failure this closes
//!
//! `Lt`, `Gt`, `Lte`, `Gte`, `And`, `Or` and `Xor` all answer from the 64 bit
//! columns rather than from the register value. The only thing tying the bits
//! to the value was booleanity plus `sum(b_i * 2^i) == rs_val`, and that is
//! not enough. Goldilocks is `P = 2^64 - 2^32 + 1`, so `2^64 > P` and a 64 bit
//! pattern can sit at or above the modulus and wrap. Every value below
//! `2^32 - 1` therefore has a second valid bit string: `rs_val = 5` has both
//! `0x0000000000000005` and `0xFFFFFFFF00000006` (`= 5 + P`, still under
//! `2^64`). Both reconstitute to 5, but the comparison opcodes read the bits,
//! so the prover picks which answer it gets.
//!
//! # What is checked
//!
//! For each decomposed operand:
//!
//! * the reconstitution constraint still exists (the bits stay tied to the
//!   register value),
//! * every bit is asserted boolean,
//! * a canonicity witness column exists and is read into the AIR,
//! * both halves of the canonicity rule are present: the inverse is pinned
//!   (`d * (1 - z) == 0`) and the saturated case costs something
//!   (`(1 - z) * lo == 0`).
//!
//! The last pair is the trap: a witness that is declared and multiplied but
//! never pinned looks like a canonicity check and enforces nothing. The prover
//! has to fill the witness, and the difference has to be computed in the field
//! rather than with `wrapping_sub`.

use std::fmt::Write as _;
use std::path::Path;

/// The operands whose decomposition must be canonical.
const OPERANDS: [(&str, &str, &str); 2] = [
    ("COL_CMP_RS1_BASE", "COL_CMP_RS1_HI_INV", "rs1"),
    ("COL_CMP_RS2_BASE", "COL_CMP_RS2_HI_INV", "rs2"),
];

/// Python `\s`: space, tab, newline, carriage return, form feed, vertical tab.
fn skip_py_ws(s: &str) -> &str {
    let mut idx = 0usize;
    for (i, c) in s.char_indices() {
        if matches!(c, ' ' | '\t' | '\n' | '\r' | '\u{000c}' | '\u{000b}') {
            idx = i + c.len_utf8();
        } else {
            break;
        }
    }
    &s[idx..]
}

/// A word boundary right after this point: the next character, if any, is not
/// a word character. Python's `\b`.
fn word_boundary_after(s: &str) -> bool {
    s.chars()
        .next()
        .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'))
}

/// After `\s*` the literal must appear immediately, then the rest recurses.
///
/// Python `\s*` is whitespace only, so a literal cannot be found later in the
/// text past non-whitespace: `wrapping_sub(src1_val...)` does not match
/// `wrapping_sub\(\s*0xFFFF_FFFF` even when `0xFFFF_FFFF` appears later.
fn ws_seq_at(rest: &str, needles: &[&str]) -> bool {
    let Some((first, tail)) = needles.split_first() else {
        return true;
    };
    let r = skip_py_ws(rest);
    let Some(after) = r.strip_prefix(first) else {
        return false;
    };
    ws_seq_at(after, tail)
}

/// Search the whole text for the whitespace-separated literal chain, trying
/// each occurrence of the first literal.
fn ws_seq(text: &str, needles: &[&str]) -> bool {
    let mut from = 0usize;
    while let Some(pos) = text[from..].find(needles[0]) {
        let abs = from + pos;
        if ws_seq_at(&text[abs + needles[0].len()..], &needles[1..]) {
            return true;
        }
        from = abs + needles[0].len();
    }
    false
}

/// Blank line comments, the one sanitization the shell version applies before
/// searching the AIR (`re.sub(r"//[^\n]*", "", air_src)`).
fn strip_line_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let Some(pos) = line.find("//") else {
            out.push_str(line);
            continue;
        };
        out.push_str(&line[..pos]);
        for c in line[pos..].chars() {
            out.push(if c == '\n' { '\n' } else { ' ' });
        }
    }
    out
}

/// The bit locals the AIR reads out of `cur[BASE + i]`, matching
/// `let\s+(\w+)\s*:[^=]*=\s*cur\[\s*BASE\s*\+`.
fn bit_locals(code: &str, base: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(pos) = code[from..].find("let") {
        let abs = from + pos;
        if let Some(name) = bit_local_at(&code[abs + 3..], base) {
            out.push(name.to_string());
        }
        from = abs + 3;
    }
    out
}

/// `let\s+(\w+)\s*:[^=]*=\s*cur\[\s*BASE\s*\+`, starting right after `let`.
fn bit_local_at<'a>(r: &'a str, base: &str) -> Option<&'a str> {
    let after_ws = skip_py_ws(r);
    if after_ws.len() == r.len() {
        return None; // `\s+` after `let` is required
    }
    let name_end = after_ws
        .char_indices()
        .take_while(|&(_, c)| c.is_ascii_alphanumeric() || c == '_')
        .map(|(i, c)| i + c.len_utf8())
        .last()?;
    let name = &after_ws[..name_end];
    // `\s*:` then `[^=]*=` then `\s*cur[` then `\s*BASE` then `\s*+`
    let after_colon = skip_py_ws(&after_ws[name_end..]).strip_prefix(':')?;
    let eq_rel = after_colon.find('=')?;
    let after_cur = skip_py_ws(&after_colon[eq_rel + 1..]).strip_prefix("cur[")?;
    let after_base = skip_py_ws(after_cur).strip_prefix(base)?;
    if skip_py_ws(after_base).starts_with('+') {
        Some(name)
    } else {
        None
    }
}

/// `assert_bool\(\s*LOC\b`
fn assert_bool_local(code: &str, loc: &str) -> bool {
    let mut from = 0usize;
    while let Some(pos) = code[from..].find("assert_bool(") {
        let abs = from + pos;
        let r = skip_py_ws(&code[abs + "assert_bool(".len()..]);
        if let Some(after) = r.strip_prefix(loc) {
            if word_boundary_after(after) {
                return true;
            }
        }
        from = abs + 1;
    }
    false
}

/// `assert_bool\(\s*z\b`
fn bool_z(code: &str) -> bool {
    let mut from = 0usize;
    while let Some(pos) = code[from..].find("assert_bool(") {
        let abs = from + pos;
        let r = skip_py_ws(&code[abs + "assert_bool(".len()..]);
        if let Some(after) = r.strip_prefix('z') {
            if word_boundary_after(after) {
                return true;
            }
        }
        from = abs + 1;
    }
    false
}

/// The inverse is pinned to the difference it claims.
fn pinned(code: &str) -> bool {
    ws_seq(
        code,
        &["assert_zero(", "d", "*", "(", "AB::Expr::ONE", "-", "z"],
    ) || code.contains("assert_zero(d * (AB::Expr::ONE - z")
}

/// The saturated case costs something: `(1 - z) * lo == 0`.
fn costs(code: &str) -> bool {
    ws_seq(
        code,
        &[
            "assert_zero(",
            "(",
            "AB::Expr::ONE",
            "-",
            "z",
            ")",
            "*",
            "lo",
        ],
    )
}

/// Check one decomposed operand: reconstitution, booleanity, witness
/// presence, witness read, and both halves of the canonicity rule.
///
/// Returns the findings and the number of checks performed, mirroring the
/// shell version's `checked` accounting.
fn check_operand(
    air_src: &str,
    code: &str,
    base: &str,
    inv: &str,
    name: &str,
) -> (Vec<String>, usize) {
    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    if !air_src.contains(base) {
        problems.push(format!(
            "{base} is gone from the AIR. If the decomposition was removed the \
             entry here should go with it, in the same commit, with the reason."
        ));
        return (problems, checked);
    }

    checked += 1;

    // The decomposition has to still be tied to the register value.
    if !ws_seq(code, &[base, "+", "i", "]"]) {
        problems.push(format!(
            "{base} is no longer indexed per bit, so this gate cannot tell \
             whether the decomposition is still reconstituted. Update the gate \
             together with the rewrite."
        ));
        return (problems, checked);
    }

    // Booleanity is written against the local the bit is read into, not
    // against `cur[BASE + i]`, so follow the local.
    let locals = bit_locals(code, base);
    if !locals.iter().any(|loc| assert_bool_local(code, loc)) {
        problems.push(format!(
            "the bits of {name} are not asserted boolean, so the \
             reconstitution sum can be satisfied by field elements that are \
             not bits at all."
        ));
    }

    // Canonicity witness must exist, be read, and be pinned on both sides.
    if !air_src.contains(inv) {
        problems.push(format!(
            "{name} has no canonicity witness ({inv}). Booleanity plus \
             `sum(b_i * 2^i) == val` admits two bit strings for every value \
             below 2^32 - 1, because 2^64 > P, and the comparison opcodes read \
             the bits, so the prover chooses the answer."
        ));
        return (problems, checked);
    }

    checked += 1;

    let read_directly = ws_seq(code, &["cur[", inv, "]"]);
    let read_via_pair = ws_seq(code, &[base, ",", inv]) && ws_seq(code, &["cur[", "inv_col", "]"]);
    if !(read_directly || read_via_pair) {
        problems.push(format!(
            "{inv} is declared but never read by the AIR, so it is a column \
             the prover fills and nothing consults."
        ));
        return (problems, checked);
    }

    if !bool_z(code) {
        problems.push(format!(
            "the canonicity flag derived from {inv} is not asserted boolean, \
             so the witness can take a value that is neither 0 nor 1."
        ));
    }
    if !pinned(code) {
        problems.push(format!(
            "nothing forces the canonicity flag to 1 when the high half is not \
             saturated, so a prover writes zero for {inv} and the low-half rule \
             below never fires. A witness that is multiplied but not pinned \
             enforces nothing."
        ));
    }
    if !costs(code) {
        problems.push(String::from(
            "a saturated high half costs nothing: the rule that the low half \
             must then be zero is missing, so the non-canonical patterns are \
             still available.",
        ));
    }
    checked += 3;
    (problems, checked)
}

/// # Errors
///
/// Missing files, a decomposition that is not canonical, or a gate that
/// checked nothing.
pub fn run(root: &Path) -> Result<String, String> {
    let air = root.join("budzero/bud-proof/src/plonky3_air.rs");
    let prover = root.join("budzero/bud-proof/src/plonky3_prover.rs");

    for (path, what) in [(&air, "AIR"), (&prover, "prover")] {
        if !path.is_file() {
            return Err(format!("FAIL: no {what} at {}", path.display()));
        }
    }

    let air_src = std::fs::read_to_string(&air).unwrap_or_default();
    let prover_src = std::fs::read_to_string(&prover).unwrap_or_default();
    let code = strip_line_comments(&air_src);

    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for (base, inv, name) in OPERANDS {
        let (p, c) = check_operand(&air_src, &code, base, inv, name);
        problems.extend(p);
        checked += c;
    }

    // The prover has to fill the witness, or every honest proof fails.
    for (_, inv, _name) in OPERANDS {
        if air_src.contains(inv) && !prover_src.contains(inv) {
            problems.push(format!(
                "prover: {inv} is read by the AIR but never filled, so no honest \
                 proof for a comparison can exist."
            ));
        } else {
            checked += 1;
        }
    }

    // The subtraction has to happen in the field. For a high half of 0,
    // `wrapping_sub` gives 0xFFFFFFFF00000001 while the field difference is
    // `P - 0xFFFFFFFF`, and those are different elements.
    if air_src.contains("COL_CMP_RS1_HI_INV")
        && ws_seq(&prover_src, &["wrapping_sub(", "0xFFFF_FFFF"])
    {
        problems.push(String::from(
            "prover: the canonicity difference is computed with `wrapping_sub` \
             rather than in the field. Those disagree for every high half below \
             0xFFFFFFFF, so the witness would be the inverse of the wrong element.",
        ));
    }
    checked += 1;

    if checked == 0 {
        return Err(String::from("FAIL: gate checked nothing"));
    }

    if !problems.is_empty() {
        let mut msg = String::new();
        for p in &problems {
            let _ = writeln!(msg, "FAIL: {p}");
        }
        return Err(msg);
    }

    Ok(format!(
        "bit decomposition gate OK: {checked} checks, both operands pinned to the canonical representative"
    ))
}

// ---------------------------------------------------------------------------
// Self-test: the eight canaries of the shell version.
// ---------------------------------------------------------------------------

const GOOD_AIR: &str = r"pub const COL_CMP_RS1_BASE: usize = 65;
pub const COL_CMP_RS2_BASE: usize = 129;
pub const COL_CMP_RS1_HI_INV: usize = 738;
pub const COL_CMP_RS2_HI_INV: usize = 739;
        for i in 0..64 {
            let a_bit: AB::Expr = cur[COL_CMP_RS1_BASE + i].into();
            let b_bit: AB::Expr = cur[COL_CMP_RS2_BASE + i].into();
            builder.when(is_cmp_or_bw.clone()).assert_bool(a_bit);
            builder.when(is_cmp_or_bw.clone()).assert_bool(b_bit);
        }
        {
            for (base, inv_col) in [
                (COL_CMP_RS1_BASE, COL_CMP_RS1_HI_INV),
                (COL_CMP_RS2_BASE, COL_CMP_RS2_HI_INV),
            ] {
                let d_inv: AB::Expr = cur[inv_col].into();
                let z = d.clone() * d_inv;
                builder.when(is_cmp_or_bw.clone()).assert_bool(z.clone());
                builder.when(is_cmp_or_bw.clone()).assert_zero(d * (AB::Expr::ONE - z.clone()));
                builder.when(is_cmp_or_bw.clone()).assert_zero((AB::Expr::ONE - z) * lo);
            }
        }";

const GOOD_PROVER: &str = r"            let d = bud_vm::field_sub_goldilocks(hi, 0xFFFF_FFFF);
            values[row_start + COL_CMP_RS1_HI_INV] = Goldilocks::new(inv);
            values[row_start + COL_CMP_RS2_HI_INV] = Goldilocks::new(inv);";

const NO_WITNESS_AIR: &str = r"pub const COL_CMP_RS1_BASE: usize = 65;
pub const COL_CMP_RS2_BASE: usize = 129;
        for i in 0..64 {
            let a_bit: AB::Expr = cur[COL_CMP_RS1_BASE + i].into();
            let b_bit: AB::Expr = cur[COL_CMP_RS2_BASE + i].into();
            builder.when(is_cmp_or_bw.clone()).assert_bool(a_bit);
            builder.when(is_cmp_or_bw.clone()).assert_bool(b_bit);
        }";

const UNREAD_AIR: &str = r"pub const COL_CMP_RS1_BASE: usize = 65;
pub const COL_CMP_RS2_BASE: usize = 129;
pub const COL_CMP_RS1_HI_INV: usize = 738;
pub const COL_CMP_RS2_HI_INV: usize = 739;
        for i in 0..64 {
            let a_bit: AB::Expr = cur[COL_CMP_RS1_BASE + i].into();
            let b_bit: AB::Expr = cur[COL_CMP_RS2_BASE + i].into();
            builder.when(is_cmp_or_bw.clone()).assert_bool(a_bit);
            builder.when(is_cmp_or_bw.clone()).assert_bool(b_bit);
        }";

const UNPINNED_AIR: &str = r"pub const COL_CMP_RS1_BASE: usize = 65;
pub const COL_CMP_RS2_BASE: usize = 129;
pub const COL_CMP_RS1_HI_INV: usize = 738;
pub const COL_CMP_RS2_HI_INV: usize = 739;
        for i in 0..64 {
            let a_bit: AB::Expr = cur[COL_CMP_RS1_BASE + i].into();
            let b_bit: AB::Expr = cur[COL_CMP_RS2_BASE + i].into();
            builder.when(is_cmp_or_bw.clone()).assert_bool(a_bit);
            builder.when(is_cmp_or_bw.clone()).assert_bool(b_bit);
        }
        {
            let d_inv: AB::Expr = cur[COL_CMP_RS1_HI_INV].into();
            let z = d.clone() * d_inv;
            builder.when(is_cmp_or_bw.clone()).assert_bool(z.clone());
            builder.when(is_cmp_or_bw.clone()).assert_zero((AB::Expr::ONE - z) * lo);
        }";

const NO_COST_AIR: &str = r"pub const COL_CMP_RS1_BASE: usize = 65;
pub const COL_CMP_RS2_BASE: usize = 129;
pub const COL_CMP_RS1_HI_INV: usize = 738;
pub const COL_CMP_RS2_HI_INV: usize = 739;
        for i in 0..64 {
            let a_bit: AB::Expr = cur[COL_CMP_RS1_BASE + i].into();
            let b_bit: AB::Expr = cur[COL_CMP_RS2_BASE + i].into();
            builder.when(is_cmp_or_bw.clone()).assert_bool(a_bit);
            builder.when(is_cmp_or_bw.clone()).assert_bool(b_bit);
        }
        {
            let d_inv: AB::Expr = cur[COL_CMP_RS1_HI_INV].into();
            let z = d.clone() * d_inv;
            builder.when(is_cmp_or_bw.clone()).assert_bool(z.clone());
            builder.when(is_cmp_or_bw.clone()).assert_zero(d * (AB::Expr::ONE - z.clone()));
        }";

const WRAPPING_PROVER: &str = r"            let d = hi.wrapping_sub(0xFFFF_FFFF);
            values[row_start + COL_CMP_RS1_HI_INV] = Goldilocks::new(inv);
            values[row_start + COL_CMP_RS2_HI_INV] = Goldilocks::new(inv);";

const UNFILLED_PROVER: &str = r"            let d = bud_vm::field_sub_goldilocks(hi, 0xFFFF_FFFF);";

/// Write a fixture tree and check the gate's verdict.
fn check_fixture(
    air_body: Option<&str>,
    prover_body: Option<&str>,
    expect_ok: bool,
    label: &str,
) -> Result<(), String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!(
        "budlum-gates-bitdecomp-{}-{nanos}",
        std::process::id()
    ));
    let src_dir = dir.join("budzero/bud-proof/src");
    let _ = std::fs::create_dir_all(&src_dir);
    if let Some(body) = air_body {
        std::fs::write(src_dir.join("plonky3_air.rs"), body).map_err(|e| e.to_string())?;
    }
    if let Some(body) = prover_body {
        std::fs::write(src_dir.join("plonky3_prover.rs"), body).map_err(|e| e.to_string())?;
    }

    let result = run(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    if expect_ok {
        result.map(|_| ()).map_err(|e| format!("{label}: {e}"))
    } else {
        match result {
            Err(_) => Ok(()),
            Ok(_) => Err(format!("{label}: gate passed when it must fail")),
        }
    }
}

/// # Errors
///
/// The canaries that did not behave.
pub fn self_test() -> Result<String, String> {
    // 1. The corrected shape must pass, otherwise the gate is unusable.
    check_fixture(
        Some(GOOD_AIR),
        Some(GOOD_PROVER),
        true,
        "the corrected tree was rejected",
    )?;

    // 2. The original bug: a decomposition with no canonicity witness at all.
    check_fixture(
        Some(NO_WITNESS_AIR),
        Some(GOOD_PROVER),
        false,
        "a decomposition with no canonicity witness was accepted",
    )?;

    // 3. A witness that is declared and multiplied but never pinned. This is
    //    the trap: it looks like a canonicity check and enforces nothing.
    check_fixture(
        Some(UNPINNED_AIR),
        Some(GOOD_PROVER),
        false,
        "an unpinned canonicity witness was accepted",
    )?;

    // 4. The saturated case costing nothing: the low-half rule missing.
    check_fixture(
        Some(NO_COST_AIR),
        Some(GOOD_PROVER),
        false,
        "a canonicity rule with no cost for a saturated high half was accepted",
    )?;

    // 5. A witness the AIR declares and never reads.
    check_fixture(
        Some(UNREAD_AIR),
        Some(GOOD_PROVER),
        false,
        "a witness column that is never read was accepted",
    )?;

    // 6. The prover computing the difference with wrapping_sub.
    check_fixture(
        Some(GOOD_AIR),
        Some(WRAPPING_PROVER),
        false,
        "a wrapping_sub difference was accepted",
    )?;

    // 7. The prover never filling the witness the AIR reads.
    check_fixture(
        Some(GOOD_AIR),
        Some(UNFILLED_PROVER),
        false,
        "an unfilled witness was accepted",
    )?;

    // 8. A missing tree must fail rather than pass by default.
    check_fixture(None, None, false, "a tree with no sources was accepted")?;

    Ok(String::from(
        "bit decomposition gate self-test OK: a missing witness, an unpinned \
         witness, a missing low-half rule, an unread column, a wrapping_sub \
         difference, an unfilled witness and a missing tree are all rejected; \
         the canonical tree passes.",
    ))
}
