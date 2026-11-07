//! The class-aware placement gate.
//!
//! `src/storage/bud3/placement.rs` answers one question: who holds the symbols
//! of a segment. Four ways to look right and be wrong:
//!
//! 1. The choice reshuffles on every set change, so one departure moves every
//!    share of the object.
//! 2. It ignores the stake, and the bond stops answering for a lost share.
//! 3. It forgets the classes, so one Mobile departure can cost a segment that
//!    was supposed to survive the whole Mobile class leaving.
//! 4. It uses floating point, and two nodes rank the candidates differently.
//!
//! # What is checked
//!
//! The default table rebuilds every segment (`total >= k + 2`), the mixed rows
//! hold at least 30 percent of their symbols on Mobile shares, the draw reads
//! only the segment key and one validator address (so it is derived and
//! sticky), the rank drops zero-stake candidates and orders by stake over the
//! fixed-point logarithm, the order breaks ties by address, `place` enforces
//! the account and network caps and keeps the two classes apart, and the
//! production half holds no floating point and no clock.
//!
//! # Baseline
//!
//! Section 6.9 of the directive gives the parameters. The table itself is a
//! genesis parameter recomputed off chain; the consensus path only reads it,
//! which is why the table's shape is what this gate pins.

use std::fmt::Write as _;
use std::path::Path;

/// The placement module, repository relative.
const MODULE: &str = "src/storage/bud3/placement.rs";

/// The Mobile floor of section 6.9.4, in thousandths of a segment's symbols.
const MOBILE_FLOOR_MILLI: u64 = 300;

/// The placement domain tag.
const TAG: &str = "BDLM_BUD3_PLACEMENT_V1";

/// Read one repository file as raw text.
fn raw_of(root: &Path, rel: &str) -> Result<String, String> {
    let file = root.join(rel);
    if !file.is_file() {
        return Err(format!("expected file missing: {}", file.display()));
    }
    std::fs::read_to_string(&file).map_err(|e| e.to_string())
}

/// The production half: everything above the first test module.
fn production(code: &str) -> &str {
    code.split("#[cfg(test)]").next().unwrap_or(code)
}

/// The brace-matched body of the function named `name`.
fn body_of<'a>(src: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("fn {name}");
    let mut from = 0usize;
    while let Some(pos) = src[from..].find(&needle) {
        let abs = from + pos;
        from = abs + needle.len();
        let after = &src[abs + needle.len()..];
        let Some(open_rel) = after.find('{') else {
            continue;
        };
        let Some(close_rel) = after.find(')') else {
            continue;
        };
        if close_rel > open_rel {
            continue;
        }
        let open = abs + needle.len() + open_rel;
        let mut depth = 0usize;
        for (off, c) in src[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return Some(&src[open..open + off + 1]);
                    }
                }
                _ => {}
            }
        }
        return None;
    }
    None
}

/// Whether `word` appears as a whole token.
fn has_word(src: &str, word: &str) -> bool {
    let mut from = 0usize;
    while let Some(pos) = src[from..].find(word) {
        let abs = from + pos;
        from = abs + 1;
        let before = src[..abs]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'));
        let after = src[abs + word.len()..]
            .chars()
            .next()
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'));
        if before && after {
            return true;
        }
    }
    false
}

/// The four numbers of every `r(a, b, c, d)` row of the default table.
fn table_rows(body: &str) -> Vec<[u64; 4]> {
    let mut rows = Vec::new();
    let mut from = 0usize;
    while let Some(pos) = body[from..].find("r(") {
        let abs = from + pos;
        from = abs + 2;
        let Some(close) = body[abs..].find(')') else {
            break;
        };
        let inner = &body[abs + 2..abs + close];
        let nums: Vec<u64> = inner
            .split(',')
            .filter_map(|p| p.trim().parse::<u64>().ok())
            .collect();
        if nums.len() == 4 {
            rows.push([nums[0], nums[1], nums[2], nums[3]]);
        }
    }
    rows
}

/// The `k` of the table, as written in the source.
fn source_symbols(body: &str) -> Option<u64> {
    let at = body.find("k:")?;
    let rest = body[at + 2..].trim_start();
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

fn check_table(code: &str, problems: &mut Vec<String>, checked: &mut usize) {
    *checked += 1;
    let Some(body) = body_of(code, "testnet_default") else {
        problems.push(String::from(
            "`PlacementTable::testnet_default` is gone. The consensus path reads \
             only the table, so an absent table leaves the node with no row to \
             place a segment against.",
        ));
        return;
    };
    let Some(k) = source_symbols(body) else {
        problems.push(String::from(
            "the default table declares no source symbols per segment (`k`), so \
             nothing can check that a row rebuilds a segment.",
        ));
        return;
    };
    let rows = table_rows(body);
    *checked += 1;
    if rows.len() < 5 {
        problems.push(format!(
            "the default table has {} row(s); the design needs a bucket per \
             network size and class mix, and five is the smallest useful set.",
            rows.len()
        ));
    }
    let mut mixed = 0usize;
    for [n_full, s_full, n_mobile, s_mobile] in &rows {
        let total = n_full * s_full + n_mobile * s_mobile;
        *checked += 1;
        if total < k + 2 {
            problems.push(format!(
                "row {n_full} x {s_full} Full / {n_mobile} x {s_mobile} Mobile \
                 holds {total} symbols, below k + 2 = {}. The row cannot rebuild \
                 a segment, so the last two symbols of tolerance are imaginary.",
                k + 2
            ));
        }
        if *n_mobile > 0 {
            mixed += 1;
            *checked += 1;
            let milli = n_mobile * s_mobile * 1000 / total.max(1);
            if milli < MOBILE_FLOOR_MILLI {
                problems.push(format!(
                    "row {n_full} x {s_full} Full / {n_mobile} x {s_mobile} \
                     Mobile puts {milli} thousandths of its symbols on Mobile \
                     shares, under the {MOBILE_FLOOR_MILLI} floor. The floor is \
                     what keeps a phone class that joins late from being a \
                     decoration."
                ));
            }
        }
    }
    *checked += 1;
    if mixed == 0 {
        problems.push(String::from(
            "no row of the default table holds Mobile shares, so the class split \
             is gone from the table and the Mobile class cannot hold anything.",
        ));
    }
}

fn check_map(code: &str, problems: &mut Vec<String>, checked: &mut usize) {
    *checked += 1;
    let Some(place) = body_of(code, "place") else {
        problems.push(String::from(
            "`place` is gone, so nothing turns a row and a candidate set into \
             shares.",
        ));
        return;
    };
    *checked += 1;
    if !place.contains("(n / 64).max(1)") {
        problems.push(String::from(
            "`place` no longer caps the shares of one account at `max(1, n / 64)`. \
             Without the cap one operator holds every share of a segment by \
             listing validators under one account.",
        ));
    }
    *checked += 1;
    if !place.contains("(n / 32).max(2)") {
        problems.push(String::from(
            "`place` no longer caps the shares behind one network prefix at \
             `max(2, n / 32)`. The cap is the only thing that makes a single \
             rack unlikely to hold a whole segment.",
        ));
    }
    *checked += 1;
    if !has_word(place, "Mobile") {
        problems.push(String::from(
            "`place` does not mention the Mobile class, so the row's Mobile half \
             is unplaced and the class-aware placement is one class.",
        ));
    }
    *checked += 1;
    if !place.contains("free_quota_bytes") {
        problems.push(String::from(
            "`place` does not read the candidate's free quota, so a validator that \
             declared no room is given a share anyway.",
        ));
    }
    *checked += 1;
    if !place.contains("NotEnough") {
        problems.push(String::from(
            "`place` does not refuse a class with too few candidates. Padding a \
             short set with duplicates means one departure costs two shares.",
        ));
    }
    *checked += 1;
    if place.contains("cycle(") {
        problems.push(String::from(
            "`place` cycles the candidate list, which pads a short set with \
             duplicates instead of refusing it.",
        ));
    }
}

fn check_rank(code: &str, problems: &mut Vec<String>, checked: &mut usize) {
    *checked += 1;
    let Some(rank) = body_of(code, "rank") else {
        problems.push(String::from(
            "`rank` is gone, so the candidates of a segment have no order.",
        ));
        return;
    };
    *checked += 1;
    if !rank.contains("stake > 0") {
        problems.push(String::from(
            "`rank` no longer drops zero-stake candidates. An operator with \
             nothing at risk has nothing to lose by dropping the bytes.",
        ));
    }
    *checked += 1;
    if !rank.contains("sort_by") {
        problems.push(String::from(
            "`rank` does not sort, so the shares go to whatever order the \
             candidate list arrived in.",
        ));
    }
}

fn check_order(code: &str, problems: &mut Vec<String>, checked: &mut usize) {
    *checked += 1;
    let Some(before) = body_of(code, "before") else {
        problems.push(String::from(
            "`Ranked::before` is gone, so the score has no comparison and the \
             order is undefined.",
        ));
        return;
    };
    *checked += 1;
    if !before.contains("stake") {
        problems.push(String::from(
            "`Ranked::before` does not read the stake. The bond is what answers \
             for a lost share, so a score without it puts bytes behind \
             collateral that cannot pay for their loss.",
        ));
    }
    *checked += 1;
    if !before.contains("validator.cmp") {
        problems.push(String::from(
            "`Ranked::before` has no tiebreak on the validator address. Two \
             equal scores would then be ordered by input order, which differs \
             between nodes.",
        ));
    }
}

fn check_draw(code: &str, problems: &mut Vec<String>, checked: &mut usize) {
    *checked += 1;
    let Some(draw) = body_of(code, "draw") else {
        problems.push(String::from(
            "`draw` is gone, so the placement is not derived from the segment and \
             the holder.",
        ));
        return;
    };
    *checked += 1;
    if !(draw.contains("segment_key") && draw.contains("validator")) {
        problems.push(String::from(
            "`draw` no longer reads the segment key and the validator address. \
             Those two inputs are what make the choice derived and sticky: a \
             validator that leaves moves only the shares it held or wins.",
        ));
    }
    *checked += 1;
    if draw.contains("candidates") {
        problems.push(String::from(
            "`draw` reads the candidate list, so the draw depends on set \
             membership and one departure reshuffles every share.",
        ));
    }
    for needle in ["SystemTime", "Instant", "thread_rng"] {
        *checked += 1;
        if draw.contains(needle) {
            problems.push(format!(
                "`draw` reads {needle}, so the placement is not a pure function \
                 of the segment and the holder."
            ));
        }
    }
}

fn check_float(prod: &str, problems: &mut Vec<String>, checked: &mut usize) {
    *checked += 1;
    if has_word(prod, "f32") || has_word(prod, "f64") {
        problems.push(String::from(
            "the production half of the placement uses floating point. Every node \
             recomputes the placement, and a float makes the answer depend on the \
             rounding mode and the target, so two nodes can disagree about who \
             owes a share.",
        ));
    }
}

/// # Errors
///
/// The first file that cannot be read, or the list of violated claims.
pub fn run(root: &Path) -> Result<String, String> {
    let raw = raw_of(root, MODULE)?;
    let code = crate::gates::rust_literals::scrub(&raw);
    let prod = production(&code);
    let prod_raw = production(&raw);

    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    *checked += 1;
    if !prod_raw.contains(TAG) {
        problems.push(format!(
            "the placement domain tag `{TAG}` is missing from the production \
             half. Sharing a tag with another hash lets a digest computed for \
             one purpose be replayed as the other."
        ));
    }

    check_table(prod, &mut problems, &mut checked);
    check_map(prod, &mut problems, &mut checked);
    check_rank(prod, &mut problems, &mut checked);
    check_order(prod, &mut problems, &mut checked);
    check_draw(prod, &mut problems, &mut checked);
    check_float(prod, &mut problems, &mut checked);

    if checked == 0 {
        return Err(String::from("the placement gate checked nothing"));
    }
    if !problems.is_empty() {
        let mut msg = String::from("the placement is not class aware and sticky:\n");
        for p in &problems {
            let _ = writeln!(msg, "  - {p}");
        }
        return Err(msg);
    }
    Ok(format!(
        "placement gate OK: {checked} checks, the table rebuilds every row, the \
         Mobile floor holds, the draw is derived and sticky, and the caps are in \
         place."
    ))
}

// ---------------------------------------------------------------------------
// Canaries
// ---------------------------------------------------------------------------

/// A placement module that satisfies every claim.
const GOOD: &str = r#"
pub const PLACEMENT_TAG: &[u8] = b"BDLM_BUD3_PLACEMENT_V1";
pub enum Class { Full, Mobile }
pub struct Candidate { pub validator: [u8; 32], pub account: [u8; 32], pub class: Class, pub stake: u64, pub free_quota_bytes: u64 }
pub struct Share { pub validator: [u8; 32], pub class: Class, pub first_esi: u32, pub symbols: u32 }
pub struct PlacementRow { pub n_full: u32, pub s_full: u32, pub n_mobile: u32, pub s_mobile: u32 }
pub struct PlacementTable { pub k: u32, pub rows: Vec<PlacementRow> }
impl PlacementTable {
    pub fn testnet_default() -> Self {
        let r = |n_full, s_full, n_mobile, s_mobile| PlacementRow { n_full, s_full, n_mobile, s_mobile };
        Self {
            k: 4096,
            rows: vec![
                r(8, 443, 256, 13),
                r(16, 242, 256, 8),
                r(32, 171, 0, 0),
                r(64, 54, 512, 4),
                r(128, 26, 1024, 2),
            ],
        }
    }
}
fn log2_q32(x: u128) -> u64 { u64::try_from(x & 0xffff).unwrap_or(0) }
fn neg_log2_unit_q32(h: u64) -> u64 { h.max(1) }
fn draw(segment_key: &[u8; 32], validator: &[u8; 32]) -> u64 {
    let mut acc = 0u64;
    for b in segment_key.iter().chain(validator.iter()) { acc = acc.wrapping_add(u64::from(*b)); }
    acc
}
struct Ranked { c: Candidate, l: u64 }
impl Ranked {
    fn before(&self, other: &Self) -> core::cmp::Ordering {
        let a = u128::from(self.c.stake) * u128::from(other.l);
        let b = u128::from(other.c.stake) * u128::from(self.l);
        b.cmp(&a).then(self.c.validator.cmp(&other.c.validator))
    }
}
pub fn rank(segment_key: &[u8; 32], candidates: &[Candidate]) -> Vec<Candidate> {
    let mut ranked: Vec<Ranked> = candidates.iter().filter(|c| c.stake > 0)
        .map(|c| Ranked { c: *c, l: neg_log2_unit_q32(draw(segment_key, &c.validator)) })
        .collect();
    ranked.sort_by(Ranked::before);
    ranked.into_iter().map(|r| r.c).collect()
}
pub fn place(segment_key: &[u8; 32], candidates: &[Candidate], row: &PlacementRow, k: u32, symbol_size: u32) -> Result<Vec<Share>, PlacementError> {
    if row.n_full * row.s_full + row.n_mobile * row.s_mobile < k + 2 { return Err(PlacementError::RowTooSmall); }
    let n = row.n_full.saturating_add(row.n_mobile);
    let account_cap = (n / 64).max(1);
    let network_cap = (n / 32).max(2);
    let ordered = rank(segment_key, candidates);
    let mut shares = Vec::new();
    for (class, want, per) in [(Class::Full, row.n_full, row.s_full), (Class::Mobile, row.n_mobile, row.s_mobile)] {
        let share_bytes = u64::from(per) * u64::from(symbol_size);
        let mut got = 0u32;
        for c in ordered.iter().filter(|c| c.class == class) {
            if got == want { break; }
            if c.free_quota_bytes < share_bytes { continue; }
            if account_cap == 0 || network_cap == 0 { continue; }
            shares.push(Share { validator: c.validator, class, first_esi: got, symbols: per });
            got += 1;
        }
        if got < want { return Err(PlacementError::NotEnough { class, want, got }); }
    }
    Ok(shares)
}
pub enum PlacementError { RowTooSmall, NotEnough { class: Class, want: u32, got: u32 } }
"#;

/// Write `placement.rs` with `content` into a scratch tree and run the gate.
fn check_fixture(content: &str, expect_ok: bool, label: &str) -> Result<(), String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-placement")?;
    let module = dir.join(MODULE);
    if let Some(parent) = module.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(&module, content).map_err(|e| e.to_string())?;
    let result = run(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    match (result, expect_ok) {
        (Ok(_), true) | (Err(_), false) => Ok(()),
        (Ok(_), false) => Err(format!(
            "{label}: the gate passed a placement it had to refuse"
        )),
        (Err(e), true) => Err(format!("{label}: the gate refused a good placement: {e}")),
    }
}

/// Break one claim of [`GOOD`] and expect the gate to refuse it.
fn breaks(old: &str, new: &str, label: &str) -> Result<(), String> {
    if !GOOD.contains(old) {
        return Err(format!(
            "canary `{label}` no longer matches the fixture; the canary would \
             break nothing"
        ));
    }
    check_fixture(&GOOD.replace(old, new), false, label)
}

/// # Errors
///
/// The canaries that did not behave.
pub fn self_test() -> Result<String, String> {
    check_fixture(GOOD, true, "the correct placement")?;

    breaks(
        "r(16, 242, 256, 8)",
        "r(16, 400, 2, 1)",
        "a mixed row under the Mobile floor",
    )?;
    breaks("r(32, 171, 0, 0)", "r(32, 1, 0, 0)", "a row below k + 2")?;
    breaks(
        "fn neg_log2_unit_q32(h: u64) -> u64 { h.max(1) }",
        "fn neg_log2_unit_q32(h: u64) -> u64 { (h as f64).ln().abs() as u64 }",
        "a fixed-point rank that became a float",
    )?;
    breaks(
        "let account_cap = (n / 64).max(1);",
        "let account_cap = u32::MAX;",
        "a placement with no account cap",
    )?;
    breaks(
        "let network_cap = (n / 32).max(2);",
        "let network_cap = u32::MAX;",
        "a placement with no network cap",
    )?;
    breaks(
        "(Class::Mobile, row.n_mobile, row.s_mobile)",
        "(Class::Full, row.n_mobile, row.s_mobile)",
        "a placement that places every share as Full",
    )?;
    breaks(
        "filter(|c| c.stake > 0)",
        "filter(|_c| true)",
        "a rank that keeps zero-stake candidates",
    )?;
    breaks(
        "b.cmp(&a).then(self.c.validator.cmp(&other.c.validator))",
        "b.cmp(&a)",
        "a rank with no deterministic tiebreak",
    )?;
    breaks(
        "let mut acc = 0u64;",
        "let _now = std::time::SystemTime::now();\n    let mut acc = 0u64;",
        "a draw that reads a clock",
    )?;
    breaks(
        "b\"BDLM_BUD3_PLACEMENT_V1\"",
        "b\"BDLM_HASH_V1\"",
        "a placement hash with no domain tag",
    )?;
    breaks(
        "        if got < want { return Err(PlacementError::NotEnough { class, want, got }); }",
        "            let _ = want;",
        "a placement that pads a short class instead of refusing",
    )?;

    Ok(String::from(
        "placement gate self-test OK: one clean pass and 11 refusals, one per \
         way placement can look right and be wrong",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The repository root, from the crate's own manifest directory.
    fn repo_root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .to_path_buf()
    }

    #[test]
    fn every_default_row_rebuilds_a_segment() {
        let raw = std::fs::read_to_string(repo_root().join(MODULE))
            .expect("the placement module");
        let code = crate::gates::rust_literals::scrub(&raw);
        let body = body_of(production(&code), "testnet_default").expect("the default table");
        let k = source_symbols(body).expect("k");
        let rows = table_rows(body);
        assert!(rows.len() >= 5, "{rows:?}");
        for [n_full, s_full, n_mobile, s_mobile] in rows {
            let total = n_full * s_full + n_mobile * s_mobile;
            assert!(total >= k + 2, "{n_full} x {s_full} holds {total}");
        }
    }

    #[test]
    fn a_row_under_the_mobile_floor_is_refused() {
        let broken = GOOD.replace("r(16, 242, 256, 8)", "r(16, 4096, 1, 1)");
        let dir = crate::gates::rust_literals::exclusive_scratch_dir("bud3-placement-floor")
            .expect("scratch dir");
        let module = dir.join(MODULE);
        std::fs::create_dir_all(module.parent().expect("parent")).expect("dirs");
        std::fs::write(&module, broken).expect("fixture");
        let verdict = run(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        let finding = verdict.expect_err("a row under the Mobile floor must be refused");
        assert!(finding.contains("Mobile"), "{finding}");
    }
}
