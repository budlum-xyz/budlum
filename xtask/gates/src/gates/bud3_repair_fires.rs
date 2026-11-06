//! The repair trigger gate.
//!
//! Repair is what makes a departure cheap. The three ways it looks wired and is
//! not:
//!
//! 1. Nothing fires on loss, so the object shrinks silently until it cannot be
//!    read.
//! 2. It fires on the first lost share, so a network with churn repairs the
//!    whole tree continuously and pays for symbols it did not need.
//! 3. The repair reuses an ESI, so the new symbols are the old ones and the loss
//!    is still there.
//!
//! # What is checked
//!
//! `src/storage/bud3/registry.rs` answers `repairs_due` from the lost shares of
//! a segment against half its tolerance, `record_repair` refuses a segment that
//! is not due and takes fresh contiguous ESIs from `next_esi`, and
//! `settle_repairs` drops an old share only once every new share of its segment
//! is confirmed. The state machine reads no clock: the trigger is an epoch
//! number and a lost flag, never a timer.

use std::fmt::Write as _;
use std::path::Path;

/// The state machine, repository relative.
const REGISTRY: &str = "src/storage/bud3/registry.rs";

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

fn check_trigger(prod: &str, problems: &mut Vec<String>, checked: &mut usize) {
    *checked += 1;
    if !prod.contains("fn repairs_due(&self") {
        problems.push(String::from(
            "`repairs_due` is gone or is no longer a read. Repair has to be \
             answerable from the state the block already holds, or two nodes \
             schedule different repairs.",
        ));
    }
    *checked += 1;
    let Some(due) = body_of(prod, "repairs_due") else {
        problems.push(String::from(
            "`repairs_due` is gone, so nothing detects a lost share.",
        ));
        return;
    };
    *checked += 1;
    if !due.contains("saturating_add(2)") {
        problems.push(String::from(
            "`repairs_due` no longer asks for `k + 2` symbols. Without the two \
             repair symbols every row loses its tolerance and the first repair \
             makes the segment unreadable.",
        ));
    }
    *checked += 1;
    if !due.contains("sort_unstable_by") {
        problems.push(String::from(
            "`repairs_due` no longer orders the shares by size, so the tolerance \
             it derives is not the number of the largest shares the row can lose.",
        ));
    }
    *checked += 1;
    if !due.contains("(f / 2).max(1)") {
        problems.push(String::from(
            "`repairs_due` no longer waits for half the tolerance. Repairing on \
             the first lost share pays for symbols the code did not need, and a \
             phone leaving once triggers a rewrite of the segment.",
        ));
    }
    *checked += 1;
    if !due.contains("lost") {
        problems.push(String::from(
            "`repairs_due` does not read the lost flag, so nothing about the \
             segment can make it due.",
        ));
    }
    *checked += 1;
    if due.contains("SystemTime") || due.contains("Instant") || due.contains("thread::sleep") {
        problems.push(String::from(
            "`repairs_due` reads a clock. The trigger has to be an epoch number \
             and a lost flag; a timer makes the answer differ between nodes.",
        ));
    }
}

fn check_record(prod: &str, problems: &mut Vec<String>, checked: &mut usize) {
    *checked += 1;
    let Some(record) = body_of(prod, "record_repair") else {
        problems.push(String::from(
            "`record_repair` is gone, so a repairer has no way to place new \
             shares and a due segment stays due forever.",
        ));
        return;
    };
    *checked += 1;
    if !record.contains("repairs_due") {
        problems.push(String::from(
            "`record_repair` does not ask `repairs_due`, so a repair is accepted \
             for a segment that lost nothing. That is free storage for anyone \
             willing to call it.",
        ));
    }
    *checked += 1;
    if !record.contains("BadRepair") {
        problems.push(String::from(
            "`record_repair` no longer refuses a bad repair, so a repair that \
             replaces nothing counts as one.",
        ));
    }
    *checked += 1;
    if !record.contains(".next_esi") {
        problems.push(String::from(
            "`record_repair` does not take its ESIs from `next_esi`, so a repair \
             can reuse an ESI and the new symbol is the lost one.",
        ));
    }
    *checked += 1;
    if !record.contains("first_esi") {
        problems.push(String::from(
            "`record_repair` does not check that the new ESIs are contiguous from \
             the next unused one, so two shares of the repair can overlap.",
        ));
    }
    *checked += 1;
    if !record.contains("MAX_ESI") {
        problems.push(String::from(
            "`record_repair` no longer bounds the ESIs at the fountain ceiling, so \
             a repair can push a segment outside the code.",
        ));
    }
}

fn check_settle(prod: &str, problems: &mut Vec<String>, checked: &mut usize) {
    *checked += 1;
    let Some(settle) = body_of(prod, "settle_repairs") else {
        problems.push(String::from(
            "`settle_repairs` is gone, so an old share is never dropped and the \
             quota of the network only grows.",
        ));
        return;
    };
    *checked += 1;
    if !settle.contains("upload_roots") {
        problems.push(String::from(
            "`settle_repairs` no longer separates the upload roots from the repair \
             roots, so an upload share can be read as unrepaired.",
        ));
    }
    *checked += 1;
    if !settle.contains("ShareStatus::Confirmed") {
        problems.push(String::from(
            "`settle_repairs` does not wait for the repair shares to be confirmed. \
             Dropping an old share before the new one is acknowledged is how a \
             repair loses the segment it was repairing.",
        ));
    }
    *checked += 1;
    if !settle.contains("settled.contains") {
        problems.push(String::from(
            "`settle_repairs` drops lost shares of every segment, not only of the \
             segments whose repair is settled.",
        ));
    }
}

fn check_unseen(prod: &str, problems: &mut Vec<String>, checked: &mut usize) {
    *checked += 1;
    let Some(unseen) = body_of(prod, "mark_unseen") else {
        problems.push(String::from(
            "`mark_unseen` is gone, so a validator that left the network keeps its \
             shares and no repair is ever due.",
        ));
        return;
    };
    *checked += 1;
    if !unseen.contains("lost = true") {
        problems.push(String::from(
            "`mark_unseen` does not mark the shares lost, so the departure is \
             recorded nowhere.",
        ));
    }
    *checked += 1;
    if !unseen.contains("open_audit = None") {
        problems.push(String::from(
            "`mark_unseen` leaves an audit open on a share whose holder left, so \
             the window closes as a miss against a validator that is gone.",
        ));
    }
}

/// # Errors
///
/// The first file that cannot be read, or the list of violated claims.
pub fn run(root: &Path) -> Result<String, String> {
    let raw = raw_of(root, REGISTRY)?;
    let code = crate::gates::rust_literals::scrub(&raw);
    let prod = production(&code);

    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;
    check_trigger(prod, &mut problems, &mut checked);
    check_record(prod, &mut problems, &mut checked);
    check_settle(prod, &mut problems, &mut checked);
    check_unseen(prod, &mut problems, &mut checked);

    if checked == 0 {
        return Err(String::from("the repair gate checked nothing"));
    }
    if !problems.is_empty() {
        let mut msg = String::from("repair does not fire on loss:\n");
        for p in &problems {
            let _ = writeln!(msg, "  - {p}");
        }
        return Err(msg);
    }
    Ok(format!(
        "repair gate OK: {checked} checks, the trigger is half the tolerance, a \
         repair takes fresh ESIs and refuses when nothing is due, and an old share \
         is dropped only after the new one is confirmed."
    ))
}

// ---------------------------------------------------------------------------
// Canaries
// ---------------------------------------------------------------------------

/// A registry module that satisfies every claim.
const GOOD: &str = r#"
pub const FULL_MISSES_TO_LOSS: u64 = 2;
pub struct Bud3Registry { objects: std::collections::BTreeMap<[u8; 32], Object> }
pub struct Object { shares: Vec<Share>, roots: Vec<Root>, next_esi: Vec<u32>, record: Record }
pub struct Record { symbol_roots: Vec<[u8; 32]> }
pub struct Share { segment: u64, share: Placed, status: ShareStatus, open_audit: Option<u64>, lost: bool, root: usize }
pub struct Placed { validator: [u8; 32], first_esi: u32, symbols: u32 }
pub struct Root { segment: u64, first_esi: u32, count: u32 }
pub enum ShareStatus { Pending, Confirmed }
pub enum RegistryError { BadRepair(&'static str), UnknownObject }
impl Bud3Registry {
    pub fn repairs_due(&self, key: &[u8; 32]) -> Vec<u64> {
        let Some(obj) = self.objects.get(key) else { return Vec::new(); };
        let mut due = Vec::new();
        for index in 0..1u64 {
            let need = 4096u64.saturating_add(2);
            let mut sizes: Vec<u64> = obj.shares.iter().filter(|s| s.segment == index)
                .map(|s| u64::from(s.share.symbols)).collect();
            sizes.sort_unstable_by(|a, b| b.cmp(a));
            let mut f = 0u64;
            let mut left: u64 = sizes.iter().sum();
            for sz in &sizes {
                if left.saturating_sub(*sz) < need { break; }
                left -= sz;
                f += 1;
            }
            let lost = obj.shares.iter().filter(|s| s.segment == index && s.lost).count() as u64;
            if lost > 0 && lost >= (f / 2).max(1) { due.push(index); }
        }
        due
    }
    pub fn record_repair(&mut self, key: &[u8; 32], segment: u64, new_shares: Vec<Placed>, new_root: [u8; 32]) -> Result<(), RegistryError> {
        if !self.repairs_due(key).contains(&segment) {
            return Err(RegistryError::BadRepair("segment needs no repair"));
        }
        let obj = self.objects.get_mut(key).ok_or(RegistryError::UnknownObject)?;
        let seg_idx = usize::try_from(segment).map_err(|_| RegistryError::BadRepair("segment"))?;
        let first = *obj.next_esi.get(seg_idx).ok_or(RegistryError::BadRepair("segment"))?;
        let mut next = u64::from(first);
        for s in &new_shares {
            if s.symbols == 0 || u64::from(s.first_esi) != next {
                return Err(RegistryError::BadRepair("new ESIs must be fresh and contiguous"));
            }
            next += u64::from(s.symbols);
        }
        if next > u64::from(MAX_ESI) {
            return Err(RegistryError::BadRepair("ESI range"));
        }
        let _ = new_root;
        if let Some(n) = obj.next_esi.get_mut(seg_idx) { *n = next as u32; }
        Ok(())
    }
    pub fn settle_repairs(&mut self) -> usize {
        let mut dropped = 0usize;
        for obj in self.objects.values_mut() {
            let upload_roots = obj.record.symbol_roots.len();
            let settled: std::collections::BTreeSet<u64> = obj.roots.iter().enumerate()
                .skip(upload_roots)
                .filter(|(i, _)| obj.shares.iter().filter(|s| s.root == *i).all(|s| matches!(s.status, ShareStatus::Confirmed)))
                .map(|(_, r)| r.segment)
                .collect();
            let before = obj.shares.len();
            obj.shares.retain(|s| !(s.lost && settled.contains(&s.segment)));
            dropped += before - obj.shares.len();
        }
        dropped
    }
    pub fn mark_unseen(&mut self, holder: &[u8; 32]) -> usize {
        let mut n = 0usize;
        for obj in self.objects.values_mut() {
            for s in obj.shares.iter_mut().filter(|s| s.share.validator == *holder) {
                if !s.lost {
                    s.lost = true;
                    s.open_audit = None;
                    n += 1;
                }
            }
        }
        n
    }
}
pub const MAX_ESI: u32 = 16_777_215;
"#;

/// Write the module into a scratch tree and run the gate.
fn check_fixture(content: &str, expect_ok: bool, label: &str) -> Result<(), String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-repair")?;
    let file = dir.join(REGISTRY);
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(&file, content).map_err(|e| e.to_string())?;
    let result = run(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    match (result, expect_ok) {
        (Ok(_), true) | (Err(_), false) => Ok(()),
        (Ok(_), false) => Err(format!("{label}: the gate passed it")),
        (Err(e), true) => Err(format!("{label}: the gate refused a good tree: {e}")),
    }
}

/// Break one claim and expect the gate to refuse the result.
fn breaks(old: &str, new: &str, label: &str) -> Result<(), String> {
    if !GOOD.contains(old) {
        return Err(format!(
            "canary `{label}` no longer matches the fixture; it would break nothing"
        ));
    }
    check_fixture(&GOOD.replace(old, new), false, label)
}

/// # Errors
///
/// The canaries that did not behave.
pub fn self_test() -> Result<String, String> {
    check_fixture(GOOD, true, "the correct repair path")?;

    breaks(
        "if lost > 0 && lost >= (f / 2).max(1) { due.push(index); }",
        "let _ = (lost, f);",
        "a trigger that never fires",
    )?;
    breaks(
        "if lost > 0 && lost >= (f / 2).max(1) { due.push(index); }",
        "if lost > 0 { due.push(index); }",
        "a trigger that fires on the first lost share",
    )?;
    breaks(
        "let need = 4096u64.saturating_add(2);",
        "let need = 4096u64;",
        "a tolerance that forgot the two repair symbols",
    )?;
    breaks(
        "        if !self.repairs_due(key).contains(&segment) {",
        "        if false {",
        "a repair accepted for a segment that is not due",
    )?;
    let stale_esi = GOOD
        .replace(
            "        let first = *obj.next_esi.get(seg_idx).ok_or(RegistryError::BadRepair(\"segment\"))?;",
            "        let first = 0u32;",
        )
        .replace(
            "        if let Some(n) = obj.next_esi.get_mut(seg_idx) { *n = next as u32; }",
            "        let _ = next;",
        );
    check_fixture(&stale_esi, false, "a repair that reuses the first ESI")?;
    breaks(
        "            if s.symbols == 0 || u64::from(s.first_esi) != next {",
        "            if s.symbols == 0 {",
        "a repair whose new ESIs may overlap",
    )?;
    breaks(
        "        if next > u64::from(MAX_ESI) {",
        "        if next > u64::MAX {",
        "a repair outside the fountain ceiling",
    )?;
    breaks(
        "                .filter(|(i, _)| obj.shares.iter().filter(|s| s.root == *i).all(|s| matches!(s.status, ShareStatus::Confirmed)))",
        "                .filter(|(_i, _)| true)",
        "a settle that drops an old share before the new one is confirmed",
    )?;
    let upload_blind = GOOD
        .replace(
            "            let upload_roots = obj.record.symbol_roots.len();",
            "            let repair_roots = 0usize;",
        )
        .replace("                .skip(upload_roots)", "                .skip(repair_roots)");
    check_fixture(
        &upload_blind,
        false,
        "a settle that reads an upload root as a repair root",
    )?;
    breaks(
        "                    s.lost = true;",
        "                    let _ = &mut s.lost;",
        "a departure that marks nothing lost",
    )?;
    breaks(
        "                    s.open_audit = None;",
        "                    let _ = s.open_audit;",
        "a departure that leaves an audit open",
    )?;
    breaks(
        "        let Some(obj) = self.objects.get(key) else { return Vec::new(); };",
        "        let Some(obj) = self.objects.get(key) else { return Vec::new(); };\n        let _now = std::time::Instant::now();",
        "a trigger that reads a clock",
    )?;

    Ok(String::from("repair gate self-test OK: 12 canaries"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_real_registry_answers_repairs_due_as_a_read() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let Ok(raw) = raw_of(&root, REGISTRY) else {
            return; // the gates crate is also built outside the repository tree
        };
        let code = crate::gates::rust_literals::scrub(&raw);
        assert!(production(&code).contains("fn repairs_due(&self"));
    }
}
