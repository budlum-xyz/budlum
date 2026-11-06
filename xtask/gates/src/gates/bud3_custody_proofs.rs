//! The custody proof gate.
//!
//! A custody share is a promise that bytes are on a disk. The promise is
//! checked with a Merkle path, and the ways the check can look right and be
//! wrong:
//!
//! 1. The audit names the whole share instead of one sub-block, so the holder
//!    can answer with a prepublished root and nothing on the disk.
//! 2. The proof is not bound to the audit, so an old proof answers a new
//!    challenge.
//! 3. The draw is uniform, so the class parameter is decoration and a phone is
//!    audited like a server.
//! 4. A refused batch still marks passes, so a holder learns which proofs are
//!    wrong and pays nothing for the rest.
//! 5. A missed audit slashes. A miss costs the window's reward and, after
//!    enough of them, the share; the bond is for a forged proof, not for a
//!    phone on a train.
//!
//! # What is checked
//!
//! `src/storage/bud3/custody.rs` cuts a symbol into 64-byte sub-blocks, binds
//! the leaf count into every root, verifies a proof against the audit and the
//! stored root, and draws audits per class with integer arithmetic only.
//! `src/storage/bud3/registry.rs` verifies every proof of a batch before it
//! changes one share, counts a pass only then, and counts a closed window as a
//! miss without a slash.

use std::fmt::Write as _;
use std::path::Path;

/// The proof module, repository relative.
const CUSTODY: &str = "src/storage/bud3/custody.rs";
/// The state machine that checks the proofs, repository relative.
const REGISTRY: &str = "src/storage/bud3/registry.rs";

/// The sub-block tree tag.
const SYMBOL_TAG: &str = "BDLM_BUD3_SYMBOL_V1";
/// The symbol root tag.
const SYMBOLS_TAG: &str = "BDLM_BUD3_SYMBOLS_V1";

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

fn check_tree(prod: &str, prod_raw: &str, problems: &mut Vec<String>, checked: &mut usize) {
    *checked += 1;
    if !prod.contains("SUB_BLOCK: usize = 64") {
        problems.push(String::from(
            "the sub-block size is no longer 64 bytes. The proof size follows this \
             constant, and the design sized the answer to fit one packet.",
        ));
    }
    *checked += 1;
    if !prod_raw.contains(SYMBOL_TAG) {
        problems.push(format!(
            "the symbol leaf tag `{SYMBOL_TAG}` is missing. Sharing a tag with \
             another hash lets a digest computed for one purpose be replayed as \
             the other."
        ));
    }
    *checked += 1;
    if !prod_raw.contains(SYMBOLS_TAG) {
        problems.push(format!(
            "the symbol root tag `{SYMBOLS_TAG}` is missing, so the root over a \
             segment is not bound to its purpose."
        ));
    }
    *checked += 1;
    if let Some(root) = body_of(prod, "root_hash") {
        if !root.contains("count") {
            problems.push(String::from(
                "`root_hash` no longer binds the leaf count. A tree over seven \
                 leaves and a tree over eight must not share a root, or the last \
                 leaf can be read as a whole level.",
            ));
        }
    } else {
        problems.push(String::from(
            "`root_hash` is gone, so a root no longer says how many leaves it holds.",
        ));
    }
    *checked += 1;
    match body_of(prod, "symbol_leaf") {
        Some(body) if body.contains("SYMBOL_TAG") => {}
        _ => problems.push(String::from(
            "`symbol_leaf` does not build the sub-block root under the symbol tag.",
        )),
    }
    *checked += 1;
    match body_of(prod, "symbol_root") {
        Some(body) if body.contains("SYMBOLS_TAG") => {}
        _ => problems.push(String::from(
            "`symbol_root` does not build the segment root under the symbols tag.",
        )),
    }
}

fn check_verify(prod: &str, problems: &mut Vec<String>, checked: &mut usize) {
    *checked += 1;
    let Some(verify) = body_of(prod, "verify") else {
        problems.push(String::from(
            "`CustodyProof::verify` is gone, so a proof is never checked.",
        ));
        return;
    };
    *checked += 1;
    if !verify.contains("WrongChallenge") {
        problems.push(String::from(
            "`verify` no longer refuses a proof that answers another audit. An \
             old proof would then answer a fresh challenge forever.",
        ));
    }
    *checked += 1;
    if !verify.contains("BadPath") {
        problems.push(String::from(
            "`verify` no longer refuses a path that does not hash to the root, so \
             the bytes are not bound to what the chain holds.",
        ));
    }
    *checked += 1;
    if !verify.contains("symbol_root") {
        problems.push(String::from(
            "`verify` does not compare against the stored symbol root, so it \
             proves only that the holder can hash.",
        ));
    }
    *checked += 1;
    if has_word(prod, "f32") || has_word(prod, "f64") {
        problems.push(String::from(
            "the proof path uses floating point. Every validator and every phone \
             recomputes it, and a float makes two devices disagree about a valid \
             proof.",
        ));
    }
}

fn check_draw(prod: &str, problems: &mut Vec<String>, checked: &mut usize) {
    *checked += 1;
    if !(prod.contains("FULL_AUDIT_PPM: u32") && prod.contains("MOBILE_AUDIT_PPM: u32")) {
        problems.push(String::from(
            "the per-class audit probabilities are gone. With one probability the \
             class parameter is decoration and a phone is audited like a server.",
        ));
    }
    *checked += 1;
    let Some(draw) = body_of(prod, "audit_for") else {
        problems.push(String::from(
            "`audit_for` is gone, so nothing turns the seed into a challenge.",
        ));
        return;
    };
    *checked += 1;
    if !draw.contains("probability_ppm") {
        problems.push(String::from(
            "`audit_for` does not take the class probability, so the draw cannot \
             depend on the class.",
        ));
    }
    *checked += 1;
    if !draw.contains("PPM") {
        problems.push(String::from(
            "`audit_for` no longer divides the draw by the parts-per-million base, \
             so the probability is not a probability.",
        ));
    }
    *checked += 1;
    if !(draw.contains("sub_block") && draw.contains("position")) {
        problems.push(String::from(
            "`audit_for` does not name one symbol and one sub-block of it. A share \
             wide challenge lets the holder answer with the share root alone.",
        ));
    }
}

fn check_registry(prod: &str, problems: &mut Vec<String>, checked: &mut usize) {
    *checked += 1;
    let Some(submit) = body_of(prod, "submit_proofs") else {
        problems.push(String::from(
            "`Bud3Registry::submit_proofs` is gone, so a holder cannot answer an \
             audit and the window closes as a miss.",
        ));
        return;
    };
    *checked += 1;
    if !submit.contains(".verify(&audit, &ctx)") {
        problems.push(String::from(
            "`submit_proofs` does not call `CustodyProof::verify`, so a batch is \
             accepted without a path check.",
        ));
    }
    *checked += 1;
    match (submit.find("hits.push"), submit.find("passes += 1")) {
        (Some(push), Some(pass)) if push < pass => {}
        (Some(_), Some(_)) => problems.push(String::from(
            "`submit_proofs` counts a pass before it has checked every proof of \
             the batch. A batch with one bad proof would pay for the good ones.",
        )),
        _ => problems.push(String::from(
            "`submit_proofs` no longer records the checked hits and then counts \
             them, so a refused batch and an accepted batch cannot be told apart.",
        )),
    }
    *checked += 1;
    if !submit.contains("open_audit = None") {
        problems.push(String::from(
            "`submit_proofs` does not close the audit it answered, so the same \
             challenge stays open and can be answered again.",
        ));
    }

    *checked += 1;
    if let Some(close) = body_of(prod, "close_windows") {
        *checked += 1;
        if !(close.contains("consecutive_misses") && close.contains("lost = true")) {
            problems.push(String::from(
                "`close_windows` no longer loses the share after enough missed \
                 windows in a row, so a share that never answers stays owed \
                 forever.",
            ));
        }
        *checked += 1;
        for needle in ["slash", "penalt", "forfeit"] {
            if close.contains(needle) {
                problems.push(format!(
                    "`close_windows` punishes a miss with `{needle}`. A miss costs \
                     the window's reward and, after enough of them, the share; the \
                     bond answers for a forged proof, not for a phone on a train."
                ));
            }
        }
    } else {
        problems.push(String::from(
            "`close_windows` is gone, so a missed window is never counted.",
        ));
    }

    *checked += 1;
    if let Some(open) = body_of(prod, "open_audits") {
        *checked += 1;
        if !(open.contains("params.full_ppm") && open.contains("params.mobile_ppm")) {
            problems.push(String::from(
                "`open_audits` does not read the class probabilities, so every \
                 class draws from one rate.",
            ));
        }
        *checked += 1;
        if !open.contains("open_audit") {
            problems.push(String::from(
                "`open_audits` does not record the audit on the share, so the \
                 answer cannot be bound to the challenge.",
            ));
        }
    } else {
        problems.push(String::from(
            "`open_audits` is gone, so an epoch draws nothing.",
        ));
    }
}

/// # Errors
///
/// The first file that cannot be read, or the list of violated claims.
pub fn run(root: &Path) -> Result<String, String> {
    let custody_raw = raw_of(root, CUSTODY)?;
    let registry_raw = raw_of(root, REGISTRY)?;
    let custody = crate::gates::rust_literals::scrub(&custody_raw);
    let registry = crate::gates::rust_literals::scrub(&registry_raw);
    let custody_prod = production(&custody);
    let registry_prod = production(&registry);

    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;
    check_tree(custody_prod, production(&custody_raw), &mut problems, &mut checked);
    check_verify(custody_prod, &mut problems, &mut checked);
    check_draw(custody_prod, &mut problems, &mut checked);
    check_registry(registry_prod, &mut problems, &mut checked);

    if checked == 0 {
        return Err(String::from("the custody proof gate checked nothing"));
    }
    if !problems.is_empty() {
        let mut msg = String::from("custody proofs are not checked end to end:\n");
        for p in &problems {
            let _ = writeln!(msg, "  - {p}");
        }
        return Err(msg);
    }
    Ok(format!(
        "custody proof gate OK: {checked} checks, the tree binds its leaf count, a \
         proof answers one audit, the draw is per class, and a miss costs the \
         share and never the bond."
    ))
}

// ---------------------------------------------------------------------------
// Canaries
// ---------------------------------------------------------------------------

/// A custody module that satisfies every claim.
const GOOD_CUSTODY: &str = r#"
pub const SUB_BLOCK: usize = 64;
pub const SYMBOL_TAG: &[u8] = b"BDLM_BUD3_SYMBOL_V1";
pub const SYMBOLS_TAG: &[u8] = b"BDLM_BUD3_SYMBOLS_V1";
pub const AUDIT_TAG: &[u8] = b"BDLM_BUD3_AUDIT_V1";
pub const PPM: u32 = 1_000_000;
pub const FULL_AUDIT_PPM: u32 = 20_000;
pub const MOBILE_AUDIT_PPM: u32 = 10_000;
fn leaf_hash(tag: &[u8], index: u64, bytes: &[u8]) -> [u8; 32] {
    let _ = (tag, index, bytes);
    [0u8; 32]
}
fn root_hash(tag: &[u8], count: u64, root: &[u8; 32]) -> [u8; 32] {
    let _ = (tag, count, root);
    [0u8; 32]
}
fn merkle(tag: &[u8], leaves: Vec<[u8; 32]>, want: Option<usize>) -> ([u8; 32], Vec<Option<[u8; 32]>>) {
    let _ = (tag, leaves, want);
    ([0u8; 32], Vec::new())
}
pub fn symbol_leaf(symbol: &[u8]) -> [u8; 32] {
    let leaves = symbol.iter().map(|b| leaf_hash(SYMBOL_TAG, 0, &[*b])).collect();
    merkle(SYMBOL_TAG, leaves, None).0
}
pub fn symbol_root(leaves: &[(u32, [u8; 32])]) -> [u8; 32] {
    let inner = leaves.iter().map(|(_, l)| *l).collect();
    merkle(SYMBOLS_TAG, inner, None).0
}
pub struct Audit { pub segment: u64, pub position: u64, pub sub_block: u64 }
pub struct ProofContext { pub symbol_root: [u8; 32], pub symbol_count: u64, pub sub_blocks: u64 }
pub struct CustodyProof { pub segment: u64, pub position: u64, pub sub_block: u64, pub bytes: [u8; SUB_BLOCK] }
pub enum ProofError { WrongChallenge, BadPath }
impl CustodyProof {
    pub fn verify(&self, audit: &Audit, ctx: &ProofContext) -> Result<(), ProofError> {
        if self.segment != audit.segment || self.position != audit.position || self.sub_block != audit.sub_block {
            return Err(ProofError::WrongChallenge);
        }
        let _ = (&self.bytes, ctx.symbol_count, ctx.sub_blocks);
        if ctx.symbol_root != [0u8; 32] { return Err(ProofError::BadPath); }
        Ok(())
    }
}
pub struct ShareRef { pub segment: u64, pub holder: [u8; 32], pub first_position: u64, pub symbols: u64 }
pub fn audit_for(seed: &[u8; 32], share: &ShareRef, probability_ppm: u32, sub_blocks: u64) -> Option<Audit> {
    let _ = seed;
    if share.symbols == 0 || sub_blocks == 0 { return None; }
    let drawn = u64::from(share.symbols) % u64::from(PPM);
    if drawn >= u64::from(probability_ppm.min(PPM)) { return None; }
    Some(Audit { segment: share.segment, position: drawn % share.symbols, sub_block: drawn % sub_blocks })
}
"#;

/// A registry module that satisfies every claim.
const GOOD_REGISTRY: &str = r#"
pub struct Bud3Registry { objects: std::collections::BTreeMap<[u8; 32], Object> }
pub struct Object { shares: Vec<Share>, roots: Vec<Root> }
pub struct Share { share: Placed, status: Status, open_audit: Option<(Audit, u64)>, passes: u64, misses: u64, consecutive_misses: u64, lost: bool }
pub struct Placed { validator: [u8; 32], class: Class, first_esi: u32, symbols: u32 }
pub struct Root { root: [u8; 32], count: u32, first_esi: u32 }
pub struct Audit { position: u64 }
pub struct ProofContext { symbol_root: [u8; 32], symbol_count: u64, sub_blocks: u64 }
pub struct CustodyProof;
impl CustodyProof { pub fn verify(&self, audit: &Audit, ctx: &ProofContext) -> Result<(), ()> { let _ = (audit, ctx); Ok(()) } }
pub enum Class { Full, Mobile }
pub enum Status { Pending, Confirmed }
pub struct AuditParams { pub full_ppm: u32, pub mobile_ppm: u32 }
impl Bud3Registry {
    pub fn open_audits(&mut self, seed: &[u8; 32], epoch: u64, params: &AuditParams) -> usize {
        let _ = (seed, epoch);
        let mut opened = 0usize;
        for obj in self.objects.values_mut() {
            for s in &mut obj.shares {
                let ppm = match s.share.class { Class::Full => params.full_ppm, Class::Mobile => params.mobile_ppm };
                if ppm == 0 { continue; }
                s.open_audit = Some((Audit { position: 0 }, 0));
                opened += 1;
            }
        }
        opened
    }
    pub fn submit_proofs(&mut self, holder: &[u8; 32], proofs: &[([u8; 32], CustodyProof)], epoch: u64) -> Result<usize, ()> {
        let mut hits = Vec::new();
        for (key, proof) in proofs {
            let obj = self.objects.get(key).ok_or(())?;
            let idx = obj.shares.iter().position(|s| s.share.validator == *holder).ok_or(())?;
            let share = obj.shares.get(idx).ok_or(())?;
            let (audit, last) = share.open_audit.ok_or(())?;
            let root = obj.roots.get(0).ok_or(())?;
            let ctx = ProofContext { symbol_root: root.root, symbol_count: u64::from(root.count), sub_blocks: 1 };
            proof.verify(&audit, &ctx).map_err(|_| ())?;
            let _ = epoch;
            hits.push((key, idx));
        }
        for (key, idx) in &hits {
            if let Some(s) = self.objects.get_mut(*key).and_then(|o| o.shares.get_mut(*idx)) {
                s.open_audit = None;
                s.passes += 1;
                s.consecutive_misses = 0;
            }
        }
        Ok(hits.len())
    }
    pub fn close_windows(&mut self, epoch: u64) -> usize {
        let mut missed = 0usize;
        for obj in self.objects.values_mut() {
            for s in &mut obj.shares {
                if s.open_audit.is_some_and(|(_, last)| last < epoch) {
                    s.open_audit = None;
                    s.misses += 1;
                    s.consecutive_misses += 1;
                    missed += 1;
                    if s.consecutive_misses >= 2 { s.lost = true; }
                }
            }
        }
        missed
    }
}
"#;

/// Write both modules into a scratch tree and run the gate.
fn check_fixture(
    custody: &str,
    registry: &str,
    expect_ok: bool,
    label: &str,
) -> Result<(), String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-custody")?;
    for (rel, content) in [(CUSTODY, custody), (REGISTRY, registry)] {
        let file = dir.join(rel);
        if let Some(parent) = file.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&file, content).map_err(|e| e.to_string())?;
    }
    let result = run(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    match (result, expect_ok) {
        (Ok(_), true) | (Err(_), false) => Ok(()),
        (Ok(_), false) => Err(format!("{label}: the gate accepted it")),
        (Err(e), true) => Err(format!("{label}: the gate refused a good tree: {e}")),
    }
}

/// Break one claim and expect the gate to refuse the result.
fn breaks(custody: bool, old: &str, new: &str, label: &str) -> Result<(), String> {
    let (c, r) = if custody {
        (GOOD_CUSTODY.replace(old, new), String::from(GOOD_REGISTRY))
    } else {
        (String::from(GOOD_CUSTODY), GOOD_REGISTRY.replace(old, new))
    };
    if c == GOOD_CUSTODY && r == GOOD_REGISTRY {
        return Err(format!("canary `{label}` no longer matches the fixture"));
    }
    check_fixture(&c, &r, false, label)
}

/// # Errors
///
/// The canaries that did not behave.
pub fn self_test() -> Result<String, String> {
    check_fixture(
        GOOD_CUSTODY,
        GOOD_REGISTRY,
        true,
        "the correct proof path",
    )?;

    breaks(
        true,
        "pub const SUB_BLOCK: usize = 64;",
        "pub const SUB_BLOCK: usize = 256;",
        "a sub-block that no longer fits one packet",
    )?;
    breaks(
        true,
        "fn root_hash(tag: &[u8], count: u64, root: &[u8; 32]) -> [u8; 32] {\n    let _ = (tag, count, root);",
        "fn root_hash(tag: &[u8], count: u64, root: &[u8; 32]) -> [u8; 32] {\n    let _ = (tag, root);\n    let _hash = 0u8;",
        "a root that forgets its leaf count",
    )?;
    breaks(
        true,
        "            return Err(ProofError::WrongChallenge);",
        "            return Ok(());",
        "a proof that answers another audit",
    )?;
    breaks(
        true,
        "        if ctx.symbol_root != [0u8; 32] { return Err(ProofError::BadPath); }",
        "        let _ = 0u8;",
        "a proof that is not compared to the stored root",
    )?;
    breaks(
        true,
        "pub const MOBILE_AUDIT_PPM: u32 = 10_000;",
        "",
        "a draw with one class probability",
    )?;
    breaks(
        true,
        "if drawn >= u64::from(probability_ppm.min(PPM)) { return None; }",
        "if drawn >= u64::from(PPM) { return None; }",
        "a draw that ignores the class probability",
    )?;
    breaks(
        false,
        "            proof.verify(&audit, &ctx).map_err(|_| ())?;",
        "            let _ = proof;",
        "a batch accepted without a path check",
    )?;
    breaks(
        false,
        "        let mut hits = Vec::new();",
        "        let mut hits = Vec::new();\n        for s in self.objects.values_mut() { for sh in &mut s.shares { sh.passes += 1; } }",
        "a batch that counts a pass before the checks",
    )?;
    breaks(
        false,
        "                s.open_audit = None;\n                s.passes += 1;",
        "                s.passes += 1;",
        "a pass that leaves the audit open",
    )?;
    breaks(
        false,
        "                    if s.consecutive_misses >= 2 { s.lost = true; }",
        "                    if s.consecutive_misses >= 2 { s.lost = true; }\n                    let _slash = 1;",
        "a missed audit that slashes",
    )?;
    breaks(
        false,
        "let ppm = match s.share.class { Class::Full => params.full_ppm, Class::Mobile => params.mobile_ppm };",
        "let ppm = 20_000u32;",
        "a draw with no class parameter",
    )?;

    Ok(String::from(
        "custody proof gate self-test OK: one clean pass and 11 refusals",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_real_tree_binds_its_tags() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let Ok(raw) = raw_of(&root, CUSTODY) else {
            return; // the gates crate is also built outside the repository tree
        };
        assert!(raw.contains(SYMBOL_TAG));
        assert!(raw.contains(SYMBOLS_TAG));
    }
}
