//! Storage must be priced by size.
//!
//! Ported from `scripts/check-storage-is-priced-by-size.sh`. `fee_per_epoch`
//! (duration-only pricing) must be gone, `fee_per_byte_epoch` must exist and
//! be multiplied only inside `total_fee`, `total_fee` must round up, the deal
//! leaf must commit to `shard_bytes`, and a set of regression tests must
//! exist.

use std::fmt::Write as _;
use std::path::Path;

fn code_of(root: &Path, rel: &str) -> Result<String, String> {
    let f = root.join(rel);
    if !f.is_file() {
        return Err(format!("expected source file missing: {}", f.display()));
    }
    std::fs::read_to_string(&f).map_err(|e| e.to_string())
}

/// Comment-stripped source (the shell's `re.sub(r"//[^\n]*", "", src)`).
fn strip_comments(src: &str) -> String {
    src.lines()
        .map(|l| {
            let idx = l.find("//").unwrap_or(l.len());
            l[..idx].to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `fee_per_byte_epoch` multiplied at a site: `fee_per_byte_epoch * X` or
/// `X * fee_per_byte_epoch` (with optional saturating/as-cast adornments).
fn is_mult_site(line: &str) -> bool {
    let t = line.trim();
    if t.contains("fee_per_byte_epoch") {
        let has_mul = t.contains("saturating_mul") || t.contains('*') || t.contains("mul(");
        if has_mul {
            return true;
        }
    }
    false
}

/// The deal leaf must commit to `shard_bytes` and `total_fee` must round up.
fn check_leaf_and_rounding(deal_code: &str, body: Option<&str>) -> Vec<String> {
    let mut problems = Vec::new();
    let leaf = fn_body(deal_code, "storage_deal_leaf_hash");
    match leaf {
        None => problems
            .push("cannot find `storage_deal_leaf_hash` to check what it commits to.".to_string()),
        Some(l) if !l.contains("shard_bytes") => problems.push(
            "`storage_deal_leaf_hash` does not commit to `shard_bytes`. The size \
             is what the price is computed from, so leaving it out lets the agreed \
             number move without the commitment noticing."
                .to_string(),
        ),
        _ => {}
    }
    if body.is_some_and(|b| !b.contains("div_ceil")) {
        problems.push(
            "`total_fee` does not round up. Integer division sends any deal \
             priced below one base unit to zero, and a zero fee is free \
             storage the operator must still serve and answer challenges for. \
             A genuinely free deal is written as a zero rate."
                .to_string(),
        );
    }
    problems
}

/// Extract the brace-balanced body of `fn <name>` from `code`.
fn fn_body(code: &str, name: &str) -> Option<String> {
    let start = code.find(&format!("fn {name}("))?;
    let rest = &code[start..];
    let open = rest.find('{')? + start + 1;
    let mut depth = 1i32;
    let mut i = open;
    while i < code.len() {
        match code.as_bytes()[i] {
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
    Some(code[open..i].to_string())
}

/// `fn name(` present as a definition or call.
fn has_fn(code: &str, name: &str) -> bool {
    code.contains(&format!("fn {name}("))
}

/// A `#[test] fn name(` present.
fn has_test(deal_src: &str, name: &str) -> bool {
    let mut rest = deal_src;
    while let Some(pos) = rest.find(&format!("fn {name}(")) {
        let before = &rest[..pos];
        let last_test = before.rfind("#[test]");
        if last_test.is_some_and(|t| before[t..].lines().count() <= 3) {
            return true;
        }
        rest = &rest[pos + 1..];
    }
    false
}

/// # Errors
///
/// Returns the list of violated claims.
pub fn run(root: &Path) -> Result<String, String> {
    let deal_src = code_of(root, "src/domain/storage_deal.rs")?;
    let chain_src = code_of(root, "src/chain/blockchain.rs")?;
    let deal_code = strip_comments(&deal_src);
    let chain_code = strip_comments(&chain_src);
    let both = format!("{deal_code}\n{chain_code}");
    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    checked += 1;
    if both.contains("fee_per_epoch") {
        problems.push(
            "`fee_per_epoch` is still present. That field priced a deal by \
             duration alone, so a 1 KiB and a 16 MiB shard cost the same. The \
             per-byte rate is `fee_per_byte_epoch`."
                .to_string(),
        );
    }
    checked += 1;
    if !deal_code.contains("fee_per_byte_epoch") {
        problems.push(
            "`StorageEconomicsParams` has no `fee_per_byte_epoch`. Storage has to \
             be priced by the bytes it holds."
                .to_string(),
        );
    }
    checked += 1;
    if !deal_code.contains("pub shard_bytes: u64") {
        problems.push(
            "`StorageDeal` has no `shard_bytes` field. The deal outlives the \
             caller's manifest, so the size the price was agreed at has to travel \
             with it rather than being looked up again later."
                .to_string(),
        );
    }
    checked += 1;
    if !has_fn(&deal_code, "total_fee") {
        problems
            .push("no `total_fee` in storage_deal.rs; the price has no single home.".to_string());
    }

    // Multiplication sites outside total_fee.
    checked += 1;
    let body = fn_body(&deal_code, "total_fee");
    let total_sites = both.lines().filter(|l| is_mult_site(l)).count();
    let body_sites = body
        .as_deref()
        .map_or(0, |b| b.lines().filter(|l| is_mult_site(l)).count());
    if total_sites > body_sites {
        problems.push(format!(
            "the rate is multiplied out at {} site(s) outside `total_fee`. Every fee must go through it, or the call sites drift apart the way the three readers of `fee_per_epoch` did.",
            total_sites - body_sites
        ));
    }

    checked += 1; // leaf commitment
    checked += 1; // rounding
    problems.extend(check_leaf_and_rounding(&deal_code, body.as_deref()));

    // Required regression tests.
    checked += 1;
    for name in [
        "a_larger_shard_costs_more_for_the_same_duration",
        "a_longer_deal_costs_more_for_the_same_shard",
        "a_priced_deal_is_never_free_through_rounding",
        "a_zero_rate_stays_free",
        "an_unpayable_deal_saturates_rather_than_wrapping",
        "opening_a_deal_records_the_shard_size_it_was_priced_at",
        "the_deal_leaf_commits_to_the_shard_size",
    ] {
        if !has_test(&deal_src, name) {
            problems.push(format!(
                "required regression test `{name}` is missing or is not a `#[test]`."
            ));
        }
    }

    if !problems.is_empty() {
        let mut msg = String::new();
        for p in problems {
            writeln!(msg, "FAIL: {p}").expect("writing to a String cannot fail");
        }
        return Err(msg);
    }
    Ok(format!(
        "storage pricing gate OK: {checked} checks, storage is priced by size"
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
    let dir =
        std::env::temp_dir().join(format!("budlum-gates-price-{}-{nanos}", std::process::id()));
    let _ = std::fs::create_dir_all(dir.join("src/domain"));
    let _ = std::fs::create_dir_all(dir.join("src/chain"));

    // Good: fee_per_epoch gone, per-byte rate, leaf commits shard_bytes,
    // total_fee rounds up, all tests present.
    let mut good = String::from(
        "pub struct StorageEconomicsParams { pub fee_per_byte_epoch: u64 }\npub struct StorageDeal { pub shard_bytes: u64 }\nfn total_fee() { let n = fee_per_byte_epoch.saturating_mul(shard_bytes).div_ceil(1); }\nfn storage_deal_leaf_hash() { let _ = shard_bytes; }\n",
    );
    for t in [
        "a_larger_shard_costs_more_for_the_same_duration",
        "a_longer_deal_costs_more_for_the_same_shard",
        "a_priced_deal_is_never_free_through_rounding",
        "a_zero_rate_stays_free",
        "an_unpayable_deal_saturates_rather_than_wrapping",
        "opening_a_deal_records_the_shard_size_it_was_priced_at",
        "the_deal_leaf_commits_to_the_shard_size",
    ] {
        writeln!(good, "#[test]\nfn {t}() {{}}").expect("writing to a String cannot fail");
    }
    std::fs::write(dir.join("src/domain/storage_deal.rs"), &good).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("src/chain/blockchain.rs"), "fn nothing() {}\n")
        .map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a module with correct pricing was refused",
        ));
    }

    // Bad: fee_per_epoch resurrected.
    let bad = good.replace("fee_per_byte_epoch", "fee_per_epoch");
    std::fs::write(dir.join("src/domain/storage_deal.rs"), bad).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: fee_per_epoch came back and passed"));
    }

    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "storage-pricing canary OK (correct PASSes, fee_per_epoch FAILs).",
    ))
}
