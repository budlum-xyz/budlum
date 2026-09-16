//! The mempool may not be a market.
//!
//! Gate code: `K-NETWORK-MEV-FREE`. A finding or a document that names this code resolves here.
//!
//! `pool.rs` states why the ordering is what it is: transactions sharing a fee
//! used to arrive in insertion order, so two nodes produced two different
//! blocks from the same pool, and a node could reshuffle a tie to its own
//! advantage. The fix is a canonical order, fee descending then transaction
//! hash ascending, held in ordered containers, with a test that pins the
//! tie-break.
//!
//! This gate refuses a widening of that rule. The ordering structure must
//! stay a `BTreeMap<u64, BTreeSet<String>>` keyed by fee, the per-sender index
//! must keep its inner map ordered, `get_sorted_transactions` must read the
//! fee map in reverse rather than sorting an ad-hoc vector, the tie-break test
//! must exist, and no new "by priority / by who pays more per sender" index may
//! appear. A fee floor and a byte-based admission rule stay required, because a
//! pool bounded only by count is filled by cheap transactions.

use std::fmt::Write as _;
use std::path::Path;

fn body_of(src: &str, name: &str) -> Option<String> {
    let at = src.find(&format!("fn {name}("))?;
    let open = src[at..].find('{')? + at;
    let mut depth = 0usize;
    let mut out = String::new();
    for ch in src[open..].chars() {
        out.push(ch);
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(out);
                }
            }
            _ => {}
        }
    }
    None
}

/// Any new ordering index keyed on a bid, a boost or a priority: the pool may
/// order by fee and hash, nothing else.
fn bidding_index(src: &str) -> Vec<String> {
    let mut widen = Vec::new();
    for l in src.lines() {
        let line = l.trim_start();
        if !line.contains(": HashMap<") && !line.contains(": BTreeMap<") {
            continue;
        }
        let name = line.split(':').next().unwrap_or_default().trim();
        if name.starts_with("by_")
            && (name.contains("priority") || name.contains("boost") || name.contains("bid"))
        {
            widen.push(name.to_string());
        }
    }
    widen
}

/// # Errors
///
/// Returns the list of violated claims.
/// Formats the findings the way every gate in this crate reports them.
fn report(problems: &[String]) -> String {
    let mut msg = String::new();
    for p in problems {
        writeln!(msg, "FAIL: {p}").expect("writing to a String cannot fail");
    }
    msg
}

pub fn run(root: &Path) -> Result<String, String> {
    let f = root.join("src/mempool/pool.rs");
    if !f.is_file() {
        return Err(format!("no mempool/pool.rs at {}", f.display()));
    }
    let src = std::fs::read_to_string(&f).map_err(|e| e.to_string())?;
    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    if src.contains("by_fee: BTreeMap<u64, BTreeSet<String>>") {
        checked += 1;
    } else {
        let line = src
            .lines()
            .find(|l| l.trim_start().starts_with("by_fee:"))
            .unwrap_or("by_fee is gone");
        problems.push(format!(
            "the fee index is `{}` rather than `BTreeMap<u64, BTreeSet<String>>`. The inner set \
             is what makes a same-fee tie canonical: an unordered collection hands block \
             construction to whatever the allocator's iteration order happens to be.",
            line.trim()
        ));
    }
    let sender = src
        .lines()
        .find(|l| l.trim_start().starts_with("by_sender:"))
        .unwrap_or_default();
    if sender.contains("BTreeMap<u64, String>") {
        checked += 1;
    } else {
        problems.push(format!(
            "`by_sender` no longer holds an ordered nonce index (`{}`). Nonce order inside one \
             sender is consensus-visible: an unordered index lets a node pack a sender's \
             transactions in a chosen order and skip the one it does not like.",
            sender.trim()
        ));
    }
    let sorted = body_of(&src, "get_sorted_transactions").unwrap_or_default();
    if sorted.contains("by_fee.iter().rev()") {
        checked += 1;
    } else {
        problems.push(
            "`get_sorted_transactions` no longer reads the fee index in reverse. A local sort \
             here is where a preference gets introduced: the ordering must be a property of the \
             structure, not of a comparator someone can extend."
                .to_string(),
        );
    }
    if src.contains("fn test_same_fee_canonical_order_by_hash") {
        checked += 1;
    } else {
        problems.push(
            "the same-fee tie-break test is gone. It is the only thing keeping the hash ordering \
             from drifting back to insertion order."
                .to_string(),
        );
    }
    let widen = bidding_index(&src);
    if widen.is_empty() {
        checked += 1;
    } else {
        problems.push(format!(
            "a bidding index appeared in the pool: {}. The pool orders by fee and hash only; \
             a per-sender or per-block bid index is a private auction for whoever can watch it.",
            widen.join(", ")
        ));
    }
    for need in ["min_fee: u64", "fn charged_bytes"] {
        if src.contains(need) {
            checked += 1;
        } else {
            problems.push(format!(
                "`{need}` is gone. A pool with no fee floor and no byte accounting accepts a \
                 flood of maximum-size transactions for one unit of fee."
            ));
        }
    }

    if checked == 0 {
        return Err(String::from("gate checked nothing"));
    }
    if !problems.is_empty() {
        return Err(report(&problems));
    }
    Ok(format!(
        "mempool ordering OK: {checked} checks, canonical fee-DESC/hash-ASC order held in \
         ordered maps, no bidding index, tie-break test present"
    ))
}

/// # Errors
///
/// Returns a finding when a defect fixture passes.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-pool")?;
    std::fs::create_dir_all(dir.join("src/mempool")).map_err(|e| e.to_string())?;
    let good = "pub struct Pool {\n    by_sender: HashMap<Address, BTreeMap<u64, String>>,\n    by_fee: BTreeMap<u64, BTreeSet<String>>,\n    min_fee: u64,\n}\n\nfn charged_bytes(tx: &Transaction) -> usize { tx.data.len() }\n\nimpl Pool {\n    pub fn get_sorted_transactions(&self, limit: usize) -> Vec<Transaction> {\n        for (_, hashes) in self.by_fee.iter().rev() { for h in hashes { push(h); } }\n        out\n    }\n}\n\n#[cfg(test)]\nmod tests {\n    fn test_same_fee_canonical_order_by_hash() {}\n}\n";
    std::fs::write(dir.join("src/mempool/pool.rs"), good).map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a canonical pool was refused"));
    }
    let unordered = good.replace(
        "by_fee: BTreeMap<u64, BTreeSet<String>>",
        "by_fee: HashMap<u64, BTreeSet<String>>",
    );
    std::fs::write(dir.join("src/mempool/pool.rs"), unordered).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: an unordered fee index passed"));
    }
    let bid = good.replace(
        "min_fee: u64,",
        "min_fee: u64,\n    by_priority: HashMap<u64, String>,",
    );
    std::fs::write(dir.join("src/mempool/pool.rs"), bid).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a bidding index passed"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "mempool canary OK (canonical order PASSes; an unordered fee index and a priority \
         bid map each FAIL).",
    ))
}
