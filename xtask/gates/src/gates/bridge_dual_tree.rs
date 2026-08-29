//! The bridge root commits to both trees, not one.
//!
//! Gate code: `K-CROSS-DOMAIN-DUAL-TREE`. A finding or a document that names this code resolves here.
//!
//! `BridgeState` holds two independent ledgers: where every asset currently
//! sits (`asset_locations`) and what is moving (`transfers`). A root over the
//! first alone lets a node hide an in-flight transfer, claim a matching root,
//! and be slashed for nothing, because nothing in the commitment says the
//! transfer exists. The file records this as a fixed defect: the root used to
//! hash only `asset_locations`.
//!
//! The gate pins the fix: both ledgers must be folded into the leaves, the
//! fold must go through the shared `merkle_root`, the expiry queue must stay
//! height-indexed so a sweep cannot be made quadratic, and the four ledger
//! fields must be ordered maps, since an unordered iteration would give two
//! honest nodes two different roots.

use std::fmt::Write as _;
use std::path::Path;

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
    let f = root.join("src/cross_domain/bridge.rs");
    if !f.is_file() {
        return Err(format!("no cross_domain/bridge.rs at {}", f.display()));
    }
    let src = std::fs::read_to_string(&f).map_err(|e| e.to_string())?;
    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    let at = src.find("fn root(").ok_or_else(|| {
        "no `fn root(` in `BridgeState`; without a single commitment the two ledgers can be \
         agreed about separately, which is not the same thing"
            .to_string()
    })?;
    let open = src[at..]
        .find('{')
        .map(|o| at + o)
        .ok_or("unterminated `fn root(`")?;
    let mut depth = 0usize;
    let mut body = String::new();
    for ch in src[open..].chars() {
        body.push(ch);
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
    }
    for (ledger, why) in [
        (
            "asset_locations",
            "where each asset sits: the settlement side reads only this",
        ),
        (
            "transfers",
            "what is in flight: the receiving side claims against this",
        ),
    ] {
        if body.contains(ledger) {
            checked += 1;
        } else {
            problems.push(format!(
                "`root()` no longer folds `{ledger}` ({why}). A root that omits one of the two \
                 ledgers is a root two nodes can agree on while disagreeing about the bridge."
            ));
        }
    }
    if body.contains("merkle_root") {
        checked += 1;
    } else {
        problems.push(
            "`root()` does not go through `commitment_tree::merkle_root`. Every other set \
             commitment in this chain is a Merkle root over canonical leaves; a private \
             fold here would not be provable to a light client."
                .to_string(),
        );
    }

    let struct_at = src
        .find("pub struct BridgeState")
        .ok_or_else(|| "no `pub struct BridgeState`".to_string())?;
    let struct_end = src[struct_at..]
        .find('}')
        .map_or(src.len(), |i| struct_at + i);
    let struct_body = &src[struct_at..struct_end];
    for field in ["asset_locations", "transfers", "expiry_queue"] {
        let line = struct_body
            .lines()
            .find(|l| l.trim_start().starts_with(&format!("{field}:")))
            .unwrap_or_default();
        if line.contains("BTreeMap<") {
            checked += 1;
        } else {
            problems.push(format!(
                "`BridgeState::{field}` is `{}`; it must be a `BTreeMap`. An unordered ledger \
                 gives each node a different leaf order, and a different root for the same \
                 bridge state.",
                line.trim()
            ));
        }
    }
    let expiry = struct_body
        .lines()
        .find(|l| l.trim_start().starts_with("expiry_queue:"))
        .unwrap_or_default();
    if expiry.contains("BTreeMap<u64, Vec<MessageId>>") {
        checked += 1;
    } else {
        problems.push(format!(
            "the expiry queue is no longer indexed by height (`{}`). It used to be swept over \
             every transfer, which made the expiry path O(N) per block and a free DoS lever.",
            expiry.trim()
        ));
    }

    if checked == 0 {
        return Err(String::from("gate checked nothing"));
    }
    if !problems.is_empty() {
        return Err(report(&problems));
    }
    Ok(format!(
        "bridge dual-tree root OK: {checked} checks, both ledgers folded through merkle_root \
         over ordered maps with a height-indexed expiry queue"
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
    let dir = std::env::temp_dir().join(format!(
        "budlum-gates-bridge-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(dir.join("src/cross_domain")).map_err(|e| e.to_string())?;
    let good = "pub struct BridgeState {\n    asset_locations: BTreeMap<AssetId, BridgeStatus>,\n    transfers: BTreeMap<MessageId, BridgeTransfer>,\n    expiry_queue: BTreeMap<u64, Vec<MessageId>>,\n}\n\nimpl BridgeState {\n    pub fn root(&self) -> Hash32 {\n        let mut leaves = self.asset_locations.iter().map(hash_it).collect::<Vec<_>>();\n        for t in &self.transfers { leaves.push(hash_it(t)); }\n        crate::settlement::commitment_tree::merkle_root(&leaves)\n    }\n}\n";
    std::fs::write(dir.join("src/cross_domain/bridge.rs"), good).map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a dual-tree bridge was refused"));
    }
    let one = good.replace(
        "for t in &self.transfers { leaves.push(hash_it(t)); }\n        ",
        "",
    );
    std::fs::write(dir.join("src/cross_domain/bridge.rs"), one).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a one-ledger root passed"));
    }
    let unordered = good.replace(
        "transfers: BTreeMap<MessageId",
        "transfers: HashMap<MessageId",
    );
    std::fs::write(dir.join("src/cross_domain/bridge.rs"), unordered).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: an unordered transfer ledger passed"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "bridge dual-tree canary OK (both ledgers PASS; dropping the transfer fold and an \
         unordered ledger each FAIL).",
    ))
}
