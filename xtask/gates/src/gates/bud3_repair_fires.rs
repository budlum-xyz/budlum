//! `bud3_repair_fires`: the repair path is reachable from production code.
//!
//! §6.10 and WP-20 item 8 describe a repair that happens: a segment that loses
//! `f / 2` shares becomes a task, a Full repairer decodes it, `RecordRepair`
//! writes fresh ESIs, and 1% of repairs are re-derived each epoch with a 1%
//! slash for a mismatch. Every one of those limbs can exist as a function that
//! nothing calls, and the tree is full of that shape - a `pub fn` with a test
//! and no caller reads as finished work to everybody except the operator whose
//! segment never gets repaired.
//!
//! This gate is the call graph, spelled out as text: for every piece of the
//! repair path, the place in production code that has to reach it. Each entry
//! names the file to look in, the call it expects, and what stops working when
//! the call is gone.
//!
//! # Why text and not a real call graph
//!
//! The gate crate has no dependencies (it is inside the trust boundary and must
//! build before anything else), so it cannot link the node's crate. A textual
//! requirement is weaker than a call-graph query, and it is still much stronger
//! than nothing: it fails when the wiring is deleted rather than merely unused,
//! which is the regression that actually happens in review.

use std::fmt::Write as _;
use std::path::Path;

/// One edge of the repair path that has to exist.
struct Edge {
    /// What the caller does.
    what: &'static str,
    /// The file that must contain the call.
    file: &'static str,
    /// The exact text the caller must carry.
    call: &'static str,
    /// What silently stops happening without it.
    consequence: &'static str,
}

/// The edges.
const EDGES: &[Edge] = &[
    Edge {
        what: "the state root covers the custody registry",
        file: "src/core/account.rs",
        call: "bud3_registry.state_root()",
        consequence: "share loss, repairs and declines stop moving the state root, so two \
                      nodes that disagree about who holds what commit the same root",
    },
    Edge {
        what: "storage transactions reach the B.U.D. 3.0 door",
        file: "src/storage/bud3/tx.rs",
        call: "pub fn apply(",
        consequence: "RegisterObject, CustodyProofBatch and RecordRepair are unreachable \
                      from a block",
    },
    Edge {
        what: "the repair threshold lives in one place",
        file: "src/storage/bud3/registry.rs",
        call: "pub fn repairs_due(",
        consequence: "the lazy `f / 2` rule of §6.10 item 1 would be re-implemented per \
                      caller and drift",
    },
    Edge {
        what: "settling a repair is a registry operation",
        file: "src/storage/bud3/registry.rs",
        call: "pub fn settle_repairs(",
        consequence: "the old shares of a repaired segment are never dropped, so a segment \
                      accumulates dead shares forever",
    },
    Edge {
        what: "a repair assignment is produced",
        file: "src/storage/bud3/repair.rs",
        call: "pub fn repairer_at(",
        consequence: "no repairer is ever named, so no repair task can be picked up",
    },
    Edge {
        what: "a repair symbol can be checked against its source",
        file: "src/storage/bud3/repair.rs",
        call: "pub fn verify(",
        consequence: "§6.10 item 8's 1% re-derivation has nothing to call, and a bad repair \
                      is never detected",
    },
    Edge {
        what: "a bad repair becomes a slashable report",
        file: "src/storage/bud3/repair.rs",
        call: "pub fn bad_repair_report(",
        consequence: "a mismatch is detected and then discarded; the 1% penalty of §11.7 \
                      is never charged",
    },
    Edge {
        what: "the bad-repair condition reaches the parameter table",
        file: "src/registry/params.rs",
        call: "bad_repair_slash_ratio_fixed",
        consequence: "the condition exists but has no ratio, so `slash_ratio` cannot price it",
    },
    Edge {
        what: "a block cannot carry an unverified bad-repair report",
        file: "src/chain/blockchain.rs",
        call: "SlashingProof::BadRepair",
        consequence: "a producer could accuse any repairer and the block would be accepted",
    },
    Edge {
        what: "the audit draw is the custody module's, not a second copy",
        file: "src/storage/bud3/registry.rs",
        call: "audit_for(seed, &r, ppm, subs)",
        consequence: "the draw and the verification would sample different shares",
    },
];

/// Where the module tree points at the repair module.
const MODULE: (&str, &str) = ("src/storage/bud3/mod.rs", "pub mod repair;");

/// Read a file, or explain why the gate cannot.
fn read(root: &Path, rel: &str) -> Result<String, String> {
    let path = root.join(rel);
    std::fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

fn check_edges(root: &Path) -> Result<Vec<String>, String> {
    let mut missing = Vec::new();
    for edge in EDGES {
        let Ok(text) = read(root, edge.file) else {
            missing.push(format!(
                "  {}: {} -- the file is gone, so {}",
                edge.what, edge.file, edge.consequence
            ));
            continue;
        };
        if !text.contains(edge.call) {
            missing.push(format!(
                "  {}: {} no longer contains `{}` -- {}",
                edge.what, edge.file, edge.call, edge.consequence
            ));
        }
    }
    Ok(missing)
}

/// Run the gate.
///
/// # Errors
///
/// The missing edges, one per line.
pub fn run(root: &Path) -> Result<String, String> {
    let module = read(root, MODULE.0)?;
    if !module.contains(MODULE.1) {
        return Err(format!(
            "FAIL: {} does not declare `{}`, so the repair module is not compiled at all",
            MODULE.0, MODULE.1
        ));
    }
    let missing = check_edges(root)?;
    if missing.is_empty() {
        return Ok(format!(
            "bud3 repair OK: {} repair-path edge(s) present and the module is declared",
            EDGES.len()
        ));
    }
    let mut out = String::new();
    for line in &missing {
        let _ = writeln!(out, "{line}");
    }
    Err(format!(
        "FAIL: the B.U.D. 3.0 repair path is not wired (§6.10):\n{out}  \
         A repair function with no caller is a function that never repairs anything."
    ))
}

/// The canary: deleting one edge and the module declaration each fail.
///
/// # Errors
///
/// When the gate does not behave.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-repair")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };
        // Every edge present.
        for edge in EDGES {
            let mut text = String::new();
            for other in EDGES.iter().filter(|e| e.file == edge.file) {
                let _ = writeln!(text, "{}", other.call);
            }
            put(edge.file, &text)?;
        }
        put(MODULE.0, &format!("// modules\n{}\n", MODULE.1))?;
        run(&dir).map_err(|e| format!("canary: a fully wired tree failed: {e}"))?;

        // Delete one edge.
        let broken = EDGES[3].file;
        let mut text = String::new();
        for other in EDGES
            .iter()
            .filter(|e| e.file == broken && e.call != EDGES[3].call)
        {
            let _ = writeln!(text, "{}", other.call);
        }
        put(broken, &text)?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a deleted edge passed"));
        }
        // Delete the module declaration: the module is not compiled at all.
        put(broken, &text)?;
        put(MODULE.0, "// modules\n")?;
        if run(&dir).is_ok() {
            return Err(String::from(
                "canary: an undeclared repair module passed",
            ));
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "bud3-repair canary OK: a deleted edge and a missing module declaration each failed.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn bud3_repair_fires_gate() {
        assert!(super::self_test().is_ok(), "{:?}", super::self_test());
    }

    #[test]
    fn the_tree_is_wired() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("the gate crate lives two levels below the root");
        assert!(super::run(root).is_ok(), "{:?}", super::run(root));
    }
}
