//! Consensus state is written only by block execution (
//! item 7).
//!
//! The account state is what the state root commits. A write to it that runs
//! outside the block transition (an operator RPC, a chain-actor command, a
//! post-commit maintenance pass) happens on one node and not on its peers, or
//! on live nodes and not on a node that replays the blocks after a restart.
//! Either way two honest nodes hold different roots for the same chain.
//! moved every such write into a signed transaction door or into the
//! `(state, block) -> state` transition; this gate keeps them there.
//!
//! The chain actor is the only bridge from RPC and gossip into `Blockchain`,
//! so the gate reads its production code (tests, comments and strings
//! stripped) and checks:
//!
//!   1. It never writes `self.blockchain.state` directly: no `&mut` borrow,
//!      no assignment, and every method it calls on the state is a read.
//!   2. Every `Blockchain` method it calls is classified in [`CALLS`]: a
//!      read, node-local work outside the state root, a block path (the
//!      functions that apply blocks), snapshot sync, or a devnet-only credit.
//!      There is no class for a consensus write, so the set of out-of-block
//!      consensus writes is empty and cannot grow; a new call fails here
//!      until a reviewer classifies it.
//!   3. A method classified as a read or as node-local does not write
//!      `self.state` in its own body.

use std::path::Path;

/// How a `Blockchain` method the chain actor calls relates to the state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Class {
    /// Reads only.
    Read,
    /// Writes node-local structures outside the state root: the mempool,
    /// finality votes and certificates, the slashing evidence pool, the QC
    /// blob cache, the node-local header archive.
    NodeLocal,
    /// Applies a block: production, validation, reorg. The state transition
    /// itself.
    BlockPath,
    /// Replaces the state with a verified snapshot.
    Sync,
    /// Credits a development account; refused outside the devnet chain id
    ///.
    DevnetOnly,
}

use Class::{BlockPath, DevnetOnly, NodeLocal, Read, Sync};

/// Every `Blockchain` method the chain actor's production code calls.
const CALLS: &[(&str, Class)] = &[
    ("add_transaction", NodeLocal),
    ("apply_state_snapshot", Sync),
    ("build_global_header", Read),
    ("consensus", Read),
    ("credit_development_account", DevnetOnly),
    ("drain_local_slashing_evidence", NodeLocal),
    ("external_domain_profile", Read),
    ("external_domain_profiles", Read),
    ("external_domain_registration", Read),
    ("external_quorum_round", Read),
    ("external_quorum_rounds", Read),
    ("find_common_height", Read),
    ("fund_development_account", DevnetOnly),
    ("get_aggregator_state", Read),
    ("global_header", Read),
    ("global_header_proof", Read),
    ("get_qc_blob", Read),
    ("get_locator", Read),
    ("get_state_root", Read),
    ("get_state_snapshot", Read),
    ("get_transaction_by_hash", Read),
    ("graft_payment_proof", Read),
    ("import_pruned_segment", Sync),
    ("pq_sealed_heights", Read),
    ("pq_stage_observation", NodeLocal),
    ("quantum_view", Read),
    // Taking a transaction back out of the pool: the mempool and its node-local
    // persistence only. Nothing under `self.state` is touched, so a node that
    // forgets an admitted transaction still holds the same state root as its
    // peers - it either re-admits the transaction or never produces it.
    ("remove_transaction", NodeLocal),
    ("storage_economics_events", Read),
    ("try_reorg_suffix", BlockPath),
    ("get_transaction_receipt", Read),
    ("get_validator_set_hash", Read),
    ("handle_finality_cert", NodeLocal),
    ("handle_precommit", NodeLocal),
    ("handle_prevote", NodeLocal),
    ("handle_qc_fault_proof", NodeLocal),
    ("import_qc_blob", NodeLocal),
    ("last_block", Read),
    ("produce_block", BlockPath),
    ("sign_precommit", NodeLocal),
    ("sign_prevote", NodeLocal),
    ("start_pending_finality_round", NodeLocal),
    ("submit_slashing_evidence", NodeLocal),
    ("try_reorg", BlockPath),
    ("tx_precheck", Read),
    ("validate_and_add_block", BlockPath),
    ("validate_sovereign_audit_export", Read),
];

/// Method-name prefixes that only read. A state method the actor calls must
/// start with one of them.
const READ_PREFIXES: &[&str] = &[
    "get",
    "is_",
    "has_",
    "check_",
    "calculate_",
    "resolve",
    "len",
    "iter",
    "values",
    "keys",
    "contains",
    "domains",
    "external_intake_digest",
    "commitments_for_",
    "active_members",
    "slashing_history",
    "agents_by_",
    "payments_",
    "verifiers_by_",
    "may_view",
    "owner_of",
    "all_",
    "root",
    "params",
];

/// Read methods whose names no prefix above covers, matched exactly: an
/// identity record and credential lookup, a protected-content lookup, and
/// the coding-audit answer check (`&self`, it judges an answer and stores
/// nothing).
const READ_NAMES: &[&str] = &[
    "record",
    "credential",
    "asset_for",
    "verify_coding_audit",
    "delegations_for",
    "delegation_unbonding_for",
    "latest",
    "deals_for_manifest",
    "deals_for_shard",
    "under_replicated_shards",
];

/// Calls on `self.state` inside a `Blockchain` method body that write it.
const STATE_WRITERS: &[&str] = &[
    "add_balance(",
    "try_add_balance(",
    "try_mint_balance(",
    "get_or_create(",
    "mark_dirty(",
    "insert(",
    "remove(",
    "register",
    "bond",
    "slash",
    "set_",
    "open_",
    "finalize_",
    "expire_",
    "prune_",
    "sweep_",
    "annotate_",
    "accrue",
    "lock(",
    "mint(",
    "unlock(",
    "burn",
    "transition",
    "ensure_validator(",
    "anchor_",
    "credit",
    "debit",
    "get_mut(",
    "push(",
    "retain(",
    "clear(",
    "drain",
];

fn code_of(root: &Path, rel: &str) -> Result<String, String> {
    let f = root.join(rel);
    if !f.is_file() {
        return Err(format!("expected file missing: {}", f.display()));
    }
    let text = std::fs::read_to_string(&f).map_err(|e| e.to_string())?;
    Ok(normalize(&super::capability_modules_are_wired::code_only(
        &text,
    )))
}

/// Join method chains split over lines (`self\n    .blockchain\n    .x(`)
/// so a chain reads as one token run.
fn normalize(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_whitespace() {
            let mut ws = String::from(c);
            while let Some(&n) = chars.peek() {
                if n.is_whitespace() {
                    ws.push(n);
                    chars.next();
                } else {
                    break;
                }
            }
            if chars.peek() == Some(&'.') {
                continue;
            }
            out.push_str(&ws);
        } else if c == '.' {
            out.push(c);
            while chars.peek().is_some_and(|n| n.is_whitespace()) {
                chars.next();
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn ident_at(src: &str, at: usize) -> &str {
    let rest = &src[at..];
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    &rest[..end]
}

/// The method chain after `self.blockchain.state` at `at` (just past the
/// prefix): the final method name called, if the chain ends in a call, and
/// whether the chain is the target of an assignment.
fn state_chain(src: &str, at: usize) -> (Option<String>, bool) {
    let mut i = at;
    let bytes = src.as_bytes();
    let mut last = None;
    while i < bytes.len() && bytes[i] == b'.' {
        let name = ident_at(src, i + 1);
        if name.is_empty() {
            break;
        }
        i += 1 + name.len();
        last = Some(name.to_string());
    }
    let rest = src[i..].trim_start();
    if rest.starts_with('(') {
        return (last, false);
    }
    let assigned = (rest.starts_with('=') && !rest.starts_with("=="))
        || rest.starts_with("+=")
        || rest.starts_with("-=");
    (None, assigned)
}

/// Check 1: the actor never writes the state directly.
fn check_actor_state_access(actor: &str) -> Result<(), String> {
    if actor.contains("&mut self.blockchain.state") {
        return Err(
            "chain_actor.rs takes `&mut self.blockchain.state`: consensus state is written only \
             by block execution"
                .to_string(),
        );
    }
    let needle = "self.blockchain.state";
    let mut from = 0;
    while let Some(rel) = actor[from..].find(needle) {
        let at = from + rel + needle.len();
        from = at;
        let (method, assigned) = state_chain(actor, at);
        if assigned {
            return Err(
                "chain_actor.rs assigns into `self.blockchain.state` outside block execution"
                    .to_string(),
            );
        }
        if let Some(method) = method {
            if !READ_PREFIXES.iter().any(|p| method.starts_with(p))
                && !READ_NAMES.contains(&method.as_str())
            {
                return Err(format!(
                    "chain_actor.rs calls `{method}` on `self.blockchain.state`, which is not a \
                     read: consensus state is written only by block execution"
                ));
            }
        }
    }
    Ok(())
}

/// The `Blockchain` methods the actor calls.
fn actor_calls(actor: &str) -> std::collections::BTreeSet<String> {
    let needle = "self.blockchain.";
    let mut out = std::collections::BTreeSet::new();
    let mut from = 0;
    while let Some(rel) = actor[from..].find(needle) {
        let at = from + rel + needle.len();
        from = at;
        let name = ident_at(actor, at);
        if name.is_empty() || name == "state" {
            continue;
        }
        if actor[at + name.len()..].starts_with('(') {
            out.insert(name.to_string());
        }
    }
    out
}

/// The body of `fn name` in `src`, brace-matched.
fn fn_body<'a>(src: &'a str, name: &str) -> Option<&'a str> {
    let sig = format!("fn {name}(");
    let at = src.find(&sig)?;
    let open = at + src[at..].find('{')?;
    let mut depth = 0usize;
    for (i, b) in src.as_bytes()[open..].iter().enumerate() {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&src[at..=open + i]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Check 3: a read or node-local method does not write `self.state`.
fn check_body_writes(bc: &str, name: &str) -> Result<(), String> {
    let Some(body) = fn_body(bc, name) else {
        return Err(format!(
            "`Blockchain::{name}` is classified but its body was not found"
        ));
    };
    if body.contains("&mut self.state") {
        return Err(format!(
            "`Blockchain::{name}` is classified read or node-local and takes `&mut self.state`"
        ));
    }
    let needle = "self.state";
    let mut from = 0;
    while let Some(rel) = body[from..].find(needle) {
        let at = from + rel + needle.len();
        from = at;
        let (method, assigned) = state_chain(body, at);
        if assigned {
            return Err(format!(
                "`Blockchain::{name}` is classified read or node-local and assigns into the state"
            ));
        }
        if let Some(method) = method {
            if STATE_WRITERS
                .iter()
                .any(|w| format!("{method}(").starts_with(w))
            {
                return Err(format!(
                    "`Blockchain::{name}` is classified read or node-local and calls the state \
                     writer `{method}`"
                ));
            }
        }
    }
    Ok(())
}

/// # Errors
///
/// The first out-of-block write path, or an unclassified actor call.
pub fn run(root: &Path) -> Result<String, String> {
    let actor = code_of(root, "src/chain/chain_actor.rs")?;
    let bc = code_of(root, "src/chain/blockchain.rs")?;

    check_actor_state_access(&actor)?;

    let calls = actor_calls(&actor);
    for call in &calls {
        let Some((_, class)) = CALLS.iter().find(|(n, _)| n == call) else {
            return Err(format!(
                "chain_actor.rs calls `Blockchain::{call}`, which is not classified in \
                 no_out_of_block_consensus_writes::CALLS. Classify it (read, node-local, block \
                 path, sync, devnet-only); a consensus write belongs in a transaction door."
            ));
        };
        if matches!(class, Read | NodeLocal) {
            check_body_writes(&bc, call)?;
        }
    }
    let stale: Vec<&str> = CALLS
        .iter()
        .map(|(n, _)| *n)
        .filter(|n| !calls.contains(*n))
        .collect();
    if !stale.is_empty() {
        return Err(format!(
            "no_out_of_block_consensus_writes::CALLS classifies methods the actor no longer \
             calls: {stale:?}. Remove the rows."
        ));
    }
    Ok(format!(
        "No out-of-block consensus writes: the chain actor writes no state directly, and its {} \
         Blockchain calls are classified with no consensus-write class.",
        calls.len()
    ))
}

/// Break one staged file, expect a refusal, restore it.
fn break_and_expect_refusal(
    tmp: &Path,
    pristine: &Path,
    rel: &str,
    from: &str,
    to: &str,
    why: &str,
) -> Result<(), String> {
    let dst = tmp.join(rel);
    let text = std::fs::read_to_string(&dst).map_err(|e| e.to_string())?;
    if !text.contains(from) {
        return Err(format!("canary: anchor not found in {rel}: {from}"));
    }
    std::fs::write(&dst, text.replacen(from, to, 1)).map_err(|e| e.to_string())?;
    let refused = run(tmp).is_err();
    std::fs::copy(pristine.join(rel), &dst).map_err(|e| e.to_string())?;
    if !refused {
        return Err(format!("canary: {why}"));
    }
    Ok(())
}

/// # Errors
///
/// A canary the gate let through.
pub fn self_test() -> Result<String, String> {
    let root = std::env::var_os("BUDLUM_ROOT").map_or_else(
        || std::env::current_dir().unwrap_or_default(),
        std::path::PathBuf::from,
    );
    if !root.join("src/chain/chain_actor.rs").is_file() {
        return Err(String::from(
            "canary: real tree not found (run from the repo root)",
        ));
    }
    let tmp = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-noobcw")?;
    std::fs::create_dir_all(tmp.join("src/chain")).map_err(|e| e.to_string())?;
    for rel in ["src/chain/chain_actor.rs", "src/chain/blockchain.rs"] {
        std::fs::copy(root.join(rel), tmp.join(rel)).map_err(|e| e.to_string())?;
    }
    if let Err(e) = run(&tmp) {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(format!("canary: an unmodified copy was refused: {e}"));
    }
    let anchor = "ChainCommand::GetBalance(addr, tx) => {\n";
    let cases = [
        (
            "src/chain/chain_actor.rs",
            format!("{anchor}                    let _ = self.blockchain.state.add_balance(&addr, 1);\n"),
            "an actor arm that credits a balance passed",
        ),
        (
            "src/chain/chain_actor.rs",
            format!("{anchor}                    self.blockchain.state.epoch_index = 0;\n"),
            "an actor arm that assigns into the state passed",
        ),
        (
            "src/chain/chain_actor.rs",
            format!("{anchor}                    let _ = self.blockchain.unclassified_write(addr);\n"),
            "an unclassified Blockchain call passed",
        ),
    ];
    for (rel, to, why) in &cases {
        break_and_expect_refusal(&tmp, &root, rel, anchor, to, why)?;
    }
    // A node-local method that starts writing the state: the injected body
    // is the first `fn import_qc_blob(` the gate finds.
    break_and_expect_refusal(
        &tmp,
        &root,
        "src/chain/blockchain.rs",
        "pub fn import_qc_blob(",
        "pub fn import_qc_blob(&mut self) { self.state.add_balance(&Address::zero(), 1); }\n    pub fn import_qc_blob_original(",
        "a node-local method that credits a balance passed",
    )?;
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(String::from(
        "no-out-of-block-consensus-writes canary OK (clean PASSes, broken FAILs).",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_split_chain_is_joined() {
        let src = "let x = self\n    .blockchain\n    .state\n    .get_balance(&a);";
        assert!(normalize(src).contains("self.blockchain.state.get_balance("));
    }

    #[test]
    fn a_read_passes_and_a_write_fails() {
        assert!(check_actor_state_access("let b = self.blockchain.state.get_balance(&a);").is_ok());
        assert!(check_actor_state_access("self.blockchain.state.add_balance(&a, 1);").is_err());
        assert!(check_actor_state_access("self.blockchain.state.epoch_index = 3;").is_err());
        assert!(check_actor_state_access("if self.blockchain.state.epoch_index == 3 {}").is_ok());
    }
}
