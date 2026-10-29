//! Consensus state must only change inside a block (C3, step 1).
//!
//! The `state_updates` half of decision 50 has landed (slice 1+2): a verified
//! domain commitment's nonce writes now travel in a signed `StateUpdateTx` and
//! are applied inside block execution by the executor's `StateUpdate` arm,
//! instead of out of block by `apply_pending_commitments`. This gate pins the
//! landed invariant and keeps the still-out-of-block mutators
//! (`message_registry`, `bridge_state`) safe until their slices land:
//!
//!   1. The state root keeps covering the consensus fields. The fix moves the
//!      mutation into blocks; it does not drop the fields from the root, which
//!      would hide the divergence instead of fixing it.
//!   2. `apply_pending_commitments` no longer writes account nonces out of
//!      block; the executor's `StateUpdate` arm is retired and refuses
//!      every `StateUpdate` outright (431d7fb).
//!   3. `validate_commitment_state_updates` still rejects non-monotonic,
//!      near-`u64::MAX` and over-ceiling updates for whatever door ends up
//!      carrying the writes.
//!   4. `message_registry` and `bridge_state` only change inside a block: the
//!      executor's `BridgeBurn` and `CrossDomainMessage` arms are the only
//!      writers, and the old request-path doors
//!      (`submit_cross_domain_message`, `submit_relayed_cross_domain_message`,
//!      `burn_bridge_transfer_with_event`) are not in production code. A
//!      message that is in the state root must also be in the durable store,
//!      so the lock path still calls `save_cross_domain_message`.
//!
//! An out-of-block, unvalidated or unpersisted mutation is how two honest
//! nodes end up with different `state_root` values (partition), or how one
//! node is dropped remotely (v2 report, C3).

use std::path::Path;

fn code_of(root: &Path, rel: &str) -> Result<String, String> {
    let f = root.join(rel);
    if !f.is_file() {
        return Err(format!("expected file missing: {}", f.display()));
    }
    let text = std::fs::read_to_string(&f).map_err(|e| e.to_string())?;
    Ok(production_text(&text))
}

/// The text without test items, comments and string literals: a needle in a
/// comment, a string or a unit test is no evidence about production code.
fn production_text(text: &str) -> String {
    super::capability_modules_are_wired::code_only(text)
}

/// The text between `start` (inclusive) and `end` (exclusive, searched from
/// `start` onwards).
fn slice_of<'a>(src: &'a str, start: &str, end: &str) -> Result<&'a str, String> {
    let s = src
        .find(start)
        .ok_or_else(|| format!("marker not found: {start}"))?;
    let e = src[s..]
        .find(end)
        .map(|i| s + i)
        .ok_or_else(|| format!("end marker not found after {start}: {end}"))?;
    Ok(&src[s..e])
}

/// # Errors
///
/// Returns the first violated claim.
/// Checks 1 and 2: the state root still covers the consensus fields, and
/// the nonce writes are block-scoped (no out-of-block write; the executor
/// refuses `StateUpdate` entirely).
fn check_root_covers_and_nonces_are_block_scoped(
    bc: &str,
    acc: &str,
    ex: &str,
) -> Result<(), String> {
    // 1. The state root covers the consensus fields the out-of-block paths
    //    mutate.
    for (needle, msg) in [
        (
            "final_hasher.update(self.bridge_root)",
            "calculate_state_root no longer folds bridge_root",
        ),
        (
            "final_hasher.update(self.message_root)",
            "calculate_state_root no longer folds message_root",
        ),
        (
            "final_hasher.update(self.settlement_root)",
            "calculate_state_root no longer folds settlement_root",
        ),
    ] {
        if !acc.contains(needle) {
            return Err(msg.to_string());
        }
    }

    // 2. The commitment nonce writes are block-scoped: the out-of-block path
    //    must not write account nonces any more, and the executor's StateUpdate
    //    arm must validate before it writes. The assignment `account.nonce =
    //    *new_nonce` may only exist in the executor's StateUpdate arm; every
    //    other copy (apply_pending_commitments, the startup load path, the
    //    reorg reload path) is an out-of-block mutation.
    if bc.matches("account.nonce = *new_nonce").count() != 0 {
        return Err(
            "blockchain.rs still writes account nonces out of block (startup load, reorg reload, or apply_pending_commitments)"
                .to_string(),
        );
    }
    let apc = slice_of(
        bc,
        "fn apply_pending_commitments",
        "pub fn submit_verified_domain_commitment(",
    )?;
    if apc.contains("account.nonce = *new_nonce") {
        return Err(
            "apply_pending_commitments still writes account nonces out of block".to_string(),
        );
    }

    let arm = slice_of(ex, "TransactionType::StateUpdate { domain_id", "Ok(())")?;
    // The arm is RETIRED (431d7fb, BLG-0286 / P18-F01): it refuses every
    // StateUpdate instead of validating and writing, so the strongest form
    // of the block-scoping claim is that the arm carries the refusal and
    // contains no nonce write at all. A write that reappears here without
    // the validation stack around it is exactly the regression this gate
    // exists for.
    if !arm.contains("return Err") {
        return Err("executor StateUpdate arm no longer refuses every StateUpdate".to_string());
    }
    if arm.contains("*new_nonce") {
        return Err(
            "executor StateUpdate arm regained nonce logic; the arm must refuse every StateUpdate (431d7fb)"
                .to_string(),
        );
    }
    Ok(())
}

/// Checks 3 and 4: the validation rejects non-monotonic, near-MAX and
/// over-ceiling updates, and every out-of-block mutator leaves a durable
/// trail.
fn check_validation_and_durable_trails(bc: &str, ex: &str) -> Result<(), String> {
    // 3. The validation itself rejects non-monotonic, near-MAX and
    //    over-ceiling updates.
    let vcu = slice_of(
        bc,
        "fn validate_commitment_state_updates",
        "fn apply_pending_commitments",
    )?;
    for (needle, msg) in [
        (
            "MAX_STATE_UPDATES",
            "commitment state-update ceiling check removed",
        ),
        (
            "*new_nonce <= current",
            "non-monotonic nonce updates no longer rejected",
        ),
        ("u64::MAX - 1000", "near-u64::MAX nonce guard removed"),
    ] {
        if !vcu.contains(needle) {
            return Err(msg.to_string());
        }
    }

    // 4. `message_registry` and `bridge_state` only change inside a block.
    //
    // Both are folded into the state root, and both used to be written from the
    // request path (`submit_cross_domain_message`,
    // `submit_relayed_cross_domain_message`, `burn_bridge_transfer_with_event`).
    // Those methods are now `#[cfg(test)]`, so the production text this gate
    // scans must not contain them at all, and the write has to be in an
    // executor arm instead. This is the stricter form the earlier "durable
    // trail" check was standing in for.
    for gone in [
        "fn submit_cross_domain_message(",
        "fn submit_relayed_cross_domain_message(",
        "fn burn_bridge_transfer_with_event(",
    ] {
        if bc.contains(gone) {
            return Err(format!(
                "{gone} is reachable from production code: it writes consensus state outside block execution"
            ));
        }
    }
    for (needle, msg) in [
        (
            "TransactionType::BridgeBurn(burn)",
            "the executor lost the in-block BridgeBurn arm",
        ),
        (
            "apply_burn_to_state(",
            "the in-block burn no longer runs the shared burn body",
        ),
        (
            "TransactionType::CrossDomainMessage(message)",
            "the executor lost the in-block CrossDomainMessage arm",
        ),
        (
            "register_relayed_on_state(",
            "the in-block relayed door no longer runs the gated body",
        ),
    ] {
        if !ex.contains(needle) {
            return Err(msg.to_string());
        }
    }
    // The lock path still persists the message it registers; the lock itself is
    // the one remaining out-of-block bridge mutation (tracked separately), and
    // a message in the state root must also be in the durable store.
    if !bc.contains("save_cross_domain_message(") {
        return Err("the bridge lock no longer persists the message it registers".to_string());
    }
    let srp = slice_of(
        bc,
        "pub fn submit_relay_proof(",
        "pub fn pending_relay_count(",
    )?;
    if !srp.contains("save_universal_relayer") {
        return Err(
            "submit_relay_proof no longer persists the universal relayer state".to_string(),
        );
    }
    if !srp.contains("save_bridge_state") {
        return Err(
            "submit_relay_proof no longer persists bridge_state after mint/unlock".to_string(),
        );
    }
    Ok(())
}

/// # Errors
///
/// Returns the first violated claim.
pub fn run(root: &Path) -> Result<String, String> {
    let bc = code_of(root, "src/chain/blockchain.rs")?;
    let acc = code_of(root, "src/core/account.rs")?;
    let ex = code_of(root, "src/execution/executor.rs")?;

    check_root_covers_and_nonces_are_block_scoped(&bc, &acc, &ex)?;
    check_validation_and_durable_trails(&bc, &ex)?;

    Ok("Consensus-state boundary OK: state root covers consensus fields, StateUpdate nonce writes are block-scoped (executor validates before writing, no out-of-block write), and `message_registry` / `bridge_state` now move only in block - the BridgeBurn and CrossDomainMessage transaction arms apply them, and the old request-path doors are not in production code. The bridge lock is the one remaining out-of-block bridge mutation, tracked separately.".to_string())
}

/// # Errors
///
/// Returns a finding when the gate accepts a broken copy of the real tree.
/// Break one file of the staged copy, expect the gate to refuse it, and
/// restore the pristine row either way, so the next canary starts from a
/// clean tree.
fn break_and_expect_refusal(
    tmp: &std::path::Path,
    pristine: &std::path::Path,
    rel: &str,
    from: &str,
    to: &str,
    why: &str,
) -> Result<(), String> {
    let dst = tmp.join(rel);
    let text = std::fs::read_to_string(&dst).map_err(|e| e.to_string())?;
    std::fs::write(&dst, text.replace(from, to)).map_err(|e| e.to_string())?;
    let refused = run(tmp).is_err();
    std::fs::copy(pristine.join(rel), &dst).map_err(|e| e.to_string())?;
    if !refused {
        return Err(format!("canary: {why}"));
    }
    Ok(())
}

pub fn self_test() -> Result<String, String> {
    let root = std::env::var_os("BUDLUM_ROOT").map_or_else(
        || std::env::current_dir().unwrap_or_default(),
        std::path::PathBuf::from,
    );
    if !root.join("src/chain/blockchain.rs").is_file() {
        return Err(String::from(
            "canary: real tree not found (run from the repo root)",
        ));
    }
    let tmp = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-cscib")?;
    for sub in ["src/chain", "src/core", "src/execution"] {
        std::fs::create_dir_all(tmp.join(sub)).map_err(|e| e.to_string())?;
    }
    for rel in [
        "src/chain/blockchain.rs",
        "src/core/account.rs",
        "src/execution/executor.rs",
    ] {
        std::fs::copy(root.join(rel), tmp.join(rel)).map_err(|e| e.to_string())?;
    }
    if run(&tmp).is_err() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from("canary: an unmodified copy was refused"));
    }

    // Break 1: the state root stops covering settlement_root.
    break_and_expect_refusal(
        &tmp,
        &root,
        "src/core/account.rs",
        "final_hasher.update(self.settlement_root)",
        "final_hasher.update([0u8; 32])",
        "a state root without settlement_root passed",
    )?;

    // Break 2: the executor StateUpdate arm regains nonce logic. The arm
    // is retired (431d7fb), so the canary plants a nonce touch inside it
    // and the gate must refuse any StateUpdate arm that is not a pure
    // refusal.
    break_and_expect_refusal(
        &tmp,
        &root,
        "src/execution/executor.rs",
        "TransactionType::StateUpdate { domain_id, .. } => {",
        "TransactionType::StateUpdate { domain_id, .. } => { let planted: u64 = *new_nonce; let _ = planted;",
        "an executor StateUpdate arm that regained nonce logic passed",
    )?;

    // Break 3: apply_pending_commitments regains an out-of-block nonce write.
    break_and_expect_refusal(
        &tmp,
        &root,
        "src/chain/blockchain.rs",
        "self.validate_commitment_state_updates(&com)?;",
        "self.validate_commitment_state_updates(&com)?;\n                for (addr, new_nonce) in &com.state_updates {\n                    let account = self.state.get_or_create(addr);\n                    account.nonce = *new_nonce;\n                }",
        "an out-of-block nonce write in apply_pending_commitments passed",
    )?;

    // Break 4: the in-block burn stops running the shared body.
    break_and_expect_refusal(
        &tmp,
        &root,
        "src/execution/executor.rs",
        "apply_burn_to_state(",
        "apply_burn_to_state_gone(",
        "an executor whose burn arm skips the burn body passed",
    )?;

    // Break 4b: the executor's relayed arm stops gating.
    break_and_expect_refusal(
        &tmp,
        &root,
        "src/execution/executor.rs",
        "register_relayed_on_state(",
        "register_relayed_on_state_gone(",
        "an executor whose relayed arm skips the gate passed",
    )?;

    // Break 5: the startup load path regains an out-of-block nonce write.
    break_and_expect_refusal(
        &tmp,
        &root,
        "src/chain/blockchain.rs",
        "// out-of-block mutation of consensus state.\n",
        "// out-of-block mutation of consensus state.\n                    let account = state.get_or_create(&commitment_addr); account.nonce = *new_nonce;\n",
        "a startup load path that writes nonces out of block passed",
    )?;

    let _ = std::fs::remove_dir_all(&tmp);
    Ok(String::from(
        "consensus-state-only-changes-in-blocks canary OK (clean PASSes, broken FAILs).",
    ))
}

#[cfg(test)]
mod production_text_tests {
    use super::*;

    #[test]
    fn needles_in_comments_strings_and_tests_are_gone() {
        let src = "// final_hasher.update(self.bridge_root)\nlet s = \"MAX_STATE_UPDATES\";\n#[cfg(test)]\nmod t { fn x() { save_cross_domain_message(); } }\nfn real() {}\n";
        let out = production_text(src);
        assert!(!out.contains("bridge_root"));
        assert!(!out.contains("MAX_STATE_UPDATES"));
        assert!(!out.contains("save_cross_domain_message"));
        assert!(out.contains("fn real"));
    }
}
