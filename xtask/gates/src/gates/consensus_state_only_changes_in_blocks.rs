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
//!      block; the executor's `StateUpdate` arm validates before it writes.
//!   3. The validation itself rejects non-monotonic, near-`u64::MAX` and
//!      over-ceiling updates.
//!   4. Every out-of-block mutation leaves a durable trail
//!      (`save_cross_domain_message`, `save_universal_relayer`,
//!      `save_bridge_state`), so a restart can reconstruct the same state.
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
    std::fs::read_to_string(&f).map_err(|e| e.to_string())
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
pub fn run(root: &Path) -> Result<String, String> {
    let bc = code_of(root, "src/chain/blockchain.rs")?;
    let acc = code_of(root, "src/core/account.rs")?;
    let ex = code_of(root, "src/execution/executor.rs")?;

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
        &bc,
        "fn apply_pending_commitments",
        "pub fn submit_verified_domain_commitment(",
    )?;
    if apc.contains("account.nonce = *new_nonce") {
        return Err(
            "apply_pending_commitments still writes account nonces out of block".to_string(),
        );
    }

    let arm = slice_of(&ex, "TransactionType::StateUpdate", "Ok(())")?;
    let val = arm
        .find("*new_nonce <= current")
        .ok_or("executor StateUpdate arm lost the monotonic nonce check")?;
    let write = arm
        .find("account.nonce = *new_nonce")
        .ok_or("executor StateUpdate arm lost the nonce write")?;
    if val > write {
        return Err("executor StateUpdate arm writes nonces before validating".to_string());
    }
    for (needle, msg) in [
        (
            "MAX_STATE_UPDATES",
            "executor StateUpdate arm lost the update ceiling check",
        ),
        (
            "u64::MAX - 1000",
            "executor StateUpdate arm lost the near-u64::MAX nonce guard",
        ),
    ] {
        if !arm.contains(needle) {
            return Err(msg.to_string());
        }
    }

    // 3. The validation itself rejects non-monotonic, near-MAX and
    //    over-ceiling updates.
    let vcu = slice_of(
        &bc,
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

    // 4. Out-of-block mutators leave a durable trail.
    let scdm = slice_of(
        &bc,
        "pub fn submit_cross_domain_message(",
        "pub fn burn_bridge_transfer(",
    )?;
    if !scdm.contains("save_cross_domain_message(") {
        return Err(
            "submit_cross_domain_message no longer persists the message (durable trail lost)"
                .to_string(),
        );
    }
    let srp = slice_of(
        &bc,
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

    Ok("Consensus-state boundary OK: state root covers consensus fields, StateUpdate nonce writes are block-scoped (executor validates before writing, no out-of-block write), out-of-block mutators persist a durable trail. message_registry and bridge_state move in-block in later slices (decision 50).".to_string())
}

/// # Errors
///
/// Returns a finding when the gate accepts a broken copy of the real tree.
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
    let bc_src = root.join("src/chain/blockchain.rs");
    let acc_src = root.join("src/core/account.rs");
    let ex_src = root.join("src/execution/executor.rs");
    let bc_dst = tmp.join("src/chain/blockchain.rs");
    let acc_dst = tmp.join("src/core/account.rs");
    let ex_dst = tmp.join("src/execution/executor.rs");

    std::fs::copy(&bc_src, &bc_dst).map_err(|e| e.to_string())?;
    std::fs::copy(&acc_src, &acc_dst).map_err(|e| e.to_string())?;
    std::fs::copy(&ex_src, &ex_dst).map_err(|e| e.to_string())?;
    if run(&tmp).is_err() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from("canary: an unmodified copy was refused"));
    }

    // Break 1: the state root stops covering settlement_root.
    let text = std::fs::read_to_string(&acc_dst).map_err(|e| e.to_string())?;
    std::fs::write(
        &acc_dst,
        text.replace(
            "final_hasher.update(self.settlement_root)",
            "final_hasher.update([0u8; 32])",
        ),
    )
    .map_err(|e| e.to_string())?;
    if run(&tmp).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: a state root without settlement_root passed",
        ));
    }
    std::fs::copy(&acc_src, &acc_dst).map_err(|e| e.to_string())?;

    // Break 2: the executor StateUpdate arm accepts equal nonce.
    let text = std::fs::read_to_string(&ex_dst).map_err(|e| e.to_string())?;
    std::fs::write(
        &ex_dst,
        text.replace("*new_nonce <= current", "*new_nonce < current"),
    )
    .map_err(|e| e.to_string())?;
    if run(&tmp).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: an executor StateUpdate arm that accepts equal nonce passed",
        ));
    }
    std::fs::copy(&ex_src, &ex_dst).map_err(|e| e.to_string())?;

    // Break 3: apply_pending_commitments regains an out-of-block nonce write.
    let text = std::fs::read_to_string(&bc_dst).map_err(|e| e.to_string())?;
    std::fs::write(
        &bc_dst,
        text.replace(
            "self.validate_commitment_state_updates(&com)?;",
            "self.validate_commitment_state_updates(&com)?;\n                for (addr, new_nonce) in &com.state_updates {\n                    let account = self.state.get_or_create(addr);\n                    account.nonce = *new_nonce;\n                }",
        ),
    )
    .map_err(|e| e.to_string())?;
    if run(&tmp).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: an out-of-block nonce write in apply_pending_commitments passed",
        ));
    }
    std::fs::copy(&bc_src, &bc_dst).map_err(|e| e.to_string())?;

    // Break 4: the cross-domain message durable trail is gone.
    let text = std::fs::read_to_string(&bc_dst).map_err(|e| e.to_string())?;
    std::fs::write(
        &bc_dst,
        text.replace(
            "save_cross_domain_message(",
            "save_cross_domain_message_gone(",
        ),
    )
    .map_err(|e| e.to_string())?;
    if run(&tmp).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: an unpersisted cross-domain message passed",
        ));
    }
    std::fs::copy(&bc_src, &bc_dst).map_err(|e| e.to_string())?;

    // Break 5: the startup load path regains an out-of-block nonce write.
    let text = std::fs::read_to_string(&bc_dst).map_err(|e| e.to_string())?;
    std::fs::write(
        &bc_dst,
        text.replace(
            "// out-of-block mutation of consensus state.\n",
            "// out-of-block mutation of consensus state.\n                    let account = state.get_or_create(&commitment_addr); account.nonce = *new_nonce;\n",
        ),
    )
    .map_err(|e| e.to_string())?;
    if run(&tmp).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: a startup load path that writes nonces out of block passed",
        ));
    }

    let _ = std::fs::remove_dir_all(&tmp);
    Ok(String::from(
        "consensus-state-only-changes-in-blocks canary OK (clean PASSes, broken FAILs).",
    ))
}
