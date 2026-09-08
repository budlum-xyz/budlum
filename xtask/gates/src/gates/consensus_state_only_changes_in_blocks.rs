//! Consensus state must only change inside a block (C3, step 1).
//!
//! The full invariant - `message_registry`, `bridge_state` and `state_updates`
//! mutate only inside block execution - lands with the signed-tx refactor
//! (decision 50, PLAN-C3-TX-YOLU). Until it lands, the out-of-block mutators
//! are safe only because of preconditions this gate pins:
//!
//!   1. The state root keeps covering the consensus fields. The fix moves the
//!      mutation into blocks; it does not drop the fields from the root, which
//!      would hide the divergence instead of fixing it.
//!   2. `validate_commitment_state_updates` runs BEFORE the nonce write and
//!      rejects non-monotonic, near-`u64::MAX` and over-ceiling updates.
//!   3. Every out-of-block mutation leaves a durable trail
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

    // 2. Nonce writes: validate before write, inside apply_pending_commitments.
    let apc = slice_of(
        &bc,
        "fn apply_pending_commitments",
        "pub fn submit_verified_domain_commitment(",
    )?;
    let val = apc.find("validate_commitment_state_updates(&com)?");
    let write = apc.find("account.nonce = *new_nonce");
    let val =
        val.ok_or("apply_pending_commitments lost the validate_commitment_state_updates call")?;
    let write = write.ok_or("apply_pending_commitments lost the nonce write")?;
    if val > write {
        return Err(
            "nonce write runs before validate_commitment_state_updates in apply_pending_commitments"
                .to_string(),
        );
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

    Ok("Consensus-state boundary OK: state root covers consensus fields, nonce writes validate-before-write, out-of-block mutators persist a durable trail. Full block-scoped mutation lands with the signed-tx refactor (decision 50).".to_string())
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
    for sub in ["src/chain", "src/core"] {
        std::fs::create_dir_all(tmp.join(sub)).map_err(|e| e.to_string())?;
    }
    let bc_src = root.join("src/chain/blockchain.rs");
    let acc_src = root.join("src/core/account.rs");
    let bc_dst = tmp.join("src/chain/blockchain.rs");
    let acc_dst = tmp.join("src/core/account.rs");

    std::fs::copy(&bc_src, &bc_dst).map_err(|e| e.to_string())?;
    std::fs::copy(&acc_src, &acc_dst).map_err(|e| e.to_string())?;
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

    // Break 2: non-monotonic nonce updates are no longer rejected.
    let text = std::fs::read_to_string(&bc_dst).map_err(|e| e.to_string())?;
    std::fs::write(
        &bc_dst,
        text.replace("*new_nonce <= current", "*new_nonce < current"),
    )
    .map_err(|e| e.to_string())?;
    if run(&tmp).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: a validation that accepts equal nonce passed",
        ));
    }
    std::fs::copy(&bc_src, &bc_dst).map_err(|e| e.to_string())?;

    // Break 3: the cross-domain message durable trail is gone.
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

    let _ = std::fs::remove_dir_all(&tmp);
    Ok(String::from(
        "consensus-state-only-changes-in-blocks canary OK (clean PASSes, broken FAILs).",
    ))
}
