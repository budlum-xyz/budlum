//! Consensus state must only change inside a block (C3, step 1).
//!
//! A verified domain commitment's nonce writes are applied by the settlement
//! door (`SettlementTx::SubmitCommitment`, `src/settlement/domains.rs`), in
//! the same in-block transaction that verifies the commitment's finality.
//! The earlier `StateUpdate` door, which moved other accounts' nonces on a
//! validator signature alone, is retired. The bridge state, the
//! bridge's cross-domain messages and the universal relayer are written by
//! the bridge door (`BridgeTx`, `src/cross_domain/bridge_tx.rs`), also in
//! block. This gate pins both invariants:
//!
//!   1. The state root keeps covering the consensus fields. The fix moves the
//!      mutation into blocks; it does not drop the fields from the root, which
//!      would hide the divergence instead of fixing it.
//!   2. `blockchain.rs` writes no account nonce; the settlement door validates
//!      a commitment's nonce writes before it applies them; the executor's
//!      `StateUpdate` arm and the account validation refuse the retired tag.
//!   3. The validation itself rejects non-monotonic, near-`u64::MAX` and
//!      over-ceiling updates.
//!   4. `blockchain.rs` production code runs no bridge state transition, no
//!      message registration and no relay, and keeps no side-store row for
//!      them; the executor's `Bridge` arm delegates to `execute_bridge_tx`.
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
/// the nonce writes are block-scoped (no out-of-block write, the settlement
/// door validates before it writes, the retired door refuses).
fn check_root_covers_and_nonces_are_block_scoped(
    bc: &str,
    dom: &str,
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

    // 2. The commitment nonce writes are block-scoped: blockchain.rs writes
    //    no account nonce (no startup load, reorg reload or out-of-block
    //    accept path), the settlement door validates each commitment's writes
    //    before it applies them, and the retired StateUpdate tag is refused
    //    by the executor and by the account validation.
    if bc.matches("account.nonce = *new_nonce").count() != 0 {
        return Err(
            "blockchain.rs still writes account nonces out of block (startup load, reorg reload, or an accept path)"
                .to_string(),
        );
    }
    let apc = slice_of(
        dom,
        "fn apply_pending_commitments",
        "pub fn accept_verified_commitment(",
    )?;
    let val = apc
        .find("validate_commitment_state_updates(state, &com)?")
        .ok_or("the settlement door no longer validates a commitment's nonce writes")?;
    let write = apc
        .find("account.nonce = *new_nonce")
        .ok_or("the settlement door lost the commitment nonce write")?;
    if val > write {
        return Err("the settlement door writes nonces before validating them".to_string());
    }
    if dom.matches("account.nonce = *new_nonce").count() != 1 {
        return Err(
            "settlement/domains.rs writes account nonces outside apply_pending_commitments"
                .to_string(),
        );
    }

    let arm = slice_of(
        ex,
        "TransactionType::StateUpdate",
        "TransactionType::Identity",
    )?;
    if arm.contains("account.nonce") || !arm.contains("return Err(") {
        return Err("the executor StateUpdate arm is no longer a refusal".to_string());
    }
    let vac = slice_of(acc, "TransactionType::StateUpdate", "Ok(())")?;
    if !vac.contains("return Err(") {
        return Err("the account validation accepts the retired StateUpdate tag".to_string());
    }
    Ok(())
}

/// Checks 3 and 4: the validation rejects non-monotonic, near-MAX and
/// over-ceiling updates, and the bridge writes are block-scoped.
fn check_validation_and_bridge_door(
    bc: &str,
    dom: &str,
    ex: &str,
    bridge: &str,
) -> Result<(), String> {
    // 3. The validation itself rejects non-monotonic, near-MAX and
    //    over-ceiling updates.
    let vcu = slice_of(
        dom,
        "fn validate_commitment_state_updates",
        "fn freeze_domain",
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

    // 4. The bridge writes are block-scoped: blockchain.rs production code
    //    runs none of them and keeps no side-store row, and the executor's
    //    Bridge arm delegates to the door.
    for (needle, what) in [
        ("bridge_state.lock(", "a bridge lock"),
        ("bridge_state.mint(", "a bridge mint"),
        ("bridge_state.unlock(", "a bridge unlock"),
        ("bridge_state.burn_with_event(", "a bridge burn"),
        (
            "bridge_state.register_asset(",
            "a bridge asset registration",
        ),
        (
            "message_registry.insert(",
            "a cross-domain message registration",
        ),
        ("process_relay(", "a relay"),
        ("save_bridge_state", "a bridge side-store write"),
        ("save_universal_relayer", "a relayer side-store write"),
        ("save_cross_domain_message", "a message side-store write"),
    ] {
        if bc.contains(needle) {
            return Err(format!(
                "blockchain.rs performs {what} outside the bridge door ({needle})"
            ));
        }
    }
    if !bridge.contains("pub fn execute_bridge_tx(") {
        return Err("the bridge door execute_bridge_tx is gone".to_string());
    }
    let arm = slice_of(ex, "TransactionType::Bridge(bridge_tx)", "Ok(())")?;
    if !arm.contains("execute_bridge_tx(") {
        return Err("the executor Bridge arm no longer delegates to the bridge door".to_string());
    }
    Ok(())
}

/// # Errors
///
/// Returns the first violated claim.
pub fn run(root: &Path) -> Result<String, String> {
    let bc = code_of(root, "src/chain/blockchain.rs")?;
    let dom = code_of(root, "src/settlement/domains.rs")?;
    let acc = code_of(root, "src/core/account.rs")?;
    let ex = code_of(root, "src/execution/executor.rs")?;
    let bridge = code_of(root, "src/cross_domain/bridge_tx.rs")?;

    check_root_covers_and_nonces_are_block_scoped(&bc, &dom, &acc, &ex)?;
    check_validation_and_bridge_door(&bc, &dom, &ex, &bridge)?;

    Ok("Consensus-state boundary OK: state root covers consensus fields, commitment nonce writes are block-scoped (the settlement door validates before writing, the retired StateUpdate door refuses, no out-of-block write), and the bridge, its messages and the relayer are written only by the Bridge door.".to_string())
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
    for sub in [
        "src/chain",
        "src/core",
        "src/cross_domain",
        "src/execution",
        "src/settlement",
    ] {
        std::fs::create_dir_all(tmp.join(sub)).map_err(|e| e.to_string())?;
    }
    for rel in [
        "src/chain/blockchain.rs",
        "src/settlement/domains.rs",
        "src/core/account.rs",
        "src/execution/executor.rs",
        "src/cross_domain/bridge_tx.rs",
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

    // Break 2: the settlement door's validation accepts an equal nonce.
    break_and_expect_refusal(
        &tmp,
        &root,
        "src/settlement/domains.rs",
        "*new_nonce <= current",
        "*new_nonce < current",
        "a commitment validation that accepts an equal nonce passed",
    )?;

    // Break 3: the settlement door applies nonce writes unvalidated.
    break_and_expect_refusal(
        &tmp,
        &root,
        "src/settlement/domains.rs",
        "        validate_commitment_state_updates(state, &com)?;\n        for (addr, new_nonce)",
        "        for (addr, new_nonce)",
        "a settlement door that applies unvalidated nonce writes passed",
    )?;

    // Break 4: blockchain.rs regains an out-of-block bridge mint.
    break_and_expect_refusal(
        &tmp,
        &root,
        "src/chain/blockchain.rs",
        "    fn release_unfrozen_domains(&mut self, unfrozen: &[DomainId]) {\n",
        "    fn release_unfrozen_domains(&mut self, unfrozen: &[DomainId]) {\n        let _ = self.state.bridge_state.mint(&Default::default(), 0);\n",
        "an out-of-block bridge mint in blockchain.rs passed",
    )?;

    // Break 7: the executor Bridge arm stops delegating to the door.
    break_and_expect_refusal(
        &tmp,
        &root,
        "src/execution/executor.rs",
        "crate::cross_domain::bridge_tx::execute_bridge_tx(state, &ctx, bridge_tx)",
        "Ok::<(), String>(())",
        "an executor Bridge arm that skips the door passed",
    )?;

    // Break 5: blockchain.rs regains an out-of-block nonce write.
    break_and_expect_refusal(
        &tmp,
        &root,
        "src/chain/blockchain.rs",
        "    fn release_unfrozen_domains(&mut self, unfrozen: &[DomainId]) {\n",
        "    fn release_unfrozen_domains(&mut self, unfrozen: &[DomainId]) {\n        for (addr, new_nonce) in &[(Address::zero(), 1u64)] { let account = self.state.get_or_create(addr); account.nonce = *new_nonce; }\n",
        "an out-of-block nonce write in blockchain.rs passed",
    )?;

    // Break 6: the executor accepts the retired StateUpdate tag again.
    break_and_expect_refusal(
        &tmp,
        &root,
        "src/execution/executor.rs",
        "// blocks keep their meaning; no new block may carry one.\n",
        "// blocks keep their meaning; no new block may carry one.\n                let account = state.get_or_create(&tx.from); account.nonce = 0;\n",
        "an executor StateUpdate arm that writes nonces passed",
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
