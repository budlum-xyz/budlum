//! Fail closed when the direct settlement door is not guarded in production.
//!
//! This is a production-wiring check: `settlement::app_binding` must refuse
//! unenabled chain ids before dispatching a transaction, with the refusal in
//! executed code - not in a comment, a devnet-only profile helper, or an
//! unexecuted test. A source file or a named test is not evidence; the door
//! itself must carry the guard.
//!
//! The launch-evidence row validation that used to share this gate moved to
//! the workspace repository together with the launch ledger (the product tree
//! must not carry audit ledgers; `no-internal-ids` refuses the directories).

use std::path::Path;

fn cited_binding_guard(source: &str) -> bool {
    let Some(start) = source.find("pub fn execute_app_binding_tx(") else {
        return false;
    };
    let body = &source[start..];
    let Some(end) = body.find("match tx {") else {
        return false;
    };
    let preflight = &body[..end];
    let Some(guard) = preflight.find("if !app_binding_enabled_for_chain_id(ctx.chain_id)") else {
        return false;
    };
    preflight[guard..].contains("return Err(")
}

/// A profile helper and a named test do not close the direct settlement API.
fn binding_direct_guard(source: &str) -> bool {
    cited_binding_guard(&super::capability_modules_are_wired::code_only(source))
}

fn binding_guard(root: &Path) -> Result<(), String> {
    let path = "src/settlement/app_binding.rs";
    let code = std::fs::read_to_string(root.join(path))
        .map_err(|e| format!("{path}: cannot inspect settlement door: {e}"))?;
    if !binding_direct_guard(&code) {
        return Err(String::from("app-binding direct settlement door lacks a testnet chain-ID refusal: settlement app-binding module::execute_app_binding_tx_or_legacy must call app_binding_enabled_for_chain_id(ctx.chain_id) before match tx. A devnet-only profile helper or an unexecuted test is insufficient."));
    }
    Ok(())
}

/// Check the direct `app_binding` settlement guard.
///
/// # Errors
///
/// Reports an absent or unwired settlement door module.
pub fn run(root: &Path) -> Result<String, String> {
    binding_guard(root)?;
    Ok(String::from(
        "settlement app-binding guard OK: the direct settlement door refuses unenabled chain ids before match tx",
    ))
}

/// Run `app-binding-guard`. The gate takes no arguments.
///
/// # Errors
///
/// Reports an unknown argument or an unwired settlement door.
pub fn run_args(root: &Path, args: &[&str]) -> Result<String, String> {
    match args.first().copied() {
        None => run(root),
        Some(other) => Err(format!(
            "unknown argument `{other}`; the app-binding guard takes no arguments"
        )),
    }
}

/// Inject comment-only, inverted, profile-helper and unwired doors to prove
/// this gate can fail.
///
/// # Errors
///
/// Reports if any injected absence or comment-only guard was accepted.
pub fn self_test() -> Result<String, String> {
    let good = "pub fn execute_app_binding_tx(ctx: C, tx: T) -> R { if !app_binding_enabled_for_chain_id(ctx.chain_id) { return Err(refused()); } match tx { _ => Ok(()) } }";
    let comment = "pub fn execute_app_binding_tx(ctx: C, tx: T) -> R { // app_binding_enabled_for_chain_id(ctx.chain_id) return Err(..);\n match tx { _ => Ok(()) } }";
    let inverted = good.replace(
        "if !app_binding_enabled_for_chain_id",
        "if app_binding_enabled_for_chain_id",
    );
    let helper_only = "pub fn app_binding_enabled_for_chain_id() {} pub fn execute_app_binding_tx(ctx: C, tx: T) -> R { match tx { _ => Ok(()) } }";
    let guard_after_match = "pub fn execute_app_binding_tx(ctx: C, tx: T) -> R { match tx { _ => { if !app_binding_enabled_for_chain_id(ctx.chain_id) { return Err(refused()); } } } }";
    if !binding_direct_guard(good)
        || binding_direct_guard(comment)
        || binding_direct_guard(&inverted)
        || binding_direct_guard(helper_only)
        || binding_direct_guard(guard_after_match)
    {
        return Err(String::from(
            "app-binding direct-gate canary failed: a comment-only, inverted, profile-helper or post-dispatch guard was accepted",
        ));
    }
    let tmp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let door = tmp.path().join("src/settlement");
    std::fs::create_dir_all(&door).map_err(|e| e.to_string())?;
    std::fs::write(
        door.join("app_binding.rs"),
        "pub fn execute_app_binding_tx(ctx: C, tx: T) -> R { match tx { _ => Ok(()) } }\n",
    )
    .map_err(|e| e.to_string())?;
    if binding_guard(tmp.path()).is_ok() {
        return Err(String::from("unwired settlement door was accepted"));
    }
    Ok(String::from(
        "app-binding-guard canary OK: comment-only, inverted, profile-helper, post-dispatch and unwired doors refused",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn app_binding_guard_rejects_unwired_and_comment_only_doors() {
        super::self_test().unwrap();
    }

    #[test]
    fn app_binding_guard_rejects_inverted_and_post_dispatch_guards() {
        use super::*;
        let good = "pub fn execute_app_binding_tx(ctx: C, tx: T) -> R { if !app_binding_enabled_for_chain_id(ctx.chain_id) { return Err(refused()); } match tx { _ => Ok(()) } }";
        assert!(binding_direct_guard(good));
        let inverted = good.replace(
            "if !app_binding_enabled_for_chain_id",
            "if app_binding_enabled_for_chain_id",
        );
        let post_dispatch = good.replace(
            "if !app_binding_enabled_for_chain_id(ctx.chain_id) { return Err(refused()); } ",
            "",
        );
        assert!(!binding_direct_guard(&inverted));
        assert!(!binding_direct_guard(&post_dispatch));
    }

    #[test]
    fn app_binding_guard_requires_direct_preflight_not_comment_or_profile_helper() {
        use super::*;
        let good = "pub fn execute_app_binding_tx(ctx: C, tx: T) -> R { if !app_binding_enabled_for_chain_id(ctx.chain_id) { return Err(refused()); } match tx { _ => Ok(()) } }";
        assert!(binding_direct_guard(good));
        let comment = "pub fn execute_app_binding_tx(ctx: C, tx: T) -> R { // app_binding_enabled_for_chain_id(ctx.chain_id) return Err(...);\n match tx { _ => Ok(()) } }";
        assert!(!binding_direct_guard(comment));
        assert!(!binding_direct_guard("pub fn app_binding_enabled_for_chain_id() {} pub fn execute_app_binding_tx(ctx: C, tx: T) -> R { match tx { _ => Ok(()) } }"));
    }
}
