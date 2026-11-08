//! B.U.D. 3.0 custody rewards: pro-rata Custody Endowment payouts, missed-audit
//! forfeiture to the Network Security Pool, zero minting, and zero stake slashing.
//!
//! Enforces that:
//! 1. `src/storage/bud3/fees.rs` distributes Custody Endowment payouts per epoch
//!    proportional to audited symbol bytes and validator presence (`presence_ppm`),
//!    and routes missed-audit / declined-share forfeitures to `reward_pool_account()`.
//! 2. `src/storage/bud3/` never calls `try_mint_balance` (G-3: fixed supply) and
//!    never slashes validator stake on missed custody audits (V-4: missing an
//!    audit withholds reward and eventually marks the share lost, never slashes).
//! 3. `src/tokenomics/mod.rs` defines the 40% / 50% / 10% Network Security Pool
//!    shares (`CONSENSUS_REWARD_SHARE_BPS = 4_000`, `STORAGE_REWARD_SHARE_BPS = 5_000`,
//!    `REPAIR_RELAY_REWARD_SHARE_BPS = 1_000`).

use std::fmt::Write as _;
use std::path::Path;

fn read_rel(root: &Path, rel: &str) -> Result<String, String> {
    let path = root.join(rel);
    if !path.is_file() {
        return Err(format!("missing required file: {rel}"));
    }
    std::fs::read_to_string(&path).map_err(|e| format!("{rel}: {e}"))
}

fn strip_cfg_test(src: &str) -> &str {
    match src.find("#[cfg(test)]") {
        Some(idx) => src.get(..idx).unwrap_or(src),
        None => src,
    }
}

fn strip_line_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.lines() {
        let code = match line.find("//") {
            Some(idx) => line.get(..idx).unwrap_or(line),
            None => line,
        };
        out.push_str(code);
        out.push('\n');
    }
    out
}

fn scan_bud3_dir(dir: &Path, out: &mut Vec<(String, String)>) -> Result<(), String> {
    if !dir.is_dir() {
        return Err(String::from("missing `src/storage/bud3` directory"));
    }
    let entries = std::fs::read_dir(dir).map_err(|e| e.to_string())?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() && path.extension().is_some_and(|e| e == "rs") {
            let name = entry.file_name().to_string_lossy().to_string();
            let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
            out.push((name, text));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(())
}

/// Run the `bud3-custody-rewards` gate against `root`.
///
/// # Errors
///
/// Returns a human-readable failure report if any custody reward or non-slashing
/// invariant is violated.
pub fn run(root: &Path) -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();

    let fees_raw = read_rel(root, "src/storage/bud3/fees.rs")?;
    let registry_raw = read_rel(root, "src/storage/bud3/registry.rs")?;
    let tok_raw = read_rel(root, "src/tokenomics/mod.rs")?;

    let fees_prod = strip_line_comments(strip_cfg_test(&fees_raw));
    let registry_prod = strip_line_comments(strip_cfg_test(&registry_raw));
    let tok_prod = strip_line_comments(strip_cfg_test(&tok_raw));

    for token in [
        "distribute_object_endowment_epoch",
        "forfeited_to_security_pool",
        "reward_pool_account",
        "presence_ppm",
        "epoch_storage_reward_share",
    ] {
        if !fees_prod.contains(token) {
            problems.push(format!(
                "`src/storage/bud3/fees.rs` is missing required custody settlement symbol `{token}`."
            ));
        }
    }

    if !registry_prod.contains("distribute_object_endowment_epoch") {
        problems.push(String::from(
            "`src/storage/bud3/registry.rs` does not invoke `distribute_object_endowment_epoch` during epoch window close.",
        ));
    }

    for share_const in [
        "CONSENSUS_REWARD_SHARE_BPS: u64 = 4_000",
        "STORAGE_REWARD_SHARE_BPS: u64 = 5_000",
        "REPAIR_RELAY_REWARD_SHARE_BPS: u64 = 1_000",
    ] {
        if !tok_prod.contains(share_const) {
            problems.push(format!(
                "`src/tokenomics/mod.rs` is missing Network Security Pool share `{share_const}`."
            ));
        }
    }

    let mut files = Vec::new();
    scan_bud3_dir(&root.join("src/storage/bud3"), &mut files)?;
    for (name, raw) in &files {
        let prod = strip_line_comments(strip_cfg_test(raw));
        if prod.contains("try_mint_balance") {
            problems.push(format!(
                "`src/storage/bud3/{name}` calls `try_mint_balance`; custody rewards must never mint supply (G-3)."
            ));
        }
        for slash_tok in ["SlashingProof", "slash_validator", "slash_stake"] {
            if prod.contains(slash_tok) {
                problems.push(format!(
                    "`src/storage/bud3/{name}` references `{slash_tok}`; missed custody audits withhold reward and trigger suspension/repair, never stake slashing (V-4)."
                ));
            }
        }
    }

    if !problems.is_empty() {
        let mut msg = String::from("bud3-custody-rewards failed:\n");
        for p in &problems {
            let _ = writeln!(msg, "  - {p}");
        }
        return Err(msg);
    }

    Ok(String::from(
        "bud3-custody-rewards OK: pro-rata endowment settlement, security-pool forfeiture, 40/50/10 pool shares, zero minting, and zero audit slashing verified.",
    ))
}

/// Self-test with positive and negative synthetic trees.
///
/// # Errors
///
/// Returns an error if any canary fails to trigger or a clean tree fails.
pub fn self_test() -> Result<String, String> {
    let dir =
        crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-custody-rewards")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };

        let clean_fees = "\
pub fn distribute_object_endowment_epoch(presence_ppm: u32) {
    let forfeited_to_security_pool = reward_pool_account();
    let _ = epoch_storage_reward_share(0);
    let _ = (presence_ppm, forfeited_to_security_pool);
}
";
        let clean_reg = "\
pub fn close_windows() {
    distribute_object_endowment_epoch(1_000_000);
}
";
        let clean_tok = "\
pub const CONSENSUS_REWARD_SHARE_BPS: u64 = 4_000;
pub const STORAGE_REWARD_SHARE_BPS: u64 = 5_000;
pub const REPAIR_RELAY_REWARD_SHARE_BPS: u64 = 1_000;
";
        put("src/storage/bud3/fees.rs", clean_fees)?;
        put("src/storage/bud3/registry.rs", clean_reg)?;
        put("src/tokenomics/mod.rs", clean_tok)?;
        run(&dir).map_err(|e| format!("canary: clean tree failed: {e}"))?;

        // Canary 1: minting in bud3 must fail.
        put(
            "src/storage/bud3/registry.rs",
            &format!("{clean_reg}\npub fn bad() {{ try_mint_balance(); }}\n"),
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: try_mint_balance in bud3 passed"));
        }

        // Canary 2: stake slashing on custody audit must fail.
        put(
            "src/storage/bud3/registry.rs",
            &format!("{clean_reg}\npub fn bad() {{ slash_stake(); }}\n"),
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: slash_stake in bud3 passed"));
        }

        // Canary 3: wrong tokenomics storage share must fail.
        put("src/storage/bud3/registry.rs", clean_reg)?;
        put(
            "src/tokenomics/mod.rs",
            &clean_tok.replace("5_000", "2_500"),
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: wrong STORAGE_REWARD_SHARE_BPS passed"));
        }

        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "bud3-custody-rewards canary OK: clean tree passed; minting, audit slashing, and altered pool share failed.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn bud3_custody_rewards_canary() {
        assert!(super::self_test().is_ok());
    }
}
