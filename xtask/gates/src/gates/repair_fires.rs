//! The repair trigger must actually fire on loss.
//!
//! Ported from `scripts/check-repair-fires-on-loss.sh`. A set of presence
//! claims over four source files: the maintenance sweep reads the repair
//! band, the margin scales with the erasure scheme, unrecoverable objects are
//! surfaced separately, and expiry opens a reallocation ticket. Each claim is
//! a `grep` over one file's source with `//` comments stripped.

use std::path::Path;

fn code_of(root: &Path, rel: &str) -> Result<String, String> {
    let f = root.join(rel);
    if !f.is_file() {
        return Err(format!("expected file missing: {}", f.display()));
    }
    let text = std::fs::read_to_string(&f).map_err(|e| e.to_string())?;
    Ok(text
        .lines()
        .map(|l| l.split("//").next().unwrap_or("").to_string())
        .collect::<Vec<_>>()
        .join("\n"))
}

macro_rules! claim {
    ($cond:expr, $msg:expr) => {
        if !$cond {
            return Err($msg.to_string());
        }
    };
}

/// # Errors
///
/// Returns the first violated claim.
pub fn run(root: &Path) -> Result<String, String> {
    let actor = code_of(root, "src/chain/chain_actor.rs")?;
    let registry = code_of(root, "src/domain/storage_deal.rs")?;
    let manifest = code_of(root, "src/storage/manifest.rs")?;
    let blockchain = code_of(root, "src/chain/blockchain.rs")?;

    // 1. The sweep reads the band.
    claim!(
        actor.contains("objects_below_own_repair_margin"),
        "the maintenance sweep does not read the repair band.\n  `objects_below_own_repair_margin` is not called from chain_actor.rs, so\n  the repair trigger is unwired and the effective repair window is unbounded."
    );

    // 2. The margin scales with the scheme.
    claim!(
        manifest.contains("fn repair_margin"),
        "ContentManifest::repair_margin is gone.\n  Without a per-scheme margin the sweep has to pick one number for every\n  object, which is measurably wrong for the wide codes."
    );
    let margin_fn: Vec<String> = manifest
        .lines()
        .filter(|l| l.contains("fn repair_margin"))
        .map(ToString::to_string)
        .collect();
    claim!(
        margin_fn.len() >= 2,
        format!(
            "repair_margin is defined {} time(s), expected 2.\n  ErasureScheme holds the rule and ContentManifest forwards it. With only\n  one of them, either the rule is gone or every caller has to reach through\n  to `erasure` itself, which is how a per-scheme rule becomes a constant.",
            margin_fn.len()
        )
    );
    claim!(
        manifest.contains("self.erasure.repair_margin()"),
        "ContentManifest::repair_margin does not forward to the scheme.\n  A forwarder that computes its own answer is a second rule, and two rules\n  drift."
    );
    let margin_block: String = manifest
        .lines()
        .skip_while(|l| !l.contains("fn repair_margin"))
        .take(12)
        .collect::<Vec<_>>()
        .join("\n");
    claim!(
        margin_block.contains("parity_count"),
        "repair_margin no longer derives from the parity budget.\n  A constant margin means two different things on (10,16) and LRC k=2000."
    );
    let reg_block: String = registry
        .lines()
        .skip_while(|l| !l.contains("fn objects_below_own_repair_margin"))
        .take(24)
        .collect::<Vec<_>>()
        .join("\n");
    claim!(
        reg_block.contains("repair_margin()"),
        "the per-object scan does not ask each manifest for its margin."
    );

    // 3. Unrecoverable objects are surfaced separately.
    claim!(
        actor.contains("unrecoverable_objects"),
        "the sweep does not surface unrecoverable objects.\n  Without a separate unrecoverable class, a shard that has fallen below the\n  code's loss tolerance is treated as repairable until repair simply fails."
    );

    // 4. Expiry opens a reallocation ticket.
    claim!(
        blockchain.contains("open_expiry_reallocation"),
        "expiring a deal does not open a reallocation ticket.\n  The slash path opens one. Without this, an operator that serves its whole\n  term and leaves drops a shard with nothing arranged to replace it."
    );
    claim!(
        registry.contains("fn open_expiry_reallocation"),
        "StorageRegistry::open_expiry_reallocation is gone."
    );
    claim!(
        registry.contains("fn renew_deal"),
        "StorageRegistry::renew_deal is gone.\n  Renewal is what makes the expiry ticket cheap: an incumbent still holding\n  the bytes extends for no transfer, a replacement moves a whole shard."
    );

    Ok(String::from("Repair-fires gate OK: sweep reads the band, margin scales with the scheme, unrecoverable is separate, expiry opens a ticket."))
}

/// # Errors
///
/// Returns a finding when a defect fixture passes.
pub fn self_test() -> Result<String, String> {
    // The canaries copy the real files and sed-break one claim at a time,
    // which needs the real tree. Reuse the real repo root: BUDLUM_ROOT or cwd.
    let root = std::env::var_os("BUDLUM_ROOT").map_or_else(
        || std::env::current_dir().unwrap_or_default(),
        std::path::PathBuf::from,
    );
    if !root.join("src/chain/chain_actor.rs").is_file() {
        return Err(String::from(
            "canary: real tree not found (run from the repo root)",
        ));
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let tmp = std::env::temp_dir().join(format!(
        "budlum-gates-repair-{}-{nanos}",
        std::process::id()
    ));
    for sub in ["src/chain", "src/domain", "src/storage"] {
        std::fs::create_dir_all(tmp.join(sub)).map_err(|e| e.to_string())?;
    }
    for (rel, from) in [
        ("src/chain/chain_actor.rs", "src/chain/chain_actor.rs"),
        ("src/chain/blockchain.rs", "src/chain/blockchain.rs"),
        ("src/domain/storage_deal.rs", "src/domain/storage_deal.rs"),
        ("src/storage/manifest.rs", "src/storage/manifest.rs"),
    ] {
        std::fs::copy(root.join(from), tmp.join(rel)).map_err(|e| e.to_string())?;
    }
    if run(&tmp).is_err() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from("canary: değiştirilmemiş kopya reddedildi"));
    }
    // Break one claim: remove the sweep's band read.
    let actor = tmp.join("src/chain/chain_actor.rs");
    let text = std::fs::read_to_string(&actor).map_err(|e| e.to_string())?;
    std::fs::write(
        &actor,
        text.replace("objects_below_own_repair_margin", "CANARY_REMOVED_scan"),
    )
    .map_err(|e| e.to_string())?;
    if run(&tmp).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: bağlantısız onarım tetikleyicisi geçti",
        ));
    }
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(String::from(
        "repair-fires kanaryası OK (temiz PASS, kırık tetikleyici FAIL).",
    ))
}
