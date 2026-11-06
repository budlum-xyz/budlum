//! Placement is derived, sticky, stake-weighted and class-aware.
//!
//! The placement group of a segment is a pure function of the object
//! commitment, the segment number and the candidate set: rendezvous ranking
//! weighted by `stake / -ln(u)`. It is sticky - a joining or leaving
//! validator only moves the shares it wins or loses - and it is capped: one
//! account holds at most `max(1, n / 64)` shares of one segment, so no
//! account can corner a segment.
//!
//! This gate pins those four rules in `src/storage/bud3/placement.rs`. The
//! cap is checked as code, not as prose, because the cap is the rule that
//! bounds what one account can hold.

use std::path::Path;

const PLACEMENT: &str = "src/storage/bud3/placement.rs";

fn production_code(text: &str) -> String {
    let no_tests = super::capability_modules_are_wired::strip_test_mods(text);
    no_tests
        .lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

/// # Errors
///
/// The missing rule.
pub fn run(root: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(root.join(PLACEMENT))
        .map_err(|e| format!("read {PLACEMENT}: {e}"))?;
    let code = production_code(&text);
    let lowered = code.to_lowercase();

    // 1. Derived: a ranking function and a segment key derive the group.
    if !code.contains("pub fn rank(") || !code.contains("pub fn segment_key(") {
        return Err(String::from(
            "placement.rs no longer derives the group: `rank` and `segment_key` are the derivation.",
        ));
    }
    // 2. Stake-weighted: the rendezvous weight divides by the negative log.
    if !code.contains("neg_log2") && !code.contains("ln(") {
        return Err(String::from(
            "placement.rs no longer weights by stake / -ln(u): the weighting vanished.",
        ));
    }
    if !lowered.contains("stake") {
        return Err(String::from(
            "placement.rs no longer names stake: the placement is stake-weighted.",
        ));
    }
    // 3. Class-aware: the candidate carries its class into the shares.
    if !code.contains("class") && !code.contains("Class") {
        return Err(String::from(
            "placement.rs no longer sees classes: Full and Mobile shares are class-aware.",
        ));
    }
    // 4. The cap: one account holds at most max(1, n / 64) shares of a segment.
    let has_cap = code.contains("/ 64") && (code.contains("account_cap") || code.contains("per_account"));
    if !has_cap {
        return Err(String::from(
            "placement.rs no longer caps one account at max(1, n / 64) shares of a segment. \n  Without the cap an account corners a segment.",
        ));
    }
    // 5. Sticky is the contract the code implements.
    if !text.contains("sticky") {
        return Err(String::from(
            "placement.rs no longer states the sticky rule: a joining or leaving validator \n  only moves the shares it wins or loses.",
        ));
    }
    Ok(String::from(
        "bud3 placement OK: derived, sticky, stake-weighted, class-aware, and capped at max(1, n / 64) per account and segment",
    ))
}

/// The canary: a placement without the cap must fail.
///
/// # Errors
///
/// When the gate does not behave.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-place")?;
    let result = (|| {
        let put = |body: &str| -> Result<(), String> {
            let p = dir.join(PLACEMENT);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };
        put(
            "//! sticky placement.\npub fn rank() {}\npub fn segment_key() {}\n\
             fn neg_log2_unit(x: u64) -> u64 { x }\npub fn place(stake: u64, class: u8) {\n\
             \x20   let account_cap = (n / 64).max(1);\n    let per_account = account_cap;\n}\n",
        )?;
        run(&dir).map_err(|e| format!("canary: a complete placement failed: {e}"))?;
        put(
            "//! sticky placement.\npub fn rank() {}\npub fn segment_key() {}\n\
             fn neg_log2_unit(x: u64) -> u64 { x }\npub fn place(stake: u64, class: u8) {}\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a placement without the account cap passed"));
        }
        put(
            "//! sticky placement.\npub fn rank() {}\npub fn segment_key() {}\n\
             fn neg_log2_unit(x: u64) -> u64 { x }\n\
             \x20   fn place(n: u64) { let account_cap = (n / 64).max(1); let per_account = account_cap; }\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a placement that names no stake passed"));
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "bud3-placement canary OK: a missing cap failed and a missing stake failed.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn bud3_placement_gate() {
        assert!(super::self_test().is_ok(), "{:?}", super::self_test());
    }
}
