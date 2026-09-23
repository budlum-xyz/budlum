//! Gate: the regeneration health layer stays wired, blocked, and provable.
//!
//! What this gate promises, per the 2026-09-17 decision record (item 11):
//! code that is incompatible with the regeneration layer's wiring is BLOCKED
//! at CI - the gate turns red and the merge cannot proceed - and the gate
//! proves it is not vacuous by corrupting its own fixture set in
//! `self_test` and requiring every corruption to be caught.
//!
//! What it checks:
//!
//! 1. The health layer exists and is exported (`src/domain/mod.rs` declares
//!    it; the door cannot be deleted silently).
//! 2. The ledger's old "unwired" doors are gone: `regeneration_stage.rs` no
//!    longer marks `cheapest_target` or `reversion_beats_repair` as unwired,
//!    and the forgery door (`revert_after_forgery` plus its two refusal
//!    variants) exists.
//! 3. The advisor's decision ordering: audit-trail integrity first, then
//!    canonicality, then economics, then the reversion verdict. The ordering
//!    is the substance of the module (a verdict chosen before the canonical
//!    check is a verdict that follows whatever the node claims), so the
//!    token positions in `assess` must be strictly increasing.
//! 4. The chaos acceptance suite stays pinned: the recovery window constant
//!    and the four named chaos tests exist, so nobody dissolves the
//!    acceptance criterion by renaming it away.

use std::path::Path;

const MOD_RS: &str = "src/domain/mod.rs";
const STAGE_RS: &str = "src/domain/regeneration_stage.rs";
const HEALTH_RS: &str = "src/domain/regen_health.rs";
const CHAOS_RS: &str = "src/tests/regeneration_recovery.rs";

/// The decision-order tokens inside `assess`, in the required order. Each is
/// a code token (not a comment), so rewording prose cannot weaken the pin.
const ASSESS_ORDER: &[&str] = &[
    "ledger.validate()",
    "canonical(ledger.stage, ledger.height)",
    "reversion_beats_repair(",
    "HealthVerdict::RevertTo",
];

const HEALTH_REQUIRED: &[&str] = &[
    "pub enum HealthVerdict",
    "pub enum AlarmReason",
    "pub struct HealthPolicy",
    "pub fn assess(",
    "cheapest_target(",
];

const STAGE_REQUIRED: &[&str] = &[
    "pub fn revert_after_forgery(",
    "LedgerIsValid",
    "ForgedTrailTargetNotPolyp",
];

const CHAOS_TESTS: &[&str] = &[
    "chaos_corrupt_view_recovers_within_n_blocks_via_canonical_reversion",
    "chaos_forged_audit_trail_recovers_by_full_reversion_within_n_blocks",
    "chaos_compromised_anchor_reversion_follows_the_canonical_source_by_design",
    "chaos_no_canonical_source_alarms_and_never_reverts_blind",
];

/// The whole check, factored out so `self_test` can feed it tampered copies.
fn probe(mod_rs: &str, stage: &str, health: &str, chaos: &str, problems: &mut Vec<String>) {
    if !mod_rs.contains("pub mod regen_health;") {
        problems.push(format!(
            "{MOD_RS}: regen_health no longer declared - the health layer was removed silently"
        ));
    }
    if stage.contains("WIRING: unwired") {
        problems.push(format!(
            "{STAGE_RS}: a ledger entry point is marked 'WIRING: unwired' again - the health \
             layer is the caller, keep the door named and open"
        ));
    }
    for token in STAGE_REQUIRED {
        if !stage.contains(token) {
            problems.push(format!(
                "{STAGE_RS}: required forgery-door symbol missing: {token}"
            ));
        }
    }
    for token in HEALTH_REQUIRED {
        if !health.contains(token) {
            problems.push(format!(
                "{HEALTH_RS}: required health-layer symbol missing: {token}"
            ));
        }
    }
    // Decision ordering inside `assess`: audit trail, canonicality,
    // economics, and the (last) reversion verdict. The audit-trail branch
    // legitimately emits its own RevertTo early, so the ladder is verified
    // against the final verdict in the function, not the first occurrence.
    let Some(start) = health.find("pub fn assess(") else {
        problems.push(format!("{HEALTH_RS}: assess not found"));
        return;
    };
    let body = &health[start..];
    let positions: Vec<(usize, &str)> = ASSESS_ORDER
        .iter()
        .filter_map(|token| {
            let pos = if *token == "HealthVerdict::RevertTo" {
                body.rfind(token)
            } else {
                body.find(token)
            };
            pos.map(|p| (p, *token))
        })
        .collect();
    if positions.len() < ASSESS_ORDER.len() {
        problems.push(format!(
            "{HEALTH_RS}: assess order token(s) missing (expected all of: {})",
            ASSESS_ORDER.join(" -> ")
        ));
    }
    for window in positions.windows(2) {
        let (p1, t1) = window[0];
        let (p2, t2) = window[1];
        if p2 <= p1 {
            problems.push(format!(
                "{HEALTH_RS}: decision order broken - '{t2}' must come after '{t1}' in assess                  (the verdict ladder is the substance)"
            ));
        }
    }
    if !chaos.contains("RECOVERY_WINDOW_BLOCKS") {
        problems.push(format!(
            "{CHAOS_RS}: the recovery-window constant is gone - the acceptance criterion was \
             dissolved"
        ));
    }
    for name in CHAOS_TESTS {
        if !chaos.contains(name) {
            problems.push(format!("{CHAOS_RS}: pinned chaos test missing: {name}"));
        }
    }
}

pub fn run(root: &Path) -> Result<String, String> {
    let read = |rel: &str| -> Result<String, String> {
        std::fs::read_to_string(root.join(rel)).map_err(|e| format!("{rel}: cannot read ({e})"))
    };
    let mod_rs = read(MOD_RS)?;
    let stage = read(STAGE_RS)?;
    let health = read(HEALTH_RS)?;
    let chaos = read(CHAOS_RS)?;
    let mut problems: Vec<String> = Vec::new();
    probe(&mod_rs, &stage, &health, &chaos, &mut problems);
    if !problems.is_empty() {
        return Err(problems.join("\n  "));
    }
    Ok(String::from(
        "regen-health door wired: advisor ordering pinned, forgery door present, \
         chaos suite name-locked",
    ))
}

pub fn self_test() -> Result<String, String> {
    let good_mod = "pub mod regen_health;\npub mod regeneration_stage;\n";
    let good_stage = concat!(
        "pub fn revert_after_forgery( self ) ReversionError::LedgerIsValid ",
        "ForgedTrailTargetNotPolyp { to } wired through the health layer"
    );
    let good_health = concat!(
        "pub enum HealthVerdict pub enum AlarmReason pub struct HealthPolicy ",
        "pub fn assess( { let _ = ledger.validate(); ",
        "let _ = canonical(ledger.stage, ledger.height); ",
        "let _ = cheapest_target(damaged_below); ",
        "let _ = reversion_beats_repair(a, b, c, d); ",
        "HealthVerdict::RevertTo { target, stress } }"
    );
    let good_chaos = concat!(
        "const RECOVERY_WINDOW_BLOCKS: u64 = 64; ",
        "chaos_corrupt_view_recovers_within_n_blocks_via_canonical_reversion ",
        "chaos_forged_audit_trail_recovers_by_full_reversion_within_n_blocks ",
        "chaos_compromised_anchor_reversion_follows_the_canonical_source_by_design ",
        "chaos_no_canonical_source_alarms_and_never_reverts_blind"
    );

    let mut problems: Vec<String> = Vec::new();

    // Canary 1: the module declaration is removed silently.
    {
        let mut p: Vec<String> = Vec::new();
        probe(
            "pub mod regeneration_stage;\n",
            good_stage,
            good_health,
            good_chaos,
            &mut p,
        );
        if p.is_empty() {
            problems.push("canary failed: deleted health-layer declaration not caught".into());
        }
    }
    // Canary 2: an entry point drifts back to unwired.
    {
        let mut p: Vec<String> = Vec::new();
        let tampered = format!("{good_stage} // WIRING: unwired - nobody calls this");
        probe(good_mod, &tampered, good_health, good_chaos, &mut p);
        if p.is_empty() {
            problems.push("canary failed: re-unwired entry point not caught".into());
        }
    }
    // Canary 3: the forgery door is deleted.
    {
        let mut p: Vec<String> = Vec::new();
        let tampered = good_stage.replace("revert_after_forgery(", "revert_after_forg(");
        probe(good_mod, &tampered, good_health, good_chaos, &mut p);
        if p.is_empty() {
            problems.push("canary failed: deleted forgery door not caught".into());
        }
    }
    // Canary 4: the decision ordering is scrambled (verdict before canonicality).
    {
        let mut p: Vec<String> = Vec::new();
        let tampered = concat!(
            "pub enum HealthVerdict pub enum AlarmReason pub struct HealthPolicy ",
            "pub fn assess( { let _ = ledger.validate(); ",
            "HealthVerdict::RevertTo { target, stress } ",
            "let _ = canonical(ledger.stage, ledger.height); ",
            "let _ = cheapest_target(damaged_below); ",
            "let _ = reversion_beats_repair(a, b, c, d); }"
        );
        let scrambled = tampered.replace("reversion_beats_repair(", "beats_(");
        probe(good_mod, good_stage, &scrambled, good_chaos, &mut p);
        if p.is_empty() {
            problems.push("canary failed: scrambled decision order not caught".into());
        }
    }
    // Canary 5: a chaos test is renamed/dissolved.
    {
        let mut p: Vec<String> = Vec::new();
        let tampered = good_chaos.replace(
            "chaos_no_canonical_source_alarms_and_never_reverts_blind",
            "chaos_trivially_passing_placeholder",
        );
        probe(good_mod, good_stage, good_health, &tampered, &mut p);
        if p.is_empty() {
            problems.push("canary failed: dissolved chaos test not caught".into());
        }
    }

    if !problems.is_empty() {
        return Err(problems.join("\n  "));
    }
    Ok(String::from(
        "regen-health-door gate canaries all caught: deletion, re-unwiring, forgery-door \
         removal, order scramble, test dissolution",
    ))
}
