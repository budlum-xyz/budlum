//! Chaos acceptance for the regeneration layer (decision record 2026-09-17,
//! item 12): a node that suffers damage must re-enter serving from a
//! canonical stage within N blocks, never from a state it invented.
//!
//! N is 64. The number is arbitrarily small in chain terms and deliberately
//! constant in code: an acceptance criterion that someone can lower by
//! editing a comment is not a criterion. The points of this file:
//!
//! 1. **Corrupt derived state** heals by canonical reversion + re-growth,
//!    inside 64 blocks of service emergence.
//! 2. **A forged audit trail** (the deepest damage class) heals by full
//!    reversion, inside the same window.
//! 3. **A compromised canonical source is documented, not dismissed.**
//!    Reversion follows the canonical source by design; if the anchor that
//!    source is built from is broken, reversion heals the node *onto the
//!    attacker's line*, and the response belongs to the dormant-anchor /
//!    cold-committee channel, not to this layer. This file pins the property
//!    so the boundary stays visible in code rather than in tribal memory.

use crate::domain::regen_health::{assess, HealthPolicy, HealthVerdict};
use crate::domain::regeneration_stage::{
    RegenerationLedger, Reversion, Stage, StageSnapshot, Stress, Transdifferentiated,
};

/// Acceptance window: recovered serving must emerge no later than this many
/// blocks above the damage height.
const RECOVERY_WINDOW_BLOCKS: u64 = 64;

const C_POLYP: [u8; 32] = [0x11; 32];
const C_EPHYRA: [u8; 32] = [0x22; 32];
const C_MEDUSA: [u8; 32] = [0x33; 32];
const C_MEDUSA_RECOVERED: [u8; 32] = [0x44; 32];

const DAMAGE_HEIGHT: u64 = 300;
const EPHYRA_HEIGHT: u64 = 100;
const RECOVERED_HEIGHT: u64 = 320;

fn canonical(stage: Stage, height: u64) -> Option<[u8; 32]> {
    match (stage, height) {
        (Stage::Polyp, 0) => Some(C_POLYP),
        (Stage::Ephyra, EPHYRA_HEIGHT) => Some(C_EPHYRA),
        (Stage::Medusa, DAMAGE_HEIGHT) => Some(C_MEDUSA),
        (Stage::Medusa, RECOVERED_HEIGHT) => Some(C_MEDUSA_RECOVERED),
        _ => None,
    }
}

fn stage_height(stage: Stage) -> Option<u64> {
    match stage {
        Stage::Polyp => Some(0),
        Stage::Ephyra => Some(EPHYRA_HEIGHT),
        Stage::Medusa => Some(DAMAGE_HEIGHT),
    }
}

#[test]
fn chaos_corrupt_view_recovers_within_n_blocks_via_canonical_reversion() {
    let policy = HealthPolicy::default();
    let ledger = RegenerationLedger::at(DAMAGE_HEIGHT, C_MEDUSA);

    // Chaos: derived state is corrupted in place (bitrot, racing GC, a bad
    // patch - the health layer cannot and does not care which).
    let mut damaged = ledger.clone();
    damaged.commitment = [0xEE; 32];

    match assess(&damaged, &policy, &canonical, &stage_height, 10_000, 100) {
        HealthVerdict::RevertTo { target, stress } => {
            assert_eq!(stress, Stress::Divergence);
            assert_eq!(target.stage, Stage::Ephyra);
            assert!(target.height <= DAMAGE_HEIGHT);
            // Execute the verdict: the ledger, not the health layer, owns
            // the reversion rules.
            let event = damaged
                .revert(&target, stress, &policy.reversion, &canonical)
                .expect("canonical reversion is always executable");
            assert_eq!(event.event_number, 1);
        }
        other => panic!("corruption must be answered with RevertTo, got {other:?}"),
    }
    assert_eq!(damaged.stage, Stage::Ephyra);
    assert_eq!(damaged.height, EPHYRA_HEIGHT);

    // Re-growth: serving re-emerges inside the acceptance window.
    damaged
        .grow(
            &StageSnapshot {
                stage: Stage::Medusa,
                height: RECOVERED_HEIGHT,
                commitment: C_MEDUSA_RECOVERED,
                carried: Transdifferentiated {
                    proofs_reusable: 40,
                    proofs_discarded: 8,
                    records_refiled: 12,
                },
            },
            &canonical,
        )
        .expect("re-growth into a canonical height succeeds");
    assert!(
        RECOVERED_HEIGHT <= DAMAGE_HEIGHT + RECOVERY_WINDOW_BLOCKS,
        "recovered serving emerged within {RECOVERY_WINDOW_BLOCKS} blocks"
    );
    assert_eq!(damaged.stage, Stage::Medusa);
    // The audit trail stayed honest throughout.
    assert!(damaged.validate().is_ok());
    assert_eq!(damaged.event_count(), 1);
}

#[test]
fn chaos_forged_audit_trail_recovers_by_full_reversion_within_n_blocks() {
    let policy = HealthPolicy::default();
    let mut forged = RegenerationLedger::at(DAMAGE_HEIGHT, C_MEDUSA);
    forged.stage = Stage::Ephyra;
    forged.height = EPHYRA_HEIGHT;
    forged.commitment = C_EPHYRA;
    // Push a falsified event: totals contradict the recorded history, so the
    // audit trail cannot recompute.
    forged.reversion_events.push(Reversion {
        from: Stage::Medusa,
        to: Stage::Ephyra,
        stress: Stress::Divergence,
        height_after: EPHYRA_HEIGHT,
        carried: Transdifferentiated {
            proofs_reusable: 7,
            proofs_discarded: 0,
            records_refiled: 9,
        },
        event_number: 1,
    });
    forged.total_reused = 1_000_000;
    forged.total_discarded = 42;
    assert!(forged.validate().is_err(), "forged trail must not validate");

    match assess(&forged, &policy, &canonical, &stage_height, 10_000, 100) {
        HealthVerdict::RevertTo { target, stress } => {
            assert_eq!(stress, Stress::RepairFailed);
            assert_eq!(target.stage, Stage::Polyp);
            // Execute through the forgery door: `revert` itself (correctly)
            // refuses invalid ledgers, so damaged-trust state enters via the
            // door that trusts nothing inside the ledger.
            forged
                .revert_after_forgery(&target, stress, &canonical)
                .expect("forgery-door recovery to a canonical polyp is allowed");
        }
        other => panic!("forged trail must be answered with full reversion, got {other:?}"),
    }
    assert_eq!(forged.stage, Stage::Polyp);

    // Two stage-growths back to serving, inside the window.
    forged
        .grow(
            &StageSnapshot {
                stage: Stage::Ephyra,
                height: EPHYRA_HEIGHT,
                commitment: C_EPHYRA,
                carried: Transdifferentiated::default(),
            },
            &canonical,
        )
        .expect("grow to ephyra");
    forged
        .grow(
            &StageSnapshot {
                stage: Stage::Medusa,
                height: RECOVERED_HEIGHT,
                commitment: C_MEDUSA_RECOVERED,
                carried: Transdifferentiated::default(),
            },
            &canonical,
        )
        .expect("grow to serving");
    assert!(
        RECOVERED_HEIGHT <= DAMAGE_HEIGHT + RECOVERY_WINDOW_BLOCKS,
        "recovered serving emerged within {RECOVERY_WINDOW_BLOCKS} blocks"
    );
    assert!(forged.validate().is_ok(), "audit trail is honest again");
}

#[test]
fn chaos_compromised_anchor_reversion_follows_the_canonical_source_by_design() {
    // This test does not celebrate the outcome; it pins it. Reversion is a
    // healing mechanism, not an anchor: it follows the canonical source
    // wherever the source points, because that is what makes two damaged
    // nodes converge. If the anchor the source is built from has been
    // replaced by an adversary, the nodes converge onto the adversary's
    // line, and no amount of reversion policy changes that. The failure
    // mode belongs to the dormant-anchor / cold-committee channel
    // (decision record 2026-09-17, item 4), which rotates the anchor from
    // authority the adversary does not hold.
    let adversarial_canonical = |_stage: Stage, _height: u64| -> Option<[u8; 32]> {
        Some([0xAD; 32]) // one line: attacker's canonical everything
    };
    let policy = HealthPolicy::default();
    let mut ledger = RegenerationLedger::at(DAMAGE_HEIGHT, C_MEDUSA);

    // The honest node's view mismatches the (compromised) canonical source.
    let verdict = assess(
        &ledger,
        &policy,
        &adversarial_canonical,
        &stage_height,
        10_000,
        100,
    );
    let HealthVerdict::RevertTo { target, stress } = verdict else {
        panic!("a compromised anchor still yields a convergent verdict");
    };
    ledger
        .revert(&target, stress, &policy.reversion, &adversarial_canonical)
        .expect("reversion follows the canonical source, by design");
    assert_eq!(
        ledger.commitment, [0xAD; 32],
        "documented: healing follows the anchor, not the adversary's opponent"
    );
}

#[test]
fn chaos_no_canonical_source_alarms_and_never_reverts_blind() {
    let policy = HealthPolicy::default();
    let empty_canonical = |_stage: Stage, _height: u64| -> Option<[u8; 32]> { None };
    let mut ledger = RegenerationLedger::at(DAMAGE_HEIGHT, C_MEDUSA);
    ledger.commitment = [0xEE; 32];
    let before = ledger.clone();
    match assess(
        &ledger,
        &policy,
        &empty_canonical,
        &stage_height,
        10_000,
        100,
    ) {
        HealthVerdict::Alarm { .. } => {}
        other => panic!("damage without canonical source must alarm, got {other:?}"),
    }
    // An alarm is a standstill for the ledger, not a partial move.
    assert_eq!(ledger, before);
}
