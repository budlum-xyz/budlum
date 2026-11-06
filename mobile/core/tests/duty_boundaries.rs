//! Admission and custody regressions for the mobile duty engine.

use budlum_mobile_core::custody::symbol_leaf;
use budlum_mobile_core::{
    AssignedShare, Audit, CoreError, DutyTx, LastAudit, MobileCore, Policy, ShareStore,
    ValidatorClass, FREE_SPACE_FLOOR_BYTES, QUOTA_MIN_BYTES,
};

fn assigned(object: u8, value: u8) -> AssignedShare {
    let symbol = vec![value; 64];
    AssignedShare {
        object: [object; 32],
        segment: 0,
        esi: 7,
        position: 0,
        placed: vec![(7, symbol_leaf(&symbol))],
        symbol,
    }
}

fn core(available: u64) -> MobileCore {
    MobileCore::new([9; 32], ValidatorClass::Mobile, Vec::new(), available)
}

fn refusal<T: std::fmt::Debug>(result: Result<T, CoreError>) -> CoreError {
    match result {
        Err(error) => error,
        Ok(value) => panic!("expected a refusal, got {value:?}"),
    }
}

#[test]
fn mobile_assignment_position_must_name_its_esi_and_leaf() {
    for position in [1, u64::MAX] {
        let mut share = assigned(1, 10);
        share.position = position;
        let mut store = ShareStore::new();
        refusal(store.accept(share, QUOTA_MIN_BYTES));
        assert!(store.is_empty());
        assert_eq!(store.stored_bytes(), 0);
    }

    let mut share = assigned(1, 10);
    share.placed.insert(0, (6, symbol_leaf(&[20; 64])));
    let mut store = ShareStore::new();
    refusal(store.accept(share, QUOTA_MIN_BYTES));
    assert!(store.is_empty());
}

#[test]
fn mobile_assignment_requires_strict_esi_order() {
    for esis in [[7, 7], [7, 6]] {
        let mut share = assigned(1, 10);
        share.placed = esis
            .into_iter()
            .map(|esi| (esi, symbol_leaf(&share.symbol)))
            .collect();
        let mut store = ShareStore::new();
        refusal(store.accept(share, QUOTA_MIN_BYTES));
        assert!(store.is_empty());
    }
}

#[test]
fn mobile_assignment_replay_does_not_consume_quota() -> Result<(), Box<dyn std::error::Error>> {
    let share = assigned(1, 10);
    let mut store = ShareStore::new();
    let first = store.accept(share.clone(), QUOTA_MIN_BYTES)?;
    let before = store.stored_bytes();
    refusal(store.accept(share, QUOTA_MIN_BYTES));
    assert_eq!(store.len(), 1);
    assert_eq!(store.stored_bytes(), before);
    assert_eq!(store.get(first.id), Some(&first));
    Ok(())
}

#[test]
fn mobile_accept_preserves_free_space_floor() {
    let mut core = core(FREE_SPACE_FLOOR_BYTES + 63);
    let before = core.status();
    let available = core.available_bytes();
    let error = refusal(core.accept_share(assigned(1, 10)));
    assert_eq!(error.code, "mobile_free_space_floor");
    assert_eq!(core.status(), before);
    assert_eq!(core.available_bytes(), available);
    assert!(core.drain_duties().is_empty());
}

#[test]
fn mobile_failed_admission_does_not_release_existing_shares(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut core = core(FREE_SPACE_FLOOR_BYTES + 128);
    core.accept_share(assigned(1, 10))?;
    core.set_available_bytes(FREE_SPACE_FLOOR_BYTES - 1);
    core.drain_duties();
    let before = core.status();
    let available = core.available_bytes();
    let mut bad = assigned(2, 20);
    bad.placed.clear();
    refusal(core.accept_share(bad));
    assert_eq!(core.status(), before);
    assert_eq!(core.available_bytes(), available);
    assert!(core.drain_duties().is_empty());
    Ok(())
}

#[test]
fn mobile_floor_release_keeps_a_valid_user_quota() -> Result<(), Box<dyn std::error::Error>> {
    let mut core = core(FREE_SPACE_FLOOR_BYTES + 64);
    core.accept_share(assigned(1, 10))?;
    core.set_available_bytes(FREE_SPACE_FLOOR_BYTES - 1);
    assert!(matches!(
        core.drain_duties().as_slice(),
        [DutyTx::ReleaseShares { .. }]
    ));
    assert_eq!(core.status().stored_bytes, 0);
    assert!(core.available_bytes() >= FREE_SPACE_FLOOR_BYTES);
    assert!(Policy::with_quota(core.policy().quota_bytes).is_ok());
    Ok(())
}

#[test]
fn mobile_unknown_object_audit_does_not_fall_back_to_another_object(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut core = core(FREE_SPACE_FLOOR_BYTES + 128);
    core.accept_share(assigned(1, 10))?;
    core.accept_share(assigned(2, 20))?;
    let error = refusal(core.answer_audit(
        [3; 32],
        Audit {
            segment: 0,
            position: 0,
            sub_block: 0,
        },
    ));
    assert_eq!(error.code, "mobile_audit_unknown_share");
    assert_eq!(core.status().last_audit, LastAudit::Missed);
    Ok(())
}

#[test]
fn mobile_proof_duty_keeps_the_object_identity() -> Result<(), Box<dyn std::error::Error>> {
    let mut core = core(FREE_SPACE_FLOOR_BYTES + 128);
    core.accept_share(assigned(1, 10))?;
    core.accept_share(assigned(2, 10))?;
    let audit = Audit {
        segment: 0,
        position: 0,
        sub_block: 0,
    };
    let first = core.answer_audit([1; 32], audit)?;
    let second = core.answer_audit([2; 32], audit)?;
    assert_ne!(first, second, "the host must know which object to submit");
    Ok(())
}

#[test]
fn mobile_core_replay_refusal_preserves_space_and_pending_duties(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut core = core(FREE_SPACE_FLOOR_BYTES + 128);
    let share = assigned(1, 10);
    core.accept_share(share.clone())?;
    let before = core.status();
    let available = core.available_bytes();
    assert_eq!(
        refusal(core.accept_share(share)).code,
        "mobile_share_already_stored"
    );
    assert_eq!(core.status(), before);
    assert_eq!(core.available_bytes(), available);
    assert!(core.drain_duties().is_empty());
    Ok(())
}

#[test]
fn mobile_conflicting_position_or_esi_does_not_replace_a_share(
) -> Result<(), Box<dyn std::error::Error>> {
    for same_esi in [false, true] {
        let first = assigned(1, 10);
        let mut conflicting = assigned(1, 20);
        if same_esi {
            conflicting.position = 1;
            conflicting.placed.insert(0, (6, symbol_leaf(&[30; 64])));
        } else {
            conflicting.esi = 8;
            conflicting.placed = vec![(8, symbol_leaf(&conflicting.symbol))];
        }
        let mut store = ShareStore::new();
        let original = store.accept(first, QUOTA_MIN_BYTES)?;
        assert_eq!(
            refusal(store.accept(conflicting, QUOTA_MIN_BYTES)).code,
            "mobile_share_already_stored"
        );
        assert_eq!(store.len(), 1);
        assert_eq!(store.get(original.id), Some(&original));
    }
    Ok(())
}

#[test]
fn mobile_distinct_symbols_of_one_segment_remain_usable() -> Result<(), Box<dyn std::error::Error>>
{
    let mut first = assigned(1, 10);
    let mut second = assigned(1, 20);
    second.esi = 8;
    second.position = 1;
    let placed = vec![
        (7, symbol_leaf(&first.symbol)),
        (8, symbol_leaf(&second.symbol)),
    ];
    first.placed = placed.clone();
    second.placed = placed;
    let mut core = core(FREE_SPACE_FLOOR_BYTES + 128);
    core.accept_share(first)?;
    core.accept_share(second)?;
    assert_eq!(core.status().stored_bytes, 128);
    for position in [0, 1] {
        assert!(matches!(
            core.answer_audit(
                [1; 32],
                Audit {
                    segment: 0,
                    position,
                    sub_block: 0
                }
            )?,
            DutyTx::CustodyProofBatch(_)
        ));
    }
    Ok(())
}

#[test]
fn presence_preimage_matches_shared_golden_vector() {
    use budlum_mobile_core::presence::{presence_message, presence_preimage};
    use sha3::{Digest, Sha3_256};

    const EXPECTED: &[u8; 32] = include_bytes!("../../../tests/vectors/presence/v1/digest.bin");
    const PREIMAGE: &[u8; 65] = include_bytes!("../../../tests/vectors/presence/v1/preimage.bin");
    assert_eq!(Sha3_256::digest(PREIMAGE).as_slice(), EXPECTED);
    assert_eq!(
        presence_preimage(45_261, 11, ValidatorClass::Mobile),
        *PREIMAGE
    );
    assert_eq!(
        presence_message(45_261, 11, ValidatorClass::Mobile),
        *EXPECTED
    );
    assert_ne!(
        presence_message(45_261, 11, ValidatorClass::Full),
        *EXPECTED
    );
    assert_ne!(
        presence_message(45_261, 12, ValidatorClass::Mobile),
        *EXPECTED
    );
    assert_ne!(presence_message(1, 11, ValidatorClass::Mobile), *EXPECTED);
}
