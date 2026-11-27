//! Security regression tests for BNS grace-period overflow boundaries.

use budlum_core::bns::registry::BnsRegistry;
use budlum_core::bns::types::NameRecord;
use budlum_core::core::address::Address;

fn must<T, E: std::fmt::Debug>(res: Result<T, E>, ctx: &str) -> T {
    match res {
        Ok(v) => v,
        Err(e) => panic!("{ctx}: {e:?}"),
    }
}

#[test]
fn bns_registry_near_u64_max_grace_does_not_saturate_into_premature_reclaim() {
    let reg = BnsRegistry::new();
    let owner = Address([0x12; 32]);
    let mut rec = NameRecord::new("nearmax.bud".to_string(), owner, u64::MAX - 5);
    rec.address = Some(owner);

    let mut val = must(serde_json::to_value(&reg), "to_value");
    if let Some(names) = val.get_mut("names").and_then(|v| v.as_object_mut()) {
        names.insert(
            "nearmax.bud".to_string(),
            must(serde_json::to_value(&rec), "rec to_value"),
        );
    } else {
        panic!("could not locate names map in BnsRegistry JSON");
    }
    let mut restored: BnsRegistry = must(serde_json::from_value(val), "from_value");
    restored.rebuild_expiry_index();

    assert!(
        !restored.is_available_for_primary("nearmax.bud", u64::MAX),
        "name with expires_at = u64::MAX - 5 is still within GRACE_PERIOD at u64::MAX"
    );
    assert_eq!(
        restored.active_name_count_for_owner(&owner, u64::MAX),
        1,
        "name still in grace must remain counted for its owner at u64::MAX"
    );
}
