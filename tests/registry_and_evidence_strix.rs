use budlum_core::core::address::Address;
use budlum_core::registry::evidence::{
    DoubleSignKind, EvidenceError, SlashingProof, SlashingReport,
};
use budlum_core::registry::permissionless::{PermissionlessRegistry, RegistryError};
use budlum_core::registry::role::roles;

#[test]
fn permissionless_registry_refuses_zero_address_duplicate_deser_and_empty_double_sign_hashes() {
    let mut reg = PermissionlessRegistry::new();
    assert_eq!(
        reg.register(Address::zero(), roles::VALIDATOR, 10_000, 0),
        Err(RegistryError::ZeroAddress)
    );
    reg.upsert_stake(Address::zero(), roles::VALIDATOR, 10_000, 0);
    assert!(reg.get(&Address::zero(), roles::VALIDATOR).is_none());

    let member = Address::from([42u8; 32]);
    reg.register(member, roles::VALIDATOR, 10_000, 0).unwrap();
    let mut json: serde_json::Value = serde_json::to_value(&reg).unwrap();
    let first = json["registrations"][0].clone();
    json["registrations"].as_array_mut().unwrap().push(first);
    let dup: Result<PermissionlessRegistry, _> = serde_json::from_value(json);
    assert!(
        dup.is_err(),
        "duplicate (role, account) in serialized registrations must fail closed"
    );

    let empty_ds = SlashingReport::new(
        member,
        roles::VALIDATOR,
        SlashingProof::DoubleSign {
            kind: DoubleSignKind::BlockHeader,
            height: 12,
            epoch: None,
            block_hash_1: "0x".into(),
            block_hash_2: "0xdeadbeef".into(),
            signature_1: vec![1; 64],
            signature_2: vec![2; 64],
        },
        None,
    );
    assert_eq!(
        empty_ds.validate_shape(),
        Err(EvidenceError::NonConflictingHashes)
    );

    let blank_tag = SlashingReport::new(
        member,
        roles::VALIDATOR,
        SlashingProof::Other {
            tag: "   ".into(),
            data: vec![1],
        },
        None,
    );
    assert_eq!(
        blank_tag.validate_shape(),
        Err(EvidenceError::EmptyProofTag)
    );
}
