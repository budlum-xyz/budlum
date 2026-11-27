use budlum_core::account_abstraction::private_transfer_auth::transfer_commitment;
use budlum_core::account_abstraction::{
    PrivateTransferAuth, PrivateTransferError, QuantumAccount, QuantumAccountRegistry,
    QuantumAccountRegistryError, RecoveryProposal,
};
use budlum_core::crypto::primitives::{ML_DSA_87_PUBLIC_KEY_LEN, ML_DSA_87_SIGNATURE_LEN};

fn sample_account(nonce: u64) -> QuantumAccount {
    let pk = [7u8; ML_DSA_87_PUBLIC_KEY_LEN];
    let guardians = vec![
        [1u8; ML_DSA_87_PUBLIC_KEY_LEN],
        [2u8; ML_DSA_87_PUBLIC_KEY_LEN],
        [3u8; ML_DSA_87_PUBLIC_KEY_LEN],
    ];
    QuantumAccount {
        address: QuantumAccount::address_from_public_key(&pk),
        pq_public_key: pk,
        storage_root: [0u8; 32],
        pact_root: [0u8; 32],
        guardian_root: QuantumAccount::guardian_root(&guardians),
        guardians,
        multisig_threshold: 2,
        recovery_threshold: 2,
        timelock_blocks: 10,
        nonce,
        balance: 500,
        storage_bytes: 0,
    }
}

#[test]
fn registry_snapshot_deserialize_rejects_unvalidated_or_unbound_accounts() {
    let mut registry = QuantumAccountRegistry::new();
    let acc = sample_account(3);
    let addr = acc.address;
    registry.register(acc).expect("valid registration");

    let mut raw: serde_json::Value =
        serde_json::to_value(&registry).expect("serialize valid registry");
    let addr_hex_or_key = raw["accounts"]
        .as_object()
        .and_then(|m| m.keys().next().cloned())
        .expect("serialized account map entry");

    // Corrupt multisig_threshold to 0 inside serialized snapshot: restore MUST reject.
    raw["accounts"][&addr_hex_or_key]["multisig_threshold"] = serde_json::json!(0);
    let corrupted_policy = serde_json::to_string(&raw).expect("encode corrupted snapshot");
    assert!(
        serde_json::from_str::<QuantumAccountRegistry>(&corrupted_policy).is_err(),
        "snapshot restore must enforce validate_all() on every restored account"
    );

    // Corrupt address field so map key != account.address / address_from_public_key: restore MUST reject.
    let mut raw2: serde_json::Value =
        serde_json::to_value(&registry).expect("serialize valid registry");
    let mut forged_addr = addr;
    forged_addr[0] ^= 0xFF;
    raw2["accounts"][&addr_hex_or_key]["address"] =
        serde_json::to_value(forged_addr).expect("encode forged address");
    let corrupted_binding = serde_json::to_string(&raw2).expect("encode unbound snapshot");
    assert!(
        serde_json::from_str::<QuantumAccountRegistry>(&corrupted_binding).is_err(),
        "snapshot restore must enforce map-key and public-key address binding"
    );
}

#[test]
fn registry_update_rejects_account_nonce_rollback() {
    let mut registry = QuantumAccountRegistry::new();
    let acc = sample_account(5);
    let addr = acc.address;
    registry.register(acc).expect("register account at nonce 5");

    let err = registry
        .update(&addr, |a| a.nonce = 4)
        .expect_err("rolling account nonce backwards must be refused");
    assert!(matches!(
        err,
        QuantumAccountRegistryError::InvalidAccount { .. }
    ));
    assert_eq!(registry.get(&addr).map(|a| a.nonce), Some(5));
}

#[test]
fn recovery_proposal_rejects_zero_chain_id() {
    let cur = [0x11u8; ML_DSA_87_PUBLIC_KEY_LEN];
    let nxt = [0x22u8; ML_DSA_87_PUBLIC_KEY_LEN];
    assert!(
        RecoveryProposal::new(cur, nxt, 100, 10, 0, 0).is_err(),
        "RecoveryProposal::new must reject chain_id == 0"
    );
}

#[test]
fn private_transfer_rejects_zero_blinding_and_zero_nullifier() {
    let zero_blinding = [0u8; 32];
    let nullifier = [0x55u8; 32];
    let unblinded = PrivateTransferAuth {
        authorization_sig: [1u8; ML_DSA_87_SIGNATURE_LEN],
        spender_key: [2u8; ML_DSA_87_PUBLIC_KEY_LEN],
        nullifier,
        commitment: transfer_commitment(&nullifier, 100, &zero_blinding),
        amount: 100,
    };
    assert_eq!(
        unblinded.verify_commitment(&zero_blinding),
        Err(PrivateTransferError::CommitmentMismatch),
        "all-zero blinding leaves small amounts dictionary-guessable and must fail"
    );

    let blinding = [0x99u8; 32];
    let zero_nullifier = [0u8; 32];
    let unset_nullifier = PrivateTransferAuth {
        authorization_sig: [1u8; ML_DSA_87_SIGNATURE_LEN],
        spender_key: [2u8; ML_DSA_87_PUBLIC_KEY_LEN],
        nullifier: zero_nullifier,
        commitment: transfer_commitment(&zero_nullifier, 100, &blinding),
        amount: 100,
    };
    assert_eq!(
        unset_nullifier.verify_commitment(&blinding),
        Err(PrivateTransferError::CommitmentMismatch),
        "all-zero nullifier sentinel must fail commitment verification"
    );
}

#[test]
fn valid_snapshot_restore_and_monotonic_nonce_update_succeed() {
    let mut registry = QuantumAccountRegistry::new();
    registry.set_epoch(9);
    let acc = sample_account(3);
    let addr = acc.address;
    registry.register(acc).expect("register valid account");
    registry
        .update(&addr, |a| a.nonce = 4)
        .expect("monotonic nonce increment succeeds");

    let encoded = serde_json::to_string(&registry).expect("serialize registry");
    let restored: QuantumAccountRegistry =
        serde_json::from_str(&encoded).expect("restore valid registry snapshot");
    assert_eq!(restored.epoch, 9);
    assert_eq!(restored.root(), registry.root());
    assert_eq!(restored.get(&addr).map(|a| a.nonce), Some(4));

    let cur = [0x11u8; ML_DSA_87_PUBLIC_KEY_LEN];
    let nxt = [0x22u8; ML_DSA_87_PUBLIC_KEY_LEN];
    let proposal = RecoveryProposal::new(cur, nxt, 100, 10, 45_262, 4).expect("valid chain_id");
    assert_eq!(proposal.chain_id, 45_262);
}

