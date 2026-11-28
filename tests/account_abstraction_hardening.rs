//! Regression tests for post-quantum private transfer authorization zero-value
//! refusals and threshold multisig pre-crypto cardinality / zero-owner guards.

use std::collections::BTreeSet;

use budlum_core::account_abstraction::private_transfer_auth::{
    transfer_commitment, PrivateTransferAuth, PrivateTransferError,
};
use budlum_core::account_abstraction::threshold_mldsa::{
    MultisigPolicy, OwnerSignature, ThresholdError,
};
use budlum_core::crypto::primitives::{ML_DSA_87_PUBLIC_KEY_LEN, ML_DSA_87_SIGNATURE_LEN};

#[test]
fn private_transfer_refuses_zero_nullifier_and_zero_blinding() {
    let auth_zero_nullifier = PrivateTransferAuth {
        authorization_sig: [0x11; ML_DSA_87_SIGNATURE_LEN],
        spender_key: [0x22; ML_DSA_87_PUBLIC_KEY_LEN],
        nullifier: [0u8; 32],
        commitment: transfer_commitment(&[0u8; 32], 500, &[0xAB; 32]),
        amount: 500,
    };
    let spent = BTreeSet::new();
    assert!(
        auth_zero_nullifier.verify_nullifier(&spent).is_err(),
        "all-zero nullifier must be refused"
    );

    let zero_blinding = [0u8; 32];
    let nonzero_nullifier = [0x33; 32];
    let auth_zero_blinding = PrivateTransferAuth {
        authorization_sig: [0x11; ML_DSA_87_SIGNATURE_LEN],
        spender_key: [0x22; ML_DSA_87_PUBLIC_KEY_LEN],
        nullifier: nonzero_nullifier,
        commitment: transfer_commitment(&nonzero_nullifier, 500, &zero_blinding),
        amount: 500,
    };
    assert_eq!(
        auth_zero_blinding.verify_commitment(&zero_blinding),
        Err(PrivateTransferError::CommitmentMismatch),
        "all-zero blinding factor destroys amount hiding and must be refused"
    );
}

#[test]
fn threshold_multisig_refuses_zero_owner_and_checks_cardinality_before_ml_dsa_crypto() {
    // 1. All-zero ML-DSA-87 owner public key must be refused at policy construction.
    assert!(
        MultisigPolicy::new(vec![[0u8; ML_DSA_87_PUBLIC_KEY_LEN]], 1).is_err(),
        "all-zero ML-DSA-87 owner public key must be refused"
    );

    // 2. Sub-threshold signature list carrying unverified bytes must return
    //    ThresholdNotMet BEFORE running expensive dual-library ML-DSA-87 verification!
    let pk1 = [0x41; ML_DSA_87_PUBLIC_KEY_LEN];
    let pk2 = [0x42; ML_DSA_87_PUBLIC_KEY_LEN];
    let pk3 = [0x43; ML_DSA_87_PUBLIC_KEY_LEN];
    let policy = MultisigPolicy::new(vec![pk1, pk2, pk3], 2).expect("valid 2-of-3 policy");

    let one_garbage_sig = [OwnerSignature {
        public_key: pk1,
        signature: [0xEE; ML_DSA_87_SIGNATURE_LEN],
    }];
    assert_eq!(
        policy.verify(b"authorize", &one_garbage_sig),
        Err(ThresholdError::ThresholdNotMet {
            valid: 1,
            threshold: 2,
        }),
        "1 signature for a 2-of-3 policy must fail ThresholdNotMet before ML-DSA verification"
    );
}
