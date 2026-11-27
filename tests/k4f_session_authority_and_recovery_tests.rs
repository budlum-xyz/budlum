use budlum_core::account_abstraction::{
    recovery_approval_digest, recovery_cancel_digest, session_revoke_digest, session_spend_digest,
    AccountAbstractionError, FeeSponsorAuthorization, FeeSponsorRegistry, FeeSponsorTerms,
    GuardianRecoveryApproval, QuantumAccountRegistry, SessionDelegation, SessionDelegationParams,
    SessionDelegationRegistry, SessionKeyPosture, SessionSpendRequest, SocialRecoveryPolicy,
    TimelockedRecoveryRegistry, FEE_SPONSOR_DOMAIN_TAG, MAX_CLASSICAL_HARDWARE_SESSION_CAP,
    MAX_CONSUMED_GRANTS, MAX_GUARDIANS, RECOVERY_APPROVAL_DOMAIN_TAG, RECOVERY_CANCEL_DOMAIN_TAG,
    SESSION_REVOKE_DOMAIN_TAG, SESSION_SPEND_DOMAIN_TAG,
};
use budlum_core::core::address::Address;
use budlum_core::crypto::composite::CompositeKeypair;
use budlum_core::crypto::pq::ML_DSA_SEED_LEN;
use budlum_core::crypto::scheme::SuiteId;

fn must<T, E: std::fmt::Debug>(res: Result<T, E>, msg: &str) -> T {
    match res {
        Ok(v) => v,
        Err(e) => panic!("{msg}: {e:?}"),
    }
}

fn sign_secp_65(secret: &[u8; 32], digest: &[u8; 32]) -> ([u8; 20], Vec<u8>) {
    use k256::ecdsa::SigningKey;
    use sha3::{Digest, Keccak256};

    let sk = must(SigningKey::from_bytes(secret.into()), "secp256k1 sk");
    let (sig, rec_id) = sk.sign_prehash_recoverable(digest);
    let vk = sk.verifying_key().to_sec1_point(false);
    let vk_bytes = vk.as_bytes();
    let tail = vk_bytes.get(1..).unwrap_or(&[]);
    let hash: [u8; 32] = Keccak256::digest(tail).into();
    let mut addr = [0u8; 20];
    if let Some(last20) = hash.get(12..32) {
        addr.copy_from_slice(last20);
    }
    let mut sig65 = Vec::with_capacity(65);
    sig65.extend_from_slice(&sig.to_bytes());
    sig65.push(rec_id.to_byte().saturating_add(27));
    (addr, sig65)
}

#[test]
fn k4f_fee_sponsorship_binds_sender_pubkey_tx_hash_chain_and_capacity() {
    let sponsor_a = must(
        CompositeKeypair::from_seeds(SuiteId::VALIDATOR, &[0x31; ML_DSA_SEED_LEN], &[0x32; 32]),
        "sponsor A",
    );
    let sponsor_b = must(
        CompositeKeypair::from_seeds(SuiteId::VALIDATOR, &[0x33; ML_DSA_SEED_LEN], &[0x34; 32]),
        "sponsor B",
    );
    let sender = Address::from([0x41; 32]);
    let tx_hash = [0x51; 32];
    let other_tx = [0x52; 32];

    // Zero sender is rejected on both sign and verify.
    let zero_terms = FeeSponsorTerms {
        chain_id: 45_261,
        tx_hash,
        sender: Address::zero(),
        max_fee_bud: 5_000,
        expiry_epoch: 100,
        sponsor_nonce: 1,
    };
    assert_eq!(
        FeeSponsorAuthorization::sign(&sponsor_a, zero_terms, &[0x11; 32]),
        Err(AccountAbstractionError::InvalidSender)
    );

    let terms = FeeSponsorTerms {
        chain_id: 45_261,
        tx_hash,
        sender,
        max_fee_bud: 5_000,
        expiry_epoch: 100,
        sponsor_nonce: 1,
    };
    let grant_a = must(
        FeeSponsorAuthorization::sign(&sponsor_a, terms.clone(), &[0x11; 32]),
        "sign grant A",
    );
    let grant_b = must(
        FeeSponsorAuthorization::sign(&sponsor_b, terms, &[0x12; 32]),
        "sign grant B",
    );

    // Signing digest and grant id bind sponsor_pubkey so distinct sponsors never collide.
    assert_ne!(
        FeeSponsorAuthorization::signing_digest(
            &FeeSponsorTerms {
                chain_id: 45_261,
                tx_hash,
                sender,
                max_fee_bud: 5_000,
                expiry_epoch: 100,
                sponsor_nonce: 1,
            },
            &grant_a.sponsor_pubkey,
        ),
        FeeSponsorAuthorization::signing_digest(
            &FeeSponsorTerms {
                chain_id: 45_261,
                tx_hash,
                sender,
                max_fee_bud: 5_000,
                expiry_epoch: 100,
                sponsor_nonce: 1,
            },
            &grant_b.sponsor_pubkey,
        ),
    );

    // Tampering sender to zero in a decoded grant fails closed.
    let mut forged_zero = grant_a.clone();
    forged_zero.sender = Address::zero();
    assert_eq!(
        forged_zero.verify(45_261, &tx_hash, 1_000, 50),
        Err(AccountAbstractionError::InvalidSender)
    );

    // Stateless registry verification matches current epoch and rejects mismatch/expiry.
    let mut qa_reg = QuantumAccountRegistry::new();
    qa_reg.epoch = 50;
    assert!(qa_reg
        .verify_fee_sponsor(&grant_a, 45_261, &tx_hash, 1_000)
        .is_ok());
    assert_eq!(
        qa_reg.verify_fee_sponsor(&grant_a, 45_261, &other_tx, 1_000),
        Err(AccountAbstractionError::TxHashMismatch)
    );

    let mut reg = FeeSponsorRegistry::default();
    assert_eq!(
        reg.consume(&grant_a, 45_261, &other_tx, 1_000, 50),
        Err(AccountAbstractionError::TxHashMismatch)
    );
    assert_eq!(
        reg.consume(&grant_a, 45_261, &tx_hash, 5_001, 50),
        Err(AccountAbstractionError::FeeExceedsSponsoredCap {
            actual: 5_001,
            max: 5_000
        })
    );
    let id_a = must(
        reg.consume(&grant_a, 45_261, &tx_hash, 1_200, 50),
        "consume A",
    );
    let id_b = must(
        reg.consume(&grant_b, 45_261, &tx_hash, 1_200, 50),
        "consume B",
    );
    assert_ne!(id_a, id_b);
    assert!(reg.is_consumed(&id_a));
    assert_eq!(
        reg.consume(&grant_a, 45_261, &tx_hash, 1_200, 50),
        Err(AccountAbstractionError::SponsorAuthorizationAlreadyConsumed)
    );
    assert_eq!(MAX_CONSUMED_GRANTS, 65_536);
    assert_eq!(FEE_SPONSOR_DOMAIN_TAG, b"BDLM/FEE_SPONSOR/V1");
}

#[test]
fn k4f_session_delegation_supports_pq_and_capped_classical_keys_and_master_signed_revocation() {
    let master_kp = must(
        CompositeKeypair::from_seeds(SuiteId::VALIDATOR, &[0x61; ML_DSA_SEED_LEN], &[0x63; 32]),
        "master",
    );
    let pq_session_kp = must(
        CompositeKeypair::from_seeds(SuiteId::VALIDATOR, &[0x62; ML_DSA_SEED_LEN], &[0x64; 32]),
        "pq session",
    );
    let stranger_kp = must(
        CompositeKeypair::from_seeds(SuiteId::VALIDATOR, &[0x65; ML_DSA_SEED_LEN], &[0x66; 32]),
        "stranger",
    );
    let pq_session_pk = must(pq_session_kp.public_key(), "pq session pk").encode();
    let merchant = Address::from([0x71; 32]);
    let outsider = Address::from([0x72; 32]);

    // Undecodable PQ session pubkey is refused.
    assert_eq!(
        SessionDelegation::sign(
            &master_kp,
            SessionDelegationParams {
                chain_id: 45_261,
                session_key: SessionKeyPosture::PostQuantumComposite {
                    composite_pubkey: vec![0x99; 4],
                },
                total_spend_cap: 1_000,
                per_tx_cap: 500,
                allowed_recipients: vec![merchant],
                not_before_epoch: 10,
                expiry_epoch: 20,
                delegation_nonce: 1,
            },
            &[0x12; 32],
        ),
        Err(AccountAbstractionError::InvalidCompositeKey)
    );

    // Zero EVM hardware address or excessive classical cap is refused.
    assert_eq!(
        SessionDelegation::sign(
            &master_kp,
            SessionDelegationParams {
                chain_id: 45_261,
                session_key: SessionKeyPosture::HardwareClassicalCapped {
                    evm_address: [0u8; 20],
                },
                total_spend_cap: 1_000,
                per_tx_cap: 500,
                allowed_recipients: vec![merchant],
                not_before_epoch: 10,
                expiry_epoch: 20,
                delegation_nonce: 2,
            },
            &[0x12; 32],
        ),
        Err(AccountAbstractionError::InvalidClassicalKey)
    );
    assert!(matches!(
        SessionDelegation::sign(
            &master_kp,
            SessionDelegationParams {
                chain_id: 45_261,
                session_key: SessionKeyPosture::HardwareClassicalCapped {
                    evm_address: [0xAA; 20],
                },
                total_spend_cap: MAX_CLASSICAL_HARDWARE_SESSION_CAP + 1,
                per_tx_cap: 1_000,
                allowed_recipients: vec![merchant],
                not_before_epoch: 10,
                expiry_epoch: 20,
                delegation_nonce: 3,
            },
            &[0x12; 32],
        ),
        Err(AccountAbstractionError::ClassicalHardwareCapExceeded { .. })
    ));

    // Zero address in allowed_recipients is refused.
    assert_eq!(
        SessionDelegation::sign(
            &master_kp,
            SessionDelegationParams {
                chain_id: 45_261,
                session_key: SessionKeyPosture::PostQuantumComposite {
                    composite_pubkey: pq_session_pk.clone(),
                },
                total_spend_cap: 1_000,
                per_tx_cap: 500,
                allowed_recipients: vec![Address::zero()],
                not_before_epoch: 10,
                expiry_epoch: 20,
                delegation_nonce: 4,
            },
            &[0x12; 32],
        ),
        Err(AccountAbstractionError::RecipientNotAllowed)
    );

    let pq_del = must(
        SessionDelegation::sign(
            &master_kp,
            SessionDelegationParams {
                chain_id: 45_261,
                session_key: SessionKeyPosture::PostQuantumComposite {
                    composite_pubkey: pq_session_pk,
                },
                total_spend_cap: 1_000,
                per_tx_cap: 600,
                allowed_recipients: vec![merchant],
                not_before_epoch: 10,
                expiry_epoch: 20,
                delegation_nonce: 5,
            },
            &[0x13; 32],
        ),
        "pq delegation",
    );
    let qa_reg = QuantumAccountRegistry::new();
    assert!(qa_reg.verify_session_delegation(&pq_del, 45_261).is_ok());

    let mut sess_reg = SessionDelegationRegistry::default();
    let del_id = must(sess_reg.register(pq_del.clone(), 45_261), "register");
    // Duplicate delegation registration must fail closed.
    assert_eq!(
        sess_reg.register(pq_del, 45_261),
        Err(AccountAbstractionError::DuplicateSession)
    );

    let spend = SessionSpendRequest {
        delegation_id: del_id,
        chain_id: 45_261,
        recipient: merchant,
        amount: 600,
        spend_nonce: 1,
        current_epoch: 15,
    };
    let spend_digest = session_spend_digest(&del_id, 45_261, &merchant, 600, 1);
    let spend_sig = must(
        pq_session_kp.sign(SESSION_SPEND_DOMAIN_TAG, &spend_digest, &[0x14; 32]),
        "spend sig",
    )
    .encode();
    assert_eq!(sess_reg.authorize_spend(&spend, &spend_sig), Ok(400));

    // Disallowed recipient & remaining cap checks.
    assert_eq!(
        sess_reg.authorize_spend(
            &SessionSpendRequest {
                recipient: outsider,
                amount: 100,
                spend_nonce: 2,
                ..spend.clone()
            },
            &spend_sig,
        ),
        Err(AccountAbstractionError::RecipientNotAllowed)
    );
    assert_eq!(
        sess_reg.authorize_spend(
            &SessionSpendRequest {
                amount: 401,
                spend_nonce: 3,
                ..spend.clone()
            },
            &spend_sig,
        ),
        Err(AccountAbstractionError::AmountExceedsRemainingCap {
            amount: 401,
            remaining: 400
        })
    );

    // Hardware-capped classical secp256k1 session works cleanly within its ceiling.
    let hw_secret = [0x7Au8; 32];
    let hw_preview_digest = [0x01u8; 32];
    let (hw_addr, _) = sign_secp_65(&hw_secret, &hw_preview_digest);
    let hw_del = must(
        SessionDelegation::sign(
            &master_kp,
            SessionDelegationParams {
                chain_id: 45_261,
                session_key: SessionKeyPosture::HardwareClassicalCapped {
                    evm_address: hw_addr,
                },
                total_spend_cap: MAX_CLASSICAL_HARDWARE_SESSION_CAP,
                per_tx_cap: 5_000_000_000,
                allowed_recipients: vec![],
                not_before_epoch: 10,
                expiry_epoch: 30,
                delegation_nonce: 6,
            },
            &[0x15; 32],
        ),
        "hw delegation",
    );
    let hw_id = must(sess_reg.register(hw_del, 45_261), "register hw");
    let hw_spend_digest = session_spend_digest(&hw_id, 45_261, &merchant, 250_000, 1);
    let (_, hw_sig) = sign_secp_65(&hw_secret, &hw_spend_digest);
    assert_eq!(
        sess_reg.authorize_spend(
            &SessionSpendRequest {
                delegation_id: hw_id,
                chain_id: 45_261,
                recipient: merchant,
                amount: 250_000,
                spend_nonce: 1,
                current_epoch: 20,
            },
            &hw_sig,
        ),
        Ok(MAX_CLASSICAL_HARDWARE_SESSION_CAP - 250_000)
    );
    // Spend to zero address refused even with empty allowlist.
    assert_eq!(
        sess_reg.authorize_spend(
            &SessionSpendRequest {
                delegation_id: hw_id,
                chain_id: 45_261,
                recipient: Address::zero(),
                amount: 10,
                spend_nonce: 2,
                current_epoch: 20,
            },
            &hw_sig,
        ),
        Err(AccountAbstractionError::RecipientNotAllowed)
    );

    // Revocation requires master signature under SESSION_REVOKE_DOMAIN_TAG.
    let revoke_digest = session_revoke_digest(&del_id, 45_261);
    let bad_revoke = must(
        stranger_kp.sign(SESSION_REVOKE_DOMAIN_TAG, &revoke_digest, &[0x16; 32]),
        "stranger revoke sig",
    )
    .encode();
    assert_eq!(
        sess_reg.revoke(&del_id, &bad_revoke),
        Err(AccountAbstractionError::InvalidCompositeSignature)
    );
    let master_revoke = must(
        master_kp.sign(SESSION_REVOKE_DOMAIN_TAG, &revoke_digest, &[0x17; 32]),
        "master revoke sig",
    )
    .encode();
    must(sess_reg.revoke(&del_id, &master_revoke), "master revoke");
    assert_eq!(
        sess_reg.revoke(&del_id, &master_revoke),
        Err(AccountAbstractionError::SessionRevoked)
    );
    assert_eq!(
        sess_reg.authorize_spend(
            &SessionSpendRequest {
                amount: 100,
                spend_nonce: 9,
                ..spend
            },
            &spend_sig,
        ),
        Err(AccountAbstractionError::SessionRevoked)
    );
}

#[test]
fn k4f_timelocked_social_recovery_enforces_guardian_isolation_window_and_single_veto() {
    let owner_kp = must(
        CompositeKeypair::from_seeds(SuiteId::VALIDATOR, &[0x80; ML_DSA_SEED_LEN], &[0x90; 32]),
        "owner",
    );
    let g1 = must(
        CompositeKeypair::from_seeds(SuiteId::VALIDATOR, &[0x81; ML_DSA_SEED_LEN], &[0x91; 32]),
        "g1",
    );
    let g2 = must(
        CompositeKeypair::from_seeds(SuiteId::VALIDATOR, &[0x82; ML_DSA_SEED_LEN], &[0x92; 32]),
        "g2",
    );
    let new_owner = must(
        CompositeKeypair::from_seeds(SuiteId::VALIDATOR, &[0x83; ML_DSA_SEED_LEN], &[0x93; 32]),
        "new owner",
    );
    let owner_pk = must(owner_kp.public_key(), "owner pk").encode();
    let g1_pk = must(g1.public_key(), "g1 pk").encode();
    let g2_pk = must(g2.public_key(), "g2 pk").encode();
    let new_owner_pk = must(new_owner.public_key(), "new owner pk").encode();

    // Owner cannot appear in guardians list, and guardian list is bounded by MAX_GUARDIANS.
    assert_eq!(
        SocialRecoveryPolicy {
            chain_id: 45_261,
            current_owner_pubkey: owner_pk.clone(),
            guardians: vec![owner_pk.clone(), g1_pk.clone()],
            threshold: 1,
            delay_epochs: 5,
        }
        .validate(),
        Err(AccountAbstractionError::OwnerCannotBeGuardian)
    );
    assert_eq!(
        SocialRecoveryPolicy {
            chain_id: 45_261,
            current_owner_pubkey: owner_pk.clone(),
            guardians: vec![g1_pk.clone(); MAX_GUARDIANS + 1],
            threshold: 1,
            delay_epochs: 5,
        }
        .validate(),
        Err(AccountAbstractionError::InvalidGuardianPolicy)
    );

    let policy = SocialRecoveryPolicy {
        chain_id: 45_261,
        current_owner_pubkey: owner_pk.clone(),
        guardians: vec![g1_pk.clone(), g2_pk.clone()],
        threshold: 2,
        delay_epochs: 5,
    };
    let qa_reg = QuantumAccountRegistry::new();
    assert!(qa_reg.verify_recovery_policy(&policy).is_ok());

    let rec_digest = recovery_approval_digest(45_261, &owner_pk, &new_owner_pk, 1);
    let approvals = vec![
        GuardianRecoveryApproval {
            guardian_pubkey: g1_pk.clone(),
            signature: must(
                g1.sign(RECOVERY_APPROVAL_DOMAIN_TAG, &rec_digest, &[0x21; 32]),
                "g1",
            )
            .encode(),
        },
        GuardianRecoveryApproval {
            guardian_pubkey: g2_pk.clone(),
            signature: must(
                g2.sign(RECOVERY_APPROVAL_DOMAIN_TAG, &rec_digest, &[0x22; 32]),
                "g2",
            )
            .encode(),
        },
    ];

    let mut rec_reg = TimelockedRecoveryRegistry::default();
    // Unchanged proposed_new_owner_pubkey is rejected.
    assert_eq!(
        rec_reg.initiate(policy.clone(), owner_pk.clone(), 1, &approvals, 100),
        Err(AccountAbstractionError::UnchangedOwnerKey)
    );
    // Overflowing timelock arithmetic is rejected rather than silently saturating.
    assert_eq!(
        rec_reg.initiate(
            policy.clone(),
            new_owner_pk.clone(),
            1,
            &approvals,
            u64::MAX
        ),
        Err(AccountAbstractionError::ArithmeticOverflow)
    );

    let rec_id = must(
        rec_reg.initiate(policy.clone(), new_owner_pk.clone(), 1, &approvals, 100),
        "initiate",
    );
    // Duplicate recovery_id is rejected.
    assert_eq!(
        rec_reg.initiate(policy.clone(), new_owner_pk.clone(), 1, &approvals, 100),
        Err(AccountAbstractionError::DuplicateRecovery)
    );
    // Early finalization before timelock window fails closed.
    assert!(matches!(
        rec_reg.finalize(&rec_id, 104),
        Err(AccountAbstractionError::RecoveryWindowStillOpen { .. })
    ));

    // Owner veto cancels recovery permanently, and double-cancellation is rejected.
    let cancel_sig = must(
        owner_kp.sign(
            RECOVERY_CANCEL_DOMAIN_TAG,
            &recovery_cancel_digest(&rec_id, 45_261),
            &[0x23; 32],
        ),
        "cancel",
    )
    .encode();
    must(rec_reg.cancel_by_owner(&rec_id, &cancel_sig), "veto");
    assert_eq!(
        rec_reg.cancel_by_owner(&rec_id, &cancel_sig),
        Err(AccountAbstractionError::RecoveryCancelled)
    );
    assert_eq!(
        rec_reg.finalize(&rec_id, 200),
        Err(AccountAbstractionError::RecoveryCancelled)
    );

    // Uncancelled second recovery finalizes once timelock expires.
    let rec2_digest = recovery_approval_digest(45_261, &owner_pk, &new_owner_pk, 2);
    let approvals2 = vec![
        GuardianRecoveryApproval {
            guardian_pubkey: g1_pk,
            signature: must(
                g1.sign(RECOVERY_APPROVAL_DOMAIN_TAG, &rec2_digest, &[0x24; 32]),
                "g1 2",
            )
            .encode(),
        },
        GuardianRecoveryApproval {
            guardian_pubkey: g2_pk,
            signature: must(
                g2.sign(RECOVERY_APPROVAL_DOMAIN_TAG, &rec2_digest, &[0x25; 32]),
                "g2 2",
            )
            .encode(),
        },
    ];
    let rec2_id = must(
        rec_reg.initiate(policy, new_owner_pk.clone(), 2, &approvals2, 300),
        "initiate 2",
    );
    assert_eq!(rec_reg.finalize(&rec2_id, 305), Ok(new_owner_pk));
}
