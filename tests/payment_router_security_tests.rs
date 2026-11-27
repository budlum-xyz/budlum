//! End-to-end security tests for UniversalPaymentRouter, offline spend
//! vouchers, AssetEquivalenceClass, PaymentStatusReport, and canonical
//! payment request URIs.

use std::collections::BTreeSet;

use budlum_core::crypto::composite::CompositeKeypair;
use budlum_core::crypto::scheme::SuiteId;
use budlum_core::unification::payment_router::{
    AssetEquivalenceClass, AssetEquivalenceMember, DeliveredPaymentProof, DomainTokenBalance,
    FinalizedPaymentProof, GuaranteedPaymentProof, PaymentError, PaymentRail, PaymentStatusReport,
    PreauthorizedSpendAccount, SignedOfflineVoucher, UniversalPaymentIntent,
    UniversalPaymentRequestUri, UniversalPaymentRouter, OFFLINE_VOUCHER_CTX,
};

#[test]
fn payment_intent_rejects_zero_payer_merchant_and_target_asset() {
    let bal = DomainTokenBalance {
        domain_id: 1,
        asset_id: [0x11; 32],
        symbol: "BUD".into(),
        available_amount: 10_000,
    };

    let zero_payer = UniversalPaymentIntent {
        payer_id: [0u8; 32],
        merchant_id: [0xB2; 32],
        nonce: 1,
        target_domain: 1,
        target_asset_id: [0x11; 32],
        target_amount: 100,
        max_slippage_bps: 50,
        deadline_unix_secs: 2_000,
        invoice_hash: [0x33; 32],
        rail: PaymentRail::OnChain,
    };
    assert!(matches!(
        UniversalPaymentRouter::quote_payment(&zero_payer, std::slice::from_ref(&bal), &[], 1_000),
        Err(PaymentError::InvalidIntent(_))
    ));

    let zero_merchant = UniversalPaymentIntent {
        payer_id: [0xA1; 32],
        merchant_id: [0u8; 32],
        ..zero_payer.clone()
    };
    assert!(matches!(
        UniversalPaymentRouter::quote_payment(
            &zero_merchant,
            std::slice::from_ref(&bal),
            &[],
            1_000
        ),
        Err(PaymentError::InvalidIntent(_))
    ));

    let zero_asset_bal = DomainTokenBalance {
        domain_id: 1,
        asset_id: [0u8; 32],
        symbol: "BAD".into(),
        available_amount: 10_000,
    };
    let zero_asset = UniversalPaymentIntent {
        payer_id: [0xA1; 32],
        merchant_id: [0xB2; 32],
        target_asset_id: [0u8; 32],
        ..zero_payer
    };
    assert!(matches!(
        UniversalPaymentRouter::quote_payment(&zero_asset, &[zero_asset_bal], &[], 1_000),
        Err(PaymentError::InvalidIntent(_))
    ));
}

#[test]
fn offline_voucher_cannot_outlive_parent_account_or_use_zero_account_or_exceed_nonce_cap() {
    let kp = CompositeKeypair::from_seeds(SuiteId::USER, &[0x44; 32], &[0x55; 32])
        .expect("composite keypair");
    let pk_bytes = kp.public_key().expect("pk").encode();

    let mut account = PreauthorizedSpendAccount {
        account_id: [0xAA; 32],
        payer_composite_pubkey: pk_bytes.clone(),
        asset_id: [0xBB; 32],
        spend_cap_atoms: 1_000_000,
        spent_atoms: 0,
        valid_until_unix_secs: 5_000,
        used_nonces: BTreeSet::new(),
    };

    // Voucher whose valid_until_unix_secs outlives parent account MUST be refused fail-closed.
    let mut outliving = SignedOfflineVoucher {
        account_id: account.account_id,
        voucher_nonce: 1,
        merchant_id: [0xCC; 32],
        amount_atoms: 100,
        valid_until_unix_secs: 5_001,
        signature: Vec::new(),
    };
    let digest = outliving.signing_payload();
    outliving.signature = kp
        .sign(OFFLINE_VOUCHER_CTX, &digest, &[0x01; 32])
        .expect("sign")
        .encode();
    assert!(
        matches!(
            outliving.verify_offline(&account, 1_000),
            Err(PaymentError::InvalidIntent(_))
        ),
        "offline voucher must never outlive its parent pre-authorized spend account"
    );

    // Zero account_id or zero asset_id MUST be refused.
    let zero_acct = PreauthorizedSpendAccount {
        account_id: [0u8; 32],
        ..account.clone()
    };
    let mut zero_acct_voucher = SignedOfflineVoucher {
        account_id: [0u8; 32],
        voucher_nonce: 2,
        merchant_id: [0xCC; 32],
        amount_atoms: 100,
        valid_until_unix_secs: 4_000,
        signature: Vec::new(),
    };
    let z_digest = zero_acct_voucher.signing_payload();
    zero_acct_voucher.signature = kp
        .sign(OFFLINE_VOUCHER_CTX, &z_digest, &[0x02; 32])
        .expect("sign")
        .encode();
    assert!(matches!(
        zero_acct_voucher.verify_offline(&zero_acct, 1_000),
        Err(PaymentError::InvalidIntent(_))
    ));

    // Saturating used_nonces up to the hard replay ceiling MUST reject further batches atomically.
    for n in 0..65_536u64 {
        account.used_nonces.insert(n);
    }
    let mut valid_voucher = SignedOfflineVoucher {
        account_id: account.account_id,
        voucher_nonce: 99_999,
        merchant_id: [0xCC; 32],
        amount_atoms: 100,
        valid_until_unix_secs: 4_000,
        signature: Vec::new(),
    };
    let v_digest = valid_voucher.signing_payload();
    valid_voucher.signature = kp
        .sign(OFFLINE_VOUCHER_CTX, &v_digest, &[0x03; 32])
        .expect("sign")
        .encode();
    let err = account
        .settle_voucher_batch(&[valid_voucher], 1_000)
        .expect_err("used_nonces table past ceiling must fail closed");
    assert!(matches!(err, PaymentError::InputLimitExceeded));
    assert_eq!(account.spent_atoms, 0);
}

#[test]
fn equivalence_class_status_report_and_payment_uri_reject_zero_domain_and_zero_deadline() {
    // AssetEquivalenceClass MUST refuse domain_id == 0 and asset_id == 0.
    let zero_dom_member = AssetEquivalenceMember {
        domain_id: 0,
        asset_id: [0x11; 32],
        symbol: "USDC".into(),
        fee_bps: 10,
        available_liquidity: 1_000_000,
        provenance_proof_root: [0x99; 32],
        finality_proven: true,
    };
    assert!(matches!(
        AssetEquivalenceClass::new("USDC".into(), vec![zero_dom_member]),
        Err(PaymentError::InvalidIntent(_))
    ));

    let zero_asset_member = AssetEquivalenceMember {
        domain_id: 1,
        asset_id: [0u8; 32],
        symbol: "USDC".into(),
        fee_bps: 10,
        available_liquidity: 1_000_000,
        provenance_proof_root: [0x99; 32],
        finality_proven: true,
    };
    assert!(matches!(
        AssetEquivalenceClass::new("USDC".into(), vec![zero_asset_member]),
        Err(PaymentError::InvalidIntent(_))
    ));

    // PaymentStatusReport::validate MUST refuse DeliveredPaymentProof with target_domain == 0.
    let bad_report = PaymentStatusReport {
        intent_id: [0x55; 32],
        guaranteed: Some(GuaranteedPaymentProof {
            block_height: 10,
            escrow_commitment: [0x11; 32],
            solver_bond_commitment: [0x22; 32],
        }),
        finalized: Some(FinalizedPaymentProof {
            checkpoint_height: 12,
            finality_certificate_digest: [0x33; 32],
        }),
        delivered: Some(DeliveredPaymentProof {
            target_domain: 0,
            delivery_proof_root: [0x44; 32],
            merchant_receipt_hash: [0x55; 32],
        }),
    };
    assert!(matches!(
        bad_report.validate(),
        Err(PaymentError::InvalidIntent(_))
    ));

    // UniversalPaymentRequestUri MUST refuse target_domain == 0 and deadline_unix_secs == 0.
    let zero_dom_uri = UniversalPaymentRequestUri {
        version: 1,
        recipient: [0x11; 32],
        target_domain: 0,
        target_asset_id: [0x22; 32],
        target_amount: 500,
        invoice_digest: [0x33; 32],
        deadline_unix_secs: 2_000,
        callback_ref: None,
    };
    assert!(matches!(
        zero_dom_uri.encode_canonical(),
        Err(PaymentError::InvalidIntent(_))
    ));

    let zero_dl_uri = UniversalPaymentRequestUri {
        target_domain: 1,
        deadline_unix_secs: 0,
        ..zero_dom_uri
    };
    assert!(matches!(
        zero_dl_uri.encode_canonical(),
        Err(PaymentError::InvalidIntent(_))
    ));
}
