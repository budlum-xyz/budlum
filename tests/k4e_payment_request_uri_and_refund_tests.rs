use budlum_core::crypto::primitives::WalletKeyPair;
use budlum_core::unification::payment_router::{
    DomainTokenBalance, PaymentError, PaymentRail, RefundIntent, RefundRegistry,
    UniversalPaymentIntent, UniversalPaymentRequestUri, UniversalPaymentRouter,
    REFUND_SIGNATURE_CONTEXT,
};

fn must<T, E: std::fmt::Debug>(res: Result<T, E>, msg: &str) -> T {
    match res {
        Ok(v) => v,
        Err(e) => panic!("{msg}: {e:?}"),
    }
}

#[test]
fn k4e_oe1_canonical_payment_uri_is_byte_identical_across_surfaces_and_checks_expiry() {
    let terminal_req = UniversalPaymentRequestUri {
        version: 1,
        recipient: [0xA1; 32],
        target_domain: 42,
        target_asset_id: [0xB2; 32],
        target_amount: 125_000,
        invoice_digest: [0xC3; 32],
        deadline_unix_secs: 1_900_000_000,
        callback_ref: Some(String::from("order-2026-001")),
    };
    let website_req = terminal_req.clone();
    let invoice_req = terminal_req.clone();

    let uri_terminal = must(terminal_req.encode_canonical(), "encode terminal");
    let uri_website = must(website_req.encode_canonical(), "encode website");
    let uri_invoice = must(invoice_req.encode_canonical(), "encode invoice");

    assert_eq!(uri_terminal, uri_website);
    assert_eq!(uri_website, uri_invoice);
    assert_eq!(terminal_req.request_digest(), website_req.request_digest());

    // Wallet decodes the canonical URI and validates active deadline.
    let decoded = must(
        UniversalPaymentRequestUri::decode_canonical(&uri_terminal),
        "decode canonical URI",
    );
    assert_eq!(decoded, terminal_req);
    must(
        decoded.validate_not_expired(1_899_999_999),
        "active request accepted",
    );
    assert!(matches!(
        decoded.validate_not_expired(1_900_000_001),
        Err(PaymentError::Expired { .. })
    ));

    // Zero invoice digest or zero deadline is refused fail-closed.
    let zero_invoice = UniversalPaymentRequestUri {
        invoice_digest: [0u8; 32],
        ..terminal_req.clone()
    };
    assert!(zero_invoice.validate_not_expired(100).is_err());

    let zero_deadline = UniversalPaymentRequestUri {
        deadline_unix_secs: 0,
        ..terminal_req
    };
    assert!(zero_deadline.validate_not_expired(0).is_err());

    // Non-canonical parameter ordering or duplicate keys fail closed.
    let swapped = uri_terminal.replace("amount=125000&asset=", "asset=b2&amount=125000&extra=");
    assert!(UniversalPaymentRequestUri::decode_canonical(&swapped).is_err());
}

#[test]
fn k4e_oe4_merchant_mldsa87_signed_refund_succeeds_once_and_refuses_impersonation_or_replay() {
    let merchant_kp = WalletKeyPair::generate();
    let imposter_kp = WalletKeyPair::generate();
    let payer_id = [0x11; 32];
    let merchant_id = merchant_kp.address().0;

    let intent = UniversalPaymentIntent {
        payer_id,
        merchant_id,
        target_domain: 1,
        target_asset_id: [0x01; 32],
        target_amount: 1_000,
        max_slippage_bps: 100,
        rail: PaymentRail::PosTerminal {
            terminal_id: String::from("POS-77"),
            merchant_code: String::from("MCC5411"),
            iso_currency_code: String::from("TRY"),
        },
        invoice_hash: [0xD4; 32],
        deadline_unix_secs: 2_000,
        nonce: 7,
    };
    let balances = vec![DomainTokenBalance {
        domain_id: 1,
        asset_id: [0x01; 32],
        symbol: String::from("BUD"),
        available_amount: 5_000,
    }];
    let receipt = must(
        UniversalPaymentRouter::quote_payment(&intent, &balances, &[], 1_500),
        "quote honest POS receipt",
    );

    let refund = RefundIntent {
        original_intent_id: receipt.intent_id,
        original_receipt_hash: receipt.receipt_hash,
        merchant_id,
        refund_recipient: payer_id,
        refund_amount: 1_000,
        reason_code: 42,
    };
    let refund_id = refund.refund_id();
    let merchant_sig = merchant_kp.sign(REFUND_SIGNATURE_CONTEXT, &refund_id);
    let imposter_sig = imposter_kp.sign(REFUND_SIGNATURE_CONTEXT, &refund_id);
    let wrong_ctx_sig = merchant_kp.sign(budlum_core::crypto::ctx::OFFLINE_VOUCHER_V1, &refund_id);

    let mut registry = RefundRegistry::default();

    // 1. Imposter key attempting to claim original merchant's refund MUST fail closed.
    assert!(registry
        .record_signed_refund(
            &receipt,
            &intent,
            &refund,
            &imposter_kp.public_key_bytes(),
            &imposter_sig,
        )
        .is_err());

    // 2. Signature under wrong domain context MUST fail closed.
    assert!(registry
        .record_signed_refund(
            &receipt,
            &intent,
            &refund,
            &merchant_kp.public_key_bytes(),
            &wrong_ctx_sig,
        )
        .is_err());

    // 3. Over-amount refund signed by genuine merchant MUST fail closed.
    let over_refund = RefundIntent {
        refund_amount: 1_001,
        ..refund.clone()
    };
    let over_sig = merchant_kp.sign(REFUND_SIGNATURE_CONTEXT, &over_refund.refund_id());
    assert!(registry
        .record_signed_refund(
            &receipt,
            &intent,
            &over_refund,
            &merchant_kp.public_key_bytes(),
            &over_sig,
        )
        .is_err());

    // 4. Genuine ML-DSA-87 merchant-signed refund succeeds on first submission.
    let recorded_id = must(
        registry.record_signed_refund(
            &receipt,
            &intent,
            &refund,
            &merchant_kp.public_key_bytes(),
            &merchant_sig,
        ),
        "genuine merchant ML-DSA-87 refund succeeds",
    );
    assert_eq!(recorded_id, refund_id);

    // 5. Second refund against the SAME settled payment MUST fail with ReplayDetected!
    assert_eq!(
        registry.record_signed_refund(
            &receipt,
            &intent,
            &refund,
            &merchant_kp.public_key_bytes(),
            &merchant_sig,
        ),
        Err(PaymentError::ReplayDetected)
    );
}
