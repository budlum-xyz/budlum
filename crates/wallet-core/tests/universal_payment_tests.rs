//! End-to-end integration tests for wallet-core universal payment primitives:
//! - Light-client unified balance proof verification (never trusts RPC)
//! - Chain-agnostic payment presentation and finality assurance labels
//! - ML-DSA-87 signed payment intents, binding solver quotes, URIs, receipts,
//!   and deterministic remote-account address derivation
//! - `.bud` recipient resolution with address-bar confusable/punycode checks

use budlum_wallet_core::bns::{
    compute_bns_leaf_digest, compute_bns_registry_root, fold_bns_merkle_branch, BnsHeaderBook,
    TrustedBnsHeader, WalletBnsProof,
};
use budlum_wallet_core::crypto;
use budlum_wallet_core::universal_payment::{
    build_balance_leaf_digest, check_bud_name_address_bar_safety, derive_remote_account_address,
    fold_balance_merkle_branch, resolve_and_check_bud_payment_recipient, verify_balance_proof,
    AssuranceClass, BalanceLocation, BalanceProofBranch, ConfusableWarning, PaymentReceipt,
    PaymentRequest, SignedSolverQuote, SolverQuote, StateHeaderBook, TrustedStateHeader,
    UnifiedPortfolio, UniversalPaymentError, UniversalPaymentIntent,
};
use budlum_wallet_core::Wallet;

fn test_wallet(seed_byte: u8) -> Wallet {
    Wallet::from_entropy(&[seed_byte; 32]).expect("fixed 32-byte test entropy")
}

#[test]
fn unified_balance_proof_accepts_anchored_rows_and_rejects_forged_rpc_balance() {
    let wallet = test_wallet(0x11);
    let other_wallet = test_wallet(0x12);
    let owner = wallet.address();
    let asset_bud = [0xAA; 32];
    let asset_usdc = [0xBB; 32];

    let native_loc = BalanceLocation::NativeBudlum;
    let remote_addr = wallet
        .derive_remote_account("eip155:1", &[0x42; 32])
        .expect("valid remote addr");
    let remote_loc = BalanceLocation::RemoteAccount {
        caip2: "eip155:1".into(),
        remote_address: remote_addr,
    };

    let leaf_native =
        build_balance_leaf_digest(&owner, &asset_bud, 500_000, &native_loc).expect("native leaf");
    let leaf_remote =
        build_balance_leaf_digest(&owner, &asset_usdc, 250_000, &remote_loc).expect("remote leaf");

    let root_h10 = fold_balance_merkle_branch(&leaf_native, &[(leaf_remote, true)]);
    let root_h10_check = fold_balance_merkle_branch(&leaf_remote, &[(leaf_native, false)]);
    assert_eq!(root_h10, root_h10_check);

    let mut headers = StateHeaderBook::new();
    headers
        .trust(TrustedStateHeader {
            height: 10,
            state_root: root_h10,
            finalized_at_ms: 1_700_000_000_000,
        })
        .expect("valid header");

    let proof_native = BalanceProofBranch {
        header_height: 10,
        location: native_loc.clone(),
        asset_id: asset_bud,
        owner,
        amount: 500_000,
        siblings: vec![(leaf_remote, true)],
    };
    let proof_remote = BalanceProofBranch {
        header_height: 10,
        location: remote_loc.clone(),
        asset_id: asset_usdc,
        owner,
        amount: 250_000,
        siblings: vec![(leaf_native, false)],
    };

    let portfolio = wallet
        .verify_unified_portfolio(&[proof_native.clone(), proof_remote.clone()], &headers)
        .expect("valid verified portfolio");
    assert_eq!(portfolio.rows().len(), 2);
    assert_eq!(portfolio.total_for_asset(&asset_bud), 500_000);
    assert_eq!(portfolio.total_for_asset(&asset_usdc), 250_000);

    // Different wallet MUST refuse proofs belonging to another owner.
    assert!(other_wallet
        .verify_unified_portfolio(std::slice::from_ref(&proof_native), &headers)
        .is_err());

    // Duplicate balance row MUST be rejected so an RPC cannot double-count funds.
    let dup_err = UnifiedPortfolio::from_verified_proofs(
        &[proof_native.clone(), proof_native.clone()],
        &headers,
    )
    .expect_err("duplicate balance row must be refused");
    assert!(matches!(dup_err, UniversalPaymentError::InvalidInput(_)));

    // A lying RPC provider inflates the balance by 1 atom: MUST fail closed.
    let mut forged = proof_native.clone();
    forged.amount = 500_001;
    let err = verify_balance_proof(&forged, &headers).expect_err("forged RPC balance must fail");
    assert!(matches!(err, UniversalPaymentError::ProofMismatch(_)));

    // Missing header height MUST fail closed.
    let mut missing_hdr = proof_native.clone();
    missing_hdr.header_height = 999;
    let err = verify_balance_proof(&missing_hdr, &headers).expect_err("unknown header must fail");
    assert!(matches!(err, UniversalPaymentError::HeaderUnknown(999)));

    // Zero state root MUST be rejected at header enrollment.
    let err = headers
        .trust(TrustedStateHeader {
            height: 11,
            state_root: [0u8; 32],
            finalized_at_ms: 1_700_000_001_000,
        })
        .expect_err("zero state root must be rejected");
    assert!(matches!(err, UniversalPaymentError::InvalidInput(_)));
}

#[test]
fn unified_portfolio_rejects_u128_overflow_across_locations() {
    let owner = [0x31u8; 32];
    let asset = [0x44u8; 32];
    let loc_a = BalanceLocation::NativeBudlum;
    let loc_b = BalanceLocation::LinkedForeign {
        caip2: "cosmos:cosmoshub-4".into(),
        foreign_address: vec![0x99u8; 20],
    };
    let leaf_a = build_balance_leaf_digest(&owner, &asset, u128::MAX, &loc_a).expect("leaf a");
    let leaf_b = build_balance_leaf_digest(&owner, &asset, 1, &loc_b).expect("leaf b");
    let root = fold_balance_merkle_branch(&leaf_a, &[(leaf_b, true)]);
    let mut headers = StateHeaderBook::new();
    headers
        .trust(TrustedStateHeader {
            height: 1,
            state_root: root,
            finalized_at_ms: 1000,
        })
        .expect("trust");
    let p_a = BalanceProofBranch {
        header_height: 1,
        location: loc_a,
        asset_id: asset,
        owner,
        amount: u128::MAX,
        siblings: vec![(leaf_b, true)],
    };
    let p_b = BalanceProofBranch {
        header_height: 1,
        location: loc_b,
        asset_id: asset,
        owner,
        amount: 1,
        siblings: vec![(leaf_a, false)],
    };
    let err = UnifiedPortfolio::from_verified_proofs(&[p_a, p_b], &headers)
        .expect_err("u128 overflow must fail closed");
    assert!(matches!(err, UniversalPaymentError::Overflow(_)));
}

#[test]
fn payment_request_uri_parses_strictly_and_hides_chain_by_default() {
    let asset_hex = hex::encode([0x33u8; 32]);
    let uri = format!(
        "budlum:pay?to=merchant.bud&amount=1250000&asset={asset_hex}&expiry=1800000000000&memo=coffee&max_slippage_bps=50"
    );
    let req = PaymentRequest::parse_uri(&uri).expect("valid payment URI");
    assert_eq!(req.amount, 1_250_000);
    assert_eq!(req.asset_id, [0x33u8; 32]);
    assert_eq!(req.max_slippage_bps, Some(50));
    assert_eq!(req.memo.as_deref(), Some("coffee"));

    let view = req.presentation("BUD", AssuranceClass::PostQuantumFinal);
    assert!(view.chain_details_hidden_by_default);
    assert!(!view.requires_user_warning);
    assert_eq!(view.assurance_label, "Final (quantum-safe)");

    let prob_view = req.presentation("BUD", AssuranceClass::ProbabilisticWork);
    assert!(prob_view.requires_user_warning);

    // Reject dangerous schemes, punycode .bud, duplicate params, zero amount, control chars, slippage > 10000.
    assert!(PaymentRequest::parse_uri("javascript:alert(1)").is_err());
    assert!(PaymentRequest::parse_uri(&format!(
        "budlum:pay?to=xn--merchant.bud&amount=10&asset={asset_hex}"
    ))
    .is_err());
    assert!(PaymentRequest::parse_uri(&format!(
        "budlum:pay?to=merchant.bud&amount=0&asset={asset_hex}"
    ))
    .is_err());
    assert!(PaymentRequest::parse_uri(&format!(
        "budlum:pay?to=merchant.bud&amount=10&amount=20&asset={asset_hex}"
    ))
    .is_err());
    assert!(PaymentRequest::parse_uri(&format!(
        "budlum:pay?to=merchant.bud&amount=10&asset={asset_hex}&max_slippage_bps=10001"
    ))
    .is_err());
    assert!(PaymentRequest::parse_uri(&format!(
        "budlum:pay?to=merchant.bud&amount=10&asset={asset_hex}&memo=hi\nspoof"
    ))
    .is_err());
}

#[test]
fn ml_dsa_intent_quote_and_receipt_roundtrip_and_tamper_rejection() {
    let payer = test_wallet(0x21);
    let solver = test_wallet(0x22);
    let attacker = test_wallet(0x23);
    let recipient = [0x99u8; 32];
    let asset_in = [0x10u8; 32];
    let asset_out = [0x20u8; 32];
    let now_ms = 1_700_000_000_000u64;

    let intent = UniversalPaymentIntent {
        chain_id: 77701,
        payer: payer.address(),
        recipient,
        output_asset_id: asset_out,
        output_amount: 1_000_000,
        max_input_asset_id: asset_in,
        max_input_amount: 1_010_000,
        max_slippage_bps: 100,
        nonce: 7,
        expiry_ms: now_ms + 60_000,
        memo_hash: [0u8; 32],
    };

    let signed_intent = payer
        .sign_payment_intent(intent.clone())
        .expect("payer signs intent");
    signed_intent
        .verify(now_ms)
        .expect("fresh signed intent verifies");

    // Expired intent MUST fail closed.
    assert!(signed_intent.verify(intent.expiry_ms).is_err());

    // Tampered output amount, chain_id, or signer public key MUST fail closed.
    let mut tampered_intent = signed_intent.clone();
    tampered_intent.intent.output_amount += 1;
    assert!(tampered_intent.verify(now_ms).is_err());

    let mut wrong_chain = signed_intent.clone();
    wrong_chain.intent.chain_id += 1;
    assert!(wrong_chain.verify(now_ms).is_err());

    let mut wrong_pk = signed_intent.clone();
    wrong_pk.payer_public_key = attacker.public_key();
    assert!(wrong_pk.verify(now_ms).is_err());

    // Solver signs binding quote.
    let quote = SolverQuote {
        intent_id: intent.intent_id(),
        solver: solver.address(),
        input_asset_id: asset_in,
        input_amount: 1_005_000,
        output_asset_id: asset_out,
        output_amount: 1_000_000,
        valid_until_ms: now_ms + 30_000,
        assurance: AssuranceClass::PostQuantumFinal,
    };
    let signed_quote = solver
        .sign_solver_quote(quote.clone())
        .expect("solver signs quote");
    signed_quote
        .verify_against_intent(&signed_intent.intent, now_ms)
        .expect("binding quote verifies against intent");

    // Quote exceeding payer max_input_amount MUST be rejected.
    let overpriced = SolverQuote {
        input_amount: 1_010_001,
        ..quote.clone()
    };
    let signed_overpriced = solver.sign_solver_quote(overpriced).expect("sign");
    assert!(signed_overpriced
        .verify_against_intent(&signed_intent.intent, now_ms)
        .is_err());

    // Quote delivering less than requested output_amount MUST be rejected.
    let short_out = SolverQuote {
        output_amount: 999_999,
        ..quote.clone()
    };
    let signed_short = solver.sign_solver_quote(short_out).expect("sign");
    assert!(signed_short
        .verify_against_intent(&signed_intent.intent, now_ms)
        .is_err());

    // Same-asset quote exceeding max_slippage_bps MUST be rejected even when <= max_input_amount.
    let same_asset_intent = UniversalPaymentIntent {
        output_asset_id: asset_in,
        max_input_asset_id: asset_in,
        output_amount: 1_000_000,
        max_input_amount: 1_050_000,
        max_slippage_bps: 50, // max 1_005_000
        ..intent.clone()
    };
    let slippage_quote = SolverQuote {
        intent_id: same_asset_intent.intent_id(),
        solver: solver.address(),
        input_asset_id: asset_in,
        input_amount: 1_006_000,
        output_asset_id: asset_in,
        output_amount: 1_000_000,
        valid_until_ms: now_ms + 30_000,
        assurance: AssuranceClass::EconomicFinal,
    };
    let signed_slip = solver.sign_solver_quote(slippage_quote).expect("sign");
    assert!(signed_slip
        .verify_against_intent(&same_asset_intent, now_ms)
        .is_err());

    // Quote with unverified assurance MUST be rejected BOTH at signing time AND at verification time.
    let unverified_quote = SolverQuote {
        assurance: AssuranceClass::PendingOrUnverified,
        ..quote.clone()
    };
    assert!(solver.sign_solver_quote(unverified_quote.clone()).is_err());
    let rogue_sig = solver.sign_for(
        crypto::ctx::CROSS_DOMAIN_V1,
        &unverified_quote.signing_digest(),
    );
    let rogue_signed = SignedSolverQuote {
        quote: unverified_quote,
        solver_public_key: solver.public_key(),
        signature: rogue_sig,
    };
    assert!(rogue_signed
        .verify_against_intent(&signed_intent.intent, now_ms)
        .is_err());

    // Receipt binds intent, quote, block height, tx hash, and assurance.
    let receipt =
        PaymentReceipt::from_verified(&signed_intent, &signed_quote, 42_000, [0xEF; 32], now_ms)
            .expect("receipt builds from verified intent + quote");
    receipt
        .verify(&signed_intent, &signed_quote, now_ms)
        .expect("receipt verifies");

    let mut tampered_receipt = receipt.clone();
    tampered_receipt.output_amount += 1;
    assert!(tampered_receipt
        .verify(&signed_intent, &signed_quote, now_ms)
        .is_err());
}

#[test]
fn remote_account_address_derivation_is_deterministic_and_domain_separated() {
    let owner = [0x55u8; 32];
    let salt = [0x01u8; 32];
    let eth = derive_remote_account_address("eip155:1", &owner, &salt).expect("eth remote");
    let eth_again = derive_remote_account_address("eip155:1", &owner, &salt).expect("eth again");
    let arb = derive_remote_account_address("eip155:42161", &owner, &salt).expect("arb remote");
    let cosmos =
        derive_remote_account_address("cosmos:cosmoshub-4", &owner, &salt).expect("cosmos remote");
    let diff_salt =
        derive_remote_account_address("eip155:1", &owner, &[0x02u8; 32]).expect("diff salt");

    assert_eq!(eth, eth_again);
    assert_ne!(eth, [0u8; 32]);
    assert_ne!(eth, arb);
    assert_ne!(eth, cosmos);
    assert_ne!(eth, diff_salt);

    // Invalid CAIP-2 or zero owner MUST fail closed.
    assert!(derive_remote_account_address("bad", &owner, &salt).is_err());
    assert!(derive_remote_account_address("EIP155:1", &owner, &salt).is_err());
    assert!(derive_remote_account_address("eip155:1", &[0u8; 32], &salt).is_err());
}

#[test]
fn bud_name_payment_enforces_punycode_ban_confusable_warning_and_merkle_proof() {
    // Punycode prefix `xn--` MUST be refused fail-closed even though ASCII.
    assert!(check_bud_name_address_bar_safety("xn--ayaz.bud", &[]).is_err());
    assert!(check_bud_name_address_bar_safety("pay.xn--merchant.bud", &[]).is_err());

    // Lookalike `rnerchant.bud` vs trusted contact `merchant.bud` MUST emit a confusable warning.
    let warnings = check_bud_name_address_bar_safety("rnerchant.bud", &["merchant.bud"])
        .expect("valid syntax");
    assert!(
        warnings
            .iter()
            .any(|w| matches!(w, ConfusableWarning::LookalikeContact { similar_to } if similar_to == "merchant.bud")),
        "expected lookalike warning, got {warnings:?}"
    );

    // Exact match to known contact emits zero warnings.
    let clean =
        check_bud_name_address_bar_safety("merchant.bud", &["merchant.bud"]).expect("clean");
    assert!(clean.is_empty());

    // End-to-end BNS Merkle proof resolution with header book.
    let target = [0x77u8; 32];
    let name = "merchant.bud";
    let extras_digest = [0u8; 32];
    let leaf = compute_bns_leaf_digest(name, &target, 100, None, None, &extras_digest);
    let names_root = fold_bns_merkle_branch(name, leaf, &[]).expect("fold BNS root");
    let meta = [0x01u8; 32];
    let root = compute_bns_registry_root(&meta, &names_root);
    let mut book = BnsHeaderBook::new();
    book.trust(TrustedBnsHeader {
        height: 50,
        epoch: 10,
        bns_root: root,
    });
    let proof = WalletBnsProof {
        name: name.into(),
        owner: target,
        expires_at: 100,
        content_binding: None,
        storage_root: None,
        extras_digest,
        extras_preimage: None,
        meta_digest: meta,
        siblings: Vec::new(),
        header_height: 50,
    };
    let resolved =
        resolve_and_check_bud_payment_recipient(name, &target, &proof, &book, &["merchant.bud"])
            .expect("verified .bud recipient");
    assert_eq!(resolved.address, target);
    assert!(resolved.warnings.is_empty());

    // Forged target address MUST be rejected against the anchored Merkle proof.
    let forged_target = [0x88u8; 32];
    assert!(resolve_and_check_bud_payment_recipient(
        name,
        &forged_target,
        &proof,
        &book,
        &["merchant.bud"],
    )
    .is_err());
}
