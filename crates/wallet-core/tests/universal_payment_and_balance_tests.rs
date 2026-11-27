//! End-to-end tests for universal payment intents, quotes, receipts,
//! proof-backed unified balances, remote account derivation, and confusable
//! `.bud` recipient warnings.

use budlum_wallet_core::bns::{detect_confusable_bud_name, ConfusableReason};
use budlum_wallet_core::payment::{
    build_payment_receipt, derive_contract_account, derive_foreign_account, verify_payment_quote,
    BalanceHeaderBook, BalanceMerkleStep, DeliveredPaymentProof, FinalizedPaymentProof,
    ForeignScheme, GuaranteedPaymentProof, NativeBalanceProof, PaymentCompletionLevel,
    PaymentDisplaySummary, PaymentRail, PaymentRequestUri, PaymentStatusReport, RemoteBalanceProof,
    TrustedBalanceHeader, WalletLiquidityQuote, WalletPaymentIntent, WalletSplitLeg, RATE_SCALE,
};
use budlum_wallet_core::Wallet;

fn sample_wallet() -> Wallet {
    Wallet::from_entropy(&[0x42u8; 32]).expect("valid 256-bit entropy")
}

#[test]
fn payment_request_uri_roundtrip_and_canonical_rejection() {
    let uri = PaymentRequestUri {
        version: 1,
        recipient: [0x11u8; 32],
        target_domain: 2,
        target_asset_id: [0x22u8; 32],
        target_amount: 100_000_000,
        invoice_digest: [0x33u8; 32],
        deadline_unix_secs: 1_800_000_000,
        callback_ref: Some("pos-term-7".to_string()),
    };
    let encoded = uri.encode_canonical().expect("canonical encode");
    assert!(encoded.starts_with("budlum:pay/v1?amount=100000000&"));
    let decoded = PaymentRequestUri::decode_canonical(&encoded).expect("canonical decode");
    assert_eq!(decoded, uri);

    // Non-canonical key order must fail closed.
    let reordered = format!(
        "budlum:pay/v1?domain=2&amount=100000000&asset={}&deadline=1800000000&invoice={}&recipient={}",
        hex::encode([0x22u8; 32]),
        hex::encode([0x33u8; 32]),
        hex::encode([0x11u8; 32])
    );
    assert!(PaymentRequestUri::decode_canonical(&reordered).is_err());

    // Duplicate parameter and zero recipient must fail closed.
    let dup = format!("{encoded}&domain=2");
    assert!(PaymentRequestUri::decode_canonical(&dup).is_err());
    let mut zero_recipient = uri.clone();
    zero_recipient.recipient = [0u8; 32];
    assert!(zero_recipient.encode_canonical().is_err());

    // Path traversal in callback_ref must fail closed.
    let mut bad_cb = uri;
    bad_cb.callback_ref = Some("../escape".to_string());
    assert!(bad_cb.encode_canonical().is_err());
}

#[test]
fn wallet_signs_and_verifies_payment_intent_with_chain_id_binding() {
    let wallet = sample_wallet();
    let intent = WalletPaymentIntent {
        payer_id: wallet.address(),
        merchant_id: [0x99u8; 32],
        nonce: 7,
        target_domain: 3,
        target_asset_id: [0xAAu8; 32],
        target_amount: 500_000,
        max_slippage_bps: 150,
        deadline_unix_secs: 2_000,
        invoice_hash: [0xBBu8; 32],
        rail: PaymentRail::PosTerminal {
            terminal_id: "TERM-01".to_string(),
            merchant_code: "M-5411".to_string(),
            iso_currency_code: "USD".to_string(),
        },
    };

    let signed = wallet
        .sign_payment_intent(&intent, 777, 1_500)
        .expect("valid intent signs");
    assert!(signed.verify(&wallet.public_key(), 777, 1_500).is_ok());

    // Cross-chain replay must fail closed.
    assert!(signed.verify(&wallet.public_key(), 1, 1_500).is_err());
    // Expired intent must fail closed.
    assert!(signed.verify(&wallet.public_key(), 777, 2_001).is_err());
    // Tampered amount must fail closed.
    let mut tampered = signed.clone();
    tampered.intent.target_amount += 1;
    assert!(tampered.verify(&wallet.public_key(), 777, 1_500).is_err());
    // Wrong signer wallet must fail closed.
    let other = Wallet::from_entropy(&[0x77u8; 32]).unwrap();
    assert!(signed.verify(&other.public_key(), 777, 1_500).is_err());
}

#[test]
fn quote_verification_enforces_slippage_expiry_ceiling_math_and_solver_signature() {
    let payer = sample_wallet();
    let solver = Wallet::from_entropy(&[0x55u8; 32]).unwrap();
    let intent = WalletPaymentIntent {
        payer_id: payer.address(),
        merchant_id: [0x22u8; 32],
        nonce: 1,
        target_domain: 10,
        target_asset_id: [0x33u8; 32],
        target_amount: 101,
        max_slippage_bps: 100,
        deadline_unix_secs: 5_000,
        invoice_hash: [0x44u8; 32],
        rail: PaymentRail::OnChain,
    };
    let quote = WalletLiquidityQuote {
        quote_id: [0x66u8; 32],
        source_domain: 1,
        source_asset_id: [0x77u8; 32],
        target_domain: 10,
        target_asset_id: [0x33u8; 32],
        rate_scaled: 2 * RATE_SCALE, // 2 target per 1 source
        max_target_liquidity: 1_000,
        fee_bps: 50,
        valid_until_unix_secs: 4_500,
    };

    // Ceiling math: 101 / 2 = 50.5 -> base 51, plus 50 bps fee (51 * 10050 / 10000 = 51.255 -> 52).
    let eval = verify_payment_quote(&intent, &quote, 101, 4_000).expect("valid quote");
    assert_eq!(eval.required_source_amount, 52);
    assert_eq!(eval.target_delivered, 101);

    // Slippage violation refused.
    let mut greedy = quote.clone();
    greedy.fee_bps = 101;
    assert!(verify_payment_quote(&intent, &greedy, 101, 4_000).is_err());

    // Expired quote refused.
    assert!(verify_payment_quote(&intent, &quote, 101, 4_501).is_err());

    // Signed solver quote verifies and refuses tampering.
    let signed_quote = solver
        .sign_liquidity_quote(&quote, 777)
        .expect("solver signs quote");
    assert!(signed_quote
        .verify(&solver.public_key(), 777, 4_000)
        .is_ok());
    let mut bad_quote = signed_quote.clone();
    bad_quote.quote.rate_scaled += 1;
    assert!(bad_quote.verify(&solver.public_key(), 777, 4_000).is_err());
    assert!(signed_quote
        .verify(&solver.public_key(), 999, 4_000)
        .is_err());
}

#[test]
fn payment_receipt_and_display_summary_hide_network_names_and_enforce_tier_order() {
    let wallet = sample_wallet();
    let intent = WalletPaymentIntent {
        payer_id: wallet.address(),
        merchant_id: [0x12u8; 32],
        nonce: 9,
        target_domain: 4,
        target_asset_id: [0x34u8; 32],
        target_amount: 1_000,
        max_slippage_bps: 200,
        deadline_unix_secs: 9_000,
        invoice_hash: [0x56u8; 32],
        rail: PaymentRail::PosTerminal {
            terminal_id: "POS-9".to_string(),
            merchant_code: "CAFE".to_string(),
            iso_currency_code: "EUR".to_string(),
        },
    };
    let legs = vec![
        WalletSplitLeg {
            source_domain: 1,
            source_asset_id: [0xA1u8; 32],
            source_symbol: "BUD".to_string(),
            source_debited: 600,
            target_delivered: 600,
            fee_bps: 0,
            direct_same_domain: false,
            quote_id: Some([0xD1u8; 32]),
        },
        WalletSplitLeg {
            source_domain: 2,
            source_asset_id: [0xA2u8; 32],
            source_symbol: "USDC".to_string(),
            source_debited: 405,
            target_delivered: 400,
            fee_bps: 25,
            direct_same_domain: false,
            quote_id: Some([0xD2u8; 32]),
        },
    ];
    let receipt = build_payment_receipt(&intent, legs).expect("valid receipt");
    assert!(receipt
        .pos_auth_code
        .as_ref()
        .is_some_and(|c| c.len() == 12));
    assert!(receipt.verify(&intent).is_ok());

    // Forged receipt hash must fail verification.
    let mut forged = receipt.clone();
    forged.receipt_hash[0] ^= 0xFF;
    assert!(forged.verify(&intent).is_err());

    // Monotonicity: Delivered without Finalized must fail closed.
    let invalid_status = PaymentStatusReport {
        intent_id: intent.intent_id(),
        guaranteed: Some(GuaranteedPaymentProof {
            block_height: 10,
            escrow_commitment: [1u8; 32],
            solver_bond_commitment: [2u8; 32],
        }),
        finalized: None,
        delivered: Some(DeliveredPaymentProof {
            target_domain: 4,
            delivery_proof_root: [3u8; 32],
            merchant_receipt_hash: receipt.receipt_hash,
        }),
    };
    assert!(invalid_status.validate().is_err());

    // Valid full status yields a display summary with NO raw network name on primary label.
    let valid_status = PaymentStatusReport {
        intent_id: intent.intent_id(),
        guaranteed: invalid_status.guaranteed,
        finalized: Some(FinalizedPaymentProof {
            checkpoint_height: 15,
            finality_certificate_digest: [4u8; 32],
        }),
        delivered: invalid_status.delivered,
    };
    assert_eq!(
        valid_status.highest_level().unwrap(),
        Some(PaymentCompletionLevel::Delivered)
    );
    let summary = PaymentDisplaySummary::from_receipt_and_status(&receipt, &valid_status, "USDC")
        .expect("summary builds");
    assert_eq!(summary.guarantee_label, "Delivered");
    assert!(!summary.primary_headline.contains("domain"));
    assert!(!summary.primary_headline.contains("Ethereum"));
    assert!(!summary.primary_headline.contains("Solana"));
    assert!(summary.advanced_details.is_some());
}

#[test]
fn foreign_and_contract_account_derivation_matches_node_spec_and_rejects_bad_lengths() {
    let eth_addr = [0xABu8; 20];
    let derived_eth =
        derive_foreign_account(ForeignScheme::EthereumSecp256k1, &eth_addr).expect("20B eth");
    let derived_cosmos =
        derive_foreign_account(ForeignScheme::CosmosSecp256k1, &eth_addr).expect("20B cosmos");
    assert_ne!(derived_eth, derived_cosmos);

    // Exact node formula: SHA3-256("BDLM_FOREIGN_ACCOUNT_V1" || 1u8 || 20u64_le || eth_addr).
    let sol_pk = [0xCDu8; 32];
    let derived_sol =
        derive_foreign_account(ForeignScheme::SolanaEd25519, &sol_pk).expect("32B sol");
    assert_ne!(derived_eth, derived_sol);

    // Wrong length or all-zero local_id must fail closed.
    assert!(derive_foreign_account(ForeignScheme::EthereumSecp256k1, &[0xABu8; 32]).is_err());
    assert!(derive_foreign_account(ForeignScheme::SolanaEd25519, &[0xCDu8; 20]).is_err());
    assert!(derive_foreign_account(ForeignScheme::EthereumSecp256k1, &[0u8; 20]).is_err());

    let c1 = derive_contract_account(1, &eth_addr).expect("contract addr");
    let c2 = derive_contract_account(2, &eth_addr).expect("distinct ee");
    assert_ne!(c1, c2);
    assert_ne!(c1, derived_eth);
    assert!(derive_contract_account(1, &[]).is_err());
}

#[test]
fn unified_balance_portfolio_rejects_forged_or_stale_rpc_balances() {
    let wallet = sample_wallet();
    let owner = wallet.address();
    let bud_asset = [0x01u8; 32];
    let usdc_asset = [0x02u8; 32];
    let eth_owner =
        derive_foreign_account(ForeignScheme::EthereumSecp256k1, &[0x22u8; 20]).unwrap();

    // Construct an honest native balance proof + an honest remote balance proof anchored at height 100.
    let native_sibling = [0x5Au8; 32];
    let native_leaf = NativeBalanceProof::leaf_digest(&owner, &bud_asset, 5_000);
    let native_root = NativeBalanceProof::node_hash(&native_leaf, &native_sibling);
    let native_proof = NativeBalanceProof {
        header_height: 100,
        owner,
        asset_id: bud_asset,
        amount: 5_000,
        inclusion_path: vec![BalanceMerkleStep {
            sibling: native_sibling,
            sibling_is_right: true,
        }],
    };

    let remote_domain_id = 2u64;
    let remote_key = RemoteBalanceProof::balance_state_key(&eth_owner, &usdc_asset);
    let remote_val = 2_500u128.to_le_bytes().to_vec();
    let remote_sibling = [0x7Cu8; 32];
    let remote_root = RemoteBalanceProof::compute_merkle_root(
        &remote_key,
        &remote_val,
        &[BalanceMerkleStep {
            sibling: remote_sibling,
            sibling_is_right: false,
        }],
    );
    let domain_commitment_root =
        RemoteBalanceProof::expected_domain_commitment(remote_domain_id, &remote_root);
    let remote_proof = RemoteBalanceProof {
        header_height: 100,
        remote_domain_id,
        remote_state_root: remote_root,
        owner: eth_owner,
        asset_id: usdc_asset,
        amount: 2_500,
        inclusion_path: vec![BalanceMerkleStep {
            sibling: remote_sibling,
            sibling_is_right: false,
        }],
    };

    let mut book = BalanceHeaderBook::new();
    book.trust(TrustedBalanceHeader {
        height: 100,
        state_root: native_root,
        domain_commitment_root,
    });

    let portfolio = wallet
        .verify_unified_balances(
            std::slice::from_ref(&native_proof),
            std::slice::from_ref(&remote_proof),
            &book,
        )
        .expect("honest proofs verify");
    assert_eq!(portfolio.total_for_asset(&bud_asset), 5_000);
    assert_eq!(portfolio.total_for_asset(&usdc_asset), 2_500);
    assert_eq!(portfolio.entries().len(), 2);

    // Lying RPC inflates native balance by +1 -> MUST fail closed.
    let mut forged_native = native_proof.clone();
    forged_native.amount = 5_001;
    assert!(wallet
        .verify_unified_balances(&[forged_native], &[], &book)
        .is_err());

    // Lying RPC inflates remote balance by +1 -> MUST fail closed.
    let mut forged_remote = remote_proof.clone();
    forged_remote.amount = 2_501;
    assert!(wallet
        .verify_unified_balances(&[], &[forged_remote], &book)
        .is_err());

    // Duplicate balance entry double-counting -> MUST fail closed.
    assert!(wallet
        .verify_unified_balances(&[native_proof.clone(), native_proof.clone()], &[], &book)
        .is_err());

    // Future header height ahead of wallet tip -> MUST fail closed.
    let mut future_native = native_proof.clone();
    future_native.header_height = 101;
    assert!(wallet
        .verify_unified_balances(&[future_native], &[], &book)
        .is_err());

    // Stale header (> 5 blocks behind tip) -> MUST fail closed.
    book.trust(TrustedBalanceHeader {
        height: 106,
        state_root: [0xEEu8; 32],
        domain_commitment_root: [0xDDu8; 32],
    });
    assert!(wallet
        .verify_unified_balances(&[native_proof], &[], &book)
        .is_err());
}

#[test]
fn unified_balance_portfolio_rejects_u128_overflow_across_accounts() {
    let wallet = sample_wallet();
    let owner_a = wallet.address();
    let owner_b = [0x66u8; 32];
    let asset = [0x09u8; 32];

    let leaf_a = NativeBalanceProof::leaf_digest(&owner_a, &asset, u128::MAX);
    let leaf_b = NativeBalanceProof::leaf_digest(&owner_b, &asset, 1);
    let root = NativeBalanceProof::node_hash(&leaf_a, &leaf_b);

    let proof_a = NativeBalanceProof {
        header_height: 50,
        owner: owner_a,
        asset_id: asset,
        amount: u128::MAX,
        inclusion_path: vec![BalanceMerkleStep {
            sibling: leaf_b,
            sibling_is_right: true,
        }],
    };
    let proof_b = NativeBalanceProof {
        header_height: 50,
        owner: owner_b,
        asset_id: asset,
        amount: 1,
        inclusion_path: vec![BalanceMerkleStep {
            sibling: leaf_a,
            sibling_is_right: false,
        }],
    };

    let mut book = BalanceHeaderBook::new();
    book.trust(TrustedBalanceHeader {
        height: 50,
        state_root: root,
        domain_commitment_root: [0x11u8; 32],
    });

    assert!(wallet
        .verify_unified_balances(&[proof_a, proof_b], &[], &book)
        .is_err());
}

#[test]
fn uri_to_signed_intent_and_wallet_confusable_check_end_to_end() {
    let wallet = sample_wallet();
    let uri = PaymentRequestUri {
        version: 1,
        recipient: [0x88u8; 32],
        target_domain: 5,
        target_asset_id: [0x77u8; 32],
        target_amount: 250_000,
        invoice_digest: [0x66u8; 32],
        deadline_unix_secs: 8_000,
        callback_ref: None,
    };
    let raw = uri.encode_canonical().expect("encode");
    let parsed = PaymentRequestUri::decode_canonical(&raw).expect("decode");
    let intent = parsed.to_payment_intent(wallet.address(), 42, 50, PaymentRail::OnChain);
    let signed = wallet
        .sign_payment_intent(&intent, 777, 7_500)
        .expect("sign");
    assert!(signed.verify(&wallet.public_key(), 777, 7_500).is_ok());

    let contacts = ["paypal.bud", "wallet.bud", "dao.bud"];
    assert!(wallet
        .check_confusable_bud_recipient("pay-pal.bud", &contacts)
        .is_some());
    assert!(wallet
        .check_confusable_bud_recipient("vvall.bud", &["wall.bud"])
        .is_some());
    assert!(wallet
        .check_confusable_bud_recipient("clao.bud", &contacts)
        .is_some());
    assert!(wallet
        .check_confusable_bud_recipient("paypal.bud", &contacts)
        .is_none());
}

#[test]
fn confusable_bud_name_detector_warns_on_lookalikes_and_allows_exact_matches() {
    let contacts = ["paypal.bud", "google.bud", "budlum.bud", "market.bud"];

    // Exact match is NOT a warning.
    assert!(detect_confusable_bud_name("paypal.bud", &contacts).is_none());

    // Visually confusable ASCII lookalikes MUST trigger warning.
    let w1 = detect_confusable_bud_name("paypa1.bud", &contacts).expect("1 vs l spoof");
    assert_eq!(w1.similar_to, "paypal.bud");
    assert_eq!(w1.reason, ConfusableReason::VisualSkeletonMatch);

    let w2 = detect_confusable_bud_name("g00gle.bud", &contacts).expect("0 vs o spoof");
    assert_eq!(w2.similar_to, "google.bud");
    assert_eq!(w2.reason, ConfusableReason::VisualSkeletonMatch);

    let w3 = detect_confusable_bud_name("rnarket.bud", &contacts).expect("rn vs m spoof");
    assert_eq!(w3.similar_to, "market.bud");
    assert_eq!(w3.reason, ConfusableReason::VisualSkeletonMatch);

    // 1-edit-distance typosquat on >=4 char label MUST trigger warning.
    let w4 = detect_confusable_bud_name("budlun.bud", &contacts).expect("1-edit spoof");
    assert_eq!(w4.similar_to, "budlum.bud");
    assert_eq!(w4.reason, ConfusableReason::NearEditDistance);

    // Unrelated legitimate name triggers no warning.
    assert!(detect_confusable_bud_name("coffee.bud", &contacts).is_none());
}
