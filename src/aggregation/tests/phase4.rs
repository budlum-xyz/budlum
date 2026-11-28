//! Phase 4 tests: `ObjectKind::StarkProof` -> `Claim::Prog`, hidden m-of-n
//! multisig program accounts (`Account.auth_program_hash`), and domain
//! state-transition finality through `ClaimedDomainFinalityAdapter`.

use zeroize::Zeroizing;

use crate::aggregation::backend::{AggBackend, TickCtx};
use crate::aggregation::chain::{
    account_claim_for, check_block_with_backend, claim_program_auth, claim_signature,
    settlement_of_with_accounts,
};
use crate::aggregation::claim::Claim;
use crate::aggregation::domain_finality::{
    compile_domain_transition, derive_transition_state_root, domain_transition_claim,
    prove_domain_transition, ClaimedDomainFinalityAdapter, TAG_DOMAIN_TRANSITION_IN,
    TAG_DOMAIN_TRANSITION_OUT, TAG_DOMAIN_TRANSITION_STEP,
};
use crate::aggregation::frame::FrameLimits;
use crate::aggregation::hash::{
    auth_ok, TAG_AGG_MERGE, TAG_AGG_TICK, TAG_CLAIM, TAG_CLAIM_ROOT, TAG_FRAME, TAG_OBJECT,
};
use crate::aggregation::object::{derive_claim, ObjectError};
use crate::aggregation::params::{AggMode, AggParams};
use crate::aggregation::pool::PoolItem;
use crate::aggregation::programs::hidden_multisig::{
    prove_hidden_multisig_auth, prove_hidden_multisig_with_witnesses, HiddenMultisigPolicy,
    MemberSignatureWitness,
};
use crate::aggregation::programs::prog_claim::{verify_vm_proof, ProgClaimError, StarkProofObject};
use crate::aggregation::stark::{StarkBackend, STARK_PARAMETER_SET};
use crate::core::account::{Account, AccountState};
use crate::core::address::Address;
use crate::core::block::Block;
use crate::core::transaction::Transaction;
use crate::crypto::primitives::WalletKeyPair;
use crate::crypto::scheme::SchemeStatusRegistry;
use crate::domain::finality_adapter::{DomainFinalityAdapter, FinalityProof, FinalityStatus};
use crate::domain::types::{
    ConsensusDomain, ConsensusKind, DomainCommitment, DomainId, DomainStatus, Hash32, RootScheme,
};

const DOMAIN: DomainId = 45262;
const CHAIN_ID: u64 = 45262;

fn test_domain(program_hash: Hash32) -> ConsensusDomain {
    ConsensusDomain {
        id: 77,
        kind: ConsensusKind::Zk,
        status: DomainStatus::Active,
        domain_chain_id: 42_161,
        operator: None,
        operator_bond: 0,
        config_hash: [0x55; 32],
        validator_set_hash: [0x66; 32],
        finality_adapter: "agg-claimed-program-finality".into(),
        min_confirmations: 1,
        bridge_enabled: true,
        block_hash_scheme: RootScheme::Sha3_256,
        state_root_scheme: RootScheme::Sha3_256,
        tx_root_scheme: RootScheme::Sha3_256,
        last_committed_height: 10,
        last_committed_hash: [0x11; 32],
        pow_parameters: None,
        zk_program_allowlist: vec![program_hash],
        plugin_code_hash: None,
        genesis_state_root: [0x11; 32],
    }
}

fn test_commitment(height: u64, state_root: Hash32) -> DomainCommitment {
    DomainCommitment {
        domain_id: 77,
        domain_height: height,
        domain_block_hash: [0x44; 32],
        parent_domain_block_hash: [0x43; 32],
        state_root,
        tx_root: [0x22; 32],
        event_root: [0x33; 32],
        finality_proof_hash: [0x55; 32],
        consensus_kind: ConsensusKind::Zk,
        validator_set_hash: [0x66; 32],
        timestamp_ms: 1_750_000_000_000,
        sequence: height,
        producer: None,
        state_updates: std::collections::BTreeMap::new(),
    }
}

#[test]
fn phase4_hidden_multisig_authorizes_tx_through_master_proof_without_leaking_policy() {
    let registry = SchemeStatusRegistry::genesis();
    let params = AggParams {
        mode: AggMode::On,
        ..AggParams::default()
    };
    let backend = StarkBackend::new(
        registry.clone(),
        FrameLimits::from(&params),
        STARK_PARAMETER_SET,
    );

    // Hidden 2-of-3 multisig policy (never published on chain).
    let policy = HiddenMultisigPolicy::new(2, vec![11_111, 22_222, 33_333], 99_991)
        .expect("valid 2-of-3 policy");
    let compiled = policy.compile().expect("compile hidden multisig");

    let prog_addr = Address::from([0x77; 32]);
    let recipient = Address::from([0x88; 32]);

    // Verify Account.auth_program_hash commits into state_root without perturbing
    // accounts that keep auth_program_hash == None.
    let mut state_without = AccountState::new();
    state_without
        .accounts
        .insert(prog_addr, Account::with_balance(prog_addr, 10_000_000));
    let root_without = state_without.calculate_state_root();

    let mut state = AccountState::new();
    state.accounts.insert(
        prog_addr,
        Account::with_auth_program(prog_addr, 10_000_000, compiled.program_hash),
    );
    let root_with = state.calculate_state_root();
    assert_ne!(root_without, root_with);
    assert_eq!(
        state.auth_program_hash(&prog_addr),
        Some(compiled.program_hash)
    );

    // Construct a transfer from the hidden-multisig program account.
    let mut raw_tx = Transaction::new(prog_addr, recipient, 1_000, Vec::new());
    raw_tx.fee = 100_000;
    raw_tx.nonce = 0;
    raw_tx.chain_id = CHAIN_ID;
    let msg_hash = raw_tx.signing_hash();

    // Negative guest checks before generating the valid proof.
    // 1. Duplicate signer index (0, 0) must abort guest Assert.
    let s0 = policy.sign_as(0, &msg_hash).expect("sign 0");
    assert_eq!(
        prove_hidden_multisig_with_witnesses(
            &compiled,
            policy.policy_salt,
            &policy.member_pks,
            &[s0, s0],
            msg_hash,
            DOMAIN,
        )
        .unwrap_err(),
        ProgClaimError::AssertionFailed
    );
    // 2. Unordered indices (2, 0) must abort guest Assert.
    let s2 = policy.sign_as(2, &msg_hash).expect("sign 2");
    assert_eq!(
        prove_hidden_multisig_with_witnesses(
            &compiled,
            policy.policy_salt,
            &policy.member_pks,
            &[s2, s0],
            msg_hash,
            DOMAIN,
        )
        .unwrap_err(),
        ProgClaimError::AssertionFailed
    );
    // 3. Forged signature scalar must abort guest Assert.
    let forged = MemberSignatureWitness {
        signature: s2.signature ^ 1,
        ..s2
    };
    assert_eq!(
        prove_hidden_multisig_with_witnesses(
            &compiled,
            policy.policy_salt,
            &policy.member_pks,
            &[s0, forged],
            msg_hash,
            DOMAIN,
        )
        .unwrap_err(),
        ProgClaimError::AssertionFailed
    );

    // Valid hidden 2-of-3 STARK proof using signers {0, 2}.
    let (prog_again, stark_obj) = prove_hidden_multisig_auth(&policy, &[0, 2], msg_hash, DOMAIN)
        .expect("hidden 2-of-3 proves");
    assert_eq!(prog_again.program_hash, compiled.program_hash);

    // Tamper checks on verify_vm_proof:
    // Cross-domain replay must be refused.
    assert_eq!(
        verify_vm_proof(DOMAIN + 1, &stark_obj),
        Err(ObjectError::Invalid)
    );
    // Tampering output_hash away from AUTH_OK must be refused.
    let mut bad_out = stark_obj.clone();
    bad_out.output_hash[0] ^= 0x01;
    assert_eq!(verify_vm_proof(DOMAIN, &bad_out), Err(ObjectError::Invalid));

    // Convert into claimed tx + ObjectKind::StarkProof envelope.
    let (claimed_tx, prog_env) =
        claim_program_auth(&raw_tx, compiled.program_hash, &stark_obj).expect("claim_program_auth");
    assert!(claimed_tx.signature.is_none());
    assert!(claimed_tx.signer_public_key.is_empty());

    // Verify derive_claim produces the exact Phase 4 program-account claim.
    let derived = derive_claim(&registry, &prog_env).expect("derive_claim StarkProof");
    let expected_claim =
        account_claim_for(&claimed_tx, Some(compiled.program_hash)).expect("program account claim");
    assert_eq!(
        expected_claim,
        Claim::Prog {
            program_hash: compiled.program_hash,
            input_hash: msg_hash,
            output_hash: auth_ok(),
        }
    );
    assert_eq!(derived, expected_claim);

    // Also include a standard ML-DSA-87 V5 transaction in the same block,
    // proving heterogeneous Sig + Prog aggregation into one MasterProof.
    let kp = WalletKeyPair::generate();
    let mut sig_tx = Transaction::new(kp.address(), recipient, 500, Vec::new());
    sig_tx.fee = 100_000;
    sig_tx.nonce = 0;
    sig_tx.chain_id = CHAIN_ID;
    sig_tx.sign_v5(&kp);
    let (claimed_sig_tx, sig_env) = claim_signature(&sig_tx).expect("claim_signature");
    let sig_claim = derive_claim(&registry, &sig_env).expect("derive sig claim");

    let prog_tick = backend
        .prove_tick(
            &TickCtx::from_seed(DOMAIN, Zeroizing::new([0xA1; 32])).expect("ctx 1"),
            &[PoolItem {
                envelope: prog_env,
                claim: derived,
            }],
        )
        .expect("prog tick proves");
    let sig_tick = backend
        .prove_tick(
            &TickCtx::from_seed(DOMAIN, Zeroizing::new([0xA2; 32])).expect("ctx 2"),
            &[PoolItem {
                envelope: sig_env,
                claim: sig_claim,
            }],
        )
        .expect("sig tick proves");

    let merged_proof = backend
        .prove_merge(&prog_tick, &sig_tick)
        .expect("merge prog + sig ticks");
    let master =
        crate::aggregation::frame::ClaimFrame::combine(&prog_tick, &sig_tick, merged_proof)
            .expect("combine frames");
    assert!(master.proof.len() <= params.max_proof_bytes);
    backend
        .verify(&master, DOMAIN)
        .expect("heterogeneous MasterProof verifies");

    // Bond both segment aggregators above the Devnet validator floor before
    // consensus block validation.
    let agg_floor = state.validator_stake_floor(CHAIN_ID);
    for seg in &master.segments {
        state.add_validator_with_floor(seg.aggregator, agg_floor, agg_floor);
    }

    // Build block and validate against AccountState (resolving auth_program_hash).
    let mut block = Block::new_with_chain_id(
        1,
        "0".repeat(64),
        vec![claimed_tx.clone(), claimed_sig_tx],
        CHAIN_ID,
    );
    block.frame_hash = Some(master.hash(DOMAIN).expect("frame hash"));
    block.claim_frame = Some(master);

    check_block_with_backend(&params, &registry, Some(&state), &block, &backend)
        .expect("block with hidden-multisig program account passes all 10 rules");
    let settlement =
        settlement_of_with_accounts(&params, Some(&state), &block).expect("settlement succeeds");
    assert_eq!(settlement.failed, vec![false, false]);
    state
        .validate_claimed_transaction(&claimed_tx)
        .expect("claimed program tx validates against AccountState");

    // Block rule 6 negative check: if the account's registered auth_program_hash
    // differs, the exact same block MUST be refused.
    let mut wrong_prog_state = state.clone();
    wrong_prog_state.set_auth_program_hash(&prog_addr, Some([0xFF; 32]));
    assert!(check_block_with_backend(
        &params,
        &registry,
        Some(&wrong_prog_state),
        &block,
        &backend
    )
    .is_err());
}

#[test]
fn phase4_domain_transition_finalizes_through_master_proof() {
    let registry = SchemeStatusRegistry::genesis();
    let params = AggParams {
        mode: AggMode::On,
        ..AggParams::default()
    };
    let backend = StarkBackend::new(
        registry.clone(),
        FrameLimits::from(&params),
        STARK_PARAMETER_SET,
    );

    let compiled = compile_domain_transition(77, 42_161).expect("compile domain transition");
    let ext_domain = test_domain(compiled.program_hash);

    let prev_height = 10u64;
    let prev_root = [0x11; 32];
    let batch_digest = [0xAB; 32];
    let next_root =
        derive_transition_state_root(77, 42_161, prev_height, 11, &prev_root, &batch_digest);
    let commitment = test_commitment(11, next_root);

    // Non-monotonic height must abort inside BudVM.
    let bad_height = test_commitment(10, next_root);
    assert_eq!(
        prove_domain_transition(
            &compiled,
            &ext_domain,
            prev_height,
            &prev_root,
            &bad_height,
            &batch_digest,
            DOMAIN,
        )
        .unwrap_err(),
        ProgClaimError::AssertionFailed
    );

    // Forged state_root unrelated to (prev_root, batch_digest) must abort inside BudVM.
    let forged_root_commitment = test_commitment(11, [0xFE; 32]);
    assert_eq!(
        prove_domain_transition(
            &compiled,
            &ext_domain,
            prev_height,
            &prev_root,
            &forged_root_commitment,
            &batch_digest,
            DOMAIN,
        )
        .unwrap_err(),
        ProgClaimError::AssertionFailed
    );

    // Valid transition proof inside BudVM (BudAir).
    let stark_obj = prove_domain_transition(
        &compiled,
        &ext_domain,
        prev_height,
        &prev_root,
        &commitment,
        &batch_digest,
        DOMAIN,
    )
    .expect("domain transition proves");

    // Roundtrip encode/decode of StarkProofObject preserves verification.
    let encoded = stark_obj.encode().expect("encode StarkProofObject");
    let decoded = StarkProofObject::decode(&encoded).expect("decode StarkProofObject");
    let expected_claim = domain_transition_claim(
        compiled.program_hash,
        &ext_domain,
        prev_height,
        &prev_root,
        &commitment,
    );
    assert_eq!(
        verify_vm_proof(DOMAIN, &decoded),
        Ok(expected_claim.clone())
    );

    // Aggregate the domain transition claim into a StarkBackend MasterProof.
    let tx_hash = [0xEE; 32];
    let env = stark_obj.to_envelope(DOMAIN, tx_hash).expect("envelope");
    let claim = derive_claim(&registry, &env).expect("derive_claim");
    assert_eq!(claim, expected_claim);
    let claim_digest = claim.digest(DOMAIN);

    let frame = backend
        .prove_tick(
            &TickCtx::from_seed(DOMAIN, Zeroizing::new([0xB1; 32])).expect("ctx"),
            &[PoolItem {
                envelope: env,
                claim,
            }],
        )
        .expect("prove domain transition tick");
    assert!(frame.proof.len() <= params.max_proof_bytes);

    // Finalize through ClaimedDomainFinalityAdapter: unbonded state must fail,
    // bonded validator state must pass.
    let mut adapter = ClaimedDomainFinalityAdapter::new(DOMAIN);
    adapter.register_domain_program(ext_domain.id, compiled.program_hash);
    assert!(adapter
        .admit_verified_frame(&AccountState::new(), &backend, &frame)
        .is_err());
    let mut accounts = AccountState::new();
    let agg_floor = accounts.validator_stake_floor(CHAIN_ID);
    for seg in &frame.segments {
        accounts.add_validator_with_floor(seg.aggregator, agg_floor, agg_floor);
    }
    assert_eq!(
        adapter
            .admit_verified_frame(&accounts, &backend, &frame)
            .expect("admit verified MasterProof"),
        1
    );

    let proof = FinalityProof::AggregatedProg {
        program_hash: compiled.program_hash,
        prev_height,
        prev_state_root: prev_root,
        claim_digest,
    };
    assert_eq!(
        adapter
            .verify_finality(&ext_domain, &commitment, &proof)
            .expect("verify_finality"),
        FinalityStatus::Finalized
    );

    let mut empty_allowlist = ext_domain.clone();
    empty_allowlist.zk_program_allowlist.clear();
    let without_authority = adapter
        .verify_finality(&empty_allowlist, &commitment, &proof)
        .expect("an empty allowlist is a rejection, not a verifier error");
    assert!(
        matches!(without_authority, FinalityStatus::Rejected(_)),
        "a registered program bypassed an empty domain allowlist: {without_authority:?}"
    );

    // Negative checks on ClaimedDomainFinalityAdapter:
    // 1. Tampered commitment state_root must be rejected.
    let tampered_commitment = test_commitment(11, [0x98; 32]);
    assert!(matches!(
        adapter
            .verify_finality(&ext_domain, &tampered_commitment, &proof)
            .expect("rejected"),
        FinalityStatus::Rejected(_)
    ));

    // 2. Tampered prev_state_root must be rejected.
    let tampered_prev = FinalityProof::AggregatedProg {
        program_hash: compiled.program_hash,
        prev_height,
        prev_state_root: [0x12; 32],
        claim_digest,
    };
    assert!(matches!(
        adapter
            .verify_finality(&ext_domain, &commitment, &tampered_prev)
            .expect("rejected"),
        FinalityStatus::Rejected(_)
    ));

    // 3. Unregistered program_hash must be rejected.
    let wrong_prog = FinalityProof::AggregatedProg {
        program_hash: [0x01; 32],
        prev_height,
        prev_state_root: prev_root,
        claim_digest,
    };
    assert!(matches!(
        adapter
            .verify_finality(&ext_domain, &commitment, &wrong_prog)
            .expect("rejected"),
        FinalityStatus::Rejected(_)
    ));

    // 4. Tampered parent_domain_block_hash or timestamp_ms must be rejected.
    let mut tampered_parent = commitment.clone();
    tampered_parent.parent_domain_block_hash = [0x7E; 32];
    assert!(matches!(
        adapter
            .verify_finality(&ext_domain, &tampered_parent, &proof)
            .expect("rejected"),
        FinalityStatus::Rejected(_)
    ));
    let mut tampered_time = commitment.clone();
    tampered_time.timestamp_ms += 1;
    assert!(matches!(
        adapter
            .verify_finality(&ext_domain, &tampered_time, &proof)
            .expect("rejected"),
        FinalityStatus::Rejected(_)
    ));

    // 5. Once finalized tip advances to (11, next_root), replaying the old
    //    (10 -> 11) transition fails predecessor continuity, while anchoring at
    //    (10, prev_root) admits it.
    adapter.record_finalized_tip(ext_domain.id, prev_height, prev_root);
    assert_eq!(
        adapter
            .verify_finality(&ext_domain, &commitment, &proof)
            .expect("connected transition finalizes"),
        FinalityStatus::Finalized
    );
    adapter.record_finalized_tip(
        ext_domain.id,
        commitment.domain_height,
        commitment.state_root,
    );
    assert!(matches!(
        adapter
            .verify_finality(&ext_domain, &commitment, &proof)
            .expect("stale predecessor rejected"),
        FinalityStatus::Rejected(_)
    ));

    // 6. Trailing bytes after deflate EOF on StarkProofObject must be rejected.
    let mut trailing = encoded.clone();
    trailing.push(0x00);
    assert!(StarkProofObject::decode(&trailing).is_err());
}

#[test]
fn phase4_program_account_refuses_inline_signature_and_binds_merkle_proof() {
    use crate::core::account::TxAuthority;
    use crate::execution::executor::Executor;

    let kp = WalletKeyPair::generate();
    let sender = kp.address();
    let recipient = Address::from([0x44; 32]);
    let prog_hash = [0xA5; 32];

    let mut state = AccountState::new();
    state.add_balance(&sender, 1_000_000);
    state.set_auth_program_hash(&sender, Some(prog_hash));
    let _ = state.calculate_state_root();

    // Account Merkle proof commits to `auth_program_hash` and refuses stripping.
    let proof = state.get_account_proof(&sender);
    assert!(proof.present);
    assert_eq!(proof.auth_program_hash, Some(prog_hash));
    assert!(proof.verify_self_consistent());
    let mut stripped = proof.clone();
    stripped.auth_program_hash = None;
    assert!(!stripped.verify_self_consistent());

    // Absence proof adjacent to a program account also verifies cleanly.
    let absent = state.get_account_proof(&recipient);
    assert!(!absent.present);
    assert!(absent.verify_self_consistent());

    // Inline signature for the underlying wallet key MUST be refused once
    // `auth_program_hash` is set, on both validate_transaction and Executor.
    let mut inline_tx = Transaction::new(sender, recipient, 1_000, Vec::new());
    inline_tx.fee = 10;
    inline_tx.nonce = 0;
    inline_tx.chain_id = CHAIN_ID;
    inline_tx.sign_v5(&kp);
    assert!(inline_tx.verify_in(&state.scheme_registry));
    let err = state
        .validate_transaction_with_context(&inline_tx, 0, 1_000_000, TxAuthority::Inline)
        .expect_err("inline signature must not bypass auth_program_hash");
    assert!(err.contains("Program account"));
    let exec_err = Executor::apply_transaction_checked(&mut state, &inline_tx)
        .expect_err("Executor must refuse inline transaction from program account");
    assert_eq!(exec_err.code(), "program_account_requires_auth_claim");
}

#[test]
fn phase4_domain_tags_are_unique_and_prefix_free() {
    let tags: &[&[u8]] = &[
        TAG_CLAIM,
        TAG_CLAIM_ROOT,
        TAG_AGG_TICK,
        TAG_AGG_MERGE,
        TAG_OBJECT,
        TAG_FRAME,
        b"BDLM_AUTH_OK_V1",
        b"BDLM_AUTH_PROG_V1",
        TAG_DOMAIN_TRANSITION_IN,
        TAG_DOMAIN_TRANSITION_OUT,
        TAG_DOMAIN_TRANSITION_STEP,
    ];
    for (i, a) in tags.iter().enumerate() {
        for (j, b) in tags.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "duplicate domain tag");
                assert!(
                    !a.starts_with(b),
                    "tag {:?} is a prefix of {:?}",
                    String::from_utf8_lossy(b),
                    String::from_utf8_lossy(a)
                );
            }
        }
    }
}
