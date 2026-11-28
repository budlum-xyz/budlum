//! End-to-end local consensus domain tests covering:
//! 1. Custom consensus domains bound to a BudZKVM program hash (`ConsensusKind::Custom` + STARK finality).
//! 2. Sovereign domain template lifecycle transitions in block and state-root commitment.
//! 3. Closed Garden final PoA quorum certificate anchored on Budlum with Merkle-provable final state root.
//! 4. Conflicting commitment domain freeze and in-block finality proof fork resolution.

use bud_isa::{Instruction, Opcode};
use budlum_core::core::account::AccountState;
use budlum_core::core::address::Address;
use budlum_core::core::chain_config::Network;
use budlum_core::core::hash::hash_fields_bytes;
use budlum_core::cross_domain::external::IntakeState;
use budlum_core::cross_domain::message::{CrossDomainMessage, CrossDomainMessageParams};
use budlum_core::cross_domain::MessageKind;
use budlum_core::crypto::primitives::KeyPair;
use budlum_core::domain::finality_adapter::{
    hash_finality_proof, poa_authority_set_hash, poa_commit_signing_message, FinalityProof,
    PoAAuthoritySignature,
};
use budlum_core::domain::producer::{build_pow_commitment, PowBlockContent, PowChainSpec};
use budlum_core::domain::registry::MIN_DOMAIN_OPERATOR_BOND;
use budlum_core::domain::sovereign::{
    ComplianceEvidence, DomainLifecycleState, SovereignDomainClass, SovereignDomainTemplate,
};
use budlum_core::domain::{
    default_domain, ConsensusKind, DomainCommitment, DomainStatus, PoWDomainParameters, RootScheme,
    VerifiedDomainCommitment, POW_HEADER_CHAIN_ADAPTER,
};
use budlum_core::execution::zkvm::{prove_bytecode, DEFAULT_CONTRACT_GAS_LIMIT};
use budlum_core::garden::closing_settlement_from_parts;
use budlum_core::prover::{zk_program_hash, ZkProofSubmission};
use budlum_core::registry::role::roles;
use budlum_core::settlement::commitment_tree::merkle_root;
use budlum_core::settlement::domains::{
    execute_settlement_tx, ResolveDomainFork, SettlementTx, SettlementTxContext,
};
use std::collections::BTreeMap;

fn ctx(sender: Address, chain_id: u64) -> SettlementTxContext {
    SettlementTxContext {
        sender,
        chain_id,
        fee: 0,
        bls: IntakeState::production_bls,
    }
}

fn fund_and_bond_relayer(state: &mut AccountState, relayer: Address) {
    state.get_or_create(&relayer).balance = 50_000_000_000;
    let stake = state.registry.params().min_stake.max(10_000_000);
    state
        .registry
        .register(relayer, roles::RELAYER, stake, 0)
        .expect("register relayer");
}

fn sample_custom_consensus_bytecode(imm_val: i32) -> Vec<u8> {
    let words = vec![
        Instruction {
            opcode: Opcode::Load,
            rd: 1,
            rs1: 0,
            rs2: 0,
            imm: 1,
        }
        .encode(),
        Instruction {
            opcode: Opcode::Load,
            rd: 2,
            rs1: 0,
            rs2: 0,
            imm: imm_val,
        }
        .encode(),
        Instruction {
            opcode: Opcode::SWrite,
            rd: 0,
            rs1: 1,
            rs2: 2,
            imm: 0,
        }
        .encode(),
        Instruction {
            opcode: Opcode::Halt,
            rd: 0,
            rs1: 0,
            rs2: 0,
            imm: 0,
        }
        .encode(),
    ];
    words.into_iter().flat_map(u64::to_le_bytes).collect()
}

#[test]
fn custom_consensus_budzkvm_program_domain_registers_and_advances_via_stark_proof() {
    let chain_id = Network::Devnet.chain_id().value();
    let operator = Address::from([0x11; 32]);
    let relayer = Address::from([0x12; 32]);
    let prover = Address::from([0x13; 32]);

    let (proof, mut public_inputs, program) = prove_bytecode(
        &sample_custom_consensus_bytecode(42),
        DEFAULT_CONTRACT_GAS_LIMIT,
    )
    .expect("real STARK proof");
    public_inputs.chain_id = chain_id;
    let program_hash = zk_program_hash(&program);

    let mut state_a = AccountState::default();
    state_a.get_or_create(&operator).balance = MIN_DOMAIN_OPERATOR_BOND * 4;
    state_a.get_or_create(&prover).balance = 10_000_000;
    fund_and_bond_relayer(&mut state_a, relayer);

    let domain_id = 701;
    let mut custom = default_domain(
        domain_id,
        ConsensusKind::Custom("threshold-vrf-bft".into()),
        99_701,
        "zk-proof-verification",
        0,
    );
    custom.operator = Some(operator);
    custom.operator_bond = MIN_DOMAIN_OPERATOR_BOND;
    custom.plugin_code_hash = Some(program_hash);
    custom.zk_program_allowlist = vec![program_hash];
    custom.genesis_state_root = [0u8; 32];

    let mut state_b = state_a.clone();

    for state in [&mut state_a, &mut state_b] {
        execute_settlement_tx(
            state,
            &ctx(operator, chain_id),
            &SettlementTx::RegisterDomain(Box::new(custom.clone())),
        )
        .expect("custom consensus domain backed by BudZKVM program must register");

        // Mutating allowlist away from plugin_code_hash must be refused.
        assert!(
            execute_settlement_tx(
                state,
                &ctx(operator, chain_id),
                &SettlementTx::SetZkProgram {
                    domain_id,
                    program: [0x99; 32],
                    allow: true,
                },
            )
            .is_err(),
            "custom consensus rule is pinned to plugin_code_hash"
        );

        let payload_hash =
            ZkProofSubmission::payload_binding_hash(&proof, &public_inputs, &program, domain_id, 1);
        let msg = CrossDomainMessage::new(CrossDomainMessageParams {
            source_domain: 0,
            target_domain: domain_id,
            source_height: 1,
            event_index: 0,
            nonce: 1,
            sender: prover,
            recipient: operator,
            payload_hash,
            kind: MessageKind::Custom("zk-custom-consensus".into()),
            expiry_height: 1_000,
        });
        let sub = ZkProofSubmission {
            message: msg,
            proof: proof.clone(),
            public_inputs: public_inputs.clone(),
            program: program.clone(),
        };
        execute_settlement_tx(
            state,
            &ctx(prover, chain_id),
            &SettlementTx::SubmitZkProof(Box::new(sub)),
        )
        .expect("real STARK proof for pinned custom consensus program must verify");

        let zk_proof = FinalityProof::Zk {
            domain_id,
            target_height: 1,
            final_state_root: public_inputs.final_state_root,
        };
        let commitment = DomainCommitment {
            domain_id,
            domain_height: 1,
            domain_block_hash: public_inputs.final_state_root,
            parent_domain_block_hash: [0u8; 32],
            state_root: public_inputs.final_state_root,
            tx_root: [0xB1; 32],
            event_root: [0xC1; 32],
            validator_set_hash: [0u8; 32],
            consensus_kind: ConsensusKind::Custom("threshold-vrf-bft".into()),
            finality_proof_hash: hash_finality_proof(&zk_proof).expect("hash proof"),
            sequence: 1,
            producer: Some(operator),
            timestamp_ms: 1_700_000_000_000,
            state_updates: BTreeMap::new(),
        };
        execute_settlement_tx(
            state,
            &ctx(relayer, chain_id),
            &SettlementTx::SubmitCommitment(Box::new(VerifiedDomainCommitment {
                commitment,
                proof: zk_proof,
            })),
        )
        .expect("custom consensus domain commitment attested by BudZKVM proof must finalize");
    }

    assert_eq!(
        state_a
            .settlement
            .domains
            .get(domain_id)
            .unwrap()
            .last_committed_height,
        1
    );
    assert_eq!(
        state_a.calculate_state_root(),
        state_b.calculate_state_root(),
        "two nodes applying the custom consensus domain blocks must derive the exact same state root"
    );
}

#[test]
fn sovereign_template_lifecycle_transitions_in_block_and_folds_into_state_root() {
    let chain_id = Network::Devnet.chain_id().value();
    let operator = Address::from([0x21; 32]);
    let intruder = Address::from([0x22; 32]);

    let mut state = AccountState::default();
    state.get_or_create(&operator).balance = MIN_DOMAIN_OPERATOR_BOND * 4;
    state.get_or_create(&intruder).balance = MIN_DOMAIN_OPERATOR_BOND * 4;

    let domain_id = 702;
    let mut poa = default_domain(
        domain_id,
        ConsensusKind::PoA,
        99_702,
        "poa-authority-quorum",
        1,
    );
    poa.operator = Some(operator);
    poa.operator_bond = MIN_DOMAIN_OPERATOR_BOND;
    poa.validator_set_hash = [0x44; 32];

    execute_settlement_tx(
        &mut state,
        &ctx(operator, chain_id),
        &SettlementTx::RegisterDomain(Box::new(poa)),
    )
    .expect("register sovereign PoA domain");

    let evidence = ComplianceEvidence {
        policy_hash: [1u8; 32],
        authority_set_hash: [0x44; 32],
        jurisdiction_hash: [3u8; 32],
        audit_commitment: [4u8; 32],
    };
    let template = SovereignDomainTemplate::new(
        domain_id,
        SovereignDomainClass::EnterprisePoa,
        ConsensusKind::PoA,
        operator,
        true,
        evidence,
        DomainLifecycleState::Draft,
    );

    execute_settlement_tx(
        &mut state,
        &ctx(operator, chain_id),
        &SettlementTx::RegisterSovereignTemplate(Box::new(template)),
    )
    .expect("register sovereign template in Draft");

    let draft_root = state.settlement.sovereign.root();
    let draft_state_root = state.calculate_state_root();

    // Non-operator transition must fail without mutating state.
    assert!(execute_settlement_tx(
        &mut state,
        &ctx(intruder, chain_id),
        &SettlementTx::TransitionSovereignLifecycle {
            domain_id,
            next: DomainLifecycleState::Active,
        },
    )
    .is_err());
    assert_eq!(state.calculate_state_root(), draft_state_root);

    // Draft -> Active -> Frozen -> Retired must each advance and fold into root().
    execute_settlement_tx(
        &mut state,
        &ctx(operator, chain_id),
        &SettlementTx::TransitionSovereignLifecycle {
            domain_id,
            next: DomainLifecycleState::Active,
        },
    )
    .expect("Draft -> Active");
    let active_root = state.settlement.sovereign.root();
    let active_state_root = state.calculate_state_root();
    assert_ne!(
        draft_root, active_root,
        "lifecycle change must enter sovereign root"
    );
    assert_ne!(
        draft_state_root, active_state_root,
        "lifecycle change must enter chain state root"
    );

    execute_settlement_tx(
        &mut state,
        &ctx(operator, chain_id),
        &SettlementTx::TransitionSovereignLifecycle {
            domain_id,
            next: DomainLifecycleState::Frozen,
        },
    )
    .expect("Active -> Frozen");
    let frozen_root = state.settlement.sovereign.root();
    assert_ne!(active_root, frozen_root);

    execute_settlement_tx(
        &mut state,
        &ctx(operator, chain_id),
        &SettlementTx::TransitionSovereignLifecycle {
            domain_id,
            next: DomainLifecycleState::Retired,
        },
    )
    .expect("Frozen -> Retired");
    let retired_root = state.settlement.sovereign.root();
    let retired_state_root = state.calculate_state_root();
    assert_ne!(frozen_root, retired_root);

    // Retired is terminal: Retired -> Active must be refused without mutating state.
    assert!(execute_settlement_tx(
        &mut state,
        &ctx(operator, chain_id),
        &SettlementTx::TransitionSovereignLifecycle {
            domain_id,
            next: DomainLifecycleState::Active,
        },
    )
    .is_err());
    assert_eq!(state.calculate_state_root(), retired_state_root);
}

#[test]
fn closed_garden_final_certificate_commits_provable_final_state_root_on_budlum() {
    let chain_id = Network::Devnet.chain_id().value();
    let host_kp = KeyPair::generate().expect("host keypair");
    let member_a = KeyPair::generate().expect("member_a keypair");
    let member_b = KeyPair::generate().expect("member_b keypair");
    let host_addr = Address::from(host_kp.public_key_bytes());
    let a_addr = Address::from(member_a.public_key_bytes());
    let b_addr = Address::from(member_b.public_key_bytes());

    let garden_chain_id: u64 = 0x4741_0000_0001_2345;
    let digest = hash_fields_bytes(&[b"BDLM_GARDEN_DOMAIN_V1", &garden_chain_id.to_le_bytes()]);
    let mut low4 = [0u8; 4];
    low4.copy_from_slice(&digest[..4]);
    let garden_dom_id = 0x8000_0000 | (u32::from_le_bytes(low4) & 0x7FFF_FFFF);
    let genesis_hash = [0x77; 32];

    let probe_domain = default_domain(
        garden_dom_id,
        ConsensusKind::PoA,
        garden_chain_id,
        "poa-authority-quorum",
        1,
    );
    let authorities = vec![host_addr, a_addr, b_addr];
    let auth_hash = poa_authority_set_hash(&probe_domain, &authorities).expect("authority hash");

    let final_state_root = [0xEE; 32];
    let mut commitment = DomainCommitment {
        domain_id: garden_dom_id,
        domain_height: 5,
        domain_block_hash: [0x55; 32],
        parent_domain_block_hash: [0x44; 32],
        state_root: final_state_root,
        tx_root: [0x66; 32],
        event_root: [0u8; 32],
        validator_set_hash: auth_hash,
        consensus_kind: ConsensusKind::PoA,
        finality_proof_hash: [0u8; 32],
        sequence: 5,
        producer: Some(host_addr),
        timestamp_ms: 1_700_000_005_000,
        state_updates: BTreeMap::new(),
    };
    let sign_msg = poa_commit_signing_message(garden_chain_id, garden_dom_id, &commitment);
    let sig_host = host_kp.sign(&sign_msg);
    let sig_a = member_a.sign(&sign_msg);
    let proof = FinalityProof::PoA {
        authorities: authorities.clone(),
        signatures: vec![
            PoAAuthoritySignature {
                authority: host_addr,
                signature: sig_host.to_vec(),
            },
            PoAAuthoritySignature {
                authority: a_addr,
                signature: sig_a.to_vec(),
            },
        ],
    };
    commitment.finality_proof_hash = hash_finality_proof(&proof).expect("proof hash");
    let verified = VerifiedDomainCommitment { commitment, proof };

    let closed = closing_settlement_from_parts(garden_chain_id, genesis_hash, host_addr, verified)
        .expect("build closed garden settlement package");

    let mut state = AccountState::default();
    state.get_or_create(&host_addr).balance = MIN_DOMAIN_OPERATOR_BOND * 4;
    state.get_or_create(&b_addr).balance = MIN_DOMAIN_OPERATOR_BOND * 4;

    let root_before = state.calculate_state_root();
    assert!(execute_settlement_tx(
        &mut state,
        &ctx(b_addr, chain_id),
        &SettlementTx::AnchorClosedGarden(Box::new(closed.clone())),
    )
    .is_err());
    assert_eq!(state.calculate_state_root(), root_before);

    execute_settlement_tx(
        &mut state,
        &ctx(host_addr, chain_id),
        &SettlementTx::AnchorClosedGarden(Box::new(closed)),
    )
    .expect("host anchors closed Garden final certificate on Budlum");

    let anchored_domain = state
        .settlement
        .domains
        .get(garden_dom_id)
        .expect("closed Garden domain registered");
    assert_eq!(anchored_domain.status, DomainStatus::Retired);
    assert_eq!(anchored_domain.last_committed_height, 5);
    assert!(!anchored_domain.bridge_enabled);

    let stored = state
        .settlement
        .commitments
        .find_by_height(garden_dom_id, 5)
        .expect("closed Garden final commitment stored");
    assert_eq!(stored.state_root, final_state_root);

    let leaves: Vec<[u8; 32]> = state
        .settlement
        .commitments
        .commitments_for_global_block()
        .iter()
        .map(DomainCommitment::leaf_hash)
        .collect();
    assert_eq!(leaves.len(), 1);
    assert_eq!(state.settlement.commitments.root(), merkle_root(&leaves));
}

#[test]
fn conflicting_commitments_freeze_domain_and_only_in_block_proof_unfreezes() {
    let chain_id = Network::Devnet.chain_id().value();
    let operator = Address::from([0x31; 32]);
    let relayer = Address::from([0x32; 32]);

    let mut state = AccountState::default();
    state.get_or_create(&operator).balance = MIN_DOMAIN_OPERATOR_BOND * 4;
    fund_and_bond_relayer(&mut state, relayer);

    let domain_id = 703;
    let mut pow = default_domain(
        domain_id,
        ConsensusKind::PoW,
        99_703,
        POW_HEADER_CHAIN_ADAPTER,
        1,
    );
    pow.operator = Some(operator);
    pow.operator_bond = MIN_DOMAIN_OPERATOR_BOND;
    pow.block_hash_scheme = RootScheme::Sha256;
    pow.pow_parameters = Some(PoWDomainParameters {
        min_difficulty_bits: 1,
        max_difficulty_bits: 16,
        min_cumulative_work: 1,
        max_headers: 16,
    });

    execute_settlement_tx(
        &mut state,
        &ctx(operator, chain_id),
        &SettlementTx::RegisterDomain(Box::new(pow.clone())),
    )
    .expect("register PoW domain");

    let branch_a_h1 = build_pow_commitment(&PowChainSpec {
        domain: pow.clone(),
        parent_hash: [0u8; 32],
        height: 1,
        difficulty_bits: 1,
        sequence: 1,
        producer: Some(operator),
        blocks: vec![PowBlockContent {
            timestamp_ms: 1_700_000_001_000,
            state_root: [0xA1; 32],
            tx_root: [0xA2; 32],
            event_root: [0xA3; 32],
        }],
    })
    .expect("mine branch A h1");

    execute_settlement_tx(
        &mut state,
        &ctx(relayer, chain_id),
        &SettlementTx::SubmitCommitment(Box::new(branch_a_h1.clone())),
    )
    .expect("commit branch A h1");

    let branch_b_h1 = build_pow_commitment(&PowChainSpec {
        domain: pow.clone(),
        parent_hash: [0u8; 32],
        height: 1,
        difficulty_bits: 1,
        sequence: 2,
        producer: Some(operator),
        blocks: vec![PowBlockContent {
            timestamp_ms: 1_700_000_099_000,
            state_root: [0xB1; 32],
            tx_root: [0xB2; 32],
            event_root: [0xB3; 32],
        }],
    })
    .expect("mine conflicting branch B h1");

    execute_settlement_tx(
        &mut state,
        &ctx(relayer, chain_id),
        &SettlementTx::SubmitCommitment(Box::new(branch_b_h1.clone())),
    )
    .expect("equivocating commitment executes and freezes domain in block");
    assert_eq!(
        state.settlement.domains.get(domain_id).unwrap().status,
        DomainStatus::Frozen
    );

    // Forged / invalid proof resolution must be refused and leave the domain Frozen.
    let mut forged = branch_b_h1.clone();
    forged.commitment.state_root = [0xFF; 32];
    let frozen_root = state.calculate_state_root();
    assert!(execute_settlement_tx(
        &mut state,
        &ctx(relayer, chain_id),
        &SettlementTx::ResolveDomainFork(Box::new(ResolveDomainFork {
            domain_id,
            conflicting_height: 1,
            head_a: branch_a_h1.commitment.domain_block_hash,
            head_b: branch_b_h1.commitment.domain_block_hash,
            winning: forged,
        })),
    )
    .is_err());
    assert_eq!(state.calculate_state_root(), frozen_root);
    assert_eq!(
        state.settlement.domains.get(domain_id).unwrap().status,
        DomainStatus::Frozen
    );

    let winning_heavier = build_pow_commitment(&PowChainSpec {
        domain: pow,
        parent_hash: [0u8; 32],
        height: 1,
        difficulty_bits: 2,
        sequence: 3,
        producer: Some(operator),
        blocks: vec![PowBlockContent {
            timestamp_ms: 1_700_000_200_000,
            state_root: [0xC1; 32],
            tx_root: [0xC2; 32],
            event_root: [0xC3; 32],
        }],
    })
    .expect("mine heavier winning branch");

    state.current_block_height = 10;
    execute_settlement_tx(
        &mut state,
        &ctx(relayer, chain_id),
        &SettlementTx::ResolveDomainFork(Box::new(ResolveDomainFork {
            domain_id,
            conflicting_height: 1,
            head_a: branch_a_h1.commitment.domain_block_hash,
            head_b: branch_b_h1.commitment.domain_block_hash,
            winning: winning_heavier.clone(),
        })),
    )
    .expect("in-block verified winning proof unfreezes domain");

    let resolved_domain = state.settlement.domains.get(domain_id).unwrap();
    assert_eq!(resolved_domain.status, DomainStatus::Active);
    assert_eq!(
        resolved_domain.last_committed_hash,
        winning_heavier.commitment.domain_block_hash
    );
    assert_eq!(
        state
            .settlement
            .commitments
            .find_by_height(domain_id, 1)
            .unwrap()
            .state_root,
        [0xC1; 32]
    );
}
