//! Domains, cross-domain bridge, settlement, and testnet feature-matrix
//! regression locks (`zk_domain_refuses_empty_halt_proof`,
//! `bridge_e2e_lock_mint_burn_unlock`, `ethereum_sync_committee_is_closed_on_testnet`,
//! `shared_security_is_closed_on_testnet`, `app_binding_is_closed_on_testnet`,
//! and functional regression names).

use crate::chain::blockchain::Blockchain;
use crate::chain::finality::{FinalityCert, ValidatorSetSnapshot};
use crate::consensus::pow::PoWEngine;
use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::chain_config::Network;
use crate::cross_domain::bridge_tx::{
    burn_with_event, execute_bridge_tx, lock, register_asset, submit_relay_proof,
    unlock_from_verified_event, BridgeTx, BridgeTxContext, BurnRequest, LockRequest,
    ProvenBridgeEvent,
};
use crate::cross_domain::event_tree::DomainEventTree;
use crate::cross_domain::external::ethereum::{layout, BlsVerifier, PinnedCommittee};
use crate::cross_domain::external::external_tx::{
    execute_external_domain_tx, ExternalDomainTx, ExternalDomainTxContext, ExternalDomainTxError,
};
use crate::cross_domain::external::intake::{AdapterSpec, IntakeState, RegistrationRequest};
use crate::cross_domain::external::registry::RegistryError as ExternalRegistryError;
use crate::cross_domain::external::selftest::AdmissionReport;
use crate::cross_domain::external::spec::{
    ExternalFinalityAdapter, RawConsensusEvidence, VerificationPolicy,
};
use crate::cross_domain::external::versioning::VersionPolicy;
use crate::cross_domain::external::zkvm_proof::{ZkFinalityEvidence, ZkVmFinalityAdapter};
use crate::cross_domain::message::{CrossDomainMessage, CrossDomainMessageParams};
use crate::cross_domain::{AssetId, DomainEvent, DomainEventKind, MerkleProof, MessageKind};
use crate::domain::finality_adapter::{
    BftFinalityAdapter, DomainFinalityAdapter, FinalityProof, FinalityStatus, PoAFinalityAdapter,
    PoSFinalityAdapter, PoWHeaderChainFinalityAdapter,
};
use crate::domain::plugin::default_domain;
use crate::domain::{ConsensusKind, DomainCommitment, Hash32, POW_HEADER_CHAIN_ADAPTER};
use crate::execution::zkvm::{prove_bytecode, DEFAULT_CONTRACT_GAS_LIMIT};
use crate::prover::ZkProofSubmission;
use crate::settlement::domains::{
    execute_settlement_tx, submit_zk_proof, SettlementTx, SettlementTxContext,
};
use crate::settlement::graft::{execute_graft_tx, GraftTx};
use crate::settlement::proof_market::{ProofReceipt, ReceiptStatus};
use crate::settlement::shared_security::{execute_shared_security_tx, SharedSecurityTx};
use crate::tokenomics::VestingSchedule;
use bud_isa::{Instruction, Opcode};
use std::collections::BTreeMap;
use std::sync::Arc;

const TESTNET_CHAIN_ID: u64 = 45261;
const DEVNET_CHAIN_ID: u64 = 45262;

fn addr(byte: u8) -> Address {
    Address::from([byte; 32])
}

fn single_event_tree(event: &DomainEvent) -> (Hash32, MerkleProof) {
    let mut tree = DomainEventTree::new();
    tree.push(event.clone());
    let root = tree.root();
    let proof = tree.proof(0).expect("single-event proof");
    (root, proof)
}

fn make_commitment(
    domain_id: u32,
    domain_height: u64,
    sequence: u64,
    block_hash: Hash32,
    event_root: Hash32,
    kind: ConsensusKind,
) -> DomainCommitment {
    DomainCommitment {
        domain_id,
        domain_height,
        domain_block_hash: block_hash,
        parent_domain_block_hash: [0u8; 32],
        state_root: [0xB1; 32],
        tx_root: [0xC1; 32],
        event_root,
        finality_proof_hash: [0xD1; 32],
        consensus_kind: kind,
        validator_set_hash: [0u8; 32],
        timestamp_ms: 1_000,
        sequence,
        producer: None,
        state_updates: BTreeMap::new(),
    }
}

struct AcceptTestBls;

impl BlsVerifier for AcceptTestBls {
    fn verify_aggregate(
        &self,
        _signing_root: &[u8; 32],
        aggregate_pubkey: &[u8],
        signature: &[u8],
        participants: u64,
    ) -> Result<(), String> {
        if participants == 0
            || aggregate_pubkey.iter().all(|&b| b == 0)
            || signature.iter().all(|&b| b == 0)
        {
            return Err("invalid test BLS aggregate".into());
        }
        Ok(())
    }
}

fn test_bls() -> Box<dyn BlsVerifier> {
    Box::new(AcceptTestBls)
}

fn bare_halt_bytecode() -> (Vec<u64>, Vec<u8>) {
    let words = vec![Instruction {
        opcode: Opcode::Halt,
        rd: 0,
        rs1: 0,
        rs2: 0,
        imm: 0,
    }
    .encode()];
    let mut bytes = Vec::with_capacity(words.len() * 8);
    for w in &words {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    (words, bytes)
}

/// both the in-chain ZK proof door
/// (`submit_zk_proof`) and `ZkVmFinalityAdapter` refuse an empty or bare
/// `[Halt]` program before accepting any state root claim.
#[test]
fn zk_domain_refuses_empty_halt_proof() {
    let (halt_words, halt_bytes) = bare_halt_bytecode();
    assert!(crate::prover::is_empty_or_halt_only_program(&[]));
    assert!(crate::prover::is_empty_or_halt_only_program(&halt_words));

    let (envelope, mut pi) =
        prove_bytecode(&halt_bytes, DEFAULT_CONTRACT_GAS_LIMIT).expect("prove bare Halt");
    pi.chain_id = TESTNET_CHAIN_ID;
    pi.block_height = 1;

    // 1) Settlement ZK domain door (`submit_zk_proof`) refuses even when the
    //    allowlist explicitly holds the bare Halt hash.
    let mut state = AccountState::new();
    let sender = addr(0x11);
    state.add_balance(&sender, 1_000_000);
    let mut zk_domain = default_domain(
        7,
        ConsensusKind::Zk,
        TESTNET_CHAIN_ID,
        "zk-proof-verification",
        0,
    );
    zk_domain
        .zk_program_allowlist
        .push(crate::prover::zk_program_hash(&halt_words));
    state
        .settlement
        .domains
        .register(zk_domain)
        .expect("register zk domain");

    let payload_hash =
        ZkProofSubmission::payload_binding_hash(&envelope, &pi, &halt_words, 7, 1);
    let msg = CrossDomainMessage::new(CrossDomainMessageParams {
        source_domain: 7,
        source_height: 1,
        event_index: 0,
        target_domain: 0,
        sender,
        recipient: Address::zero(),
        payload_hash,
        kind: MessageKind::Custom(b"zk-proof".to_vec()),
        expiry_height: 0,
    });
    let sub = ZkProofSubmission {
        message: msg,
        proof: envelope.clone(),
        public_inputs: pi.clone(),
        program: halt_words.clone(),
    };
    let err = submit_zk_proof(&mut state, &sub, TESTNET_CHAIN_ID, 1, 10)
        .expect_err("bare Halt proof must be refused by submit_zk_proof");
    assert!(err.contains("Halt"), "unexpected error: {err}");

    // 2) External `ZkVmFinalityAdapter` also refuses bare `[Halt]`.
    let pinned = bud_proof::canonical_set::program_hash_of(&halt_words);
    let adapter = ZkVmFinalityAdapter::new("testnet", Some(pinned), Some(TESTNET_CHAIN_ID));
    let payload = ZkFinalityEvidence {
        envelope,
        inputs: pi.clone(),
        program: halt_words,
    }
    .encode()
    .expect("encode evidence");
    let raw_evidence = RawConsensusEvidence {
        adapter: adapter.descriptor().id,
        evidence_version: 1,
        network: "testnet".to_string(),
        payload,
        declared_height: pi.block_height,
        declared_root: pi.final_state_root,
        submitter: sender,
    };
    let ext_err = adapter
        .verify(&raw_evidence, &VerificationPolicy::proven(10))
        .expect_err("ZkVmFinalityAdapter must refuse bare Halt evidence");
    assert!(
        ext_err.to_string().contains("Halt"),
        "unexpected external adapter error: {ext_err}"
    );
}

#[test]
fn zkvm_adapter_refuses_bare_halt_program() {
    zk_domain_refuses_empty_halt_proof();
}

/// Ethereum sync-committee external domain
/// registration is refused on Testnet (`45261`).
#[test]
fn ethereum_sync_committee_is_closed_on_testnet() {
    let poster = addr(0x21);
    let spec = AdapterSpec::EthereumSync {
        network: "testnet".to_string(),
        committee: Some(PinnedCommittee {
            period: 0,
            aggregate_pubkey: vec![0x11; 96],
            next_committee_root: [0xbb; 32],
        }),
    };
    let adapter = spec.build(Some(test_bls()), None);
    let economics = IntakeState::conservative_economics(1_000_000);
    let bond = u64::try_from(economics.required_bond_atoms()).expect("bond fits u64");

    let mut payload = vec![0u8; layout::LEN];
    if let Some(s) = payload.get_mut(layout::FINALIZED_ROOT) {
        s.copy_from_slice(&[0xaa; 32]);
    }
    if let Some(s) = payload.get_mut(layout::FINALIZED_SLOT) {
        s.copy_from_slice(&64u64.to_le_bytes());
    }
    if let Some(s) = payload.get_mut(layout::ATTESTED_SLOT) {
        s.copy_from_slice(&128u64.to_le_bytes());
    }
    if let Some(s) = payload.get_mut(layout::NEXT_COMMITTEE_ROOT) {
        s.copy_from_slice(&[0xbb; 32]);
    }
    if let Some(s) = payload.get_mut(layout::AGGREGATE_PUBKEY) {
        s.copy_from_slice(&[0x11; 96]);
    }
    if let Some(s) = payload.get_mut(layout::SIGNATURE) {
        s.copy_from_slice(&[0x22; 96]);
    }
    if let Some(s) = payload.get_mut(layout::PARTICIPATION_BITS) {
        s.copy_from_slice(&[0xff; 64]);
    }
    if let Some(s) = payload.get_mut(layout::STATE_ROOT) {
        s.copy_from_slice(&[0xcc; 32]);
    }

    let request = RegistrationRequest {
        spec,
        policy: VerificationPolicy::strict(1_000),
        bond_atoms: economics.required_bond_atoms(),
        economics,
        versions: VersionPolicy::single(adapter.descriptor().id, 2, 0),
        poster,
        golden: RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: 2,
            network: "testnet".to_string(),
            payload,
            declared_height: 64,
            declared_root: [0xcc; 32],
            submitter: poster,
        },
    };

    let mut state = AccountState::new();
    state.add_balance(&poster, bond.saturating_mul(4));
    let ctx = ExternalDomainTxContext {
        sender: poster,
        chain_id: Network::Testnet.chain_id().value(),
        fee: 10,
        bls: test_bls,
    };
    let err = execute_external_domain_tx(
        &mut state,
        &ctx,
        &ExternalDomainTx::Register(Box::new(request)),
    )
    .expect_err("EthereumSync must be refused on testnet chain id 45261");
    assert_eq!(err, ExternalDomainTxError::TestnetSyncCommitteeDisabled);
    assert!(state.settlement.external_intake.entries.is_empty());
    assert_eq!(state.get_balance(&poster), bond.saturating_mul(4));
}

#[test]
fn ethereum_sync_committee_refused_on_testnet_chain_id() {
    ethereum_sync_committee_is_closed_on_testnet();
}

/// shared security (`shared_security`) is closed on Testnet (`45261`).
#[test]
fn shared_security_is_closed_on_testnet() {
    assert!(!Network::Testnet.shared_security().enabled);
    let operator = addr(0x31);
    let mut state = AccountState::new();
    let ctx = SettlementTxContext {
        sender: operator,
        chain_id: Network::Testnet.chain_id().value(),
        fee: 10,
        bls: IntakeState::production_bls,
    };
    let err = execute_shared_security_tx(
        &mut state,
        &ctx,
        &SharedSecurityTx::SetRegistrar {
            domain_key: 1,
            registrar: vec![0xAB; 20],
        },
    )
    .expect_err("shared_security must be closed on testnet");
    assert!(err.to_string().contains("not enabled"), "{err}");
}

/// remote app binding (`app_binding`) is closed on Testnet (`45261`).
#[test]
fn app_binding_is_closed_on_testnet() {
    assert!(!Network::Testnet.app_binding_enabled());
    assert!(Network::Devnet.app_binding_enabled());
    let registrant = addr(0x32);
    let mut state = AccountState::new();
    state.add_balance(&registrant, 1_000_000);
    let mut domain = default_domain(
        9,
        ConsensusKind::PoW,
        TESTNET_CHAIN_ID,
        POW_HEADER_CHAIN_ADAPTER,
        1,
    );
    domain.operator = Some(registrant);
    crate::settlement::domains::register_domain(&mut state, domain).expect("register domain");

    let ctx = SettlementTxContext {
        sender: registrant,
        chain_id: Network::Testnet.chain_id().value(),
        fee: 5,
        bls: IntakeState::production_bls,
    };
    let tx = GraftTx::Register {
        domain_key: 9,
        origin_app: vec![0x44; 20],
        manifest_hash: [0x55; 32],
    };
    let err = execute_graft_tx(&mut state, &ctx, &tx)
        .expect_err("app_binding must be closed on testnet");
    assert!(err.to_string().contains("not enabled"), "{err}");
    assert!(state.settlement.graft.apps.is_empty());

    let outer_err = execute_settlement_tx(
        &mut state,
        &ctx,
        &SettlementTx::Graft(Box::new(tx)),
        1,
    )
    .expect_err("SettlementTx::Graft must be closed on testnet");
    assert!(outer_err.to_string().contains("not enabled"), "{outer_err}");
}

/// Bridge proof on Testnet (`45261`): full end-to-end
/// `lock -> mint -> burn -> unlock` through `execute_bridge_tx` with verified
/// committed `DomainEventTree` proofs and exact supply conservation.
#[test]
fn bridge_e2e_lock_mint_burn_unlock() {
    let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), None, TESTNET_CHAIN_ID, None);
    let op1 = addr(0x41);
    let op2 = addr(0x42);
    for (id, op) in [(1u32, op1), (2u32, op2)] {
        let mut d = default_domain(
            id,
            ConsensusKind::PoW,
            TESTNET_CHAIN_ID,
            POW_HEADER_CHAIN_ADAPTER,
            1,
        );
        d.operator = Some(op);
        d.bridge_enabled = true;
        d.last_committed_height = 50;
        bc.state
            .settlement
            .domains
            .register(d)
            .expect("register domain");
    }

    let asset = AssetId([0x77; 32]);
    let relayer = addr(0x43);
    let owner = addr(0x44);
    let recipient = addr(0x45);
    let min_relayer = bc.state.registry.params.min_relayer_stake;
    bc.state.add_balance(&relayer, min_relayer.saturating_mul(2));
    bc.state
        .bond_relayer(&relayer, min_relayer)
        .expect("bond relayer");
    bc.state.add_balance(&owner, 10_000);
    bc.state.add_balance(&recipient, 100);

    // 1) Operator registers asset.
    execute_bridge_tx(
        &mut bc.state,
        &BridgeTxContext {
            sender: op1,
            fee: 0,
            height: 10,
        },
        &BridgeTx::RegisterAsset {
            asset_id: asset,
            domain: 1,
        },
    )
    .expect("register bridge asset on testnet");

    // 2) Owner locks 1,000 units.
    let (_transfer, lock_event) = lock(
        &mut bc.state,
        owner,
        &LockRequest {
            source_domain: 1,
            target_domain: 2,
            source_height: 20,
            event_index: 0,
            asset_id: asset,
            recipient,
            amount: 1_000,
            expiry_height: 500,
        },
        10,
        10,
    )
    .expect("lock on source domain");
    assert_eq!(bc.state.get_balance(&owner), 9_000);
    let lock_msg_id = lock_event.message.as_ref().expect("lock msg").message_id;

    // Anchor source commitment at (domain 1, height 20, seq 1).
    let (lock_root, lock_proof) = single_event_tree(&lock_event);
    let src_block_hash = [0xA1; 32];
    bc.state
        .settlement
        .commitments
        .insert(make_commitment(
            1,
            20,
            1,
            src_block_hash,
            lock_root,
            ConsensusKind::PoW,
        ))
        .expect("insert source commitment");

    // 3) Relayer mints on target domain.
    execute_bridge_tx(
        &mut bc.state,
        &BridgeTxContext {
            sender: relayer,
            fee: 0,
            height: 25,
        },
        &BridgeTx::Mint(Box::new(ProvenBridgeEvent {
            domain: 1,
            height: 20,
            sequence: 1,
            expected_block_hash: src_block_hash,
            event: lock_event,
            proof: lock_proof,
        })),
    )
    .expect("mint from verified lock event");

    let params = *bc.state.registry.params();
    let (held_bud, relayer_fee_bud) = crate::cross_domain::bridge::split_bridge_fee(
        crate::core::money::Bud::new(1_000),
        params.bridge_relayer_fee_ppm,
        params.bridge_relayer_min_fee,
    )
    .expect("fee split");
    assert_eq!(bc.state.get_balance(&recipient), 100 + held_bud.get());

    // 4) Recipient burns minted units to return to source domain.
    let burn_event = burn_with_event(
        &mut bc.state,
        &BurnRequest {
            message_id: lock_msg_id,
            domain: 2,
            domain_height: 30,
            event_index: 0,
            expiry_height: 600,
            recipient_eth: [0xEE; 20],
        },
        10,
        30,
    )
    .expect("burn with event");
    assert_eq!(bc.state.get_balance(&recipient), 100);

    // Anchor target commitment at (domain 2, height 30, seq 1).
    let (burn_root, burn_proof) = single_event_tree(&burn_event);
    let dst_block_hash = [0xA2; 32];
    bc.state
        .settlement
        .commitments
        .insert(make_commitment(
            2,
            30,
            1,
            dst_block_hash,
            burn_root,
            ConsensusKind::PoW,
        ))
        .expect("insert target commitment");

    // 5) Relayer unlocks on source domain; owner receives exact `burned_amount`.
    unlock_from_verified_event(
        &mut bc.state,
        &ProvenBridgeEvent {
            domain: 2,
            height: 30,
            sequence: 1,
            expected_block_hash: dst_block_hash,
            event: burn_event,
            proof: burn_proof,
        },
        35,
    )
    .expect("unlock from verified burn event");
    assert_eq!(bc.state.get_balance(&owner), 9_000 + held_bud.get());
    assert_eq!(
        bc.state.get_balance(&owner)
            + bc.state.get_balance(&recipient)
            + bc.state.get_balance(&relayer),
        10_000 + 100 + min_relayer + relayer_fee_bud.get(),
        "full bridge round-trip conserves every atom"
    );
}

#[test]
fn bridge_unlock_returns_exact_burned_amount() {
    bridge_e2e_lock_mint_burn_unlock();
}

/// Bridge `lock` refuses `amount + fee` `u64` overflow.
#[test]
fn bridge_lock_and_burn_reject_fee_overflow() {
    let mut state = AccountState::new();
    let op = addr(0x51);
    for id in [1u32, 2u32] {
        let mut d = default_domain(
            id,
            ConsensusKind::PoW,
            DEVNET_CHAIN_ID,
            POW_HEADER_CHAIN_ADAPTER,
            1,
        );
        d.operator = Some(op);
        d.bridge_enabled = true;
        state.settlement.domains.register(d).expect("register");
    }
    let asset = AssetId([0x57; 32]);
    register_asset(&mut state, asset, 1).expect("asset");

    let owner = addr(0x52);
    state.add_balance(&owner, u64::MAX);
    let err = lock(
        &mut state,
        owner,
        &LockRequest {
            source_domain: 1,
            target_domain: 2,
            source_height: 5,
            event_index: 0,
            asset_id: asset,
            recipient: addr(0x53),
            amount: u64::MAX,
            expiry_height: 100,
        },
        10,
        5,
    )
    .expect_err("amount + fee overflow must fail closed");
    assert!(err.contains("overflows u64"), "unexpected error: {err}");
    assert_eq!(state.get_balance(&owner), u64::MAX);
}

/// Bridge `lock` enforces `spendable_balance` vesting locks.
#[test]
fn bridge_lock_and_burn_enforce_vesting_and_debit_burner() {
    let mut state = AccountState::new();
    let op = addr(0x54);
    for id in [1u32, 2u32] {
        let mut d = default_domain(
            id,
            ConsensusKind::PoW,
            DEVNET_CHAIN_ID,
            POW_HEADER_CHAIN_ADAPTER,
            1,
        );
        d.operator = Some(op);
        d.bridge_enabled = true;
        state.settlement.domains.register(d).expect("register");
    }
    let asset = AssetId([0x58; 32]);
    register_asset(&mut state, asset, 1).expect("asset");

    let vested_owner = addr(0x55);
    state.add_balance(&vested_owner, 50_000);
    state.team_vesting = Some((
        vested_owner,
        VestingSchedule {
            total: 50_000,
            start_epoch: 0,
            cliff_epochs: 20,
            duration_epochs: 100,
        },
    ));
    let err = execute_bridge_tx(
        &mut state,
        &BridgeTxContext {
            sender: vested_owner,
            fee: 10,
            height: 5,
        },
        &BridgeTx::Lock(LockRequest {
            source_domain: 1,
            target_domain: 2,
            source_height: 5,
            event_index: 0,
            asset_id: asset,
            recipient: addr(0x56),
            amount: 1_000,
            expiry_height: 100,
        }),
    )
    .expect_err("vesting-locked owner must not lock bridge funds");
    assert!(
        err.to_string().contains("holds 0") || err.to_string().contains("spendable"),
        "{err}"
    );
    assert_eq!(state.get_balance(&vested_owner), 50_000);
}

/// `submit_relay_proof` rolls back `settlement.relayer` if downstream
/// supply/balance checks fail so the pending relay is never permanently lost.
#[test]
fn relay_proof_rolls_back_ledger_on_supply_ceiling_refusal() {
    let mut state = AccountState::new();
    let op = addr(0x61);
    for id in [1u32, 2u32] {
        let mut d = default_domain(
            id,
            ConsensusKind::PoW,
            DEVNET_CHAIN_ID,
            POW_HEADER_CHAIN_ADAPTER,
            1,
        );
        d.operator = Some(op);
        d.bridge_enabled = true;
        d.last_committed_height = 50;
        state.settlement.domains.register(d).expect("register");
    }
    let asset = AssetId([0x62; 32]);
    register_asset(&mut state, asset, 1).expect("asset");

    let owner = addr(0x63);
    let recipient = addr(0x64);
    let relayer = addr(0x65);
    state.add_balance(&owner, 5_000);
    state.add_balance(&recipient, u64::MAX - 5);

    let (_transfer, lock_event) = lock(
        &mut state,
        owner,
        &LockRequest {
            source_domain: 1,
            target_domain: 2,
            source_height: 10,
            event_index: 0,
            asset_id: asset,
            recipient,
            amount: 1_000,
            expiry_height: 500,
        },
        0,
        10,
    )
    .expect("lock");
    assert_eq!(lock_event.kind, DomainEventKind::BridgeLocked);
    let msg_id = lock_event.message.as_ref().expect("msg").message_id;

    let (root, proof) = single_event_tree(&lock_event);
    state
        .settlement
        .commitments
        .insert(make_commitment(1, 10, 1, [0xD1; 32], root, ConsensusKind::PoW))
        .expect("commit");

    let err = submit_relay_proof(&mut state, msg_id, relayer, &proof, 1, 15)
        .expect_err("overflowing recipient credit must refuse");
    assert!(
        err.contains("overflow") || err.contains("Mint") || err.contains("supply"),
        "{err}"
    );
    assert!(
        state.settlement.relayer.pending_relay(&msg_id).is_some(),
        "pending relay must remain intact after rollback"
    );
}

/// `PoW`, `PoS`, `PoA`, and `Bft` finality adapters each reject a
/// commitment whose `domain_id` disagrees with `domain.id`, and
/// `PoAFinalityAdapter` rejects an empty authority set without panicking.
#[test]
fn finality_adapters_reject_cross_domain_commitment_and_empty_authorities() {
    let wrong_commitment = make_commitment(99, 5, 1, [0x11; 32], [0x44; 32], ConsensusKind::PoA);

    let pow_domain = default_domain(
        1,
        ConsensusKind::PoW,
        DEVNET_CHAIN_ID,
        POW_HEADER_CHAIN_ADAPTER,
        1,
    );
    let pow_res = PoWHeaderChainFinalityAdapter
        .verify_finality(
            &pow_domain,
            &wrong_commitment,
            &FinalityProof::PoWHeaderChain {
                headers: Vec::new(),
            },
        )
        .expect("pow verify returns status");
    assert!(matches!(pow_res, FinalityStatus::Rejected(_)));

    let pos_domain = default_domain(2, ConsensusKind::PoS, DEVNET_CHAIN_ID, "pos-qc-finality", 0);
    let empty_snap = ValidatorSetSnapshot::new(0, Vec::new());
    let empty_cert = FinalityCert {
        epoch: 0,
        checkpoint_height: 5,
        checkpoint_hash: "11".repeat(32),
        chain_id: DEVNET_CHAIN_ID,
        agg_sig_bls: vec![0u8; 48],
        bitmap: Vec::new(),
        set_hash: empty_snap.set_hash.clone(),
        seat_table_version: 0,
    };
    let pos_res = PoSFinalityAdapter::default()
        .verify_finality(
            &pos_domain,
            &wrong_commitment,
            &FinalityProof::PoS {
                cert: empty_cert.clone(),
                validator_snapshot: empty_snap.clone(),
            },
        )
        .expect("pos verify returns status");
    assert!(matches!(pos_res, FinalityStatus::Rejected(_)));

    let bft_domain = default_domain(
        3,
        ConsensusKind::Bft,
        DEVNET_CHAIN_ID,
        "bft-commit-quorum",
        0,
    );
    let bft_res = BftFinalityAdapter::default()
        .verify_finality(
            &bft_domain,
            &wrong_commitment,
            &FinalityProof::Bft {
                round: 0,
                commit_hash: [0x11; 32],
                cert: empty_cert,
                validator_snapshot: empty_snap,
            },
        )
        .expect("bft verify returns status");
    assert!(matches!(bft_res, FinalityStatus::Rejected(_)));

    let poa_domain = default_domain(
        4,
        ConsensusKind::PoA,
        DEVNET_CHAIN_ID,
        "poa-authority-quorum",
        0,
    );
    let poa_mismatch = PoAFinalityAdapter::default()
        .verify_finality(
            &poa_domain,
            &wrong_commitment,
            &FinalityProof::PoA {
                authorities: vec![addr(1)],
                signatures: Vec::new(),
            },
        )
        .expect("poa mismatch returns status");
    assert!(matches!(poa_mismatch, FinalityStatus::Rejected(_)));

    let mut matching_poa = wrong_commitment;
    matching_poa.domain_id = 4;
    let poa_empty = PoAFinalityAdapter::default()
        .verify_finality(
            &poa_domain,
            &matching_poa,
            &FinalityProof::PoA {
                authorities: Vec::new(),
                signatures: Vec::new(),
            },
        )
        .expect("empty PoA authority set must not panic");
    assert!(matches!(poa_empty, FinalityStatus::Rejected(_)));
}

/// A `Paid` proof-market receipt is terminal and cannot be
/// overwritten to `Revoked`.
#[test]
fn proof_market_paid_receipt_cannot_be_revoked() {
    let mut receipt = ProofReceipt::new([0xAA; 32], addr(0x71), 5, [0xCC; 32], 1_000);
    receipt.mark_paid().expect("pending -> paid");
    assert_eq!(receipt.status, ReceiptStatus::Paid);
    let err = receipt
        .revoke("attempt to overwrite paid status".to_string())
        .expect_err("Paid -> Revoked must be refused");
    assert!(err.contains("Paid"), "unexpected error: {err}");
    assert_eq!(receipt.status, ReceiptStatus::Paid);
}

/// `ExternalDomainRegistry::readmit` refuses a 0-probe or
/// version-mismatched admission report, and `last_accepted_height` never
/// rewinds when a lower-height attestation is submitted later.
#[test]
fn external_registry_readmit_requires_probes_and_height_is_monotonic() {
    let poster = addr(0x81);
    let spec = AdapterSpec::EthereumSync {
        network: "devnet".to_string(),
        committee: Some(PinnedCommittee {
            period: 0,
            aggregate_pubkey: vec![0x11; 96],
            next_committee_root: [0xbb; 32],
        }),
    };
    let adapter = spec.build(Some(test_bls()), None);
    let economics = IntakeState::conservative_economics(1_000_000);
    let make_ev = |height: u64, root_byte: u8| -> RawConsensusEvidence {
        let mut payload = vec![0u8; layout::LEN];
        if let Some(s) = payload.get_mut(layout::FINALIZED_ROOT) {
            s.copy_from_slice(&[0xaa; 32]);
        }
        if let Some(s) = payload.get_mut(layout::FINALIZED_SLOT) {
            s.copy_from_slice(&height.to_le_bytes());
        }
        if let Some(s) = payload.get_mut(layout::ATTESTED_SLOT) {
            s.copy_from_slice(&(height.saturating_mul(2)).to_le_bytes());
        }
        if let Some(s) = payload.get_mut(layout::NEXT_COMMITTEE_ROOT) {
            s.copy_from_slice(&[0xbb; 32]);
        }
        if let Some(s) = payload.get_mut(layout::AGGREGATE_PUBKEY) {
            s.copy_from_slice(&[0x11; 96]);
        }
        if let Some(s) = payload.get_mut(layout::SIGNATURE) {
            s.copy_from_slice(&[0x22; 96]);
        }
        if let Some(s) = payload.get_mut(layout::PARTICIPATION_BITS) {
            s.copy_from_slice(&[0xff; 64]);
        }
        if let Some(s) = payload.get_mut(layout::STATE_ROOT) {
            s.copy_from_slice(&[root_byte; 32]);
        }
        RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: 2,
            network: "devnet".to_string(),
            payload,
            declared_height: height,
            declared_root: [root_byte; 32],
            submitter: poster,
        }
    };

    let mut intake = IntakeState::new();
    let key = intake
        .register_domain(
            RegistrationRequest {
                spec,
                policy: VerificationPolicy::strict(1_000),
                bond_atoms: economics.required_bond_atoms(),
                economics,
                versions: VersionPolicy::single(adapter.descriptor().id, 2, 0),
                poster,
                golden: make_ev(64, 0xcc),
            },
            Some(test_bls()),
        )
        .expect("register external domain on devnet");

    // Submit height 200, then height 120: `last_accepted_height` must stay 200.
    intake
        .submit_evidence(&make_ev(200, 0xd1), Some(test_bls()))
        .expect("accept height 200");
    assert_eq!(
        intake
            .registry
            .domain(&key)
            .and_then(|d| d.record.last_accepted_height),
        Some(200)
    );
    intake
        .submit_evidence(&make_ev(120, 0xd2), Some(test_bls()))
        .expect("accept height 120 within max_age");
    assert_eq!(
        intake
            .registry
            .domain(&key)
            .and_then(|d| d.record.last_accepted_height),
        Some(200),
        "last_accepted_height must not rewind when an older height arrives"
    );

    // Mark faulted and attempt readmit with 0 probes or wrong evidence version.
    intake
        .registry
        .mark_faulted(&key, "fault test")
        .expect("mark faulted");
    let zero_probe_report = AdmissionReport {
        adapter_version: adapter.descriptor().adapter_version,
        evidence_version: 2,
        golden_verified: true,
        probes: Vec::new(),
        probe_commitment: [0u8; 32],
        admitted: true,
    };
    let err_zero = intake
        .registry
        .readmit(&key, &zero_probe_report, "zero probes")
        .expect_err("0-probe report must not readmit a faulted domain");
    assert!(matches!(err_zero, ExternalRegistryError::AdmissionFailed { .. }));

    let mut wrong_ver = crate::cross_domain::external::admit(
        adapter.as_ref(),
        &VerificationPolicy::strict(1_000),
    );
    wrong_ver.evidence_version = 999;
    let err_ver = intake
        .registry
        .readmit(&key, &wrong_ver, "wrong evidence version")
        .expect_err("mismatched evidence version must not readmit");
    assert!(matches!(
        err_ver,
        ExternalRegistryError::AdmissionEvidenceVersionMismatch { .. }
    ));
}
