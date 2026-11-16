//! The aggregation layer on a chain: a block that carries a claim frame is
//! built, sent, checked and executed, and every block rule refuses what it
//! must.

use std::sync::Arc;

use crate::aggregation::backend::{AggBackend, TickCtx};
use crate::aggregation::chain::{
    account_claim, check_block, claim_domain, claim_signature, genesis_commitment, settlement_of,
    validate_params, ChainBackend,
};
use crate::aggregation::fees::{ClaimSettlement, FeePayout};
use crate::aggregation::frame::ClaimFrame;
use crate::aggregation::object::derive_claim;
use crate::aggregation::params::{AggMode, AggParams};
use crate::aggregation::pool::PoolItem;
use crate::chain::blockchain::Blockchain;
use crate::chain::genesis::GenesisConfig;
use crate::consensus::PoWEngine;
use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::block::Block;
use crate::core::transaction::Transaction;
use crate::crypto::primitives::WalletKeyPair;
use crate::crypto::scheme::SchemeStatusRegistry;
use crate::execution::executor::Executor;

pub(super) const CHAIN: u64 = 45262;
pub(super) const FEE: u64 = 100_000;
pub(super) const AMOUNT: u64 = 10;
/// Fee of one signature claim under the default parameters: 64 per byte
/// over 67 bytes.
pub(super) const SIG_CLAIM_FEE: u64 = 4288;

pub(super) fn aggregator() -> Address {
    Address::from([0xA6; 32])
}

pub(super) fn producer() -> Address {
    Address::from([0xB7; 32])
}

pub(super) fn recipient() -> Address {
    Address::from([0x44; 32])
}

pub(super) fn on() -> AggParams {
    AggParams {
        mode: AggMode::On,
        ..AggParams::default()
    }
}

pub(super) fn wallet(seed: u8) -> WalletKeyPair {
    WalletKeyPair::from_seed(&[seed; 32])
}

pub(super) fn genesis(params: Option<AggParams>, funded: &[Address]) -> GenesisConfig {
    let mut config = GenesisConfig::new(CHAIN);
    for address in funded {
        config = config.with_allocation(*address, 10_000_000);
    }
    config.aggregation = params;
    config
}

pub(super) fn chain(config: GenesisConfig) -> Blockchain {
    Blockchain::new_with_genesis(Arc::new(PoWEngine::new(0)), None, CHAIN, None, Some(config))
}

/// A signed V5 transfer of `wallet` with nonce `nonce`.
pub(super) fn signed(wallet: &WalletKeyPair, nonce: u64, fee: u64) -> Transaction {
    let mut tx = Transaction::new_with_fee(
        wallet.address(),
        recipient(),
        AMOUNT,
        fee,
        nonce,
        Vec::new(),
    );
    tx.chain_id = CHAIN;
    tx.sign_v5(wallet);
    tx
}

/// The claimed forms of `txs` and one tick frame over their signatures.
fn tick(params: &AggParams, txs: &[Transaction]) -> (Vec<Transaction>, ClaimFrame) {
    let registry = SchemeStatusRegistry::genesis();
    let domain = claim_domain(CHAIN).expect("domain");
    let mut claimed = Vec::new();
    let mut items = Vec::new();
    for tx in txs {
        let (body, envelope) = claim_signature(tx).expect("a signed V5 transaction");
        let claim = derive_claim(&registry, &envelope).expect("the object verifies");
        items.push(PoolItem { envelope, claim });
        claimed.push(body);
    }
    let ctx = TickCtx {
        domain,
        aggregator: aggregator(),
    };
    let frame = ChainBackend::new(params, &registry)
        .prove_tick(&ctx, &items)
        .expect("tick");
    (claimed, frame)
}

/// The claimed form of one transaction and a tick frame over its signature.
fn tick_one(params: &AggParams, tx: &Transaction) -> (Transaction, ClaimFrame) {
    let (mut claimed, frame) = tick(params, std::slice::from_ref(tx));
    (claimed.remove(0), frame)
}

/// Two chains with the layer on and one block that carries a frame over the
/// signature of one transfer: produced by the first, not yet seen by the
/// second.
fn frame_block() -> (Blockchain, Blockchain, Block, Transaction) {
    let sender = wallet(1);
    let config = || genesis(Some(on()), &[sender.address()]);
    let mut left = chain(config());
    let right = chain(config());
    let tx = signed(&sender, 0, FEE);
    let (claimed, frame) = tick(&on(), std::slice::from_ref(&tx));
    left.set_block_frame(frame, claimed).expect("frame taken");
    let (block, _) = left.produce_block(producer()).expect("block");
    (left, right, block, tx)
}

/// Seal a block again after a change to its body or header.
fn reseal(block: &mut Block) {
    block.witness_root = Some(block.calculate_witness_root());
    block.tx_root = block.calculate_tx_root();
    block.hash = block.calculate_hash();
}

#[test]
fn a_claimed_transaction_keeps_its_id_and_loses_its_witness() {
    let sender = wallet(1);
    let tx = signed(&sender, 0, FEE);
    assert!(tx.verify());
    let (claimed, envelope) = claim_signature(&tx).expect("claimed");

    assert_eq!(claimed.hash, tx.hash);
    assert_eq!(claimed.signing_hash(), tx.signing_hash());
    assert!(claimed.signature.is_none());
    assert!(claimed.signer_public_key.is_empty());
    assert!(claimed.claimed_shape_is_canonical());
    // The object is the key and the signature the transaction carried.
    assert_eq!(envelope.payload.len(), 2592 + 4627);
    let domain = claim_domain(CHAIN).expect("domain");
    let claim = derive_claim(&SchemeStatusRegistry::genesis(), &envelope).expect("verifies");
    assert_eq!(claimed.auth_claim, Some(claim.digest(domain)));
    assert_eq!(account_claim(&claimed), Some(claim));
    // Nothing verifies a claimed transaction on its own.
    assert!(!claimed.verify());
    // A claimed transaction cannot be claimed again.
    assert!(claim_signature(&claimed).is_none());
}

#[test]
fn claim_references_are_inside_the_signing_hash() {
    let sender = wallet(1);
    let plain = signed(&sender, 0, FEE);
    let mut with_refs = plain.clone();
    with_refs.claim_refs = vec![[1; 32], [2; 32]];
    let mut swapped = plain.clone();
    swapped.claim_refs = vec![[2; 32], [1; 32]];
    let mut one = plain.clone();
    one.claim_refs = vec![[1; 32]];

    let hashes = [
        plain.signing_hash(),
        with_refs.signing_hash(),
        swapped.signing_hash(),
        one.signing_hash(),
    ];
    for (i, a) in hashes.iter().enumerate() {
        for b in hashes.iter().skip(i + 1) {
            assert_ne!(a, b);
        }
    }
    // The signature of the plain transaction does not cover the references:
    // adding one after signing breaks it.
    with_refs.hash = with_refs.calculate_hash();
    assert!(!with_refs.verify());
    with_refs.sign_v5(&sender);
    assert!(with_refs.verify());
}

#[test]
fn the_witness_bytes_of_a_claimed_transaction_carry_its_claim() {
    let sender = wallet(1);
    let tx = signed(&sender, 0, FEE);
    let (claimed, _) = claim_signature(&tx).expect("claimed");
    let mut other = claimed.clone();
    other.auth_claim = Some([9; 32]);
    let mut none = claimed.clone();
    none.auth_claim = None;
    assert_ne!(claimed.witness_bytes(), other.witness_bytes());
    assert_ne!(claimed.witness_bytes(), none.witness_bytes());
    assert_eq!(
        claimed.witness_bytes().len(),
        none.witness_bytes().len() + 33
    );
}

#[test]
fn a_block_with_a_frame_is_built_and_accepted_and_carries_no_signature_bytes() {
    let (mut left, mut right, block, tx) = frame_block();

    let frame = block
        .claim_frame
        .as_ref()
        .expect("the block carries a frame");
    let domain = claim_domain(CHAIN).expect("domain");
    assert_eq!(block.frame_hash, Some(frame.hash(domain).expect("hash")));
    assert_eq!(frame.claims.len(), 1);
    let carried = block
        .transactions
        .iter()
        .find(|t| t.hash == tx.hash)
        .expect("the transaction is in the block");
    assert!(carried.signature.is_none());
    assert!(carried.signer_public_key.is_empty());
    assert!(carried.is_claimed());

    right
        .validate_and_add_block(block.clone())
        .expect("the block is valid");
    assert_eq!(right.chain.len(), left.chain.len());
    assert_eq!(
        right.state.calculate_state_root(),
        left.state.calculate_state_root()
    );
    assert_eq!(right.state.get_balance(&recipient()), AMOUNT);
    assert_eq!(right.state.get_nonce(&tx.from), 1);
}

#[test]
fn claim_fees_leave_the_transaction_fee_and_reach_the_aggregator_and_the_producer() {
    let (left, _, _, _) = frame_block();
    let state = &left.state;
    // Half of the claim fee goes to the aggregator of the segment.
    assert_eq!(state.get_balance(&aggregator()), SIG_CLAIM_FEE / 2);
    // The producer earns the other half and what is left of the fee after
    // the claim fee and the burn.
    let rest = FEE - SIG_CLAIM_FEE;
    let burn = state.tokenomics.metabolic_burn(rest);
    assert_eq!(
        state.get_balance(&producer()),
        SIG_CLAIM_FEE / 2 + rest - burn
    );
    // The sender paid the amount and the fee, no more.
    assert_eq!(
        state.get_balance(&wallet(1).address()),
        10_000_000 - AMOUNT - FEE
    );
}

#[test]
fn a_block_with_a_frame_survives_the_wire_and_the_store() {
    let (_, _, block, _) = frame_block();

    let proto = crate::network::proto_conversions::pb::ProtoBlock::from(&block);
    let back = Block::try_from(proto).expect("the wire form decodes");
    assert_eq!(back, block);

    let stored = bincode::serialize(&block).expect("serialize");
    let back: Block = bincode::deserialize(&stored).expect("deserialize");
    assert_eq!(back, block);

    let json = serde_json::to_string(&block).expect("json");
    let back: Block = serde_json::from_str(&json).expect("json decodes");
    assert_eq!(back, block);
}

#[test]
fn a_chain_that_reorganizes_onto_a_block_with_a_frame_checks_it_and_agrees() {
    let (mut left, mut right, _, tx) = frame_block();
    assert!(right.try_reorg(left.chain.clone()).expect("reorg"));
    assert_eq!(
        right.state.calculate_state_root(),
        left.state.calculate_state_root()
    );
    assert_eq!(right.state.get_nonce(&tx.from), 1);
    assert_eq!(right.state.get_balance(&aggregator()), SIG_CLAIM_FEE / 2);
}

#[test]
fn a_candidate_chain_whose_frame_proof_is_wrong_is_refused() {
    let (left, mut right, _, _) = frame_block();
    let mut candidate = left.chain;
    let last = candidate.last_mut().expect("tip");
    let frame = last.claim_frame.as_mut().expect("frame");
    let at = frame.proof.len() - 1;
    frame.proof[at] ^= 0x01;
    let domain = claim_domain(CHAIN).expect("domain");
    last.frame_hash = Some(frame.hash(domain).expect("hash"));
    reseal(last);
    assert!(right.try_reorg(candidate).is_err());
    assert_eq!(right.chain.len(), 1);
}

#[test]
fn a_block_whose_frame_is_missing_or_swapped_is_refused() {
    // Frame hash without a frame.
    let (_, mut right, block, _) = frame_block();
    let mut bare = block.clone();
    bare.claim_frame = None;
    assert!(right
        .validate_and_add_block(bare)
        .unwrap_err()
        .contains("not both present"));

    // Frame without a frame hash.
    let mut unsealed = block.clone();
    unsealed.frame_hash = None;
    reseal(&mut unsealed);
    assert!(right
        .validate_and_add_block(unsealed)
        .unwrap_err()
        .contains("not both present"));

    // The frame of the body is not the frame of the header (rule 10).
    let mut swapped = block.clone();
    let frame = swapped.claim_frame.as_mut().expect("frame");
    let at = frame.proof.len() - 1;
    frame.proof[at] ^= 0x01;
    assert!(right
        .validate_and_add_block(swapped)
        .unwrap_err()
        .contains("frame hash"));

    // The untouched block is still accepted: nothing above changed the chain.
    right.validate_and_add_block(block).expect("valid");
}

#[test]
fn a_block_whose_frame_proof_does_not_verify_is_refused() {
    let (_, mut right, block, _) = frame_block();
    let mut forged = block;
    let frame = forged.claim_frame.as_mut().expect("frame");
    let at = frame.proof.len() - 1;
    frame.proof[at] ^= 0x01;
    let domain = claim_domain(CHAIN).expect("domain");
    forged.frame_hash = Some(frame.hash(domain).expect("hash"));
    reseal(&mut forged);
    assert!(right
        .validate_and_add_block(forged)
        .unwrap_err()
        .contains("proof"));
    assert_eq!(right.chain.len(), 1);
}

#[test]
fn a_block_whose_transaction_claims_another_digest_is_refused() {
    let (_, mut right, block, tx) = frame_block();

    // Changing the claim without resealing changes the witness root.
    let mut loose = block;
    for t in &mut loose.transactions {
        if t.hash == tx.hash {
            t.auth_claim = Some([7; 32]);
        }
    }
    assert!(right
        .validate_and_add_block(loose.clone())
        .unwrap_err()
        .contains("witness_root"));

    // Resealed, it breaks rule 6.
    reseal(&mut loose);
    assert!(right
        .validate_and_add_block(loose)
        .unwrap_err()
        .contains("claims the wrong digest"));
}

#[test]
fn a_claimed_transaction_that_still_carries_a_signature_is_refused() {
    let (_, mut right, block, tx) = frame_block();
    let mut doubled = block;
    for t in &mut doubled.transactions {
        if t.hash == tx.hash {
            t.signature = tx.signature.clone();
            t.signer_public_key = tx.signer_public_key.clone();
        }
    }
    reseal(&mut doubled);
    assert!(right
        .validate_and_add_block(doubled)
        .unwrap_err()
        .contains("carries a witness"));
}

#[test]
fn a_block_whose_claim_no_transaction_uses_is_refused() {
    let (_, mut right, block, tx) = frame_block();
    let mut orphaned = block;
    orphaned.transactions.retain(|t| t.hash != tx.hash);
    reseal(&mut orphaned);
    assert!(right
        .validate_and_add_block(orphaned)
        .unwrap_err()
        .contains("no transaction refers to claim"));
}

#[test]
fn a_block_whose_transaction_claims_without_a_frame_is_refused() {
    let (_, mut right, block, _) = frame_block();
    let mut bare = block;
    bare.claim_frame = None;
    bare.frame_hash = None;
    reseal(&mut bare);
    assert!(right
        .validate_and_add_block(bare)
        .unwrap_err()
        .contains("outside the frame"));
}

#[test]
fn an_inline_ml_dsa_signature_is_refused_while_the_layer_is_on() {
    let sender = wallet(1);
    let mut node = chain(genesis(Some(on()), &[sender.address()]));
    let tx = signed(&sender, 0, FEE);

    // The mempool does not take it.
    let error = node.add_transaction(tx.clone()).expect_err("refused");
    assert!(error.contains("travels as a claim"), "{error}");

    // A block that carries it inline breaks the block rule.
    let (mut block, _) = node.produce_block(producer()).expect("empty block");
    let mut peer = chain(genesis(Some(on()), &[sender.address()]));
    block.transactions.push(tx);
    reseal(&mut block);
    let error = peer.validate_and_add_block(block).unwrap_err();
    assert!(error.contains("quantum-safe signature inline"), "{error}");
}

#[test]
fn a_chain_with_the_layer_off_takes_no_claim_anywhere() {
    let sender = wallet(1);
    let config = || genesis(None, &[sender.address()]);
    let mut node = chain(config());
    let mut peer = chain(config());
    let tx = signed(&sender, 0, FEE);
    let (claimed, frame) = tick_one(&on(), &tx);

    // The producer door is closed.
    assert!(node
        .set_block_frame(frame.clone(), vec![claimed.clone()])
        .is_err());
    // The mempool takes neither a claimed transaction nor a claim reference.
    assert!(node.add_transaction(claimed.clone()).is_err());
    let mut with_ref = tx.clone();
    with_ref.claim_refs = vec![[3; 32]];
    with_ref.sign_v5(&sender);
    let error = node.add_transaction(with_ref).expect_err("refused");
    assert!(error.contains("aggregation is not on"), "{error}");
    // The inline transaction is what it always was.
    node.add_transaction(tx).expect("an inline V5 transaction");

    // A block that uses the layer is refused whatever it carries.
    let (block, _) = node.produce_block(producer()).expect("block");
    let domain = claim_domain(CHAIN).expect("domain");
    let mut framed = block.clone();
    framed.frame_hash = Some(frame.hash(domain).expect("hash"));
    framed.claim_frame = Some(frame);
    reseal(&mut framed);
    let error = peer.validate_and_add_block(framed).unwrap_err();
    assert!(error.contains("aggregation is not on"), "{error}");
    let mut claimed_block = block.clone();
    claimed_block.transactions.push(claimed);
    reseal(&mut claimed_block);
    let error = peer.validate_and_add_block(claimed_block).unwrap_err();
    assert!(error.contains("aggregation is not on"), "{error}");
    // The block as built is valid: the layer changes nothing while off.
    peer.validate_and_add_block(block).expect("valid");
}

#[test]
fn the_genesis_of_a_chain_with_the_layer_on_commits_to_its_parameters() {
    let off = genesis(None, &[]).build_genesis_block();
    let explicit_off = genesis(Some(AggParams::default()), &[]).build_genesis_block();
    let shadow = genesis(
        Some(AggParams {
            mode: AggMode::Shadow,
            ..AggParams::default()
        }),
        &[],
    )
    .build_genesis_block();
    let on_block = genesis(Some(on()), &[]).build_genesis_block();
    let dearer = genesis(
        Some(AggParams {
            claim_fee_per_byte: 65,
            ..on()
        }),
        &[],
    )
    .build_genesis_block();

    // Off and Shadow change no rule: the genesis is the one it always was.
    assert_eq!(off.frame_hash, None);
    assert_eq!(off.hash, explicit_off.hash);
    assert_eq!(off.hash, shadow.hash);
    // On is another chain, and so is On with another consensus parameter.
    assert_eq!(on_block.frame_hash, genesis_commitment(&on(), CHAIN));
    assert!(on_block.frame_hash.is_some());
    assert_ne!(on_block.hash, off.hash);
    assert_ne!(on_block.hash, dearer.hash);
    // A node-local parameter is not consensus.
    let slower = genesis(
        Some(AggParams {
            tick_ms: 2000,
            ..on()
        }),
        &[],
    )
    .build_genesis_block();
    assert_eq!(on_block.hash, slower.hash);

    // A genesis block that claims another commitment is not this chain's.
    let registry = SchemeStatusRegistry::genesis();
    assert!(check_block(&on(), &registry, &on_block).is_ok());
    assert!(check_block(&on(), &registry, &off).is_err());
    assert!(check_block(&AggParams::default(), &registry, &on_block).is_err());
}

#[test]
fn parameters_a_chain_cannot_run_with_are_refused_at_startup() {
    assert!(validate_params(&AggParams::default(), CHAIN).is_ok());
    assert!(validate_params(&on(), CHAIN).is_ok());
    // The main network keeps the layer off.
    assert!(validate_params(&on(), 45260).is_err());
    assert!(validate_params(&AggParams::default(), 45260).is_ok());
    // A share over the whole.
    assert!(validate_params(
        &AggParams {
            agg_share_bps: 10_001,
            ..AggParams::default()
        },
        CHAIN
    )
    .is_err());
    // A limit the wire cannot carry.
    assert!(validate_params(
        &AggParams {
            max_claims_per_block: 65_537,
            ..AggParams::default()
        },
        CHAIN
    )
    .is_err());
    // A chain id that is no claim domain.
    assert!(validate_params(&on(), u64::from(u32::MAX) + 1).is_err());
}

#[test]
fn a_transaction_that_cannot_pay_for_its_claim_fails_and_the_producer_drops_its_frame() {
    let sender = wallet(1);
    let dear = AggParams {
        claim_fee_per_byte: 10_000,
        ..on()
    };
    let mut node = chain(genesis(Some(dear), &[sender.address()]));
    let tx = signed(&sender, 0, FEE);
    let (claimed, frame) = tick_one(&dear, &tx);

    // The settlement of a block that carried it: the transaction fails and
    // nobody is paid; the claim stays in the frame.
    let mut probe = Block::new_with_chain_id(1, "0".repeat(64), vec![claimed.clone()], CHAIN);
    probe.claim_frame = Some(frame.clone());
    let fees = settlement_of(&dear, &probe).expect("settles");
    assert_eq!(fees.failed, vec![true]);
    assert_eq!(fees.charged, vec![0]);
    assert_eq!(fees.payout.aggregators, vec![(aggregator(), 0)]);
    assert_eq!(fees.payout.producer, 0);

    // The producer does not put such a frame into a block.
    node.set_block_frame(frame, vec![claimed]).expect("taken");
    let (block, _) = node.produce_block(producer()).expect("block");
    assert!(block.claim_frame.is_none());
    assert!(block.frame_hash.is_none());
    assert!(block.transactions.iter().all(|t| !t.uses_claims()));
    assert_eq!(node.state.get_nonce(&sender.address()), 0);
}

#[test]
fn a_failed_transaction_is_not_executed_and_pays_nothing() {
    let sender = wallet(1);
    let mut state: AccountState = genesis(Some(on()), &[sender.address()]).build_state();
    let (claimed, _) = claim_signature(&signed(&sender, 0, FEE)).expect("claimed");
    let before = state.calculate_state_root();
    let failed = ClaimSettlement {
        charged: vec![0],
        failed: vec![true],
        payout: FeePayout {
            aggregators: vec![(aggregator(), 0)],
            producer: 0,
        },
    };
    Executor::apply_block_candidate_with_claims(
        &mut state,
        std::slice::from_ref(&claimed),
        Some(&producer()),
        &failed,
    )
    .expect("the block applies");
    assert_eq!(state.calculate_state_root(), before);
    assert_eq!(state.get_nonce(&sender.address()), 0);
    assert_eq!(state.get_balance(&producer()), 0);
}

#[test]
fn a_claim_fee_above_the_fee_of_its_payer_stops_the_block() {
    let sender = wallet(1);
    let mut state: AccountState = genesis(Some(on()), &[sender.address()]).build_state();
    let (claimed, _) = claim_signature(&signed(&sender, 0, FEE)).expect("claimed");
    // A settlement no valid block has: it charges more than the fee.
    let overcharged = ClaimSettlement {
        charged: vec![FEE + 1],
        failed: vec![false],
        payout: FeePayout::default(),
    };
    assert!(Executor::apply_block_candidate_with_claims(
        &mut state,
        std::slice::from_ref(&claimed),
        Some(&producer()),
        &overcharged,
    )
    .is_err());
}
