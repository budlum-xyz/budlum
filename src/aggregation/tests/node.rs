//! The aggregation side of a node: a signed transaction goes in through the
//! same door as any other, its object is verified once, a tick proves it and
//! the next block carries the frame and the transaction without a witness.

use super::chain::{
    aggregator, aggregator_seed, chain, genesis, on, producer, recipient, signed, wallet, AMOUNT,
    CHAIN, FEE, SIG_CLAIM_FEE,
};
use crate::aggregation::chain::{claim_signature, decode_gossip_frame};
use crate::aggregation::frame::aggregator_address_from_seed;
use crate::aggregation::node::ObjectRefusal;
use crate::aggregation::object::ObjectError;
use crate::aggregation::pool::Rejection;
use crate::chain::blockchain::Blockchain;
use crate::core::address::Address;
use crate::core::transaction::Transaction;
use crate::crypto::primitives::WalletKeyPair;
use crate::network::protocol::{NetworkMessage, MAX_AGG_OBJECT_BYTES};
use zeroize::Zeroizing;

/// A chain with the layer on, `funded` holding a balance, and the
/// aggregation side running with `seed`.
fn node_with_seed(funded: &[&WalletKeyPair], seed: [u8; 32]) -> (Blockchain, Address) {
    let addresses: Vec<Address> = funded.iter().map(|wallet| wallet.address()).collect();
    let mut chain = chain(genesis(Some(on()), &addresses));
    assert!(chain.enable_aggregator(Zeroizing::new(seed)).is_some());
    let addr = aggregator_address_from_seed(&seed).expect("valid seed");
    (chain, addr)
}

fn node(funded: &[&WalletKeyPair], seed: [u8; 32]) -> Blockchain {
    node_with_seed(funded, seed).0
}

/// A signed V5 transfer of `amount`.
fn transfer(wallet: &WalletKeyPair, nonce: u64, amount: u64) -> Transaction {
    let mut tx = Transaction::new_with_fee(
        wallet.address(),
        recipient(),
        amount,
        FEE,
        nonce,
        Vec::new(),
    );
    tx.chain_id = CHAIN;
    tx.sign_v5(wallet);
    tx
}

#[test]
fn the_aggregation_side_only_runs_where_the_layer_is_on() {
    let sender = wallet(1);
    let mut off = chain(genesis(None, &[sender.address()]));
    assert_eq!(off.enable_aggregator(aggregator_seed()), None);
    // Without it the transaction takes the old road, signature and all.
    off.add_transaction(signed(&sender, 0, FEE)).expect("pool");
    assert_eq!(off.mempool.len(), 1);
    assert!(off.aggregation_tick().is_empty());
    assert!(off.receive_frame(&[1, 2, 3]).is_err());

    let mut live = chain(genesis(Some(on()), &[sender.address()]));
    assert_eq!(
        live.enable_aggregator(aggregator_seed()),
        Some(on().tick_ms)
    );
}

#[test]
fn a_signed_transaction_goes_through_the_pool_into_a_block() {
    let sender = wallet(1);
    let mut left = node(&[&sender], *aggregator_seed());
    let mut right = chain(genesis(Some(on()), &[sender.address()]));
    let tx = signed(&sender, 0, FEE);

    left.add_transaction(tx.clone()).expect("admitted");
    // The mempool never sees it: it waits with its object.
    assert_eq!(left.mempool.len(), 0);
    // Nothing is proven yet, so the next block has nothing to carry.
    let (empty, _) = left.produce_block(producer()).expect("block");
    assert!(empty.claim_frame.is_none() && empty.transactions.is_empty());
    right.validate_and_add_block(empty).expect("valid");

    let frames = left.aggregation_tick();
    assert_eq!(frames.len(), 1);
    let frame = decode_gossip_frame(&frames[0]).expect("frame");
    assert_eq!(frame.claims.len(), 1);
    assert_eq!(frame.segments[0].aggregator, aggregator());

    let (block, _) = left.produce_block(producer()).expect("block");
    assert_eq!(block.claim_frame.as_ref(), Some(&frame));
    assert_eq!(block.transactions.len(), 1);
    let carried = &block.transactions[0];
    assert_eq!(carried.hash, tx.hash);
    assert!(carried.signature.is_none() && carried.signer_public_key.is_empty());

    // A node that never saw the object accepts the block and ends in the
    // same state.
    right.validate_and_add_block(block).expect("valid");
    assert_eq!(
        right.state.calculate_state_root(),
        left.state.calculate_state_root()
    );
    assert_eq!(left.state.get_balance(&recipient()), AMOUNT);
    assert_eq!(left.state.get_nonce(&sender.address()), 1);
    assert_eq!(left.state.get_balance(&aggregator()), SIG_CLAIM_FEE / 2);
    assert_eq!(
        left.state.get_balance(&producer()),
        SIG_CLAIM_FEE / 2 + (FEE - SIG_CLAIM_FEE)
            - left.state.tokenomics.metabolic_burn(FEE - SIG_CLAIM_FEE)
    );
    // The sender paid the amount and the fee, no more.
    assert_eq!(
        left.state.get_balance(&sender.address()),
        10_000_000 - AMOUNT - FEE
    );

    // The frame is spent: a later tick has nothing to publish and the next
    // block carries no frame.
    assert!(left.aggregation_tick().is_empty());
    let (after, _) = left.produce_block(producer()).expect("block");
    assert!(after.claim_frame.is_none() && after.transactions.is_empty());
}

#[test]
fn an_object_from_a_peer_is_taken_once_and_a_bad_one_blames_the_peer() {
    let sender = wallet(1);
    let mut node = node(&[&sender], *aggregator_seed());
    let tx = signed(&sender, 0, FEE);
    let (claimed, envelope) = claim_signature(&tx).expect("claimed");
    let bytes = envelope.encode();

    // A forged signature: the pool verifies the object itself.
    let mut forged = envelope;
    let last = forged.payload.len() - 1;
    forged.payload[last] ^= 0x01;
    let refusal = node
        .receive_object(&forged.encode(), claimed.clone())
        .unwrap_err();
    assert_eq!(
        refusal,
        ObjectRefusal::Pool(Rejection::Object(ObjectError::Invalid))
    );
    assert!(refusal.blames_peer());

    // The object of one transaction with another transaction.
    let other = claim_signature(&signed(&sender, 0, FEE + 1))
        .expect("claimed")
        .0;
    let refusal = node.receive_object(&bytes, other).unwrap_err();
    assert_eq!(refusal, ObjectRefusal::NotTheClaimedForm);
    assert!(refusal.blames_peer());

    // The transaction with its witness still on it.
    let refusal = node.receive_object(&bytes, tx).unwrap_err();
    assert_eq!(refusal, ObjectRefusal::NotTheClaimedForm);

    // Bytes that are no envelope.
    let refusal = node
        .receive_object(&bytes[..bytes.len() - 1], claimed.clone())
        .unwrap_err();
    assert!(matches!(refusal, ObjectRefusal::Malformed(_)));
    assert!(refusal.blames_peer());

    // A transaction that cannot run here is refused before any signature
    // is checked, and the peer may simply be ahead: no blame.
    let (ahead, ahead_envelope) = claim_signature(&signed(&sender, 7, FEE)).expect("claimed");
    let refusal = node
        .receive_object(&ahead_envelope.encode(), ahead)
        .unwrap_err();
    assert!(matches!(refusal, ObjectRefusal::Transaction(_)));
    assert!(!refusal.blames_peer());

    // None of the refusals left anything behind.
    assert!(node.aggregation_tick().is_empty());

    assert_eq!(node.receive_object(&bytes, claimed.clone()), Ok(true));
    assert_eq!(node.receive_object(&bytes, claimed.clone()), Ok(false));
    assert_eq!(node.aggregation_tick().len(), 1);

    // A node that runs no aggregator takes no object.
    let mut plain = chain(genesis(Some(on()), &[sender.address()]));
    let refusal = plain.receive_object(&bytes, claimed).unwrap_err();
    assert_eq!(refusal, ObjectRefusal::NoAggregator);
    assert!(!refusal.blames_peer());
}

#[test]
fn a_producer_carries_the_frame_of_another_aggregator() {
    let sender = wallet(1);
    let (mut prover, first) = node_with_seed(&[&sender], [0xA1; 32]);
    let mut builder = node(&[&sender], [0xB7; 32]);
    let tx = signed(&sender, 0, FEE);
    let (claimed, envelope) = claim_signature(&tx).expect("claimed");

    // Both hear the object; only the first proves before the block.
    prover.add_transaction(tx).expect("admitted");
    assert_eq!(
        builder.receive_object(&envelope.encode(), claimed),
        Ok(true)
    );
    let frames = prover.aggregation_tick();
    assert_eq!(frames.len(), 1);

    // A frame that does not verify is refused; the real one is taken once.
    let mut broken = frames[0].clone();
    let last = broken.len() - 1;
    broken[last] ^= 0x01;
    assert!(builder.receive_frame(&broken).is_err());
    assert!(builder.receive_frame(&frames[0][..last]).is_err());

    // A frame for a held claim whose segment attestation is forged is refused.
    let mut bad_attestation = decode_gossip_frame(&frames[0]).expect("frame");
    bad_attestation.segments[0].attestation.signature[0] ^= 0x01;
    assert!(builder.receive_frame(&bad_attestation.encode()).is_err());

    assert_eq!(builder.receive_frame(&frames[0]), Ok(true));
    assert_eq!(builder.receive_frame(&frames[0]), Ok(false));

    // A frame for claims `builder` does NOT hold in `AggNode` is ignored
    // (`Ok(false)`) without failing or spending signature checks.
    let other_sender = wallet(9);
    let mut orphan = node(&[&other_sender], [0xC1; 32]);
    let other_tx = transfer(&other_sender, 0, 1);
    orphan.add_transaction(other_tx).expect("admitted");
    let orphan_frames = orphan.aggregation_tick();
    assert_eq!(orphan_frames.len(), 1);
    assert_eq!(builder.receive_frame(&orphan_frames[0]), Ok(false));

    let (block, _) = builder.produce_block(producer()).expect("block");
    let frame = block.claim_frame.as_ref().expect("frame");
    assert_eq!(frame.segments.len(), 1);
    assert_eq!(frame.segments[0].aggregator, first);
    prover.validate_and_add_block(block).expect("valid");
    // The aggregator that proved is paid, wherever the block was built.
    assert_eq!(prover.state.get_balance(&first), SIG_CLAIM_FEE / 2);
    assert_eq!(
        prover.state.calculate_state_root(),
        builder.state.calculate_state_root()
    );
    // The prover saw its frame go into a block: nothing is left to publish
    // or to carry.
    assert!(prover.aggregation_tick().is_empty());
    let (after, _) = prover.produce_block(first).expect("block");
    assert!(after.claim_frame.is_none());
}

#[test]
fn transactions_of_one_sender_wait_in_nonce_order_and_a_held_nonce_is_refused() {
    let sender = wallet(1);
    let other = wallet(2);
    let mut node = node(&[&sender, &other], *aggregator_seed());

    node.add_transaction(transfer(&sender, 0, 5))
        .expect("first");
    // The second one is checked behind the first: nonce 1, on what the
    // first leaves.
    node.add_transaction(transfer(&sender, 1, 6))
        .expect("second");
    node.add_transaction(transfer(&other, 0, 7))
        .expect("other sender");
    // Another transaction for a nonce that is taken.
    let error = node.add_transaction(transfer(&sender, 1, 8)).unwrap_err();
    assert!(
        error.contains("Invalid nonce") || error.contains("holds the nonce"),
        "{error}"
    );
    // A gap.
    assert!(node.add_transaction(transfer(&sender, 3, 9)).is_err());
    // More than the pending ones leave.
    assert!(node
        .add_transaction(transfer(&sender, 2, 10_000_000))
        .is_err());

    assert_eq!(node.aggregation_tick().len(), 1);
    let (block, _) = node.produce_block(producer()).expect("block");
    assert_eq!(block.claim_frame.as_ref().map(|f| f.claims.len()), Some(3));
    let order: Vec<(Address, u64)> = block
        .transactions
        .iter()
        .map(|tx| (tx.from, tx.nonce))
        .collect();
    let at = |address: Address, nonce: u64| {
        order
            .iter()
            .position(|entry| *entry == (address, nonce))
            .expect("in the block")
    };
    assert!(at(sender.address(), 0) < at(sender.address(), 1));
    assert_eq!(order.len(), 3);
    assert_eq!(node.state.get_balance(&recipient()), 18);
    assert_eq!(node.state.get_nonce(&sender.address()), 2);
}

#[test]
fn a_transaction_that_can_no_longer_run_is_dropped_and_the_chain_goes_on() {
    let sender = wallet(1);
    let other = wallet(2);
    let mut node = node(&[&sender, &other], *aggregator_seed());
    let mut rival = self::node(&[&sender, &other], [0xA2; 32]);

    // Two ticks, so the two transactions of the sender sit in two frames.
    node.add_transaction(transfer(&sender, 0, 5))
        .expect("first");
    assert_eq!(node.aggregation_tick().len(), 1);
    node.add_transaction(transfer(&sender, 1, 6))
        .expect("second");
    assert!(!node.aggregation_tick().is_empty());

    // The sender spends nearly everything through another node, with the
    // same nonce 0, and keeps one fee and three units. That block arrives
    // first.
    let drained = 10_000_000 - FEE - (FEE + 3);
    rival
        .add_transaction(transfer(&sender, 0, drained))
        .expect("rival");
    assert_eq!(rival.aggregation_tick().len(), 1);
    let (block, _) = rival.produce_block(producer()).expect("block");
    assert!(block.claim_frame.is_some());
    node.validate_and_add_block(block).expect("valid");

    // Nonce 0 is behind the state and went with the block. Nonce 1 is next
    // in line and its frame is whole, but the sender cannot pay for it any
    // more: the producer drops it instead of building a block nobody
    // accepts, and builds the block without a frame.
    let (plain, _) = node.produce_block(producer()).expect("block");
    assert!(plain.claim_frame.is_none() && plain.transactions.is_empty());
    rival.validate_and_add_block(plain).expect("valid");

    // The dropped transaction no longer holds its nonce: one the sender can
    // still pay for takes it, and a frame over the new objects goes in as
    // before.
    node.add_transaction(transfer(&sender, 1, 2))
        .expect("the nonce is free again");
    node.add_transaction(transfer(&other, 0, 7))
        .expect("other sender");
    assert!(!node.aggregation_tick().is_empty());
    let (block, _) = node.produce_block(producer()).expect("block");
    assert_eq!(block.claim_frame.as_ref().map(|f| f.claims.len()), Some(2));
    assert_eq!(block.transactions.len(), 2);
    rival.validate_and_add_block(block).expect("valid");
    assert_eq!(rival.state.get_nonce(&sender.address()), 2);
}

#[test]
fn dropped_transaction_clears_stale_claim_and_allows_resubmission() {
    let sender = wallet(1);
    let funder = wallet(2);
    let mut node = node(&[&sender, &funder], *aggregator_seed());
    let mut rival = self::node(&[&sender, &funder], [0xA2; 32]);

    // Prove nonce 0 and nonce 1 on `node`.
    node.add_transaction(transfer(&sender, 0, 5))
        .expect("nonce 0");
    assert_eq!(node.aggregation_tick().len(), 1);
    let original_nonce_1 = transfer(&sender, 1, 6);
    node.add_transaction(original_nonce_1.clone())
        .expect("nonce 1");
    assert!(!node.aggregation_tick().is_empty());

    // `rival` commits a different nonce 0 that drains `sender` below `FEE + 6`.
    let drained = 10_000_000 - FEE - (FEE + 3);
    rival
        .add_transaction(transfer(&sender, 0, drained))
        .expect("rival nonce 0");
    assert_eq!(rival.aggregation_tick().len(), 1);
    let (drain_block, _) = rival.produce_block(producer()).expect("drain block");
    node.validate_and_add_block(drain_block)
        .expect("node accepts drain block");

    // `node` cannot run `original_nonce_1` now and drops it along with its
    // proven claim and zombie frame.
    let (plain, _) = node.produce_block(producer()).expect("empty block");
    assert!(plain.claim_frame.is_none() && plain.transactions.is_empty());

    // Top up `sender` from `funder` so `original_nonce_1` is affordable again.
    // Because the dead frames were dropped, this tick produces exactly one
    // frame instead of merging with a zombie frame.
    let mut top_up = Transaction::new_with_fee(
        funder.address(),
        sender.address(),
        1_000,
        FEE,
        0,
        Vec::new(),
    );
    top_up.chain_id = CHAIN;
    top_up.sign_v5(&funder);
    node.add_transaction(top_up).expect("top up");
    assert_eq!(node.aggregation_tick().len(), 1);
    let (fund_block, _) = node.produce_block(producer()).expect("fund block");
    assert_eq!(fund_block.transactions.len(), 1);

    // Resubmitting the exact same signed `original_nonce_1` must not remain
    // trapped behind stale `claims`/`seen` state from the dropped run; it must
    // re-enter, prove into a fresh frame, and execute in a block.
    node.add_transaction(original_nonce_1)
        .expect("resubmission of dropped tx");
    let frames = node.aggregation_tick();
    assert_eq!(frames.len(), 1);
    let (block, _) = node.produce_block(producer()).expect("final block");
    assert_eq!(block.transactions.len(), 1);
    assert_eq!(node.state.get_nonce(&sender.address()), 2);
}

#[test]
fn objects_and_frames_cross_the_wire_and_the_message_layer_bounds_them() {
    let sender = wallet(1);
    let mut node = node(&[&sender], *aggregator_seed());
    let tx = signed(&sender, 0, FEE);
    let (claimed, envelope) = claim_signature(&tx).expect("claimed");

    let message = NetworkMessage::AggObject {
        envelope: envelope.encode(),
        transaction: claimed.clone(),
    };
    let bytes = message.to_bytes();
    // The object is the heavy part: the signature and the key travel once.
    assert!(bytes.len() > 7219 && bytes.len() < 7219 + 1024);
    match NetworkMessage::from_bytes(&bytes).expect("decodes") {
        NetworkMessage::AggObject {
            envelope: got,
            transaction,
        } => {
            assert_eq!(got, envelope.encode());
            assert_eq!(transaction, claimed);
            assert_eq!(node.receive_object(&got, transaction), Ok(true));
        }
        other => panic!("not an object: {other:?}"),
    }

    let frames = node.aggregation_tick();
    let bytes = NetworkMessage::AggFrame(frames[0].clone()).to_bytes();
    match NetworkMessage::from_bytes(&bytes).expect("decodes") {
        NetworkMessage::AggFrame(got) => assert_eq!(got, frames[0]),
        other => panic!("not a frame: {other:?}"),
    }

    // The message layer refuses an envelope over the limit, an empty one
    // and an empty frame before anything else looks at them.
    let oversized = NetworkMessage::AggObject {
        envelope: vec![0; MAX_AGG_OBJECT_BYTES + 1],
        transaction: claimed.clone(),
    };
    assert!(NetworkMessage::from_bytes(&oversized.to_bytes()).is_err());
    let empty = NetworkMessage::AggObject {
        envelope: Vec::new(),
        transaction: claimed,
    };
    assert!(NetworkMessage::from_bytes(&empty.to_bytes()).is_err());
    assert!(NetworkMessage::from_bytes(&NetworkMessage::AggFrame(Vec::new()).to_bytes()).is_err());
}

#[test]
fn frames_stay_within_the_proof_limit_and_every_transaction_gets_its_block() {
    let senders: Vec<WalletKeyPair> = (1..=5).map(wallet).collect();
    let addresses: Vec<Address> = senders.iter().map(WalletKeyPair::address).collect();
    // Room for the proof of two signature objects, not three.
    let tight = crate::aggregation::params::AggParams {
        max_proof_bytes: 2 * 7262 + 64,
        ..on()
    };
    let mut left = chain(genesis(Some(tight), &addresses));
    let mut right = chain(genesis(Some(tight), &addresses));
    assert!(left.enable_aggregator(aggregator_seed()).is_some());
    for sender in &senders {
        left.add_transaction(signed(sender, 0, FEE))
            .expect("admitted");
    }

    // The chain never stops: every round yields a block the other node
    // accepts, and after a few rounds every transaction is in one.
    let mut carried = 0;
    for _ in 0..6 {
        left.aggregation_tick();
        let (block, _) = left.produce_block(producer()).expect("a block every round");
        if let Some(frame) = block.claim_frame.as_ref() {
            assert!(frame.proof.len() <= tight.max_proof_bytes);
        }
        carried += block.transactions.len();
        right.validate_and_add_block(block).expect("valid");
    }
    assert_eq!(carried, 5);
    assert_eq!(left.state.get_balance(&recipient()), 5 * AMOUNT);
}

#[test]
fn the_frame_counts_toward_the_block_size() {
    use crate::crypto::primitives::KeyPair;
    // 36 signature objects are the most a proof of 262144 bytes holds.
    let senders: Vec<WalletKeyPair> = (1..=36).map(wallet).collect();
    let classical = KeyPair::generate().expect("key");
    let payer = Address::from(classical.public_key_bytes());
    let mut addresses: Vec<Address> = senders.iter().map(WalletKeyPair::address).collect();
    addresses.push(payer);
    let mut left = chain(genesis(Some(on()), &addresses));
    let mut right = chain(genesis(Some(on()), &addresses));
    assert!(left.enable_aggregator(aggregator_seed()).is_some());
    for sender in &senders {
        left.add_transaction(signed(sender, 0, FEE))
            .expect("admitted");
    }
    assert_eq!(left.aggregation_tick().len(), 1);
    // Six transactions of about 120 kB of JSON each wait in the mempool:
    // with the frame they are more than a block holds.
    for nonce in 0..6u64 {
        let mut tx =
            Transaction::new_with_fee(payer, recipient(), 1, 1_000_000, nonce, vec![0u8; 60_000]);
        tx.chain_id = CHAIN;
        tx.sign(&classical);
        left.mempool.add_transaction(tx).expect("pool");
    }

    let (block, _) = left.produce_block(producer()).expect("block");
    let frame = block.claim_frame.as_ref().expect("the frame is carried");
    assert_eq!(frame.claims.len(), 36);
    let size = serde_json::to_vec(&block).expect("json").len();
    assert!(
        size <= crate::consensus::MAX_BLOCK_SIZE,
        "the block is {size} bytes"
    );
    // The frame took its share; some of the mempool waits for the next
    // block, and what went in is valid everywhere.
    let inline = block.transactions.len() - 36;
    assert!((1..6).contains(&inline), "{inline} mempool transactions");
    right.validate_and_add_block(block).expect("valid");
}

#[test]
fn a_proof_limit_no_block_could_carry_is_refused_at_genesis() {
    use crate::aggregation::chain::validate_params;
    let third = crate::consensus::MAX_BLOCK_SIZE / 3;
    let fits = crate::aggregation::params::AggParams {
        max_proof_bytes: third,
        ..on()
    };
    assert_eq!(validate_params(&fits, CHAIN), Ok(()));
    let over = crate::aggregation::params::AggParams {
        max_proof_bytes: third + 1,
        ..on()
    };
    assert!(validate_params(&over, CHAIN)
        .unwrap_err()
        .contains("max_proof_bytes"));
    // While the layer is off the limit binds nothing.
    let off = crate::aggregation::params::AggParams {
        max_proof_bytes: third + 1,
        ..crate::aggregation::params::AggParams::default()
    };
    assert_eq!(validate_params(&off, CHAIN), Ok(()));
}

#[test]
fn a_block_whose_transactions_use_claims_passes_the_wire_scan_of_gossip() {
    use crate::core::block::Block;
    // Gossip reads a message through `from_bytes_validated`, whose scan
    // lets a transaction carry one typed payload and every field once. A
    // claimed transaction with claim references has to get through it,
    // inside an object and inside a block.
    let sender = wallet(1);
    let mut tx = signed(&sender, 0, FEE);
    tx.claim_refs = vec![[1; 32], [2; 32], [3; 32]];
    tx.hash = tx.calculate_hash();
    tx.sign_v5(&sender);
    let (claimed, envelope) = claim_signature(&tx).expect("claimed");
    assert_eq!(claimed.claim_refs.len(), 3);

    let object = NetworkMessage::AggObject {
        envelope: envelope.encode(),
        transaction: claimed.clone(),
    };
    match NetworkMessage::from_bytes_validated(&object.to_bytes()).expect("object") {
        NetworkMessage::AggObject { transaction, .. } => assert_eq!(transaction, claimed),
        other => panic!("not an object: {other:?}"),
    }

    let mut block = Block::new_with_chain_id(1, "00".repeat(32), vec![claimed.clone()], CHAIN);
    block.frame_hash = Some([7; 32]);
    block.hash = block.calculate_hash();
    match NetworkMessage::from_bytes_validated(&NetworkMessage::Block(block).to_bytes())
        .expect("block")
    {
        NetworkMessage::Block(got) => {
            assert_eq!(got.transactions, vec![claimed.clone()]);
            assert_eq!(got.frame_hash, Some([7; 32]));
        }
        other => panic!("not a block: {other:?}"),
    }

    // The scan reaches the transaction inside an object: one over the
    // transaction size limit is refused there, as it is on `transactions`.
    let mut heavy = claimed;
    heavy.data = vec![0; crate::network::protocol::MAX_TX_SIZE + 1];
    let object = NetworkMessage::AggObject {
        envelope: envelope.encode(),
        transaction: heavy,
    };
    assert!(matches!(
        NetworkMessage::from_bytes_validated(&object.to_bytes()),
        Err(crate::network::protocol::MessageError::TooLarge(_))
    ));
}
