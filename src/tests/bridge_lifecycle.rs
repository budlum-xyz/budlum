//! Integration test for the bridge lock → mint → burn → unlock happy path
//!. After the `bud_lockBridgeTransfer` RPC was
//! Removed (it allowed an unauthenticated caller to lock any `asset_id`
//! Forever), the canonical bridge lifecycle is exercised here through
//! The *internal* `Blockchain::lock_bridge_transfer` system path.

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;

use crate::domain::plugin::default_domain;
use crate::domain::ConsensusKind;
use std::sync::Arc;

fn addr(b: u8) -> Address {
    Address::from([b; 32])
}

fn asset_id() -> crate::cross_domain::AssetId {
    crate::cross_domain::AssetId([42u8; 32])
}

/// A refused lock (insufficient balance) must not leave a lock record in
/// the bridge state: the balance check runs before the in-memory insert,
/// so a refusal cannot leave a phantom lock that a later sweep would
/// "refund" out of thin air.
#[test]
fn a_refused_lock_leaves_no_bridge_record() {
    let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None);
    for (id, operator) in [(1u32, addr(11)), (2u32, addr(12))] {
        let mut d = default_domain(id, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 1);
        d.operator = Some(operator);
        d.operator_bond = 100_000;
        d.bridge_enabled = true;
        bc.register_consensus_domain(d)
            .expect("domain must register");
    }
    bc.register_bridge_asset(asset_id(), 1)
        .expect("asset must register");

    let owner = addr(77);
    let recipient = addr(12);
    // Whatever the owner starts with, one unit more than that cannot be
    // locked, so the lock must be refused...
    let impossible = bc.state.get_balance(&owner).saturating_add(1).max(1);
    let refused =
        bc.lock_bridge_transfer(1, 2, 20, 0, asset_id(), owner, recipient, impossible, 1000);
    assert!(
        refused.is_err(),
        "an owner short of the amount must not lock"
    );
    // ...and the refusal must not leave a phantom lock behind: nothing is
    // locked, and nothing can be swept at the phantom expiry.
    assert_eq!(
        bc.state.bridge_state.locked_amount_total(),
        0,
        "a refused lock must not leave a bridge record"
    );
    assert!(
        bc.apply_bridge_sweep(1000).is_empty(),
        "a refused lock must not be swept back as a refund"
    );

    // After the refusal the same path still works for a funded owner.
    bc.state.add_balance(&owner, 1_000_000);
    let (_transfer, lock_event) = bc
        .lock_bridge_transfer(1, 2, 20, 0, asset_id(), owner, recipient, 100, 1000)
        .expect("a funded owner must lock");
    assert!(matches!(
        lock_event.kind,
        crate::cross_domain::DomainEventKind::BridgeLocked
    ));
}

/// Bridge end-to-end: register domains, register the asset, lock through
/// The internal system path, mint on the target side, burn on the source,
/// And unlock. All via the *internal* `Blockchain` API - the RPC surface
/// No longer exposes the unauthenticated `lock_bridge_transfer` entry.
#[test]
fn bridge_lock_mint_burn_unlock_lifecycle() {
    let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None);

    // Step 1: register both domains.
    for (id, operator) in [(1u32, addr(11)), (2u32, addr(12))] {
        let mut d = default_domain(id, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 1);
        d.operator = Some(operator);
        d.operator_bond = 100_000;
        d.bridge_enabled = true;
        bc.register_consensus_domain(d)
            .expect("domain must register");
    }

    // Step 2: register the bridge asset.
    bc.register_bridge_asset(asset_id(), 1)
        .expect("asset must register");

    let owner = addr(11);
    let recipient = addr(12);
    // Lock debits owner balance - fund accounts.
    bc.fund_development_account(&owner).expect("devnet faucet");
    bc.fund_development_account(&recipient)
        .expect("devnet faucet");

    // Bridge lock now debits owner balance, so the owner must
    // Have sufficient funds before locking.
    bc.fund_development_account(&owner).expect("devnet faucet");
    bc.state.add_balance(&owner, 1_000_000);

    // Step 3: lock via the internal path (the only path that exists
    // - RPC is closed).
    let (_transfer, lock_event) = bc
        .lock_bridge_transfer(1, 2, 20, 0, asset_id(), owner, recipient, 100, 1000)
        .expect("internal lock must succeed");
    let message_id = lock_event.message.as_ref().unwrap().message_id;

    // Step 4: sweep MUST NOT release the lock yet (expiry_height=1000,
    // Current=0).
    let released_early = bc.apply_bridge_sweep(0);
    assert!(
        released_early.is_empty(),
        "no lock should be released at height 0"
    );

    // Step 5: sweep at expiry_height (=1000) releases the lock.
    let released = bc.apply_bridge_sweep(1000);
    assert_eq!(
        released.len(),
        1,
        "exactly one lock must be released at expiry"
    );
    // Sweep returns (owner, amount) for balance refund.
    assert_eq!(released[0].0, owner);
    assert_eq!(released[0].1.get(), 100);

    // The asset is back to `Active` and reusable.
    let fresh = bc
        .lock_bridge_transfer(1, 2, 21, 0, asset_id(), owner, recipient, 50, 1500)
        .expect("fresh lock after sweep must succeed");
    assert!(matches!(
        fresh.1.kind,
        crate::cross_domain::DomainEventKind::BridgeLocked
    ));

    // Step 6: the original `message_id` lock (released in step 5) is
    // Still in the transfer ledger as `Active` and CANNOT be minted.
    // Use an arbitrary-but-valid commitment block hash: this mint
    // Will fail either at the forgery gate (no matching commitment
    // Exists for this exact block hash) or at the bridge-state level
    // (the lock has been released). Both are acceptable, the test's
    // Contract is "the released lock cannot be minted".
    let bad_mint = bc.mint_bridge_transfer_from_verified_event(
        1,
        20,
        0,
        Some([0xAAu8; 32]),
        lock_event.clone(),
        &crate::cross_domain::MerkleProof {
            leaf: [0u8; 32],
            index: 0,
            siblings: vec![],
        },
        Address::zero(),
    );
    assert!(
        bad_mint.is_err(),
        "mint of an already-released lock must fail"
    );
    let _ = message_id; // silence unused warning (kept for the regression witness)
}

/// BLG-0108 (P05-F01): a full lock/mint/burn/unlock cycle conserves the
/// total supply. Burn is the debit half of mint: without it, each cycle
/// mints one transfer amount out of thin air (the F01 inflation bug).
#[test]
fn bridge_lock_mint_burn_unlock_conserves_supply() {
    let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None);
    for (id, operator) in [(1u32, addr(11)), (2u32, addr(12))] {
        let mut d = default_domain(id, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 1);
        d.operator = Some(operator);
        d.operator_bond = 100_000;
        d.bridge_enabled = true;
        bc.register_consensus_domain(d).expect("domain");
    }
    bc.register_bridge_asset(asset_id(), 1).expect("asset");
    let owner = addr(77);
    let recipient = addr(12);
    bc.state.add_balance(&owner, 1_000);
    bc.state.add_balance(&recipient, 0);

    // The relayer's fee leg is part of the supply: the mint pays it out of the
    // arriving asset, so conservation counts the relayer's balance too.
    let relayer = addr(99);
    let sum = |bc: &Blockchain| -> u64 {
        bc.state.get_balance(&owner)
            + bc.state.get_balance(&recipient)
            + bc.state.get_balance(&relayer)
    };
    let start = sum(&bc);
    assert_eq!(start, 1_000);

    // The two legs of the arriving asset, as the production mint splits them.
    let params = *bc.state.registry.params();
    let (held, fee) = crate::cross_domain::bridge::split_bridge_fee(
        crate::core::money::Bud::new(400),
        params.bridge_relayer_fee_ppm,
        params.bridge_relayer_min_fee,
    )
    .expect("a 400 transfer covers the fee");
    let (held, fee) = (held.get(), fee.get());
    assert_eq!(held + fee, 400);

    // Lock: the owner's units move into the bridge.
    let (_transfer, lock_event) = bc
        .lock_bridge_transfer(1, 2, 20, 0, asset_id(), owner, recipient, 400, 1_000)
        .expect("lock");
    let lock_message = lock_event.message.clone().expect("lock carries a message");
    // The lock debits the owner into escrow (BLG-0118): the units leave the
    // live balances and sit in the transfer row until the mint credits them,
    // so conservation counts the escrow.
    let escrowed = bc
        .state
        .bridge_state
        .transfer(&lock_message.message_id)
        .map(|t| t.amount.get())
        .expect("the lock registered its transfer");
    assert_eq!(escrowed, 400);
    assert_eq!(
        sum(&bc) + escrowed,
        start,
        "lock must move units into escrow, not destroy them"
    );

    // Mint on the target side: the row flips, the recipient and the relayer
    // are credited the two legs.
    bc.state
        .bridge_state
        .mint(&lock_message, 20)
        .expect("mint the locked transfer");
    bc.state.get_or_create(&recipient).balance += held;
    bc.state.get_or_create(&relayer).balance += fee;
    assert_eq!(sum(&bc), start, "mint is the credit half of lock");

    // Burn on the target side: the fix - the burn TAKES the recipient's
    // units back (what it was credited, not the relayer's fee).
    let message_id = lock_message.message_id;
    let burn_event = bc
        .burn_bridge_transfer_with_event(message_id, 2, 40, 0, 0, [7u8; 20])
        .expect("burn the minted transfer");
    assert_eq!(
        sum(&bc),
        start - held,
        "burn must debit the minted units (BLG-0108)"
    );

    // Unlock on the source side: the owner is credited back what was burned.
    let burn_message = burn_event.message.clone().expect("burn carries a message");
    bc.state
        .bridge_state
        .unlock(message_id, 2, 40)
        .expect("unlock the burned transfer");
    bc.state.get_or_create(&owner).balance += held;
    assert_eq!(
        sum(&bc),
        start,
        "the full cycle must conserve supply exactly"
    );
    let _ = burn_message;
}

/// Sweep at multiple heights: an expired lock is released, a non-expired
/// Lock is preserved, and the released lock stays `Active` on repeated
/// Calls (idempotency).
#[test]
fn bridge_sweep_is_height_aware_and_idempotent() {
    let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None);
    bc.fund_development_account(&addr(11))
        .expect("devnet faucet");
    bc.fund_development_account(&addr(12))
        .expect("devnet faucet");
    for (id, operator) in [(1u32, addr(11)), (2u32, addr(12))] {
        let mut d = default_domain(id, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 1);
        d.operator = Some(operator);
        d.operator_bond = 100_000;
        d.bridge_enabled = true;
        bc.register_consensus_domain(d).unwrap();
    }
    bc.register_bridge_asset(asset_id(), 1).unwrap();
    let owner = addr(11);
    let recipient = addr(12);

    // Bridge lock debits owner balance
    bc.fund_development_account(&owner).expect("devnet faucet");
    bc.state.add_balance(&owner, 1_000_000);

    // Two locks: one expiring at 100, one at 500.
    bc.lock_bridge_transfer(1, 2, 20, 0, asset_id(), owner, recipient, 100, 100)
        .unwrap();
    bc.lock_bridge_transfer(1, 2, 21, 0, asset_id(), owner, recipient, 50, 500)
        .expect_err("asset must be Locked → second lock of the same asset must fail");

    // Re-register the asset to get a fresh one for the second lock:
    // The sweep test is simpler with two distinct assets.
    let asset_b = crate::cross_domain::AssetId([43u8; 32]);
    bc.register_bridge_asset(asset_b, 1).unwrap();
    bc.lock_bridge_transfer(1, 2, 21, 0, asset_b, owner, recipient, 50, 500)
        .unwrap();

    // At height 99, neither lock has expired.
    let r = bc.apply_bridge_sweep(99);
    assert_eq!(r.len(), 0, "no lock expires at height 99");

    // At height 100, the first lock expires; the second does not.
    let r = bc.apply_bridge_sweep(100);
    assert_eq!(
        r.len(),
        1,
        "only the 100-expiry lock releases at height 100"
    );
    // (Owner, amount)
    assert_eq!(r[0].0, owner);
    assert_eq!(r[0].1.get(), 100);

    // The 100-expiry lock is now Active and the asset is reusable,
    // But the second lock (expiry=500) still holds asset_b as Locked.
    let r2 = bc
        .lock_bridge_transfer(1, 2, 22, 0, asset_id(), owner, recipient, 10, 200)
        .expect("asset_id must be reusable after sweep");
    assert!(matches!(
        r2.1.kind,
        crate::cross_domain::DomainEventKind::BridgeLocked
    ));

    // Re-running the sweep at the same height releases nothing new.
    let r_dup = bc.apply_bridge_sweep(100);
    assert_eq!(r_dup.len(), 0, "sweep is idempotent at the same height");

    // At height 500, the second lock (expiry=500) releases; the
    // Re-locked asset_id (expiry=200) is also past its expiry at
    // Height 500, so it releases too. We assert >= 1 (the asset_b
    // Release is the contract-bearing observation) and that asset_b
    // Is among the released set.
    let r3 = bc.apply_bridge_sweep(500);
    // Returns owner addresses; asset_b lock owner is `owner`.
    assert!(
        r3.iter().any(|(a, amt)| *a == owner && amt.get() == 50),
        "owner must be refunded 50 for asset_b lock at height 500: {r3:?}"
    );
}

/// (security audit §9) bridge mint MUST reject calls that pass
/// `expected_block_hash = None`. Without an explicit block-hash bound,
/// A caller could pick ANY commitment matching (domain_id, height,
/// Sequence) - including stale or finality-unconfirmed ones, and
/// Mint against it. The forgery gate forces the caller to bind the
/// Mint to a specific block.
#[test]
fn bridge_mint_forgery_gate_rejects_none_expected_block_hash() {
    use crate::consensus::pos::PoSConfig;
    use crate::consensus::pos::PoSEngine;
    use std::sync::Arc;

    let mut bc = Blockchain::new(
        Arc::new(PoSEngine::new(PoSConfig::default(), None)),
        None,
        45262,
        None,
    );
    bc.fund_development_account(&addr(11))
        .expect("devnet faucet");
    bc.fund_development_account(&addr(12))
        .expect("devnet faucet");
    for (id, operator) in [(1u32, addr(11)), (2u32, addr(12))] {
        let mut d = default_domain(id, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 1);
        d.operator = Some(operator);
        d.bridge_enabled = true;
        bc.register_consensus_domain(d).unwrap();
    }
    bc.register_bridge_asset(asset_id(), 1).unwrap();

    let owner = addr(11);
    let recipient = addr(12);

    // Bridge lock debits owner balance
    bc.fund_development_account(&owner).expect("devnet faucet");
    bc.state.add_balance(&owner, 1_000_000);

    let (_transfer, lock_event) = bc
        .lock_bridge_transfer(1, 2, 30, 0, asset_id(), owner, recipient, 200, 5000)
        .expect("internal lock must succeed");

    // Forge an attempt to mint with NO expected_block_hash. The forgery
    // Gate must short-circuit the call before any merkle / commitment
    // Lookup is even attempted.
    let result = bc.mint_bridge_transfer_from_verified_event(
        1,
        30,
        0,
        None,
        lock_event.clone(),
        &crate::cross_domain::MerkleProof {
            leaf: [0u8; 32],
            index: 0,
            siblings: vec![],
        },
        Address::zero(),
    );
    assert!(
        result.is_err(),
        "bridge mint with None expected_block_hash must fail (forgery gate)"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("forgery gate") || err.contains("expected_block_hash"),
        "error message must surface the forgery-gate rationale, got: {err}"
    );

    // And the same gate must apply to the unlock path.
    let unlock_result = bc.unlock_bridge_transfer_from_verified_event(
        2,
        30,
        0,
        None,
        lock_event,
        &crate::cross_domain::MerkleProof {
            leaf: [0u8; 32],
            index: 0,
            siblings: vec![],
        },
    );
    assert!(
        unlock_result.is_err(),
        "bridge unlock with None expected_block_hash must fail (forgery gate)"
    );
    let unlock_err = unlock_result.unwrap_err();
    assert!(
        unlock_err.contains("forgery gate") || unlock_err.contains("expected_block_hash"),
        "unlock error message must surface the forgery-gate rationale, got: {unlock_err}"
    );
}

/// The burn moves state in block, not on the request path.
///
/// `Blockchain::burn_bridge_transfer_with_event` used to debit the recipient
/// and write `bridge_state` when the RPC was called. Both are folded into the
/// state root, so a node that served the call and a node that did not disagreed
/// until a state sync. The `BridgeBurn` transaction reaches the same body
/// ([`crate::cross_domain::bridge::apply_burn_to_state`]) through the
/// executor, and this test drives that exact path: build the signed
/// transaction, apply it with the executor, and assert the debit landed and the
/// relay request did not.
#[test]
fn a_bridge_burn_moves_balance_in_block_and_defers_the_relay_enqueue() {
    use crate::execution::executor::Executor;

    // A PoS engine WITH a signer: the door this test exercises builds a signed
    // transaction, and a node with no consensus signer cannot (the same rule
    // `build_state_update_transaction` follows for the domain-commitment path).
    let keypair = crate::crypto::primitives::KeyPair::generate().expect("a keypair");
    let signer = Arc::new(crate::crypto::signer::KeyPairSigner::new(keypair));
    let mut bc = Blockchain::new(
        Arc::new(crate::consensus::pos::PoSEngine::with_signer(
            crate::consensus::pos::PoSConfig::default(),
            None,
            signer,
        )),
        None,
        45262,
        None,
    );
    for (id, operator) in [(1u32, addr(11)), (2u32, addr(12))] {
        let mut d = default_domain(id, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 1);
        d.operator = Some(operator);
        d.operator_bond = 100_000;
        d.bridge_enabled = true;
        bc.register_consensus_domain(d).expect("domain");
    }
    bc.register_bridge_asset(asset_id(), 1).expect("asset");
    let owner = addr(77);
    let recipient = addr(12);
    bc.state.add_balance(&owner, 1_000);

    let (_transfer, lock_event) = bc
        .lock_bridge_transfer(1, 2, 20, 0, asset_id(), owner, recipient, 400, 1_000)
        .expect("lock");
    let message_id = lock_event
        .message
        .as_ref()
        .expect("lock message")
        .message_id;
    let params = *bc.state.registry.params();
    let (held, fee) = crate::cross_domain::bridge::split_bridge_fee(
        crate::core::money::Bud::new(400),
        params.bridge_relayer_fee_ppm,
        params.bridge_relayer_min_fee,
    )
    .expect("a 400 transfer covers the fee");
    let (held, fee) = (held.get(), fee.get());
    bc.state
        .bridge_state
        .mint(lock_event.message.as_ref().expect("lock message"), 20)
        .expect("mint");
    bc.state.get_or_create(&recipient).balance += held;
    bc.state.get_or_create(&addr(99)).balance += fee;

    // The signed transaction a node would gossip.
    let tx = bc
        .build_bridge_burn_transaction(crate::core::transaction::BridgeBurnTx {
            message_id,
            domain: 2,
            domain_height: 40,
            event_index: 0,
            expiry_height: 0,
            recipient_eth: [7u8; 20],
        })
        .expect("this node can sign");
    assert!(
        matches!(
            tx.tx_type,
            crate::core::transaction::TransactionType::BridgeBurn(_)
        ),
        "the door is a transaction, not a method call"
    );

    // The signer pays the fee, so the signer has to be able to.
    let payer = tx.from;
    bc.state.add_balance(&payer, 1_000);

    let before = bc.state.get_balance(&recipient);
    assert_eq!(before, held, "the recipient holds what the mint credited");

    // In block: the executor applies it.
    let mut state = bc.state.clone();
    Executor::apply_transaction(&mut state, &tx).expect("the burn executes in block");

    assert_eq!(
        state.get_balance(&recipient),
        before - held,
        "the burn must take the minted units back inside block execution"
    );
    assert_eq!(
        state
            .bridge_state
            .transfer(&message_id)
            .map(|t| format!("{:?}", t.status)),
        Some(format!(
            "{:?}",
            crate::cross_domain::bridge::BridgeStatus::Burned { domain: 2 }
        )),
        "the row flips inside block execution"
    );
    assert_eq!(
        state.pending_bridge_burns.len(),
        1,
        "the relay request waits for the node, it is not written by the executor"
    );
    // The burn's OWN message is registered by the same body, inside the same
    // execution - that is the half that must not wait for the node.
    let burn_message = state
        .pending_bridge_burns
        .first()
        .and_then(|event| event.message.as_ref())
        .expect("the burn carries a message");
    assert!(
        state
            .message_registry
            .get(&burn_message.message_id)
            .is_some(),
        "the message the far side unlocks against is registered in block"
    );
    assert_ne!(
        burn_message.message_id, message_id,
        "the burn message is its own id, correlated with the lock's"
    );

    // Draining the queue performs the node-local half and nothing else.
    let mut bc = bc;
    bc.state = state;
    assert_eq!(bc.drain_pending_bridge_burns(), 1);
    assert!(
        bc.state.pending_bridge_burns.is_empty(),
        "the queue is drained once"
    );
    assert_eq!(
        bc.state.get_balance(&recipient),
        before - held,
        "draining the relay queue must not move the balance again"
    );
}
