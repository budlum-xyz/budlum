//! The executor's storage arm: manifest registration in block.
//!
//! The registry rules live in `src/domain/storage_tx.rs` and are unit-tested
//! there. This file pins what only the block-application path can see: the
//! frame refusal for a value-carrying storage tx, the fee and nonce
//! epilogue, that a refusal charges nothing, and that the write reaches the
//! state root, which is the reason it has to happen in a block at all.

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType, DEFAULT_CHAIN_ID};
use crate::domain::storage_deal::OperatorClass;
use crate::domain::StorageTx;
use crate::execution::executor::Executor;
use crate::storage::{
    encode_object, ContentId, ContentManifest, ErasureScheme, MobileAvailabilityClass,
    MobileSelfContentPolicy, MobileSelfProfile,
};

fn addr(byte: u8) -> Address {
    Address::from([byte; 32])
}

fn manifest_owned_by(owner: Address) -> ContentManifest {
    let bytes: Vec<u8> = (0..4096u32).map(|i| (i % 253) as u8).collect();
    let mut m = encode_object(&bytes, ErasureScheme { k: 4, n: 6 })
        .expect("encode")
        .to_manifest()
        .expect("manifest");
    m.owner = owner;
    m
}

fn storage_tx(from: Address, amount: u64, body: StorageTx, nonce: u64) -> Transaction {
    Transaction::new_with_chain_id(
        from,
        Address::zero(),
        amount,
        1,
        nonce,
        vec![],
        DEFAULT_CHAIN_ID,
        TransactionType::Storage(body),
    )
}

fn apply(state: &mut AccountState, tx: Transaction) -> Result<(), String> {
    Executor::apply_transaction_checked(state, &tx)
        .map_err(|e| format!("{}: {}", e.code(), e.message()))
}

#[test]
fn a_manifest_registers_in_block_and_moves_the_state_root() {
    let alice = addr(1);
    let mut state = AccountState::new();
    state.add_balance(&alice, 1_000);
    let before = state.calculate_state_root();
    let m = manifest_owned_by(alice);

    apply(
        &mut state,
        storage_tx(
            alice,
            0,
            StorageTx::RegisterManifest {
                manifest: m.clone(),
            },
            0,
        ),
    )
    .expect("the owner registers its manifest");

    assert_eq!(
        state.storage_registry.get_manifest(&m.manifest_id),
        Some(&m)
    );
    assert_eq!(state.get_balance(&alice), 999, "the fee is charged");
    assert_eq!(state.get_nonce(&alice), 1, "the nonce advances");
    assert_ne!(
        state.calculate_state_root(),
        before,
        "a registry write that does not reach the root would let nodes disagree silently"
    );
}

#[test]
fn a_storage_tx_carrying_value_is_refused_before_anything_moves() {
    let alice = addr(1);
    let mut state = AccountState::new();
    state.add_balance(&alice, 1_000);
    let m = manifest_owned_by(alice);

    let err = apply(
        &mut state,
        storage_tx(
            alice,
            5,
            StorageTx::RegisterManifest {
                manifest: m.clone(),
            },
            0,
        ),
    )
    .unwrap_err();

    assert!(err.contains("storage_amount_must_be_zero"), "{err}");
    assert!(state
        .storage_registry
        .get_manifest(&m.manifest_id)
        .is_none());
    assert_eq!(state.get_balance(&alice), 1_000);
    assert_eq!(state.get_nonce(&alice), 0);
}

#[test]
fn a_refused_registration_charges_nothing() {
    let alice = addr(1);
    let mallory = addr(2);
    let mut state = AccountState::new();
    state.add_balance(&mallory, 1_000);
    let m = manifest_owned_by(alice);

    let err = apply(
        &mut state,
        storage_tx(
            mallory,
            0,
            StorageTx::RegisterManifest {
                manifest: m.clone(),
            },
            0,
        ),
    )
    .unwrap_err();

    assert!(err.contains("storage_tx_failed"), "{err}");
    assert!(state
        .storage_registry
        .get_manifest(&m.manifest_id)
        .is_none());
    assert_eq!(state.get_balance(&mallory), 1_000);
    assert_eq!(state.get_nonce(&mallory), 0);
}

#[test]
fn the_signature_commits_the_fields_the_manifest_id_leaves_out() {
    let alice = addr(1);
    let m = manifest_owned_by(alice);
    let hash_of = |manifest: ContentManifest| {
        storage_tx(alice, 0, StorageTx::RegisterManifest { manifest }, 0).calculate_hash()
    };
    let base = hash_of(m.clone());

    let mut other_owner = m.clone();
    other_owner.owner = addr(9);
    assert_ne!(hash_of(other_owner), base, "owner is outside the id");

    let mut other_len = m.clone();
    other_len.content_size = m.content_size.saturating_sub(1);
    assert_ne!(
        hash_of(other_len),
        base,
        "content_size is committed by the signature"
    );
}

fn declare_policy_tx(from: Address, m: &ContentManifest, nonce: u64) -> Transaction {
    storage_tx(
        from,
        0,
        StorageTx::DeclareSelfHostPolicy {
            manifest_id: m.manifest_id,
            policy: self_host_policy(from, m),
            profile: self_host_profile(from),
        },
        nonce,
    )
}

fn self_host_policy(owner: Address, m: &ContentManifest) -> MobileSelfContentPolicy {
    MobileSelfContentPolicy {
        content_id: m.shards[0].shard_id,
        owner,
        critical: false,
        required_paid_replicas: 1,
        self_host_allowed: true,
    }
}

fn self_host_profile(owner: Address) -> MobileSelfProfile {
    MobileSelfProfile {
        owner,
        device_commitment: [3u8; 32],
        availability: MobileAvailabilityClass::Scheduled,
        max_storage_bytes: 1 << 20,
        metered_network_ok: false,
        battery_saver_aware: true,
        last_seen_block: 5,
    }
}

#[test]
fn an_operator_class_declaration_moves_the_state_root_and_charges_the_fee() {
    let alice = addr(1);
    let mut state = AccountState::new();
    state.add_balance(&alice, 1_000);
    let before = state.calculate_state_root();

    apply(
        &mut state,
        storage_tx(
            alice,
            0,
            StorageTx::DeclareOperatorClass {
                class: OperatorClass::Mobile,
            },
            0,
        ),
    )
    .expect("the operator declares its class");

    assert_eq!(
        state.storage_registry.operator_class(&alice),
        OperatorClass::Mobile
    );
    assert_eq!(state.get_balance(&alice), 999);
    assert_eq!(state.get_nonce(&alice), 1);
    assert_ne!(state.calculate_state_root(), before);
}

#[test]
fn a_refused_class_declaration_charges_nothing() {
    let alice = addr(1);
    let mut state = AccountState::new();
    state.add_balance(&alice, 1_000);

    let err = apply(
        &mut state,
        storage_tx(
            alice,
            0,
            StorageTx::DeclareOperatorClass {
                class: OperatorClass::AlwaysOn,
            },
            0,
        ),
    )
    .unwrap_err();

    assert!(err.contains("storage_tx_failed"), "{err}");
    assert_eq!(state.get_balance(&alice), 1_000);
    assert_eq!(state.get_nonce(&alice), 0);
}

#[test]
fn a_self_host_policy_declaration_moves_the_state_root_and_charges_the_fee() {
    let alice = addr(1);
    let mut state = AccountState::new();
    state.add_balance(&alice, 1_000);
    let m = manifest_owned_by(alice);
    apply(
        &mut state,
        storage_tx(
            alice,
            0,
            StorageTx::RegisterManifest {
                manifest: m.clone(),
            },
            0,
        ),
    )
    .expect("register");
    let before = state.calculate_state_root();

    apply(&mut state, declare_policy_tx(alice, &m, 1)).expect("the owner declares");

    assert!(state
        .storage_registry
        .self_host_policies
        .contains_key(&(m.manifest_id, m.shards[0].shard_id)));
    assert_eq!(state.get_balance(&alice), 998);
    assert_eq!(state.get_nonce(&alice), 2);
    assert_ne!(state.calculate_state_root(), before);
}

#[test]
fn a_refused_self_host_policy_charges_nothing() {
    let alice = addr(1);
    let mut state = AccountState::new();
    state.add_balance(&alice, 1_000);
    let m = manifest_owned_by(alice);

    let err = apply(&mut state, declare_policy_tx(alice, &m, 0)).unwrap_err();

    assert!(err.contains("storage_tx_failed"), "{err}");
    assert!(state.storage_registry.self_host_policies.is_empty());
    assert_eq!(state.get_balance(&alice), 1_000);
    assert_eq!(state.get_nonce(&alice), 0);
}

#[test]
fn the_signature_commits_every_policy_and_profile_field() {
    let alice = addr(1);
    let m = manifest_owned_by(alice);
    let hash_of =
        |manifest_id: ContentId, policy: MobileSelfContentPolicy, profile: MobileSelfProfile| {
            storage_tx(
                alice,
                0,
                StorageTx::DeclareSelfHostPolicy {
                    manifest_id,
                    policy,
                    profile,
                },
                0,
            )
            .calculate_hash()
        };
    let policy = self_host_policy(alice, &m);
    let profile = self_host_profile(alice);
    let base = hash_of(m.manifest_id, policy.clone(), profile.clone());

    let with_policy = |f: &dyn Fn(&mut MobileSelfContentPolicy)| {
        let mut p = policy.clone();
        f(&mut p);
        hash_of(m.manifest_id, p, profile.clone())
    };
    let with_profile = |f: &dyn Fn(&mut MobileSelfProfile)| {
        let mut p = profile.clone();
        f(&mut p);
        hash_of(m.manifest_id, policy.clone(), p)
    };

    assert_ne!(
        hash_of(ContentId([1u8; 32]), policy.clone(), profile.clone()),
        base
    );
    assert_ne!(with_policy(&|p| p.content_id = ContentId([2u8; 32])), base);
    assert_ne!(with_policy(&|p| p.owner = addr(9)), base);
    assert_ne!(with_policy(&|p| p.critical = true), base);
    assert_ne!(with_policy(&|p| p.required_paid_replicas = 2), base);
    assert_ne!(with_policy(&|p| p.self_host_allowed = false), base);
    assert_ne!(with_profile(&|p| p.owner = addr(9)), base);
    assert_ne!(with_profile(&|p| p.device_commitment = [4u8; 32]), base);
    assert_ne!(
        with_profile(&|p| p.availability = MobileAvailabilityClass::Opportunistic),
        base
    );
    assert_ne!(
        with_profile(&|p| p.availability = MobileAvailabilityClass::AlwaysOnReplica),
        base
    );
    assert_ne!(with_profile(&|p| p.max_storage_bytes = 2), base);
    assert_ne!(with_profile(&|p| p.metered_network_ok = true), base);
    assert_ne!(with_profile(&|p| p.battery_saver_aware = false), base);
    assert_ne!(with_profile(&|p| p.last_seen_block = 6), base);
}

#[test]
fn the_signature_commits_the_declared_operator_class() {
    let alice = addr(1);
    let hash_of =
        |class| storage_tx(alice, 0, StorageTx::DeclareOperatorClass { class }, 0).calculate_hash();
    assert_ne!(
        hash_of(OperatorClass::AlwaysOn),
        hash_of(OperatorClass::Mobile)
    );
}

fn register_hash(from: Address, manifest: ContentManifest) -> String {
    storage_tx(from, 0, StorageTx::RegisterManifest { manifest }, 0).calculate_hash()
}

#[test]
fn the_registration_signature_commits_the_whole_manifest() {
    let alice = addr(1);
    let m = manifest_owned_by(alice);
    let base = register_hash(alice, m.clone());
    let changed = |f: &dyn Fn(&mut ContentManifest)| {
        let mut c = m.clone();
        f(&mut c);
        register_hash(alice, c)
    };

    assert_ne!(
        changed(&|c| c.shards[0].shard_id = ContentId([7u8; 32])),
        base
    );
    assert_ne!(changed(&|c| c.shards[1].index += 1), base);
    assert_ne!(changed(&|c| c.shards[1].size += 1), base);
    assert_ne!(
        changed(&|c| c.shards[0].kind = crate::storage::ShardKind::Parity),
        base
    );
    assert_ne!(changed(&|c| c.erasure.k += 1), base);
    assert_ne!(changed(&|c| c.erasure.n += 1), base);
    assert_ne!(
        changed(&|c| c.dictionary_id = Some(ContentId([5u8; 32]))),
        base
    );
    assert_ne!(
        changed(
            &|c| c.encryption = crate::storage::ContentEncryption::ClientSide(
                crate::storage::ContentCipher::Aes256Gcm
            )
        ),
        base
    );
    assert_ne!(
        changed(&|c| c.edition = crate::storage::BudStorageEdition::Three),
        base
    );
    assert_ne!(
        changed(&|c| c.source = crate::storage::ContentSource::Generated(generated_spec())),
        base
    );
    assert_ne!(changed(&|c| c.shard_count += 1), base);
}

fn generated_spec() -> crate::storage::generated::GeneratedSpec {
    crate::storage::generated::GeneratedSpec {
        generator: crate::storage::generated::GeneratorId::Avatar,
        seed: [1u8; 32],
        output_len: 64,
        step_budget: 10,
    }
}

#[test]
fn two_splits_of_source_and_dictionary_get_different_ids() {
    let alice = addr(1);
    let spec = generated_spec();
    let digest = ContentId(crate::storage::generated::generated_spec_digest(&spec));
    let a = manifest_owned_by(alice).with_source(crate::storage::ContentSource::Generated(spec));
    // The same 32 bytes worn as a dictionary commitment instead of as the
    // generated-source commitment. First as a stale-id mutation: the id the
    // clone carries was derived from the source reading, so verification
    // must refuse it outright.
    let mut stale = a.clone();
    stale.source = crate::storage::ContentSource::Stored;
    stale.dictionary_id = Some(digest);
    assert!(stale.verify_id().is_err());
    // Then built honestly, so the ids can be compared as ids: the dictionary
    // bytes carry a label in the preimage, so they cannot mimic the source
    // bytes and the two manifests must not collide.
    let b = manifest_owned_by(alice).with_dictionary_id(Some(digest));
    assert!(b.verify_id().is_ok());
    assert_ne!(a.manifest_id, b.manifest_id);
    assert_ne!(register_hash(alice, a), register_hash(alice, b));
}

#[test]
fn a_generated_registration_is_refused_and_charges_nothing() {
    let alice = addr(1);
    let mut state = AccountState::new();
    state.add_balance(&alice, 1_000);
    let m = manifest_owned_by(alice)
        .with_source(crate::storage::ContentSource::Generated(generated_spec()));

    let err = apply(
        &mut state,
        storage_tx(
            alice,
            0,
            StorageTx::RegisterManifest {
                manifest: m.clone(),
            },
            0,
        ),
    )
    .unwrap_err();

    assert!(err.contains("storage_tx_failed"), "{err}");
    assert!(err.contains("not priced"), "{err}");
    assert!(state
        .storage_registry
        .get_manifest(&m.manifest_id)
        .is_none());
    assert_eq!(state.get_balance(&alice), 1_000);
    assert_eq!(state.get_nonce(&alice), 0);
}

/// Opening a deal in block: the payer is the sender and the operator's bond
/// is locked only with the operator's own signed consent.
#[cfg(feature = "wallet-ml-dsa")]
mod open_deal {
    use super::*;
    use crate::crypto::primitives::WalletKeyPair;
    use crate::domain::storage_deal::{StorageEconomicsParams, FEE_RATE_SCALE};
    use crate::domain::storage_params::STORAGE_MIN_OPERATOR_BOND;
    use crate::domain::{
        open_deal_consent_digest, StorageDealOpen, MISSED_CHALLENGE_COOLDOWN_SECS,
    };
    use crate::storage::GrantAuthorization;

    const MAINNET: u64 = 45260;
    const PAYER_FUNDS: u64 = 5_000;
    /// Ten epochs at ten base units an epoch.
    const DEAL_FEE: u64 = 100;
    /// The fee `storage_tx` puts on every transaction.
    const TX_FEE: u64 = 1;

    fn proof() -> Vec<u8> {
        let envelope = bud_proof::ProofEnvelope {
            proof_format_version: 1,
            backend: "test-backend".to_string(),
            p3_version: "0.6".to_string(),
            fri_params_id: "test-fri".to_string(),
            public_inputs_hash: [0x42u8; 32],
            proof_bytes: vec![0xABu8; 96],
            degree_bits: 8,
        };
        bincode::serialize(&envelope).unwrap()
    }

    fn payer() -> Address {
        addr(21)
    }

    fn deal_manifest() -> ContentManifest {
        let mut m = ContentManifest::from_bytes_sliced(b"open a deal in block payload", 8).unwrap();
        m.owner = payer();
        m
    }

    /// A chain with the manifest registered, the payer funded and an operator
    /// that holds enough for the bond.
    fn world() -> (AccountState, ContentManifest, WalletKeyPair) {
        let mut state = AccountState::new();
        let m = deal_manifest();
        state.storage_registry.register_manifest(&m);
        state.add_balance(&payer(), PAYER_FUNDS);
        let op = WalletKeyPair::generate();
        state.add_balance(&op.address(), STORAGE_MIN_OPERATOR_BOND * 2);
        (state, m, op)
    }

    fn unsigned_body(m: &ContentManifest, op: &WalletKeyPair) -> StorageDealOpen {
        let shard_bytes = u64::from(m.shards[0].size);
        StorageDealOpen {
            domain_id: 42,
            manifest_id: m.manifest_id,
            shard_id: m.shards[0].shard_id,
            operator: op.address(),
            replica_index: 0,
            start_epoch: 0,
            end_epoch: 10,
            economics: StorageEconomicsParams {
                operator_bond: STORAGE_MIN_OPERATOR_BOND,
                fee_per_byte_epoch: 10 * (FEE_RATE_SCALE as u64) / shard_bytes,
            },
            merkle_proof: proof(),
            storage_root: [0x42u8; 32],
            operator_consent: GrantAuthorization {
                owner_key: op.public_key_bytes(),
                signature: Vec::new(),
            },
        }
    }

    fn consent(
        op: &WalletKeyPair,
        chain_id: u64,
        payer_address: &Address,
        nonce: u64,
        body: &StorageDealOpen,
    ) -> GrantAuthorization {
        let digest = open_deal_consent_digest(chain_id, payer_address, nonce, body);
        GrantAuthorization {
            owner_key: op.public_key_bytes(),
            signature: op.sign(&digest).to_vec(),
        }
    }

    /// A body signed for the payer's current nonce on the default chain.
    fn signed_body(m: &ContentManifest, op: &WalletKeyPair) -> StorageDealOpen {
        let mut body = unsigned_body(m, op);
        body.operator_consent = consent(op, DEFAULT_CHAIN_ID, &payer(), 0, &body);
        body
    }

    fn open_tx(body: StorageDealOpen, chain_id: u64) -> Transaction {
        Transaction::new_with_chain_id(
            payer(),
            Address::zero(),
            0,
            TX_FEE,
            0,
            vec![],
            chain_id,
            TransactionType::Storage(StorageTx::OpenDeal(Box::new(body))),
        )
    }

    /// What a refused open must leave exactly as it was.
    fn snapshot(state: &mut AccountState, op: &Address) -> (u64, u64, u64, String) {
        (
            state.get_balance(&payer()),
            state.get_balance(op),
            state.get_nonce(&payer()),
            state.calculate_state_root(),
        )
    }

    /// Apply the transaction and, when it is refused, check that it wrote nothing.
    fn apply_without_write(
        state: &mut AccountState,
        op: &Address,
        tx: Transaction,
    ) -> Result<(), String> {
        let before = snapshot(state, op);
        let result = apply(state, tx);
        if result.is_err() {
            assert_eq!(snapshot(state, op), before, "a refusal must not write");
        }
        result
    }

    #[test]
    fn a_consented_open_escrows_the_fee_locks_the_bond_and_moves_the_root() {
        let (mut state, m, op) = world();
        let before = state.calculate_state_root();

        apply(&mut state, open_tx(signed_body(&m, &op), DEFAULT_CHAIN_ID)).expect("opens");

        assert_eq!(
            state.get_balance(&payer()),
            PAYER_FUNDS - DEAL_FEE - TX_FEE,
            "escrow and the transaction fee are charged to the payer"
        );
        assert_eq!(
            state.get_balance(&op.address()),
            STORAGE_MIN_OPERATOR_BOND,
            "the operator's bond is locked"
        );
        assert_eq!(state.get_nonce(&payer()), 1);
        assert_eq!(state.storage_registry.deals_iter().count(), 1);
        assert_ne!(state.calculate_state_root(), before);
    }

    #[test]
    fn a_consent_signed_for_another_digest_is_refused() {
        let (mut state, m, op) = world();
        let mut body = unsigned_body(&m, &op);
        // Signed over a different price than the one the body carries.
        let mut other = body.clone();
        other.economics.fee_per_byte_epoch += 1;
        body.operator_consent = consent(&op, DEFAULT_CHAIN_ID, &payer(), 0, &other);

        let err = apply_without_write(&mut state, &op.address(), open_tx(body, DEFAULT_CHAIN_ID))
            .unwrap_err();
        assert!(err.contains("consent"), "got {err}");
        assert_eq!(state.storage_registry.deals_iter().count(), 0);
    }

    #[test]
    fn a_consent_signed_for_another_nonce_is_refused() {
        let (mut state, m, op) = world();
        let mut body = unsigned_body(&m, &op);
        body.operator_consent = consent(&op, DEFAULT_CHAIN_ID, &payer(), 1, &body);

        let err = apply_without_write(&mut state, &op.address(), open_tx(body, DEFAULT_CHAIN_ID))
            .unwrap_err();
        assert!(err.contains("consent"), "got {err}");
    }

    #[test]
    fn a_consent_is_spent_by_the_nonce_it_was_signed_for() {
        let (mut state, m, op) = world();
        let body = signed_body(&m, &op);
        apply(&mut state, open_tx(body.clone(), DEFAULT_CHAIN_ID)).expect("opens");
        // The same signed body again: the payer's nonce moved on.
        let err = apply_without_write(&mut state, &op.address(), open_tx(body, DEFAULT_CHAIN_ID))
            .unwrap_err();
        assert!(err.contains("consent"), "got {err}");
    }

    #[test]
    fn a_consent_from_another_operator_is_refused() {
        let (mut state, m, op) = world();
        let stranger = WalletKeyPair::generate();
        let mut body = unsigned_body(&m, &op);
        // Valid signature, over the right digest, by a key that is not the
        // operator named in the body.
        body.operator_consent = consent(&stranger, DEFAULT_CHAIN_ID, &payer(), 0, &body);

        let err = apply_without_write(&mut state, &op.address(), open_tx(body, DEFAULT_CHAIN_ID))
            .unwrap_err();
        assert!(err.contains("consent"), "got {err}");
    }

    #[test]
    fn a_missing_consent_signature_is_refused() {
        let (mut state, m, op) = world();
        let err = apply_without_write(
            &mut state,
            &op.address(),
            open_tx(unsigned_body(&m, &op), DEFAULT_CHAIN_ID),
        )
        .unwrap_err();
        assert!(err.contains("consent"), "got {err}");
    }

    #[test]
    fn an_unregistered_manifest_is_refused() {
        let (mut state, m, op) = world();
        let mut body = unsigned_body(&m, &op);
        body.manifest_id = ContentId([0xEEu8; 32]);
        body.operator_consent = consent(&op, DEFAULT_CHAIN_ID, &payer(), 0, &body);

        let err = apply_without_write(&mut state, &op.address(), open_tx(body, DEFAULT_CHAIN_ID))
            .unwrap_err();
        assert!(err.contains("not registered"), "got {err}");
    }

    /// A deal row is what every durability number is derived from: it
    /// suppresses repair and holds the guard that keeps an object's last
    /// copies from being released. Anyone used to be able to open one over
    /// somebody else's manifest - the operator consented, the payer paid, and
    /// nothing tied the payer to the content. The registry's own authority
    /// (`has_claim`) now decides, as it does for grants, self-host, reads and
    /// prunes.
    #[test]
    fn a_deal_over_someone_elses_manifest_is_refused() {
        let mut state = AccountState::new();
        let owner = addr(99);
        let mut m = deal_manifest();
        m.owner = owner;
        state.storage_registry.register_manifest(&m);
        state.add_balance(&payer(), PAYER_FUNDS);
        let op = WalletKeyPair::generate();
        state.add_balance(&op.address(), STORAGE_MIN_OPERATOR_BOND * 2);

        let err = apply_without_write(
            &mut state,
            &op.address(),
            open_tx(signed_body(&m, &op), DEFAULT_CHAIN_ID),
        )
        .unwrap_err();
        assert!(err.contains("not the owner"), "got {err}");
        assert_eq!(state.storage_registry.deals_iter().count(), 0);
    }

    #[test]
    fn an_operator_in_cooldown_is_refused_until_the_cooldown_ends() {
        let (mut state, m, op) = world();
        let start = 1_000;
        state
            .storage_registry
            .begin_operator_cooldown(op.address(), start);
        state.current_block_unix_secs = start;
        let body = signed_body(&m, &op);

        let err = apply_without_write(
            &mut state,
            &op.address(),
            open_tx(body.clone(), DEFAULT_CHAIN_ID),
        )
        .unwrap_err();
        assert!(err.contains("missed a challenge"), "got {err}");

        state.current_block_unix_secs = start + MISSED_CHALLENGE_COOLDOWN_SECS;
        apply(&mut state, open_tx(body, DEFAULT_CHAIN_ID)).expect("the cooldown has ended");
        assert_eq!(state.storage_registry.deals_iter().count(), 1);
    }

    #[test]
    fn mainnet_refuses_to_open_a_deal_in_block() {
        let (mut state, m, op) = world();
        let mut body = unsigned_body(&m, &op);
        body.operator_consent = consent(&op, MAINNET, &payer(), 0, &body);

        let err =
            apply_without_write(&mut state, &op.address(), open_tx(body, MAINNET)).unwrap_err();
        assert!(err.contains("mainnet"), "got {err}");
    }

    #[test]
    fn a_value_carrying_open_is_refused_before_anything_moves() {
        let (mut state, m, op) = world();
        let mut tx = open_tx(signed_body(&m, &op), DEFAULT_CHAIN_ID);
        tx.amount = 5;
        let err = apply_without_write(&mut state, &op.address(), tx).unwrap_err();
        assert!(err.contains("storage_amount_must_be_zero"), "got {err}");
    }

    #[test]
    fn a_payer_who_cannot_keep_the_fee_after_escrow_is_refused() {
        let (mut state, m, op) = world();
        // Enough for the escrow, not for the escrow and the transaction fee.
        let funds = state.get_balance(&payer());
        state.get_or_create(&payer()).balance = DEAL_FEE;
        assert!(funds > DEAL_FEE);

        let err = apply_without_write(
            &mut state,
            &op.address(),
            open_tx(signed_body(&m, &op), DEFAULT_CHAIN_ID),
        )
        .unwrap_err();
        assert!(err.contains("Insufficient payer balance"), "got {err}");
    }

    #[test]
    fn a_payer_who_is_also_the_operator_keeps_the_fee_after_the_bond() {
        let mut state = AccountState::new();
        let op = WalletKeyPair::generate();
        let mut m = deal_manifest();
        m.owner = op.address();
        state.storage_registry.register_manifest(&m);
        // Covers the escrow and the bond but not the transaction fee as well.
        state.add_balance(&op.address(), DEAL_FEE + STORAGE_MIN_OPERATOR_BOND);
        let mut body = unsigned_body(&m, &op);
        body.operator_consent = consent(&op, DEFAULT_CHAIN_ID, &op.address(), 0, &body);
        let tx = Transaction::new_with_chain_id(
            op.address(),
            Address::zero(),
            0,
            TX_FEE,
            0,
            vec![],
            DEFAULT_CHAIN_ID,
            TransactionType::Storage(StorageTx::OpenDeal(Box::new(body))),
        );

        let before = state.get_balance(&op.address());
        let root = state.calculate_state_root();
        let err = apply(&mut state, tx).unwrap_err();
        assert!(err.contains("Insufficient payer balance"), "{err}");
        assert_eq!(state.get_balance(&op.address()), before);
        assert_eq!(state.calculate_state_root(), root);
    }

    #[test]
    fn a_relay_rewriting_any_open_field_changes_the_signing_hash() {
        let (_, m, op) = world();
        let base = signed_body(&m, &op);
        let hash_of = |b: &StorageDealOpen| open_tx(b.clone(), DEFAULT_CHAIN_ID).calculate_hash();
        let honest = hash_of(&base);

        let mut variants: Vec<(&str, StorageDealOpen)> = Vec::new();
        let mut v = base.clone();
        v.domain_id += 1;
        variants.push(("domain_id", v));
        let mut v = base.clone();
        v.manifest_id = ContentId([1u8; 32]);
        variants.push(("manifest_id", v));
        let mut v = base.clone();
        v.shard_id = ContentId([2u8; 32]);
        variants.push(("shard_id", v));
        let mut v = base.clone();
        v.operator = addr(3);
        variants.push(("operator", v));
        let mut v = base.clone();
        v.replica_index += 1;
        variants.push(("replica_index", v));
        let mut v = base.clone();
        v.start_epoch += 1;
        variants.push(("start_epoch", v));
        let mut v = base.clone();
        v.end_epoch += 1;
        variants.push(("end_epoch", v));
        let mut v = base.clone();
        v.economics.operator_bond += 1;
        variants.push(("economics.operator_bond", v));
        let mut v = base.clone();
        v.economics.fee_per_byte_epoch += 1;
        variants.push(("economics.fee_per_byte_epoch", v));
        let mut v = base.clone();
        v.merkle_proof.push(0);
        variants.push(("merkle_proof", v));
        let mut v = base.clone();
        v.storage_root[0] ^= 1;
        variants.push(("storage_root", v));
        let mut v = base.clone();
        v.operator_consent.owner_key[0] ^= 1;
        variants.push(("operator_consent.owner_key", v));
        let mut v = base.clone();
        v.operator_consent.signature[0] ^= 1;
        variants.push(("operator_consent.signature", v));

        for (field, variant) in variants {
            assert_ne!(
                hash_of(&variant),
                honest,
                "{field} is not in the signing hash"
            );
        }
    }
}

/// The answer to a coding audit, through the executor. The registry rules
/// are unit-tested in `storage_tx.rs`; this pins the fee and nonce epilogue,
/// that a refusal charges nothing, and that the signature commits every
/// field of the answer.
mod answer_coding_audit {
    use super::*;
    use crate::domain::storage_deal::CodingAuditOutcome;
    use crate::storage::EncodedObject;

    fn proof() -> Vec<u8> {
        let envelope = bud_proof::ProofEnvelope {
            proof_format_version: 1,
            backend: "test-backend".to_string(),
            p3_version: "0.6".to_string(),
            fri_params_id: "test-fri".to_string(),
            public_inputs_hash: [0x42u8; 32],
            proof_bytes: vec![0xABu8; 96],
            degree_bits: 8,
        };
        bincode::serialize(&envelope).expect("envelope")
    }

    /// A (4,6) object with one live deal on each parity shard and one open
    /// audit. Returns the state, the encoded object and the audit id.
    fn world() -> (AccountState, EncodedObject, u64) {
        // Not a repeating pattern: equal shards share a content id.
        let data: Vec<u8> = (0..800u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let encoded = encode_object(&data, ErasureScheme { k: 4, n: 6 }).expect("encode");
        let m = encoded.to_manifest().expect("manifest");
        let mut state = AccountState::new();
        state.storage_registry.register_manifest(&m);
        for (shard, holder) in [(4usize, 10u8), (5, 12)] {
            state
                .storage_registry
                .open_deal(
                    42,
                    &m,
                    m.shards[shard].shard_id,
                    addr(holder),
                    0,
                    100,
                    200,
                    crate::domain::storage_deal::StorageEconomicsParams {
                        operator_bond: 5_000_000,
                        fee_per_byte_epoch: 100,
                    },
                    &crate::domain::storage_params::StorageDomainParams {
                        chunk_size: 256,
                        max_committed_chunks: 1000,
                        challenge_interval: 10,
                        min_operator_bond: 1_000_000,
                    },
                    Some(proof()),
                    Some([0x42u8; 32]),
                )
                .expect("a parity shard deal opens");
        }
        let id = state
            .storage_registry
            .open_coding_audit(&[1u8; 32], m.manifest_id, 120, 130)
            .expect("the object can be audited");
        state.epoch_index = 125;
        state.current_block_unix_secs = 1_000_000;
        (state, encoded, id)
    }

    /// The audited operator and its honest answer.
    fn honest(state: &AccountState, encoded: &EncodedObject, id: u64) -> (Address, StorageTx) {
        let stored = state
            .storage_registry
            .coding_audit(id)
            .expect("audit is stored");
        let column = stored.audit.column as usize;
        let k = encoded.scheme.k as usize;
        let body = StorageTx::AnswerCodingAudit {
            audit_id: id,
            data_column: (0..k).map(|j| encoded.shards[j][column]).collect(),
            parity_byte: encoded.shards[k + stored.audit.parity_index as usize][column],
        };
        (stored.operator, body)
    }

    fn outcome(state: &AccountState, id: u64) -> CodingAuditOutcome {
        state
            .storage_registry
            .coding_audit(id)
            .expect("audit is stored")
            .outcome
    }

    #[test]
    fn an_answer_in_block_passes_moves_the_root_and_charges_the_fee() {
        let (mut state, encoded, id) = world();
        let (operator, body) = honest(&state, &encoded, id);
        state.add_balance(&operator, 1_000);
        let before = state.calculate_state_root();

        apply(&mut state, storage_tx(operator, 0, body, 0)).expect("the operator answers");

        assert_eq!(outcome(&state, id), CodingAuditOutcome::Passed);
        assert_eq!(state.get_balance(&operator), 999);
        assert_eq!(state.get_nonce(&operator), 1);
        assert_ne!(state.calculate_state_root(), before);
    }

    #[test]
    fn a_refused_answer_charges_nothing() {
        let (mut state, encoded, id) = world();
        let (_, body) = honest(&state, &encoded, id);
        let stranger = addr(99);
        state.add_balance(&stranger, 1_000);

        let err = apply(&mut state, storage_tx(stranger, 0, body, 0)).unwrap_err();

        assert!(err.contains("storage_tx_failed"), "{err}");
        assert_eq!(outcome(&state, id), CodingAuditOutcome::Open);
        assert_eq!(state.get_balance(&stranger), 1_000);
        assert_eq!(state.get_nonce(&stranger), 0);
    }

    #[test]
    fn the_signature_commits_every_answer_field() {
        let hash_of = |audit_id: u64, data_column: Vec<u8>, parity_byte: u8| {
            let body = StorageTx::AnswerCodingAudit {
                audit_id,
                data_column,
                parity_byte,
            };
            storage_tx(addr(10), 0, body, 0).calculate_hash()
        };
        let honest = hash_of(1, vec![1, 2, 3, 4], 5);
        assert_ne!(hash_of(2, vec![1, 2, 3, 4], 5), honest, "audit_id");
        assert_ne!(hash_of(1, vec![1, 2, 3, 5], 5), honest, "data_column");
        assert_ne!(hash_of(1, vec![1, 2, 3, 4, 0], 5), honest, "column length");
        assert_ne!(hash_of(1, vec![1, 2, 3, 4], 6), honest, "parity_byte");
    }
}
