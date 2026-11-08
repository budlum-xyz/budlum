/// Budlum settlement endpoint, Move family.
///
/// Takes custody of Fungible Asset and token objects that enter the Budlum
/// Universal Object Layer, carries home calls, and tracks the last accepted
/// Budlum checkpoint for the silence window. Published immutable: no admin,
/// no upgrade, no pause.
///
/// The event layouts are pinned by `src/object_layer/family/move.rs`
/// (BCS, field order as declared here).
module budlum::settlement_endpoint {
    use std::option::{Self, Option};
    use std::signer;
    use std::vector;
    use aptos_framework::event;
    use aptos_framework::fungible_asset::Metadata;
    use aptos_framework::object::{Self, Object, ObjectCore, ExtendRef};
    use aptos_framework::primary_fungible_store;
    use aptos_framework::timestamp;
    use aptos_std::table::{Self, Table};
    use budlum::budlum_verifier;

    const FUNGIBLE: u8 = 0;
    const UNIQUE: u8 = 1;

    const E_NOTHING_RECEIVED: u64 = 1;
    const E_BAD_RECIPIENT: u64 = 2;
    const E_NOT_FINAL: u64 = 3;
    const E_NOT_NEWER: u64 = 4;
    /// release and escape open with the object-layer root opening.
    const E_NOT_OPEN: u64 = 5;

    /// Seconds without a newly accepted checkpoint before the exit opens.
    const SILENCE_WINDOW_SECS: u64 = 1209600;

    struct Endpoint has key {
        /// The custody object; assets are held at its address.
        vault: ExtendRef,
        last_accepted_height: u64,
        last_accepted_at: u64,
        home_nonce: Table<address, u64>,
    }

    #[event]
    /// budlum/object-layer/arrive/v1
    struct ArriveEvent has drop, store {
        kind: u8,
        class: address,
        native_id: Option<address>,
        amount: u64,
        depositor: address,
        recipient: Option<vector<u8>>,
    }

    #[event]
    /// budlum/object-layer/call/v1
    struct HomeCallEvent has drop, store {
        sender: address,
        nonce: u64,
        calls: vector<u8>,
    }

    #[event]
    /// budlum/object-layer/released/v1
    struct ReleasedEvent has drop, store {
        departure_id: vector<u8>,
    }

    #[event]
    /// budlum/object-layer/escaped/v1
    struct EscapedEvent has drop, store {
        kind: u8,
        class: address,
        native_id: Option<address>,
        to: address,
    }

    fun init_module(publisher: &signer) {
        let ctor = object::create_object(signer::address_of(publisher));
        let vault = object::generate_extend_ref(&ctor);
        // The vault object cannot be transferred away from the endpoint.
        object::disable_ungated_transfer(&object::generate_transfer_ref(&ctor));
        move_to(publisher, Endpoint {
            vault,
            last_accepted_height: 0,
            last_accepted_at: timestamp::now_seconds(),
            home_nonce: table::new(),
        });
    }

    fun vault_address(): address acquires Endpoint {
        object::address_from_extend_ref(&borrow_global<Endpoint>(@budlum).vault)
    }

    fun recipient_of(recipient: vector<u8>): Option<vector<u8>> {
        let len = vector::length(&recipient);
        assert!(len == 0 || len == 32, E_BAD_RECIPIENT);
        if (len == 0) option::none() else option::some(recipient)
    }

    /// Fungible arrival. The amount is the vault's balance difference.
    public entry fun deposit_fa(
        owner: &signer,
        metadata: Object<Metadata>,
        amount: u64,
        recipient: vector<u8>,
    ) acquires Endpoint {
        let vault = vault_address();
        let before = primary_fungible_store::balance(vault, metadata);
        primary_fungible_store::transfer(owner, metadata, vault, amount);
        let received = primary_fungible_store::balance(vault, metadata) - before;
        assert!(received > 0, E_NOTHING_RECEIVED);
        event::emit(ArriveEvent {
            kind: FUNGIBLE,
            class: object::object_address(&metadata),
            native_id: option::none(),
            amount: received,
            depositor: signer::address_of(owner),
            recipient: recipient_of(recipient),
        });
    }

    /// Unique arrival: a token object moves into the vault.
    public entry fun deposit_token(
        owner: &signer,
        collection: address,
        token: Object<ObjectCore>,
        recipient: vector<u8>,
    ) acquires Endpoint {
        object::transfer(owner, token, vault_address());
        event::emit(ArriveEvent {
            kind: UNIQUE,
            class: collection,
            native_id: option::some(object::object_address(&token)),
            amount: 1,
            depositor: signer::address_of(owner),
            recipient: recipient_of(recipient),
        });
    }

    /// A home call: Budlum runs `calls` as the home identity of the signer.
    public entry fun home_call(sender: &signer, calls: vector<u8>) acquires Endpoint {
        let e = borrow_global_mut<Endpoint>(@budlum);
        let who = signer::address_of(sender);
        let nonce = table::borrow_mut_with_default(&mut e.home_nonce, who, 0);
        let current = *nonce;
        *nonce = current + 1;
        event::emit(HomeCallEvent { sender: who, nonce: current, calls });
    }

    /// Accept a newer final Budlum checkpoint; restarts the silence clock.
    public entry fun accept_header(height: u64) acquires Endpoint {
        let e = borrow_global_mut<Endpoint>(@budlum);
        assert!(height > e.last_accepted_height, E_NOT_NEWER);
        assert!(budlum_verifier::height_final(height), E_NOT_FINAL);
        e.last_accepted_height = height;
        e.last_accepted_at = timestamp::now_seconds();
    }

    #[view]
    public fun silent(): bool acquires Endpoint {
        let e = borrow_global<Endpoint>(@budlum);
        timestamp::now_seconds() > e.last_accepted_at + SILENCE_WINDOW_SECS
    }

    /// Opens with the object-layer root opening.
    public entry fun release(_proof: vector<u8>) {
        abort E_NOT_OPEN
    }

    /// Opens with the object-layer root opening.
    public entry fun escape(_proof: vector<u8>) {
        abort E_NOT_OPEN
    }
}
