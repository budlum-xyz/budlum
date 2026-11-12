/// Budlum settlement endpoint, Move family.
///
/// Custody and home calls are closed until departure and escape can return
/// assets. Only finalized checkpoint tracking remains available. Published
/// immutable: no admin,
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

    /// Custody without an authenticated departure or escape is irreversible.
    public entry fun deposit_fa(
        _owner: &signer,
        _metadata: Object<Metadata>,
        _amount: u64,
        _recipient: vector<u8>,
    ) {
        abort E_NOT_OPEN
    }

    /// Do not accept unique objects into a vault with no exit.
    public entry fun deposit_token(
        _owner: &signer,
        _token: Object<ObjectCore>,
        _recipient: vector<u8>,
    ) {
        abort E_NOT_OPEN
    }

    /// Home calls cannot be honored before identity proofs are available.
    public entry fun home_call(_sender: &signer, _calls: vector<u8>) {
        abort E_NOT_OPEN
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
