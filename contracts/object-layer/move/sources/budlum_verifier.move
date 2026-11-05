/// Budlum finality on a Move home chain (WP-64, part 2).
///
/// The endpoint asks one question: is this Budlum checkpoint final. The
/// answer needs the succinct Budlum finality proof (WP-60); until it lands
/// the verifier is fail-closed and records nothing, so the endpoint's
/// silence clock never restarts and no release can pass.
module budlum::budlum_verifier {
    use aptos_std::table::{Self, Table};

    /// The proof system is not open yet (WP-60).
    const E_NOT_OPEN: u64 = 1;
    /// A different header was already recorded for this height.
    const E_CONFLICT: u64 = 2;

    struct Checkpoints has key {
        header_at: Table<u64, vector<u8>>,
    }

    fun init_module(publisher: &signer) {
        move_to(publisher, Checkpoints { header_at: table::new() });
    }

    /// Record a checkpoint with its proof. Fail-closed until WP-60.
    public entry fun record(_height: u64, _header_hash: vector<u8>, _proof: vector<u8>) {
        abort E_NOT_OPEN
    }

    #[view]
    public fun height_final(height: u64): bool acquires Checkpoints {
        let c = borrow_global<Checkpoints>(@budlum);
        table::contains(&c.header_at, height)
    }

    #[test_only]
    public fun conflict_code(): u64 { E_CONFLICT }
}
