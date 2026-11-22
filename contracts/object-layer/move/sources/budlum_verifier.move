/// Budlum finality on a Move home chain.
///
/// Implements the unified four-query `IBudlumFinality` surface
/// (`height_final`, `root_at_height`, `latest_final_height`,
/// `finality_mode_at_height`) backed by real committee Ed25519 quorum
/// signature verification (`PROOF_FORMAT_SIGNATURE = 1`).
module budlum::budlum_verifier {
    use std::bcs;
    use std::signer;
    use std::vector;
    use aptos_std::ed25519;
    use aptos_std::table::{Self, Table};

    /// Canonical domain separator shared identically across EVM, CosmWasm, SVM, and Move.
    const SIGNING_DOMAIN: vector<u8> = b"BDLM_OUTBOUND_FINALITY_V1";
    /// Canonical domain separator for permissionless validator-set handoff certificates.
    const HANDOFF_DOMAIN: vector<u8> = b"BDLM_OUTBOUND_HANDOFF_V1";

    /// FinalityMode discriminants matching Solidity `FinalityMode`.
    const MODE_NONE: u8 = 0;
    const MODE_CLASSICAL_ONLY: u8 = 1;
    const MODE_POST_QUANTUM_ONLY: u8 = 2;
    const MODE_HYBRID: u8 = 3;

    /// ProofFormat discriminants (`1 = Signature`, `2 = Succinct`).
    const PROOF_FORMAT_SIGNATURE: u8 = 1;

    /// Error codes.
    const E_NOT_AUTHORIZED: u64 = 1;
    const E_CONFLICT: u64 = 2;
    const E_INVALID_COMMITTEE: u64 = 3;
    const E_ALREADY_INITIALIZED: u64 = 4;
    const E_NOT_INITIALIZED: u64 = 5;
    const E_ZERO_FIELD: u64 = 6;
    const E_MODE_NONE: u64 = 7;
    const E_DOMAIN_MISMATCH: u64 = 8;
    const E_QUORUM_NOT_MET: u64 = 9;
    const E_INVALID_SIGNER: u64 = 10;
    const E_DUPLICATE_SIGNER: u64 = 11;
    const E_INVALID_SIGNATURE: u64 = 12;

    struct Committee has key {
        budlum_chain_id: u64,
        epoch: u64,
        threshold: u64,
        members: vector<vector<u8>>,
    }

    struct CheckpointRecord has store, drop, copy {
        state_root: vector<u8>,
        header_hash: vector<u8>,
        mode: u8,
    }

    struct Checkpoints has key {
        records: Table<u64, CheckpointRecord>,
        latest_final_height: u64,
    }

    fun init_module(publisher: &signer) {
        move_to(publisher, Checkpoints {
            records: table::new(),
            latest_final_height: 0,
        });
    }

    /// Initialize the immutable finality committee once under `@budlum`.
    public entry fun initialize_committee(
        publisher: &signer,
        budlum_chain_id: u64,
        epoch: u64,
        threshold: u64,
        members: vector<vector<u8>>,
    ) {
        assert!(signer::address_of(publisher) == @budlum, E_NOT_AUTHORIZED);
        assert!(!exists<Committee>(@budlum), E_ALREADY_INITIALIZED);
        let n = vector::length(&members);
        assert!(budlum_chain_id > 0 && n > 0, E_INVALID_COMMITTEE);
        assert!(threshold > 0 && threshold <= n, E_INVALID_COMMITTEE);
        assert!((threshold as u128) * 3 > (n as u128) * 2, E_INVALID_COMMITTEE);

        let i = 0;
        while (i < n) {
            let pk = vector::borrow(&members, i);
            assert!(is_valid_32_nonzero(pk), E_INVALID_COMMITTEE);
            let j = i + 1;
            while (j < n) {
                assert!(*pk != *vector::borrow(&members, j), E_INVALID_COMMITTEE);
                j = j + 1;
            };
            i = i + 1;
        };

        move_to(publisher, Committee {
            budlum_chain_id,
            epoch,
            threshold,
            members,
        });
    }

    /// Permissionlessly rotate the active committee from `epoch` to `epoch + 1`
    /// using a `> 2/3` supermajority handoff certificate signed by the active committee.
    public entry fun rotate_committee(
        next_epoch: u64,
        next_threshold: u64,
        next_members: vector<vector<u8>>,
        signer_indices: vector<u64>,
        signatures: vector<vector<u8>>,
    ) acquires Committee {
        assert!(exists<Committee>(@budlum), E_NOT_INITIALIZED);
        let committee = borrow_global_mut<Committee>(@budlum);
        assert!(next_epoch == committee.epoch + 1, E_DOMAIN_MISMATCH);

        let next_n = vector::length(&next_members);
        assert!(next_n > 0 && next_threshold > 0 && next_threshold <= next_n, E_INVALID_COMMITTEE);
        assert!((next_threshold as u128) * 3 > (next_n as u128) * 2, E_INVALID_COMMITTEE);
        let a = 0;
        while (a < next_n) {
            let pk = vector::borrow(&next_members, a);
            assert!(is_valid_32_nonzero(pk), E_INVALID_COMMITTEE);
            let b = a + 1;
            while (b < next_n) {
                assert!(*pk != *vector::borrow(&next_members, b), E_INVALID_COMMITTEE);
                b = b + 1;
            };
            a = a + 1;
        };

        let sig_count = vector::length(&signatures);
        assert!(sig_count == vector::length(&signer_indices), E_INVALID_SIGNATURE);
        assert!(sig_count >= committee.threshold, E_QUORUM_NOT_MET);

        let msg = handoff_message(
            committee.budlum_chain_id,
            committee.epoch,
            next_epoch,
            (next_threshold as u32),
            &next_members,
        );
        let cur_n = vector::length(&committee.members);
        let seen = vector::empty<bool>();
        let k = 0;
        while (k < cur_n) {
            vector::push_back(&mut seen, false);
            k = k + 1;
        };

        let valid = 0;
        let idx = 0;
        while (idx < sig_count) {
            let member_idx = *vector::borrow(&signer_indices, idx);
            assert!(member_idx < cur_n, E_INVALID_SIGNER);
            assert!(!*vector::borrow(&seen, member_idx), E_DUPLICATE_SIGNER);
            let sig_bytes = *vector::borrow(&signatures, idx);
            assert!(vector::length(&sig_bytes) == 64, E_INVALID_SIGNATURE);
            let pk_bytes = *vector::borrow(&committee.members, member_idx);

            let pk = ed25519::new_unvalidated_public_key_from_bytes(pk_bytes);
            let sig = ed25519::new_signature_from_bytes(sig_bytes);
            assert!(ed25519::signature_verify_strict(&sig, &pk, msg), E_INVALID_SIGNATURE);

            *vector::borrow_mut(&mut seen, member_idx) = true;
            valid = valid + 1;
            idx = idx + 1;
        };
        assert!(valid >= committee.threshold, E_QUORUM_NOT_MET);

        committee.epoch = next_epoch;
        committee.threshold = next_threshold;
        committee.members = next_members;
    }

    /// Build the canonical handoff signing message shared across CosmWasm, SVM, and Move.
    public fun handoff_message(
        chain_id: u64,
        from_epoch: u64,
        to_epoch: u64,
        next_threshold: u32,
        next_members: &vector<vector<u8>>,
    ): vector<u8> {
        let out = HANDOFF_DOMAIN;
        vector::append(&mut out, bcs::to_bytes(&chain_id));
        vector::append(&mut out, bcs::to_bytes(&from_epoch));
        vector::append(&mut out, bcs::to_bytes(&to_epoch));
        vector::append(&mut out, bcs::to_bytes(&next_threshold));
        let count = (vector::length(next_members) as u32);
        vector::append(&mut out, bcs::to_bytes(&count));
        let i = 0;
        let n = vector::length(next_members);
        while (i < n) {
            vector::append(&mut out, *vector::borrow(next_members, i));
            i = i + 1;
        };
        out
    }

    /// Verify and record a finalized Budlum checkpoint using its signature-format quorum proof.
    public entry fun record(
        height: u64,
        chain_id: u64,
        epoch: u64,
        state_root: vector<u8>,
        header_hash: vector<u8>,
        mode: u8,
        signer_indices: vector<u64>,
        signatures: vector<vector<u8>>,
    ) acquires Committee, Checkpoints {
        assert!(height > 0, E_ZERO_FIELD);
        assert!(is_valid_32_nonzero(&state_root), E_ZERO_FIELD);
        assert!(is_valid_32_nonzero(&header_hash), E_ZERO_FIELD);
        assert!(
            mode == MODE_CLASSICAL_ONLY || mode == MODE_POST_QUANTUM_ONLY || mode == MODE_HYBRID,
            E_MODE_NONE,
        );
        assert!(exists<Committee>(@budlum), E_NOT_INITIALIZED);

        let committee = borrow_global<Committee>(@budlum);
        assert!(chain_id == committee.budlum_chain_id && epoch == committee.epoch, E_DOMAIN_MISMATCH);

        let c = borrow_global_mut<Checkpoints>(@budlum);
        if (table::contains(&c.records, height)) {
            let existing = table::borrow(&c.records, height);
            assert!(
                existing.state_root == state_root && existing.header_hash == header_hash,
                E_CONFLICT,
            );
            return
        };

        let sig_count = vector::length(&signatures);
        assert!(sig_count == vector::length(&signer_indices), E_INVALID_SIGNATURE);
        assert!(sig_count >= committee.threshold, E_QUORUM_NOT_MET);

        let msg = signing_message(chain_id, epoch, height, &state_root, &header_hash, mode);
        let n = vector::length(&committee.members);
        let seen = vector::empty<bool>();
        let k = 0;
        while (k < n) {
            vector::push_back(&mut seen, false);
            k = k + 1;
        };

        let valid = 0;
        let idx = 0;
        while (idx < sig_count) {
            let member_idx = *vector::borrow(&signer_indices, idx);
            assert!(member_idx < n, E_INVALID_SIGNER);
            assert!(!*vector::borrow(&seen, member_idx), E_DUPLICATE_SIGNER);

            let sig_bytes = *vector::borrow(&signatures, idx);
            assert!(vector::length(&sig_bytes) == 64, E_INVALID_SIGNATURE);
            let pk_bytes = *vector::borrow(&committee.members, member_idx);

            let pk = ed25519::new_unvalidated_public_key_from_bytes(pk_bytes);
            let sig = ed25519::new_signature_from_bytes(sig_bytes);
            assert!(ed25519::signature_verify_strict(&sig, &pk, msg), E_INVALID_SIGNATURE);

            *vector::borrow_mut(&mut seen, member_idx) = true;
            valid = valid + 1;
            idx = idx + 1;
        };
        assert!(valid >= committee.threshold, E_QUORUM_NOT_MET);

        table::add(&mut c.records, height, CheckpointRecord {
            state_root,
            header_hash,
            mode,
        });
        if (height > c.latest_final_height) {
            c.latest_final_height = height;
        };
    }

    /// Build the canonical 114-byte signing message shared identically across all four families.
    public fun signing_message(
        chain_id: u64,
        epoch: u64,
        height: u64,
        state_root: &vector<u8>,
        header_hash: &vector<u8>,
        mode: u8,
    ): vector<u8> {
        let out = SIGNING_DOMAIN;
        vector::append(&mut out, bcs::to_bytes(&chain_id));
        vector::append(&mut out, bcs::to_bytes(&epoch));
        vector::append(&mut out, bcs::to_bytes(&height));
        vector::append(&mut out, *state_root);
        vector::append(&mut out, *header_hash);
        vector::push_back(&mut out, mode);
        out
    }

    fun is_valid_32_nonzero(bytes: &vector<u8>): bool {
        if (vector::length(bytes) != 32) {
            return false
        };
        let i = 0;
        while (i < 32) {
            if (*vector::borrow(bytes, i) != 0) {
                return true
            };
            i = i + 1;
        };
        false
    }

    /// `IBudlumFinality::acceptedProofFormat()`: `1 = Signature`.
    #[view]
    public fun accepted_proof_format(): u8 {
        PROOF_FORMAT_SIGNATURE
    }

    /// `IBudlumFinality::heightFinal(height)`.
    #[view]
    public fun height_final(height: u64): bool acquires Checkpoints {
        let c = borrow_global<Checkpoints>(@budlum);
        if (!table::contains(&c.records, height)) {
            return false
        };
        let rec = table::borrow(&c.records, height);
        rec.mode != MODE_NONE
    }

    /// `IBudlumFinality::rootAtHeight(height)`.
    #[view]
    public fun root_at_height(height: u64): vector<u8> acquires Checkpoints {
        let c = borrow_global<Checkpoints>(@budlum);
        if (table::contains(&c.records, height)) {
            table::borrow(&c.records, height).state_root
        } else {
            vector::empty()
        }
    }

    /// Authenticated Budlum global header hash at `height`, or empty if not final.
    #[view]
    public fun header_at(height: u64): vector<u8> acquires Checkpoints {
        let c = borrow_global<Checkpoints>(@budlum);
        if (table::contains(&c.records, height)) {
            table::borrow(&c.records, height).header_hash
        } else {
            vector::empty()
        }
    }

    /// `IBudlumFinality::latestFinalHeight()`.
    #[view]
    public fun latest_final_height(): u64 acquires Checkpoints {
        let c = borrow_global<Checkpoints>(@budlum);
        c.latest_final_height
    }

    /// `IBudlumFinality::finalityModeAtHeight(height)`.
    #[view]
    public fun finality_mode_at_height(height: u64): u8 acquires Checkpoints {
        let c = borrow_global<Checkpoints>(@budlum);
        if (table::contains(&c.records, height)) {
            table::borrow(&c.records, height).mode
        } else {
            MODE_NONE
        }
    }

    #[test_only]
    public fun conflict_code(): u64 { E_CONFLICT }
}
