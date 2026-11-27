//! Acceptance and forgery-rejection tests for the Keccak-256 Merkle path
//! verification STARK chip (`bud_proof::chips::merkle_path`).

use bud_proof::chips::merkle_path::{
    build_merkle_path_trace, check_merkle_path_constraints, compress_keccak_pair,
    compute_merkle_root, prove_merkle_path, verify_merkle_path, MerklePathAir, MerklePathChipError,
    MerklePathWitness, COL_INDEX_BIT, COL_SIB_LIMBS_BASE, MAX_MERKLE_DEPTH, MIN_MERKLE_DEPTH,
};
use p3_commit::Mmcs;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PseudoCompressionFunction, SerializingHasher};

fn deterministic_digest(seed: u64, level: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut s = seed ^ ((level as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    for chunk in out.chunks_mut(8) {
        s = s.wrapping_add(0xBF58_476D_1CE4_E5B9);
        let z = (s ^ (s >> 30)).wrapping_mul(0x94D0_49BB_1331_11EB);
        chunk.copy_from_slice(&(z ^ (z >> 31)).to_le_bytes());
    }
    out
}

#[test]
fn valid_paths_from_depth_1_to_24_verify_and_match_p3_merkle_mmcs() {
    let p3_compress = CompressionFunctionFromHasher::<Keccak256Hash, 2, 32>::new(Keccak256Hash);

    // Every depth 1..=24 must satisfy all AIR constraints and match Plonky3's Keccak compressor;
    // representative depths including both endpoints (1 and 24) run full STARK prove + verify.
    for depth in MIN_MERKLE_DEPTH..=MAX_MERKLE_DEPTH {
        let leaf = deterministic_digest(0x1234_5678, depth);
        let siblings: Vec<[u8; 32]> = (0..depth)
            .map(|lvl| deterministic_digest(0xABCD_EF01 ^ (depth as u64), lvl))
            .collect();
        let index: u64 = ((0x5A5A_A5A5u64) ^ (depth as u64 * 17)) & ((1u64 << depth) - 1);

        let mut expected_cur = leaf;
        for (lvl, sib) in siblings.iter().enumerate() {
            let bit = (index >> lvl) & 1;
            let pair = if bit == 0 {
                [expected_cur, *sib]
            } else {
                [*sib, expected_cur]
            };
            let compressed = p3_compress.compress(pair);
            assert_eq!(compress_keccak_pair(&pair[0], &pair[1]), compressed);
            expected_cur = compressed;
        }
        let root = compute_merkle_root(leaf, index, &siblings)
            .unwrap_or_else(|e| panic!("compute root depth {depth}: {e:?}"));
        assert_eq!(root, expected_cur);

        let witness = MerklePathWitness {
            leaf,
            index,
            siblings: siblings.clone(),
        };
        let (trace, pvs, computed_root) = build_merkle_path_trace(&witness)
            .unwrap_or_else(|e| panic!("trace depth {depth}: {e:?}"));
        assert_eq!(computed_root, root);
        check_merkle_path_constraints(depth, &trace, &pvs)
            .unwrap_or_else(|e| panic!("constraints depth {depth}: {e:?}"));

        let run_full_stark = !cfg!(debug_assertions) || matches!(depth, 1 | 2 | 24);
        if run_full_stark {
            let (proof, proved_root) = prove_merkle_path(&witness)
                .unwrap_or_else(|e| panic!("prove depth {depth}: {e:?}"));
            assert_eq!(proved_root, root);
            verify_merkle_path(leaf, index, depth, root, &proof)
                .unwrap_or_else(|e| panic!("verify depth {depth}: {e:?}"));
        }
    }

    // End-to-end check against a genuine Plonky3 MerkleTreeMmcs matrix commitment opening.
    type ValHasher = SerializingHasher<Keccak256Hash>;
    type ValCompress = CompressionFunctionFromHasher<Keccak256Hash, 2, 32>;
    type ValMmcs = MerkleTreeMmcs<Goldilocks, u8, ValHasher, ValCompress, 2, 32>;

    let mmcs = ValMmcs::new(
        ValHasher::new(Keccak256Hash),
        ValCompress::new(Keccak256Hash),
        0,
    );
    let height = 16usize; // depth = 4
    let width = 4usize;
    let vals: Vec<Goldilocks> = (0..(height * width))
        .map(|i| Goldilocks::new((i as u64) * 13 + 7))
        .collect();
    let mat = RowMajorMatrix::new(vals, width);
    let dims = vec![mat.dimensions()];
    let (commit, prover_data) = mmcs.commit(vec![mat]);
    let query_index = 11usize;
    let opening = mmcs.open_batch(query_index, &prover_data);
    mmcs.verify_batch(&commit, &dims, query_index, (&opening).into())
        .unwrap_or_else(|e| panic!("native mmcs verify: {e:?}"));

    use p3_symmetric::CryptographicHasher;
    let leaf_hash = ValHasher::new(Keccak256Hash)
        .hash_iter_slices(opening.opened_values.iter().map(Vec::as_slice));
    let root_bytes: [u8; 32] = commit.as_ref()[0];
    let witness = MerklePathWitness {
        leaf: leaf_hash,
        index: query_index as u64,
        siblings: opening.opening_proof.clone(),
    };
    let (proof, chip_root) =
        prove_merkle_path(&witness).unwrap_or_else(|e| panic!("prove mmcs opening: {e:?}"));
    assert_eq!(chip_root, root_bytes);
    verify_merkle_path(leaf_hash, query_index as u64, 4, root_bytes, &proof)
        .unwrap_or_else(|e| panic!("verify mmcs opening: {e:?}"));
}

#[test]
fn fixed_vk_depends_only_on_depth_not_on_leaf_or_siblings() {
    let air_a = MerklePathAir::new(3).unwrap_or_else(|e| panic!("air: {e:?}"));
    let w1 = MerklePathWitness {
        leaf: deterministic_digest(1, 0),
        index: 2,
        siblings: vec![
            deterministic_digest(10, 0),
            deterministic_digest(11, 1),
            deterministic_digest(12, 2),
        ],
    };
    let w2 = MerklePathWitness {
        leaf: deterministic_digest(99, 0),
        index: 5,
        siblings: vec![
            deterministic_digest(20, 0),
            deterministic_digest(21, 1),
            deterministic_digest(22, 2),
        ],
    };
    let (p1, r1) = prove_merkle_path(&w1).unwrap_or_else(|e| panic!("p1: {e:?}"));
    let (p2, r2) = prove_merkle_path(&w2).unwrap_or_else(|e| panic!("p2: {e:?}"));
    assert_ne!(r1, r2);
    // Both proofs verify under one single preprocessed VK derived from depth = 3 alone.
    let cfg = bud_proof::plonky3_prover::build_config();
    let (_, vk_a) = bud_proof::bud_stark::setup_preprocessed(&cfg, &air_a, p1.degree_bits)
        .unwrap_or_else(|| panic!("setup vk_a"));
    let pvs_1 = bud_proof::chips::merkle_path::merkle_public_values(w1.leaf, r1, w1.index, 3);
    let pvs_2 = bud_proof::chips::merkle_path::merkle_public_values(w2.leaf, r2, w2.index, 3);
    bud_proof::bud_stark::verify_with_preprocessed(&cfg, &air_a, &p1, &pvs_1, Some(&vk_a))
        .unwrap_or_else(|e| panic!("vk_a verify p1: {e:?}"));
    bud_proof::bud_stark::verify_with_preprocessed(&cfg, &air_a, &p2, &pvs_2, Some(&vk_a))
        .unwrap_or_else(|e| panic!("vk_a verify p2: {e:?}"));
    verify_merkle_path(w1.leaf, w1.index, 3, r1, &p1).unwrap_or_else(|e| panic!("v1: {e:?}"));
    verify_merkle_path(w2.leaf, w2.index, 3, r2, &p2).unwrap_or_else(|e| panic!("v2: {e:?}"));
    // Cross-verifying p1 against w2's statement must fail.
    assert!(verify_merkle_path(w2.leaf, w2.index, 3, r2, &p1).is_err());
}

#[test]
fn flipped_sibling_flipped_index_and_wrong_root_are_rejected() {
    let witness = MerklePathWitness {
        leaf: deterministic_digest(0xCAFE, 0),
        index: 0b101,
        siblings: vec![
            deterministic_digest(0x1111, 0),
            deterministic_digest(0x2222, 1),
            deterministic_digest(0x3333, 2),
        ],
    };
    let (proof, root) = prove_merkle_path(&witness).unwrap_or_else(|e| panic!("prove: {e:?}"));

    // 1. Wrong root rejected by STARK verifier.
    let mut wrong_root = root;
    wrong_root[0] ^= 1;
    assert!(verify_merkle_path(witness.leaf, witness.index, 3, wrong_root, &proof).is_err());

    // 2. Wrong leaf rejected by STARK verifier.
    let mut wrong_leaf = witness.leaf;
    wrong_leaf[31] ^= 0x80;
    assert!(verify_merkle_path(wrong_leaf, witness.index, 3, root, &proof).is_err());

    // 3. Flipped public index bit rejected by STARK verifier.
    assert!(verify_merkle_path(witness.leaf, witness.index ^ 1, 3, root, &proof).is_err());
    assert!(verify_merkle_path(witness.leaf, witness.index ^ 0b100, 3, root, &proof).is_err());

    // 4. Flipped sibling limb in the witness trace rejected by AIR constraints.
    let (mut bad_sib_trace, pvs, _) =
        build_merkle_path_trace(&witness).unwrap_or_else(|e| panic!("trace: {e:?}"));
    bad_sib_trace.values[COL_SIB_LIMBS_BASE] =
        Goldilocks::new(bad_sib_trace.values[COL_SIB_LIMBS_BASE].as_canonical_u64() ^ 1);
    assert!(check_merkle_path_constraints(3, &bad_sib_trace, &pvs).is_err());

    // 5. Flipped index_bit in the witness trace rejected by AIR constraints.
    let (mut bad_bit_trace, pvs, _) =
        build_merkle_path_trace(&witness).unwrap_or_else(|e| panic!("trace: {e:?}"));
    for r in 0..24 {
        let w = bad_bit_trace.width();
        bad_bit_trace.values[r * w + COL_INDEX_BIT] = Goldilocks::ZERO;
    }
    assert!(check_merkle_path_constraints(3, &bad_bit_trace, &pvs).is_err());

    // 6. Non-boolean index_bit (2) rejected by AIR constraints.
    let (mut non_bool_trace, pvs, _) =
        build_merkle_path_trace(&witness).unwrap_or_else(|e| panic!("trace: {e:?}"));
    non_bool_trace.values[COL_INDEX_BIT] = Goldilocks::new(2);
    assert!(check_merkle_path_constraints(3, &non_bool_trace, &pvs).is_err());

    // 7. Spliced two-level Merkle trace (both Keccak permutations valid in isolation,
    //    but level 1 starts from an unrelated digest instead of level 0's output)
    //    must be rejected solely by the inter-level digest chain constraint.
    let w_bottom = MerklePathWitness {
        leaf: deterministic_digest(0xAAAA, 0),
        index: 0b01,
        siblings: vec![
            deterministic_digest(0xBBBB, 0),
            deterministic_digest(0xCCCC, 1),
        ],
    };
    let w_top_forged = MerklePathWitness {
        leaf: deterministic_digest(0xDEAD, 0),
        index: 0b01,
        siblings: vec![
            deterministic_digest(0xEEEE, 0),
            deterministic_digest(0xCCCC, 1),
        ],
    };
    let (mut spliced_trace, _, _) =
        build_merkle_path_trace(&w_bottom).unwrap_or_else(|e| panic!("w_bottom: {e:?}"));
    let (forged_top_trace, forged_top_pvs, forged_root) =
        build_merkle_path_trace(&w_top_forged).unwrap_or_else(|e| panic!("w_top: {e:?}"));
    let w = spliced_trace.width();
    // Copy level 1 (rows 24..48) from the forged trace, preserving index_acc = 1.
    spliced_trace.values[24 * w..48 * w].copy_from_slice(&forged_top_trace.values[24 * w..48 * w]);
    let spliced_pvs = bud_proof::chips::merkle_path::merkle_public_values(
        w_bottom.leaf,
        forged_root,
        w_bottom.index,
        2,
    );
    let _ = forged_top_pvs;
    assert!(check_merkle_path_constraints(2, &spliced_trace, &spliced_pvs).is_err());
}

#[test]
fn out_of_bounds_depth_and_index_are_refused_fail_closed() {
    let d0 = deterministic_digest(7, 0);
    let zero_depth = MerklePathAir::new(0);
    assert!(zero_depth.is_err());
    assert_eq!(zero_depth.err(), Some(MerklePathChipError::InvalidDepth(0)));

    let deep = MerklePathAir::new(MAX_MERKLE_DEPTH + 1);
    assert!(deep.is_err());
    assert_eq!(
        deep.err(),
        Some(MerklePathChipError::InvalidDepth(MAX_MERKLE_DEPTH + 1))
    );

    let oob = prove_merkle_path(&MerklePathWitness {
        leaf: d0,
        index: 2,
        siblings: vec![d0],
    });
    assert!(oob.is_err());
    assert_eq!(
        oob.err(),
        Some(MerklePathChipError::IndexOutOfBounds { index: 2, depth: 1 })
    );
}
