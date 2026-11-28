// This file is included from `stark.rs` only in test builds.
use super::*;

#[test]
fn postfix_shape_determines_recursion_level_and_rejects_malformed_tree() {
    assert_eq!(recursion_level_for_shape(&[SHAPE_TICK]), Ok(0));
    assert_eq!(
        recursion_level_for_shape(&[SHAPE_TICK, SHAPE_TICK, SHAPE_MERGE]),
        Ok(1)
    );
    assert_eq!(
        recursion_level_for_shape(&[
            SHAPE_TICK,
            SHAPE_TICK,
            SHAPE_MERGE,
            SHAPE_TICK,
            SHAPE_TICK,
            SHAPE_MERGE,
            SHAPE_MERGE,
        ]),
        Ok(2)
    );
    assert!(recursion_level_for_shape(&[SHAPE_TICK, SHAPE_MERGE]).is_err());
    assert!(recursion_level_for_shape(&[SHAPE_TICK, SHAPE_TICK]).is_err());
}

#[test]
fn child_verification_key_digest_is_parameter_set_bound_and_deterministic() {
    let key_a = agg_fold_child_verification_key_hash(STARK_PARAMETER_SET);
    let key_a_again = agg_fold_child_verification_key_hash(STARK_PARAMETER_SET);
    let key_b = agg_fold_child_verification_key_hash(STARK_PARAMETER_SET + 1);
    assert_eq!(key_a, key_a_again);
    assert_ne!(key_a, key_b);
    assert_ne!(key_a, [0; 32]);
}

#[test]
fn recursive_context_is_committed_into_the_air_statement_digest() {
    let segments = Vec::new();
    let shape = [SHAPE_TICK];
    let child_key = agg_fold_child_verification_key_hash(STARK_PARAMETER_SET);
    let level_zero = compute_shape_digest(43, 0, &[0; 32], &segments, &shape);
    let level_one = compute_shape_digest(43, 1, &child_key, &segments, &shape);
    let wrong_child = compute_shape_digest(43, 1, &[0xA5; 32], &segments, &shape);
    let wrong_domain = compute_shape_digest(44, 1, &child_key, &segments, &shape);
    assert_ne!(level_zero, level_one);
    assert_ne!(level_one, wrong_child);
    assert_ne!(level_one, wrong_domain);
}
