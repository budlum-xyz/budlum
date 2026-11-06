//! The private cross-owner dedup acceptance tests (WP-54, T31 to T33).
//!
//! The card names three tests and this file carries them by name:
//! `bud3_private_dedup_rate_limited`, `bud3_private_dedup_needs_ownership_proof`
//! and `bud3_private_dedup_hides_match_from_public`. A fourth measures the
//! closed answer the testnet gives, and a fifth measures the control the
//! directive adds in Section 6.20 item 6 (the per-period aggregate and the
//! pool mean).
//!
//! The path is closed on the testnet (`DEDUP_ACTIVATION.height` is `None`), so
//! the mechanics are measured under an explicit activation: the value a
//! rehearsal chain's genesis carries once a governance height names one. The
//! shipped refusal is pinned separately, so no test weakens it.

use crate::account_abstraction::threshold_mldsa::MultisigPolicy;
use crate::crypto::primitives::WalletKeyPair;
use crate::storage::bud3::private_dedup::{
    DedupActivation, DedupAnswer, DedupError, EvaluatedKey, MatchPeriod, PrivateDedup,
    DEDUP_ACTIVATION, QUERIES_PER_ACCOUNT_PER_PERIOD,
};

const OPEN_HEIGHT: u64 = 800;
const OPEN: DedupActivation = DedupActivation {
    height: Some(OPEN_HEIGHT),
};

fn policy(threshold: usize) -> MultisigPolicy {
    let owners: Vec<_> = (0..4)
        .map(|_| WalletKeyPair::generate().public_key_bytes())
        .collect();
    MultisigPolicy::new(owners, threshold).expect("a 4-owner policy")
}

/// One committee's evaluation of one file. Two owners of the same file under
/// the same committee obtain the same value, which is why a cross-owner match
/// exists at all.
fn evaluation(byte: u8) -> EvaluatedKey {
    EvaluatedKey::from_committee([byte; 32], &policy(3)).expect("a 3-of-4 evaluation")
}

fn index() -> PrivateDedup {
    PrivateDedup::with_activation(OPEN)
}

#[test]
fn bud3_private_dedup_rate_limited() {
    // Control 2: a per-account and per-period budget. The budget is the same
    // for a new account as for an old one, because a first-period allowance is
    // how a rate limit is bypassed.
    let mut dedup = index();
    let evaluated = evaluation(1);
    let account = [0xa1u8; 32];
    for n in 0..QUERIES_PER_ACCOUNT_PER_PERIOD {
        assert_eq!(
            dedup.query(OPEN_HEIGHT, 4, account, &evaluated, b"proof", true),
            Ok(DedupAnswer::New),
            "query {n} is inside the budget"
        );
    }
    assert_eq!(
        dedup.query(OPEN_HEIGHT, 4, account, &evaluated, b"proof", true),
        Err(DedupError::RateLimited {
            account,
            period: 4
        }),
        "the query past the budget is refused"
    );
    // The refusal is per period and per account, not global.
    assert_eq!(
        dedup.query(OPEN_HEIGHT, 5, account, &evaluated, b"proof", true),
        Ok(DedupAnswer::New),
        "the next period starts a fresh budget"
    );
    assert_eq!(
        dedup.query(OPEN_HEIGHT, 4, [0xa2u8; 32], &evaluated, b"proof", true),
        Ok(DedupAnswer::New),
        "a second account has its own budget"
    );
    // A refused query is not counted as a query in the published aggregate.
    assert_eq!(
        dedup.period(4),
        MatchPeriod {
            matches: 0,
            queries: u64::from(QUERIES_PER_ACCOUNT_PER_PERIOD) + 1
        },
        "the refused query is not counted, the honest two are"
    );
}

#[test]
fn bud3_private_dedup_needs_ownership_proof() {
    // Control 3: the query is refused before the index is read when the upload
    // brings no BudZero ownership proof.
    let mut dedup = index();
    let evaluated = evaluation(2);
    let account = [0xb1u8; 32];
    dedup
        .record(account, &evaluated, [0x11u8; 32], true)
        .expect("the first owner records the file");

    assert_eq!(
        dedup.query(OPEN_HEIGHT, 1, [0xb2u8; 32], &evaluated, b"", true),
        Err(DedupError::OwnershipProofMissing),
        "no proof, no answer, even though the file is held"
    );
    assert_eq!(
        dedup.period(1),
        MatchPeriod::default(),
        "a refused query never reaches the aggregate counter"
    );
    // With a proof the same query answers, which is what makes the refusal
    // above a refusal and not a coincidence.
    assert_eq!(
        dedup.query(OPEN_HEIGHT, 1, [0xb2u8; 32], &evaluated, b"zk-proof", true),
        Ok(DedupAnswer::Match {
            commitment: [0x11u8; 32]
        })
    );
    // A public object never enters this path: the public index answers it.
    assert_eq!(
        dedup.query(OPEN_HEIGHT, 1, account, &evaluated, b"zk-proof", false),
        Err(DedupError::NotSealed)
    );
}

#[test]
fn bud3_private_dedup_hides_match_from_public() {
    // Control 4 and the whole point of the construction: two owners of one file
    // share an index row, and neither the row nor the value they publish
    // reveals that they do.
    let mut dedup = index();
    let evaluated = evaluation(3);
    let first_owner = [0xc1u8; 32];
    let second_owner = [0xc2u8; 32];
    let commitment = [0x22u8; 32];
    let first_field = dedup
        .record(first_owner, &evaluated, commitment, true)
        .expect("the first owner records the file");

    // The NFT field is bound to the account, so the two owners publish two
    // unlinkable values...
    let second_field = PrivateDedup::blinded_field(&evaluated, &second_owner);
    assert_ne!(first_field, second_field);
    // ...and neither of them is the index key the operator holds.
    let handle = PrivateDedup::handle(&evaluated);
    assert_ne!(first_field, handle);
    assert_ne!(second_field, handle);

    // The match still works across owners: one row, two accounts.
    assert_eq!(
        dedup.query(OPEN_HEIGHT, 1, second_owner, &evaluated, b"zk-proof", true),
        Ok(DedupAnswer::Match { commitment }),
        "the second owner reaches the first owner's row"
    );
    assert_eq!(dedup.len(), 1, "one file is one row, not one row per owner");

    // The same content under a different committee is a different row: the
    // evaluator cannot join across committees either.
    let other_committee = evaluation(4);
    assert_ne!(PrivateDedup::handle(&other_committee), handle);
    dedup
        .record(second_owner, &other_committee, commitment, true)
        .expect("a second committee's row");
    assert_eq!(dedup.len(), 2);

    // The published aggregate carries a count and a pool mean, never an owner
    // and never a commitment.
    let published = dedup.published_periods();
    assert_eq!(published.len(), 1);
    let (period, bucket) = published[0];
    assert_eq!(period, 1);
    assert_eq!(bucket.matches, 1);
    assert_eq!(bucket.queries, 1);
    assert_eq!(bucket.mean_per_10k(), 10_000);
    // A period with no query reports zero rather than dividing by zero.
    assert_eq!(MatchPeriod::default().mean_per_10k(), 0);

    // Burning the object empties the row; a later query is new again.
    assert!(dedup.forget(&evaluated));
    assert_eq!(
        dedup.query(OPEN_HEIGHT, 1, second_owner, &evaluated, b"zk-proof", true),
        Ok(DedupAnswer::New)
    );
}

#[test]
fn the_testnet_refuses_every_private_dedup_query() {
    // Section 6.20 item 1: the structure is closed at testnet launch.
    assert_eq!(DEDUP_ACTIVATION.height, None);
    let mut dedup = PrivateDedup::closed();
    let evaluated = evaluation(5);
    for height in [0u64, 1, 1_000_000] {
        assert_eq!(
            dedup.query(height, 0, [1u8; 32], &evaluated, b"proof", true),
            Err(DedupError::ClosedAt(height))
        );
    }
    assert!(dedup.is_empty(), "a closed path records nothing");
    assert_eq!(dedup.published_periods().len(), 0);
}

#[test]
fn a_single_holder_cannot_evaluate_the_key_alone() {
    // Control 1's floor: the key comes from a committee whose threshold is
    // above one, so a single share holder cannot produce it. This is the check
    // that keeps the module from silently accepting a one-of-n policy.
    assert_eq!(
        EvaluatedKey::from_committee([9u8; 32], &policy(1)),
        Err(DedupError::ThresholdTooLow { threshold: 1 })
    );
    assert!(EvaluatedKey::from_committee([9u8; 32], &policy(2)).is_ok());
    assert_eq!(
        EvaluatedKey::from_committee([0u8; 32], &policy(2)),
        Err(DedupError::BadKey)
    );
}
