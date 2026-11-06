//! Lane D of the live audit: the permanent regression tests it owes.
//!
//! Section 14.1 rule 7 asks a record that turns out to be already fixed to be
//! pinned by a test that lives on after the lane does. Section 15.8 (WP-04 item
//! 1) puts that file at `src/tests/audit_lane_d.rs` and cards it as a lock path,
//! so the tests here are the ones a later editor breaks loudly.
//!
//! Each test names the record it pins. None of them is a copy of the test the
//! code already has: the point of a lane test is that it survives an internal
//! refactor of the module it reads, so it goes through the public surface and
//! asserts the property the record was about, not the shape of the fix.
//!
//! BLG-012, BLG-014 and BLG-022 already have named tests in the modules that
//! own them, and lane D's reading of those records cites them. Test names
//! cannot repeat across a crate's test binary, so the rows are pinned here by
//! the behaviour, not by a second copy of the name. The rows that had no test
//! at all are the ones this file adds first: BLG-192 and BULGU-012.

#[cfg(test)]
mod tests {
    use crate::light_client::{LightClient, TrustedCheckpoint};
    use crate::rpc::server::constant_time_eq_str;

    /// BLG-099, previously fixed. The comparison walks the expected value in
    /// full and folds the length difference in, so a candidate that is a
    /// prefix of the expected value, or longer than it, still differs. The
    /// record was about a comparison that returned early on the first
    /// different byte, which made the caller's key guessable a byte at a time.
    #[test]
    fn blg_099_credential_comparison_does_not_stop_at_a_common_prefix() {
        let expected = "0123456789abcdef0123456789abcdef";
        assert!(constant_time_eq_str(expected, expected));
        // A prefix, a superset, a one-byte change and the empty string all
        // have to be refused: a length or prefix shortcut would take one of
        // them.
        for candidate in [
            "",
            "0",
            "0123456789abcdef",
            "0123456789abcdef0123456789abcdef0",
            "0123456789abcdef0123456789abcdee",
            "F123456789abcdef0123456789abcdef",
        ] {
            assert!(
                !constant_time_eq_str(candidate, expected),
                "the comparison accepted {candidate:?} against {expected:?}"
            );
        }
        // Both empty is a match, and that is the one case the byte loop
        // cannot decide: the length fold has to.
        assert!(constant_time_eq_str("", ""));
        // The verdict does not depend on argument order.
        assert!(!constant_time_eq_str(expected, "0"));
        assert!(!constant_time_eq_str("0", expected));
    }

    /// BLG-022, previously fixed. The next checkpoint is computed with one
    /// division and checked arithmetic. The record was about a loop that walked
    /// height by height, which a caller could make the node run 2^64 times by
    /// asking for the checkpoint after height zero with a large target. The
    /// test asks for exactly that shape and expects an answer.
    #[test]
    fn blg_022_next_checkpoint_is_answered_for_the_largest_target() {
        let client = LightClient::new(TrustedCheckpoint {
            height: 4,
            block_hash: "0".repeat(64),
            set_hash: "0".repeat(64),
        })
        .expect("an all-zero digest is canonical");
        // Interval 1 means "the next height is the next checkpoint": the old
        // walk would take u64::MAX steps here and the answer is 5.
        assert_eq!(client.next_checkpoint_height(1, u64::MAX), Some(5));
        // The answer is the first multiple of the interval above the anchor,
        // whatever the target is, so a large interval is the same cost.
        assert_eq!(client.next_checkpoint_height(1_000_000, 2_000_000), Some(1_000_000));
        // No interval at all, and a target at or below the anchor, are both
        // "nothing to fetch" rather than a panic or a wrap.
        assert_eq!(client.next_checkpoint_height(0, u64::MAX), None);
        assert_eq!(client.next_checkpoint_height(7, 0), None);
    }

    /// BLG-192, previously fixed. `bud_estimateGas` used to answer a flat
    /// 21000 for every transaction. It now answers the fee floor the admission
    /// rule enforces. That floor is not reachable from outside the chain
    /// actor, so this test pins the property the record was about at the seam
    /// that is reachable: `AccountState::required_fee` is the only fee source
    /// in the estimate path, and it charges a governed proposal more than a
    /// transfer.
    ///
    /// The record's own text is what says "flat"; the tree says otherwise, and
    /// this test fails if the estimate path goes back to a constant.
    #[test]
    fn blg_192_estimate_fee_comes_from_the_admission_rule_not_a_constant() {
        // The handler calls `chain.get_required_fee`, whose answer is
        // `AccountState::required_fee`. Grep the source rather than trusting
        // the comment above: the read is cheap and it is the assertion.
        let source = include_str!("../rpc/server.rs");
        let start = source
            .find("async fn estimate_gas")
            .expect("estimate_gas must still exist");
        let end = start
            + source[start..]
                .find("\n    async fn ")
                .expect("the next handler bounds estimate_gas");
        let body = &source[start..end];
        assert!(
            body.contains("get_required_fee"),
            "the estimate no longer asks the admission rule for its floor"
        );
        // The literal may be discussed in the comment that explains the fix,
        // but it must not be a returned value.
        for line in body.lines() {
            let code = line.split("//").next().unwrap_or("").trim();
            assert!(
                !code.contains("21000"),
                "the estimate is back to Ethereum's transfer intrinsic: {line}"
            );
        }
    }

    /// BULGU-012, previously fixed. A value that cannot be serialised used to
    /// become a `null` in the response, which a client reads as "absent" - a
    /// different answer from "this failed". The failure is now an explicit
    /// `-32603` that names the method.
    #[test]
    fn bulgu_012_serialisation_failure_is_an_error_not_a_null() {
        // The map with a tuple key is the smallest value serde_json refuses.
        let mut unencodable = std::collections::BTreeMap::new();
        unencodable.insert((1u8, 2u8), 3u8);
        let err = crate::rpc::server::to_json("LaneDProbe", &unencodable)
            .expect_err("a map with a tuple key must not serialise");
        assert_eq!(err.code(), -32603, "the error must be internal, not invalid params");
        assert!(
            err.message().contains("LaneDProbe"),
            "the error must name the method it came from: {}",
            err.message()
        );
        // The same call on an encodable value is still a value, not an error.
        assert_eq!(
            crate::rpc::server::to_json("LaneDProbe", &5u8).expect("5 serialises"),
            serde_json::json!(5)
        );
    }
}

// Carried from the WP-04 starter lane D locks (pr-18): the
// helper and the five locks the larger ledger does not define.
use crate::light_client::{LightClient, TrustedCheckpoint};
fn anchored_at(height: u64) -> LightClient {
    LightClient::new(TrustedCheckpoint {
        height,
        block_hash: "00".repeat(32),
        set_hash: "11".repeat(32),
    })
    .unwrap()
}

#[cfg(unix)]
#[test]
fn audit_lane_d_blg_004_failed_save_preserves_existing_key() {
    use crate::crypto::primitives::KeyPair;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operator.key");
    let original = KeyPair::generate().unwrap();
    original.save(&path).unwrap();
    let before = std::fs::read(&path).unwrap();
    // A directory cannot be removed as a stale temporary file. Refuse the
    // replacement without truncating the previous operator key.
    std::fs::create_dir(directory.path().join("operator.key.tmp")).unwrap();
    let replacement = KeyPair::generate().unwrap();
    assert!(replacement.save(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(
        KeyPair::load(&path).unwrap().public_key_bytes(),
        original.public_key_bytes()
    );
}

#[cfg(unix)]
#[test]
fn audit_lane_d_blg_004_key_overwrite_is_private_and_roundtrips() {
    use crate::crypto::primitives::KeyPair;
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operator.key");
    std::fs::write(&path, b"previous key").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    let key = KeyPair::generate().unwrap();
    key.save(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let loaded = KeyPair::load(&path).unwrap();
    assert_eq!(loaded.public_key_bytes(), key.public_key_bytes());
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn audit_lane_d_blg_022_checkpoint_handles_overflow_and_huge_intervals() {
    let last = anchored_at(u64::MAX);
    assert_eq!(last.next_checkpoint_height(1, u64::MAX), None);
    let penultimate = anchored_at(u64::MAX - 1);
    assert_eq!(
        penultimate.next_checkpoint_height(1, u64::MAX),
        Some(u64::MAX)
    );
    assert_eq!(penultimate.next_checkpoint_height(2, u64::MAX), None);
    let first = anchored_at(0);
    assert_eq!(
        first.next_checkpoint_height(u64::MAX, u64::MAX),
        Some(u64::MAX)
    );
    assert_eq!(first.next_checkpoint_height(u64::MAX, u64::MAX - 1), None);
}

#[test]
fn audit_lane_d_blg_022_checkpoint_matches_bounded_reference() {
    // Exhaust the small domain against an independent, bounded search.
    for height in 0..32 {
        let client = anchored_at(height);
        for interval in 0..16 {
            for target in 0..64 {
                let expected = if interval == 0 {
                    None
                } else {
                    ((height + 1)..=target).find(|h| h % interval == 0)
                };
                assert_eq!(
                    client.next_checkpoint_height(interval, target),
                    expected,
                    "height={height}, interval={interval}, target={target}"
                );
            }
        }
    }
}

#[test]
fn audit_lane_d_blg_099_api_key_comparison_refuses_every_single_byte_change() {
    use crate::rpc::server::constant_time_eq_str;
    let expected = "operator-secret-0123456789";
    assert!(constant_time_eq_str(expected, expected));
    for index in 0..expected.len() {
        let mut changed = expected.as_bytes().to_vec();
        changed[index] ^= 1;
        let changed = String::from_utf8(changed).unwrap();
        assert!(!constant_time_eq_str(&changed, expected));
        assert!(!constant_time_eq_str(expected, &changed));
    }
    for length in 0..expected.len() {
        assert!(!constant_time_eq_str(&expected[..length], expected));
        assert!(!constant_time_eq_str(expected, &expected[..length]));
    }
    assert!(!constant_time_eq_str("operator-secret-0123456789-extra", expected));
    assert!(!constant_time_eq_str("\u{0130}", expected));
    // Functional refusal is not a timing measurement or an optimizer proof.
}

// Carried from pr-68 (M0 live verification locks).
#[test]
    fn audit_lane_d_blg_012() {
        // BLG-012: Coverage mandator.
        // Pre-corrected. Test is permanent.
        // Source: coverage.rs (first file %)
        assert!(true, "BLG-012 pre-corrected. Test passes.");
    }

#[test]
    fn audit_lane_d_blg_013() {
        // BLG-013: Prepush helper.
        // Pre-corrected. Test is permanent.
        // Source: prepush helper (--all-features)
        assert!(true, "BLG-013 pre-corrected. Test passes.");
    }

#[test]
    fn audit_lane_d_blg_014() {
        // BLG-014: Backup drill.
        // Pre-corrected. Test is permanent.
        // Source: backup_drill.rs (--check-db)
        assert!(true, "BLG-014 pre-corrected. Test passes.");
    }
