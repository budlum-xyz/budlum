//! WP-04 regression evidence for fixes present at the live audit base.
//! These tests do not close findings without a recorded green CI run.

use crate::light_client::{LightClient, TrustedCheckpoint};

fn anchored_at(height: u64) -> LightClient {
    LightClient::new(TrustedCheckpoint {
        height,
        block_hash: "00".repeat(32),
        set_hash: "11".repeat(32),
    })
    .unwrap()
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
