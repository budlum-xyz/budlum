//! The object replacement flow: a new representation of the same content
//! replaces the object under the same content id. The triggers are a layer
//! transition, a new codec or a new dedup match. The content id never
//! changes; a change of content is a different object and is refused.
//!
//! The proposer is a Full validator of the object's placement group. At
//! least [`REPLACEMENT_VALIDATIONS`] independent Full validators of that
//! group decode the new object and confirm its content id; each signs the
//! validation message. A replacement that would produce different content
//! is refused and the proposer is punished under the proven-guilty faulty
//! repair rule.

use super::content_id::{ContentId, ContentIdKind};
use super::pipeline::ObjectRecord;
use super::registry::{Address, ObjectKey, RegistryError};
use crate::core::hash::hash_fields_bytes;
use crate::crypto::primitives::verify_signature;
use std::collections::BTreeSet;

/// Independent Full validators that must decode and verify the new object.
pub const REPLACEMENT_VALIDATIONS: usize = 3;

/// The tag of the replacement validation message.
pub const REPLACE_TAG: &[u8] = b"BDLM_BUD3_REPLACE_V1";

fn content_kind_byte(kind: ContentIdKind) -> u8 {
    match kind {
        ContentIdKind::Public => 0,
        ContentIdKind::Sealed => 1,
    }
}

/// The message the validating Full validators sign: the content id, the old
/// and the new commitment, and the new object length, every input length
/// prefixed.
#[must_use]
pub fn validation_message(
    content: &ContentId,
    old_object: &ObjectKey,
    new_commitment: &ObjectKey,
    object_len: u64,
) -> [u8; 32] {
    hash_fields_bytes(&[
        REPLACE_TAG,
        &[content_kind_byte(content.kind)],
        &content.digest,
        &content.len.to_le_bytes(),
        old_object,
        new_commitment,
        &object_len.to_le_bytes(),
    ])
}

/// Check the validation signatures: at least [`REPLACEMENT_VALIDATIONS`]
/// distinct Full holders of the old placement signed the validation message
/// of this exact replacement.
///
/// # Errors
///
/// [`RegistryError::BadReplacement`] when a signer is not a Full holder of
/// the old placement, a signer repeats, a signature does not verify, or
/// there are fewer than [`REPLACEMENT_VALIDATIONS`] validations.
pub fn verify_validations(
    content: &ContentId,
    old_object: &ObjectKey,
    new_record: &ObjectRecord,
    full_holders: &BTreeSet<Address>,
    validations: &[([u8; 32], [u8; 64])],
) -> Result<(), RegistryError> {
    let message = validation_message(
        content,
        old_object,
        &new_record.commitment,
        new_record.object_len,
    );
    let mut seen = BTreeSet::new();
    for (validator, signature) in validations {
        if !full_holders.contains(validator) {
            return Err(RegistryError::BadReplacement(
                "a validator is not a Full holder of the old placement",
            ));
        }
        if !seen.insert(*validator) {
            return Err(RegistryError::BadReplacement(
                "the validations are not independent",
            ));
        }
        if verify_signature(&message, signature, validator).is_err() {
            return Err(RegistryError::BadReplacement(
                "a validation signature does not verify",
            ));
        }
    }
    if seen.len() < REPLACEMENT_VALIDATIONS {
        return Err(RegistryError::BadReplacement(
            "fewer than three validations",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::limits::{Bud3Limits, Profile};
    use super::super::pipeline::prepare_public_upload;
    use super::super::placement::{Class, Share};
    use super::super::registry::{Bud3Registry, Registered, ShareStatus};
    use super::*;
    use crate::crypto::primitives::KeyPair;

    const P: Profile = Profile {
        id: 0,
        qr_version: 40,
        symbol_size: 128,
        fps: 10,
        k_max: 16,
    };

    /// A second profile: the same content segments differently, so its new
    /// representation is a new object under the same content id.
    const P2: Profile = Profile {
        id: 1,
        qr_version: 40,
        symbol_size: 64,
        fps: 10,
        k_max: 16,
    };

    fn keys(n: usize) -> Vec<KeyPair> {
        (0..n).map(|_| KeyPair::generate().unwrap()).collect()
    }

    /// Four Full holders of five symbols per segment: 20 symbols, enough
    /// for `k + 2` in every segment of either profile.
    fn placement(holders: &[KeyPair], segments: u64) -> Vec<(u64, Share)> {
        let mut shares = Vec::new();
        for seg in 0..segments {
            for (h, kp) in holders.iter().enumerate() {
                shares.push((
                    seg,
                    Share {
                        validator: kp.public_key_bytes(),
                        class: Class::Full,
                        first_esi: u32::try_from(h).unwrap() * 5,
                        symbols: 5,
                    },
                ));
            }
        }
        shares
    }

    fn signed_validations(
        holders: &[KeyPair],
        content: &ContentId,
        old: &ObjectKey,
        new: &ObjectKey,
        object_len: u64,
    ) -> Vec<([u8; 32], [u8; 64])> {
        let message = validation_message(content, old, new, object_len);
        holders
            .iter()
            .map(|kp| (kp.public_key_bytes(), kp.sign(&message)))
            .collect()
    }

    /// Register `content` under `profile` and return the record and the
    /// segment count.
    fn representation(content: &[u8], profile: &Profile) -> (ObjectRecord, u64) {
        let up = prepare_public_upload(content, profile, &Bud3Limits::default(), 20).unwrap();
        let segments = up.segments.len() as u64;
        (up.record, segments)
    }

    fn setup(content: &[u8]) -> (Bud3Registry, Vec<KeyPair>, Address, ObjectRecord, ObjectRecord) {
        let (old_record, old_segments) = representation(content, &P);
        let (new_record, _) = representation(content, &P2);
        let holders = keys(4);
        let proposer = holders[0].public_key_bytes();
        let mut r = Bud3Registry::default();
        r.register_object(
            proposer,
            old_record.clone(),
            placement(&holders, old_segments),
            0,
            100,
        )
        .unwrap();
        r.bind_nft([9; 32], proposer, &old_record.commitment).unwrap();
        (r, holders, proposer, old_record, new_record)
    }

    /// Acceptance: a valid replacement keeps the content id and moves the
    /// NFT atomically; a replacement that would produce different content
    /// is refused and changes nothing.
    #[test]
    fn bud3_object_replacement() {
        let content = vec![0x5A_u8; 2500];
        let (mut r, holders, proposer, old_record, new_record) = setup(&content);
        let old_key = old_record.commitment;
        let new_key = new_record.commitment;
        assert_ne!(old_key, new_key, "the new representation is a new object");
        assert_eq!(old_record.content_id, new_record.content_id);

        // Three independent Full validators of the old placement, not the
        // proposer, sign the new commitment.
        let validations = signed_validations(
            &holders[1..4],
            &old_record.content_id,
            &old_key,
            &new_key,
            new_record.object_len,
        );
        let new_segments = new_record.symbol_roots.len() as u64;
        let replaced = r.replace_object(
            &proposer,
            old_record.content_id.clone(),
            &old_key,
            new_record.clone(),
            placement(&holders, new_segments),
            &validations,
        );
        assert_eq!(replaced, Ok(new_key));

        // The content id is unchanged and the NFT moved atomically.
        let entry = r.object(&new_key).unwrap();
        assert_eq!(entry.record.content_id, old_record.content_id);
        assert_eq!(entry.supersedes, Some(old_key));
        assert_eq!(r.refcount(&new_key), 1);
        assert_eq!(r.refcount(&old_key), 0);
        assert!(entry.shares.iter().all(|s| s.status == ShareStatus::Pending));
        // The old shares stay until the new ones are confirmed.
        assert!(r.object(&old_key).is_some());
        // The dedup index resolves to the new key.
        let mut third = new_record.clone();
        third.commitment = [0x33; 32];
        assert_eq!(
            r.register_object(proposer, third, placement(&holders, new_segments), 5, 100),
            Ok(Registered::Deduplicated(new_key))
        );

        // A replacement that would produce different content is refused.
        let other = vec![0x9C_u8; 2500];
        let (other_record, other_segments) = representation(&other, &P2);
        let root = r.state_root();
        let bad = signed_validations(
            &holders[1..4],
            &other_record.content_id,
            &old_key,
            &other_record.commitment,
            other_record.object_len,
        );
        assert_eq!(
            r.replace_object(
                &proposer,
                old_record.content_id.clone(),
                &old_key,
                other_record,
                placement(&holders, other_segments),
                &bad,
            ),
            Err(RegistryError::ContentIdChanged)
        );
        assert_eq!(r.state_root(), root, "a refused replacement changes nothing");
    }

    /// Once every new share is confirmed, the replaced object and its stale
    /// chain are deleted; the delete must not take the dedup entry that now
    /// names the new key.
    #[test]
    fn a_confirmed_replacement_deletes_the_old_object() {
        let content = vec![0x2B_u8; 2500];
        let (mut r, holders, proposer, old_record, new_record) = setup(&content);
        let old_key = old_record.commitment;
        let new_key = new_record.commitment;
        let validations = signed_validations(
            &holders[1..4],
            &old_record.content_id,
            &old_key,
            &new_key,
            new_record.object_len,
        );
        let new_segments = new_record.symbol_roots.len() as u64;
        r.replace_object(
            &proposer,
            old_record.content_id.clone(),
            &old_key,
            new_record.clone(),
            placement(&holders, new_segments),
            &validations,
        )
        .unwrap();

        // Confirmations by half of the holders keep the old object.
        for kp in &holders[..2] {
            r.ack(&new_key, &kp.public_key_bytes(), 7).unwrap();
        }
        assert!(r.object(&old_key).is_some());
        for kp in &holders[2..] {
            r.ack(&new_key, &kp.public_key_bytes(), 7).unwrap();
        }
        assert!(r.object(&old_key).is_none());
        assert_eq!(r.tombstone(&old_key), Some(7));
        assert!(r.object(&new_key).is_some());
        // The dedup entry survived the delete and still names the new key.
        let mut third = new_record;
        third.commitment = [0x44; 32];
        assert_eq!(
            r.register_object(proposer, third, placement(&holders, new_segments), 8, 100),
            Ok(Registered::Deduplicated(new_key))
        );
    }

    /// A tampered or unsigned validation is refused and changes nothing.
    #[test]
    fn a_tampered_validation_is_refused() {
        let content = vec![0x77_u8; 2500];
        let (mut r, holders, proposer, old_record, new_record) = setup(&content);
        let old_key = old_record.commitment;
        let new_key = new_record.commitment;
        let mut validations = signed_validations(
            &holders[1..4],
            &old_record.content_id,
            &old_key,
            &new_key,
            new_record.object_len,
        );
        validations[0].1 = [0xFF; 64];
        let new_segments = new_record.symbol_roots.len() as u64;
        let root = r.state_root();
        assert_eq!(
            r.replace_object(
                &proposer,
                old_record.content_id.clone(),
                &old_key,
                new_record.clone(),
                placement(&holders, new_segments),
                &validations,
            ),
            Err(RegistryError::BadReplacement(
                "a validation signature does not verify",
            ))
        );
        // Two validations are fewer than three.
        let good = signed_validations(
            &holders[1..3],
            &old_record.content_id,
            &old_key,
            &new_key,
            new_record.object_len,
        );
        assert_eq!(
            r.replace_object(
                &proposer,
                old_record.content_id.clone(),
                &old_key,
                new_record,
                placement(&holders, new_segments),
                &good,
            ),
            Err(RegistryError::BadReplacement(
                "fewer than three validations",
            ))
        );
        assert_eq!(r.state_root(), root, "a refused replacement changes nothing");
    }
}
