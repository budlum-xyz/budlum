//! Atomic object replacement (`StorageTxV3::ReplaceObject`, Section 6.14 items 1-7).
//! exposed for `apply_storage_tx_v3` and placement-group replacement verifiers.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use super::bof1::{codec_is_open_on_testnet, codec_is_registered, CodecId};
use super::content_id::{ContentId, ContentIdKind};
use super::pipeline::ObjectRecord;
use super::registry::{Address, ObjectKey};
use super::repair::bad_repair_slash_amount;
use crate::core::hash::hash_fields_bytes;
use crate::crypto::ctx::STORAGE_V2;
use crate::crypto::pq::{ml_dsa_sign, verify, PqError};
use crate::crypto::scheme::SchemeId;

/// Domain tag binding Full-validator replacement attestations to `(old_key, new_record)`.
pub const REPLACE_ATTEST_DOMAIN: &[u8] = b"BDLM_BUD3_REPLACE_ATTEST_V1";

/// Minimum independent Full validators from the placement group required to
/// verify `decode(new_object)` produces the exact same `ContentId` (Section 6.14 item 3).
pub const MIN_REPLACE_ATTESTATIONS: usize = 3;

/// Minimum fast-probe savings in basis points (`5% = 500 bps`) required before
/// running `MediumO` generic candidates (Section 6.6.2 item 11).
pub const FAST_PROBE_MIN_SAVINGS_BPS: u32 = 500;

/// Entropy ceiling in millibits per byte (`7.900` bits/byte) above which generic
/// compressors are skipped in favor of raw codec `0` (Section 6.6.2 item 8).
pub const GENERIC_ENTROPY_CEILING_MILLIBITS: u32 = 7_900;

/// Independent Full-validator attestation over a proposed replacement object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplaceAttestation {
    pub validator: Address,
    pub verified_content_id: ContentId,
    pub new_commitment: ObjectKey,
    pub signature: Vec<u8>,
}

/// Canonical domain-separated digest signed by each placement-group Full
/// validator over `(old_key, new_record)`.
#[must_use]
pub fn replace_attestation_digest(old_key: &ObjectKey, new_record: &ObjectRecord) -> [u8; 32] {
    let kind_byte = [match new_record.content_id.kind {
        ContentIdKind::Public => 0u8,
        ContentIdKind::Sealed => 1u8,
    }];
    let cid_len = new_record.content_id.len.to_le_bytes();
    let obj_len = new_record.object_len.to_le_bytes();
    let prof_id = new_record.profile.id.to_le_bytes();
    let qr_ver = [new_record.profile.qr_version];
    let sym_sz = new_record.profile.symbol_size.to_le_bytes();
    let fps = new_record.profile.fps.to_le_bytes();
    let k_max = new_record.profile.k_max.to_le_bytes();
    let codec = new_record.codec.to_le_bytes();
    let syms_per_seg = new_record.symbols_per_segment.to_le_bytes();
    let roots_count = (new_record.symbol_roots.len() as u64).to_le_bytes();
    let mut roots_flat = Vec::with_capacity(new_record.symbol_roots.len() * 32);
    for root in &new_record.symbol_roots {
        roots_flat.extend_from_slice(root);
    }
    hash_fields_bytes(&[
        REPLACE_ATTEST_DOMAIN,
        old_key,
        &kind_byte,
        &new_record.content_id.digest,
        &cid_len,
        &obj_len,
        &new_record.commitment,
        &prof_id,
        &qr_ver,
        &sym_sz,
        &fps,
        &k_max,
        &codec,
        &syms_per_seg,
        &roots_count,
        &roots_flat,
    ])
}

/// Sign a [`ReplaceAttestation`] with `validator`'s ML-DSA-65 seed under `ctx::STORAGE_V2`.
///
/// Convenience: exposed for validator custody daemons and replacement tests.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn sign_replace_attestation(
    validator: Address,
    ml_dsa_seed: &[u8; 32],
    old_key: &ObjectKey,
    new_record: &ObjectRecord,
) -> Result<ReplaceAttestation, PqError> {
    let digest = replace_attestation_digest(old_key, new_record);
    let signature = ml_dsa_sign(
        SchemeId::ML_DSA_65,
        ml_dsa_seed,
        &digest,
        STORAGE_V2,
        &[0u8; 32],
    )?;
    Ok(ReplaceAttestation {
        validator,
        verified_content_id: new_record.content_id,
        new_commitment: new_record.commitment,
        signature,
    })
}

/// Verified candidate produced during stage A0 codec selection (Section 6.6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedCodecCandidate {
    pub codec_id: CodecId,
    pub encoded_len: usize,
    pub roundtrip_verified: bool,
}

/// Select the winning open A0 codec under Section 6.6.2 items 3-11:
/// - Consults the single-source [`bud_codec::registry::REGISTER`] table (`K-4`).
/// - Rejects any candidate that is closed on testnet or not round-trip verified.
/// - Applies the entropy ceiling (`> 7.9` bits/byte -> codec `0`) and the **fast probe
///   rule** (`<= 5%` probe savings on generic input skips `Speed::Medium` candidates!).
///
/// Convenience: exposed for A0 encoder selection and CLI measurement tools.
#[must_use]
pub fn select_codec_with_fast_probe(
    raw_input: &[u8],
    has_format_specific: bool,
    fast_probe_encoded_len: usize,
    candidates: &[VerifiedCodecCandidate],
) -> (CodecId, bool) {
    let raw_len = raw_input.len();
    if !has_format_specific
        && bud_codec::entropy_millibits(raw_input) > GENERIC_ENTROPY_CEILING_MILLIBITS
    {
        return (bud_codec::RAW, true);
    }

    let skipped_medium = if !has_format_specific && raw_len > 0 {
        let saved = raw_len.saturating_sub(fast_probe_encoded_len);
        let saved_u64 = u64::try_from(saved).unwrap_or(u64::MAX);
        let raw_u64 = u64::try_from(raw_len).unwrap_or(u64::MAX);
        let savings_bps = u128::from(saved_u64).saturating_mul(10_000) / u128::from(raw_u64);
        savings_bps <= u128::from(FAST_PROBE_MIN_SAVINGS_BPS)
    } else {
        false
    };

    let mut best_id: CodecId = bud_codec::RAW;
    let mut best_len = raw_len;

    for cand in candidates {
        if !cand.roundtrip_verified {
            continue;
        }
        let Some(row) = bud_codec::registry::entry(cand.codec_id) else {
            continue;
        };
        if row.state != bud_codec::registry::CodecState::Open
            || !codec_is_open_on_testnet(cand.codec_id)
        {
            continue;
        }
        let Some(speed) = row.speed else {
            continue;
        };
        if speed == bud_codec::registry::Speed::Slow {
            continue;
        }
        if skipped_medium && speed == bud_codec::registry::Speed::Medium {
            continue;
        }
        if cand.encoded_len < best_len || (cand.encoded_len == best_len && cand.codec_id < best_id)
        {
            best_len = cand.encoded_len;
            best_id = cand.codec_id;
        }
    }

    (best_id, skipped_medium)
}

/// Outcome when a proposed replacement fails validation (Section 6.14 items 2-9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplaceError {
    OldObjectNotFound,
    SealedReplacementMustComeFromOwner,
    CodecNotOpen(CodecId),
    CommitmentUnchanged,
    /// A second proposal cannot overwrite an unconfirmed replacement.
    ReplacementAlreadyPending,
    /// A live or tombstoned commitment cannot be reused for a replacement.
    CommitmentAlreadyLive,
    InsufficientAttestations {
        got: usize,
        need: usize,
    },
    AttesterOutsidePlacementGroup(Address),
    InvalidAttestationSignature(Address),
    NoIndependentAttester,
    /// Different content produced: rejected AND proposer is slashed 1% under bad-repair rule!
    ContentIdMismatch {
        proposer_slash_atoms: u64,
    },
}

/// Guard enforcing Section 6.14 items 2-9 before committing `StorageTxV3::ReplaceObject`:
/// 1. Sealed objects can ONLY be replaced by their owner (`sender == old_owner`).
/// 2. `new_record.codec` must be registered and open on testnet (`bud_codec::is_open`).
/// 3. If `new_record.content_id != old_record.content_id`, refuses AND computes the
///    1% bad-repair slash (`bad_repair_slash_amount(proposer_stake)`).
/// 4. Requires at least `MIN_REPLACE_ATTESTATIONS` (3) distinct Full validators from
///    `placement_group_full` signing `(old_record.commitment, new_record)` with their
///    registered consensus ML-DSA-65 keys, including at least one attester independent
///    of `sender`.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn admit_object_replacement(
    (sender, old_owner, proposer_stake): (&Address, &Address, u64),
    (old_record, new_record): (&ObjectRecord, &ObjectRecord),
    (placement_group_full, validator_keys): (&BTreeSet<Address>, &BTreeMap<Address, Vec<u8>>),
    attestations: &[ReplaceAttestation],
) -> Result<(), ReplaceError> {
    if old_record.commitment == new_record.commitment {
        return Err(ReplaceError::CommitmentUnchanged);
    }
    if old_record.content_id.kind == ContentIdKind::Sealed && sender != old_owner {
        return Err(ReplaceError::SealedReplacementMustComeFromOwner);
    }
    if !codec_is_registered(new_record.codec)
        || !bud_codec::is_open(new_record.codec)
        || !codec_is_open_on_testnet(new_record.codec)
    {
        return Err(ReplaceError::CodecNotOpen(new_record.codec));
    }

    if new_record.content_id != old_record.content_id {
        return Err(ReplaceError::ContentIdMismatch {
            proposer_slash_atoms: bad_repair_slash_amount(proposer_stake),
        });
    }

    let digest = replace_attestation_digest(&old_record.commitment, new_record);
    let mut distinct_attesters = BTreeSet::new();
    for att in attestations {
        if !placement_group_full.contains(&att.validator) {
            return Err(ReplaceError::AttesterOutsidePlacementGroup(att.validator));
        }
        if att.verified_content_id != old_record.content_id {
            return Err(ReplaceError::ContentIdMismatch {
                proposer_slash_atoms: bad_repair_slash_amount(proposer_stake),
            });
        }
        if att.new_commitment != new_record.commitment {
            return Err(ReplaceError::InvalidAttestationSignature(att.validator));
        }
        let Some(pk) = validator_keys.get(&att.validator) else {
            return Err(ReplaceError::InvalidAttestationSignature(att.validator));
        };
        if verify(SchemeId::ML_DSA_65, pk, &digest, STORAGE_V2, &att.signature).is_err() {
            return Err(ReplaceError::InvalidAttestationSignature(att.validator));
        }
        distinct_attesters.insert(att.validator);
    }

    if distinct_attesters.len() < MIN_REPLACE_ATTESTATIONS {
        return Err(ReplaceError::InsufficientAttestations {
            got: distinct_attesters.len(),
            need: MIN_REPLACE_ATTESTATIONS,
        });
    }
    if !distinct_attesters.iter().any(|v| v != sender) {
        return Err(ReplaceError::NoIndependentAttester);
    }
    Ok(())
}

/// Tracks pending share-retirement barriers so old object shares are NEVER deleted
/// before all replacement shares are acknowledged (Section 6.14 item 6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingReplacementBarrier {
    pub old_object: ObjectKey,
    pub new_object: ObjectKey,
    pub required_acks: usize,
    pub observed_acks: usize,
}

impl PendingReplacementBarrier {
    /// True once every replacement custody share has been acknowledged.
    /// Convenience: exposed for registry share retirement sweep.
    #[must_use]
    pub const fn can_retire_old_shares(&self) -> bool {
        self.observed_acks >= self.required_acks
    }
}

#[cfg(test)]
mod tests {
    use super::super::limits::Profile;
    use super::*;
    use crate::crypto::pq::ml_dsa_public_key;

    fn sample_record(commitment: [u8; 32], content_id: ContentId, codec: CodecId) -> ObjectRecord {
        ObjectRecord {
            content_id,
            object_len: 4_096,
            commitment,
            profile: Profile {
                id: 0,
                qr_version: 40,
                symbol_size: 1_024,
                fps: 10,
                k_max: 64,
            },
            codec,
            symbols_per_segment: 6,
            symbol_roots: vec![[0xAA; 32]],
        }
    }

    fn key_map(ids: &[u8]) -> BTreeMap<Address, Vec<u8>> {
        ids.iter()
            .map(|&b| {
                let seed = [b; 32];
                let pk = ml_dsa_public_key(SchemeId::ML_DSA_65, &seed).unwrap();
                ([b; 32], pk)
            })
            .collect()
    }

    #[test]
    fn closed_codecs_refuse_on_testnet() {
        let cid = ContentId::public(b"closed codec test");
        let old_rec = sample_record([1u8; 32], cid, 0);
        let pg: BTreeSet<Address> = [[1u8; 32], [2u8; 32], [3u8; 32]].into();
        let keys = key_map(&[1, 2, 3]);

        for closed in [9u16, 27u16] {
            let bad = sample_record([2u8; 32], cid, closed);
            let atts: Vec<ReplaceAttestation> = [1u8, 2, 3]
                .into_iter()
                .map(|b| {
                    sign_replace_attestation([b; 32], &[b; 32], &old_rec.commitment, &bad).unwrap()
                })
                .collect();
            assert_eq!(
                admit_object_replacement(
                    (&[1u8; 32], &[1u8; 32], 50_000),
                    (&old_rec, &bad),
                    (&pg, &keys),
                    &atts
                ),
                Err(ReplaceError::CodecNotOpen(closed))
            );
        }
    }

    #[test]
    fn bud3_fast_probe_skips_slow_candidates() {
        let input = vec![0x41u8; 4_096];
        let candidates = [VerifiedCodecCandidate {
            codec_id: 1,
            encoded_len: 3_980,
            roundtrip_verified: true,
        }];
        let (chosen, skipped_medium) =
            select_codec_with_fast_probe(&input, false, 3_980, &candidates);
        assert!(skipped_medium);
        assert_eq!(chosen, 1);
    }

    #[test]
    fn bud3_object_replacement() {
        let cid = ContentId::public(b"canonical object bytes");
        let old_rec = sample_record([10u8; 32], cid, 0);
        let new_rec = sample_record([20u8; 32], cid, 1);
        let pg: BTreeSet<Address> = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]].into();
        let keys = key_map(&[1, 2, 3, 4]);

        let two_att = vec![
            sign_replace_attestation([1u8; 32], &[1u8; 32], &old_rec.commitment, &new_rec).unwrap(),
            sign_replace_attestation([2u8; 32], &[2u8; 32], &old_rec.commitment, &new_rec).unwrap(),
        ];
        assert!(matches!(
            admit_object_replacement(
                (&[9u8; 32], &[1u8; 32], 100_000),
                (&old_rec, &new_rec),
                (&pg, &keys),
                &two_att
            ),
            Err(ReplaceError::InsufficientAttestations { got: 2, need: 3 })
        ));

        let mut three_att = two_att;
        three_att.push(
            sign_replace_attestation([3u8; 32], &[3u8; 32], &old_rec.commitment, &new_rec).unwrap(),
        );
        admit_object_replacement(
            (&[9u8; 32], &[1u8; 32], 100_000),
            (&old_rec, &new_rec),
            (&pg, &keys),
            &three_att,
        )
        .unwrap();

        // Forged signature or record swap must fail signature / commitment check.
        let mut forged = three_att.clone();
        forged[0].signature[0] ^= 0xFF;
        assert_eq!(
            admit_object_replacement(
                (&[9u8; 32], &[1u8; 32], 100_000),
                (&old_rec, &new_rec),
                (&pg, &keys),
                &forged
            ),
            Err(ReplaceError::InvalidAttestationSignature([1u8; 32]))
        );

        let bad_cid = ContentId::public(b"corrupted object bytes");
        let bad_rec = sample_record([30u8; 32], bad_cid, 1);
        assert_eq!(
            admit_object_replacement(
                (&[9u8; 32], &[1u8; 32], 100_000),
                (&old_rec, &bad_rec),
                (&pg, &keys),
                &three_att
            ),
            Err(ReplaceError::ContentIdMismatch {
                proposer_slash_atoms: 1_000
            })
        );
    }
}
