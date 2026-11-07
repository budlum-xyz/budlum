//! Atomic object replacement (`StorageTxV3::ReplaceObject`, Section 6.14 items 1-7; ).
//! exposed for `apply_storage_tx_v3` and placement-group replacement verifiers.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::bof1::{codec_is_open_on_testnet, codec_is_registered, CodecId};
use super::content_id::{ContentId, ContentIdKind};
use super::pipeline::ObjectRecord;
use super::registry::{Address, ObjectKey};
use super::repair::bad_repair_slash_amount;

/// Minimum independent Full validators from the placement group required to
/// verify `decode(new_object)` produces the exact same `ContentId` (Section 6.14 item 3).
pub const MIN_REPLACE_ATTESTATIONS: usize = 3;

/// Minimum fast-probe savings in basis points (`5% = 500 bps`) required before
/// running `MediumO` generic candidates (Section 6.6.2 item 11, closing ).
pub const FAST_PROBE_MIN_SAVINGS_BPS: u32 = 500;

/// Entropy ceiling in millibits per byte (`7.900` bits/byte) above which generic
/// compressors are skipped in favor of raw codec `0` (Section 6.6.2 item 8).
pub const GENERIC_ENTROPY_CEILING_MILLIBITS: u32 = 7_900;

/// Independent Full-validator attestation over a proposed replacement object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplaceAttestation {
    pub validator: Address,
    pub verified_content_id: ContentId,
}

/// Verified candidate produced during stage A0 codec selection (Section 6.6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedCodecCandidate {
    pub codec_id: CodecId,
    pub encoded_len: usize,
    pub roundtrip_verified: bool,
}

/// Select the winning open A0 codec under Section 6.6.2 items 3-11 (closing ):
/// - Consults the single-source [`bud_codec::registry::REGISTER`] table (`K-4`).
/// - Rejects any candidate that is closed on testnet or not round-trip verified.
/// - Applies the entropy ceiling (`> 7.9` bits/byte -> codec `0`) and the **fast probe
///   rule** (`<= 5%` probe savings on generic input skips `Speed::Medium` candidates!).
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
        let savings_bps =
            u128::from(saved as u64).saturating_mul(10_000) / u128::from(raw_len as u64);
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
        if cand.encoded_len < best_len
            || (cand.encoded_len == best_len && cand.codec_id < best_id)
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
    InsufficientAttestations { got: usize, need: usize },
    AttesterOutsidePlacementGroup(Address),
    /// Different content produced: rejected AND proposer is slashed 1% under bad-repair rule!
    ContentIdMismatch { proposer_slash_atoms: u64 },
}

/// Guard enforcing Section 6.14 items 2-9 before committing `StorageTxV3::ReplaceObject`:
/// 1. Sealed objects can ONLY be replaced by their owner (`sender == old_owner`).
/// 2. `new_record.codec` must be registered and open on testnet (`bud_codec::is_open`).
/// 3. If `new_record.content_id != old_record.content_id`, refuses AND computes the
///    1% bad-repair slash (`bad_repair_slash_amount(proposer_stake)`).
/// 4. Requires at least `MIN_REPLACE_ATTESTATIONS` (3) distinct Full validators from
///    `placement_group_full` attesting to the exact `old_record.content_id`.
pub fn admit_object_replacement(
    sender: &Address,
    old_owner: &Address,
    proposer_stake: u64,
    old_record: &ObjectRecord,
    new_record: &ObjectRecord,
    placement_group_full: &BTreeSet<Address>,
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
        distinct_attesters.insert(att.validator);
    }

    if distinct_attesters.len() < MIN_REPLACE_ATTESTATIONS {
        return Err(ReplaceError::InsufficientAttestations {
            got: distinct_attesters.len(),
            need: MIN_REPLACE_ATTESTATIONS,
        });
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

    #[test]
    fn closed_codecs_refuse_on_testnet() {
        let cid = ContentId::public(b"closed codec test");
        let old_rec = sample_record([1u8; 32], cid, 0);
        let pg: BTreeSet<Address> = [[1u8; 32], [2u8; 32], [3u8; 32]].into();
        let atts = vec![
            ReplaceAttestation { validator: [1u8; 32], verified_content_id: cid },
            ReplaceAttestation { validator: [2u8; 32], verified_content_id: cid },
            ReplaceAttestation { validator: [3u8; 32], verified_content_id: cid },
        ];

        for closed in [2u16, 6, 7, 8, 9, 12, 13, 14, 15, 22, 26] {
            let bad = sample_record([2u8; 32], cid, closed);
            assert_eq!(
                admit_object_replacement(&[1u8; 32], &[1u8; 32], 50_000, &old_rec, &bad, &pg, &atts),
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

        let two_att = vec![
            ReplaceAttestation { validator: [1u8; 32], verified_content_id: cid },
            ReplaceAttestation { validator: [2u8; 32], verified_content_id: cid },
        ];
        assert!(matches!(
            admit_object_replacement(&[9u8; 32], &[1u8; 32], 100_000, &old_rec, &new_rec, &pg, &two_att),
            Err(ReplaceError::InsufficientAttestations { got: 2, need: 3 })
        ));

        let mut three_att = two_att;
        three_att.push(ReplaceAttestation { validator: [3u8; 32], verified_content_id: cid });
        admit_object_replacement(&[9u8; 32], &[1u8; 32], 100_000, &old_rec, &new_rec, &pg, &three_att).unwrap();

        let bad_cid = ContentId::public(b"corrupted object bytes");
        let bad_rec = sample_record([30u8; 32], bad_cid, 1);
        assert_eq!(
            admit_object_replacement(&[9u8; 32], &[1u8; 32], 100_000, &old_rec, &bad_rec, &pg, &three_att),
            Err(ReplaceError::ContentIdMismatch {
                proposer_slash_atoms: 1_000
            })
        );
    }
}
