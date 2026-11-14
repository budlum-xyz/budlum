//! `StorageTx` v3: the transactions of B.U.D. 3.0 and their one apply door.
//!
//! Every variant names who must sign it; [`apply`] receives the verified
//! signer from the transaction envelope and refuses a variant signed by
//! anyone else. Apply is all-or-nothing: a refused transaction leaves the
//! registry state root unchanged.

use super::content_id::ContentId;
use super::custody::CustodyProof;
use super::delete::{GrantShredAuth, ShredOutcome};
use super::fountain::Symbol;
use super::grants::GrantRow;
use super::pipeline::ObjectRecord;
use super::placement::Share;
use super::registry::{
    Address, Bud3Registry, NftId, ObjectKey, Registered, RegistryError, SegmentRepair,
};
use super::repair::RepairWitness;

/// The `StorageTx` v3 transactions.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StorageTxV3 {
    /// Register an object. Signed by the uploader.
    RegisterObject {
        /// The object record.
        record: ObjectRecord,
        /// The placement: `(segment, share)`.
        shares: Vec<(u64, Share)>,
        /// Paid lifetime in epochs.
        lifetime_epochs: u64,
    },
    /// Confirm the signer's shares of an object. Signed by the holder.
    CustodyAck {
        /// The object.
        object: ObjectKey,
    },
    /// Answer open audits. Signed by the holder.
    CustodyProofBatch {
        /// `(object, proof)` pairs.
        proofs: Vec<(ObjectKey, CustodyProof)>,
    },
    /// Record a repair. Signed by the repairer.
    RecordRepair {
        /// The object.
        object: ObjectKey,
        /// The repaired segment.
        segment: u64,
        /// New shares with fresh ESIs.
        new_shares: Vec<Share>,
        /// Generated repair symbols matching `new_shares` and `new_root`.
        new_symbols: Vec<Symbol>,
        /// Symbol root over the new symbols.
        new_root: [u8; 32],
        /// Cryptographic witness binding `new_symbols`/`new_root` to the segment.
        witness: RepairWitness,
    },
    /// Bind an NFT to an object. Signed by the NFT holder.
    BindNft {
        /// The NFT.
        nft: NftId,
        /// The object.
        object: ObjectKey,
    },
    /// Burn an NFT's reference. Signed by the NFT holder.
    BurnReference {
        /// The NFT.
        nft: NftId,
    },
    /// Extend the paid lifetime. Anyone may sign.
    RenewObject {
        /// The object.
        object: ObjectKey,
        /// Extra epochs.
        extra_epochs: u64,
    },
    /// Refuse future shares of a content id. Signed by the validator.
    DeclineContent {
        /// The content.
        content: ContentId,
    },
    /// Issue an unlinkable view grant for a sealed object (`IssueViewGrant`).
    IssueViewGrant {
        /// NFT reference whose holder authorizes the view grant.
        nft: NftId,
        /// Per-grant random nonce binding `row.grant_tag` to `nft`.
        grant_nonce: [u8; 32],
        /// The unlinkable grant row (contains zero `content_id`, `issuer`, or `grantee`).
        row: GrantRow,
    },
    /// Revoke a view grant using its one-time ML-DSA-65 authorization (`RevokeViewGrant`).
    RevokeViewGrant {
        /// Unlinkable grant tag.
        grant_tag: [u8; 32],
        /// One-time ML-DSA-65 signature over `BDLM_BUD3_GRANT_REVOKE_V1 || grant_tag`.
        one_time_signature: Vec<u8>,
    },
    /// Atomically shred listed view-grant capsules and burn an NFT reference (`SocialDelete`).
    SocialDelete {
        /// NFT reference to burn.
        nft: NftId,
        /// One-time ML-DSA-65 shred authorizations for active view grants.
        grant_shreds: Vec<GrantShredAuth>,
    },
    /// Voluntarily release shares and lower declared custody quota without penalty (`ReleaseShares`).
    ReleaseShares {
        /// Object holding the share(s) to release.
        object: ObjectKey,
        /// Specific segment index, or `None` for all segments of `object`.
        segment: Option<u64>,
        /// Bytes by which to lower the holder's declared custody quota.
        lower_quota_bytes: u64,
    },
    /// Atomically replace an object with a new codec representation verified to
    /// decode to the identical `ContentId` (`ReplaceObject`, Section 6.14).
    ReplaceObject {
        /// Existing object commitment being replaced.
        old_object: ObjectKey,
        /// New object record carrying the identical `ContentId`.
        new_record: ObjectRecord,
        /// Placement shares for `new_record`.
        new_shares: Vec<(u64, Share)>,
        /// Independent Full-validator attestations (`>= 3`).
        attestations: Vec<super::replace::ReplaceAttestation>,
        /// Proposer stake subject to 1% slash on `ContentId` mismatch.
        proposer_stake: u64,
    },
    /// Pay on-chain for a G8 validator fallback decode receipt (`bud_storageGetContent`).
    PayFallbackView {
        /// Target public object commitment.
        object: ObjectKey,
        /// Unique receipt id matching the off-chain `PaidViewReceipt`.
        receipt_id: [u8; 32],
        /// Paid fee in BUD base units (`>= MIN_PAID_VIEW_FEE_ATOMS`).
        amount_atoms: u64,
    },
}

/// What an applied transaction did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// Registration outcome.
    Registered(Registered),
    /// Shares confirmed.
    Acked(usize),
    /// Proofs accepted.
    Proved(usize),
    /// Repair recorded.
    Repaired,
    /// NFT bound.
    Bound,
    /// Reference burned; `true` when the object was deleted.
    Burned(bool),
    /// New expiry epoch.
    Renewed(u64),
    /// Decline recorded.
    Declined,
    /// Unlinkable view grant recorded.
    GrantIssued,
    /// View grant revoked and HPKE key package deleted.
    GrantRevoked,
    /// Social delete shredded grant capsules and burned the NFT reference.
    SociallyDeleted(ShredOutcome),
    /// Shares voluntarily released for reassignment without penalty.
    Released(usize),
    /// Object atomically replaced with a new commitment for the same `ContentId`.
    Replaced(ObjectKey),
    /// On-chain paid fallback view receipt recorded.
    PaidFallbackView,
}

/// Apply one transaction signed by `signer` at `epoch`.
///
/// # Errors
///
/// The [`RegistryError`] of the refused step; the registry is unchanged.
pub fn apply(
    registry: &mut Bud3Registry,
    signer: Address,
    tx: StorageTxV3,
    epoch: u64,
) -> Result<Applied, RegistryError> {
    apply_with_validators(
        registry,
        signer,
        tx,
        epoch,
        &std::collections::BTreeMap::new(),
    )
}

/// Apply one transaction signed by `signer` at `epoch`, supplying the active
/// consensus ML-DSA-65 validator key directory for `ReplaceObject` attestations.
///
/// # Errors
///
/// The [`RegistryError`] of the refused step; the registry is unchanged.
pub fn apply_with_validators(
    registry: &mut Bud3Registry,
    signer: Address,
    tx: StorageTxV3,
    epoch: u64,
    validator_keys: &std::collections::BTreeMap<Address, Vec<u8>>,
) -> Result<Applied, RegistryError> {
    match tx {
        StorageTxV3::RegisterObject {
            record,
            shares,
            lifetime_epochs,
        } => registry
            .register_object(signer, record, shares, epoch, lifetime_epochs)
            .map(Applied::Registered),
        StorageTxV3::CustodyAck { object } => registry.ack(&object, &signer).map(Applied::Acked),
        StorageTxV3::CustodyProofBatch { proofs } => registry
            .submit_proofs(&signer, &proofs, epoch)
            .map(Applied::Proved),
        StorageTxV3::RecordRepair {
            object,
            segment,
            new_shares,
            new_symbols,
            new_root,
            witness,
        } => {
            // The repairer must not hold one of the new shares itself: a
            // repair moves symbols to new holders.
            if new_shares.iter().any(|s| s.validator == signer) {
                return Err(RegistryError::BadRepair(
                    "the repairer cannot take a new share",
                ));
            }
            registry
                .record_repair_with_validators(
                    &object,
                    SegmentRepair {
                        segment,
                        new_shares,
                        new_symbols,
                        new_root,
                        witness: &witness,
                    },
                    Some(&signer),
                    validator_keys,
                    epoch,
                )
                .map(|()| Applied::Repaired)
        }
        StorageTxV3::BindNft { nft, object } => registry
            .bind_nft(nft, signer, &object)
            .map(|()| Applied::Bound),
        StorageTxV3::BurnReference { nft } => registry
            .burn_reference(&nft, &signer, epoch)
            .map(Applied::Burned),
        StorageTxV3::RenewObject {
            object,
            extra_epochs,
        } => registry.renew(&object, extra_epochs).map(Applied::Renewed),
        StorageTxV3::DeclineContent { content } => {
            registry.decline(signer, &content);
            Ok(Applied::Declined)
        }
        StorageTxV3::IssueViewGrant {
            nft,
            grant_nonce,
            row,
        } => registry
            .issue_view_grant(&nft, &grant_nonce, &signer, row, epoch)
            .map(|()| Applied::GrantIssued),
        StorageTxV3::RevokeViewGrant {
            grant_tag,
            one_time_signature,
        } => registry
            .revoke_view_grant(&grant_tag, &one_time_signature)
            .map(|()| Applied::GrantRevoked),
        StorageTxV3::SocialDelete { nft, grant_shreds } => registry
            .social_delete(&nft, &signer, &grant_shreds, epoch)
            .map(Applied::SociallyDeleted),
        StorageTxV3::ReleaseShares {
            object,
            segment,
            lower_quota_bytes,
        } => registry
            .release_shares(&signer, &object, segment, lower_quota_bytes)
            .map(Applied::Released),
        StorageTxV3::ReplaceObject {
            old_object,
            new_record,
            new_shares,
            attestations,
            proposer_stake,
        } => registry
            .replace_object(
                (signer, proposer_stake),
                &old_object,
                new_record,
                new_shares,
                &attestations,
                (epoch, validator_keys),
            )
            .map(Applied::Replaced),
        StorageTxV3::PayFallbackView {
            object,
            receipt_id,
            amount_atoms,
        } => registry
            .record_paid_view(signer, object, receipt_id, amount_atoms, epoch)
            .map(|()| Applied::PaidFallbackView),
    }
}

#[cfg(test)]
mod tests {
    use super::super::limits::{Bud3Limits, Profile};
    use super::super::pipeline::prepare_public_upload;
    use super::super::placement::Class;
    use super::*;

    const P: Profile = Profile {
        id: 0,
        qr_version: 40,
        symbol_size: 128,
        fps: 10,
        k_max: 16,
    };

    fn register_tx() -> (StorageTxV3, ObjectKey) {
        let up = prepare_public_upload(b"via the door", &P, &Bud3Limits::default(), 8).unwrap();
        let key = up.record.commitment;
        let shares = (0..2u8)
            .map(|h| {
                (
                    0,
                    Share {
                        validator: [10 + h; 32],
                        class: Class::Full,
                        first_esi: u32::from(h) * 4,
                        symbols: 4,
                    },
                )
            })
            .collect();
        (
            StorageTxV3::RegisterObject {
                record: up.record,
                shares,
                lifetime_epochs: 50,
            },
            key,
        )
    }

    #[test]
    fn the_door_applies_the_object_lifecycle() {
        let mut r = Bud3Registry::default();
        let (tx, key) = register_tx();
        assert_eq!(
            apply(&mut r, [1; 32], tx, 0),
            Ok(Applied::Registered(Registered::New(key)))
        );
        assert_eq!(
            apply(&mut r, [10; 32], StorageTxV3::CustodyAck { object: key }, 1),
            Ok(Applied::Acked(1))
        );
        assert_eq!(
            apply(
                &mut r,
                [2; 32],
                StorageTxV3::BindNft {
                    nft: [7; 32],
                    object: key
                },
                1
            ),
            Ok(Applied::Bound)
        );
        assert_eq!(
            apply(
                &mut r,
                [9; 32],
                StorageTxV3::RenewObject {
                    object: key,
                    extra_epochs: 5
                },
                2
            ),
            Ok(Applied::Renewed(55))
        );
        // Only the NFT holder burns, and a non-owner cannot burn the sole reference.
        let before = r.state_root();
        assert_eq!(
            apply(
                &mut r,
                [3; 32],
                StorageTxV3::BurnReference { nft: [7; 32] },
                3
            ),
            Err(RegistryError::NotAuthorized)
        );
        assert_eq!(
            apply(
                &mut r,
                [2; 32],
                StorageTxV3::BurnReference { nft: [7; 32] },
                3
            ),
            Err(RegistryError::NotAuthorized)
        );
        assert_eq!(r.state_root(), before, "a refusal writes nothing");
        assert_eq!(
            apply(
                &mut r,
                [1; 32],
                StorageTxV3::BindNft {
                    nft: [8; 32],
                    object: key
                },
                3
            ),
            Ok(Applied::Bound)
        );
        assert_eq!(
            apply(
                &mut r,
                [2; 32],
                StorageTxV3::BurnReference { nft: [7; 32] },
                3
            ),
            Ok(Applied::Burned(false))
        );
        assert_eq!(
            apply(
                &mut r,
                [1; 32],
                StorageTxV3::BurnReference { nft: [8; 32] },
                3
            ),
            Ok(Applied::Burned(true))
        );
        assert_eq!(r.tombstone(&key), Some(3));
    }

    #[test]
    fn transactions_round_trip_through_the_wire_codec() {
        use super::super::custody::{prove, symbol_leaf};
        let (tx, key) = register_tx();
        let leaves = vec![(0u32, symbol_leaf(&[1u8; 100]))];
        let proof = prove(0, &leaves, 0, &[1u8; 100], 1).unwrap();
        for t in [
            tx,
            StorageTxV3::CustodyProofBatch {
                proofs: vec![(key, proof)],
            },
        ] {
            let bytes = bincode::serialize(&t).unwrap();
            let back: StorageTxV3 = bincode::deserialize(&bytes).unwrap();
            assert_eq!(back, t);
            let json = serde_json::to_string(&t).unwrap();
            assert_eq!(serde_json::from_str::<StorageTxV3>(&json).unwrap(), t);
        }
    }

    #[test]
    fn a_repairer_cannot_give_itself_the_new_share() {
        let mut r = Bud3Registry::default();
        let tx = StorageTxV3::RecordRepair {
            object: [0; 32],
            segment: 0,
            new_shares: vec![Share {
                validator: [5; 32],
                class: Class::Full,
                first_esi: 8,
                symbols: 4,
            }],
            new_symbols: Vec::new(),
            new_root: [0; 32],
            witness: RepairWitness::ProvenSymbols(Vec::new()),
        };
        assert!(matches!(
            apply(&mut r, [5; 32], tx, 0),
            Err(RegistryError::BadRepair(_))
        ));
    }

    #[test]
    fn record_repair_tx_repairs_segment_on_chain() {
        use super::super::custody::{symbol_leaf, symbol_root};
        use super::super::fountain::SegmentEncoder;
        use super::super::repair::build_repair_proven_witness;

        let mut r = Bud3Registry::default();
        let content: Vec<u8> = (0..1500u32).map(|i| (i % 249) as u8).collect();
        // The BOF-1 envelope needs 13 source symbols for this fixture; 8
        // cannot satisfy the upload's k+2 admission rule. Keep enough live
        // symbols *after* one half is lost to reconstruct a real repair.
        let up = prepare_public_upload(&content, &P, &Bud3Limits::default(), 32).unwrap();
        let total = u32::try_from(up.segments[0].len()).unwrap();
        let half = total / 2;
        let shares = vec![
            (
                0,
                Share {
                    validator: [10u8; 32],
                    class: Class::Full,
                    first_esi: 0,
                    symbols: half,
                },
            ),
            (
                0,
                Share {
                    validator: [11u8; 32],
                    class: Class::Full,
                    first_esi: half,
                    symbols: total - half,
                },
            ),
        ];
        let key = up.record.commitment;
        let uploader = [1u8; 32];
        r.register_object(uploader, up.record.clone(), shares.clone(), 0, 1000)
            .unwrap();
        for (_, s) in &shares {
            r.ack(&key, &s.validator).unwrap();
        }
        let lost = shares.last().unwrap().1;
        assert_eq!(r.mark_unseen(&lost.validator), 1);
        assert_eq!(r.repairs_due(&key), vec![0]);

        let next_esi = total;
        let selected = bud_codec::select(&content);
        let obj_bytes =
            super::super::bof1::Object::public_coded(selected.codec, selected.payload, &content)
                .unwrap()
                .encode();
        let enc = SegmentEncoder::new(0, &obj_bytes, &P).unwrap();
        assert!(
            half >= enc.k(),
            "the surviving share must decode the segment"
        );
        let fresh = enc
            .repair_symbols(next_esi - enc.k(), lost.symbols)
            .unwrap();
        let leaves: Vec<(u32, [u8; 32])> = fresh
            .iter()
            .map(|x| (x.esi, symbol_leaf(&x.data)))
            .collect();
        let new_root = symbol_root(&leaves);
        let new_share = Share {
            validator: [20u8; 32],
            class: Class::Full,
            first_esi: next_esi,
            symbols: lost.symbols,
        };
        let live = &up.segments[0][..usize::try_from(half).unwrap()];
        let witness = RepairWitness::ProvenSymbols(
            build_repair_proven_witness(0, &up.segments[0], live).unwrap(),
        );
        let tx = StorageTxV3::RecordRepair {
            object: key,
            segment: 0,
            new_shares: vec![new_share],
            new_symbols: fresh,
            new_root,
            witness,
        };
        assert_eq!(apply(&mut r, uploader, tx, 100), Ok(Applied::Repaired));
        r.ack(&key, &[20u8; 32]).unwrap();
        // The consensus block transition settles confirmed replacement shares
        // before the obsolete lost shares leave custody accounting. Model that
        // boundary explicitly: an ACK alone is not a completed repair.
        assert_eq!(r.settle_repairs(), 1);
        assert!(r.repairs_due(&key).is_empty());
    }
}
