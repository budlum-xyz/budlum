//! `StorageTx` v3: the transactions of B.U.D. 3.0 and their one apply door.
//!
//! Every variant names who must sign it; [`apply`] receives the verified
//! signer from the transaction envelope and refuses a variant signed by
//! anyone else. Apply is all-or-nothing: a refused transaction leaves the
//! registry state root unchanged.
//!
//! WIRING: unwired - the transaction envelope reaches this door once the
//! legacy `StorageTx` is removed from `TransactionType`; until then the door
//! is exercised by its tests.

use super::content_id::ContentId;
use super::custody::CustodyProof;
use super::pipeline::ObjectRecord;
use super::placement::Share;
use super::registry::{Address, Bud3Registry, NftId, ObjectKey, Registered, RegistryError};

/// Serde for the `(validator, signature)` pairs: serde derives arrays only up
/// to 32 elements, and a detached signature is 64 bytes, so each side is
/// carried as one length-prefixed byte string. A wrong length is a decode
/// error.
mod validation_pairs {
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    struct Bytes<'a>(&'a [u8]);

    impl Serialize for Bytes<'_> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(self.0)
        }
    }

    // The `serde(with)` hook passes exactly `&Vec<..>`, so the shape is fixed
    // here even though a slice would be the usual parameter.
    #[allow(clippy::ptr_arg)]
    pub fn serialize<S: Serializer>(
        pairs: &Vec<([u8; 32], [u8; 64])>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(pairs.len()))?;
        for (who, sig) in pairs {
            seq.serialize_element(&(Bytes(who.as_slice()), Bytes(sig.as_slice())))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<([u8; 32], [u8; 64])>, D::Error> {
        let raw = <Vec<(Vec<u8>, Vec<u8>)>>::deserialize(deserializer)?;
        raw.into_iter()
            .map(|(who, sig)| {
                let who = <[u8; 32]>::try_from(who.as_slice()).map_err(|_| {
                    serde::de::Error::invalid_length(who.len(), &"a 32-byte validator id")
                })?;
                let sig = <[u8; 64]>::try_from(sig.as_slice()).map_err(|_| {
                    serde::de::Error::invalid_length(sig.len(), &"a 64-byte signature")
                })?;
                Ok((who, sig))
            })
            .collect()
    }
}

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
        /// Symbol root over the new symbols.
        new_root: [u8; 32],
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
    /// Replace an object with a new representation of the same content. The
    /// content id never changes. Signed by the proposing Full validator.
    ReplaceObject {
        /// The content id; the object's fixed identity.
        content: ContentId,
        /// The object being replaced, named by its old commitment.
        old_object: ObjectKey,
        /// The record of the new representation.
        new_record: ObjectRecord,
        /// The placement of the new representation: `(segment, share)`.
        shares: Vec<(u64, Share)>,
        /// `(validator, signature)` pairs over the replacement validation
        /// message, from at least three independent Full holders of the old
        /// placement.
        #[serde(with = "validation_pairs")]
        validations: Vec<([u8; 32], [u8; 64])>,
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
    /// Object replaced; the new object key.
    Replaced(ObjectKey),
    /// NFT bound.
    Bound,
    /// Reference burned; `true` when the object was deleted.
    Burned(bool),
    /// New expiry epoch.
    Renewed(u64),
    /// Decline recorded.
    Declined,
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
    match tx {
        StorageTxV3::RegisterObject {
            record,
            shares,
            lifetime_epochs,
        } => registry
            .register_object(signer, record, shares, epoch, lifetime_epochs)
            .map(Applied::Registered),
        StorageTxV3::CustodyAck { object } => registry
            .ack(&object, &signer, epoch)
            .map(Applied::Acked),
        StorageTxV3::CustodyProofBatch { proofs } => registry
            .submit_proofs(&signer, &proofs, epoch)
            .map(Applied::Proved),
        StorageTxV3::RecordRepair {
            object,
            segment,
            new_shares,
            new_root,
        } => {
            // The repairer must not hold one of the new shares itself: a
            // repair moves symbols to new holders.
            if new_shares.iter().any(|s| s.validator == signer) {
                return Err(RegistryError::BadRepair(
                    "the repairer cannot take a new share",
                ));
            }
            registry
                .record_repair(&object, segment, new_shares, new_root)
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
        StorageTxV3::ReplaceObject {
            content,
            old_object,
            new_record,
            shares,
            validations,
        } => registry
            .replace_object(&signer, content, &old_object, new_record, shares, &validations)
            .map(Applied::Replaced),
        StorageTxV3::DeclineContent { content } => {
            registry.decline(signer, &content);
            Ok(Applied::Declined)
        }
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
        // Only the NFT holder burns.
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
        assert_eq!(r.state_root(), before, "a refusal writes nothing");
        assert_eq!(
            apply(
                &mut r,
                [2; 32],
                StorageTxV3::BurnReference { nft: [7; 32] },
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
            new_root: [0; 32],
        };
        assert!(matches!(
            apply(&mut r, [5; 32], tx, 0),
            Err(RegistryError::BadRepair(_))
        ));
    }
}
