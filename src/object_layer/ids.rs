//! Identity derivations of the Universal Object Layer (directive 9.3.3).
//!
//! Every identity is a domain-separated hash. The home domain fixes the
//! identity of an asset once (N-1): Budlum never mints a wrapped copy, so the
//! same native token on its home chain has exactly one `AssetId` here, on
//! every arrival, after every round trip.
//!
//! ```text
//! AssetClassId = H("BDLM_OBJECT_LAYER_CLASS_V1", home_domain_id, len(class_ref), class_ref)
//! AssetId      = H("BDLM_OBJECT_LAYER_ASSET_V1", class_id, len(native_id), native_id)
//! DependencyId = H("BDLM_OBJECT_LAYER_DEP_V1", home_domain, home_height, home_block_hash, len(event_id), event_id)
//! HomeIdentity = H("BDLM_HOME_IDENTITY_V1", home_domain, len(home_address), home_address)
//! ```
//!
//! `hash_fields_bytes` already length-prefixes every field. The explicit
//! `len(..)` fields are kept anyway so the preimage is the formula above,
//! field for field, and a second implementation can follow the text.

use crate::core::hash::hash_fields_bytes;
use crate::domain::types::{DomainId, Hash32};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const CLASS_ID_TAG: &[u8] = b"BDLM_OBJECT_LAYER_CLASS_V1";
pub const ASSET_ID_TAG: &[u8] = b"BDLM_OBJECT_LAYER_ASSET_V1";
pub const DEPENDENCY_ID_TAG: &[u8] = b"BDLM_OBJECT_LAYER_DEP_V1";
pub const HOME_IDENTITY_TAG: &[u8] = b"BDLM_HOME_IDENTITY_V1";
pub const DEPARTURE_ID_TAG: &[u8] = b"BDLM_OBJECT_LAYER_DEPARTURE_V1";
pub const ARRIVAL_KEY_TAG: &[u8] = b"BDLM_OBJECT_LAYER_ARRIVAL_V1";

fn len_field(bytes: &[u8]) -> [u8; 8] {
    (bytes.len() as u64).to_le_bytes()
}

macro_rules! hash_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub struct $name(pub Hash32);

        impl $name {
            #[must_use]
            pub fn as_bytes(&self) -> &Hash32 {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "0x{}", hex::encode(self.0))
            }
        }
    };
}

hash_id!(
    /// The identity of an asset class: one contract, mint, coin type or
    /// collection on one home domain.
    AssetClassId
);
hash_id!(
    /// The identity of one asset inside a class. For a fungible class the
    /// native id is empty and the asset id names the class's unit.
    AssetId
);
hash_id!(
    /// The identity of one tentative home event that Budlum state depends on.
    DependencyId
);
hash_id!(
    /// The Budlum-side identity of an address on a home domain. A home call
    /// runs as this identity; its authority is the home domain's finality
    /// proof, not a signature (9.3.10).
    HomeIdentity
);
hash_id!(
    /// The identity of one departure record.
    DepartureId
);
hash_id!(
    /// The single-use key of one arrival event (`arrival_is_single_use`).
    ArrivalKey
);

impl AssetClassId {
    #[must_use]
    pub fn derive(home_domain: DomainId, class_ref: &[u8]) -> Self {
        Self(hash_fields_bytes(&[
            CLASS_ID_TAG,
            &home_domain.to_le_bytes(),
            &len_field(class_ref),
            class_ref,
        ]))
    }
}

impl AssetId {
    #[must_use]
    pub fn derive(class: &AssetClassId, native_id: &[u8]) -> Self {
        Self(hash_fields_bytes(&[
            ASSET_ID_TAG,
            &class.0,
            &len_field(native_id),
            native_id,
        ]))
    }
}

impl DependencyId {
    #[must_use]
    pub fn derive(
        home_domain: DomainId,
        home_height: u64,
        home_block_hash: &Hash32,
        event_id: &[u8],
    ) -> Self {
        Self(hash_fields_bytes(&[
            DEPENDENCY_ID_TAG,
            &home_domain.to_le_bytes(),
            &home_height.to_le_bytes(),
            home_block_hash,
            &len_field(event_id),
            event_id,
        ]))
    }
}

impl HomeIdentity {
    #[must_use]
    pub fn derive(home_domain: DomainId, home_address: &[u8]) -> Self {
        Self(hash_fields_bytes(&[
            HOME_IDENTITY_TAG,
            &home_domain.to_le_bytes(),
            &len_field(home_address),
            home_address,
        ]))
    }
}

impl DepartureId {
    /// One departure per (asset, holder, sequence number). The sequence is
    /// the registry's departure counter, so two departures of the same
    /// fungible amount never share an id.
    #[must_use]
    pub fn derive(asset: &AssetId, sequence: u64) -> Self {
        Self(hash_fields_bytes(&[
            DEPARTURE_ID_TAG,
            &asset.0,
            &sequence.to_le_bytes(),
        ]))
    }
}

impl ArrivalKey {
    /// The key is bound to the position of the event on its home chain, so
    /// the same deposit presented twice (or by two carriers) maps to one key.
    #[must_use]
    pub fn derive(home_domain: DomainId, home_height: u64, event_id: &[u8]) -> Self {
        Self(hash_fields_bytes(&[
            ARRIVAL_KEY_TAG,
            &home_domain.to_le_bytes(),
            &home_height.to_le_bytes(),
            &len_field(event_id),
            event_id,
        ]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_layer_ids_change_with_every_field() {
        let class = AssetClassId::derive(7, b"ref");
        assert_ne!(class, AssetClassId::derive(8, b"ref"));
        assert_ne!(class, AssetClassId::derive(7, b"reg"));

        let asset = AssetId::derive(&class, b"1");
        assert_ne!(asset, AssetId::derive(&class, b"2"));
        assert_ne!(asset, AssetId::derive(&AssetClassId::derive(8, b"ref"), b"1"));

        let dep = DependencyId::derive(7, 10, &[1; 32], b"e");
        assert_ne!(dep, DependencyId::derive(8, 10, &[1; 32], b"e"));
        assert_ne!(dep, DependencyId::derive(7, 11, &[1; 32], b"e"));
        assert_ne!(dep, DependencyId::derive(7, 10, &[2; 32], b"e"));
        assert_ne!(dep, DependencyId::derive(7, 10, &[1; 32], b"f"));

        let home = HomeIdentity::derive(7, b"addr");
        assert_ne!(home, HomeIdentity::derive(8, b"addr"));
        assert_ne!(home, HomeIdentity::derive(7, b"adds"));
    }

    #[test]
    fn identity_tags_are_distinct() {
        // The same preimage under two tags must not collide: a class id can
        // never be presented as a home identity.
        let tags = [
            CLASS_ID_TAG,
            ASSET_ID_TAG,
            DEPENDENCY_ID_TAG,
            HOME_IDENTITY_TAG,
            DEPARTURE_ID_TAG,
            ARRIVAL_KEY_TAG,
        ];
        for (i, a) in tags.iter().enumerate() {
            for b in &tags[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert_ne!(
            AssetClassId::derive(1, b"x").0,
            HomeIdentity::derive(1, b"x").0
        );
    }

    #[test]
    fn length_prefix_separates_concatenations() {
        let a = AssetId::derive(&AssetClassId::derive(1, b"ab"), b"c");
        let b = AssetId::derive(&AssetClassId::derive(1, b"a"), b"bc");
        assert_ne!(a, b);
    }
}
