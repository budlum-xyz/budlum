//! Serialize a `BTreeMap` as a sequence of `(key, value)` pairs.
//!
//! The object-layer maps are keyed by ids and enums. `serde_json` (the V2
//! state snapshot) refuses non-string map keys, so every such map carries
//! `#[serde(with = "crate::object_layer::pairs")]`. The pair sequence is the
//! same in every format, keeps the map's sorted order, and refuses duplicate
//! keys on the way back in.
//!
//! WIRING: the block executor reaches this module through the
//! `SettlementTx::ObjectLayer(Box<ObjectLayerTx>)` door, and RPC reads it
//! through `bud_getCharter`, `bud_getAssetClass`, `bud_getAsset` and the
//! other object-layer read methods. Both land in a later step; until then
//! the state is held by `SettlementRegistries::object_layer` and closed on
//! the testnet by `ACTIVATION`.

use serde::de::{Deserialize, Deserializer, Error, SeqAccess, Visitor};
use serde::ser::{Serialize, Serializer};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

/// Performs the requested operation.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn serialize<Key, Value, S>(
    map: &BTreeMap<Key, Value>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    Key: Serialize,
    Value: Serialize,
    S: Serializer,
{
    serializer.collect_seq(map.iter())
}

struct PairsVisitor<Key, Value>(PhantomData<fn() -> (Key, Value)>);

impl<'de, Key, Value> Visitor<'de> for PairsVisitor<Key, Value>
where
    Key: Deserialize<'de> + Ord,
    Value: Deserialize<'de>,
{
    type Value = BTreeMap<Key, Value>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a canonically sorted sequence of unique (key, value) pairs")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut map: BTreeMap<Key, Value> = BTreeMap::new();
        while let Some((k, v)) = seq.next_element::<(Key, Value)>()? {
            if let Some(prev) = map.keys().next_back() {
                match prev.cmp(&k) {
                    Ordering::Equal => return Err(A::Error::custom("duplicate map key")),
                    Ordering::Greater => return Err(A::Error::custom("unsorted map key")),
                    Ordering::Less => {}
                }
            }
            map.insert(k, v);
        }
        Ok(map)
    }
}

/// Performs the requested operation.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn deserialize<'de, Key, Value, D>(deserializer: D) -> Result<BTreeMap<Key, Value>, D::Error>
where
    Key: Deserialize<'de> + Ord,
    Value: Deserialize<'de>,
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(PairsVisitor(PhantomData))
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct BoxedMap {
        #[serde(with = "super")]
        entries: BTreeMap<u32, String>,
    }

    #[test]
    fn pairs_deserialize_refuses_unsorted_and_duplicate_keys() {
        let sorted_json = r#"{"entries":[[1,"a"],[2,"b"]]}"#;
        let parsed: BoxedMap = serde_json::from_str(sorted_json).expect("sorted pairs valid");
        assert_eq!(parsed.entries.len(), 2);

        let duplicate_json = r#"{"entries":[[1,"a"],[1,"b"]]}"#;
        assert!(
            serde_json::from_str::<BoxedMap>(duplicate_json).is_err(),
            "duplicate keys must be rejected"
        );

        let unsorted_json = r#"{"entries":[[2,"b"],[1,"a"]]}"#;
        assert!(
            serde_json::from_str::<BoxedMap>(unsorted_json).is_err(),
            "out-of-order pair sequences must be rejected to keep canonical wire order"
        );
    }
}
