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

use serde::de::{Deserialize, Deserializer, Error};
use serde::ser::{Serialize, Serializer};
use std::collections::BTreeMap;

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

pub fn deserialize<'de, Key, Value, D>(deserializer: D) -> Result<BTreeMap<Key, Value>, D::Error>
where
    Key: Deserialize<'de> + Ord,
    Value: Deserialize<'de>,
    D: Deserializer<'de>,
{
    let pairs: Vec<(Key, Value)> = Vec::deserialize(deserializer)?;
    let mut map = BTreeMap::new();
    for (k, v) in pairs {
        if map.insert(k, v).is_some() {
            return Err(D::Error::custom("duplicate map key"));
        }
    }
    Ok(map)
}
