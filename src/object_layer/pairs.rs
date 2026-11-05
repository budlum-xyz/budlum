//! Serialize a `BTreeMap` as a sequence of `(key, value)` pairs.
//!
//! The object-layer maps are keyed by ids and enums. `serde_json` (the V2
//! state snapshot) refuses non-string map keys, so every such map carries
//! `#[serde(with = "crate::object_layer::pairs")]`. The pair sequence is the
//! same in every format, keeps the map's sorted order, and refuses duplicate
//! keys on the way back in.

use serde::de::{Deserialize, Deserializer, Error};
use serde::ser::{Serialize, Serializer};
use std::collections::BTreeMap;

pub fn serialize<K, V, S>(map: &BTreeMap<K, V>, serializer: S) -> Result<S::Ok, S::Error>
where
    K: Serialize,
    V: Serialize,
    S: Serializer,
{
    serializer.collect_seq(map.iter())
}

pub fn deserialize<'de, K, V, D>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
where
    K: Deserialize<'de> + Ord,
    V: Deserialize<'de>,
    D: Deserializer<'de>,
{
    let pairs: Vec<(K, V)> = Vec::deserialize(deserializer)?;
    let mut map = BTreeMap::new();
    for (k, v) in pairs {
        if map.insert(k, v).is_some() {
            return Err(D::Error::custom("duplicate map key"));
        }
    }
    Ok(map)
}
