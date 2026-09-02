//! String keys for maps whose native key is bytes or a tuple.
//!
//! `serde_json` refuses to write a map whose key is not a string or an
//! integer: `BTreeMap<[u8; 32], _>` fails with "key must be a string" at the
//! first non-empty entry. The V2 state snapshot is JSON, and it carries the
//! bridge, AI, storage, PoA and cross-domain registries, so the first bridge
//! transfer on a chain made every later snapshot write fail. The failure was
//! logged at `warn!` and nothing else noticed.
//!
//! `AssetId` had the same problem and fixed it in 2026-07 with a hex string
//! (`asset_id_serde` in `cross_domain/bridge.rs`). This module is that fix
//! generalised to map keys, with one difference that matters for the rows
//! already on disk: the string form is used only when the format is
//! human-readable. `bincode` and `postcard` report `is_human_readable() ==
//! false`, and for them the map is written as a sequence of `(key, value)`
//! pairs, which is byte for byte what the derived `Serialize` wrote (a
//! `u64` length followed by the entries). No `LegacyXxx` fallback is needed
//! and no stored row changes; `map_keys_bincode_row_is_unchanged` in the
//! tests proves it against the derived encoding.
//!
//! # Key formats
//!
//! | key type | JSON string |
//! |---|---|
//! | `[u8; 32]` (`Hash32`, `MessageId`) | 64 lowercase hex characters |
//! | `AiModelId`, `AiRequestId`, `ContentId` | the inner 32 bytes as hex |
//! | `(DomainId, Address)` | `"<domain>:<address hex>"` |
//! | `(DomainId, DomainId, Address)` | `"<src>:<dst>:<address hex>"` |
//! | `(DomainId, u64, u64)` | `"<domain>:<height>:<index>"` |
//! | `(AiRequestId, [u8; 32])` | `"<request hex>:<hash hex>"` |
//! | `(ContentId, ContentId)` | `"<content hex>:<shard hex>"` |
//! | `ProofClaimKey` | `"<domain>:<target height>"` |
//!
//! The parser is strict: wrong length, non-hex characters, a missing tuple
//! part or a duplicate key is a deserialisation error, never a silent skip.
//! A leading `0x` is accepted on hex parts, as `Address::from_hex` does.
//!
//! # Usage
//!
//! ```ignore
//! #[serde(with = "crate::core::map_keys")]
//! pub transfers: BTreeMap<MessageId, BridgeTransfer>,
//! ```
//!
//! The `serialize-map-keys-are-strings` gate lists every map field of a
//! `Serialize` struct whose key type is not a string or integer and that
//! carries no `with` / `serialize_with` / `skip`, so a new registry cannot
//! reintroduce the failure.

use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::ser::{SerializeMap, SerializeSeq, Serializer};
use serde::{Deserialize, Serialize};

use crate::ai::types::AiRequestId;
use crate::core::Address;
use crate::domain::types::DomainId;
use crate::storage::content_id::ContentId;

/// A map key with a canonical string form for human-readable formats.
///
/// A named key type implements this next to its own definition
/// (`AiRequestId` in `ai/types.rs`, `ContentId` in `storage/content_id.rs`,
/// `ProofClaimKey` in `prover/mod.rs`), the way `AssetId` carries its own
/// hex serde. Bare byte arrays and tuples have no home of their own, so
/// their impls live here. Add a row to the table above with every impl.
pub trait MapKey: Sized + Ord {
    /// The JSON key for this value.
    fn to_key_string(&self) -> String;
    /// Parse a key written by [`MapKey::to_key_string`].
    fn from_key_string(s: &str) -> Result<Self, String>;
}

/// Parse one 32-byte hex part of a key (an optional `0x` prefix is accepted).
///
/// # Errors
///
/// Non-hex input or any length other than 32 bytes.
pub fn parse_hex32(part: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(part.strip_prefix("0x").unwrap_or(part))
        .map_err(|e| format!("invalid hex map key: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "invalid map key length: expected 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Parse one integer part of a key; `what` names the part in the error.
///
/// # Errors
///
/// Input that is not a number of the requested width.
pub fn parse_uint<T: std::str::FromStr>(part: &str, what: &str) -> Result<T, String> {
    part.parse::<T>()
        .map_err(|_| format!("invalid map key: {what} `{part}` is not a number"))
}

/// Split a `:`-joined key into exactly `N` parts.
///
/// # Errors
///
/// Fewer or more than `N` parts.
pub fn parts<const N: usize>(s: &str) -> Result<[&str; N], String> {
    let mut out = [""; N];
    let mut it = s.split(':');
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = it
            .next()
            .ok_or_else(|| format!("invalid map key `{s}`: expected {N} parts, got {i}"))?;
    }
    if it.next().is_some() {
        return Err(format!(
            "invalid map key `{s}`: expected {N} parts, got more"
        ));
    }
    Ok(out)
}

impl MapKey for [u8; 32] {
    fn to_key_string(&self) -> String {
        hex::encode(self)
    }
    fn from_key_string(s: &str) -> Result<Self, String> {
        parse_hex32(s)
    }
}

impl MapKey for (DomainId, Address) {
    fn to_key_string(&self) -> String {
        format!("{}:{}", self.0, self.1.to_hex())
    }
    fn from_key_string(s: &str) -> Result<Self, String> {
        let [domain, address] = parts::<2>(s)?;
        Ok((
            parse_uint(domain, "domain")?,
            Address(parse_hex32(address)?),
        ))
    }
}

impl MapKey for (DomainId, DomainId, Address) {
    fn to_key_string(&self) -> String {
        format!("{}:{}:{}", self.0, self.1, self.2.to_hex())
    }
    fn from_key_string(s: &str) -> Result<Self, String> {
        let [source, target, address] = parts::<3>(s)?;
        Ok((
            parse_uint(source, "source domain")?,
            parse_uint(target, "target domain")?,
            Address(parse_hex32(address)?),
        ))
    }
}

impl MapKey for (DomainId, u64, u64) {
    fn to_key_string(&self) -> String {
        format!("{}:{}:{}", self.0, self.1, self.2)
    }
    fn from_key_string(s: &str) -> Result<Self, String> {
        let [domain, height, index] = parts::<3>(s)?;
        Ok((
            parse_uint(domain, "domain")?,
            parse_uint(height, "height")?,
            parse_uint(index, "index")?,
        ))
    }
}

impl MapKey for (AiRequestId, [u8; 32]) {
    fn to_key_string(&self) -> String {
        format!("{}:{}", hex::encode(self.0 .0), hex::encode(self.1))
    }
    fn from_key_string(s: &str) -> Result<Self, String> {
        let [request, hash] = parts::<2>(s)?;
        Ok((AiRequestId(parse_hex32(request)?), parse_hex32(hash)?))
    }
}

impl MapKey for (ContentId, ContentId) {
    fn to_key_string(&self) -> String {
        format!("{}:{}", hex::encode(self.0 .0), hex::encode(self.1 .0))
    }
    fn from_key_string(s: &str) -> Result<Self, String> {
        let [content, shard] = parts::<2>(s)?;
        Ok((
            ContentId(parse_hex32(content)?),
            ContentId(parse_hex32(shard)?),
        ))
    }
}

/// `#[serde(with)]` half: string keys for JSON, the derived layout for
/// binary formats.
pub fn serialize<S, Key, Value>(
    map: &BTreeMap<Key, Value>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    Key: MapKey + Serialize,
    Value: Serialize,
{
    if serializer.is_human_readable() {
        let mut out = serializer.serialize_map(Some(map.len()))?;
        for (key, value) in map {
            out.serialize_entry(&key.to_key_string(), value)?;
        }
        out.end()
    } else {
        // A sequence of pairs is what the derived map encoding writes in
        // bincode and postcard: a length, then each entry in order.
        let mut out = serializer.serialize_seq(Some(map.len()))?;
        for entry in map {
            out.serialize_element(&entry)?;
        }
        out.end()
    }
}

struct StringKeyMap<Key, Value>(PhantomData<(Key, Value)>);

impl<'de, Key, Value> Visitor<'de> for StringKeyMap<Key, Value>
where
    Key: MapKey,
    Value: Deserialize<'de>,
{
    type Value = BTreeMap<Key, Value>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a map with string keys")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut out = BTreeMap::new();
        while let Some((raw, value)) = access.next_entry::<String, Value>()? {
            let key = Key::from_key_string(&raw).map_err(de::Error::custom)?;
            if out.insert(key, value).is_some() {
                return Err(de::Error::custom(format!("duplicate map key `{raw}`")));
            }
        }
        Ok(out)
    }
}

/// `#[serde(with)]` half: the inverse of [`serialize`].
pub fn deserialize<'de, D, Key, Value>(deserializer: D) -> Result<BTreeMap<Key, Value>, D::Error>
where
    D: Deserializer<'de>,
    Key: MapKey + Deserialize<'de>,
    Value: Deserialize<'de>,
{
    if deserializer.is_human_readable() {
        deserializer.deserialize_map(StringKeyMap(PhantomData))
    } else {
        let entries = Vec::<(Key, Value)>::deserialize(deserializer)?;
        Ok(entries.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::types::AiModelId;
    use crate::prover::ProofClaimKey;

    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
    struct Derived {
        by_hash: BTreeMap<[u8; 32], u64>,
        by_route: BTreeMap<(DomainId, DomainId, Address), u64>,
        tail: u8,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
    struct Keyed {
        #[serde(with = "super")]
        by_hash: BTreeMap<[u8; 32], u64>,
        #[serde(with = "super")]
        by_route: BTreeMap<(DomainId, DomainId, Address), u64>,
        tail: u8,
    }

    fn sample() -> (Derived, Keyed) {
        let mut by_hash = BTreeMap::new();
        by_hash.insert([7u8; 32], 1);
        by_hash.insert([1u8; 32], 2);
        let mut by_route = BTreeMap::new();
        by_route.insert((1, 2, Address([9u8; 32])), 5);
        (
            Derived {
                by_hash: by_hash.clone(),
                by_route: by_route.clone(),
                tail: 3,
            },
            Keyed {
                by_hash,
                by_route,
                tail: 3,
            },
        )
    }

    #[test]
    fn serde_json_still_refuses_derived_byte_keys() {
        // The failure this module exists for. If serde_json ever starts
        // accepting these keys the module can go; until then this test is
        // the reason it stays.
        let (derived, _) = sample();
        let err = serde_json::to_string(&derived).unwrap_err().to_string();
        assert!(err.contains("key must be a string"), "{err}");
    }

    #[test]
    fn map_keys_json_round_trip_uses_hex_strings() {
        let (_, keyed) = sample();
        let json = serde_json::to_string_pretty(&keyed).unwrap();
        let hash7 = "07".repeat(32);
        let addr9 = "09".repeat(32);
        assert!(json.contains(&format!("\"{hash7}\": 1")), "{json}");
        assert!(json.contains(&format!("\"1:2:{addr9}\": 5")), "{json}");
        let back: Keyed = serde_json::from_str(&json).unwrap();
        assert_eq!(back, keyed);
    }

    #[test]
    fn map_keys_bincode_row_is_unchanged() {
        // The stored rows are bincode. The helper must write exactly the
        // bytes the derived impl wrote, so no legacy fallback is needed.
        let (derived, keyed) = sample();
        let derived_row = bincode::serialize(&derived).unwrap();
        let keyed_row = bincode::serialize(&keyed).unwrap();
        assert_eq!(derived_row, keyed_row);
        let keyed_back: Keyed = bincode::deserialize(&derived_row).unwrap();
        assert_eq!(keyed_back, keyed);
        let derived_back: Derived = bincode::deserialize(&keyed_row).unwrap();
        assert_eq!(derived_back, derived);
    }

    #[test]
    fn map_keys_json_rejects_malformed_keys() {
        let cases = [
            r#"{"by_hash":{"zz":1},"by_route":{},"tail":0}"#,
            r#"{"by_hash":{"0707":1},"by_route":{},"tail":0}"#,
            r#"{"by_hash":{},"by_route":{"1:2":1},"tail":0}"#,
            r#"{"by_hash":{},"by_route":{"x:2:0000000000000000000000000000000000000000000000000000000000000000":1},"tail":0}"#,
            r#"{"by_hash":{},"by_route":{"1:2:0000000000000000000000000000000000000000000000000000000000000000:9":1},"tail":0}"#,
        ];
        for case in cases {
            assert!(serde_json::from_str::<Keyed>(case).is_err(), "{case}");
        }
    }

    #[test]
    fn map_keys_json_rejects_duplicate_keys() {
        let addr = "09".repeat(32);
        let dup =
            format!(r#"{{"by_hash":{{}},"by_route":{{"1:2:{addr}":1,"1:2:{addr}":2}},"tail":0}}"#);
        let err = serde_json::from_str::<Keyed>(&dup).unwrap_err().to_string();
        assert!(err.contains("duplicate map key"), "{err}");
    }

    #[test]
    fn map_keys_accept_0x_prefix_on_hex_parts() {
        let hash = format!("0x{}", "ab".repeat(32));
        let json = format!(r#"{{"by_hash":{{"{hash}":4}},"by_route":{{}},"tail":0}}"#);
        let back: Keyed = serde_json::from_str(&json).unwrap();
        assert_eq!(back.by_hash.get(&[0xabu8; 32]), Some(&4));
    }

    #[test]
    fn every_key_type_round_trips_through_its_string() {
        fn check<Key: MapKey + fmt::Debug + PartialEq>(key: Key) {
            let s = key.to_key_string();
            assert_eq!(Key::from_key_string(&s).unwrap(), key, "{s}");
        }
        check([5u8; 32]);
        check(AiModelId([6u8; 32]));
        check(AiRequestId([7u8; 32]));
        check(ContentId([8u8; 32]));
        check((3u32, Address([1u8; 32])));
        check((3u32, 4u32, Address([2u8; 32])));
        check((3u32, u64::MAX, 0u64));
        check((AiRequestId([9u8; 32]), [10u8; 32]));
        check((ContentId([11u8; 32]), ContentId([12u8; 32])));
        check(ProofClaimKey {
            domain_id: 7,
            target_height: 99,
        });
    }
}
