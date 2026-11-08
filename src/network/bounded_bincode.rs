//! Bounded decoding for peer-controlled bincode payloads.
//!
//! Bincode's byte budget also bounds strings and byte buffers, but sequence and
//! map counts are only exposed to Serde as size hints. Guard those hints before
//! a visitor can reserve capacity, and share one aggregate item budget through
//! nested structs, options, enums, sequences, and maps.

use serde::de::{
    self, DeserializeOwned, DeserializeSeed, Deserializer, EnumAccess, MapAccess, SeqAccess,
    VariantAccess, Visitor,
};
use std::cell::Cell;
use std::fmt;
use std::marker::PhantomData;
use std::rc::Rc;

struct BoundedSeed<S> {
    seed: S,
    item_budget: Rc<Cell<usize>>,
}

impl<'de, S> DeserializeSeed<'de> for BoundedSeed<S>
where
    S: DeserializeSeed<'de>,
{
    type Value = S::Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        self.seed.deserialize(BoundedDeserializer {
            inner: deserializer,
            item_budget: self.item_budget,
        })
    }
}

struct BoundedDeserializer<D> {
    inner: D,
    item_budget: Rc<Cell<usize>>,
}

struct GuardVisitor<V> {
    inner: V,
    item_budget: Rc<Cell<usize>>,
    limit_current_container: bool,
}

impl<V> GuardVisitor<V> {
    fn fixed(inner: V, item_budget: Rc<Cell<usize>>) -> Self {
        Self {
            inner,
            item_budget,
            limit_current_container: false,
        }
    }

    fn counted(inner: V, item_budget: Rc<Cell<usize>>) -> Self {
        Self {
            inner,
            item_budget,
            limit_current_container: true,
        }
    }
}

impl<'de, V> Visitor<'de> for GuardVisitor<V>
where
    V: Visitor<'de>,
{
    type Value = V::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.expecting(formatter)
    }

    fn visit_seq<A>(self, access: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if self.limit_current_container {
            let count = access.size_hint().ok_or_else(|| {
                <A::Error as de::Error>::custom(
                    "bincode sequence is missing its bounded item count",
                )
            })?;
            let remaining = self.item_budget.get();
            if count > remaining {
                return Err(<A::Error as de::Error>::custom(format!(
                    "bincode sequence item count {count} exceeds the remaining payload-derived budget {remaining}"
                )));
            }
            self.item_budget.set(remaining - count);
        }
        self.inner.visit_seq(BoundedSeqAccess {
            inner: access,
            item_budget: self.item_budget,
        })
    }

    fn visit_map<A>(self, access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        if self.limit_current_container {
            let count = access.size_hint().ok_or_else(|| {
                <A::Error as de::Error>::custom(
                    "bincode map is missing its bounded entry count",
                )
            })?;
            let remaining = self.item_budget.get();
            if count > remaining {
                return Err(<A::Error as de::Error>::custom(format!(
                    "bincode map entry count {count} exceeds the remaining payload-derived budget {remaining}"
                )));
            }
            self.item_budget.set(remaining - count);
        }
        self.inner.visit_map(BoundedMapAccess {
            inner: access,
            item_budget: self.item_budget,
        })
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        self.inner.visit_some(BoundedDeserializer {
            inner: deserializer,
            item_budget: self.item_budget,
        })
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        self.inner.visit_newtype_struct(BoundedDeserializer {
            inner: deserializer,
            item_budget: self.item_budget,
        })
    }

    fn visit_enum<A>(self, access: A) -> Result<Self::Value, A::Error>
    where
        A: EnumAccess<'de>,
    {
        self.inner.visit_enum(BoundedEnumAccess {
            inner: access,
            item_budget: self.item_budget,
        })
    }
}

struct BoundedSeqAccess<A> {
    inner: A,
    item_budget: Rc<Cell<usize>>,
}

impl<'de, A> SeqAccess<'de> for BoundedSeqAccess<A>
where
    A: SeqAccess<'de>,
{
    type Error = A::Error;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: DeserializeSeed<'de>,
    {
        self.inner.next_element_seed(BoundedSeed {
            seed,
            item_budget: Rc::clone(&self.item_budget),
        })
    }

    fn size_hint(&self) -> Option<usize> {
        self.inner.size_hint()
    }
}

struct BoundedMapAccess<A> {
    inner: A,
    item_budget: Rc<Cell<usize>>,
}

impl<'de, A> MapAccess<'de> for BoundedMapAccess<A>
where
    A: MapAccess<'de>,
{
    type Error = A::Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
    where
        K: DeserializeSeed<'de>,
    {
        self.inner.next_key_seed(BoundedSeed {
            seed,
            item_budget: Rc::clone(&self.item_budget),
        })
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
    where
        V: DeserializeSeed<'de>,
    {
        self.inner.next_value_seed(BoundedSeed {
            seed,
            item_budget: Rc::clone(&self.item_budget),
        })
    }

    fn size_hint(&self) -> Option<usize> {
        self.inner.size_hint()
    }
}

struct BoundedEnumAccess<A> {
    inner: A,
    item_budget: Rc<Cell<usize>>,
}

impl<'de, A> EnumAccess<'de> for BoundedEnumAccess<A>
where
    A: EnumAccess<'de>,
{
    type Error = A::Error;
    type Variant = BoundedVariantAccess<A::Variant>;

    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant), Self::Error>
    where
        V: DeserializeSeed<'de>,
    {
        let (variant, access) = self.inner.variant_seed(BoundedSeed {
            seed,
            item_budget: Rc::clone(&self.item_budget),
        })?;
        Ok((
            variant,
            BoundedVariantAccess {
                inner: access,
                item_budget: self.item_budget,
            },
        ))
    }
}

struct BoundedVariantAccess<A> {
    inner: A,
    item_budget: Rc<Cell<usize>>,
}

impl<'de, A> VariantAccess<'de> for BoundedVariantAccess<A>
where
    A: VariantAccess<'de>,
{
    type Error = A::Error;

    fn unit_variant(self) -> Result<(), Self::Error> {
        self.inner.unit_variant()
    }

    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value, Self::Error>
    where
        T: DeserializeSeed<'de>,
    {
        self.inner.newtype_variant_seed(BoundedSeed {
            seed,
            item_budget: self.item_budget,
        })
    }

    fn tuple_variant<V>(self, len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.inner
            .tuple_variant(len, GuardVisitor::fixed(visitor, self.item_budget))
    }

    fn struct_variant<V>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.inner
            .struct_variant(fields, GuardVisitor::fixed(visitor, self.item_budget))
    }
}

macro_rules! forward_to_inner {
    ($($method:ident),+ $(,)?) => {
        $(
            fn $method<V>(self, visitor: V) -> Result<V::Value, D::Error>
            where
                V: Visitor<'de>,
            {
                self.inner.$method(visitor)
            }
        )+
    };
}

impl<'de, D> de::Deserializer<'de> for BoundedDeserializer<D>
where
    D: Deserializer<'de>,
{
    type Error = D::Error;

    forward_to_inner!(
        deserialize_any,
        deserialize_bool,
        deserialize_i8,
        deserialize_i16,
        deserialize_i32,
        deserialize_i64,
        deserialize_i128,
        deserialize_u8,
        deserialize_u16,
        deserialize_u32,
        deserialize_u64,
        deserialize_u128,
        deserialize_f32,
        deserialize_f64,
        deserialize_char,
        deserialize_str,
        deserialize_string,
        deserialize_bytes,
        deserialize_byte_buf,
        deserialize_unit,
        deserialize_identifier,
        deserialize_ignored_any,
    );

    fn deserialize_unit_struct<V>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, D::Error>
    where
        V: Visitor<'de>,
    {
        self.inner.deserialize_unit_struct(name, visitor)
    }

    fn deserialize_newtype_struct<V>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, D::Error>
    where
        V: Visitor<'de>,
    {
        self.inner
            .deserialize_newtype_struct(name, GuardVisitor::fixed(visitor, self.item_budget))
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, D::Error>
    where
        V: Visitor<'de>,
    {
        self.inner
            .deserialize_option(GuardVisitor::fixed(visitor, self.item_budget))
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, D::Error>
    where
        V: Visitor<'de>,
    {
        self.inner
            .deserialize_seq(GuardVisitor::counted(visitor, self.item_budget))
    }

    fn deserialize_tuple<V>(self, len: usize, visitor: V) -> Result<V::Value, D::Error>
    where
        V: Visitor<'de>,
    {
        self.inner
            .deserialize_tuple(len, GuardVisitor::fixed(visitor, self.item_budget))
    }

    fn deserialize_tuple_struct<V>(
        self,
        name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, D::Error>
    where
        V: Visitor<'de>,
    {
        self.inner.deserialize_tuple_struct(
            name,
            len,
            GuardVisitor::fixed(visitor, self.item_budget),
        )
    }

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value, D::Error>
    where
        V: Visitor<'de>,
    {
        self.inner
            .deserialize_map(GuardVisitor::counted(visitor, self.item_budget))
    }

    fn deserialize_struct<V>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, D::Error>
    where
        V: Visitor<'de>,
    {
        self.inner.deserialize_struct(
            name,
            fields,
            GuardVisitor::fixed(visitor, self.item_budget),
        )
    }

    fn deserialize_enum<V>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, D::Error>
    where
        V: Visitor<'de>,
    {
        self.inner.deserialize_enum(
            name,
            variants,
            GuardVisitor::fixed(visitor, self.item_budget),
        )
    }

    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }
}

/// Decode bincode under a byte ceiling and a shared payload-derived item budget
/// for every advertised sequence or map count. The fixed-int and trailing-byte
/// settings preserve the legacy `bincode::deserialize` wire behavior.
///
/// # Errors
///
/// Returns an error for an oversized payload, an excessive aggregate
/// collection count, or any malformed value rejected by bincode or its target
/// type.
pub(crate) fn decode_bounded_bincode<T: DeserializeOwned>(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<T, String> {
    if bytes.len() > max_bytes {
        return Err(format!(
            "payload length {} exceeds the {max_bytes}-byte limit",
            bytes.len()
        ));
    }
    let byte_limit = u64::try_from(bytes.len())
        .map_err(|_| "bincode limit exceeds u64".to_string())?;
    use bincode::Options as _;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(byte_limit)
        .deserialize_seed(
            BoundedSeed {
                seed: PhantomData::<T>,
                item_budget: Rc::new(Cell::new(bytes.len())),
            },
            bytes,
        )
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::decode_bounded_bincode;
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct NestedSequences {
        values: Vec<Vec<u8>>,
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct NestedZeroSized {
        groups: Vec<Vec<()>>,
    }

    #[test]
    fn oversized_sequence_count_is_rejected_before_visitor_allocation() {
        let payload = 4_096u64.to_le_bytes();
        let error = decode_bounded_bincode::<Vec<u8>>(&payload, payload.len())
            .expect_err("a sequence hint larger than its encoded payload must be refused");
        assert!(error.contains("sequence item count"), "{error}");
    }

    #[test]
    fn nested_sequence_count_is_guarded() {
        let mut payload = 1u64.to_le_bytes().to_vec();
        payload.extend_from_slice(&4_096u64.to_le_bytes());
        let error = decode_bounded_bincode::<NestedSequences>(&payload, payload.len())
            .expect_err("a nested count hint larger than its payload must be refused");
        assert!(error.contains("sequence item count"), "{error}");
    }

    #[test]
    fn aggregate_budget_limits_nested_zero_sized_sequence_work() {
        let mut payload = 2u64.to_le_bytes().to_vec();
        payload.extend_from_slice(&2u64.to_le_bytes());
        payload.extend_from_slice(&2u64.to_le_bytes());
        let decoded = decode_bounded_bincode::<NestedZeroSized>(&payload, payload.len())
            .expect("a small nested zero-sized sequence fits the aggregate item budget");
        assert_eq!(decoded.groups, vec![vec![(), ()], vec![(), ()]]);

        let mut excessive = 1u64.to_le_bytes().to_vec();
        excessive.extend_from_slice(&17u64.to_le_bytes());
        let error = decode_bounded_bincode::<NestedZeroSized>(&excessive, excessive.len())
            .expect_err("nested counts that exceed the total payload-derived budget must fail");
        assert!(error.contains("sequence item count"), "{error}");
    }

    #[test]
    fn oversized_map_count_is_rejected_before_visitor_allocation() {
        let payload = 4_096u64.to_le_bytes();
        let error = decode_bounded_bincode::<BTreeMap<u8, u8>>(&payload, payload.len())
            .expect_err("a map hint larger than its encoded payload must be refused");
        assert!(error.contains("map entry count"), "{error}");
    }

    #[test]
    fn valid_values_and_legacy_trailing_bytes_are_preserved() {
        let expected = vec![1u8, 2, 3];
        let mut payload = bincode::serialize(&expected).expect("serialize");
        payload.push(0xA5);
        let decoded = decode_bounded_bincode(&payload, payload.len()).expect("decode");
        assert_eq!(decoded, expected);
    }

    #[test]
    fn claimed_string_length_cannot_exceed_the_input_byte_budget() {
        let payload = 4_096u64.to_le_bytes();
        let result = decode_bounded_bincode::<String>(&payload, payload.len());
        assert!(result.is_err(), "a length prefix cannot authorize missing bytes");
    }

    #[test]
    fn payload_byte_limit_is_enforced_before_deserialization() {
        let payload = bincode::serialize(&vec![1u8, 2, 3]).expect("serialize");
        let error = decode_bounded_bincode::<Vec<u8>>(&payload, payload.len() - 1)
            .expect_err("a payload above its byte budget must be refused");
        assert!(error.contains("payload length"), "{error}");
    }
}
