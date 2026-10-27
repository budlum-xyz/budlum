//! `.bud` resolution through the testnet indexer (`budlum-indexer`,
//! `GET /v1/bns/{name}`), which answers from the node's `bud_bnsResolveFull`.
//!
//! The crate still fetches nothing itself: the caller hands in the function
//! that performs the GET, so the browser keeps its one network stack. The
//! answer is an RPC answer and nothing more, so the resolution carries
//! [`BnsInclusionProof::None`] and the badge says so; a light-client proof is
//! a separate, stronger path ([`crate::bns_proof`]).
//!
//! The indexer answers with one flat JSON object of strings, booleans,
//! numbers and nulls. `flat_object` reads exactly that shape and refuses
//! anything nested, so no JSON library enters this crate.

use crate::bns_proof::{BnsInclusionProof, ResolvedName};
use crate::content_id::ContentId;
use crate::resolve::NameResolver;
use std::collections::BTreeMap;

/// One value of a flat JSON object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlatValue {
    Str(String),
    Bool(bool),
    Num(String),
    Null,
}

/// Parse a flat JSON object (no nested objects or arrays).
///
/// # Errors
///
/// Anything that is not one flat object of string keys.
pub fn flat_object(text: &str) -> Result<BTreeMap<String, FlatValue>, String> {
    let mut chars = text.trim().chars().peekable();
    let mut out = BTreeMap::new();
    if chars.next() != Some('{') {
        return Err("expected an object".into());
    }
    loop {
        skip_ws(&mut chars);
        match chars.peek() {
            Some('}') => {
                chars.next();
                break;
            }
            Some('"') => {}
            _ => return Err("expected a key".into()),
        }
        let key = string(&mut chars)?;
        skip_ws(&mut chars);
        if chars.next() != Some(':') {
            return Err("expected ':'".into());
        }
        skip_ws(&mut chars);
        let value = match chars.peek() {
            Some('"') => FlatValue::Str(string(&mut chars)?),
            Some('t' | 'f' | 'n') => {
                let word: String =
                    std::iter::from_fn(|| chars.next_if(char::is_ascii_alphabetic)).collect();
                match word.as_str() {
                    "true" => FlatValue::Bool(true),
                    "false" => FlatValue::Bool(false),
                    "null" => FlatValue::Null,
                    _ => return Err(format!("unexpected word {word}")),
                }
            }
            Some(c) if c.is_ascii_digit() || *c == '-' => FlatValue::Num(
                std::iter::from_fn(|| chars.next_if(|c| c.is_ascii_digit() || *c == '-')).collect(),
            ),
            _ => return Err("nested or unknown value".into()),
        };
        out.insert(key, value);
        skip_ws(&mut chars);
        match chars.next() {
            Some(',') => {}
            Some('}') => break,
            _ => return Err("expected ',' or '}'".into()),
        }
    }
    skip_ws(&mut chars);
    if chars.next().is_some() {
        return Err("trailing characters".into());
    }
    Ok(out)
}

fn skip_ws(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while chars.next_if(|c| c.is_whitespace()).is_some() {}
}

fn string(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Result<String, String> {
    if chars.next() != Some('"') {
        return Err("expected '\"'".into());
    }
    let mut out = String::new();
    loop {
        match chars.next() {
            Some('"') => return Ok(out),
            // The indexer writes names, hex and base-ten numbers only; an
            // escape would mean a string this reader was not made for.
            Some('\\') | None => return Err("escapes and unterminated strings are refused".into()),
            Some(c) => out.push(c),
        }
    }
}

fn hex32(value: Option<&FlatValue>) -> Result<Option<[u8; 32]>, String> {
    match value {
        None | Some(FlatValue::Null) => Ok(None),
        Some(FlatValue::Str(s)) => {
            let bytes =
                hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|e| e.to_string())?;
            <[u8; 32]>::try_from(bytes.as_slice())
                .map(Some)
                .map_err(|_| "expected 32 bytes".to_string())
        }
        Some(_) => Err("expected a hex string".into()),
    }
}

/// Read an indexer answer into a resolution.
///
/// # Errors
///
/// A `null` answer (the name is not registered) or a malformed one.
pub fn resolution_from_indexer(text: &str) -> Result<ResolvedName, String> {
    if text.trim() == "null" {
        return Err("the name is not registered".into());
    }
    let object = flat_object(text)?;
    let name = match object.get("name") {
        Some(FlatValue::Str(s)) => s.clone(),
        _ => return Err("the answer names no name".into()),
    };
    let owner = hex32(object.get("owner"))?.ok_or("the answer names no owner")?;
    let content_id = hex32(object.get("content_id"))?.map(ContentId);
    let is_expired = matches!(object.get("is_expired"), Some(FlatValue::Bool(true)));
    Ok(ResolvedName {
        name,
        owner,
        storage_root: hex32(object.get("storage_root"))?,
        content_id,
        is_expired,
    })
}

/// A [`NameResolver`] over the indexer. `get` performs `GET <base><path>`
/// and returns the body.
pub struct IndexerResolver<F: Fn(&str) -> Result<String, String>> {
    get: F,
}

impl<F: Fn(&str) -> Result<String, String>> IndexerResolver<F> {
    pub fn new(get: F) -> Self {
        Self { get }
    }
}

impl<F: Fn(&str) -> Result<String, String>> NameResolver for IndexerResolver<F> {
    fn resolve_bud(&self, name: &str) -> Result<(ResolvedName, BnsInclusionProof), String> {
        let body = (self.get)(&format!("/v1/bns/{name}"))?;
        Ok((resolution_from_indexer(&body)?, BnsInclusionProof::None))
    }

    fn bns_root(&self) -> Option<[u8; 32]> {
        None
    }

    fn current_epoch(&self) -> u64 {
        0
    }

    fn resolve_eth(&self, _name: &str) -> Result<(Vec<u8>, bool), String> {
        Err("the Budlum indexer resolves .bud names only".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANSWER: &str = r#"{"name":"ayaz.bud","owner":"0x0101010101010101010101010101010101010101010101010101010101010101","address":null,"storage_root":null,"storage_domain_id":null,"content_id":"0x0202020202020202020202020202020202020202020202020202020202020202","is_expired":false}"#;

    #[test]
    fn an_indexer_answer_becomes_an_unproven_resolution() {
        let resolver = IndexerResolver::new(|path: &str| {
            assert_eq!(path, "/v1/bns/ayaz.bud");
            Ok(ANSWER.to_string())
        });
        let (resolved, proof) = resolver.resolve_bud("ayaz.bud").expect("resolves");
        assert_eq!(resolved.name, "ayaz.bud");
        assert_eq!(resolved.owner, [1u8; 32]);
        assert_eq!(resolved.content_id, Some(ContentId([2u8; 32])));
        assert!(!resolved.is_expired);
        assert_eq!(proof, BnsInclusionProof::None);
    }

    #[test]
    fn null_nested_and_escaped_answers_are_refused() {
        assert!(resolution_from_indexer("null").is_err());
        assert!(flat_object(r#"{"a":{"b":1}}"#).is_err());
        assert!(flat_object(r#"{"a":"x\"y"}"#).is_err());
        assert!(flat_object(r#"{"a":1} extra"#).is_err());
    }
}
