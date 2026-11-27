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

use crate::bns_proof::{content_binding, BnsInclusionProof, NameContent, ResolvedName};
use crate::content_id::ContentId;
use crate::name_rule;
use crate::resolve::NameResolver;
use std::collections::BTreeMap;

/// Maximum size of a single indexer JSON response body (64 KiB).
///
/// WIRING: Explorer indexer response body ceiling constant.
pub const MAX_INDEXER_BODY_BYTES: usize = 64 * 1024;

/// One value of a flat JSON object.
#[derive(Debug, Clone, PartialEq, Eq)]
/// exposed for: the scanner crate's API surface - its CLI consumers land with the scan rollout.
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
/// Anything that is not one flat object of unique string keys within
/// [`MAX_INDEXER_BODY_BYTES`].
/// exposed for: the scanner crate's API surface - its CLI consumers land with the scan rollout.
pub fn flat_object(text: &str) -> Result<BTreeMap<String, FlatValue>, String> {
    if text.len() > MAX_INDEXER_BODY_BYTES {
        return Err(format!(
            "indexer response is {} bytes, above the {MAX_INDEXER_BODY_BYTES} byte ceiling",
            text.len()
        ));
    }
    let mut chars = text.trim().chars().peekable();
    let mut out = BTreeMap::new();
    if chars.next() != Some('{') {
        return Err("expected an object".into());
    }
    skip_ws(&mut chars);
    if chars.peek() == Some(&'}') {
        chars.next();
    } else {
        loop {
            skip_ws(&mut chars);
            if chars.peek() != Some(&'"') {
                return Err("expected a key".into());
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
                Some(c) if c.is_ascii_digit() || *c == '-' => FlatValue::Num(number(&mut chars)?),
                _ => return Err("nested or unknown value".into()),
            };
            if out.contains_key(&key) {
                return Err(format!("duplicate key {key:?}"));
            }
            out.insert(key, value);
            skip_ws(&mut chars);
            match chars.next() {
                Some(',') => {}
                Some('}') => break,
                _ => return Err("expected ',' or '}'".into()),
            }
        }
    }
    skip_ws(&mut chars);
    if chars.next().is_some() {
        return Err("trailing characters".into());
    }
    Ok(out)
}

fn number(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Result<String, String> {
    let mut out = String::new();
    if chars.next_if(|c| *c == '-').is_some() {
        out.push('-');
    }
    let mut digits = 0usize;
    while let Some(d) = chars.next_if(char::is_ascii_digit) {
        out.push(d);
        digits += 1;
    }
    if digits == 0 || matches!(chars.peek(), Some('-')) {
        return Err("malformed number".into());
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
            // escape or raw control character violates RFC 8259 / flat schema.
            Some('\\') | None => return Err("escapes and unterminated strings are refused".into()),
            Some(c) if c.is_control() => {
                return Err("control characters in strings are refused".into())
            }
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
/// exposed for: the scanner crate's API surface - its CLI consumers land with the scan rollout.
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
    // The content reference arrives flat: `content_digest`, `content_len`,
    // `content_object`, `content_sealed` and `content_nft`. The binding the
    // leaf commits to is computed here from all of them, never read from the
    // answer, so a proof that verifies has proven the digest the page is
    // fetched by.
    let content = match hex32(object.get("content_digest"))? {
        None => None,
        Some(digest) => {
            let len = match object.get("content_len") {
                Some(FlatValue::Num(n)) => n
                    .parse::<u64>()
                    .map_err(|_| "content_len is not a length".to_string())?,
                _ => return Err("the content names no length".into()),
            };
            Some(NameContent {
                sealed: matches!(object.get("content_sealed"), Some(FlatValue::Bool(true))),
                digest,
                len,
                object_commitment: hex32(object.get("content_object"))?
                    .ok_or("the content names no object")?,
                nft_id: hex32(object.get("content_nft"))?,
            })
        }
    };
    let content_id = content.map(|c| ContentId(c.digest));
    let content_binding = content.map(|c| content_binding(&name, owner, &c));
    let is_expired = matches!(object.get("is_expired"), Some(FlatValue::Bool(true)));
    Ok(ResolvedName {
        name,
        owner,
        storage_root: hex32(object.get("storage_root"))?,
        content_id,
        content_binding,
        is_expired,
    })
}

/// A [`NameResolver`] over the indexer. `get` performs `GET <base><path>`
/// and returns the body.
/// exposed for: the scanner crate's API surface - its CLI consumers land with the scan rollout.
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
        if let Err(rejection) = name_rule::check_resolvable(name) {
            return Err(format!("invalid .bud name: {rejection}"));
        }
        if name_rule::suffix_of(name) != Some("bud") {
            return Err("the Budlum indexer resolves .bud names only".into());
        }
        let body = (self.get)(&format!("/v1/bns/{name}"))?;
        let resolved = resolution_from_indexer(&body)?;
        if resolved.name != name {
            return Err(format!(
                "indexer name mismatch: requested {name:?}, received {:?}",
                resolved.name
            ));
        }
        Ok((resolved, BnsInclusionProof::None))
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

    const ANSWER: &str = r#"{"name":"ayaz.bud","owner":"0x0101010101010101010101010101010101010101010101010101010101010101","address":null,"storage_root":null,"storage_domain_id":null,"content_digest":"0x0202020202020202020202020202020202020202020202020202020202020202","content_len":1024,"content_object":"0x0303030303030303030303030303030303030303030303030303030303030303","content_sealed":false,"content_nft":null,"is_expired":false}"#;

    #[test]
    fn an_indexer_answer_becomes_an_unproven_resolution() {
        let resolver = IndexerResolver::new(|path: &str| {
            assert_eq!(path, "/v1/bns/ayaz.bud");
            Ok(ANSWER.to_string())
        });
        let (answer, proof) = resolver.resolve_bud("ayaz.bud").expect("resolves");
        assert_eq!(answer.name, "ayaz.bud");
        assert_eq!(answer.owner, [1u8; 32]);
        assert_eq!(answer.content_id, Some(ContentId([2u8; 32])));
        assert_eq!(
            answer.content_binding.map(hex::encode).as_deref(),
            Some("1f64b4ce979f1864d4ab5d6784d32094a6085e6adef0fcd5410fc0261516560c")
        );
        assert!(!answer.is_expired);
        assert_eq!(proof, BnsInclusionProof::None);
    }

    #[test]
    fn null_nested_and_escaped_answers_are_refused() {
        assert!(resolution_from_indexer("null").is_err());
        assert!(flat_object(r#"{"a":{"b":1}}"#).is_err());
        assert!(flat_object(r#"{"a":"x\"y"}"#).is_err());
        assert!(flat_object(r#"{"a":1} extra"#).is_err());
    }

    #[test]
    fn exp05_indexer_rejects_duplicate_keys_bad_nums_ctrl_oversized_traversal_and_name_mismatch() {
        // Duplicate JSON keys must fail closed instead of silently overwriting.
        assert!(flat_object(r#"{"owner":"0x11","owner":"0x22"}"#).is_err());
        // Trailing comma must be rejected.
        assert!(flat_object(r#"{"a":1,}"#).is_err());
        // Malformed numbers must be rejected.
        for bad_num in [r#"{"n":---}"#, r#"{"n":-}"#, r#"{"n":12-34}"#] {
            assert!(flat_object(bad_num).is_err(), "{bad_num} must be refused");
        }
        // Raw control characters inside JSON strings violate RFC 8259.
        assert!(flat_object("{\"a\":\"line1\nline2\"}").is_err());
        assert!(flat_object("{\"a\":\"nul\0byte\"}").is_err());
        // Oversized indexer response (> 64 KiB) must be refused.
        let huge = format!("{{\"a\":\"{}\"}}", "x".repeat(70 * 1024));
        assert!(flat_object(&huge).is_err());

        // Path traversal / query injection in resolve_bud must never reach the transport.
        let resolver = IndexerResolver::new(|_path: &str| {
            panic!("transport must not be called for invalid .bud name")
        });
        assert!(resolver.resolve_bud("../../admin?x=1").is_err());
        assert!(resolver.resolve_bud("ayaz.eth").is_err());

        // Mismatched name in indexer response must be refused.
        let mismatched = IndexerResolver::new(|_path: &str| Ok(ANSWER.to_string()));
        let err = mismatched
            .resolve_bud("other.bud")
            .expect_err("mismatched name must be rejected");
        assert!(err.contains("mismatch"), "{err}");
    }
}
