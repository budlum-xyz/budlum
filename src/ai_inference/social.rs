//! The SocialFi and AI inference layer runtime integration.
//!
//! An AI inference layer AI output is published on SocialFi as a **real NFT**
//! (`NftRegistry::mint`), and social NFT content is turned into a
//! closed-circuit data source for AI inference layer (`SocialDataRef`). Both directions
//! work: AI inference layer to social (an NFT) and social to the AI inference layer (the `Pollen`
//! `DataAsset` bridge: the output is recorded with `register_data_asset` and
//! read through the existing `AiDataInputRef`/`validate_ai_read_ref` grant
//! path).
//!
//! WIRING: wired - `ai_output_to_nft` is now called from the executor's
//! `AiInferenceResult` finalization path (src/execution/executor.rs); the
//! finalised output is minted to the requester as a "ai-inference" NFT, and the
//! `Pollen` `DataAsset` record is written in the same block (best-effort).

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::socialfi::NftRegistry;
use crate::storage::content_id::ContentId;

use super::SocialDataRef;

const FEDERATED_AI_EVENT_DOMAIN: &[u8] = b"BDLM-AI-FEDERATED-EVENT-v1";
const AI_OUTPUT_EVENT_KIND: &str = "budlum.ai.output.v1";

/// Clean-room federation event envelope for an AI output that was minted into
/// SocialFi.
///
/// This is Budlum-native code: it borrows only the general federation lesson from
/// design briefs (stable event ids, explicit actor/object fields, and portable
/// JSON), not any upstream server implementation. The event id is length-prefixed
/// and domain-separated so the JSON rendering is a transport view, not the hash
/// preimage itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederatedAiOutputEvent {
    /// Domain-separated event id.
    pub event_id: [u8; 32],
    /// NFT minted for the output.
    pub nft_id: u64,
    /// Owner / actor of the minted output.
    pub owner: Address,
    /// Content id of the AI output bytes.
    pub content_id: ContentId,
    /// Settlement epoch at which the output was minted.
    pub epoch: u64,
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

/// Build the federation envelope for an already minted AI output.
#[must_use]
pub fn federated_ai_output_event(
    owner: Address,
    nft_id: u64,
    content_id: ContentId,
    epoch: u64,
) -> FederatedAiOutputEvent {
    let nft_le = nft_id.to_le_bytes();
    let epoch_le = epoch.to_le_bytes();
    let event_id = hash_fields_bytes(&[
        FEDERATED_AI_EVENT_DOMAIN,
        AI_OUTPUT_EVENT_KIND.as_bytes(),
        &nft_le,
        &owner.0,
        &content_id.0,
        &epoch_le,
    ]);
    FederatedAiOutputEvent {
        event_id,
        nft_id,
        owner,
        content_id,
        epoch,
    }
}

impl FederatedAiOutputEvent {
    /// Deterministic JSON view for off-chain federation bridges.
    ///
    /// The bridge can map these fields to its chosen protocol; the on-chain /
    /// consensus identity is still [`Self::event_id`]. The string contains only
    /// fixed keys, lowercase hex and integers, so no user-controlled escaping is
    /// needed here.
    #[must_use]
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\"type\":\"{AI_OUTPUT_EVENT_KIND}\",\"id\":\"{}\",",
                "\"actor\":\"{}\",\"object\":{{\"type\":\"budlum.socialfi.nft\",",
                "\"nft_id\":{},\"content_id\":\"{}\"}},\"epoch\":{}}}"
            ),
            hex_lower(&self.event_id),
            hex_lower(&self.owner.0),
            self.nft_id,
            hex_lower(&self.content_id.0),
            self.epoch
        )
    }
}

/// Mint an AI inference layer AI output as an NFT on SocialFi (the real
/// `NftRegistry::mint`). `output` is the bytes of the AI inference layer inference
/// response; the ContentId is `ContentId::of(output)`.
/// # Errors
///
/// Whatever `NftRegistry::mint` refuses, which today is a duplicate id: the
/// registry's counter disagreeing with its own contents. Propagated rather
/// than unwrapped, because minting over a live NFT hands somebody else's
/// asset to this caller.
pub fn ai_output_to_nft(
    registry: &mut NftRegistry,
    owner: Address,
    output: &[u8],
    epoch: u64,
) -> Result<(u64, ContentId), crate::socialfi::NftError> {
    let cid = ContentId::of(output);
    let nft_id = registry.mint(owner, cid, epoch, Some("ai-inference".to_string()))?;
    Ok((nft_id, cid))
}

/// Turn social NFT content into an AI inference layer closed-circuit data source.
/// (AI inference layer reads that content only with a Pollen grant -
/// `validate_inference_grant`.)
#[must_use]
pub fn social_nft_to_data_ref(nft_id: u64, content_id: ContentId, owner: Address) -> SocialDataRef {
    SocialDataRef::from_social(nft_id, content_id.0, owner)
}

/// Add a tag to an AI inference layer NFT (for example "#ai-inference" or "#ai-output").
pub fn tag_ai_nft(registry: &mut NftRegistry, nft_id: u64, tag: &str) -> Result<(), String> {
    registry
        .add_tag(nft_id, tag.to_string())
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socialfi::NftRegistry;

    fn addr(b: u8) -> Address {
        Address([b; 32])
    }

    #[test]
    fn ai_output_mints_real_social_nft() {
        let mut registry = NftRegistry::new();
        let owner = addr(1);
        let (nft_id, cid) = ai_output_to_nft(&mut registry, owner, b"ai-inference-output", 10)
            .expect("a fresh registry has no id to collide with");
        // The NftRegistry starts its first mint id at 0 (next_id=0).
        let first = nft_id;

        // Add a tag (the real add_tag).
        assert!(tag_ai_nft(&mut registry, nft_id, "#ai-inference").is_ok());

        // A social NFT becomes an AI inference layer data source.
        let data_ref = social_nft_to_data_ref(nft_id, cid, owner);
        assert_eq!(data_ref.nft_id, first);
        assert_eq!(data_ref.owner, owner);
    }

    #[test]
    fn federated_event_id_is_bound_to_every_field() {
        let owner = addr(7);
        let cid = ContentId::of(b"ai output");
        let base = federated_ai_output_event(owner, 42, cid, 9);
        assert_eq!(base.nft_id, 42);
        assert_eq!(base.owner, owner);
        assert_eq!(base.content_id, cid);
        assert_eq!(base.epoch, 9);

        assert_ne!(
            base.event_id,
            federated_ai_output_event(addr(8), 42, cid, 9).event_id
        );
        assert_ne!(
            base.event_id,
            federated_ai_output_event(owner, 43, cid, 9).event_id
        );
        assert_ne!(
            base.event_id,
            federated_ai_output_event(owner, 42, ContentId::of(b"other"), 9).event_id
        );
        assert_ne!(
            base.event_id,
            federated_ai_output_event(owner, 42, cid, 10).event_id
        );
    }

    #[test]
    fn federated_event_json_is_deterministic_transport_view() {
        let event = federated_ai_output_event(addr(3), 5, ContentId::of(b"payload"), 11);
        let json = event.to_json();
        assert_eq!(json, event.to_json(), "rendering must be deterministic");
        assert!(json.contains("\"type\":\"budlum.ai.output.v1\""));
        assert!(json.contains("\"object\""));
        assert!(json.contains("\"nft_id\":5"));
        assert!(json.contains("\"epoch\":11"));
        assert!(json.contains(&hex_lower(&event.event_id)));
        assert!(json.contains(&hex_lower(&event.owner.0)));
        assert!(json.contains(&hex_lower(&event.content_id.0)));
    }
}
