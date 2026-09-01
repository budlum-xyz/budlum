//! The SocialFi and Agent runtime integration.
//!
//! A Agent AI output is published on SocialFi as a **real NFT**
//! (`NftRegistry::mint`), and social NFT content is turned into a
//! closed-circuit data source for Agent (`SocialDataRef`). Both directions
//! work: Agent to social (an NFT) and social to Agent (the `Pollen`
//! `DataAsset` bridge: the output is recorded with `register_data_asset` and
//! read through the existing `AiDataInputRef`/`validate_ai_read_ref` grant
//! path).
//!
//! WIRING: wired - `agent_output_to_nft` is now called from the executor's
//! `AiInferenceResult` finalization path (src/execution/executor.rs); the
//! finalised output is minted to the requester as a "agent-ai" NFT, and the
//! `Pollen` `DataAsset` record is written in the same block (best-effort).

use crate::core::address::Address;
use crate::socialfi::NftRegistry;
use crate::storage::content_id::ContentId;

use super::SocialDataRef;

/// Mint a Agent AI output as an NFT on SocialFi (the real
/// `NftRegistry::mint`). `output` is the bytes of the Agent inference
/// response; the ContentId is `ContentId::of(output)`.
/// # Errors
///
/// Whatever `NftRegistry::mint` refuses, which today is a duplicate id: the
/// registry's counter disagreeing with its own contents. Propagated rather
/// than unwrapped, because minting over a live NFT hands somebody else's
/// asset to this caller.
pub fn agent_output_to_nft(
    registry: &mut NftRegistry,
    owner: Address,
    output: &[u8],
    epoch: u64,
) -> Result<(u64, ContentId), crate::socialfi::NftError> {
    let cid = ContentId::of(output);
    let nft_id = registry.mint(owner, cid, epoch, Some("agent-ai".to_string()))?;
    Ok((nft_id, cid))
}

/// Turn social NFT content into a Agent closed-circuit data source.
/// (Agent reads that content only with a Pollen grant -
/// `validate_inference_grant`.)
#[must_use]
pub fn social_nft_to_data_ref(nft_id: u64, content_id: ContentId, owner: Address) -> SocialDataRef {
    SocialDataRef::from_social(nft_id, content_id.0, owner)
}

/// Add a tag to a Agent NFT (for example "#agent-ai" or "#ai-output").
pub fn tag_agent_nft(registry: &mut NftRegistry, nft_id: u64, tag: &str) -> Result<(), String> {
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
    fn agent_output_mints_real_social_nft() {
        let mut registry = NftRegistry::new();
        let owner = addr(1);
        let (nft_id, cid) = agent_output_to_nft(&mut registry, owner, b"agent-ai-output", 10)
            .expect("a fresh registry has no id to collide with");
        // The NftRegistry starts its first mint id at 0 (next_id=0).
        let first = nft_id;

        // Add a tag (the real add_tag).
        assert!(tag_agent_nft(&mut registry, nft_id, "#agent-ai").is_ok());

        // A social NFT becomes a Agent data source.
        let data_ref = social_nft_to_data_ref(nft_id, cid, owner);
        assert_eq!(data_ref.nft_id, first);
        assert_eq!(data_ref.owner, owner);
    }
}
