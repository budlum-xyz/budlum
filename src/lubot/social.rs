//! Faz A — SocialFi ↔ Lubot runtime entegrasyonu.
//!
//! Lubot AI çıktısı SocialFi'da **gerçek NFT** olarak yayımlanır (`NftRegistry::mint`);
//! sosyal NFT içeriği Lubot için kapalı-devre veri kaynağına dönüştürülür
//! (`SocialDataRef`). İki yön de çalışır: Lubot → sosyal, sosyal → Lubot.

use crate::core::address::Address;
use crate::socialfi::NftRegistry;
use crate::storage::content_id::ContentId;

use super::SocialDataRef;

/// Lubot AI çıktısını SocialFi'da NFT olarak mint et (gerçek `NftRegistry::mint`).
/// `output` = Lubot çıkarım yanıtının baytları; ContentId = `ContentId::of(output)`.
#[must_use]
pub fn lubot_output_to_nft(
    registry: &mut NftRegistry,
    owner: Address,
    output: &[u8],
    epoch: u64,
) -> (u64, ContentId) {
    let cid = ContentId::of(output);
    let nft_id = registry.mint(owner, cid, epoch, Some("lubot-ai".to_string()));
    (nft_id, cid)
}

/// Bir sosyal NFT içeriğini Lubot kapalı-devre veri kaynağına dönüştür.
/// (Lubot bu içeriği yalnızca bir Pollen grant ile okur — `validate_inference_grant`.)
#[must_use]
pub fn social_nft_to_data_ref(nft_id: u64, content_id: ContentId, owner: Address) -> SocialDataRef {
    SocialDataRef::from_social(nft_id, content_id.0, owner)
}

/// Lubot NFT'sine etiket ekle (örn. "#lubot-ai", "#ai-output").
pub fn tag_lubot_nft(registry: &mut NftRegistry, nft_id: u64, tag: &str) -> Result<(), String> {
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
    fn lubot_output_mints_real_social_nft() {
        let mut registry = NftRegistry::new();
        let owner = addr(1);
        let (nft_id, cid) = lubot_output_to_nft(&mut registry, owner, b"lubot-ai-output", 10);
        // NftRegistry ilk mint id 0'dan başlar (next_id=0).
        let first = nft_id;

        // Etiket ekle (gerçek add_tag).
        assert!(tag_lubot_nft(&mut registry, nft_id, "#lubot-ai").is_ok());

        // Sosyal NFT → Lubot veri kaynağı.
        let data_ref = social_nft_to_data_ref(nft_id, cid, owner);
        assert_eq!(data_ref.nft_id, first);
        assert_eq!(data_ref.owner, owner);
    }
}
