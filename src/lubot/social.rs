//! SocialFi ↔ Lubot runtime entegrasyonu.
//!
//! Lubot AI çıktısı SocialFi'da **gerçek NFT** olarak yayımlanır (`NftRegistry::mint`);
//! Sosyal NFT içeriği Lubot için kapalı-devre veri kaynağına dönüştürülür
//! (`SocialDataRef`). İki yön de çalışır: Lubot → sosyal (NFT), sosyal → Lubot
//! (`Pollen` `DataAsset` köprüsü: çıktı `register_data_asset` ile kaydedilir ve
//! mevcut `AiDataInputRef`/`validate_ai_read_ref` grant yoluyla okunur).
//!
//! WIRING: wired - `lubot_output_to_nft` artık executor'ün `AiInferenceResult`
//! finalization yolundan çağrılır (src/execution/executor.rs); kesinleşmiş
//! çıktı istek sahibine "lubot-ai" NFT'si olarak basılır ve aynı blokta
//! `Pollen` `DataAsset` kaydı yapılır (best-effort).

use crate::core::address::Address;
use crate::socialfi::NftRegistry;
use crate::storage::content_id::ContentId;

use super::SocialDataRef;

/// Lubot AI çıktısını SocialFi'da NFT olarak mint et (gerçek `NftRegistry::mint`).
/// `output` = Lubot çıkarım yanıtının baytları; ContentId = `ContentId::of(output)`.
/// # Errors
///
/// Whatever `NftRegistry::mint` refuses, which today is a duplicate id: the
/// registry's counter disagreeing with its own contents. Propagated rather
/// than unwrapped, because minting over a live NFT hands somebody else's
/// asset to this caller.
pub fn lubot_output_to_nft(
    registry: &mut NftRegistry,
    owner: Address,
    output: &[u8],
    epoch: u64,
) -> Result<(u64, ContentId), crate::socialfi::NftError> {
    let cid = ContentId::of(output);
    let nft_id = registry.mint(owner, cid, epoch, Some("lubot-ai".to_string()))?;
    Ok((nft_id, cid))
}

/// Bir sosyal NFT içeriğini Lubot kapalı-devre veri kaynağına dönüştür.
/// (Lubot bu içeriği yalnızca bir Pollen grant ile okur - `validate_inference_grant`.)
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
        let (nft_id, cid) = lubot_output_to_nft(&mut registry, owner, b"lubot-ai-output", 10)
            .expect("a fresh registry has no id to collide with");
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
