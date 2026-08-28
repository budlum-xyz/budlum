//! Default visibility for Three uploads (user 2026-08-27).
//!
//! **Start sealed (V0).** Owner later opens via key infrastructure to everyone
//! (PublicKeyId) or named people (NamedGrantee). When the owner deletes from
//! social/DM, the key id rotates / grant revokes → content stops being
//! openable for **new** sessions (T3 honesty: devices already holding frames
//! are not clawed back).

use crate::storage::qr_recipe::{ThreeRecipe, ThreeRecipePublic};
use crate::storage::view_grant::ViewPolicy;

/// Product default at upload time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UploadVisibility {
    /// V0 — sealed recipe; only owner keystore opens.
    #[default]
    SealedOwner,
    /// V1 — will attach NamedGrantee grants after upload.
    Restricted,
    /// V2 — public recipe on chain.
    Public,
}



/// Build on-chain recipe form from the full public pipe recipe.
#[must_use]
pub fn recipe_for_upload(full: &ThreeRecipePublic, vis: UploadVisibility) -> ThreeRecipe {
    match vis {
        UploadVisibility::Public => ThreeRecipe::Public(full.clone()),
        UploadVisibility::SealedOwner | UploadVisibility::Restricted => {
            ThreeRecipe::Sealed(full.seal())
        }
    }
}

/// ViewPolicy to pair with the upload (grant layer).
#[must_use]
pub const fn policy_for_upload(vis: UploadVisibility) -> ViewPolicy {
    match vis {
        UploadVisibility::SealedOwner => ViewPolicy::OwnerOnly,
        UploadVisibility::Restricted => ViewPolicy::NamedGrantee,
        UploadVisibility::Public => ViewPolicy::PublicKeyId,
    }
}

/// Social/DM delete → treat as key rotation signal (hook kind).
#[must_use]
pub const fn delete_implies_key_rotate() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::qr_carousel::CarouselEncoder;
    use crate::storage::qr_payload::{pack_payload, payload_commitment, PayloadKind};

    #[test]
    fn default_is_sealed() {
        assert_eq!(UploadVisibility::default(), UploadVisibility::SealedOwner);
        let packed = pack_payload(PayloadKind::ContentBytes, b"vis").unwrap();
        let c = payload_commitment(&packed);
        let enc = CarouselEncoder::new(&packed, 32).unwrap();
        let s = enc.params().stream_commitment(&c);
        let full = ThreeRecipePublic::new(c, enc.params(), s);
        let r = recipe_for_upload(&full, UploadVisibility::default());
        assert!(matches!(r, ThreeRecipe::Sealed(_)));
        assert_eq!(
            policy_for_upload(UploadVisibility::default()),
            ViewPolicy::OwnerOnly
        );
    }
}
