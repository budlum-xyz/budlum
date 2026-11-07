//! B.U.D. 3.0 SocialFi NFT bindings and `nft_folders` registry (Section 5.6).
//! exposed for SocialFi transaction execution, RPC handlers, and wallet folder organization.
//!
//! * Every B.U.D. 3.0 SocialFi NFT binds both its [`ContentId`] and its
//!   `object_commitment` ([`ObjectKey`], Section 6.4 Y15).
//! * Minting and burning strictly enforce ownership:
//!   - A caller cannot mint an NFT bound to a third party's sealed object.
//!   - Burning an NFT requires `nft.owner == caller` and decrements the
//!     reference count in [`Bud3Registry`] via `burn_reference` / `social_delete`,
//!     so burning one user's NFT never evicts a shared public object while
//!     another owner's NFT still references it.
//! * `nft_folders` organizes owned NFTs into named folders per account.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{NftError, NftRegistry, MAX_AUTHOR_NAME_BYTES};
use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::storage::bud3::content_id::{ContentId, ContentIdKind};
use crate::storage::bud3::content_ref::{ContentRef, ContentRefError};
use crate::storage::bud3::delete::GrantShredAuth;
use crate::storage::bud3::registry::{Bud3Registry, NftId, ObjectKey, RegistryError};

/// Domain tag deriving the 32-byte B.U.D. 3.0 [`NftId`] from a SocialFi `u64` id.
pub const DOMAIN_SOCIALFI_NFT_ID: &[u8] = b"BDLM_BUD3_SOCIALFI_NFT_V1";

/// Maximum folders one owner may create.
pub const MAX_FOLDERS_PER_OWNER: usize = 256;

/// Maximum NFTs stored inside a single folder.
pub const MAX_NFTS_PER_FOLDER: usize = 4_096;

/// Maximum UTF-8 byte length of a folder title.
pub const MAX_FOLDER_NAME_BYTES: usize = 64;

/// Derive the canonical 32-byte [`NftId`] for a SocialFi `u64` NFT id.
#[must_use]
pub fn derive_bud3_nft_id(socialfi_id: u64) -> NftId {
    hash_fields_bytes(&[DOMAIN_SOCIALFI_NFT_ID, &socialfi_id.to_le_bytes()])
}

/// Errors returned by B.U.D. 3.0 SocialFi NFT bindings and `nft_folders`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocialFiBud3Error {
    /// Underlying SocialFi NFT error (`NotOwner`, `NotFound`, `InvalidName`, etc.).
    Nft(String),
    /// Referenced `ObjectKey` does not exist in [`Bud3Registry`].
    UnknownObject,
    /// Caller attempted to mint against another account's sealed object.
    UnauthorizedSealedObject,
    /// Underlying [`Bud3Registry`] binding or burn error.
    Registry(RegistryError),
    /// Invalid `ContentRef`.
    InvalidContentRef(ContentRefError),
    /// Invalid or empty folder name.
    InvalidFolderName,
    /// Folder not found.
    FolderNotFound,
    /// Folder limit exceeded.
    FolderLimitExceeded,
}

impl std::fmt::Display for SocialFiBud3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nft(msg) => write!(f, "socialfi nft error: {msg}"),
            Self::UnknownObject => f.write_str("unknown B.U.D. 3.0 object commitment"),
            Self::UnauthorizedSealedObject => {
                f.write_str("caller does not own the target sealed B.U.D. 3.0 object")
            }
            Self::Registry(e) => write!(f, "bud3 registry error: {e:?}"),
            Self::InvalidContentRef(e) => write!(f, "invalid ContentRef: {e:?}"),
            Self::InvalidFolderName => f.write_str("invalid folder name"),
            Self::FolderNotFound => f.write_str("nft folder not found"),
            Self::FolderLimitExceeded => f.write_str("nft folder limit exceeded"),
        }
    }
}

impl std::error::Error for SocialFiBud3Error {}

/// B.U.D. 3.0 commitment metadata attached to a minted SocialFi NFT (Section 6.4 Y15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bud3NftCommitment {
    pub id: u64,
    pub nft_id: NftId,
    pub owner: Address,
    pub content_ref: ContentRef,
    pub object_commitment: ObjectKey,
}

/// One user-managed NFT folder (`nft_folders`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftFolder {
    pub folder_id: u64,
    pub owner: Address,
    pub name: String,
    pub nft_ids: Vec<u64>,
}

/// Owner-checked NFT folder registry and B.U.D. 3.0 SocialFi bridge.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NftFolderRegistry {
    commitments: BTreeMap<u64, Bud3NftCommitment>,
    folders: BTreeMap<u64, NftFolder>,
    owner_folders: BTreeMap<Address, Vec<u64>>,
    next_folder_id: u64,
}

impl NftFolderRegistry {
    /// Create an empty `nft_folders` and B.U.D. 3.0 commitment registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up the B.U.D. 3.0 commitment record for a minted SocialFi NFT.
    #[must_use]
    pub fn commitment(&self, id: u64) -> Option<&Bud3NftCommitment> {
        self.commitments.get(&id)
    }

    /// Look up a folder by `folder_id`.
    #[must_use]
    pub fn folder(&self, folder_id: u64) -> Option<&NftFolder> {
        self.folders.get(&folder_id)
    }

    /// Mint a SocialFi NFT bound to a registered B.U.D. 3.0 object.
    /// exposed for SocialFi mint transaction execution and RPC handlers.
    ///
    /// Enforces author-name bounds, sealed-object ownership, and increments the
    /// object's on-chain reference count via [`Bud3Registry::bind_nft`].
    ///
    /// # Errors
    ///
    /// Returns [`SocialFiBud3Error`] if ownership, bounds, or binding fails.
    pub fn mint_bud3_nft(
        &mut self,
        nft_reg: &mut NftRegistry,
        bud3_reg: &mut Bud3Registry,
        caller: Address,
        object_commitment: ObjectKey,
        epoch: u64,
        author_name: Option<String>,
    ) -> Result<Bud3NftCommitment, SocialFiBud3Error> {
        if author_name
            .as_ref()
            .is_some_and(|n| n.is_empty() || n.len() > MAX_AUTHOR_NAME_BYTES)
        {
            return Err(SocialFiBud3Error::Nft(NftError::InvalidName.to_string()));
        }
        let (cid, owner_addr) = {
            let obj = bud3_reg
                .object(&object_commitment)
                .ok_or(SocialFiBud3Error::UnknownObject)?;
            (obj.record.content_id, obj.owner)
        };
        if cid.kind == ContentIdKind::Sealed && owner_addr != caller.0 {
            return Err(SocialFiBud3Error::UnauthorizedSealedObject);
        }

        let legacy_cid = crate::storage::content_id::ContentId(cid.digest);
        let id = nft_reg
            .mint(caller, legacy_cid, epoch, author_name)
            .map_err(|e| SocialFiBud3Error::Nft(e.to_string()))?;
        let nft_id = derive_bud3_nft_id(id);
        let content_ref = ContentRef::new(cid, object_commitment, Some(nft_id))
            .map_err(SocialFiBud3Error::InvalidContentRef)?;
        bud3_reg
            .bind_nft(nft_id, caller.0, &object_commitment)
            .map_err(SocialFiBud3Error::Registry)?;

        let meta = Bud3NftCommitment {
            id,
            nft_id,
            owner: caller,
            content_ref,
            object_commitment,
        };
        self.commitments.insert(id, meta.clone());
        Ok(meta)
    }

    /// Burn a SocialFi NFT with strict owner verification and B.U.D. 3.0
    /// reference release / cryptographic grant shredding.
    /// exposed for SocialFi burn transaction execution and RPC handlers.
    ///
    /// # Errors
    ///
    /// Returns [`SocialFiBud3Error`] if `caller` is not the NFT owner or
    /// reference release fails.
    pub fn burn_bud3_nft(
        &mut self,
        nft_reg: &mut NftRegistry,
        bud3_reg: &mut Bud3Registry,
        id: u64,
        caller: &Address,
        grant_shreds: &[GrantShredAuth],
        epoch: u64,
    ) -> Result<ContentId, SocialFiBud3Error> {
        let current = nft_reg
            .get_nft(id)
            .ok_or_else(|| SocialFiBud3Error::Nft(NftError::NotFound.to_string()))?;
        if &current.owner != caller {
            return Err(SocialFiBud3Error::Nft(NftError::NotOwner.to_string()));
        }
        let meta = self
            .commitments
            .get(&id)
            .cloned()
            .ok_or(SocialFiBud3Error::UnknownObject)?;

        if meta.content_ref.content_id.kind == ContentIdKind::Sealed || !grant_shreds.is_empty() {
            bud3_reg
                .social_delete(&meta.nft_id, &caller.0, grant_shreds, epoch)
                .map_err(SocialFiBud3Error::Registry)?;
        } else {
            bud3_reg
                .burn_reference(&meta.nft_id, &caller.0, epoch)
                .map_err(SocialFiBud3Error::Registry)?;
        }

        nft_reg
            .burn(id, caller)
            .map_err(|e| SocialFiBud3Error::Nft(e.to_string()))?;
        self.commitments.remove(&id);

        if let Some(fids) = self.owner_folders.get(caller).cloned() {
            for fid in fids {
                if let Some(folder) = self.folders.get_mut(&fid) {
                    folder.nft_ids.retain(|&x| x != id);
                }
            }
        }
        Ok(meta.content_ref.content_id)
    }

    /// Create a named NFT folder owned by `caller`.
    /// exposed for wallet SDK and SocialFi `nft_folders` RPC handlers.
    ///
    /// # Errors
    ///
    /// Returns [`SocialFiBud3Error`] if the name or folder count is out of bounds.
    pub fn create_folder(
        &mut self,
        caller: Address,
        name: &str,
    ) -> Result<u64, SocialFiBud3Error> {
        let trimmed = name.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_FOLDER_NAME_BYTES {
            return Err(SocialFiBud3Error::InvalidFolderName);
        }
        if self
            .owner_folders
            .get(&caller)
            .is_some_and(|list| list.len() >= MAX_FOLDERS_PER_OWNER)
        {
            return Err(SocialFiBud3Error::FolderLimitExceeded);
        }
        let folder_id = self.next_folder_id;
        self.next_folder_id = self.next_folder_id.saturating_add(1);
        self.folders.insert(
            folder_id,
            NftFolder {
                folder_id,
                owner: caller,
                name: trimmed.to_string(),
                nft_ids: Vec::new(),
            },
        );
        self.owner_folders
            .entry(caller)
            .or_default()
            .push(folder_id);
        Ok(folder_id)
    }

    /// Place an owned NFT into an owned folder.
    /// exposed for wallet SDK and SocialFi `nft_folders` RPC handlers.
    ///
    /// # Errors
    ///
    /// Returns [`SocialFiBud3Error`] if `caller` owns neither the folder nor the NFT.
    pub fn add_nft_to_folder(
        &mut self,
        nft_reg: &NftRegistry,
        caller: &Address,
        folder_id: u64,
        nft_id: u64,
    ) -> Result<(), SocialFiBud3Error> {
        let nft = nft_reg
            .get_nft(nft_id)
            .ok_or_else(|| SocialFiBud3Error::Nft(NftError::NotFound.to_string()))?;
        if &nft.owner != caller {
            return Err(SocialFiBud3Error::Nft(NftError::NotOwner.to_string()));
        }
        let folder = self
            .folders
            .get_mut(&folder_id)
            .ok_or(SocialFiBud3Error::FolderNotFound)?;
        if &folder.owner != caller {
            return Err(SocialFiBud3Error::Nft(NftError::NotOwner.to_string()));
        }
        if !folder.nft_ids.contains(&nft_id) {
            if folder.nft_ids.len() >= MAX_NFTS_PER_FOLDER {
                return Err(SocialFiBud3Error::FolderLimitExceeded);
            }
            folder.nft_ids.push(nft_id);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::bud3::limits::{Bud3Limits, Profile};
    use crate::storage::bud3::pipeline::prepare_public_upload;
    use crate::storage::bud3::placement::{Class, Share};

    const P: Profile = Profile {
        id: 0,
        qr_version: 40,
        symbol_size: 128,
        fps: 10,
        k_max: 16,
    };

    #[test]
    fn socialfi_nft_burn_needs_owner() {
        let alice = Address([1u8; 32]);
        let attacker = Address([2u8; 32]);
        let mut nft_reg = NftRegistry::new();
        let mut bud3_reg = Bud3Registry::default();
        let mut folders = NftFolderRegistry::new();

        let body = b"socialfi post protected against third-party burn".repeat(6);
        let up = prepare_public_upload(&body, &P, &Bud3Limits::default(), 8).unwrap();
        let key = up.record.commitment;
        bud3_reg
            .register_object(
                alice.0,
                up.record,
                vec![(
                    0,
                    Share {
                        validator: [9u8; 32],
                        class: Class::Full,
                        first_esi: 0,
                        symbols: 8,
                    },
                )],
                1,
                20,
            )
            .unwrap();

        let alice_nft = folders
            .mint_bud3_nft(
                &mut nft_reg,
                &mut bud3_reg,
                alice,
                key,
                1,
                Some(String::from("alice")),
            )
            .unwrap();
        let fid = folders.create_folder(alice, "highlights").unwrap();
        folders
            .add_nft_to_folder(&nft_reg, &alice, fid, alice_nft.id)
            .unwrap();

        // Attacker cannot burn Alice's NFT directly.
        assert!(folders
            .burn_bud3_nft(&mut nft_reg, &mut bud3_reg, alice_nft.id, &attacker, &[], 2)
            .is_err());

        // Even if attacker mints and burns their own NFT referencing the same public object,
        // Alice's object reference stays live (`references.len() == 1`)!
        let attacker_nft = folders
            .mint_bud3_nft(&mut nft_reg, &mut bud3_reg, attacker, key, 1, None)
            .unwrap();
        assert_eq!(bud3_reg.object(&key).unwrap().references.len(), 2);
        folders
            .burn_bud3_nft(
                &mut nft_reg,
                &mut bud3_reg,
                attacker_nft.id,
                &attacker,
                &[],
                2,
            )
            .unwrap();
        assert!(bud3_reg.object(&key).is_some());
        assert_eq!(bud3_reg.object(&key).unwrap().references.len(), 1);
    }
}
