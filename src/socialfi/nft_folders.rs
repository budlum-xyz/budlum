//! SocialFi `nft_folders` and B.U.D. 3.0 NFT commitment bindings (`WP-23`, `BLG-109`).
//!
//! exposed for: SocialFi transaction execution, RPC handlers, and wallet SDK.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::types::NftError;
use super::{NftRegistry, MAX_AUTHOR_NAME_BYTES};
use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::storage::bud3::content_id::{ContentId, ContentIdKind};
use crate::storage::bud3::content_ref::{ContentRef, ContentRefError};
use crate::storage::bud3::grants::GrantShredAuth;
use crate::storage::bud3::registry::{Bud3Registry, NftId, ObjectKey, RegistryError};

/// Domain tag deriving a 32-byte `NftId` from a SocialFi `u64` token id.
pub const DOMAIN_SOCIALFI_NFT_ID: &[u8] = b"BDLM_BUD3_NFT_ID_V1";
/// Maximum folder name length in bytes.
pub const MAX_FOLDER_NAME_BYTES: usize = 64;
/// Maximum folders per owner.
pub const MAX_FOLDERS_PER_OWNER: usize = 256;
/// Maximum NFTs inside one folder.
pub const MAX_NFTS_PER_FOLDER: usize = 4096;

/// Derive a deterministic 32-byte B.U.D. 3.0 `NftId` for a SocialFi token id.
///
/// exposed for: SocialFi NFT reference binding (`WP-23`).
#[must_use]
pub fn derive_bud3_nft_id(token_id: u64) -> NftId {
    hash_fields_bytes(&[DOMAIN_SOCIALFI_NFT_ID, &token_id.to_le_bytes()])
}

/// Errors returned by `nft_folders` and B.U.D. 3.0 NFT lifecycle operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocialFiBud3Error {
    Nft(String),
    UnknownObject,
    UnauthorizedSealedObject,
    InvalidContentRef(ContentRefError),
    Registry(RegistryError),
    InvalidFolderName,
    FolderNotFound,
    FolderLimitExceeded,
}

/// B.U.D. 3.0 commitment bound to a minted SocialFi NFT (Section 6.4 Y15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bud3NftCommitment {
    pub id: u64,
    pub nft_id: NftId,
    pub owner: Address,
    pub content_ref: ContentRef,
    pub object_commitment: ObjectKey,
}

/// Named collection of owned SocialFi NFTs (`nft_folders`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftFolder {
    pub folder_id: u64,
    pub owner: Address,
    pub name: String,
    pub nft_ids: Vec<u64>,
}

/// Registry managing B.U.D. 3.0 NFT commitments and `nft_folders`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NftFolderRegistry {
    commitments: BTreeMap<u64, Bud3NftCommitment>,
    folders: BTreeMap<u64, NftFolder>,
    owner_folders: BTreeMap<Address, Vec<u64>>,
    next_folder_id: u64,
}

impl NftFolderRegistry {
    /// Create an empty `nft_folders` registry.
    ///
    /// exposed for: SocialFi state initialization (`WP-23`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up the B.U.D. 3.0 commitment record for a SocialFi NFT.
    ///
    /// exposed for: SocialFi RPC and explorer queries (`WP-23`).
    #[must_use]
    pub fn commitment(&self, id: u64) -> Option<&Bud3NftCommitment> {
        self.commitments.get(&id)
    }

    /// Look up a folder by `folder_id`.
    ///
    /// exposed for: SocialFi folder queries (`WP-23`).
    #[must_use]
    pub fn folder(&self, folder_id: u64) -> Option<&NftFolder> {
        self.folders.get(&folder_id)
    }

    /// Mint a SocialFi NFT bound to a registered B.U.D. 3.0 object (`BLG-109`).
    ///
    /// exposed for: SocialFi mint execution (`WP-23`).
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

    /// Burn a SocialFi NFT with strict owner verification, ghost-folder purge (`BLG-065`),
    /// and B.U.D. 3.0 reference release / grant shredding (`BLG-109`).
    ///
    /// exposed for: SocialFi burn execution (`WP-23`).
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
    ///
    /// exposed for: SocialFi `nft_folders` management (`WP-23`).
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
    ///
    /// exposed for: SocialFi `nft_folders` management (`WP-23`).
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
        let up = prepare_public_upload(&body, &P, &Bud3Limits::default(), 8).expect("upload");
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
            .expect("register");

        let alice_nft = folders
            .mint_bud3_nft(
                &mut nft_reg,
                &mut bud3_reg,
                alice,
                key,
                1,
                Some(String::from("alice")),
            )
            .expect("mint");
        let fid = folders.create_folder(alice, "highlights").expect("folder");
        folders
            .add_nft_to_folder(&nft_reg, &alice, fid, alice_nft.id)
            .expect("add");

        // Attacker cannot burn Alice's NFT (`BLG-109`).
        assert!(folders
            .burn_bud3_nft(&mut nft_reg, &mut bud3_reg, alice_nft.id, &attacker, &[], 2)
            .is_err());

        // Even if attacker mints and burns their own NFT referencing the same public object,
        // Alice's reference stays live (`references.len() == 1`).
        let attacker_nft = folders
            .mint_bud3_nft(&mut nft_reg, &mut bud3_reg, attacker, key, 1, None)
            .expect("attacker mint");
        assert_eq!(bud3_reg.object(&key).expect("obj").references.len(), 2);
        folders
            .burn_bud3_nft(&mut nft_reg, &mut bud3_reg, attacker_nft.id, &attacker, &[], 2)
            .expect("attacker burn");
        assert!(bud3_reg.object(&key).is_some());
        assert_eq!(bud3_reg.object(&key).expect("obj").references.len(), 1);

        // When Alice burns her own NFT, folder ghost entry is also purged (`BLG-065`).
        folders
            .burn_bud3_nft(&mut nft_reg, &mut bud3_reg, alice_nft.id, &alice, &[], 3)
            .expect("alice burn");
        assert!(folders.folder(fid).expect("folder").nft_ids.is_empty());
    }
}
