//! B.U.D. 3.0 App Registry (`src/app_registry/`,  item 5).
//!
//! Stores verified application metadata and B.U.D. 3.0 [`ContentRef`] bundle pointers.
//!
//! exposed for: dApp directory RPC handlers and governance verification.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::storage::bud3::content_id::ContentId;
use crate::storage::bud3::content_ref::{ContentRef, ContentRefError};
use crate::storage::bud3::registry::{Bud3Registry, ObjectKey};

/// Domain tag committing an App Registry record.
pub const DOMAIN_APP_REGISTRY: &[u8] = b"BDLM_BUD3_APP_REGISTRY_V1";
/// Minimum fee in whole BUD atoms to register an application.
pub const APP_REGISTRY_MIN_FEE: u64 = 10;

/// Application categories in the App Registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppRegistryCategory {
    SocialFi,
    DeFi,
    Storage,
    Gaming,
    Infrastructure,
    Other,
}

/// Errors refused by [`AppRegistry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppRegistryError {
    InvalidName,
    AlreadyRegistered,
    NotOwner,
    UnknownObject,
    ContentIdMismatch,
    InvalidContentRef(ContentRefError),
    FeeBelowMinimum,
}

/// Registered application entry backed by a B.U.D. 3.0 [`ContentRef`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredApp {
    pub app_id: [u8; 32],
    pub name: String,
    pub developer: Address,
    pub category: AppRegistryCategory,
    pub bundle_ref: ContentRef,
    pub verified_by_governance: bool,
}

/// B.U.D. 3.0 App Registry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppRegistry {
    apps: BTreeMap<String, RegisteredApp>,
}

impl AppRegistry {
    /// Create an empty App Registry.
    ///
    /// exposed for: App Registry state initialization.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new application backed by a registered B.U.D. 3.0 bundle object.
    ///
    /// exposed for: App Registry registration transactions.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn register_app(
        &mut self,
        bud3: &Bud3Registry,
        name: &str,
        developer: Address,
        category: AppRegistryCategory,
        bundle: (ContentId, ObjectKey),
        fee_paid_atoms: u64,
    ) -> Result<RegisteredApp, AppRegistryError> {
        if fee_paid_atoms < APP_REGISTRY_MIN_FEE {
            return Err(AppRegistryError::FeeBelowMinimum);
        }
        let canonical = name.trim().to_ascii_lowercase();
        if canonical.len() < 3 || canonical.len() > 64 {
            return Err(AppRegistryError::InvalidName);
        }
        if self.apps.contains_key(&canonical) {
            return Err(AppRegistryError::AlreadyRegistered);
        }
        let (cid, obj_key) = bundle;
        let obj = bud3
            .object(&obj_key)
            .ok_or(AppRegistryError::UnknownObject)?;
        if obj.record.content_id != cid {
            return Err(AppRegistryError::ContentIdMismatch);
        }
        if obj.owner != *developer.as_bytes() {
            return Err(AppRegistryError::NotOwner);
        }
        let bundle_ref =
            ContentRef::new(cid, obj_key, None).map_err(AppRegistryError::InvalidContentRef)?;
        let app_id = hash_fields_bytes(&[
            DOMAIN_APP_REGISTRY,
            canonical.as_bytes(),
            developer.as_bytes(),
            &cid.digest,
            &obj_key,
        ]);
        let rec = RegisteredApp {
            app_id,
            name: canonical.clone(),
            developer,
            category,
            bundle_ref,
            verified_by_governance: false,
        };
        self.apps.insert(canonical, rec.clone());
        Ok(rec)
    }

    /// Look up a registered application by name.
    ///
    /// exposed for: App Registry RPC queries.
    #[must_use]
    pub fn get_app(&self, name: &str) -> Option<&RegisteredApp> {
        self.apps.get(&name.trim().to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::bud3::limits::{Bud3Limits, Profile};
    use crate::storage::bud3::pipeline::prepare_public_upload;
    use crate::storage::bud3::placement::{Class, Share};

    #[test]
    fn register_app_enforces_bundle_owner_and_minimum_fee() {
        let mut bud3 = Bud3Registry::default();
        let owner = Address::from([0x11; 32]);
        let intruder = Address::from([0x22; 32]);
        let profile = Profile {
            id: 0,
            qr_version: 40,
            symbol_size: 128,
            fps: 10,
            k_max: 16,
        };
        let up = prepare_public_upload(&[0xAB; 256], &profile, &Bud3Limits::default(), 4).unwrap();
        let cid = up.record.content_id;
        let key = up.record.commitment;
        let shares = vec![(
            0,
            Share {
                validator: [0x99; 32],
                class: Class::Full,
                first_esi: 0,
                symbols: up.record.symbols_per_segment,
            },
        )];
        bud3.register_object(*owner.as_bytes(), up.record, shares, 0, 50)
            .unwrap();

        let mut reg = AppRegistry::new();
        assert_eq!(
            reg.register_app(
                &bud3,
                "budswap",
                owner,
                AppRegistryCategory::DeFi,
                (cid, key),
                APP_REGISTRY_MIN_FEE - 1,
            ),
            Err(AppRegistryError::FeeBelowMinimum)
        );
        assert_eq!(
            reg.register_app(
                &bud3,
                "budswap",
                intruder,
                AppRegistryCategory::DeFi,
                (cid, key),
                APP_REGISTRY_MIN_FEE,
            ),
            Err(AppRegistryError::NotOwner)
        );
        let registered = reg
            .register_app(
                &bud3,
                "BudSwap",
                owner,
                AppRegistryCategory::DeFi,
                (cid, key),
                APP_REGISTRY_MIN_FEE,
            )
            .unwrap();
        assert_eq!(registered.developer, owner);
        assert_eq!(reg.get_app("budswap"), Some(&registered));
    }
}
