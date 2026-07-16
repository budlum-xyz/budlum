pub mod types;

use crate::core::address::Address;
use crate::hub::types::{AppCategory, AppRecord, HubError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Phase 8.9 / M5: anti-sybil minimum app kayıt ücreti (BNS `base_cost` ile uyumlu).
/// Executor, `HubRegisterApp` tx'lerinde bu tutarı `tx.amount` üzerinden ZORUNLU
/// tutar ve tam olarak bu kadarını düşer (H1 "exact cost" deseniyle simetrik).
pub const HUB_REGISTER_MIN_FEE: u64 = 100;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HubRegistry {
    /// app_id -> record
    pub apps: BTreeMap<u64, AppRecord>,
    pub next_app_id: u64,
}

impl HubRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_app(
        &mut self,
        name: String,
        developer: Address,
        category: AppCategory,
        website_url: String,
        manifest_id: Option<crate::storage::content_id::ContentId>,
        epoch: u64,
    ) -> u64 {
        let id = self.next_app_id;
        let record = AppRecord {
            id,
            name,
            developer,
            category,
            website_url,
            manifest_id,
            registered_at_epoch: epoch,
            verified: false,
        };
        self.apps.insert(id, record);
        self.next_app_id += 1;
        id
    }

    pub fn update_app(
        &mut self,
        id: u64,
        caller: &Address,
        new_url: Option<String>,
        new_manifest: Option<crate::storage::content_id::ContentId>,
    ) -> Result<(), HubError> {
        let app = self.apps.get_mut(&id).ok_or(HubError::NotFound)?;
        if &app.developer != caller {
            return Err(HubError::NotDeveloper);
        }
        if let Some(url) = new_url {
            app.website_url = url;
        }
        if let Some(manifest) = new_manifest {
            app.manifest_id = Some(manifest);
        }
        Ok(())
    }

    /// Verify an app. Phase 8.9 H3 fix: requires either the developer
    /// OR a DAO-governance authorized verifier. Self-verify is allowed
    /// (developer proves ownership); DAO override reserved for Phase 9.
    pub fn verify_app(&mut self, id: u64, caller: &Address) -> Result<(), HubError> {
        let app = self.apps.get_mut(&id).ok_or(HubError::NotFound)?;
        // Developer can self-verify (prove ownership).
        // Future: DAO governance can verify any app via authorized_verifiers set.
        if &app.developer != caller {
            return Err(HubError::NotDeveloper);
        }
        app.verified = true;
        Ok(())
    }

    pub fn list_apps(&self) -> Vec<AppRecord> {
        self.apps.values().cloned().collect()
    }
}
