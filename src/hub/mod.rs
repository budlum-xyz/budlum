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
    /// V137 (ARENAS): authorized governors who can mark apps as governance-verified.
    /// Empty set = devnet mode (any caller accepted). Production must populate
    /// via governance action (e.g. GovernanceAction::AddHubGovernor).
    #[serde(default)]
    pub authorized_governors: std::collections::HashSet<Address>,
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
            developer_attested: false,
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

    /// Developer self-attestation (ownership proof only).
    ///
    /// V123/H2: This does **not** set `verified` (DAO/governance badge).
    /// UI/indexers must not treat `developer_attested` as third-party audit.
    pub fn attest_app_as_developer(&mut self, id: u64, caller: &Address) -> Result<(), HubError> {
        let app = self.apps.get_mut(&id).ok_or(HubError::NotFound)?;
        if &app.developer != caller {
            return Err(HubError::NotDeveloper);
        }
        app.developer_attested = true;
        Ok(())
    }

    /// Back-compat alias: self-verify == developer attestation only.
    pub fn verify_app(&mut self, id: u64, caller: &Address) -> Result<(), HubError> {
        self.attest_app_as_developer(id, caller)
    }

    /// DAO/governance verification path (sets trusted `verified` badge).
    /// Currently restricted: only the developer can call until authorized_verifiers
    /// exists — and it still only sets developer_attested via verify_app.
    /// Explicit governance action should call `mark_verified_by_governance`.
    ///
    /// V137 fix (ARENAS): Require an explicit caller identity for governance
    /// verification. Without this, any code path that reaches this function
    /// can set `verified = true` without authorization. The caller parameter
    /// is checked against an optional `authorized_governors` set; if the set
    /// is empty (devnet), any caller is accepted (matching current behavior).
    /// Production must populate `authorized_governors` via governance action.
    pub fn mark_verified_by_governance(
        &mut self,
        id: u64,
        caller: &Address,
    ) -> Result<(), HubError> {
        if !self.authorized_governors.is_empty() && !self.authorized_governors.contains(caller) {
            return Err(HubError::NotAuthorized);
        }
        let app = self.apps.get_mut(&id).ok_or(HubError::NotFound)?;
        app.verified = true;
        Ok(())
    }

    pub fn list_apps(&self) -> Vec<AppRecord> {
        self.apps.values().cloned().collect()
    }
}

impl HubRegistry {
    pub fn root(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_HUB_REGISTRY_V1");
        hasher.update(self.next_app_id.to_le_bytes());
        for (id, app) in &self.apps {
            hasher.update(id.to_le_bytes());
            hasher.update(app.developer.0);
            hasher.update(app.name.as_bytes());
            hasher.update([app.developer_attested as u8, app.verified as u8]);
        }
        hasher.finalize().into()
    }
}
