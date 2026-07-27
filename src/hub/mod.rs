pub mod types;

use crate::core::address::Address;
use crate::hub::types::{AppCategory, AppRecord, HubError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// / M5: anti-sybil minimum app kayıt ücreti (BNS `base_cost` ile uyumlu).
/// Executor, `HubRegisterApp` tx'lerinde bu tutarı `tx.amount` üzerinden ZORUNLU
/// Tutar ve tam olarak bu kadarını düşer (H1 "exact cost" deseniyle simetrik).
pub const HUB_REGISTER_MIN_FEE: u64 = 100;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HubRegistry {
    /// App_id -> record
    pub apps: BTreeMap<u64, AppRecord>,
    pub next_app_id: u64,
    /// Authorized governors who can mark apps as governance-verified.
    /// Empty set = devnet mode (any caller accepted). Production must populate
    /// Via governance action (e.g. GovernanceAction::AddHubGovernor).
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
    /// This does **not** set `verified` (DAO/governance badge).
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
    /// Exists — and it still only sets developer_attested via verify_app.
    /// Explicit governance action should call `mark_verified_by_governance`.
    ///
    /// Require an explicit caller identity for governance
    /// Verification. Without this, any code path that reaches this function
    /// Can set `verified = true` without authorization. The caller parameter
    /// Is checked against an optional `authorized_governors` set; if the set
    /// Is empty (devnet), any caller is accepted (matching current behavior).
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
    pub fn is_empty(&self) -> bool {
        self.apps.is_empty() && self.authorized_governors.is_empty() && self.next_app_id == 0
    }

    pub fn root(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_HUB_REGISTRY_V2");
        hasher.update(self.next_app_id.to_le_bytes());
        for (id, app) in &self.apps {
            hasher.update(id.to_le_bytes());
            hasher.update(app.developer.0);
            hasher.update(app.name.as_bytes());
            hasher.update([app.developer_attested as u8, app.verified as u8]);
            let category_tag = match app.category.clone() {
                AppCategory::SocialFi => 0u8,
                AppCategory::DeFi => 1u8,
                AppCategory::Storage => 2u8,
                AppCategory::Gaming => 3u8,
                AppCategory::Infrastructure => 4u8,
                AppCategory::Other => 5u8,
            };
            hasher.update([category_tag]);
            hasher.update(app.website_url.as_bytes());
            match app.manifest_id {
                Some(manifest_id) => {
                    hasher.update([1u8]);
                    hasher.update(manifest_id.0);
                }
                None => hasher.update([0u8]),
            }
            hasher.update(app.registered_at_epoch.to_le_bytes());
        }
        let mut governors: Vec<_> = self.authorized_governors.iter().copied().collect();
        governors.sort();
        for governor in governors {
            hasher.update(governor.0);
        }
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::Address;
    use crate::storage::content_id::ContentId;

    #[test]
    fn register_and_attest_flow() {
        let mut reg = HubRegistry::new();
        let dev = Address::from([1u8; 32]);
        let id = reg.register_app(
            "TestApp".into(),
            dev,
            AppCategory::SocialFi,
            "https://example.bud".into(),
            Some(ContentId([2u8; 32])),
            1,
        );
        assert_eq!(id, 0);
        assert!(!reg.apps[&id].developer_attested);
        assert!(!reg.apps[&id].verified);
        assert!(reg.attest_app_as_developer(id, &dev).is_ok());
        assert!(reg.apps[&id].developer_attested);
        let other = Address::from([9u8; 32]);
        assert!(matches!(
            reg.attest_app_as_developer(id, &other),
            Err(HubError::NotDeveloper)
        ));
        // Authorized_governors is empty → anyone can verify.
        // Add a different governor so dev is NOT authorized.
        let gov = Address::from([7u8; 32]);
        reg.authorized_governors.insert(gov);
        assert!(matches!(
            reg.mark_verified_by_governance(id, &dev),
            Err(HubError::NotAuthorized)
        ));
        assert!(!reg.apps[&id].verified);
        assert!(matches!(
            reg.update_app(id, &other, Some("x".into()), None),
            Err(HubError::NotDeveloper)
        ));
        assert_eq!(reg.list_apps().len(), 1);
    }

    #[test]
    fn governance_verify_requires_authorized_governor() {
        let mut reg = HubRegistry::new();
        let dev = Address::from([1u8; 32]);
        let gov = Address::from([5u8; 32]);
        let id = reg.register_app("G".into(), dev, AppCategory::Other, "u".into(), None, 1);
        reg.authorized_governors.insert(gov);
        assert!(reg.mark_verified_by_governance(id, &gov).is_ok());
        assert!(reg.apps[&id].verified);
        assert!(matches!(
            reg.mark_verified_by_governance(id, &dev),
            Err(HubError::NotAuthorized)
        ));
    }

    #[test]
    fn update_by_developer_succeeds() {
        let mut reg = HubRegistry::new();
        let dev = Address::from([1u8; 32]);
        let id = reg.register_app("U".into(), dev, AppCategory::DeFi, "u".into(), None, 1);
        assert!(reg
            .update_app(id, &dev, Some("new".into()), Some(ContentId([3u8; 32])))
            .is_ok());
        assert_eq!(reg.apps[&id].website_url, "new");
        assert_eq!(reg.apps[&id].manifest_id, Some(ContentId([3u8; 32])));
    }

    #[test]
    fn root_changes_when_mutable_metadata_changes() {
        let mut reg = HubRegistry::new();
        let dev = Address::from([1u8; 32]);
        let id = reg.register_app(
            "Rooted".into(),
            dev,
            AppCategory::Infrastructure,
            "https://old.example".into(),
            None,
            1,
        );
        let root_before = reg.root();
        reg.update_app(
            id,
            &dev,
            Some("https://new.example".into()),
            Some(ContentId([4u8; 32])),
        )
        .unwrap();
        assert_ne!(root_before, reg.root());
    }

    #[test]
    fn root_changes_when_governor_set_changes() {
        let mut reg = HubRegistry::new();
        let root_before = reg.root();
        reg.authorized_governors.insert(Address::from([8u8; 32]));
        assert_ne!(root_before, reg.root());
    }
}
