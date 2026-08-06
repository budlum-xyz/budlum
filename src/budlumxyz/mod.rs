pub mod types;

use crate::budlumxyz::types::{AppCategory, AppRecord, BudlumxyzError};
use crate::core::address::Address;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// / M5: anti-sybil minimum app kayıt ücreti (BNS `base_cost` ile uyumlu).
/// Executor, `BudlumxyzRegisterApp` tx'lerinde bu tutarı `tx.amount` üzerinden ZORUNLU
/// Tutar ve tam olarak bu kadarını düşer (H1 "exact cost" deseniyle simetrik).
pub const BUDLUMXYZ_REGISTER_MIN_FEE: u64 = 100;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BudlumxyzRegistry {
    /// App_id -> record
    pub apps: BTreeMap<u64, AppRecord>,
    pub next_app_id: u64,
    /// Authorized governors who can mark apps as governance-verified.
    ///
    /// Empty set = any caller accepted. `GovernanceAction::AddBudlumxyzGovernor`
    /// Does not exist - see [`BudlumxyzRegistry::mark_verified_by_governance`]
    /// For why that is currently harmless and what has to change before it
    /// Stops being harmless.
    #[serde(default)]
    pub authorized_governors: std::collections::HashSet<Address>,
}

impl BudlumxyzRegistry {
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
    ) -> Result<u64, BudlumxyzError> {
        let id = self.next_app_id;
        // The same shape as `NftRegistry::mint`: `insert` overwrites, and the
        // record it would overwrite belongs to a different developer. That
        // developer's app disappears from `apps` while `next_app_id` moves
        // on, so the id now resolves to somebody else's listing.
        //
        // `next_app_id` only increments, so this cannot happen within one
        // run. `BudlumxyzRegistry` is restored wholesale from
        // `StateSnapshotV2`, where `apps` and `next_app_id` are separate
        // fields, and a snapshot whose counter sits below its highest live id
        // produces exactly this.
        if self.apps.contains_key(&id) {
            return Err(BudlumxyzError::DuplicateAppId);
        }
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
        Ok(id)
    }

    pub fn update_app(
        &mut self,
        id: u64,
        caller: &Address,
        new_url: Option<String>,
        new_manifest: Option<crate::storage::content_id::ContentId>,
    ) -> Result<(), BudlumxyzError> {
        let app = self.apps.get_mut(&id).ok_or(BudlumxyzError::NotFound)?;
        if &app.developer != caller {
            return Err(BudlumxyzError::NotDeveloper);
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
    pub fn attest_app_as_developer(
        &mut self,
        id: u64,
        caller: &Address,
    ) -> Result<(), BudlumxyzError> {
        let app = self.apps.get_mut(&id).ok_or(BudlumxyzError::NotFound)?;
        if &app.developer != caller {
            return Err(BudlumxyzError::NotDeveloper);
        }
        app.developer_attested = true;
        Ok(())
    }

    /// Back-compat alias: self-verify == developer attestation only.
    pub fn verify_app(&mut self, id: u64, caller: &Address) -> Result<(), BudlumxyzError> {
        self.attest_app_as_developer(id, caller)
    }

    /// DAO/governance verification path (sets trusted `verified` badge).
    /// Currently restricted: only the developer can call until authorized_verifiers
    /// Exists - and it still only sets developer_attested via verify_app.
    /// Explicit governance action should call `mark_verified_by_governance`.
    ///
    /// Require an explicit caller identity for governance
    /// Verification. Without this, any code path that reaches this function
    /// Can set `verified = true` without authorization. The caller parameter
    /// Is checked against an optional `authorized_governors` set; if the set
    /// Is empty (devnet), any caller is accepted (matching current behavior).
    ///
    /// # The governance action this refers to does not exist yet
    ///
    /// The doc on [`BudlumxyzRegistry::authorized_governors`] names
    /// `GovernanceAction::AddBudlumxyzGovernor`. There is no such variant:
    /// `GovernanceAction` has `WhitelistVerifier`, `DewhitelistVerifier`,
    /// `SetEncryptionPolicy`, `SetConstitutionParameter` and
    /// `UnfreezeConsensusDomain`, and nothing else. The only writers of
    /// `authorized_governors` are tests.
    ///
    /// So on any real network the set is empty, `is_empty()` short-circuits
    /// The check, and every caller passes. That is fail-open on an
    /// Authorization gate.
    ///
    /// It is not exploitable today, and that is the only reason this is a
    /// Comment rather than a fix: nothing in production calls this function.
    /// The single caller is `src/tests/hardening_h2_locks.rs`. The moment a
    /// Transaction type or an RPC method reaches it, the empty set becomes a
    /// Live authorization bypass.
    ///
    /// Whoever wires that call path must land the governance action in the
    /// Same change, and flip this from "empty means everyone" to "empty means
    /// No one" - a permission check that defaults to allow is the wrong shape
    /// Regardless of how the set gets populated.
    pub fn mark_verified_by_governance(
        &mut self,
        id: u64,
        caller: &Address,
    ) -> Result<(), BudlumxyzError> {
        if !self.authorized_governors.is_empty() && !self.authorized_governors.contains(caller) {
            return Err(BudlumxyzError::NotAuthorized);
        }
        let app = self.apps.get_mut(&id).ok_or(BudlumxyzError::NotFound)?;
        app.verified = true;
        Ok(())
    }

    /// Award the badge on the authority of a passed governance proposal.
    ///
    /// Separate entry point from [`Self::mark_verified_by_governance`],
    /// which takes a caller and checks it against `authorized_governors`.
    /// There is no caller here: the authority is the vote itself, already
    /// counted, already delayed by the activation window, and already
    /// recorded as a `Proposal` in the state root. Reusing the caller-checked
    /// path would mean inventing an address to satisfy a check that a passed
    /// proposal has no way to fail.
    ///
    /// # Errors
    ///
    /// [`BudlumxyzError::NotFound`] if the proposal names an app that does
    /// not exist. Checked at execution rather than at submission, because an
    /// app can be registered while the vote is open.
    pub fn mark_verified_by_proposal(&mut self, id: u64) -> Result<(), BudlumxyzError> {
        let app = self.apps.get_mut(&id).ok_or(BudlumxyzError::NotFound)?;
        app.verified = true;
        Ok(())
    }

    pub fn list_apps(&self) -> Vec<AppRecord> {
        self.apps.values().cloned().collect()
    }
}

impl BudlumxyzRegistry {
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
        let mut reg = BudlumxyzRegistry::new();
        let dev = Address::from([1u8; 32]);
        let id = reg
            .register_app(
                "TestApp".into(),
                dev,
                AppCategory::SocialFi,
                "https://example.bud".into(),
                Some(ContentId([2u8; 32])),
                1,
            )
            .expect("a fresh registry has no id to collide with");
        assert_eq!(id, 0);
        assert!(!reg.apps[&id].developer_attested);
        assert!(!reg.apps[&id].verified);
        assert!(reg.attest_app_as_developer(id, &dev).is_ok());
        assert!(reg.apps[&id].developer_attested);
        let other = Address::from([9u8; 32]);
        assert!(matches!(
            reg.attest_app_as_developer(id, &other),
            Err(BudlumxyzError::NotDeveloper)
        ));
        // Authorized_governors is empty → anyone can verify.
        // Add a different governor so dev is NOT authorized.
        let gov = Address::from([7u8; 32]);
        reg.authorized_governors.insert(gov);
        assert!(matches!(
            reg.mark_verified_by_governance(id, &dev),
            Err(BudlumxyzError::NotAuthorized)
        ));
        assert!(!reg.apps[&id].verified);
        assert!(matches!(
            reg.update_app(id, &other, Some("x".into()), None),
            Err(BudlumxyzError::NotDeveloper)
        ));
        assert_eq!(reg.list_apps().len(), 1);
    }

    /// The two badges must stay two badges.
    ///
    /// `developer_attested` says "the address that registered this record
    /// claims it", which costs a signature the registrant already had.
    /// `verified` says "a vote examined it". Collapsing them would let any
    /// developer mint the badge that is supposed to mean somebody else
    /// looked, which is the failure this split exists to prevent.
    ///
    /// Both bits are hashed into the registry state root, so a path that
    /// sets one must not quietly set the other.
    #[test]
    fn self_attestation_does_not_award_the_governance_badge() {
        let mut reg = BudlumxyzRegistry::new();
        let dev = Address::from([1u8; 32]);
        let id = reg
            .register_app(
                "App".into(),
                dev,
                AppCategory::DeFi,
                "https://example.bud".into(),
                None,
                1,
            )
            .expect("a fresh registry has no id to collide with");

        reg.attest_app_as_developer(id, &dev)
            .expect("the registrant is the developer");
        assert!(reg.apps[&id].developer_attested);
        assert!(
            !reg.apps[&id].verified,
            "self-attestation must not reach the badge that means a vote \
             examined the record"
        );

        // The proposal path is the only writer of `verified`, and it takes
        // no caller: the authority is the counted vote, not an address.
        reg.mark_verified_by_proposal(id)
            .expect("the app exists, so the proposal names something real");
        assert!(reg.apps[&id].verified);
        assert!(
            reg.apps[&id].developer_attested,
            "governance verification must not clear the developer's own claim"
        );
    }

    /// A proposal naming an app that does not exist must fail, not create one.
    ///
    /// The vote can be opened against any id, and nothing stops an id from
    /// being wrong or from an app being removed while the vote runs. Silent
    /// insertion here would let governance conjure a verified record that no
    /// developer ever registered.
    #[test]
    fn a_proposal_for_a_missing_app_is_refused() {
        let mut reg = BudlumxyzRegistry::new();
        assert!(matches!(
            reg.mark_verified_by_proposal(404),
            Err(BudlumxyzError::NotFound)
        ));
        assert!(
            reg.list_apps().is_empty(),
            "a refused proposal must not leave a record behind"
        );
    }

    #[test]
    fn governance_verify_requires_authorized_governor() {
        let mut reg = BudlumxyzRegistry::new();
        let dev = Address::from([1u8; 32]);
        let gov = Address::from([5u8; 32]);
        let id = reg
            .register_app("G".into(), dev, AppCategory::Other, "u".into(), None, 1)
            .expect("a fresh registry has no id to collide with");
        reg.authorized_governors.insert(gov);
        assert!(reg.mark_verified_by_governance(id, &gov).is_ok());
        assert!(reg.apps[&id].verified);
        assert!(matches!(
            reg.mark_verified_by_governance(id, &dev),
            Err(BudlumxyzError::NotAuthorized)
        ));
    }

    #[test]
    fn update_by_developer_succeeds() {
        let mut reg = BudlumxyzRegistry::new();
        let dev = Address::from([1u8; 32]);
        let id = reg
            .register_app("U".into(), dev, AppCategory::DeFi, "u".into(), None, 1)
            .expect("a fresh registry has no id to collide with");
        assert!(reg
            .update_app(id, &dev, Some("new".into()), Some(ContentId([3u8; 32])))
            .is_ok());
        assert_eq!(reg.apps[&id].website_url, "new");
        assert_eq!(reg.apps[&id].manifest_id, Some(ContentId([3u8; 32])));
    }

    #[test]
    fn root_changes_when_mutable_metadata_changes() {
        let mut reg = BudlumxyzRegistry::new();
        let dev = Address::from([1u8; 32]);
        let id = reg
            .register_app(
                "Rooted".into(),
                dev,
                AppCategory::Infrastructure,
                "https://old.example".into(),
                None,
                1,
            )
            .expect("a fresh registry has no id to collide with");
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
        let mut reg = BudlumxyzRegistry::new();
        let root_before = reg.root();
        reg.authorized_governors.insert(Address::from([8u8; 32]));
        assert_ne!(root_before, reg.root());
    }

    /// `mark_verified_by_governance` fails open, and must stay unreachable
    /// Until it does not.
    ///
    /// The authorization check is `if !set.is_empty() && !set.contains(caller)`,
    /// so an empty set accepts everyone. The doc says production populates the
    /// Set "via governance action (e.g. `GovernanceAction::AddBudlumxyzGovernor`)".
    /// That variant does not exist, so on every real network the set is empty
    /// And the gate is open.
    ///
    /// Harmless today for exactly one reason: nothing in production calls the
    /// Function. This test pins that reason. If a transaction type, an RPC
    /// Method or a chain command starts calling it, this fails and whoever
    /// Wired it has to land the governance action, and invert the empty-set
    /// Default - in the same change.
    #[test]
    fn governance_verification_stays_unreachable_while_it_fails_open() {
        // The empty-set default really is permissive: an arbitrary caller
        // succeeds. This is the property that makes reachability matter.
        let mut reg = BudlumxyzRegistry::new();
        let id = reg
            .register_app(
                "app".into(),
                Address::from([1u8; 32]),
                AppCategory::Other,
                "https://example.invalid".into(),
                None,
                0,
            )
            .expect("a fresh registry has no id to collide with");
        assert!(reg.authorized_governors.is_empty());
        let stranger = Address::from([0xEE; 32]);
        reg.mark_verified_by_governance(id, &stranger)
            .expect("an empty governor set accepts any caller - that is the hazard");
        assert!(reg.apps[&id].verified);

        // And the named governance action still does not exist, so nothing can
        // populate the set on a real network.
        let governance_src = include_str!("../core/governance.rs");
        assert!(
            !governance_src.contains("AddBudlumxyzGovernor"),
            "the governance action now exists - populate the governor set and \
             invert the empty-set default from allow to deny"
        );
    }

    /// A counter that disagrees with the map must not overwrite a listing.
    ///
    /// The same defect as `NftRegistry::mint`, in a second registry: `insert`
    /// overwrites, and the record it replaces belongs to another developer.
    /// Their app disappears from `apps` while the id keeps resolving, now to
    /// somebody else's listing, with no transaction from the developer who
    /// lost it.
    ///
    /// Reachable through a restore: `apps` and `next_app_id` are separate
    /// fields of `StateSnapshotV2`, so a snapshot whose counter sits below
    /// its highest live id produces this on load.
    #[test]
    fn registering_onto_a_live_app_id_is_refused() {
        let mut reg = BudlumxyzRegistry::new();
        let first = Address::from([1u8; 32]);
        let second = Address::from([2u8; 32]);

        let id = reg
            .register_app(
                "First".into(),
                first,
                AppCategory::SocialFi,
                "https://first.bud".into(),
                None,
                1,
            )
            .expect("a fresh registry has no id to collide with");

        // The shape a restored snapshot can carry: counter behind contents.
        reg.next_app_id = id;

        let err = reg
            .register_app(
                "Second".into(),
                second,
                AppCategory::DeFi,
                "https://second.bud".into(),
                None,
                2,
            )
            .expect_err("registering onto a live id must be refused");
        assert!(
            matches!(err, BudlumxyzError::DuplicateAppId),
            "the refusal must name the collision, got: {err:?}"
        );

        // The first developer still owns the listing. Without the refusal,
        // `apps[&id]` would name `second` and `First` would be gone.
        let app = reg.apps.get(&id).expect("the original app must survive");
        assert_eq!(app.developer, first);
        assert_eq!(app.name, "First");
    }

    /// The refusal must stay narrow, or it is a ban on registering.
    #[test]
    fn consecutive_registrations_still_work() {
        let mut reg = BudlumxyzRegistry::new();
        let dev = Address::from([3u8; 32]);

        let a = reg
            .register_app("A".into(), dev, AppCategory::Other, "a".into(), None, 1)
            .expect("first registration");
        let b = reg
            .register_app("B".into(), dev, AppCategory::Other, "b".into(), None, 1)
            .expect("second registration");
        assert_ne!(a, b, "an incrementing counter must keep producing new ids");
    }
}
