use crate::bns::types::{BnsError, BnsResolved, NameRecord};
use crate::core::address::Address;
use crate::storage::content_id::ContentId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Genesis-seeded set of primary `.bud` name sellers.
///
/// Only addresses in `BnsRegistry::primary_sellers` (loaded at genesis from
/// `GenesisConfig::bns_primary_sellers`, which defaults to this slice, and
/// updated exclusively via `GovernanceAction::BnsSetPrimarySellers`) may open
/// `OfferKind::Primary` listings on the marketplace.
pub const BNS_PRIMARY_SELLERS: &[Address] = &[Address([0xB2; 32])];

/// Maximum number of primary seller addresses governance or genesis may configure.
const MAX_PRIMARY_SELLERS: usize = 64;

fn default_primary_sellers() -> BTreeSet<Address> {
    BNS_PRIMARY_SELLERS.iter().copied().collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsRegistry {
    pub names: BTreeMap<String, NameRecord>,
    pub base_cost: u64,
    #[serde(default = "default_primary_sellers")]
    pub primary_sellers: BTreeSet<Address>,
}

impl Default for BnsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BnsRegistry {
    /// F14: the renewal window, in epochs, that the previous owner keeps after
    /// a name expires. During that window no third party can register the name,
    /// which protects against squatting and front-running. It is roughly a
    /// 30-day window, at about 100 epochs per day.
    pub const GRACE_PERIOD: u64 = 3000;

    /// Maximum number of BNS names in the registry.
    /// At 100K names with subdomains, this bounds state growth to ~50MB.
    pub const MAX_NAMES: usize = 100_000;

    /// Maximum subdomains per name.
    pub const MAX_SUBDOMAINS_PER_NAME: usize = 1_000;

    /// Required top-level suffix for every registrable BNS name.
    const SUFFIX: &'static str = ".bud";

    /// One label: lowercase ASCII letters, digits and hyphens, not empty, no
    /// hyphen at either edge. The same table the browser name rule applies, so
    /// the registry cannot sell a name the rest of the stack refuses or one
    /// that differs from another only by case or by a look-alike letter.
    #[must_use]
    pub fn is_valid_label(label: &str) -> bool {
        !label.is_empty()
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    }

    /// Extracts `<label>` from `<label>.bud` when `<label>` is a single valid
    /// label of 3..=32 characters (counted excluding `.bud`).
    fn bud_label(name: &str) -> Option<&str> {
        let label = name.strip_suffix(Self::SUFFIX)?;
        let char_count = label.chars().count();
        if !(3..=32).contains(&char_count) || !Self::is_valid_label(label) {
            return None;
        }
        Some(label)
    }

    /// A registrable BNS name: exactly one valid 3..=32 character label
    /// followed by `.bud` (e.g. `ayaz.bud`).
    #[must_use]
    pub fn is_valid_name(name: &str) -> bool {
        Self::bud_label(name).is_some()
    }

    pub fn new() -> Self {
        Self {
            names: BTreeMap::new(),
            base_cost: 100,
            primary_sellers: default_primary_sellers(),
        }
    }

    /// Whether `seller` is authorized to open `OfferKind::Primary` listings.
    #[must_use]
    pub fn is_primary_seller(&self, seller: &Address) -> bool {
        self.primary_sellers.contains(seller)
    }

    /// Replace the primary-seller set. Called at genesis construction and from
    /// `GovernanceAction::BnsSetPrimarySellers`.
    ///
    /// # Errors
    ///
    /// Refuses the zero address or sets exceeding `MAX_PRIMARY_SELLERS`.
    pub fn set_primary_sellers(
        &mut self,
        sellers: impl IntoIterator<Item = Address>,
    ) -> Result<(), String> {
        let mut next = BTreeSet::new();
        for addr in sellers {
            if addr == Address::zero() {
                return Err("BNS primary seller cannot be the zero address".into());
            }
            next.insert(addr);
            if next.len() > MAX_PRIMARY_SELLERS {
                return Err(format!(
                    "BNS primary sellers exceed maximum count ({MAX_PRIMARY_SELLERS})"
                ));
            }
        }
        self.primary_sellers = next;
        Ok(())
    }

    /// Whether `name` is eligible for a `Primary` marketplace listing at
    /// `current_epoch`: valid `<label>.bud` and either unregistered or past its
    /// post-expiry grace window.
    #[must_use]
    pub fn is_available_for_primary(&self, name: &str, current_epoch: u64) -> bool {
        if !Self::is_valid_name(name) {
            return false;
        }
        match self.names.get(name) {
            None => true,
            Some(record) => current_epoch >= record.expires_at.saturating_add(Self::GRACE_PERIOD),
        }
    }

    /// Whether `name` is currently live (not expired) and owned by `owner`.
    #[must_use]
    pub fn is_live_owned_by(&self, name: &str, owner: &Address, current_epoch: u64) -> bool {
        matches!(
            self.names.get(name),
            Some(record) if current_epoch < record.expires_at && &record.owner == owner
        )
    }

    pub fn calculate_cost(&self, name: &str, duration: u64) -> u64 {
        let label = name.strip_suffix(Self::SUFFIX).unwrap_or(name);
        let char_count = label.chars().count();
        let multiplier: u64 = match char_count {
            1..=3 => 100,
            4..=6 => 10,
            _ => 1,
        };
        self.base_cost
            .saturating_mul(multiplier)
            .saturating_mul(duration)
    }

    /// PARTIAL: allowed - the removal is an eviction that has already
    /// succeeded when the refusal below fires. The `Err` is the branch where
    /// nothing was evicted: no expired name existed, so the registry is at
    /// capacity and nothing was taken out. The two are exclusive.
    ///
    /// Called exclusively from the consensus executor (`BnsBuyName` primary
    /// settlement) and crate-internal tests.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub(crate) fn register(
        &mut self,
        name: String,
        owner: Address,
        current_epoch: u64,
        duration: u64,
    ) -> Result<(), BnsError> {
        if !Self::is_valid_name(&name) {
            return Err(BnsError::InvalidName);
        }
        // Duration must be > 0. Zero-duration registration
        // Would expire immediately (current_epoch + 0), creating a useless
        // Record that wastes state space and could be used for name squatting.
        if duration == 0 {
            return Err(BnsError::InvalidName);
        }
        if let Some(record) = self.names.get(&name) {
            if record.expires_at > current_epoch {
                return Err(BnsError::NameTaken);
            }
            // F14: the grace period. An expired name still grants its previous
            // owner a renewal window. While
            // `current_epoch < expires_at + GRACE_PERIOD` holds, only the
            // previous owner can register or renew, which blocks front-running
            // squatters from seizing an expired name.
            let grace_until = record.expires_at.saturating_add(Self::GRACE_PERIOD);
            if current_epoch < grace_until && record.owner != owner {
                return Err(BnsError::NameTaken);
            }
        }
        // Cap total name count - fail-closed.
        // Reuse slots from expired names first; only reject if truly at capacity.
        if self.names.len() >= Self::MAX_NAMES && !self.names.contains_key(&name) {
            // Try to evict the oldest expired name to make room
            let expired_key = self
                .names
                .iter()
                .find(|(_, r)| r.expires_at.saturating_add(Self::GRACE_PERIOD) < current_epoch)
                .map(|(k, _)| k.clone());
            if let Some(key) = expired_key {
                self.names.remove(&key);
            } else {
                return Err(BnsError::NameTaken); // at capacity, no evictable names
            }
        }
        let expires_at = current_epoch
            .checked_add(duration)
            .ok_or(BnsError::InvalidName)?;
        let record = NameRecord::try_new(name.clone(), owner, current_epoch, expires_at)?;
        self.names.insert(name, record);
        Ok(())
    }

    /// Renew an existing name registration. Only the current owner may renew
    /// while the record is still live (not expired). The new expiry extends
    /// from the current expiry - never from `current_epoch` - so renewing early
    /// never shortens the registration. The transaction door charges the same
    /// duration-based cost as registration, while this method owns the
    /// lifecycle rule itself.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn renew(
        &mut self,
        name: &str,
        caller: &Address,
        current_epoch: u64,
        duration: u64,
    ) -> Result<(), BnsError> {
        if duration == 0 {
            return Err(BnsError::InvalidName);
        }
        let record = self.names.get_mut(name).ok_or(BnsError::InvalidName)?;
        if &record.owner != caller {
            return Err(BnsError::NotOwner);
        }
        if record.expires_at <= current_epoch {
            return Err(BnsError::Expired);
        }
        record.expires_at = record
            .expires_at
            .checked_add(duration)
            .ok_or(BnsError::InvalidName)?;
        Ok(())
    }

    /// Transfer ownership of a live (non-expired) name to a new owner. Only
    /// The current owner may transfer. The pointers the previous owner set
    /// (resolver, address, storage, content and subdomains) are cleared and the
    /// address points at the new owner, so the name never resolves to the
    /// previous owner after the transfer.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn transfer(
        &mut self,
        name: &str,
        caller: &Address,
        new_owner: Address,
        current_epoch: u64,
    ) -> Result<(), BnsError> {
        if new_owner == Address::zero() {
            return Err(BnsError::InvalidName);
        }
        let record = self.names.get_mut(name).ok_or(BnsError::InvalidName)?;
        if &record.owner != caller {
            return Err(BnsError::NotOwner);
        }
        if record.expires_at <= current_epoch {
            return Err(BnsError::Expired);
        }
        record.owner = new_owner;
        record.resolver = None;
        record.address = Some(new_owner);
        record.consensus_domain_id = None;
        record.storage_root = None;
        record.storage_domain_id = None;
        record.storage_root_height = None;
        record.content_id = None;
        record.subdomains.clear();
        Ok(())
    }

    /// Performs the requested operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn register_subdomain(
        &mut self,
        parent_name: &str,
        sub_label: String,
        owner: Address,
        caller: &Address,
        current_epoch: u64,
    ) -> Result<(), BnsError> {
        if !Self::is_valid_label(&sub_label) {
            return Err(BnsError::InvalidName);
        }
        let parent = self
            .names
            .get_mut(parent_name)
            .ok_or(BnsError::InvalidName)?;
        if &parent.owner != caller {
            return Err(BnsError::NotOwner);
        }
        if parent.expires_at <= current_epoch {
            return Err(BnsError::Expired);
        }
        // Cap subdomains per name - fail-closed.
        if parent.subdomains.len() >= Self::MAX_SUBDOMAINS_PER_NAME {
            return Err(BnsError::InvalidName);
        }
        parent.subdomains.insert(sub_label, owner);
        Ok(())
    }

    pub fn resolve_subdomain(
        &self,
        parent_name: &str,
        sub_label: &str,
        current_epoch: u64,
    ) -> Option<Address> {
        let parent = self.names.get(parent_name)?;
        if parent.expires_at > current_epoch {
            parent.subdomains.get(sub_label).cloned()
        } else {
            None
        }
    }

    /// Performs the requested operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn set_content(
        &mut self,
        name: &str,
        owner: &Address,
        cid: ContentId,
        current_epoch: u64,
    ) -> Result<(), BnsError> {
        let record = self.names.get_mut(name).ok_or(BnsError::InvalidName)?;
        if &record.owner != owner {
            return Err(BnsError::NotOwner);
        }
        if record.expires_at <= current_epoch {
            return Err(BnsError::Expired);
        }
        record.content_id = Some(cid);
        Ok(())
    }

    pub fn resolve_content(&self, name: &str, current_epoch: u64) -> Option<ContentId> {
        self.names.get(name).and_then(|record| {
            if record.expires_at > current_epoch {
                record.content_id
            } else {
                None
            }
        })
    }

    pub fn resolve(&self, name: &str, current_epoch: u64) -> Option<Address> {
        self.names.get(name).and_then(|record| {
            if record.expires_at > current_epoch {
                Some(record.owner)
            } else {
                None
            }
        })
    }

    pub fn resolve_full(&self, name: &str, current_epoch: u64) -> Option<BnsResolved> {
        self.names.get(name).map(|record| {
            let expired = record.expires_at <= current_epoch;
            BnsResolved {
                name: record.name.clone(),
                owner: record.owner,
                address: if expired { None } else { record.address },
                storage_root: if expired { None } else { record.storage_root },
                storage_domain_id: if expired {
                    None
                } else {
                    record.storage_domain_id
                },
                content_id: if expired { None } else { record.content_id },
                is_expired: expired,
            }
        })
    }

    /// Performs the requested operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn set_storage(
        &mut self,
        name: &str,
        caller: Address,
        storage_root: [u8; 32],
        storage_domain_id: u32,
        current_epoch: u64,
    ) -> Result<(), BnsError> {
        let rec = self.names.get_mut(name).ok_or(BnsError::InvalidName)?;
        if rec.owner != caller {
            return Err(BnsError::NotOwner);
        }
        if rec.expires_at <= current_epoch {
            return Err(BnsError::Expired);
        }
        rec.storage_root = Some(storage_root);
        rec.storage_domain_id = Some(storage_domain_id);
        rec.storage_root_height = Some(current_epoch);
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
            && self.base_cost == 100
            && self.primary_sellers == default_primary_sellers()
    }

    pub fn root(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        // V2: every variable-length part carries its length and every
        // collection its count. V1 wrote names and subdomain labels back to
        // back, so two registries with different name boundaries could
        // share a root.
        //
        // Migration policy (shared by all four V-bumped registry roots,
        // BNS V2 / liveness V3 / invalid-vote V2 / NFT V6): the new tags
        // activate with the USL genesis. Mainnet has no committed state
        // before that genesis (launch timestamp is still TBD), so there is
        // no old-format root in existence to carry over, and no activation
        // height or compatibility path is needed. Devnet and testnet state
        // is disposable and resets with its genesis; a node that still
        // holds pre-USL devnet data must resync from the new genesis
        // instead of migrating. Any future tag bump after launch needs a
        // recorded migration (activation height or state rewrite) in the
        // same commit as the bump.
        hasher.update(b"BDLM_BNS_REGISTRY_V2");
        hasher.update(self.base_cost.to_le_bytes());
        if self.primary_sellers != default_primary_sellers() {
            hasher.update(b"primary_sellers");
            hasher.update((self.primary_sellers.len() as u64).to_le_bytes());
            for seller in &self.primary_sellers {
                hasher.update(seller.0);
            }
        }
        hasher.update((self.names.len() as u64).to_le_bytes());
        for (name, record) in &self.names {
            hasher.update((name.len() as u64).to_le_bytes());
            hasher.update(name.as_bytes());
            hasher.update(record.owner.0);
            hasher.update(record.expires_at.to_le_bytes());
            match record.resolver {
                Some(resolver) => {
                    hasher.update([1u8]);
                    hasher.update(resolver.0);
                }
                None => hasher.update([0u8]),
            }
            match record.address {
                Some(address) => {
                    hasher.update([1u8]);
                    hasher.update(address.0);
                }
                None => hasher.update([0u8]),
            }
            match record.consensus_domain_id {
                Some(domain_id) => {
                    hasher.update([1u8]);
                    hasher.update(domain_id.to_le_bytes());
                }
                None => hasher.update([0u8]),
            }
            match record.storage_root {
                Some(storage_root) => {
                    hasher.update([1u8]);
                    hasher.update(storage_root);
                }
                None => hasher.update([0u8]),
            }
            match record.storage_domain_id {
                Some(domain_id) => {
                    hasher.update([1u8]);
                    hasher.update(domain_id.to_le_bytes());
                }
                None => hasher.update([0u8]),
            }
            match record.storage_root_height {
                Some(height) => {
                    hasher.update([1u8]);
                    hasher.update(height.to_le_bytes());
                }
                None => hasher.update([0u8]),
            }
            match record.content_id {
                Some(content_id) => {
                    hasher.update([1u8]);
                    hasher.update(content_id.0);
                }
                None => hasher.update([0u8]),
            }
            hasher.update((record.subdomains.len() as u64).to_le_bytes());
            for (sub_label, sub_owner) in &record.subdomains {
                hasher.update((sub_label.len() as u64).to_le_bytes());
                hasher.update(sub_label.as_bytes());
                hasher.update(sub_owner.0);
            }
        }
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Case and look-alike variants, separators and control
    /// characters are not registrable names.
    #[test]
    fn names_follow_the_lowercase_label_rule() {
        let mut reg = BnsRegistry::new();
        let owner = Address::from([1u8; 32]);
        for bad in [
            "Alice.bud",
            "al\u{0456}ce.bud",
            "ali/ce.bud",
            "..bud",
            "a..bud",
            ".alice",
            "alice.",
            "-alice.bud",
            "alice-.bud",
            "al ice.bud",
            "al\u{0007}ice.bud",
        ] {
            assert!(
                reg.register(bad.to_string(), owner, 1, 10).is_err(),
                "{bad:?} must be refused"
            );
        }
        reg.register("alice-1.bud".into(), owner, 1, 10).unwrap();
        assert!(reg
            .register_subdomain("alice-1.bud", "App".into(), owner, &owner, 1)
            .is_err());
        assert!(reg
            .register_subdomain("alice-1.bud", "a.b".into(), owner, &owner, 1)
            .is_err());
        reg.register_subdomain("alice-1.bud", "app".into(), owner, &owner, 1)
            .unwrap();
    }

    /// An expired record resolves with the flag set and its bindings
    /// cleared, so the expired branches of the gateway are reachable.
    #[test]
    fn an_expired_name_resolves_as_expired() {
        let mut reg = BnsRegistry::new();
        let owner = Address::from([1u8; 32]);
        reg.register("alice.bud".into(), owner, 1, 10).unwrap();
        let live = reg.resolve_full("alice.bud", 5).unwrap();
        assert!(!live.is_expired);
        let gone = reg.resolve_full("alice.bud", 50).unwrap();
        assert!(gone.is_expired);
        assert!(gone.content_id.is_none() && gone.address.is_none());
    }

    #[test]
    fn root_changes_when_record_mutates() {
        let mut reg = BnsRegistry::new();
        let owner = Address::from([1u8; 32]);
        reg.register("alice.bud".into(), owner, 1, 10).unwrap();
        let root_before = reg.root();
        reg.set_content("alice.bud", &owner, ContentId([0x55; 32]), 1)
            .unwrap();
        assert_ne!(root_before, reg.root());
    }

    /// The root is injective over name and label boundaries: two records
    /// whose subdomain labels concatenate to the same bytes, and two
    /// registries whose names differ only in where one ends and the next
    /// begins, hash differently.
    #[test]
    fn root_distinguishes_label_boundaries() {
        let owner = Address::from([1u8; 32]);
        let sub_owner = Address::from([2u8; 32]);

        let mut a = BnsRegistry::new();
        a.register("alice.bud".into(), owner, 1, 10).unwrap();
        a.register_subdomain("alice.bud", "ab".into(), sub_owner, &owner, 1)
            .unwrap();
        let mut b = BnsRegistry::new();
        b.register("alice.bud".into(), owner, 1, 10).unwrap();
        b.register_subdomain("alice.bud", "a".into(), sub_owner, &owner, 1)
            .unwrap();
        b.register_subdomain("alice.bud", "b".into(), sub_owner, &owner, 1)
            .unwrap();
        assert_ne!(
            a.root(),
            b.root(),
            "one label `ab` is not two labels `a`, `b`"
        );

        let mut c = BnsRegistry::new();
        c.register("alice.bud".into(), owner, 1, 10).unwrap();
        let mut d = BnsRegistry::new();
        d.register("alice.bud".into(), owner, 1, 10).unwrap();
        d.register("bob.bud".into(), owner, 1, 10).unwrap();
        assert_ne!(c.root(), d.root(), "the name count is committed");
    }

    #[test]
    fn bns_default_matches_new_base_cost_and_root() {
        let from_default = BnsRegistry::default();
        let from_new = BnsRegistry::new();
        assert_eq!(from_default.base_cost, 100);
        assert_eq!(from_default.base_cost, from_new.base_cost);
        assert_eq!(from_default.root(), from_new.root());
    }

    #[test]
    fn bns_resolves_bud3_content() {
        let owner = Address::from([0x31; 32]);
        let stranger = Address::from([0x32; 32]);
        let bud3_cid = crate::storage::bud3::content_id::ContentId::public(b"site-index-html");
        let cid = ContentId(bud3_cid.digest);

        let mut reg = BnsRegistry::new();
        reg.register("portal.bud".into(), owner, 1, 10).unwrap();
        assert_eq!(
            reg.set_content("portal.bud", &stranger, cid, 2),
            Err(BnsError::NotOwner)
        );
        reg.set_content("portal.bud", &owner, cid, 2).unwrap();
        assert_eq!(reg.resolve_content("portal.bud", 5), Some(cid));
        assert_eq!(reg.resolve_content("portal.bud", 11), None);
    }

    #[test]
    fn bud_suffix_and_label_bounds_are_enforced_and_tiered_on_label_length() {
        let mut reg = BnsRegistry::new();
        let owner = Address::from([0x41; 32]);

        // Acceptance criteria: `bids` refused, `bids.bud` accepted, `ab.bud` refused.
        assert_eq!(
            reg.register("bids".into(), owner, 1, 10),
            Err(BnsError::InvalidName)
        );
        assert_eq!(
            reg.register("ab.bud".into(), owner, 1, 10),
            Err(BnsError::InvalidName)
        );
        assert_eq!(
            reg.register("sub.bids.bud".into(), owner, 1, 10),
            Err(BnsError::InvalidName)
        );
        assert_eq!(
            reg.register("bids.eth".into(), owner, 1, 10),
            Err(BnsError::InvalidName)
        );
        reg.register("bids.bud".into(), owner, 1, 10).unwrap();

        // Label length excludes `.bud`: 32-char label (36 total chars) passes; 33-char label fails.
        let max_label = format!("{}.bud", "a".repeat(32));
        let too_long_label = format!("{}.bud", "a".repeat(33));
        reg.register(max_label, owner, 1, 10).unwrap();
        assert_eq!(
            reg.register(too_long_label, owner, 1, 10),
            Err(BnsError::InvalidName)
        );

        // 3-character label pays 100x the standard (7+ char label) cost.
        let three_char = reg.calculate_cost("abc.bud", 10);
        let four_char = reg.calculate_cost("bids.bud", 10);
        let long_char = reg.calculate_cost("abcdefgh.bud", 10);
        assert_eq!(three_char, reg.base_cost * 100 * 10);
        assert_eq!(four_char, reg.base_cost * 10 * 10);
        assert_eq!(long_char, reg.base_cost * 10);
        assert_eq!(three_char, long_char * 100);
    }
}
