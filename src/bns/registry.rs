use crate::bns::types::{BnsError, BnsResolved, NameRecord};
use crate::core::address::Address;
use crate::registry::params::{
    MAX_DURATION, MAX_NAMES_PER_OWNER, MAX_RECORDS_PER_NAME, MAX_RECORD_KEY_LEN,
    MAX_RECORD_VALUE_BYTES, MIN_DURATION, RESERVED_LABELS,
};
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

/// Maximum number of reserved labels genesis may configure.
const MAX_RESERVED_LABELS: usize = 512;

fn default_primary_sellers() -> BTreeSet<Address> {
    BNS_PRIMARY_SELLERS.iter().copied().collect()
}

fn default_reserved_labels() -> BTreeSet<String> {
    RESERVED_LABELS.iter().map(|s| (*s).to_string()).collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsRegistry {
    pub names: BTreeMap<String, NameRecord>,
    pub base_cost: u64,
    #[serde(default = "default_primary_sellers")]
    pub primary_sellers: BTreeSet<Address>,
    #[serde(default = "default_reserved_labels")]
    pub reserved_labels: BTreeSet<String>,
    #[serde(default)]
    pub primary_names: BTreeMap<Address, String>,
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
            reserved_labels: default_reserved_labels(),
            primary_names: BTreeMap::new(),
        }
    }

    /// Replace the reserved-label set (seeded at genesis).
    ///
    /// # Errors
    ///
    /// Refuses invalid labels or sets exceeding `MAX_RESERVED_LABELS`.
    pub fn set_reserved_labels(
        &mut self,
        labels: impl IntoIterator<Item = String>,
    ) -> Result<(), String> {
        let mut next = BTreeSet::new();
        for label in labels {
            let count = label.chars().count();
            if !(1..=32).contains(&count) || !Self::is_valid_label(&label) {
                return Err(format!("Invalid BNS reserved label `{label}`"));
            }
            next.insert(label);
            if next.len() > MAX_RESERVED_LABELS {
                return Err(format!(
                    "BNS reserved labels exceed maximum count ({MAX_RESERVED_LABELS})"
                ));
            }
        }
        self.reserved_labels = next;
        Ok(())
    }

    /// Whether `<label>.bud` (or bare `<label>`) is in the reserved-label list.
    #[must_use]
    pub fn is_reserved_name(&self, name: &str) -> bool {
        let label = name.strip_suffix(Self::SUFFIX).unwrap_or(name);
        self.reserved_labels.contains(label)
    }

    /// Count of live or grace-period names currently held by `owner`.
    #[must_use]
    pub fn active_name_count_for_owner(&self, owner: &Address, current_epoch: u64) -> usize {
        self.names
            .values()
            .filter(|r| {
                &r.owner == owner && current_epoch < r.expires_at.saturating_add(Self::GRACE_PERIOD)
            })
            .count()
    }

    /// Whether `duration` satisfies `[MIN_DURATION, MAX_DURATION]`.
    #[must_use]
    pub const fn is_valid_duration(duration: u64) -> bool {
        duration >= MIN_DURATION && duration <= MAX_DURATION
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

    /// Crate-internal test registration helper (rejects `RESERVED_LABELS`).
    /// Production consensus registration flows exclusively through
    /// [`Self::register_primary_sale`].
    #[cfg(test)]
    pub(crate) fn register(
        &mut self,
        name: String,
        owner: Address,
        current_epoch: u64,
        duration: u64,
    ) -> Result<(), BnsError> {
        self.register_inner(name, owner, current_epoch, duration, false)
    }

    /// Primary marketplace settlement door: allows reserved labels iff `seller`
    /// is an authorized `BNS_PRIMARY_SELLERS` member, while enforcing all B1/B3
    /// bounds (`MIN_DURATION..=MAX_DURATION`, `MAX_NAMES_PER_OWNER`).
    pub(crate) fn register_primary_sale(
        &mut self,
        seller: &Address,
        name: String,
        buyer: Address,
        current_epoch: u64,
        duration: u64,
    ) -> Result<(), BnsError> {
        if !self.is_primary_seller(seller) {
            return Err(BnsError::NotOwner);
        }
        self.register_inner(name, buyer, current_epoch, duration, true)
    }

    fn register_inner(
        &mut self,
        name: String,
        owner: Address,
        current_epoch: u64,
        duration: u64,
        allow_reserved: bool,
    ) -> Result<(), BnsError> {
        if !Self::is_valid_name(&name) {
            return Err(BnsError::InvalidName);
        }
        if !allow_reserved && self.is_reserved_name(&name) {
            return Err(BnsError::ReservedName);
        }
        if !Self::is_valid_duration(duration) {
            return Err(BnsError::InvalidDuration);
        }
        let replacing_same_owner_in_grace = self.names.get(&name).is_some_and(|r| {
            r.owner == owner && current_epoch < r.expires_at.saturating_add(Self::GRACE_PERIOD)
        });
        if let Some(record) = self.names.get(&name) {
            if record.expires_at > current_epoch {
                return Err(BnsError::NameTaken);
            }
            let grace_until = record.expires_at.saturating_add(Self::GRACE_PERIOD);
            if current_epoch < grace_until && record.owner != owner {
                return Err(BnsError::NameTaken);
            }
        }
        if !replacing_same_owner_in_grace
            && self.active_name_count_for_owner(&owner, current_epoch) >= MAX_NAMES_PER_OWNER
        {
            return Err(BnsError::OwnerNameLimitExceeded);
        }
        let expires_at = current_epoch
            .checked_add(duration)
            .ok_or(BnsError::InvalidDuration)?;
        let record = NameRecord::try_new(name.clone(), owner, current_epoch, expires_at)?;
        // Cap total name count - fail-closed.
        // Reuse slots from expired names first; only reject if truly at capacity.
        if self.names.len() >= Self::MAX_NAMES && !self.names.contains_key(&name) {
            let expired_key = self
                .names
                .iter()
                .find(|(_, r)| r.expires_at.saturating_add(Self::GRACE_PERIOD) < current_epoch)
                .map(|(k, _)| k.clone());
            let Some(key) = expired_key else {
                return Err(BnsError::NameTaken);
            };
            self.names.remove(&key);
        }
        self.names.insert(name, record);
        Ok(())
    }

    /// Renew an existing name registration. Only the current owner may renew
    /// while the record is still live (not expired). The new expiry extends
    /// from the current expiry - never from `current_epoch` - so renewing early
    /// never shortens the registration, and total remaining duration from
    /// `current_epoch` cannot exceed `MAX_DURATION`.
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
        if !Self::is_valid_duration(duration) {
            return Err(BnsError::InvalidDuration);
        }
        let record = self.names.get_mut(name).ok_or(BnsError::InvalidName)?;
        if &record.owner != caller {
            return Err(BnsError::NotOwner);
        }
        if record.expires_at <= current_epoch {
            return Err(BnsError::Expired);
        }
        let new_expires_at = record
            .expires_at
            .checked_add(duration)
            .ok_or(BnsError::InvalidDuration)?;
        if new_expires_at.saturating_sub(current_epoch) > MAX_DURATION {
            return Err(BnsError::InvalidDuration);
        }
        record.expires_at = new_expires_at;
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
        let current_owner = self.names.get(name).ok_or(BnsError::InvalidName)?.owner;
        if &current_owner != caller {
            return Err(BnsError::NotOwner);
        }
        if self.names[name].expires_at <= current_epoch {
            return Err(BnsError::Expired);
        }
        if new_owner != current_owner
            && self.active_name_count_for_owner(&new_owner, current_epoch) >= MAX_NAMES_PER_OWNER
        {
            return Err(BnsError::OwnerNameLimitExceeded);
        }
        let prev_address = self.names[name].address;
        let record = self.names.get_mut(name).ok_or(BnsError::InvalidName)?;
        record.owner = new_owner;
        record.resolver = None;
        record.address = Some(new_owner);
        record.consensus_domain_id = None;
        record.storage_root = None;
        record.storage_domain_id = None;
        record.storage_root_height = None;
        record.content_id = None;
        record.subdomains.clear();
        record.records.clear();
        if current_owner != new_owner
            && self
                .primary_names
                .get(&current_owner)
                .is_some_and(|n| n == name)
        {
            self.primary_names.remove(&current_owner);
        }
        if let Some(prev_addr) = prev_address {
            if prev_addr != new_owner
                && self
                    .primary_names
                    .get(&prev_addr)
                    .is_some_and(|n| n == name)
            {
                self.primary_names.remove(&prev_addr);
            }
        }
        Ok(())
    }

    /// Whether `label` is a valid subdomain label (`1..=32` lowercase ASCII
    /// `[a-z0-9-]`, no leading or trailing `-`).
    #[must_use]
    pub fn is_valid_sub_label(label: &str) -> bool {
        let len = label.len();
        (1..=32).contains(&len)
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    }

    /// Split a two-level `.bud` FQDN `<sub_label>.<label>.bud` into
    /// `(sub_label, "<label>.bud")`. Rejects 3+ label hierarchies.
    #[must_use]
    pub fn split_subdomain_fqdn(fqdn: &str) -> Option<(&str, String)> {
        let stem = fqdn.strip_suffix(Self::SUFFIX)?;
        let (sub_label, parent_label) = stem.split_once('.')?;
        if parent_label.contains('.') {
            return None;
        }
        if !Self::is_valid_sub_label(sub_label) || !Self::is_valid_label(parent_label) {
            return None;
        }
        Some((sub_label, format!("{parent_label}{}", Self::SUFFIX)))
    }

    /// Register or update a subdomain `<sub_label>.<parent_name>` owned by `caller`.
    ///
    /// # Errors
    ///
    /// Returns [`BnsError`] if `sub_label` or `parent_name` is invalid, `owner`
    /// is zero, `caller` is not the parent owner, the parent is expired, or the
    /// subdomain count cap (`MAX_SUBDOMAINS_PER_NAME`) would be exceeded.
    pub fn register_subdomain(
        &mut self,
        parent_name: &str,
        sub_label: String,
        owner: Address,
        caller: &Address,
        current_epoch: u64,
    ) -> Result<(), BnsError> {
        if owner == Address::zero() || !Self::is_valid_sub_label(&sub_label) {
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
        if !parent.subdomains.contains_key(&sub_label)
            && parent.subdomains.len() >= Self::MAX_SUBDOMAINS_PER_NAME
        {
            return Err(BnsError::InvalidName);
        }
        parent.subdomains.insert(sub_label, owner);
        Ok(())
    }

    /// Remove an existing subdomain `<sub_label>` from a live `parent_name`
    /// owned by `caller`.
    ///
    /// # Errors
    ///
    /// Returns [`BnsError`] if `sub_label` or `parent_name` is invalid, `caller`
    /// is not the parent owner, the parent is expired, or `sub_label` does not exist.
    pub fn remove_subdomain(
        &mut self,
        parent_name: &str,
        sub_label: &str,
        caller: &Address,
        current_epoch: u64,
    ) -> Result<(), BnsError> {
        if !Self::is_valid_sub_label(sub_label) {
            return Err(BnsError::InvalidName);
        }
        {
            let parent = self.names.get(parent_name).ok_or(BnsError::InvalidName)?;
            if &parent.owner != caller {
                return Err(BnsError::NotOwner);
            }
            if parent.expires_at <= current_epoch {
                return Err(BnsError::Expired);
            }
            if !parent.subdomains.contains_key(sub_label) {
                return Err(BnsError::InvalidName);
            }
        }
        if let Some(parent) = self.names.get_mut(parent_name) {
            parent.subdomains.remove(sub_label);
        }
        Ok(())
    }

    /// List all subdomains of a live `parent_name` (`None` if unknown or expired).
    #[must_use]
    pub fn list_subdomains(
        &self,
        parent_name: &str,
        current_epoch: u64,
    ) -> Option<BTreeMap<String, Address>> {
        let parent = self.names.get(parent_name)?;
        if parent.expires_at <= current_epoch {
            return None;
        }
        Some(parent.subdomains.clone())
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

    /// Update the forwarding/payment target address (and optional consensus
    /// domain ID) of a live `.bud` name. Passing `target = None` clears the
    /// custom target; `Some(Address::zero())` is refused.
    ///
    /// # Errors
    ///
    /// Returns [`BnsError`] if the name does not exist, is expired, `caller` is
    /// not the owner, or `target` is the zero address.
    pub fn set_address(
        &mut self,
        name: &str,
        caller: &Address,
        target: Option<Address>,
        consensus_domain_id: Option<u32>,
        current_epoch: u64,
    ) -> Result<(), BnsError> {
        if target == Some(Address::zero()) {
            return Err(BnsError::InvalidName);
        }
        let (owner, prev_target) = {
            let record = self.names.get(name).ok_or(BnsError::InvalidName)?;
            if &record.owner != caller {
                return Err(BnsError::NotOwner);
            }
            if record.expires_at <= current_epoch {
                return Err(BnsError::Expired);
            }
            (record.owner, record.address)
        };
        let record = self.names.get_mut(name).ok_or(BnsError::InvalidName)?;
        record.address = target;
        record.consensus_domain_id = if target.is_some() {
            consensus_domain_id
        } else {
            None
        };
        if let Some(prev) = prev_target {
            if prev != owner
                && Some(prev) != target
                && self.primary_names.get(&prev).is_some_and(|n| n == name)
            {
                self.primary_names.remove(&prev);
            }
        }
        Ok(())
    }

    /// Set or clear the signer's reverse primary `.bud` name.
    ///
    /// To set `Some(name)`, `name` must be live at `current_epoch` and either
    /// owned by `caller` or explicitly routed to `caller` via `record.address`.
    ///
    /// # Errors
    ///
    /// Returns [`BnsError`] if `caller` is zero, `name` is invalid/unknown,
    /// expired, or neither owned by nor routed to `caller`.
    pub fn set_primary_name(
        &mut self,
        caller: &Address,
        name: Option<String>,
        current_epoch: u64,
    ) -> Result<(), BnsError> {
        if *caller == Address::zero() {
            return Err(BnsError::InvalidName);
        }
        match name {
            Some(name) => {
                if !Self::is_valid_name(&name) {
                    return Err(BnsError::InvalidName);
                }
                let record = self.names.get(&name).ok_or(BnsError::InvalidName)?;
                if record.expires_at <= current_epoch {
                    return Err(BnsError::Expired);
                }
                if &record.owner != caller && record.address.as_ref() != Some(caller) {
                    return Err(BnsError::NotOwner);
                }
                self.primary_names.insert(*caller, name);
                Ok(())
            }
            None => {
                self.primary_names.remove(caller);
                Ok(())
            }
        }
    }

    /// Bidirectionally verified reverse `.bud` resolution for `address`.
    ///
    /// Returns `Some(name)` iff `primary_names[address] == name` AND `name` is
    /// currently live AND (`record.owner == *address` or
    /// `record.address == Some(*address)`).
    #[must_use]
    pub fn reverse_resolve(&self, address: &Address, current_epoch: u64) -> Option<String> {
        let name = self.primary_names.get(address)?;
        let record = self.names.get(name)?;
        if record.expires_at <= current_epoch {
            return None;
        }
        if &record.owner == address || record.address.as_ref() == Some(address) {
            Some(name.clone())
        } else {
            None
        }
    }

    /// Resolve a live `.bud` name to its owner address (used for authorization).
    #[must_use]
    pub fn resolve_owner(&self, name: &str, current_epoch: u64) -> Option<Address> {
        self.names.get(name).and_then(|record| {
            if record.expires_at > current_epoch {
                Some(record.owner)
            } else {
                None
            }
        })
    }

    /// Resolve a live `<label>.bud` name (to `record.address`) or a live
    /// two-level `<sub_label>.<label>.bud` subdomain (failing closed if the
    /// parent `.bud` name is unknown or expired).
    pub fn resolve(&self, name: &str, current_epoch: u64) -> Option<Address> {
        if let Some(record) = self.names.get(name) {
            return if record.expires_at > current_epoch {
                record.address
            } else {
                None
            };
        }
        let (sub_label, parent_name) = Self::split_subdomain_fqdn(name)?;
        self.resolve_subdomain(&parent_name, sub_label, current_epoch)
    }

    /// Whether `key` is a valid BNS text/profile/multi-chain record key
    /// (`1..=MAX_RECORD_KEY_LEN`, lowercase ASCII `[a-z0-9._-]`, no leading or
    /// trailing `.` or `-`).
    #[must_use]
    pub fn is_valid_record_key(key: &str) -> bool {
        let len = key.len();
        (1..=MAX_RECORD_KEY_LEN).contains(&len)
            && !key.starts_with('.')
            && !key.ends_with('.')
            && !key.starts_with('-')
            && !key.ends_with('-')
            && !key.contains("..")
            && key.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
            })
    }

    /// Whether `value` is a safe bounded UTF-8 record value (`<= MAX_RECORD_VALUE_BYTES`,
    /// no control characters except `\n`, and no dangerous script/file URI schemes).
    #[must_use]
    pub fn is_safe_record_value(value: &str) -> bool {
        if value.len() > MAX_RECORD_VALUE_BYTES {
            return false;
        }
        if value.chars().any(|c| c.is_control() && c != '\n') {
            return false;
        }
        let lower = value.trim_start().to_ascii_lowercase();
        for forbidden in ["javascript:", "vbscript:", "data:", "file:"] {
            if lower.starts_with(forbidden) {
                return false;
            }
        }
        true
    }

    /// Atomically insert, update, or delete (`None`) text/profile/multi-chain
    /// records on a live `.bud` name owned by `caller`.
    ///
    /// # Errors
    ///
    /// Returns [`BnsError`] if the name is unknown, expired, not owned by
    /// `caller`, or any key/value/count bound fails.
    pub fn set_records(
        &mut self,
        name: &str,
        caller: &Address,
        updates: &BTreeMap<String, Option<String>>,
        current_epoch: u64,
    ) -> Result<(), BnsError> {
        if updates.is_empty() || updates.len() > MAX_RECORDS_PER_NAME {
            return Err(BnsError::InvalidRecord);
        }
        for (k, v) in updates {
            if !Self::is_valid_record_key(k) {
                return Err(BnsError::InvalidRecord);
            }
            if let Some(val) = v {
                if !Self::is_safe_record_value(val) {
                    return Err(BnsError::InvalidRecord);
                }
            }
        }
        let record = self.names.get(name).ok_or(BnsError::InvalidName)?;
        if &record.owner != caller {
            return Err(BnsError::NotOwner);
        }
        if record.expires_at <= current_epoch {
            return Err(BnsError::Expired);
        }
        let mut next = record.records.clone();
        for (k, v) in updates {
            match v {
                Some(val) => {
                    next.insert(k.clone(), val.clone());
                }
                None => {
                    next.remove(k);
                }
            }
        }
        if next.len() > MAX_RECORDS_PER_NAME {
            return Err(BnsError::InvalidRecord);
        }
        let record = self.names.get_mut(name).ok_or(BnsError::InvalidName)?;
        record.records = next;
        Ok(())
    }

    /// Read all text/profile/multi-chain records of a live `.bud` name.
    #[must_use]
    pub fn get_records(&self, name: &str, current_epoch: u64) -> Option<BTreeMap<String, String>> {
        let record = self.names.get(name)?;
        if record.expires_at <= current_epoch {
            return None;
        }
        Some(record.records.clone())
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
                subdomains: if expired {
                    BTreeMap::new()
                } else {
                    record.subdomains.clone()
                },
                records: if expired {
                    BTreeMap::new()
                } else {
                    record.records.clone()
                },
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
            && self.reserved_labels == default_reserved_labels()
            && self.primary_names.is_empty()
    }

    pub fn root(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_BNS_REGISTRY_V3");
        hasher.update(self.base_cost.to_le_bytes());
        hasher.update(b"reserved_labels");
        hasher.update((self.reserved_labels.len() as u64).to_le_bytes());
        for label in &self.reserved_labels {
            hasher.update((label.len() as u64).to_le_bytes());
            hasher.update(label.as_bytes());
        }
        if self.primary_sellers != default_primary_sellers() {
            hasher.update(b"primary_sellers");
            hasher.update((self.primary_sellers.len() as u64).to_le_bytes());
            for seller in &self.primary_sellers {
                hasher.update(seller.0);
            }
        }
        if !self.primary_names.is_empty() {
            hasher.update(b"primary_names");
            hasher.update((self.primary_names.len() as u64).to_le_bytes());
            for (addr, name) in &self.primary_names {
                hasher.update(addr.0);
                hasher.update((name.len() as u64).to_le_bytes());
                hasher.update(name.as_bytes());
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
            hasher.update((record.records.len() as u64).to_le_bytes());
            for (rec_key, rec_val) in &record.records {
                hasher.update((rec_key.len() as u64).to_le_bytes());
                hasher.update(rec_key.as_bytes());
                hasher.update((rec_val.len() as u64).to_le_bytes());
                hasher.update(rec_val.as_bytes());
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
