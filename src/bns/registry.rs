use crate::bns::types::{
    BnsError, BnsMerkleBranch, BnsResolved, BnsStateProof, NameRecord, NameStatus,
};
use crate::core::address::Address;
use crate::registry::params::{
    BNS_BASE_COST_MAX_STEP_FACTOR, GRACE_PERIOD, MAX_BNS_BASE_COST, MAX_DURATION,
    MAX_NAMES_PER_OWNER, MAX_RECORDS_PER_NAME, MAX_RECORD_KEY_LEN, MAX_RECORD_VALUE_BYTES,
    MIN_BNS_BASE_COST, MIN_DURATION, RESERVED_LABELS,
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

/// B13: the first epoch at which a record leaves the registry.
///
/// Expiry is `expires_at`, and the grace window that follows it still belongs
/// to the previous owner, so a record is reclaimable only from
/// `expires_at + GRACE_PERIOD` onward. Spelling it once keeps the index key and
/// the reclaim predicate from drifting apart.
#[must_use]
fn grace_end_of(record: &NameRecord) -> u64 {
    record.expires_at.saturating_add(GRACE_PERIOD)
}

fn default_max_names() -> usize {
    crate::registry::params::DEFAULT_MAX_NAMES
}

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
    /// B13: the ceiling this registry enforces. Seeded from
    /// [`crate::registry::params::DEFAULT_MAX_NAMES`] and stored, not read from
    /// the constant, so a snapshot written under a different ceiling still
    /// deserializes to the capacity it was written with.
    ///
    /// Appended after every pre-B13 field in the struct declaration on purpose.
    /// `AccountState::from_snapshot` reads this table through bincode, which is
    /// positional and not self-describing, so a field inserted in the middle
    /// would shift every field after it. Putting the new field last means a
    /// snapshot written before B13 has exactly two fields, and
    /// `#[serde(default)]` covers the absent tail.
    #[serde(default = "default_max_names")]
    pub max_names: usize,
    /// B13: `(expires_at + GRACE_PERIOD, name)` for every live record, ordered
    /// by the epoch its grace window closes.
    ///
    /// This is a derived view: it is rebuilt from `names` and deliberately
    /// **not** part of the state root ([`Self::root`] hashes `names` through the
    /// Merkle root and the metadata digest, and this field appears in neither).
    /// Keeping it out of the root means a snapshot restore, a replay and a live
    /// application all agree on consensus state even though only the live one
    /// carries the index in memory, and the rebuild on load costs one pass.
    #[serde(skip)]
    pub expired_by_grace_end: BTreeSet<(u64, String)>,
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
    pub const GRACE_PERIOD: u64 = GRACE_PERIOD;

    /// Maximum number of BNS names in the registry.
    /// At 100K names with subdomains, this bounds state growth to ~50MB.
    pub const MAX_NAMES: usize = 100_000;

    /// Maximum subdomains per name.
    pub const MAX_SUBDOMAINS_PER_NAME: usize = 1_000;

    /// Required top-level suffix for every registrable BNS name.
    const SUFFIX: &'static str = ".bud";

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

    /// The label rule on its own: one label, lowercase ASCII letters, digits
    /// and inner hyphens.
    ///
    /// Exposed so the network gateway applies exactly the table the registry
    /// sells from. A gateway with its own copy of the rule is a second opinion
    /// about what a name is, and the two drift.
    #[must_use]
    pub fn is_valid_label(label: &str) -> bool {
        label.len() <= 63
            && !label.is_empty()
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    }

    pub fn new() -> Self {
        Self {
            names: BTreeMap::new(),
            max_names: default_max_names(),
            expired_by_grace_end: BTreeSet::new(),
            base_cost: 100,
            primary_sellers: default_primary_sellers(),
            reserved_labels: default_reserved_labels(),
            primary_names: BTreeMap::new(),
        }
    }

    /// B13: record `name` and keep the expiry index in step.
    ///
    /// Every insert goes through here so the index cannot drift from `names`.
    /// The previous expiry row for the name is removed first: a renewal or a
    /// transfer rewrites `expires_at`, and two rows for one name would let the
    /// reclaim path delete a name that is still live.
    fn insert_record(&mut self, name: String, record: NameRecord) {
        self.expired_by_grace_end
            .remove(&(grace_end_of(&record), name.clone()));
        self.expired_by_grace_end
            .insert((grace_end_of(&record), name.clone()));
        self.names.insert(name, record);
    }

    /// B13: delete `name` and its index row together.
    fn remove_record(&mut self, name: &str) -> Option<NameRecord> {
        let removed = self.names.remove(name)?;
        self.expired_by_grace_end
            .remove(&(grace_end_of(&removed), name.to_string()));
        Some(removed)
    }

    /// B13: reclaim one name whose grace window has closed, dropping its index
    /// row with it. Refuses a name that is still live or still in grace, so the
    /// reclaim path cannot be turned into a deletion door.
    ///
    /// # Errors
    ///
    /// Returns [`BnsError::NameTaken`] when the record is still within
    /// `current_epoch < expires_at + GRACE_PERIOD`.
    pub fn reclaim_expired(&mut self, name: &str, current_epoch: u64) -> Result<(), BnsError> {
        let Some(record) = self.names.get(name) else {
            return Ok(());
        };
        if current_epoch < grace_end_of(record) {
            return Err(BnsError::NameTaken);
        }
        self.remove_record(name);
        Ok(())
    }

    /// B13: delete every name whose grace window closed at or before
    /// `current_epoch`, and return how many were deleted.
    ///
    /// The index makes this a walk of the expired prefix instead of a walk of
    /// the whole registry, so an epoch boundary costs time proportional to the
    /// names that actually ended. Deterministic: the index is ordered, so every
    /// node deletes the same names in the same order.
    pub fn prune_expired(&mut self, current_epoch: u64) -> usize {
        let due: Vec<(u64, String)> = self
            .expired_by_grace_end
            .iter()
            .take_while(|(grace_end, _)| *grace_end <= current_epoch)
            .cloned()
            .collect();
        let mut removed = 0;
        for (grace_end, name) in due {
            if self
                .names
                .get(&name)
                .is_some_and(|record| grace_end_of(record) == grace_end)
            {
                self.names.remove(&name);
                removed += 1;
            }
            self.expired_by_grace_end.remove(&(grace_end, name));
        }
        removed
    }

    /// B13: rebuild the expiry index from `names`.
    ///
    /// The index is skipped by serde because it is derived state. A registry
    /// that arrives from a snapshot, a clone of a snapshot, or a fresh genesis
    /// load therefore has an empty index until this runs; the load path calls
    /// it, and so does any test that builds a registry by hand.
    pub fn rebuild_expiry_index(&mut self) {
        self.expired_by_grace_end = self
            .names
            .iter()
            .map(|(name, record)| (grace_end_of(record), name.clone()))
            .collect();
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

    /// B12: the bounds every `BnsSetBaseCost` value must satisfy, on its own.
    ///
    /// Separated from [`Self::set_base_cost`] because the two checks answer
    /// different questions. The absolute bounds are a property of the value and
    /// can be checked when a proposal is submitted; the step bound is a
    /// property of the move and can only be checked against the price the chain
    /// holds when the proposal executes. A submission-time check that used
    /// [`Self::new`] would compare against the genesis price instead of the live
    /// one.
    ///
    /// # Errors
    ///
    /// Returns a message when `base_cost` is outside
    /// `MIN_BNS_BASE_COST..=MAX_BNS_BASE_COST`.
    pub fn check_base_cost_bounds(base_cost: u64) -> Result<(), String> {
        if !(MIN_BNS_BASE_COST..=MAX_BNS_BASE_COST).contains(&base_cost) {
            return Err(format!(
                "BNS base cost {base_cost} is outside the allowed range \
                 {MIN_BNS_BASE_COST}..={MAX_BNS_BASE_COST}"
            ));
        }
        Ok(())
    }

    /// B12: replace the renewal base cost under the directive's two bounds.
    ///
    /// The price moves and nothing else does. No record is re-priced, no term
    /// is shortened and no offer is rewritten: a registration keeps the
    /// duration it already paid for, and the next renewal of any name is
    /// charged at the new base. That is the whole reason the action exists, so
    /// the function refuses every input the bounds do not allow and does not
    /// clamp a bad one into a good one: a clamped price is a price governance
    /// did not vote for.
    ///
    /// # Errors
    ///
    /// Returns a message when `base_cost` is outside
    /// `MIN_BNS_BASE_COST..=MAX_BNS_BASE_COST`, or when it moves the current
    /// price by more than `BNS_BASE_COST_MAX_STEP_FACTOR` in one step.
    pub fn set_base_cost(&mut self, base_cost: u64) -> Result<(), String> {
        Self::check_base_cost_bounds(base_cost)?;
        let current = self.base_cost;
        // Integer form of `new <= current * FACTOR && new * FACTOR >= current`,
        // without the multiplication that could overflow for a large current.
        let within_step = base_cost <= current.saturating_mul(BNS_BASE_COST_MAX_STEP_FACTOR)
            && base_cost.saturating_mul(BNS_BASE_COST_MAX_STEP_FACTOR) >= current;
        if !within_step {
            return Err(format!(
                "BNS base cost may not move by more than {BNS_BASE_COST_MAX_STEP_FACTOR}x in one \
                 step: {current} -> {base_cost}"
            ));
        }
        self.base_cost = base_cost;
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

    /// Lifecycle status (`Active`, `Grace`, or `Expired`) of `name` at `current_epoch`.
    #[must_use]
    fn name_status(&self, name: &str, current_epoch: u64) -> Option<NameStatus> {
        let rec = self.names.get(name)?;
        if current_epoch < rec.expires_at {
            Some(NameStatus::Active)
        } else if current_epoch < rec.expires_at.saturating_add(Self::GRACE_PERIOD) {
            Some(NameStatus::Grace)
        } else {
            Some(NameStatus::Expired)
        }
    }

    /// Whether `owner` may renew `name` at `current_epoch` (either `Active` or inside `Grace`).
    #[must_use]
    pub fn is_renewable_by(&self, name: &str, owner: &Address, current_epoch: u64) -> bool {
        self.names.get(name).is_some_and(|rec| {
            &rec.owner == owner && current_epoch < rec.expires_at.saturating_add(Self::GRACE_PERIOD)
        })
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
        //
        // B13: slots are reclaimed through the expiry index, not through a
        // scan of every record. The scan was O(registry size) on a path any
        // buyer can reach, so once the registry filled, each registration paid
        // for a walk of the whole map, and the walk returned the first
        // *iteration-order* expired name rather than the one that expired
        // first. The index answers the same question - which name's grace
        // window closed earliest - in the time it takes to look at the head.
        if self.names.len() >= self.max_names && !self.names.contains_key(&name) {
            let Some((_, expired_key)) = self
                .expired_by_grace_end
                .iter()
                .find(|(grace_end, _)| *grace_end < current_epoch)
            else {
                return Err(BnsError::NameTaken);
            };
            let key = expired_key.clone();
            // The index row was selected because its grace end is past, so
            // `reclaim_expired` refuses only when the record changed under it;
            // that cannot happen between the two reads in this function.
            let _ = self.reclaim_expired(&key, current_epoch);
        }
        self.insert_record(name, record);
        Ok(())
    }

    /// Renew an existing name registration while `Active` or inside `GRACE_PERIOD`.
    ///
    /// Only the current owner may renew. When `Active`, the new expiry extends
    /// from `record.expires_at` so renewing early never shortens registration;
    /// when in `Grace`, the new expiry extends from `current_epoch` (`max(expires_at, current_epoch) + duration`),
    /// restoring the name to `Active` with all existing pointers intact. Total
    /// remaining duration from `current_epoch` cannot exceed `MAX_DURATION`.
    ///
    /// # Errors
    ///
    /// Returns [`BnsError`] if `duration` is out of bounds, the name is unknown,
    /// `caller` is not the owner, or the grace period has already elapsed.
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
        let grace_expires_at = record.expires_at.saturating_add(Self::GRACE_PERIOD);
        if current_epoch >= grace_expires_at {
            return Err(BnsError::Expired);
        }
        let base_epoch = record.expires_at.max(current_epoch);
        let new_expires_at = base_epoch
            .checked_add(duration)
            .ok_or(BnsError::InvalidDuration)?;
        if new_expires_at.saturating_sub(current_epoch) > MAX_DURATION {
            return Err(BnsError::InvalidDuration);
        }
        // B13: the index carries the grace end, so a renewal must move both the
        // record and its row. Writing `record.expires_at` here directly was how
        // a renewed name kept an index entry pointing at the old epoch.
        let old_grace_end = grace_end_of(record);
        record.expires_at = new_expires_at;
        let new_grace_end = grace_end_of(record);
        if old_grace_end != new_grace_end {
            let key = name.to_string();
            self.expired_by_grace_end
                .remove(&(old_grace_end, key.clone()));
            self.expired_by_grace_end.insert((new_grace_end, key));
        }
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
        let existing = self.names.get(name).ok_or(BnsError::InvalidName)?;
        let current_owner = existing.owner;
        if &current_owner != caller {
            return Err(BnsError::NotOwner);
        }
        if existing.expires_at <= current_epoch {
            return Err(BnsError::Expired);
        }
        if new_owner != current_owner
            && self.active_name_count_for_owner(&new_owner, current_epoch) >= MAX_NAMES_PER_OWNER
        {
            return Err(BnsError::OwnerNameLimitExceeded);
        }
        let prev_address = existing.address;
        let record = self.names.get_mut(name).ok_or(BnsError::InvalidName)?;
        record.owner = new_owner;
        record.resolver = None;
        record.address = Some(new_owner);
        record.consensus_domain_id = None;
        record.storage_root = None;
        record.storage_domain_id = None;
        record.storage_root_height = None;
        record.content_id = None;
        record.bud3_content = None;
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
    fn split_subdomain_fqdn(fqdn: &str) -> Option<(&str, String)> {
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

    /// Bind or clear (`None`) a verified B.U.D. 3.0 [`ContentRef`](crate::storage::bud3::content_ref::ContentRef) on a live `.bud`
    /// name owned by `caller`, checking object existence and `ContentId` parity in
    /// `bud3_registry`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::bns::bud3::BnsBud3Error`] if `name` is invalid, expired,
    /// not owned by `caller`, or `content_ref` fails `Bud3Registry` verification.
    pub fn set_bud3_content(
        &mut self,
        name: &str,
        caller: &Address,
        bud3: &crate::storage::bud3::registry::Bud3Registry,
        content_ref: Option<crate::storage::bud3::content_ref::ContentRef>,
        current_epoch: u64,
    ) -> Result<(), crate::bns::bud3::BnsBud3Error> {
        use crate::bns::bud3::BnsBud3Error;
        use crate::storage::bud3::content_id::ContentIdKind;
        use crate::storage::bud3::content_ref::ContentRef;

        if !Self::is_valid_name(name) {
            return Err(BnsBud3Error::Bns(BnsError::InvalidName));
        }
        {
            let record = self
                .names
                .get(name)
                .ok_or(BnsBud3Error::Bns(BnsError::InvalidName))?;
            if &record.owner != caller {
                return Err(BnsBud3Error::Bns(BnsError::NotOwner));
            }
            if record.expires_at <= current_epoch {
                return Err(BnsBud3Error::Bns(BnsError::Expired));
            }
        }
        let validated = match content_ref {
            None => None,
            Some(cref) => {
                let checked = ContentRef::new(cref.content_id, cref.object_commitment, cref.nft_id)
                    .map_err(BnsBud3Error::InvalidContentRef)?;
                let obj = bud3
                    .object(&checked.object_commitment)
                    .ok_or(BnsBud3Error::UnknownObject)?;
                if obj.record.content_id != checked.content_id {
                    return Err(BnsBud3Error::ContentIdMismatch);
                }
                if checked.content_id.kind == ContentIdKind::Sealed && checked.nft_id.is_none() {
                    return Err(BnsBud3Error::SealedRequiresNftGrant);
                }
                Some(checked)
            }
        };
        let record = self
            .names
            .get_mut(name)
            .ok_or(BnsBud3Error::Bns(BnsError::InvalidName))?;
        record.bud3_content = validated;
        Ok(())
    }

    /// Resolve the live B.U.D. 3.0 [`ContentRef`](crate::storage::bud3::content_ref::ContentRef) bound to `name` (`None` if
    /// unbound, unknown, or expired).
    #[must_use]
    pub fn resolve_bud3_content(
        &self,
        name: &str,
        current_epoch: u64,
    ) -> Option<crate::storage::bud3::content_ref::ContentRef> {
        self.names.get(name).and_then(|record| {
            if record.expires_at > current_epoch {
                record.bud3_content
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
        let status = self.name_status(name, current_epoch)?;
        self.names.get(name).map(|record| {
            let expired = record.expires_at <= current_epoch;
            let grace_expires_at = record.expires_at.saturating_add(Self::GRACE_PERIOD);
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
                bud3_content: if expired { None } else { record.bud3_content },
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
                status,
                expires_at: record.expires_at,
                grace_expires_at,
                is_expired: expired,
            }
        })
    }

    /// Enumerate all `Active` and `Grace` `.bud` names held by `owner` at
    /// `current_epoch`, ordered lexicographically by name (excluding fully
    /// expired post-grace tombstones).
    #[must_use]
    pub fn list_names_by_owner(&self, owner: &Address, current_epoch: u64) -> Vec<BnsResolved> {
        self.names
            .keys()
            .filter_map(|name| {
                let rec = self.names.get(name)?;
                if &rec.owner != owner
                    || current_epoch >= rec.expires_at.saturating_add(Self::GRACE_PERIOD)
                {
                    return None;
                }
                self.resolve_full(name, current_epoch)
            })
            .collect()
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

    /// Canonical SHA-256 commitment over the auxiliary fields of `record` not
    /// carried directly in the top-level browser `ResolvedName` tuple.
    #[must_use]
    fn record_extras_digest(record: &NameRecord) -> [u8; 32] {
        Self::extras_digest(&Self::extras_from_record(record))
    }

    /// The extras a name record discloses, in the shape a proof carries.
    #[must_use]
    pub(crate) fn extras_from_record(record: &NameRecord) -> crate::bns::types::BnsBranchExtras {
        crate::bns::types::BnsBranchExtras {
            resolver: record.resolver,
            address: record.address,
            consensus_domain_id: record.consensus_domain_id,
            storage_domain_id: record.storage_domain_id,
            storage_root_height: record.storage_root_height,
            bud3_content: record.bud3_content,
            subdomains: record.subdomains.clone(),
            records: record.records.clone(),
        }
    }

    /// The commitment over a disclosed extras pre-image (`BDLM_BNS_EXTRAS_V1`).
    ///
    /// The encoding is the one the leaf digest already used, so the digest of
    /// [`Self::extras_from_record`] equals [`Self::record_extras_digest`] field
    /// for field. A proof that ships its extras can therefore be checked
    /// against the header root instead of being believed.
    #[must_use]
    pub(crate) fn extras_digest(extras: &crate::bns::types::BnsBranchExtras) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_BNS_EXTRAS_V1");
        match extras.resolver {
            Some(resolver) => {
                hasher.update([1u8]);
                hasher.update(resolver.0);
            }
            None => hasher.update([0u8]),
        }
        match extras.address {
            Some(address) => {
                hasher.update([1u8]);
                hasher.update(address.0);
            }
            None => hasher.update([0u8]),
        }
        match extras.consensus_domain_id {
            Some(domain_id) => {
                hasher.update([1u8]);
                hasher.update(domain_id.to_le_bytes());
            }
            None => hasher.update([0u8]),
        }
        match extras.storage_domain_id {
            Some(domain_id) => {
                hasher.update([1u8]);
                hasher.update(domain_id.to_le_bytes());
            }
            None => hasher.update([0u8]),
        }
        match extras.storage_root_height {
            Some(height) => {
                hasher.update([1u8]);
                hasher.update(height.to_le_bytes());
            }
            None => hasher.update([0u8]),
        }
        match extras.bud3_content {
            Some(cref) => {
                hasher.update([1u8]);
                let kind_byte = match cref.content_id.kind {
                    crate::storage::bud3::content_id::ContentIdKind::Public => 0u8,
                    crate::storage::bud3::content_id::ContentIdKind::Sealed => 1u8,
                };
                hasher.update([kind_byte]);
                hasher.update(cref.content_id.digest);
                hasher.update(cref.content_id.len.to_le_bytes());
                hasher.update(cref.object_commitment);
                match cref.nft_id {
                    Some(nft) => {
                        hasher.update([1u8]);
                        hasher.update(nft);
                    }
                    None => hasher.update([0u8]),
                }
            }
            None => hasher.update([0u8]),
        }
        hasher.update((extras.subdomains.len() as u64).to_le_bytes());
        for (sub_label, sub_owner) in &extras.subdomains {
            hasher.update((sub_label.len() as u64).to_le_bytes());
            hasher.update(sub_label.as_bytes());
            hasher.update(sub_owner.0);
        }
        hasher.update((extras.records.len() as u64).to_le_bytes());
        for (rec_key, rec_val) in &extras.records {
            hasher.update((rec_key.len() as u64).to_le_bytes());
            hasher.update(rec_key.as_bytes());
            hasher.update((rec_val.len() as u64).to_le_bytes());
            hasher.update(rec_val.as_bytes());
        }
        hasher.finalize().into()
    }

    /// Canonical per-name Merkle leaf digest (`BDLM_BNS_LEAF_V1`).
    #[must_use]
    fn compute_leaf_digest(
        name: &str,
        owner: &Address,
        expires_at: u64,
        content_id: Option<ContentId>,
        storage_root: Option<[u8; 32]>,
        extras_digest: [u8; 32],
    ) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_BNS_LEAF_V1");
        hasher.update((name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update(owner.0);
        hasher.update(expires_at.to_le_bytes());
        match content_id {
            Some(cid) => {
                hasher.update([1u8]);
                hasher.update(cid.0);
            }
            None => hasher.update([0u8]),
        }
        match storage_root {
            Some(sr) => {
                hasher.update([1u8]);
                hasher.update(sr);
            }
            None => hasher.update([0u8]),
        }
        hasher.update(extras_digest);
        hasher.finalize().into()
    }

    /// Canonical leaf digest for an existing [`NameRecord`].
    #[must_use]
    fn record_leaf_digest(record: &NameRecord) -> [u8; 32] {
        let extras = Self::record_extras_digest(record);
        Self::compute_leaf_digest(
            &record.name,
            &record.owner,
            record.expires_at,
            record.content_id,
            record.storage_root,
            extras,
        )
    }

    fn hash_merkle_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_BNS_NODE_V1");
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }

    /// Fold a Merkle branch `(siblings, directions)` from `leaf` up to `names_merkle_root`.
    #[must_use]
    fn fold_merkle_branch(
        leaf: [u8; 32],
        siblings: &[[u8; 32]],
        directions: &[bool],
    ) -> Option<[u8; 32]> {
        if siblings.len() != directions.len() || siblings.len() > 32 {
            return None;
        }
        let mut acc = leaf;
        for (sib, is_right_child) in siblings.iter().zip(directions.iter()) {
            acc = if *is_right_child {
                Self::hash_merkle_pair(sib, &acc)
            } else {
                Self::hash_merkle_pair(&acc, sib)
            };
        }
        Some(acc)
    }

    /// Registry-wide metadata commitment (`BDLM_BNS_META_V1`) covering non-leaf
    /// registry configuration (`base_cost`, `reserved_labels`, `primary_sellers`,
    /// `primary_names`, and `names.len()`).
    #[must_use]
    pub fn meta_digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_BNS_META_V1");
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
        hasher.finalize().into()
    }

    /// Combine `(meta_digest, names_merkle_root)` into `BDLM_BNS_REGISTRY_V3`.
    #[must_use]
    fn root_from_parts(meta_digest: [u8; 32], names_merkle_root: [u8; 32]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_BNS_REGISTRY_V3");
        hasher.update(meta_digest);
        hasher.update(names_merkle_root);
        hasher.finalize().into()
    }

    /// Binary Merkle root over all ordered `NameRecord` leaves (`[0u8; 32]` when empty).
    #[must_use]
    pub fn names_merkle_root(&self) -> [u8; 32] {
        if self.names.is_empty() {
            return [0u8; 32];
        }
        let mut level: Vec<[u8; 32]> = self.names.values().map(Self::record_leaf_digest).collect();
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut i = 0;
            while i < level.len() {
                let Some(left) = level.get(i) else {
                    break;
                };
                if let Some(right) = level.get(i.saturating_add(1)) {
                    next.push(Self::hash_merkle_pair(left, right));
                } else {
                    next.push(*left);
                }
                i += 2;
            }
            level = next;
        }
        level.first().copied().unwrap_or([0u8; 32])
    }

    fn build_branch_at(
        records: &[&NameRecord],
        leaves: &[[u8; 32]],
        target_idx: usize,
    ) -> Option<BnsMerkleBranch> {
        let rec = records.get(target_idx).copied()?;
        let extras_digest = Self::record_extras_digest(rec);
        let leaf = *leaves.get(target_idx)?;
        let mut siblings = Vec::new();
        let mut directions = Vec::new();
        let mut idx = target_idx;
        let mut level = leaves.to_vec();
        while level.len() > 1 {
            if idx.is_multiple_of(2) {
                if let Some(sibling) = idx
                    .checked_add(1)
                    .and_then(|sibling_idx| level.get(sibling_idx))
                {
                    siblings.push(*sibling);
                    directions.push(false);
                }
            } else {
                let sibling = idx
                    .checked_sub(1)
                    .and_then(|sibling_idx| level.get(sibling_idx))?;
                siblings.push(*sibling);
                directions.push(true);
            }
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut i = 0;
            while i < level.len() {
                let left = level.get(i)?;
                if let Some(right) = level.get(i.saturating_add(1)) {
                    next.push(Self::hash_merkle_pair(left, right));
                } else {
                    next.push(*left);
                }
                i += 2;
            }
            idx /= 2;
            level = next;
        }
        Some(BnsMerkleBranch {
            name: rec.name.clone(),
            owner: rec.owner,
            address: rec.address,
            expires_at: rec.expires_at,
            content_id: rec.content_id,
            storage_root: rec.storage_root,
            extras_digest,
            leaf,
            siblings,
            directions,
            leaf_index: Some(u64::try_from(target_idx).unwrap_or(u64::MAX)),
            tree_size: Some(u64::try_from(records.len()).unwrap_or(u64::MAX)),
            extras: Some(Self::extras_from_record(rec)),
        })
    }

    /// The absence rule: `pred` and `succ` are the two leaves flanking the
    /// target, and no name sorts between them.
    ///
    /// Lexicographic order alone is not a proof of absence. Every branch in the
    /// tree sorts next to some target, and `names_count` is a claimed field the
    /// leaf never commits to, so an honest inclusion branch of a live name could
    /// be relabelled and served as proof that the name is unregistered. Two
    /// things make the claim checkable:
    ///
    /// - Both boundary branches carry the size of the list they were built
    ///   from, and the two must agree. A predecessor from one tree and a
    ///   successor from another cannot be spliced together.
    /// - Both carry their leaf position, and the positions must be adjacent.
    ///   Adjacent positions in the ordered name list are exactly what "nothing
    ///   sorts between these two names" means, so a prover that skips a live
    ///   name in the middle has to forge a position it cannot open.
    ///
    /// The first and last positions are the two open ends: the first leaf has
    /// no predecessor and the last has no successor, which is why one boundary
    /// is allowed when it is that end.
    fn check_boundary_pair(
        proof: &BnsStateProof,
        pred: Option<&BnsMerkleBranch>,
        succ: Option<&BnsMerkleBranch>,
    ) -> Result<(), String> {
        let target = proof.name.as_str();
        for branch in [pred, succ].into_iter().flatten() {
            let (Some(index), Some(size)) = (branch.leaf_index, branch.tree_size) else {
                return Err(
                    "absence proof branch carries no leaf position; a branch without one cannot show adjacency"
                        .into(),
                );
            };
            if size != proof.names_count {
                return Err("absence proof branch was built from a different list size".into());
            }
            if index >= size {
                return Err("absence proof branch leaf position is outside the tree".into());
            }
        }
        match (pred, succ) {
            (Some(pred), Some(succ)) => {
                let (Some(pred_index), Some(succ_index)) = (pred.leaf_index, succ.leaf_index)
                else {
                    return Err("absence proof boundary branch carries no leaf position".into());
                };
                if succ_index != pred_index.saturating_add(1) {
                    return Err(
                        "absence proof boundaries are not adjacent, so a name may sort between them"
                            .into(),
                    );
                }
            }
            (Some(pred), None) => {
                let Some(pred_index) = pred.leaf_index else {
                    return Err("absence proof boundary branch carries no leaf position".into());
                };
                if pred_index.saturating_add(1) != proof.names_count {
                    return Err(
                        "a predecessor-only absence proof must name the last leaf of the tree"
                            .into(),
                    );
                }
            }
            (None, Some(succ)) => {
                let Some(succ_index) = succ.leaf_index else {
                    return Err("absence proof boundary branch carries no leaf position".into());
                };
                if succ_index != 0 {
                    return Err(
                        "a successor-only absence proof must name the first leaf of the tree"
                            .into(),
                    );
                }
            }
            (None, None) => {
                return Err("non-empty registry absence proof requires a boundary branch".into());
            }
        }
        if let Some(pred) = pred {
            if pred.name.as_str() >= target {
                return Err("predecessor name is not strictly less than target".into());
            }
        }
        if let Some(succ) = succ {
            if succ.name.as_str() <= target {
                return Err("successor name is not strictly greater than target".into());
            }
        }
        Ok(())
    }

    /// Produce an $O(\log N)$ per-name Merkle state proof (inclusion when `name`
    /// is present, or adjacent lexicographic boundary proof when `name` is absent).
    #[must_use]
    pub fn prove_name(&self, name: &str, current_epoch: u64) -> BnsStateProof {
        let meta_digest = self.meta_digest();
        let records: Vec<&NameRecord> = self.names.values().collect();
        let leaves: Vec<[u8; 32]> = records
            .iter()
            .map(|r| Self::record_leaf_digest(r))
            .collect();
        let names_root = if leaves.is_empty() {
            [0u8; 32]
        } else {
            let mut lvl = leaves.clone();
            while lvl.len() > 1 {
                let mut next = Vec::with_capacity(lvl.len().div_ceil(2));
                let mut i = 0;
                while i < lvl.len() {
                    let Some(left) = lvl.get(i) else {
                        break;
                    };
                    if let Some(right) = lvl.get(i.saturating_add(1)) {
                        next.push(Self::hash_merkle_pair(left, right));
                    } else {
                        next.push(*left);
                    }
                    i += 2;
                }
                lvl = next;
            }
            lvl.first().copied().unwrap_or([0u8; 32])
        };
        let bns_root = Self::root_from_parts(meta_digest, names_root);

        match records.binary_search_by(|r| r.name.as_str().cmp(name)) {
            Ok(idx) => BnsStateProof {
                name: name.to_string(),
                included: true,
                bns_root,
                meta_digest,
                names_count: records.len() as u64,
                epoch: current_epoch,
                entry: Self::build_branch_at(&records, &leaves, idx),
                predecessor: None,
                successor: None,
            },
            Err(insert_idx) => {
                let predecessor = insert_idx
                    .checked_sub(1)
                    .and_then(|p| Self::build_branch_at(&records, &leaves, p));
                let successor = if insert_idx < records.len() {
                    Self::build_branch_at(&records, &leaves, insert_idx)
                } else {
                    None
                };
                BnsStateProof {
                    name: name.to_string(),
                    included: false,
                    bns_root,
                    meta_digest,
                    names_count: records.len() as u64,
                    epoch: current_epoch,
                    entry: None,
                    predecessor,
                    successor,
                }
            }
        }
    }

    /// Verify a [`BnsStateProof`] against `expected_bns_root` at `current_epoch`,
    /// returning `Ok(Some(resolved_entry))` on valid live inclusion, `Ok(None)`
    /// on verified non-existence, and `Err(reason)` if forged or expired.
    ///
    /// # Errors
    ///
    /// Returns a human-readable refusal reason if any digest, Merkle path,
    /// boundary order, or expiry check fails.
    pub fn verify_state_proof<'a>(
        proof: &'a BnsStateProof,
        expected_bns_root: &[u8; 32],
        current_epoch: u64,
    ) -> Result<Option<&'a BnsMerkleBranch>, String> {
        if &proof.bns_root != expected_bns_root {
            return Err("proof bns_root does not match expected header bns_root".into());
        }
        let check_branch = |branch: &BnsMerkleBranch| -> Result<[u8; 32], String> {
            // The extras digest is a commitment; `address`, the records, the
            // subdomains and the B.U.D. 3.0 reference only mean something if
            // the pre-image behind it is the one the header root commits to.
            // A branch that discloses its extras is checked here, so every
            // field it shows is bound to the root. A branch that withholds them
            // still proves the fields outside the digest; callers that need a
            // disclosed field must read it from `branch.extras`, never from the
            // top-level copy, which is where the prover chooses freely.
            if let Some(extras) = &branch.extras {
                if Self::extras_digest(extras) != branch.extras_digest {
                    return Err("branch extras do not match the extras digest".into());
                }
                if extras.address != branch.address {
                    return Err("branch top-level address contradicts the extras digest".into());
                }
            }
            let recomputed_leaf = Self::compute_leaf_digest(
                &branch.name,
                &branch.owner,
                branch.expires_at,
                branch.content_id,
                branch.storage_root,
                branch.extras_digest,
            );
            if recomputed_leaf != branch.leaf {
                return Err("branch leaf digest mismatch".into());
            }
            Self::fold_merkle_branch(recomputed_leaf, &branch.siblings, &branch.directions)
                .ok_or_else(|| "malformed Merkle branch".to_string())
        };

        if proof.included {
            let entry = proof
                .entry
                .as_ref()
                .ok_or_else(|| "included proof missing entry branch".to_string())?;
            if entry.name != proof.name {
                return Err("entry name does not match queried name".into());
            }
            let names_root = check_branch(entry)?;
            if Self::root_from_parts(proof.meta_digest, names_root) != *expected_bns_root {
                return Err("Merkle inclusion branch did not reproduce expected bns_root".into());
            }
            if entry.expires_at <= current_epoch {
                return Err("proven BNS entry has expired at current_epoch".into());
            }
            Ok(Some(entry))
        } else {
            if proof.entry.is_some() {
                return Err("non-inclusion proof must not carry an entry branch".into());
            }
            if proof.names_count == 0 {
                if proof.predecessor.is_some() || proof.successor.is_some() {
                    return Err("empty registry proof cannot carry boundary branches".into());
                }
                if Self::root_from_parts(proof.meta_digest, [0u8; 32]) != *expected_bns_root {
                    return Err("empty registry root mismatch".into());
                }
                return Ok(None);
            }
            if proof.predecessor.is_none() && proof.successor.is_none() {
                return Err("non-empty registry absence proof requires a boundary branch".into());
            }
            // Each boundary branch must open to the header root before its
            // position means anything.
            if let Some(pred) = &proof.predecessor {
                let root = check_branch(pred)?;
                if Self::root_from_parts(proof.meta_digest, root) != *expected_bns_root {
                    return Err("predecessor branch did not reproduce expected bns_root".into());
                }
            }
            if let Some(succ) = &proof.successor {
                let root = check_branch(succ)?;
                if Self::root_from_parts(proof.meta_digest, root) != *expected_bns_root {
                    return Err("successor branch did not reproduce expected bns_root".into());
                }
            }
            // Order alone proves nothing: a live name can hide between two
            // honest branches. Only the positions can rule that out.
            Self::check_boundary_pair(proof, proof.predecessor.as_ref(), proof.successor.as_ref())?;
            Ok(None)
        }
    }

    pub fn root(&self) -> [u8; 32] {
        Self::root_from_parts(self.meta_digest(), self.names_merkle_root())
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
