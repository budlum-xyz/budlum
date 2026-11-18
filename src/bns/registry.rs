use crate::bns::smt;
use crate::bns::types::{
    BnsAbsenceProof, BnsError, BnsMerkleBranch, BnsOccupiedSlot, BnsResolved, BnsStateProof,
    NameRecord, NameStatus, SubdomainRecord,
};
use crate::core::address::Address;
use crate::registry::params::{
    BNS_BASE_COST_MAX_STEP_FACTOR, GRACE_PERIOD, MAX_BNS_BASE_COST, MAX_DURATION,
    MAX_NAMES_PER_OWNER, MAX_RECORDS_PER_NAME, MAX_RECORD_KEY_LEN, MAX_RECORD_VALUE_BYTES,
    MIN_BNS_BASE_COST, MIN_DURATION, RESERVED_LABELS,
};
use crate::storage::bud3::content_ref::ContentRef;
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

#[derive(Debug, Clone, Default)]
struct NameTreeState {
    built: bool,
    tree: smt::Tree,
    stale: BTreeSet<String>,
}

/// The sparse tree behind the names root, kept in step with the name table.
///
/// The tree is derived state. A registry that was just loaded has none, so
/// the first read builds it in one pass. After that a write only marks its
/// name, and the next read re-hashes the paths of the marked names. A block
/// that touches three names hashes three paths, whatever the table size.
///
/// The lock is what lets a read through `&self` bring the tree up to date.
#[derive(Debug, Default)]
struct NameTree(std::sync::Mutex<NameTreeState>);

impl Clone for NameTree {
    fn clone(&self) -> Self {
        let state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self(std::sync::Mutex::new(state.clone()))
    }
}

impl NameTree {
    /// Mark `name` as written. Every write to the name table calls this.
    fn touch(&mut self, name: &str) {
        let state = self
            .0
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.built {
            state.stale.insert(name.to_string());
        }
    }

    /// Bring the tree up to date with `names` and read it.
    fn read<R>(
        &self,
        names: &BTreeMap<String, NameRecord>,
        read: impl FnOnce(&smt::Tree) -> R,
    ) -> R {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.built {
            for name in std::mem::take(&mut state.stale) {
                let key = smt::key_of(&name);
                match names.get(&name) {
                    Some(record) => state
                        .tree
                        .insert(key, BnsRegistry::record_leaf_digest(record)),
                    None => state.tree.remove(&key),
                }
            }
        } else {
            let mut tree = smt::Tree::default();
            for (name, record) in names {
                tree.insert(smt::key_of(name), BnsRegistry::record_leaf_digest(record));
            }
            state.tree = tree;
            state.stale.clear();
            state.built = true;
        }
        read(&state.tree)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsRegistry {
    names: BTreeMap<String, NameRecord>,
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
    /// The sparse tree over `names`. Derived, like the expiry index: it is
    /// rebuilt on first use after a load and then follows each write.
    #[serde(skip)]
    name_tree: NameTree,
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

    #[must_use]
    pub fn new() -> Self {
        Self {
            names: BTreeMap::new(),
            max_names: default_max_names(),
            expired_by_grace_end: BTreeSet::new(),
            name_tree: NameTree::default(),
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
    /// re-registration rewrites `expires_at`, and two rows for one name would
    /// leave a stale row that breaks `max_names` enforcement and causes live
    /// nodes to diverge from snapshot-rebuilt nodes.
    fn insert_record(&mut self, name: String, record: NameRecord) {
        self.name_tree.touch(&name);
        let new_grace_end = grace_end_of(&record);
        if let Some(old) = self.names.insert(name.clone(), record) {
            self.expired_by_grace_end
                .remove(&(grace_end_of(&old), name.clone()));
        }
        self.expired_by_grace_end.insert((new_grace_end, name));
    }

    /// The name table, read-only. Writes go through the registry so the
    /// tree and the expiry index follow them.
    #[must_use]
    pub const fn names(&self) -> &BTreeMap<String, NameRecord> {
        &self.names
    }

    /// The one door to a record that is about to be edited. It tells the
    /// tree first, so no write can reach the table without its path being
    /// re-hashed. It takes the two fields apart so a caller can keep using
    /// the rest of the registry while it holds the record.
    fn slot_mut<'a>(
        names: &'a mut BTreeMap<String, NameRecord>,
        tree: &mut NameTree,
        name: &str,
    ) -> Option<&'a mut NameRecord> {
        tree.touch(name);
        names.get_mut(name)
    }

    /// A record a test edits in place, with the tree told about the write.
    #[cfg(test)]
    pub(crate) fn record_mut(&mut self, name: &str) -> Option<&mut NameRecord> {
        Self::slot_mut(&mut self.names, &mut self.name_tree, name)
    }

    /// B13: delete `name` and its index row together.
    fn remove_record(&mut self, name: &str) -> Option<NameRecord> {
        let removed = self.names.remove(name)?;
        self.name_tree.touch(name);
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
    fn reclaim_expired(&mut self, name: &str, current_epoch: u64) -> Result<(), BnsError> {
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
                self.name_tree.touch(&name);
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
            // Fail closed if the indexed row is not actually past grace so
            // `self.names.len()` can never exceed `self.max_names`.
            self.reclaim_expired(&key, current_epoch)?;
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
        let record = Self::slot_mut(&mut self.names, &mut self.name_tree, name)
            .ok_or(BnsError::InvalidName)?;
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
    /// (address, storage, content and subdomains) are cleared and the
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
        let record = Self::slot_mut(&mut self.names, &mut self.name_tree, name)
            .ok_or(BnsError::InvalidName)?;
        record.owner = new_owner;
        record.address = Some(new_owner);
        record.consensus_domain_id = None;
        record.storage_root = None;
        record.storage_domain_id = None;
        record.storage_root_height = None;
        record.content = None;
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

    /// Register the subdomain `<sub_label>.<parent_name>` for `owner`.
    ///
    /// A label that exists is never overwritten: the parent owner removes it
    /// first, so a subdomain owner cannot lose its record in silence.
    ///
    /// # Errors
    ///
    /// Returns [`BnsError`] if `sub_label` or `parent_name` is invalid, `owner`
    /// is zero, `caller` is not the parent owner, the parent is expired, the
    /// label is taken (`NameTaken`), or the subdomain count cap
    /// (`MAX_SUBDOMAINS_PER_NAME`) would be exceeded.
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
        let parent = Self::slot_mut(&mut self.names, &mut self.name_tree, parent_name)
            .ok_or(BnsError::InvalidName)?;
        if &parent.owner != caller {
            return Err(BnsError::NotOwner);
        }
        if parent.expires_at <= current_epoch {
            return Err(BnsError::Expired);
        }
        if parent.subdomains.contains_key(&sub_label) {
            return Err(BnsError::NameTaken);
        }
        if parent.subdomains.len() >= Self::MAX_SUBDOMAINS_PER_NAME {
            return Err(BnsError::InvalidName);
        }
        parent
            .subdomains
            .insert(sub_label, SubdomainRecord::owned_by(owner));
        Ok(())
    }

    /// Set or clear (`None`) the content the subdomain `<sub_label>` of a
    /// live `parent_name` serves. Only the subdomain owner may do it; the
    /// parent owner removes a subdomain and does not write into it.
    ///
    /// # Errors
    ///
    /// Returns [`crate::bns::bud3::BnsBud3Error`] if `sub_label` or
    /// `parent_name` is invalid or unknown, the parent is expired, `caller`
    /// does not own the subdomain, or `content` fails the object registry
    /// check.
    pub fn set_subdomain_content(
        &mut self,
        parent_name: &str,
        sub_label: &str,
        caller: &Address,
        bud3: &crate::storage::bud3::registry::Bud3Registry,
        content: Option<ContentRef>,
        current_epoch: u64,
    ) -> Result<(), crate::bns::bud3::BnsBud3Error> {
        use crate::bns::bud3::BnsBud3Error;

        if !Self::is_valid_sub_label(sub_label) {
            return Err(BnsBud3Error::Bns(BnsError::InvalidName));
        }
        let parent = Self::slot_mut(&mut self.names, &mut self.name_tree, parent_name)
            .ok_or(BnsBud3Error::Bns(BnsError::InvalidName))?;
        if parent.expires_at <= current_epoch {
            return Err(BnsBud3Error::Bns(BnsError::Expired));
        }
        let record = parent
            .subdomains
            .get_mut(sub_label)
            .ok_or(BnsBud3Error::Bns(BnsError::InvalidName))?;
        if &record.owner != caller {
            return Err(BnsBud3Error::Bns(BnsError::NotOwner));
        }
        record.content = match content {
            None => None,
            Some(cref) => Some(crate::bns::bud3::checked_content_ref(bud3, cref)?),
        };
        Ok(())
    }

    /// The owner of the subdomain `<sub_label>` of a live `parent_name`.
    #[must_use]
    pub fn subdomain_owner(
        &self,
        parent_name: &str,
        sub_label: &str,
        current_epoch: u64,
    ) -> Option<Address> {
        self.list_subdomains(parent_name, current_epoch)?
            .get(sub_label)
            .map(|record| record.owner)
    }

    /// The content the subdomain `<sub_label>` of a live `parent_name`
    /// serves. `None` when the parent is unknown or expired, the label does
    /// not exist, or the subdomain has no content of its own.
    #[must_use]
    pub fn resolve_subdomain_content(
        &self,
        parent_name: &str,
        sub_label: &str,
        current_epoch: u64,
    ) -> Option<ContentRef> {
        self.list_subdomains(parent_name, current_epoch)?
            .get(sub_label)
            .and_then(|record| record.content)
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
        if let Some(parent) = Self::slot_mut(&mut self.names, &mut self.name_tree, parent_name) {
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
    ) -> Option<BTreeMap<String, SubdomainRecord>> {
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
            parent
                .subdomains
                .get(sub_label)
                .and_then(|record| record.address)
        } else {
            None
        }
    }

    /// Bind or clear (`None`) the content a live name serves. The caller
    /// must own the name; the reference must name an object the chain holds,
    /// with the same content id.
    ///
    /// # Errors
    ///
    /// Returns [`crate::bns::bud3::BnsBud3Error`] if `name` is invalid, expired,
    /// not owned by `caller`, or `content` fails the object registry check.
    pub fn set_content(
        &mut self,
        name: &str,
        caller: &Address,
        bud3: &crate::storage::bud3::registry::Bud3Registry,
        content: Option<ContentRef>,
        current_epoch: u64,
    ) -> Result<(), crate::bns::bud3::BnsBud3Error> {
        use crate::bns::bud3::BnsBud3Error;

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
        let validated = match content {
            None => None,
            Some(cref) => Some(crate::bns::bud3::checked_content_ref(bud3, cref)?),
        };
        let record = Self::slot_mut(&mut self.names, &mut self.name_tree, name)
            .ok_or(BnsBud3Error::Bns(BnsError::InvalidName))?;
        record.content = validated;
        Ok(())
    }

    /// The content a live name serves (`None` if unbound, unknown, or expired).
    #[must_use]
    pub fn resolve_content(&self, name: &str, current_epoch: u64) -> Option<ContentRef> {
        self.names.get(name).and_then(|record| {
            if record.expires_at > current_epoch {
                record.content
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
        let record = Self::slot_mut(&mut self.names, &mut self.name_tree, name)
            .ok_or(BnsError::InvalidName)?;
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

    /// Resolve a live `<label>.bud` name to its address record, or to its
    /// owner when the record is empty, or a live two-level
    /// `<sub_label>.<label>.bud` subdomain (failing closed if the parent
    /// `.bud` name is unknown or expired).
    pub fn resolve(&self, name: &str, current_epoch: u64) -> Option<Address> {
        if let Some(record) = self.names.get(name) {
            return if record.expires_at > current_epoch {
                Some(record.address.unwrap_or(record.owner))
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
        let record = Self::slot_mut(&mut self.names, &mut self.name_tree, name)
            .ok_or(BnsError::InvalidName)?;
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
                // The same value `resolve` answers: the address record, or
                // the owner when the record is empty.
                address: if expired {
                    None
                } else {
                    Some(record.address.unwrap_or(record.owner))
                },
                storage_root: if expired { None } else { record.storage_root },
                storage_domain_id: if expired {
                    None
                } else {
                    record.storage_domain_id
                },
                content: if expired { None } else { record.content },
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
        let rec = Self::slot_mut(&mut self.names, &mut self.name_tree, name)
            .ok_or(BnsError::InvalidName)?;
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
    fn extras_from_record(record: &NameRecord) -> crate::bns::types::BnsBranchExtras {
        crate::bns::types::BnsBranchExtras {
            address: record.address,
            consensus_domain_id: record.consensus_domain_id,
            storage_domain_id: record.storage_domain_id,
            storage_root_height: record.storage_root_height,
            subdomains: record.subdomains.clone(),
            records: record.records.clone(),
        }
    }

    /// The commitment over a disclosed extras pre-image (`BDLM_BNS_EXTRAS_V3`).
    ///
    /// The encoding is the one the leaf digest already used, so the digest of
    /// `Self::extras_from_record` equals [`Self::record_extras_digest`] field
    /// for field. A proof that ships its extras can therefore be checked
    /// against the header root instead of being believed.
    #[must_use]
    pub(crate) fn extras_digest(extras: &crate::bns::types::BnsBranchExtras) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_BNS_EXTRAS_V3");
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
        hasher.update((extras.subdomains.len() as u64).to_le_bytes());
        for (sub_label, sub) in &extras.subdomains {
            hasher.update((sub_label.len() as u64).to_le_bytes());
            hasher.update(sub_label.as_bytes());
            hasher.update(sub.owner.0);
            match sub.address {
                Some(address) => {
                    hasher.update([1u8]);
                    hasher.update(address.0);
                }
                None => hasher.update([0u8]),
            }
            // The label and the owner are hashed just above, and the leaf
            // that carries this digest names the parent, so the reference
            // is bound to one subdomain of one name.
            match sub.content {
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

    /// The commitment a leaf carries for the content of its name: the
    /// [`Bud3NameBinding`](crate::bns::bud3::Bud3NameBinding) digest over
    /// the name, the owner and the reference.
    #[must_use]
    pub fn content_binding(
        name: &str,
        owner: &Address,
        content: Option<ContentRef>,
    ) -> Option<[u8; 32]> {
        content.map(|content_ref| {
            crate::bns::bud3::Bud3NameBinding {
                name: name.to_string(),
                owner: *owner,
                content_ref,
            }
            .digest()
        })
    }

    /// Canonical per-name Merkle leaf digest (`BDLM_BNS_LEAF_V1`).
    #[must_use]
    fn compute_leaf_digest(
        name: &str,
        owner: &Address,
        expires_at: u64,
        content: Option<ContentRef>,
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
        match Self::content_binding(name, owner, content) {
            Some(digest) => {
                hasher.update([1u8]);
                hasher.update(digest);
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
            record.content,
            record.storage_root,
            extras,
        )
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

    /// Root of the sparse tree over the names (`[0u8; 32]` when empty).
    ///
    /// Key: `SHA-256("BDLM_BNS_KEY_V1" || name)`. Value: the record digest.
    /// See [`crate::bns::smt`] for the node rules.
    #[must_use]
    pub fn names_merkle_root(&self) -> [u8; 32] {
        self.name_tree.read(&self.names, smt::Tree::root)
    }

    /// Produce the per-name state proof: the path to the name's leaf when
    /// the name is held, otherwise the path to the empty slot or to the other
    /// name's leaf that stands where it would be.
    #[must_use]
    pub fn prove_name(&self, name: &str, current_epoch: u64) -> BnsStateProof {
        let meta_digest = self.meta_digest();
        let key = smt::key_of(name);
        let (names_root, path) = self
            .name_tree
            .read(&self.names, |tree| (tree.root(), tree.prove(&key)));
        let mut proof = BnsStateProof {
            name: name.to_string(),
            included: false,
            bns_root: Self::root_from_parts(meta_digest, names_root),
            meta_digest,
            names_count: self.names.len() as u64,
            epoch: current_epoch,
            entry: None,
            absence: None,
        };
        match (path.terminal, self.names.get(name)) {
            (smt::Terminal::Leaf(leaf), Some(rec)) => {
                proof.included = true;
                proof.entry = Some(BnsMerkleBranch {
                    name: rec.name.clone(),
                    owner: rec.owner,
                    address: rec.address,
                    expires_at: rec.expires_at,
                    content: rec.content,
                    storage_root: rec.storage_root,
                    extras_digest: Self::record_extras_digest(rec),
                    leaf,
                    siblings: path.siblings,
                    extras: Some(Self::extras_from_record(rec)),
                });
            }
            (smt::Terminal::Other(key, value), _) => {
                proof.absence = Some(BnsAbsenceProof {
                    siblings: path.siblings,
                    occupant: Some(BnsOccupiedSlot { key, value }),
                });
            }
            _ => {
                proof.absence = Some(BnsAbsenceProof {
                    siblings: path.siblings,
                    occupant: None,
                });
            }
        }
        proof
    }

    /// Verify a [`BnsStateProof`] against `expected_bns_root` at `current_epoch`,
    /// returning `Ok(Some(resolved_entry))` on valid live inclusion, `Ok(None)`
    /// on verified non-existence, and `Err(reason)` if forged or expired.
    ///
    /// # Errors
    ///
    /// Returns a human-readable refusal reason if any digest, tree path or
    /// expiry check fails.
    pub fn verify_state_proof<'a>(
        proof: &'a BnsStateProof,
        expected_bns_root: &[u8; 32],
        current_epoch: u64,
    ) -> Result<Option<&'a BnsMerkleBranch>, String> {
        if &proof.bns_root != expected_bns_root {
            return Err("proof bns_root does not match expected header bns_root".into());
        }
        let check_branch = |branch: &BnsMerkleBranch| -> Result<[u8; 32], String> {
            // The extras digest is a commitment; `address`, the records and
            // the subdomains only mean something if
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
                branch.content,
                branch.storage_root,
                branch.extras_digest,
            );
            if recomputed_leaf != branch.leaf {
                return Err("branch leaf digest mismatch".into());
            }
            smt::root_of_path(
                &smt::key_of(&branch.name),
                &smt::Path {
                    terminal: smt::Terminal::Leaf(recomputed_leaf),
                    siblings: branch.siblings.clone(),
                },
            )
        };

        if proof.included {
            if proof.absence.is_some() {
                return Err("inclusion proof must not carry an absence path".into());
            }
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
            // The path of the queried name must end in an empty slot or in
            // another name's leaf, and fold to the header root. A held name
            // has its own leaf at the end of its path, so no such path exists
            // for it.
            let absence = proof
                .absence
                .as_ref()
                .ok_or_else(|| "non-inclusion proof carries no absence path".to_string())?;
            let terminal = absence
                .occupant
                .as_ref()
                .map_or(smt::Terminal::Empty, |slot| {
                    smt::Terminal::Other(slot.key, slot.value)
                });
            let names_root = smt::root_of_path(
                &smt::key_of(&proof.name),
                &smt::Path {
                    terminal,
                    siblings: absence.siblings.clone(),
                },
            )?;
            if Self::root_from_parts(proof.meta_digest, names_root) != *expected_bns_root {
                return Err("absence path did not reproduce expected bns_root".into());
            }
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
        assert!(gone.content.is_none() && gone.address.is_none());
    }

    #[test]
    fn root_changes_when_record_mutates() {
        let mut reg = BnsRegistry::new();
        let owner = Address::from([1u8; 32]);
        reg.register("alice.bud".into(), owner, 1, 10).unwrap();
        let root_before = reg.root();
        let mut bud3 = crate::storage::bud3::registry::Bud3Registry::default();
        let content = crate::bns::bud3::fixtures::public_object(&mut bud3, owner.0, b"alice");
        reg.set_content("alice.bud", &owner, &bud3, Some(content), 1)
            .unwrap();
        let root_bound = reg.root();
        assert_ne!(root_before, root_bound);
        reg.set_content("alice.bud", &owner, &bud3, None, 1)
            .unwrap();
        assert_eq!(root_before, reg.root());
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
        use crate::bns::bud3::BnsBud3Error;

        let owner = Address::from([0x31; 32]);
        let stranger = Address::from([0x32; 32]);
        let mut bud3 = crate::storage::bud3::registry::Bud3Registry::default();
        let content =
            crate::bns::bud3::fixtures::public_object(&mut bud3, owner.0, b"site-index-html");

        let mut reg = BnsRegistry::new();
        reg.register("portal.bud".into(), owner, 1, 10).unwrap();
        assert_eq!(
            reg.set_content("portal.bud", &stranger, &bud3, Some(content), 2),
            Err(BnsBud3Error::Bns(BnsError::NotOwner))
        );
        // A reference to an object the chain does not hold is refused.
        let unknown = ContentRef {
            object_commitment: [0xEE; 32],
            ..content
        };
        assert_eq!(
            reg.set_content("portal.bud", &owner, &bud3, Some(unknown), 2),
            Err(BnsBud3Error::UnknownObject)
        );
        // So is a reference whose content id is not the one of the object.
        let wrong_id = ContentRef {
            content_id: crate::storage::bud3::content_id::ContentId::public(b"other bytes"),
            ..content
        };
        assert_eq!(
            reg.set_content("portal.bud", &owner, &bud3, Some(wrong_id), 2),
            Err(BnsBud3Error::ContentIdMismatch)
        );
        assert_eq!(reg.resolve_content("portal.bud", 5), None);

        reg.set_content("portal.bud", &owner, &bud3, Some(content), 2)
            .unwrap();
        assert_eq!(reg.resolve_content("portal.bud", 5), Some(content));
        assert_eq!(reg.resolve_content("portal.bud", 11), None);
    }

    /// The proof discloses the content, and the leaf commits to it. A proof
    /// whose content was swapped after the fact does not verify.
    #[test]
    fn bns_proof_binds_the_content_of_the_name() {
        let owner = Address::from([0x35; 32]);
        let mut bud3 = crate::storage::bud3::registry::Bud3Registry::default();
        let content = crate::bns::bud3::fixtures::public_object(&mut bud3, owner.0, b"first site");
        let other = crate::bns::bud3::fixtures::public_object(&mut bud3, owner.0, b"second site");

        let mut reg = BnsRegistry::new();
        reg.register("portal.bud".into(), owner, 1, 10).unwrap();
        reg.set_content("portal.bud", &owner, &bud3, Some(content), 2)
            .unwrap();
        let root = reg.root();
        let proof = reg.prove_name("portal.bud", 2);
        assert_eq!(proof.entry.as_ref().and_then(|e| e.content), Some(content));
        assert!(BnsRegistry::verify_state_proof(&proof, &root, 2).is_ok());

        let mut swapped = proof.clone();
        if let Some(entry) = swapped.entry.as_mut() {
            entry.content = Some(other);
        }
        assert!(BnsRegistry::verify_state_proof(&swapped, &root, 2).is_err());

        let mut dropped = proof;
        if let Some(entry) = dropped.entry.as_mut() {
            entry.content = None;
        }
        assert!(BnsRegistry::verify_state_proof(&dropped, &root, 2).is_err());
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

    #[test]
    fn reregistration_replaces_old_expiry_row_and_enforces_max_names() {
        let mut live = BnsRegistry::new();
        live.max_names = 2;
        let alice = Address::from([0x11; 32]);
        let bob = Address::from([0x22; 32]);

        // Register alice.bud at epoch 0 (expires 10, grace ends 10 + GRACE_PERIOD)
        // and bob.bud at epoch 0 (expires 500).
        live.register("alice.bud".into(), alice, 0, 10).unwrap();
        live.register("bob.bud".into(), bob, 0, 500).unwrap();

        // Same-owner re-registration during grace (epoch 12, duration 500) must
        // replace the old expiry index row rather than leaving a stale entry.
        live.register("alice.bud".into(), alice, 12, 500).unwrap();
        assert_eq!(live.expired_by_grace_end.len(), live.names.len());

        // Snapshot-restored node has a freshly rebuilt index.
        let mut rebuilt = live.clone();
        rebuilt.rebuild_expiry_index();
        assert_eq!(live.expired_by_grace_end, rebuilt.expired_by_grace_end);

        // Past the old grace end, both alice.bud and bob.bud are still live, so
        // a third registration must be refused on both live and rebuilt nodes.
        let past_old_grace = 10 + BnsRegistry::GRACE_PERIOD + 1;
        assert_eq!(
            live.register("carol.bud".into(), alice, past_old_grace, 10),
            Err(BnsError::NameTaken)
        );
        assert_eq!(
            rebuilt.register("carol.bud".into(), alice, past_old_grace, 10),
            Err(BnsError::NameTaken)
        );
        assert_eq!(live.names.len(), live.max_names);
    }
}
