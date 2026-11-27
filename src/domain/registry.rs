use crate::core::hash::hash_fields_bytes;
use crate::crypto::facts::CryptoFacts;
use crate::domain::types::{ConsensusDomain, DomainId, DomainStatus, Hash32};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MIN_DOMAIN_OPERATOR_BOND: u64 = 10_000;

/// Most zk programs one domain may allow at the same time. Each entry is hashed into the
/// registry leaf and checked on proof submission.
///
/// Convenience: pub so a domain operator can refuse past the same
/// allowlist bound the registry enforces in this module.
pub const MAX_ZK_PROGRAMS_PER_DOMAIN: usize = 64;

/// The maximum number of domains that may be kept registered.
///
/// # Why a ceiling is needed
///
/// Registration is permissionless: anyone who posts enough bond can open a domain. The bond
/// is itself a cost but **not a bound** - it is a refundable
/// deposit, not a spent fee. When the unbond period expires the operator
/// gets the money back, so for someone with enough capital the net cost of opening a domain
/// is only that the money stays locked for that period.
///
/// Every registered domain adds to the chain's **per-block** work: [`ConsensusDomainRegistry::root`]
/// computes a leaf hash for every domain and this root is recomputed in every
/// block. So the registration count directly determines the work every validator does in every
/// block, and that work is paid **by the network**, not by the domain
/// owner. Because the bond is refundable, an attacker with capital can raise that work
/// permanently and still get their money back.
///
/// The ceiling breaks that combination: the bond stays refundable, but the total
/// load is now bounded from above by a constant. A number within `u16` width was chosen
/// (4096, not 65 536): a Merkle tree with 4096 leaves is 12 levels deep and recomputing it in
/// every block is a measurable cost; anything above that grows validator cost without
/// corresponding to any legitimate need.
///
/// # What happens when the ceiling is reached
///
/// New registrations are refused. That forces a governance decision - raising the
/// or retiring unused domains - and that decision
/// becomes visible. From a silently growing cost to a discussed decision.
///
/// Retired domains count too: as long as the leaf stands in the tree, the root
/// and the proof size count against it. To be excluded from the count a domain
/// has to be **removed** from the registry, which is a separate decision and a
/// separate path.
pub const MAX_REGISTERED_DOMAINS: usize = 4096;

/// Maximum number of non-retired consensus domains a single operator account
/// may keep registered concurrently. Prevents one funded account from
/// exhausting the global [`MAX_REGISTERED_DOMAINS`] table.
pub const MAX_ACTIVE_DOMAINS_PER_OPERATOR: usize = 32;

/// Number of global blocks without any observed commitment progress after
/// which an inactive domain is eligible to be retired and reclaimed so its
/// registry slot returns to the shared pool.
pub const DOMAIN_INACTIVITY_RETIREMENT_BLOCKS: u64 = 100_000;

// Cross-layer domain capacity invariants: every downstream catalog, sentry,
// finality certificate, and light-proof bundle ceiling derives from or stays
// bounded by `MAX_REGISTERED_DOMAINS` so no layer can silently exclude an
// admitted domain.
const _: () = {
    assert!(MAX_REGISTERED_DOMAINS == 4096);
    assert!(MAX_ACTIVE_DOMAINS_PER_OPERATOR > 0);
    assert!(MAX_ACTIVE_DOMAINS_PER_OPERATOR < MAX_REGISTERED_DOMAINS);
    assert!(MAX_ZK_PROGRAMS_PER_DOMAIN > 0);
    assert!(crate::unification::domain_catalog::MAX_UNIVERSAL_DOMAINS == MAX_REGISTERED_DOMAINS);
    assert!(crate::cross_domain::external::sentry::MAX_SENTRY_DOMAINS == MAX_REGISTERED_DOMAINS);
    assert!(crate::aggregation::universal_light_proof::MAX_ULP_DOMAINS > 0);
    assert!(crate::aggregation::universal_light_proof::MAX_ULP_DOMAINS <= MAX_REGISTERED_DOMAINS);
};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConsensusDomainRegistry {
    domains: BTreeMap<DomainId, ConsensusDomain>,
    /// The schemes each domain's adapter checked while finalizing its
    /// commitments. Written only where a commitment advances a
    /// domain, and folded into [`Self::progress_root`] once non-empty.
    #[serde(default)]
    observed: BTreeMap<DomainId, CryptoFacts>,
    /// Canonical CAIP-2 chain reference bound to each registered domain.
    /// Kept as the single source of truth (committed into [`Self::root`]) so
    /// forward and reverse lookups can never diverge across snapshots.
    #[serde(default)]
    caip2_by_domain: BTreeMap<DomainId, String>,
    /// Global block height at which each registered domain last registered or
    /// advanced with a verified commitment. Used to retire and reclaim stale
    /// slots once inactive for [`DOMAIN_INACTIVITY_RETIREMENT_BLOCKS`].
    #[serde(default)]
    last_activity_block: BTreeMap<DomainId, u64>,
}

/// Validates and normalizes a CAIP-2 Final chain identifier (`namespace:reference`).
///
/// Enforces the official CAIP-2 Final grammar:
/// - `namespace`: `[-a-z0-9]{3,8}`
/// - `reference`: `[-_a-zA-Z0-9]{1,32}`
fn normalize_caip2(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    let Some((ns, reference)) = trimmed.split_once(':') else {
        return Err(format!("CAIP-2 reference '{trimmed}' must contain ':'"));
    };
    if !(3..=8).contains(&ns.len()) {
        return Err(format!("CAIP-2 namespace '{ns}' must be 3..=8 characters"));
    }
    if !(1..=32).contains(&reference.len()) || reference.contains(':') {
        return Err(format!(
            "CAIP-2 reference '{reference}' must be 1..=32 characters without ':'"
        ));
    }
    if !ns
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || !reference
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(format!(
            "CAIP-2 reference '{trimmed}' contains disallowed characters"
        ));
    }
    Ok(trimmed.to_string())
}

impl ConsensusDomainRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            domains: BTreeMap::new(),
            observed: BTreeMap::new(),
            caip2_by_domain: BTreeMap::new(),
            last_activity_block: BTreeMap::new(),
        }
    }

    /// Binds a unique CAIP-2 chain reference to an already registered domain.
    ///
    /// # Errors
    ///
    /// Returns an error without mutating state if `domain_id` is unknown, the
    /// CAIP-2 string is malformed, the CAIP-2 reference is already bound to a
    /// different domain, or `domain_id` is already bound to a different CAIP-2.
    /// Validates whether `caip2` can be bound to `domain_id` without mutating
    /// state (used by callers that must pre-check atomically before applying
    /// sibling registry writes).
    ///
    /// # Errors
    ///
    /// Returns an error if `domain_id` is unknown, `caip2` violates CAIP-2
    /// Final syntax, `caip2` is claimed by another domain, or `domain_id` is
    /// already bound to a different CAIP-2 reference.
    pub fn validate_caip2_binding(
        &self,
        domain_id: DomainId,
        caip2: &str,
    ) -> Result<String, String> {
        let domain = self
            .domains
            .get(&domain_id)
            .ok_or_else(|| format!("Domain {domain_id} is not registered"))?;
        let normalized = normalize_caip2(caip2)?;
        if let Some(existing_ref) = self.caip2_by_domain.get(&domain_id) {
            if existing_ref != &normalized {
                return Err(format!(
                    "Domain {domain_id} is already bound to CAIP-2 '{existing_ref}'"
                ));
            }
            return Ok(normalized);
        }
        if domain.status != DomainStatus::Active {
            return Err(format!(
                "Domain {domain_id} must be Active to bind CAIP-2 '{normalized}' (current: {:?})",
                domain.status
            ));
        }
        if let Some(existing_domain) = self.domain_id_by_caip2(&normalized) {
            if existing_domain != domain_id {
                return Err(format!(
                    "CAIP-2 reference '{normalized}' is already registered to domain {existing_domain}"
                ));
            }
        }
        Ok(normalized)
    }

    pub fn bind_caip2(&mut self, domain_id: DomainId, caip2: &str) -> Result<(), String> {
        let normalized = self.validate_caip2_binding(domain_id, caip2)?;
        self.caip2_by_domain.insert(domain_id, normalized);
        Ok(())
    }

    /// Atomically registers a new consensus domain together with its unique
    /// CAIP-2 identity. If the CAIP-2 reference is invalid or already claimed
    /// by another domain, registration is refused with zero state mutation.
    ///
    /// # Errors
    ///
    /// Returns an error if the CAIP-2 is malformed or duplicated, or if domain
    /// registration validation fails.
    /// Convenience: kept for atomic domain+CAIP-2 registration callers and CLI.
    pub fn register_with_caip2(
        &mut self,
        domain: ConsensusDomain,
        caip2: &str,
    ) -> Result<(), String> {
        let normalized = normalize_caip2(caip2)?;
        if let Some(existing_domain) = self.domain_id_by_caip2(&normalized) {
            return Err(format!(
                "CAIP-2 reference '{normalized}' is already registered to domain {existing_domain}"
            ));
        }
        let id = domain.id;
        self.register(domain)?;
        self.caip2_by_domain.insert(id, normalized);
        Ok(())
    }

    /// Resolves a canonical CAIP-2 reference to its unique registered `DomainId`.
    #[must_use]
    pub fn domain_id_by_caip2(&self, caip2: &str) -> Option<DomainId> {
        let trimmed = caip2.trim();
        self.caip2_by_domain
            .iter()
            .find_map(|(&id, existing)| (existing == trimmed).then_some(id))
    }

    /// Returns the canonical CAIP-2 reference bound to `domain_id`, if any.
    #[must_use]
    pub fn caip2_for_domain(&self, domain_id: DomainId) -> Option<&str> {
        self.caip2_by_domain.get(&domain_id).map(String::as_str)
    }

    /// Records that `domain_id` registered or delivered a verified commitment
    /// at global `block_height`, refreshing its liveness lease.
    pub fn note_activity(&mut self, domain_id: DomainId, block_height: u64) {
        if self.domains.contains_key(&domain_id) {
            let entry = self.last_activity_block.entry(domain_id).or_insert(0);
            if block_height > *entry {
                *entry = block_height;
            }
        }
    }

    /// Retires and reclaims non-frozen domains whose recorded activity has been
    /// stale for at least `inactivity_window` global blocks, freeing their
    /// registry slots and CAIP-2 bindings for new registrations while keeping
    /// security-frozen (`DomainStatus::Frozen`) domains permanently quarantined.
    pub fn reclaim_inactive_domains(
        &mut self,
        current_block_height: u64,
        inactivity_window: u64,
    ) -> Vec<DomainId> {
        if inactivity_window == 0 {
            return Vec::new();
        }
        let stale: Vec<DomainId> = self
            .last_activity_block
            .iter()
            .filter_map(|(&id, &last_seen)| {
                let status = self.domains.get(&id)?.status;
                if status == DomainStatus::Frozen {
                    return None;
                }
                if current_block_height.saturating_sub(last_seen) >= inactivity_window {
                    Some(id)
                } else {
                    None
                }
            })
            .collect();
        for id in &stale {
            self.domains.remove(id);
            self.observed.remove(id);
            self.last_activity_block.remove(id);
            self.caip2_by_domain.remove(id);
        }
        stale
    }

    /// Adds what an adapter checked for a commitment of `id`.
    pub fn record_observed(&mut self, id: DomainId, facts: &CryptoFacts) {
        if facts.is_empty() || !self.domains.contains_key(&id) {
            return;
        }
        self.observed.entry(id).or_default().merge(facts);
    }

    /// The schemes the adapter of `id` has checked so far, empty when none.
    #[must_use]
    pub fn observed(&self, id: DomainId) -> CryptoFacts {
        self.observed.get(&id).cloned().unwrap_or_default()
    }

    /// Restore a domain loaded back from storage.
    ///
    /// Persistence is not registration: a domain that was frozen before a
    /// restart must come back frozen. Routing the load through `register`
    /// dropped it at the register-as-Active rule and genesis bootstrap then
    /// re-registered the same id as Active, so a freeze silently evaporated
    /// across every restart. Every other registration shape check still
    /// runs: a malformed stored record is refused here exactly as a
    /// malformed fresh registration would be.
    /// WIRING: domain surface - the producer/registry doors that read it land with their wiring.
    pub fn restore_persisted(&mut self, domain: ConsensusDomain) -> Result<(), String> {
        self.register_inner(domain, false)
    }

    /// Performs the requested operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn register(&mut self, domain: ConsensusDomain) -> Result<(), String> {
        self.register_inner(domain, true)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.domains.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    fn register_inner(
        &mut self,
        domain: ConsensusDomain,
        require_active: bool,
    ) -> Result<(), String> {
        if self.domains.contains_key(&domain.id) {
            return Err(format!("Domain {} is already registered", domain.id));
        }
        // The count comes after the identity check: a request arriving with an already registered id
        // must not occupy the ceiling, because it adds no new leaf.
        if self.domains.len() >= MAX_REGISTERED_DOMAINS {
            return Err(format!(
                "Domain {} rejected: registry is at its ceiling of {MAX_REGISTERED_DOMAINS} \
                 domains. Every registered domain costs every validator work in every block \
                 (the registry root is rebuilt per block), and the operator bond is refundable, \
                 so nothing else bounds that cost. Retire an unused domain or raise the ceiling \
                 through governance.",
                domain.id
            ));
        }
        // Registration can provide a pre-populated allowlist; applying the bound only
        // in `allow_zk_program` lets a newly registered domain bypass that bound.
        // Duplicate entries are also ambiguous: the leaf hash deduplicates them,
        // while the live registry retains them and counts them against the cap.
        if domain.zk_program_allowlist.len() > MAX_ZK_PROGRAMS_PER_DOMAIN {
            return Err(format!(
                "Domain {} exceeds the zk program allowlist limit of {MAX_ZK_PROGRAMS_PER_DOMAIN}",
                domain.id
            ));
        }
        let mut programs = std::collections::BTreeSet::new();
        for program in &domain.zk_program_allowlist {
            if !programs.insert(program) {
                return Err(format!(
                    "Domain {} has a duplicate zk program in its allowlist",
                    domain.id
                ));
            }
        }
        if !domain.has_operator_bond(MIN_DOMAIN_OPERATOR_BOND) {
            return Err(format!(
                "Domain {} requires operator identity and minimum bond {}",
                domain.id, MIN_DOMAIN_OPERATOR_BOND
            ));
        }
        if domain.operator == Some(crate::core::address::Address::zero()) {
            return Err(format!("Domain {} has invalid zero operator", domain.id));
        }
        if require_active {
            if let Some(op) = domain.operator {
                let held = self
                    .domains
                    .values()
                    .filter(|d| d.operator == Some(op) && d.status != DomainStatus::Retired)
                    .count();
                if held >= MAX_ACTIVE_DOMAINS_PER_OPERATOR {
                    return Err(format!(
                        "Domain {} rejected: operator already holds {held} active domains                          (quota {MAX_ACTIVE_DOMAINS_PER_OPERATOR}); retire an unused domain first",
                        domain.id
                    ));
                }
            }
        }
        // A new registration starts Active. Frozen and Retired are reached
        // only through `transition_status_checked`; registering straight into
        // them would skip the lifecycle guard. Restoring persisted
        // state is the one caller exempt from this, by the argument on
        // `restore_persisted`.
        if require_active && domain.status != DomainStatus::Active {
            return Err(format!(
                "Domain {} must register as Active, not {:?}",
                domain.id, domain.status
            ));
        }

        let pow_family_adapter = domain.finality_adapter
            == crate::domain::types::POW_HEADER_CHAIN_ADAPTER
            || domain.finality_adapter == crate::domain::types::BITCOIN_SPV_ADAPTER;
        if pow_family_adapter {
            if domain.kind != crate::domain::types::ConsensusKind::PoW {
                return Err(format!(
                    "Domain {} uses the PoW header adapter with a non-PoW consensus kind",
                    domain.id
                ));
            }
            domain
                .pow_parameters
                .as_ref()
                .ok_or_else(|| {
                    format!(
                        "Domain {} uses the PoW header adapter without pow_parameters",
                        domain.id
                    )
                })?
                .validate(domain.min_confirmations)?;
        } else if domain.pow_parameters.is_some() {
            return Err(format!(
                "Domain {} supplies pow_parameters for incompatible adapter {}",
                domain.id, domain.finality_adapter
            ));
        } else if domain.min_confirmations > 1 {
            // `min_confirmations` is a header-chain depth. Exactly one of the
            // seven finality adapters reads it - the PoW one, at
            // `observed_depth < domain.min_confirmations`. The other six never
            // look at the field, so a value above the no-op default was
            // accepted, stored, hashed into the registry, and then ignored.
            //
            // That is worse than not having the field: an operator reading
            // `"min_confirmations": 3` on a PoS domain in genesis has every
            // reason to believe three confirmations are required, and nothing
            // in the logs would ever say otherwise. Rejecting at registration
            // is the same fail-fast-at-the-edge rule the pow_parameters branch
            // above already applies.
            //
            // `1` stays allowed because it is the historical default in the
            // shipped genesis files and means the same thing as "no depth
            // requirement" for an adapter that finalises on a quorum.
            return Err(format!(
                "Domain {} sets min_confirmations={} but its adapter {} never reads it; \
                 header-chain depth only applies to {} and {}",
                domain.id,
                domain.min_confirmations,
                domain.finality_adapter,
                crate::domain::types::POW_HEADER_CHAIN_ADAPTER,
                crate::domain::types::BITCOIN_SPV_ADAPTER
            ));
        }

        // (B.U.D. Storage ConsensusDomain, vision)
        // A `StorageAttestation` domain MUST use the dedicated
        // `STORAGE_ATTESTATION_ADAPTER` finality adapter, and the
        // Parameters must validate. This is the same fail-fast-at-the-edge
        // Pattern as the PoW header-chain branch above.
        if let crate::domain::types::ConsensusKind::StorageAttestation(params) = &domain.kind {
            if domain.finality_adapter != crate::domain::types::STORAGE_ATTESTATION_ADAPTER {
                return Err(format!(
                    "Domain {} uses StorageAttestation with non-storage finality adapter '{}' \
                     (expected '{}')",
                    domain.id,
                    domain.finality_adapter,
                    crate::domain::types::STORAGE_ATTESTATION_ADAPTER
                ));
            }
            if domain.operator_bond < params.min_operator_bond {
                return Err(format!(
                    "Domain {} operator_bond {} below StorageAttestation min_operator_bond {}",
                    domain.id, domain.operator_bond, params.min_operator_bond
                ));
            }
            params.validate()?;
        } else if domain.finality_adapter == crate::domain::types::STORAGE_ATTESTATION_ADAPTER {
            return Err(format!(
                "Domain {} uses the storage-attestation adapter with a non-StorageAttestation \
                 consensus kind",
                domain.id
            ));
        }

        self.domains.insert(domain.id, domain);
        Ok(())
    }

    #[must_use]
    pub fn get(&self, id: DomainId) -> Option<&ConsensusDomain> {
        self.domains.get(&id)
    }

    pub fn get_mut(&mut self, id: DomainId) -> Option<&mut ConsensusDomain> {
        self.domains.get_mut(&id)
    }

    /// Performs the requested operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn set_status(&mut self, id: DomainId, status: DomainStatus) -> Result<(), String> {
        let domain = self
            .domains
            .get_mut(&id)
            .ok_or_else(|| format!("Unknown domain {id}"))?;
        domain.status = status;
        Ok(())
    }

    /// Lifecycle guard: use this for governance/operator-driven
    /// Transitions. `set_status` remains for migration/tests, while this helper
    /// Prevents accidental Active→Retired jumps and makes Retired terminal.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn transition_status_checked(
        &mut self,
        id: DomainId,
        next: DomainStatus,
    ) -> Result<(), String> {
        let domain = self
            .domains
            .get_mut(&id)
            .ok_or_else(|| format!("Unknown domain {id}"))?;
        let current = domain.status;
        let allowed = matches!(
            (current, next),
            (DomainStatus::Active, DomainStatus::Frozen)
                | (DomainStatus::Frozen, DomainStatus::Active)
                | (DomainStatus::Frozen, DomainStatus::Retired)
        );
        if !allowed {
            return Err(format!(
                "Illegal domain lifecycle transition for {id}: {current:?} -> {next:?}"
            ));
        }
        domain.status = next;
        Ok(())
    }

    /// Adds a zk program to the domain allowlist.
    ///
    /// # Why this path exists
    ///
    /// `zk_program_allowlist` is read in `submit_zk_proof` and an empty list means
    /// fail-closed - the right default. But nothing touched the **insertion**
    /// side of the list: `Vec::new()` is written when the domain is created and
    /// no other code path ever reached it. So there could never be anything
    /// behind the gate; a list that is read but can never be filled gives a
    /// reader the impression that "programs are managed" while they are not.
    ///
    /// # Errors
    ///
    /// If the domain does not exist, or the program is already in the list. The second case could have been
    /// passed silently, but if "it was already there" and "it was just added" give the same answer,
    /// a governance operation cannot verify its own effect.
    pub fn allow_zk_program(&mut self, id: DomainId, program: Hash32) -> Result<(), String> {
        let domain = self
            .domains
            .get_mut(&id)
            .ok_or_else(|| format!("Unknown domain {id}"))?;
        if domain.zk_program_allowlist.contains(&program) {
            return Err(format!(
                "Program {} is already on the allowlist of domain {id}",
                hex::encode(program)
            ));
        }
        if domain.zk_program_allowlist.len() >= MAX_ZK_PROGRAMS_PER_DOMAIN {
            return Err(format!(
                "Domain {id} already allows {MAX_ZK_PROGRAMS_PER_DOMAIN} zk programs; revoke one first"
            ));
        }
        domain.zk_program_allowlist.push(program);
        Ok(())
    }

    /// Removes a zk program from the allowlist.
    ///
    /// # Why revocation is mandatory
    ///
    /// An admitted program holds the right to advance the state of the domain.
    /// If a defect is later found in that program - a field the proof system
    /// does not constrain, a wrong transition rule - the only defence is to take
    /// it off the list. An allowlist with an insertion path but no removal path
    /// is a one-way door: what gets in can never be taken out, and once that
    /// program is known to be wrong the only thing left to do would be to freeze
    /// the whole domain.
    ///
    /// Revocation is **not retroactive**: proofs produced and already accepted
    /// before the removal stay valid. The history of the chain is not rewritten;
    /// what changes is what will be accepted from now on.
    ///
    /// # Errors
    ///
    /// If the domain does not exist, or the program is not on the list.
    pub fn revoke_zk_program(&mut self, id: DomainId, program: &Hash32) -> Result<(), String> {
        let domain = self
            .domains
            .get_mut(&id)
            .ok_or_else(|| format!("Unknown domain {id}"))?;
        let before = domain.zk_program_allowlist.len();
        domain.zk_program_allowlist.retain(|p| p != program);
        if domain.zk_program_allowlist.len() == before {
            return Err(format!(
                "Program {} is not on the allowlist of domain {id}, so there is nothing to revoke",
                hex::encode(program)
            ));
        }
        Ok(())
    }

    /// Freeze every active native domain whose class is classical (
    /// the quantum alarm at Isolate). The class is the observed one, or the
    /// one the consensus kind implies when nothing was observed yet. Returns
    /// the ids that moved, in id order.
    pub fn freeze_classical_domains(&mut self) -> Vec<DomainId> {
        use crate::crypto::facts::QuantumClass;
        let mut frozen = Vec::new();
        let ids: Vec<DomainId> = self.domains.keys().copied().collect();
        for id in ids {
            let Some(domain) = self.domains.get(&id) else {
                continue;
            };
            if domain.status != DomainStatus::Active {
                continue;
            }
            let class = self.observed(id).quantum_class().unwrap_or_else(|| {
                crate::settlement::pq_anchor::domain_quantum_class(&domain.kind)
            });
            if class == QuantumClass::Classical {
                if let Some(domain) = self.domains.get_mut(&id) {
                    domain.status = DomainStatus::Frozen;
                    frozen.push(id);
                }
            }
        }
        frozen
    }

    pub fn active_domains(&self) -> impl Iterator<Item = &ConsensusDomain> {
        self.domains
            .values()
            .filter(|domain| domain.status == DomainStatus::Active)
    }

    #[must_use]
    pub fn domains(&self) -> Vec<ConsensusDomain> {
        self.domains.values().cloned().collect()
    }

    pub fn root(&self) -> Hash32 {
        let leaves: Vec<Hash32> = self
            .domains
            .values()
            .map(|domain| {
                let leaf = domain_leaf_hash(domain);
                match self.caip2_by_domain.get(&domain.id) {
                    Some(caip2) => {
                        hash_fields_bytes(&[b"BDLM_DOMAIN_CAIP2_LEAF_V1", &leaf, caip2.as_bytes()])
                    }
                    None => leaf,
                }
            })
            .collect();
        crate::settlement::commitment_tree::merkle_root(&leaves)
    }

    /// The committed progress of every domain: the height and hash of its
    /// last commitment, in id order. The registry leaf binds a domain's
    /// rules, not how far it has advanced; the settlement root binds this
    /// digest, so two nodes that disagree on a domain's progress hold
    /// different state roots.
    #[must_use]
    pub fn progress_root(&self) -> Hash32 {
        let leaves: Vec<Hash32> = self
            .domains
            .values()
            .map(|domain| {
                let base = hash_fields_bytes(&[
                    b"BDLM_DOMAIN_PROGRESS_LEAF_V1",
                    &domain.id.to_le_bytes(),
                    &domain.last_committed_height.to_le_bytes(),
                    &domain.last_committed_hash,
                ]);
                // A domain that never reported a fact keeps its earlier leaf
                // byte for byte.
                match self.observed.get(&domain.id) {
                    Some(facts) if !facts.is_empty() => match bincode::serialize(facts) {
                        Ok(bytes) => {
                            hash_fields_bytes(&[b"BDLM_DOMAIN_PROGRESS_LEAF_V2", &base, &bytes])
                        }
                        Err(_) => hash_fields_bytes(&[b"BDLM_DOMAIN_FACTS_UNENCODABLE_V1", &base]),
                    },
                    _ => base,
                }
            })
            .collect();
        crate::settlement::commitment_tree::merkle_root(&leaves)
    }
}

/// A domain with a zk program allowlist or a committed plugin code hash gets a V4 leaf that
/// mixes both in. Other domains keep their earlier leaf byte for byte.
#[must_use]
pub fn domain_leaf_hash(domain: &ConsensusDomain) -> Hash32 {
    let base = base_domain_leaf_hash(domain);
    let leaf = if domain.zk_program_allowlist.is_empty() && domain.plugin_code_hash.is_none() {
        base
    } else {
        let mut allowlist = domain.zk_program_allowlist.clone();
        allowlist.sort();
        allowlist.dedup();
        let mut allowlist_bytes = Vec::new();
        for program in &allowlist {
            allowlist_bytes.extend_from_slice(program);
        }
        let plugin = domain.plugin_code_hash.unwrap_or_default();
        hash_fields_bytes(&[
            b"BDLM_DOMAIN_REGISTRY_LEAF_V4",
            &base,
            &(allowlist.len() as u64).to_le_bytes(),
            &allowlist_bytes,
            &[u8::from(domain.plugin_code_hash.is_some())],
            &plugin,
        ])
    };
    if domain.genesis_state_root == [0u8; 32] {
        leaf
    } else {
        hash_fields_bytes(&[
            b"BDLM_DOMAIN_REGISTRY_LEAF_V5",
            &leaf,
            &domain.genesis_state_root,
        ])
    }
}

fn base_domain_leaf_hash(domain: &ConsensusDomain) -> Hash32 {
    let kind = domain.kind.as_bytes();
    let status = match domain.status {
        DomainStatus::Active => b"active".as_slice(),
        DomainStatus::Frozen => b"frozen".as_slice(),
        DomainStatus::Retired => b"retired".as_slice(),
    };
    let block_scheme = domain.block_hash_scheme.as_bytes();
    let state_scheme = domain.state_root_scheme.as_bytes();
    let tx_scheme = domain.tx_root_scheme.as_bytes();
    let operator = domain
        .operator
        .map(|address| address.as_bytes().to_vec())
        .unwrap_or_default();

    if let Some(params) = &domain.pow_parameters {
        let mut pow_parameters = Vec::with_capacity(4 + 4 + 16 + 4);
        pow_parameters.extend_from_slice(&params.min_difficulty_bits.to_le_bytes());
        pow_parameters.extend_from_slice(&params.max_difficulty_bits.to_le_bytes());
        pow_parameters.extend_from_slice(&params.min_cumulative_work.to_le_bytes());
        pow_parameters.extend_from_slice(&params.max_headers.to_le_bytes());
        hash_fields_bytes(&[
            b"BDLM_DOMAIN_REGISTRY_LEAF_V2",
            &domain.id.to_le_bytes(),
            &kind,
            status,
            &domain.domain_chain_id.to_le_bytes(),
            &operator,
            &domain.operator_bond.to_le_bytes(),
            &domain.config_hash,
            &domain.validator_set_hash,
            domain.finality_adapter.as_bytes(),
            &domain.min_confirmations.to_le_bytes(),
            &pow_parameters,
            &[u8::from(domain.bridge_enabled)],
            &block_scheme,
            &state_scheme,
            &tx_scheme,
        ])
    } else if let crate::domain::types::ConsensusKind::StorageAttestation(storage) = &domain.kind {
        // B.U.D. storage domains get a V3 leaf that mixes the
        // Storage parameters into the leaf. Without this, two storage domains
        // With different chunk_size / challenge_interval would hash to the
        // Same leaf and the registry root would no longer be a sound
        // Commitment to the per-domain parameters.
        let storage_params = crate::domain::storage_params::storage_params_bytes(storage);
        hash_fields_bytes(&[
            b"BDLM_DOMAIN_REGISTRY_LEAF_V3",
            &domain.id.to_le_bytes(),
            &kind,
            status,
            &domain.domain_chain_id.to_le_bytes(),
            &operator,
            &domain.operator_bond.to_le_bytes(),
            &domain.config_hash,
            &domain.validator_set_hash,
            domain.finality_adapter.as_bytes(),
            &domain.min_confirmations.to_le_bytes(),
            &storage_params,
            &[u8::from(domain.bridge_enabled)],
            &block_scheme,
            &state_scheme,
            &tx_scheme,
        ])
    } else {
        // Preserve the exact V1 leaf for every pre- domain.
        hash_fields_bytes(&[
            b"BDLM_DOMAIN_REGISTRY_LEAF_V1",
            &domain.id.to_le_bytes(),
            &kind,
            status,
            &domain.domain_chain_id.to_le_bytes(),
            &operator,
            &domain.operator_bond.to_le_bytes(),
            &domain.config_hash,
            &domain.validator_set_hash,
            domain.finality_adapter.as_bytes(),
            &domain.min_confirmations.to_le_bytes(),
            &[u8::from(domain.bridge_enabled)],
            &block_scheme,
            &state_scheme,
            &tx_scheme,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::plugin::default_domain;
    use crate::domain::types::ConsensusKind;

    #[test]
    fn the_zk_allowlist_is_capped() {
        let mut registry = ConsensusDomainRegistry::new();
        let domain = default_domain(2, ConsensusKind::PoS, 1338, "pos", 0);
        registry.register(domain).expect("register");
        for n in 0..MAX_ZK_PROGRAMS_PER_DOMAIN {
            registry
                .allow_zk_program(2, [u8::try_from(n).unwrap_or(0); 32])
                .expect("under the cap");
        }
        assert!(registry.allow_zk_program(2, [200u8; 32]).is_err());
    }

    #[test]
    fn registration_cannot_bypass_the_zk_allowlist_limit_or_commit_a_duplicate() {
        let mut registry = ConsensusDomainRegistry::new();
        let mut oversized = default_domain(2, ConsensusKind::Zk, 1338, "zk-proof-verification", 0);
        oversized.zk_program_allowlist = (0..=MAX_ZK_PROGRAMS_PER_DOMAIN)
            .map(|n| [u8::try_from(n).unwrap_or(0); 32])
            .collect();
        let error = registry.register(oversized).unwrap_err();
        assert!(error.contains("allowlist limit"), "{error}");
        assert!(registry.is_empty());

        let mut duplicate = default_domain(3, ConsensusKind::Zk, 1338, "zk-proof-verification", 0);
        duplicate.zk_program_allowlist = vec![[7; 32], [7; 32]];
        let error = registry.register(duplicate).unwrap_err();
        assert!(error.contains("duplicate zk program"), "{error}");
        assert!(registry.is_empty());

        let mut valid = default_domain(4, ConsensusKind::Zk, 1338, "zk-proof-verification", 0);
        valid.zk_program_allowlist = vec![[7; 32], [8; 32]];
        registry
            .register(valid)
            .expect("distinct programs within the bound");
        assert_eq!(registry.get(4).unwrap().zk_program_allowlist.len(), 2);
    }

    #[test]
    fn the_leaf_commits_to_the_zk_allowlist_and_plugin_hash() {
        let plain = default_domain(2, ConsensusKind::PoS, 1338, "pos", 0);
        let mut listed = plain.clone();
        listed.zk_program_allowlist = vec![[7u8; 32]];
        let mut pinned = plain.clone();
        pinned.plugin_code_hash = Some([9u8; 32]);
        let plain_leaf = domain_leaf_hash(&plain);
        assert_eq!(plain_leaf, base_domain_leaf_hash(&plain));
        assert_ne!(domain_leaf_hash(&listed), plain_leaf);
        assert_ne!(domain_leaf_hash(&pinned), plain_leaf);
        assert_ne!(domain_leaf_hash(&listed), domain_leaf_hash(&pinned));
    }

    /// what an adapter observed is consensus data. It reaches the
    /// progress root, it never touches a domain that reported nothing, and an
    /// unregistered id cannot park facts in the registry.
    #[test]
    fn observed_facts_reach_the_progress_root_only_once_reported() {
        use crate::crypto::facts::{CryptoFacts, ObservedScheme};
        use crate::crypto::scheme::SchemeId;
        let mut registry = ConsensusDomainRegistry::new();
        registry
            .register(default_domain(2, ConsensusKind::PoS, 1338, "pos", 0))
            .expect("register");
        let before = registry.progress_root();

        registry.record_observed(2, &CryptoFacts::new());
        assert_eq!(registry.progress_root(), before, "no facts, no change");
        let mut facts = CryptoFacts::new();
        facts.record(ObservedScheme::Scheme(SchemeId::BLS12381_MINSIG));
        registry.record_observed(9, &facts);
        assert!(registry.observed(9).is_empty(), "unknown domain");
        assert_eq!(registry.progress_root(), before);

        registry.record_observed(2, &facts);
        let after = registry.progress_root();
        assert_ne!(after, before);
        registry.record_observed(2, &facts);
        assert_ne!(registry.progress_root(), after, "the count moves it too");
        assert_eq!(
            registry
                .observed(2)
                .count(ObservedScheme::Scheme(SchemeId::BLS12381_MINSIG)),
            2
        );
    }

    #[test]
    fn a_domain_cannot_register_as_frozen_or_retired() {
        for status in [DomainStatus::Frozen, DomainStatus::Retired] {
            let mut domain = default_domain(2, ConsensusKind::PoS, 1338, "pos", 0);
            domain.status = status;
            let mut registry = ConsensusDomainRegistry::new();
            let err = registry.register(domain).unwrap_err();
            assert!(err.contains("must register as Active"), "{err}");
        }
    }

    #[test]
    fn registry_root_is_order_independent_by_domain_id() {
        // Uses the real PoW header-chain adapter because 64 is a genuine
        // confirmation depth, and only that adapter reads the field.
        let domain_a = default_domain(
            1,
            ConsensusKind::PoW,
            45262,
            crate::domain::types::POW_HEADER_CHAIN_ADAPTER,
            64,
        );
        let domain_b = default_domain(2, ConsensusKind::PoS, 1338, "pos", 0);

        let mut first = ConsensusDomainRegistry::new();
        first.register(domain_b.clone()).unwrap();
        first.register(domain_a.clone()).unwrap();

        let mut second = ConsensusDomainRegistry::new();
        second.register(domain_a).unwrap();
        second.register(domain_b).unwrap();

        assert_eq!(first.root(), second.root());
    }

    /// The registry cannot exceed its ceiling.
    ///
    /// Every registered domain adds a leaf to the registry root that is recomputed in every
    /// block; the whole network bears that work, not the domain owner. Because the operator bond is
    /// refundable the bond does not bound this growth - the ceiling is the only bound.
    #[test]
    fn the_registry_does_not_grow_past_its_ceiling() {
        let mut registry = ConsensusDomainRegistry::new();

        // Filled up to the ceiling. Every registration must succeed: a gate that
        // refused before the ceiling was full would block legitimate use.
        for id in 0..MAX_REGISTERED_DOMAINS {
            let id = u32::try_from(id).expect("tavan u32'ye sigar");
            registry
                .register(default_domain(id, ConsensusKind::PoS, 1338, "pos", 0))
                .expect("every registration up to the ceiling must be accepted");
        }
        assert_eq!(registry.domains().len(), MAX_REGISTERED_DOMAINS);

        // The first registration above the ceiling is refused.
        let overflow = u32::try_from(MAX_REGISTERED_DOMAINS).expect("tavan+0 u32'ye sigar");
        let err = registry
            .register(default_domain(overflow, ConsensusKind::PoS, 1338, "pos", 0))
            .expect_err("a registration above the ceiling must be refused");
        assert!(
            err.contains("ceiling"),
            "the refusal reason must state the ceiling: {err}"
        );

        // The refusal must really have kept it out of the registry - reporting a message and adding anyway
        // would leave the ceiling silent.
        assert_eq!(
            registry.domains().len(),
            MAX_REGISTERED_DOMAINS,
            "a refused registration must not enter the registry"
        );

        // A request with an already registered id is refused for duplication,
        // not for the ceiling: because it adds no new leaf
        // tavanla ilgisi yok.
        let dup = registry
            .register(default_domain(0, ConsensusKind::PoS, 1338, "pos", 0))
            .expect_err("a duplicate registration must be refused");
        assert!(
            dup.contains("already registered"),
            "a duplicate must be checked before the ceiling: {dup}"
        );
    }

    /// A program can be admitted to the list and withdrawn again.
    ///
    /// Before the gate the list was only read: `submit_zk_proof` looked at it
    /// but no code wrote to it. An allowlist that is read but cannot be filled
    /// is a gate that looks governed and is not.
    #[test]
    fn a_zk_program_can_be_admitted_and_withdrawn() {
        let mut registry = ConsensusDomainRegistry::new();
        registry
            .register(default_domain(5, ConsensusKind::PoS, 1338, "pos", 0))
            .expect("registration");

        let program = [9u8; 32];
        let other = [8u8; 32];

        // The list starts empty: the fail-closed default is preserved.
        let domain = registry.get(5).expect("alan");
        assert!(domain.zk_program_allowlist.is_empty());

        registry.allow_zk_program(5, program).expect("ekleme");
        assert_eq!(
            registry.get(5).expect("alan").zk_program_allowlist,
            vec![program]
        );

        // Adding the same program twice does not pass silently: a governance operation
        // must be able to verify its own effect.
        assert!(registry.allow_zk_program(5, program).is_err());

        // Revocation works and removes only the target.
        registry.allow_zk_program(5, other).expect("ikinci ekleme");
        registry.revoke_zk_program(5, &program).expect("geri cekme");
        assert_eq!(
            registry.get(5).expect("alan").zk_program_allowlist,
            vec![other],
            "only the targeted program must be removed"
        );

        // Revoking something not in the list is an error: a failed revocation
        // reads as success, the program is still accepted while appearing removed
        // sanilir.
        assert!(registry.revoke_zk_program(5, &program).is_err());

        // An unknown domain is refused on both paths.
        assert!(registry.allow_zk_program(404, program).is_err());
        assert!(registry.revoke_zk_program(404, &program).is_err());
    }

    #[test]
    fn duplicate_domain_registration_is_rejected() {
        let domain = default_domain(
            1,
            ConsensusKind::PoW,
            45262,
            crate::domain::types::POW_HEADER_CHAIN_ADAPTER,
            64,
        );
        let mut registry = ConsensusDomainRegistry::new();
        registry.register(domain.clone()).unwrap();
        assert!(registry.register(domain).is_err());
    }

    #[test]
    fn domain_lifecycle_requires_freeze_before_retire() {
        let domain = default_domain(7, ConsensusKind::PoS, 45262, "pos", 0);
        let mut registry = ConsensusDomainRegistry::new();
        registry.register(domain).unwrap();
        assert!(registry
            .transition_status_checked(7, DomainStatus::Retired)
            .unwrap_err()
            .contains("Illegal domain lifecycle transition"));
        registry
            .transition_status_checked(7, DomainStatus::Frozen)
            .unwrap();
        registry
            .transition_status_checked(7, DomainStatus::Retired)
            .unwrap();
    }

    #[test]
    fn retired_domain_is_terminal() {
        let domain = default_domain(8, ConsensusKind::Bft, 45262, "bft", 0);
        let mut registry = ConsensusDomainRegistry::new();
        registry.register(domain).unwrap();
        registry
            .transition_status_checked(8, DomainStatus::Frozen)
            .unwrap();
        registry
            .transition_status_checked(8, DomainStatus::Retired)
            .unwrap();
        assert!(registry
            .transition_status_checked(8, DomainStatus::Active)
            .unwrap_err()
            .contains("Illegal domain lifecycle transition"));
    }

    /// A field that only one adapter reads must not be silently accepted by
    /// the other six.
    ///
    /// Measured: of the seven `DomainFinalityAdapter` implementations, exactly
    /// one - `PoWHeaderChainFinalityAdapter` - reads `min_confirmations`, at
    /// `observed_depth < domain.min_confirmations`. The rest never look at it.
    /// The shipped `config/mainnet-genesis.json` nonetheless sets it on all
    /// four bootstrap domains, so an operator reading that file has every
    /// reason to think a depth requirement applies where none does.
    #[test]
    fn a_non_pow_domain_cannot_claim_a_confirmation_depth() {
        let mut registry = ConsensusDomainRegistry::new();
        let domain = default_domain(101, ConsensusKind::PoS, 45262, "pos-qc-finality", 3);
        let err = registry
            .register(domain)
            .expect_err("a depth no adapter reads must not be accepted silently");
        assert!(err.contains("never reads it"), "err: {err}");
        assert!(
            err.contains("101"),
            "the message must name the domain: {err}"
        );
    }

    #[test]
    fn the_historical_default_of_one_is_still_accepted() {
        // `1` is what the shipped genesis files carry for the non-PoW domains
        // and means the same thing as "no depth requirement" for an adapter
        // that finalises on a quorum. Rejecting it would break every existing
        // configuration for no safety gain.
        let mut registry = ConsensusDomainRegistry::new();
        for (id, kind, adapter) in [
            (111u32, ConsensusKind::PoS, "pos-qc-finality"),
            (112, ConsensusKind::Bft, "bft-quorum-commit"),
            (113, ConsensusKind::PoA, "poa-authority-quorum"),
        ] {
            registry
                .register(default_domain(id, kind, 45262, adapter, 1))
                .unwrap_or_else(|e| {
                    panic!("min_confirmations=1 must stay valid for {adapter}: {e}")
                });
        }
    }

    #[test]
    fn zero_is_still_accepted_for_a_quorum_adapter() {
        let mut registry = ConsensusDomainRegistry::new();
        registry
            .register(default_domain(
                121,
                ConsensusKind::Bft,
                45262,
                "bft-quorum-commit",
                0,
            ))
            .expect("zero means no depth requirement, which is honest for a quorum adapter");
    }

    #[test]
    fn a_pow_domain_may_still_require_real_depth() {
        // The check must not have closed the one case where the field works.
        let mut registry = ConsensusDomainRegistry::new();
        registry
            .register(default_domain(
                131,
                ConsensusKind::PoW,
                45262,
                crate::domain::types::POW_HEADER_CHAIN_ADAPTER,
                6,
            ))
            .expect("a PoW header-chain domain is exactly where depth applies");
    }

    #[test]
    fn duplicate_caip2_registration_is_refused_without_mutating_state() {
        let mut reg = ConsensusDomainRegistry::new();
        let d1 = default_domain(101, ConsensusKind::Bft, 1, "bft-quorum-commit", 1);
        let d2 = default_domain(102, ConsensusKind::Bft, 11_155_111, "bft-quorum-commit", 1);

        // First registration with CAIP-2 succeeds and binds caip2 -> DomainId.
        reg.register_with_caip2(d1, "eip155:1")
            .expect("first CAIP-2 registration must succeed");
        assert_eq!(reg.domain_id_by_caip2("eip155:1"), Some(101));
        assert_eq!(reg.caip2_for_domain(101), Some("eip155:1"));
        let root_after_first = reg.root();

        // Second registration claiming the exact same CAIP-2 must fail atomically
        // without adding d2 or mutating the registry root.
        let dup_err = reg.register_with_caip2(d2.clone(), "eip155:1").unwrap_err();
        assert!(dup_err.contains("already registered"));
        assert_eq!(reg.len(), 1);
        assert!(reg.get(102).is_none());
        assert_eq!(reg.root(), root_after_first);

        // Malformed CAIP-2 references are also rejected without state mutation.
        assert!(reg.register_with_caip2(d2.clone(), "").is_err());
        assert!(reg
            .register_with_caip2(d2.clone(), "missing-colon")
            .is_err());
        assert!(reg.register_with_caip2(d2.clone(), "a:b:c").is_err());
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.root(), root_after_first);

        // Distinct CAIP-2 succeeds and updates the root deterministically.
        reg.register_with_caip2(d2, "eip155:11155111")
            .expect("distinct CAIP-2 must succeed");
        assert_eq!(reg.domain_id_by_caip2("eip155:11155111"), Some(102));
        assert_ne!(reg.root(), root_after_first);
    }

    #[test]
    fn single_operator_cannot_exhaust_domain_registry_and_inactive_domain_reclaims_slot() {
        let mut reg = ConsensusDomainRegistry::new();
        let single_operator = crate::core::address::Address([0x5A; 32]);

        // Under-bonded registration is rejected (deposit required for every slot).
        let mut underfunded = default_domain(1, ConsensusKind::PoS, 1001, "pos", 0);
        underfunded.operator = Some(single_operator);
        underfunded.operator_bond = MIN_DOMAIN_OPERATOR_BOND.saturating_sub(1);
        assert!(reg.register(underfunded).is_err());

        // A single operator can fill at most MAX_ACTIVE_DOMAINS_PER_OPERATOR slots.
        for idx in 0..MAX_ACTIVE_DOMAINS_PER_OPERATOR {
            let id = u32::try_from(idx + 10).expect("fits u32");
            let mut dom = default_domain(id, ConsensusKind::PoS, u64::from(id), "pos", 0);
            dom.operator = Some(single_operator);
            reg.register(dom)
                .expect("registrations within operator quota must succeed");
            reg.note_activity(id, 100);
        }

        // The next registration by the same operator must be rejected without
        // mutating the table.
        let mut overflow = default_domain(999, ConsensusKind::PoS, 999, "pos", 0);
        overflow.operator = Some(single_operator);
        let err = reg
            .register(overflow.clone())
            .expect_err("single operator must not exceed fair-share quota");
        assert!(err.contains("quota"), "{err}");
        assert_eq!(reg.len(), MAX_ACTIVE_DOMAINS_PER_OPERATOR);

        // Keep domain 10 active with fresh proof progress while the rest stay idle.
        reg.note_activity(10, 100 + DOMAIN_INACTIVITY_RETIREMENT_BLOCKS - 1);

        // Once the inactivity window passes, idle domains are reclaimed and
        // their slots open up while the active domain stays registered.
        let reclaimed = reg.reclaim_inactive_domains(
            100 + DOMAIN_INACTIVITY_RETIREMENT_BLOCKS,
            DOMAIN_INACTIVITY_RETIREMENT_BLOCKS,
        );
        assert_eq!(reclaimed.len(), MAX_ACTIVE_DOMAINS_PER_OPERATOR - 1);
        assert!(reg.get(10).is_some(), "active domain must remain");
        assert!(reg.get(11).is_none(), "stale domain must be reclaimed");
        assert_eq!(reg.len(), 1);

        // Freed slot accepts a new registration cleanly.
        reg.register(overflow)
            .expect("registration must succeed once inactive slots are reclaimed");
        assert!(reg.get(999).is_some());
    }
    #[test]
    fn normalize_caip2_conforms_to_official_caip2_final_grammar() {
        for valid in [
            "eip155:1",
            "cosmos:cosmoshub-3",
            "starknet:SN_GOERLI",
            "chainstd:8c3444cf8970a9e41a706fab93e7a6c4",
        ] {
            assert_eq!(normalize_caip2(valid).as_deref(), Ok(valid), "{valid}");
        }
        assert!(normalize_caip2("a:b").is_err(), "namespace < 3 must fail");
        assert!(
            normalize_caip2("namespace:1").is_err(),
            "namespace > 8 must fail"
        );
        let over_ref = format!("eip155:{}", "1".repeat(33));
        assert!(
            normalize_caip2(&over_ref).is_err(),
            "reference > 32 must fail"
        );
        assert!(
            normalize_caip2("eip155:1.2").is_err(),
            "dot is disallowed in CAIP-2 reference"
        );
    }

    #[test]
    fn frozen_domain_and_caip2_survive_inactivity_reclaim_and_refuse_inactive_caip2_binding() {
        let mut reg = ConsensusDomainRegistry::new();
        let d_frozen = default_domain(201, ConsensusKind::PoS, 10, "pos-qc-finality", 1);
        let d_idle = default_domain(202, ConsensusKind::PoS, 42_161, "pos-qc-finality", 1);
        let d_unbinder = default_domain(203, ConsensusKind::PoS, 8453, "pos-qc-finality", 1);

        reg.register_with_caip2(d_frozen, "eip155:10")
            .expect("register d_frozen");
        reg.register_with_caip2(d_idle, "eip155:42161")
            .expect("register d_idle");
        reg.register(d_unbinder).expect("register d_unbinder");
        reg.note_activity(201, 50);
        reg.note_activity(202, 50);
        reg.note_activity(203, 50 + DOMAIN_INACTIVITY_RETIREMENT_BLOCKS);

        // Freeze domain 201 (e.g. proven fraud or quantum alarm isolation) and freeze 203.
        reg.transition_status_checked(201, DomainStatus::Frozen)
            .expect("freeze 201");
        reg.transition_status_checked(203, DomainStatus::Frozen)
            .expect("freeze 203");

        // Binding a fresh CAIP-2 onto a non-Active (Frozen or Retired) domain must be refused
        // without mutating registry state so inactive rows cannot squat CAIP-2 identities.
        let root_before_squat = reg.root();
        let squat_err = reg
            .bind_caip2(203, "eip155:8453")
            .expect_err("non-active domain must not acquire a new CAIP-2 binding");
        assert!(squat_err.contains("Active"), "{squat_err}");
        assert_eq!(reg.root(), root_before_squat);

        // Advance past the inactivity retirement window: idle Active domain 202 must be reclaimed,
        // whereas Frozen domain 201 and its CAIP-2 quarantine ("eip155:10") must survive!
        let reclaimed = reg.reclaim_inactive_domains(
            50 + DOMAIN_INACTIVITY_RETIREMENT_BLOCKS,
            DOMAIN_INACTIVITY_RETIREMENT_BLOCKS,
        );
        assert_eq!(reclaimed, vec![202]);
        assert_eq!(
            reg.get(201).map(|d| d.status),
            Some(DomainStatus::Frozen),
            "frozen domain must never evaporate through inactivity reclamation"
        );
        assert_eq!(reg.domain_id_by_caip2("eip155:10"), Some(201));

        // Attempting to re-register the quarantined CAIP-2 under a fresh domain id must be refused.
        let d_reentry = default_domain(204, ConsensusKind::PoS, 10, "pos-qc-finality", 1);
        let root_after_reclaim = reg.root();
        let reentry_err = reg
            .register_with_caip2(d_reentry, "eip155:10")
            .expect_err("quarantined CAIP-2 must remain blocked while domain is Frozen");
        assert!(reentry_err.contains("already registered"), "{reentry_err}");
        assert_eq!(reg.root(), root_after_reclaim);
    }
}
